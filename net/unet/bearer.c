/*
 * net/unet/bearer.c: UNET bearer code
 *
 * Copyright (c) 2016, uNet Inc.
 * All rights reserved.
 *
 * Author: Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <net/sock.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/rwlock.h>
#include <linux/sysfs.h>
#include <linux/sched/signal.h>

#include "core.h"
#include "bearer.h"
#include "fsm.h"
#include "utils.h"

#define MAX_ADDR_STR 60

static const struct unet_media * const unet_media_info_array[] = {
	&unet_eth_media_info,
	NULL
};

int unet_bearer_send(struct unet_bearer *b, const void *dest, struct sk_buff *skb)
{
	struct net_device *dev;
	struct unet_net *un;
	int err, delta;

	if (!b || !dest || !skb) {
		err = -EINVAL;
		goto out_free_skb;
	}

	dev = unet_dev_bearer_get(b);
	if (!dev) {
		err = -EINVAL;
		goto out_free_skb;
	}

	if (!(dev->flags & IFF_UP)) {
		/* purge silently */
		err = 0;
		goto out_free_skb;
	}

	un = unet_net(dev_net(dev));
	if (!un) {
		err = -EINVAL;
		goto out_free_skb;
	}

	if (un->syslog_packet_dump &&
	    unet_skb_cb_prepare(skb, GFP_KERNEL, false) == 0) {
		unet_skb_dump_tx(b, skb, dest, false);
		unet_skb_cb_cleanup(skb);
	}

	delta = SKB_DATA_ALIGN(dev->hard_header_len - skb_headroom(skb));
	if (delta > 0 && pskb_expand_head(skb, delta, 0, GFP_KERNEL)) {
		err = -ENOMEM;
		goto out_free_skb;;
	}
	skb_reset_network_header(skb);
	skb->dev = dev;
	skb->protocol = htons(ETH_P_UNET);
	dev_hard_header(skb, dev, ETH_P_UNET, dest, dev->dev_addr, skb->len);

	err = dev_queue_xmit(skb);

	return err;

out_free_skb:
	kfree_skb(skb);
	return err;
}

int unet_bearer_send_list(struct unet_bearer *b, const void *dest,
		struct sk_buff_head *list)
{
	struct net_device *dev;
	struct sk_buff *skb;
	int err, first_err;

	if (!b || !list || !dest)
		return -EINVAL;

	/* check UP status */
	dev = unet_dev_bearer_get(b);
	if (!dev || !(dev->flags & IFF_UP)) {
		/* purge silently */
		__skb_queue_purge(list);
		return 0;
	}

	first_err = 0;
	while ((skb = __skb_dequeue(list))) {
		err = unet_bearer_send(b, dest, skb);
		if (err && !first_err)
			first_err = err;
	}

	return first_err;
}

const struct unet_media *unet_media_find(const char *name)
{
	u32 i;

	for (i = 0; unet_media_info_array[i] != NULL; i++) {
		if (!strcmp(unet_media_info_array[i]->name, name))
			break;
	}
	return unet_media_info_array[i];
}

struct unet_bearer *unet_bearer_find(struct net *net, const char *name)
{
	struct unet_net *un = unet_net(net);
	struct unet_bearer *b;
	u32 i;

	for (i = 0; i < UNET_MAX_BEARERS; i++) {
		b = rtnl_dereference(un->bearer_list[i]);
		if (b && (!strcmp(b->name, name)))
			return b;
	}
	return NULL;
}

static int unet_l2_rcv_msg(struct sk_buff *skb, struct net_device *dev,
			   struct packet_type *pt, struct net_device *orig_dev)
{
	struct unet_bearer *b;
	int err;

	if (!netif_running(dev))
		goto drop;

	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	rcu_read_lock();
	b = rcu_dereference_rtnl(dev->unet_ptr);
	if (likely(b && test_bit(0, &b->up) &&
		   skb->pkt_type <= PACKET_MULTICAST)) {
		skb->next = NULL;

		err = unet_rx_handle_skb(skb);

		rcu_read_unlock();

		return err ? NET_RX_DROP : NET_RX_SUCCESS;
	}
	rcu_read_unlock();

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static const struct unet_media *unet_is_supported_media(const struct net_device *dev)
{
	const struct unet_media *media;
	int i;

	for (i = 0; (media = unet_media_info_array[i]); i++) {
		if (media->is_supported && media->is_supported(dev))
			return media;
	}

	return NULL;
}

static ssize_t unet_stats_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t len)
{
	struct net_device *netdev = to_net_dev(dev);
	struct net *net = dev_net(netdev);
	struct unet_bearer *b = unet_bearer_dev_get(netdev);
	size_t count = len;
	ssize_t ret;

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	/* ignore trailing newline */
	if (len >  0 && buf[len - 1] == '\n')
		--count;

	if (!rtnl_trylock())
		return restart_syscall();

	memset(&b->stat, 0, sizeof(b->stat));
	ret = 0;

	rtnl_unlock();

	return ret < 0 ? ret : len;
}
static ssize_t unet_stats_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	const struct net_device *netdev = to_net_dev(dev);
	struct unet_bearer *b = unet_bearer_dev_get(netdev);
	char *s;

	if (!rtnl_trylock())
		return restart_syscall();

	s = buf;

	/* rx-stats */
	s += sprintf(s, "%-20s %lu\n", "rx_bca", b->stat.rx_bca);
	s += sprintf(s, "%-20s %lu\n", "rx_pta", b->stat.rx_pta);
	s += sprintf(s, "%-20s %lu\n", "rx_ptp", b->stat.rx_ptp);
	s += sprintf(s, "%-20s %lu\n", "rx_x",   b->stat.rx_x);
	s += sprintf(s, "%-20s %lu\n", "rx_seq", b->stat.rx_seq);

	/* tx-stats */
	s += sprintf(s, "%-20s %lu\n", "tx_bca", b->stat.tx_bca);
	s += sprintf(s, "%-20s %lu\n", "tx_pta", b->stat.tx_pta);
	s += sprintf(s, "%-20s %lu\n", "tx_ptp", b->stat.tx_ptp);
	s += sprintf(s, "%-20s %lu\n", "tx_x",   b->stat.tx_x);
	s += sprintf(s, "%-20s %lu\n", "tx_seq", b->stat.tx_seq);

	rtnl_unlock();
	return (ssize_t)(s - buf);
}
static DEVICE_ATTR_RW(unet_stats);

static const uint8_t gen_xnframe[] = {
	UNET_X,					/* Xframe   */
	UNET_X_KEEP_ALIVE,			/* 202 (KA) */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06	/* nonce    */
};

struct gen_frame {
	const char *name;
	int size;
	const void *data;
};

static const struct gen_frame gen_frames[] = {
	{
		.name	= "KA",
		.size	= sizeof(gen_xnframe),
		.data	= gen_xnframe,
	},
};

static int unet_generate(struct unet_bearer *b, int what)
{
	const struct unet_media *media;
	struct net_device *dev;
	struct sk_buff *skb;
	void *p;
	const struct gen_frame *gf;

	if ((unsigned int)what >= ARRAY_SIZE(gen_frames)) {
		netdev_err(dev, "Bad generator frame number %d\n", what);
		return -EINVAL;
	}
	gf = &gen_frames[what];

	dev = rtnl_dereference(b->dev_ptr);
	media = b->media;

	netdev_info(dev, "Generating pattern #%d (%s)\n", what, gf->name);

	skb = netdev_alloc_skb(dev, gf->size);
	if (!skb) {
		netdev_err(dev, "Failed to allocate skb\n");
		return -ENOMEM;
	}

	skb_reserve(skb, b->media->hwaddr_len);
	p = skb_put(skb, gf->size);
	memcpy(p, gf->data, gf->size);

	return unet_bearer_send(b, media->generator_dest_addr(b), skb);
}

static ssize_t unet_generator_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t len)
{
	struct net_device *netdev = to_net_dev(dev);
	struct unet_bearer *b = unet_bearer_dev_get(netdev);
	struct net *net = dev_net(netdev);
	size_t count = len;
	ssize_t ret;
	int what;

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	/* ignore trailing newline */
	if (len >  0 && buf[len - 1] == '\n')
		--count;

	ret = kstrtoint(buf, 10, &what);;
	if (ret < 0)
		return ret;

	if (!rtnl_trylock())
		return restart_syscall();

	ret = unet_generate(b, what);

	rtnl_unlock();

	return ret < 0 ? ret : len;
}

static ssize_t unet_generator_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	const struct net_device *netdev = to_net_dev(dev);
	struct unet_bearer *b = unet_bearer_dev_get(netdev);
	ssize_t ret = 0;

	(void)b;

	if (!rtnl_trylock())
		return restart_syscall();

	/* TODO */
	ret = sprintf(buf, "%d\n", 0);

	rtnl_unlock();
	return ret;
}
static DEVICE_ATTR_RW(unet_generator);

static int unet_bearer_sysfs_create(struct unet_bearer *b)
{
	struct net_device *dev;
	int err;

	dev = rtnl_dereference(b->dev_ptr);

	err = device_create_file(&dev->dev, &dev_attr_unet_stats);
	if (err)
		return err;

	err = device_create_file(&dev->dev, &dev_attr_unet_generator);
	if (err)
		goto no_generator;

	return 0;

no_generator:
	device_remove_file(&dev->dev, &dev_attr_unet_stats);
	return err;
}

static void unet_bearer_sysfs_remove(struct unet_bearer *b)
{
	struct net_device *dev;

	dev = rtnl_dereference(b->dev_ptr);

	device_remove_file(&dev->dev, &dev_attr_unet_stats);
	device_remove_file(&dev->dev, &dev_attr_unet_generator);
}

static struct unet_bearer *unet_bearer_add_dev(struct net_device *dev,
		const struct unet_media *media)
{
	struct unet_bearer *b;

	ASSERT_RTNL();

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return ERR_PTR(-ENOMEM);

	rcu_assign_pointer(b->dev_ptr, dev);
	b->mtu = dev->mtu;
	b->media = media;
	memset(&b->bcast_addr, 0, sizeof(b->bcast_addr));
	memcpy(b->bcast_addr.value, dev->broadcast, b->media->hwaddr_len);
	b->bcast_addr.media_id = b->media->type_id;
	b->bcast_addr.broadcast = 1;
	b->media->raw2addr(b, &b->addr, (char *)dev->dev_addr);
	rcu_assign_pointer(dev->unet_ptr, b);

	/* TODO cleanup in case of an error */
	(void)media->bearer_register(b);

	(void)unet_bearer_sysfs_create(b);

	return b;
}

static void unet_bearer_remove_dev(struct unet_bearer *b)
{
	struct net_device *dev;

	unet_bearer_sysfs_remove(b);

	b->media->bearer_unregister(b);

	dev = rtnl_dereference(b->dev_ptr);
	RCU_INIT_POINTER(dev->unet_ptr, NULL);
	kfree_rcu(b, rcu);
}

static int unet_l2_device_event(struct notifier_block *nb, unsigned long evt,
				void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct unet_bearer *b;
	const struct unet_media *media;

	/* register and supported type */
	if (evt == NETDEV_REGISTER && (media = unet_is_supported_media(dev))) {
		b = unet_bearer_add_dev(dev, media);
		if (IS_ERR(b)) {
			netdev_err(dev, "unet bearer attach fail\n");
			return notifier_from_errno(PTR_ERR(b));
		}
	} else {
		b = unet_bearer_dev_get(dev);
		/* no uNet bearer, we don't handle this */
		if (!b)
			return NOTIFY_DONE;
	}

	switch (evt) {
	case NETDEV_DOWN:
		unet_bearer_state_info(b, "NETDEV_DOWN\n");
		break;
	case NETDEV_CHANGE:
		if (netif_carrier_ok(dev))
			break;
		unet_bearer_state_info(b, "NETDEV_CHANGE\n");
		break;
	case NETDEV_UP:
		test_and_set_bit_lock(0, &b->up);
		unet_bearer_state_info(b, "NETDEV_UP\n");
		break;
	case NETDEV_GOING_DOWN:
		clear_bit_unlock(0, &b->up);
		unet_bearer_state_info(b, "NETDEV_DOWN\n");
		/* unet_reset_bearer(net, b); */
		break;
	case NETDEV_CHANGEMTU:
		/* unet_reset_bearer(net, b); */
		unet_bearer_state_info(b, "NETDEV_CHANGEMTU\n");
		break;
	case NETDEV_CHANGEADDR:
		b->media->raw2addr(b, &b->addr,
				   (char *)dev->dev_addr);
		unet_bearer_state_info(b, "NETDEV_CHANGEADDR\n");
		/* unet_reset_bearer(net, b); */
		break;
	case NETDEV_UNREGISTER:
		unet_bearer_state_info(b, "NETDEV_UNREGISTER\n");
		unet_bearer_remove_dev(b);
		break;
	case NETDEV_CHANGENAME:
		unet_bearer_state_info(b, "NETDEV_CHANGENAME\n");
		break;
	}
	return NOTIFY_OK;
}

static struct packet_type unet_packet_type __read_mostly = {
	.type = htons(ETH_P_UNET),
	.func = unet_l2_rcv_msg,
};

static struct notifier_block unet_dev_notifier = {
	.notifier_call  = unet_l2_device_event,
	.priority	= 0,
};

int unet_bearer_setup(void)
{
	int err;

	err = register_netdevice_notifier(&unet_dev_notifier);
	if (err)
		return err;
	dev_add_pack(&unet_packet_type);
	return 0;
}

void unet_bearer_cleanup(void)
{
	unregister_netdevice_notifier(&unet_dev_notifier);
	dev_remove_pack(&unet_packet_type);
}
