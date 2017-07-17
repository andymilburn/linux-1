/*
 * net/unet/dev.c: uNet pseudo dev code
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "core.h"
#include "bearer.h"
#include "proc.h"
#include "configfs.h"
#include "packet.h"
#include "fsm.h"
#include "sysfs.h"
#include "utils.h"
#include "router.h"
#include "next_hop.h"

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/rtnetlink.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/preempt.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/if_arp.h>
#include <linux/ip.h>

#include "core.h"

static struct device_type unet_type = {
	.name = "unet",
};

/* fwd */
static const struct net_device_ops unet_netdev_ops;

static void unet_dev_free_netdev(struct net_device *dev)
{
	struct unet_dev_priv *udp = netdev_priv(dev);

	(void)udp;
	free_netdev(dev);
}

static void unet_nl_setup(struct net_device *dev)
{
	dev->ethtool_ops = NULL;
	dev->destructor = unet_dev_free_netdev;
	dev->tx_queue_len = 0;

	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = 65535;	/* unet handles fragmentation */
	dev->type = ARPHRD_UNET;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->min_mtu = 68;
	dev->max_mtu = 65535;

	dev->hw_features = NETIF_F_LLTX;
	dev->netdev_ops = &unet_netdev_ops;
	SET_NETDEV_DEVTYPE(dev, &unet_type);
}

static const struct nla_policy unet_nl_policy[IFLA_UNET_MAX + 1] = {
	[IFLA_UNET_LOCAL_ENTITY]	= { .type = NLA_BINARY, .len = sizeof(struct unet_addr), },
	[IFLA_UNET_REMOTE_ENTITY]	= { .type = NLA_BINARY, .len = sizeof(struct unet_addr), },
	[IFLA_UNET_LOCAL]		= { .type = NLA_BINARY, .len = FIELD_SIZEOF(struct iphdr, saddr) },
	[IFLA_UNET_REMOTE]		= { .type = NLA_BINARY, .len = FIELD_SIZEOF(struct iphdr, daddr) },
	[IFLA_UNET_TOS]			= { .type = NLA_U8 },
	[IFLA_UNET_TTL]			= { .type = NLA_U8 },
};

static int unet_nl_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (!data)
		return -EINVAL;

	if (data[IFLA_UNET_LOCAL_ENTITY] &&
	    nla_len(data[IFLA_UNET_LOCAL_ENTITY]) != sizeof(struct unet_addr))
		return -EINVAL;

	if (data[IFLA_UNET_REMOTE_ENTITY] &&
	    nla_len(data[IFLA_UNET_REMOTE_ENTITY]) != sizeof(struct unet_addr))
		return -EINVAL;

	if (data[IFLA_UNET_LOCAL] &&
	    nla_len(data[IFLA_UNET_LOCAL]) != sizeof(__be32))
		return -EINVAL;

	if (data[IFLA_UNET_REMOTE] &&
	    nla_len(data[IFLA_UNET_REMOTE]) != sizeof(__be32))
		return -EINVAL;

	return 0;
}

static int unet_nl2conf(struct nlattr *tb[], struct nlattr *data[],
			 struct net_device *dev, struct unet_nl_config *conf,
			 bool changelink)
{
	struct unet_dev_priv *udp = netdev_priv(dev);

	memset(conf, 0, sizeof(*conf));

	if (changelink)
		memcpy(conf, &udp->cfg, sizeof(*conf));

	if (data[IFLA_UNET_LOCAL_ENTITY])
		nla_memcpy(&conf->local_ua, data[IFLA_UNET_LOCAL_ENTITY],
				sizeof(conf->local_ua));

	if (data[IFLA_UNET_REMOTE_ENTITY])
		nla_memcpy(&conf->remote_ua, data[IFLA_UNET_REMOTE_ENTITY],
				sizeof(conf->remote_ua));

	if (data[IFLA_UNET_LOCAL])
		conf->local_addr = nla_get_in_addr(data[IFLA_UNET_LOCAL]);
	if (data[IFLA_UNET_REMOTE])
		conf->remote_addr = nla_get_in_addr(data[IFLA_UNET_REMOTE]);

	if (!changelink) {
		if (!unet_addr_is_valid(&conf->local_ua)) {
			pr_err("unet: %s bad local entity addr\n", __func__);
			return -EINVAL;
		}

		if (!unet_addr_is_valid(&conf->remote_ua)) {
			pr_err("unet: %s bad remote entity addr\n", __func__);
			return -EINVAL;
		}
	}

	return 0;
}

static int unet_dev_configure(struct net_device *dev,
			      struct unet_nl_config *conf, bool changelink)
{
	return 0;
}

static int unet_nl_newlink(struct net *src_net, struct net_device *dev,
			  struct nlattr *tb[], struct nlattr *data[])
{
	struct unet_dev_priv *udp = netdev_priv(dev);
	struct unet_nl_config *conf;
	struct net *net;
	struct unet_net *un;
	struct unet_entity *ue;
	int err;

	conf = kzalloc(sizeof(*conf), GFP_ATOMIC);
	if (!conf) {
		pr_err("unet: alloc failure of nl_conf\n");
		return -ENOMEM;
	}

	err = unet_nl2conf(tb, data, dev, conf, false);
	if (err) {
		pr_err("unet: bad nl config\n");
		goto out_no_entity;
	}

	net = dev_net(dev);
	if (!net)
		net = &init_net;
	un = unet_net(net);

	ue = unet_entity_lookup_by_addr(un, &conf->local_ua);
	if (!ue) {
		pr_err("unet: no entity found\n");
		err = -ENOENT;
		goto out_no_entity;
	}
	if (ue->type != unet_entity_type_local) {
		pr_err("unet: can only use local entities\n");
		err = -ENOENT;
		goto out_bad_entity;
	}
	if (ue->dev) {
		pr_err("unet: can only set a single device per entity\n");
		err = -EBUSY;
		goto out_bad_entity;
	}

	memcpy(&udp->cfg, conf, sizeof(*conf));
	udp->ue = ue;

	err = unet_dev_configure(dev, conf, false);
	if (err) {
		pr_err("unet: device configuration failed\n");
		goto out_bad_config;
	}

	err = register_netdevice(dev);
	if (err) {
		pr_err("unet: device registration failed\n");
		goto out_bad_config;
	}
	ue->dev = dev;

	kfree(conf);

	return 0;

out_bad_config:
out_bad_entity:
	unet_entity_put(ue);
out_no_entity:
	kfree(conf);
	return err;
}

static int unet_nl_changelink(struct net_device *dev, struct nlattr *tb[],
			    struct nlattr *data[])
{
	struct unet_dev_priv *udp = netdev_priv(dev);
	struct unet_nl_config *conf;
	int err;

	(void)udp;
	conf = kzalloc(sizeof(*conf), GFP_ATOMIC);
	if (!conf) {
		pr_err("unet: alloc failure of nl_conf\n");
		return -ENOMEM;
	}

	err = unet_nl2conf(tb, data, dev, conf, true);
	if (err) {
		pr_err("unet: bad nl config\n");
		goto out_bad_config;
	}

	kfree(conf);

	return 0;

out_bad_config:
	kfree(conf);
	return err;
}

static void unet_nl_dellink(struct net_device *dev, struct list_head *head)
{
	struct unet_dev_priv *udp = netdev_priv(dev);

	udp->ue->dev = NULL;
	unet_entity_put(udp->ue);

	unregister_netdevice_queue(dev, head);
}

static size_t unet_nl_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(struct unet_addr)) +	/* LOCAL_ENTITY */
               nla_total_size(sizeof(struct unet_addr)) +	/* REMOTE_ENTITY */
               nla_total_size(sizeof(__be32)) +			/* LOCAL */
               nla_total_size(sizeof(__be32)) +			/* REMOTE */
	       nla_total_size(sizeof(__u8)) +			/* TTL */
	       nla_total_size(sizeof(__u8)) +			/* TOS */
	       0;
}

static int unet_nl_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct unet_dev_priv *udp = netdev_priv(dev);
	struct unet_nl_config *conf = &udp->cfg;

	if (nla_put(skb, IFLA_UNET_LOCAL_ENTITY, sizeof(conf->local_ua), &conf->local_ua) ||
	    nla_put(skb, IFLA_UNET_REMOTE_ENTITY, sizeof(conf->remote_ua), &conf->remote_ua) ||
	    nla_put_in_addr(skb, IFLA_UNET_LOCAL, conf->local_addr) ||
	    nla_put_in_addr(skb, IFLA_UNET_REMOTE, conf->remote_addr) ||
	    nla_put_u8(skb, IFLA_UNET_TTL, 0) ||
	    nla_put_u8(skb, IFLA_UNET_TOS, 0))
		return -EMSGSIZE;

	return 0;
}

static struct net *unet_nl_get_link_net(const struct net_device *dev)
{
	return dev_net(dev);
}

static struct rtnl_link_ops unet_link_ops __read_mostly = {
	.kind		= "unet",
	.maxtype	= IFLA_UNET_MAX,
	.policy		= unet_nl_policy,
	.priv_size	= sizeof(struct unet_dev_priv),
	.setup		= unet_nl_setup,
	.validate	= unet_nl_validate,
	.newlink	= unet_nl_newlink,
	.changelink	= unet_nl_changelink,
	.dellink	= unet_nl_dellink,
	.get_size	= unet_nl_get_size,
	.fill_info	= unet_nl_fill_info,
	.get_link_net	= unet_nl_get_link_net,
};

int unet_dev_setup(struct net *net)
{
	int err;

	err = rtnl_link_register(&unet_link_ops);
	if (err) {
		pr_err("unet: Can't register link_ops\n");
		return err;
	}
	return 0;
}

void unet_dev_cleanup(struct net *net)
{
	rtnl_link_unregister(&unet_link_ops);
}

static void unet_dev_uninit(struct net_device *dev)
{
	pr_info("unet: %s - %s\n", netdev_name(dev), __func__);
	/* nothing */
}

static int unet_dev_open(struct net_device *dev)
{
	pr_info("unet: %s - %s\n", netdev_name(dev), __func__);

	netif_tx_start_all_queues(dev);
	return 0;
}

static int unet_dev_close(struct net_device *dev)
{
	pr_info("unet: %s - %s\n", netdev_name(dev), __func__);

	netif_tx_stop_all_queues(dev);
	return 0;
}

static netdev_tx_t unet_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct unet_dev_priv *udp = netdev_priv(dev);
	struct unet_entity *ue = udp->ue;
	struct unet_net *un = unet_entity_unet(ue);

	rcu_read_lock();

	/* we only handle IP here */
	if (unlikely(skb->protocol != htons(ETH_P_IP)))
		goto drop;

	if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC)))
		goto drop;

	skb_tx_timestamp(skb);
	skb_orphan(skb);
	nf_reset(skb);

	/* and queue it for transmission */
	skb_queue_tail(&ue->tx_ip_skb_list, skb);
	unet_kthread_schedule(un);

	rcu_read_unlock();

	return NETDEV_TX_OK;

drop:
	skb_tx_error(skb);
	kfree_skb(skb);
	rcu_read_unlock();
	return NET_XMIT_DROP;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void unet_dev_poll_controller(struct net_device *dev)
{
	/* ??? */
	return;
}
#endif

static void
unet_dev_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	u32 rx_dropped = 0, tx_dropped = 0, rx_frame_errors = 0;

	stats->rx_dropped  = rx_dropped;
	stats->rx_frame_errors = rx_frame_errors;
	stats->tx_dropped = tx_dropped;
}

static const struct net_device_ops unet_netdev_ops = {
	.ndo_uninit		= unet_dev_uninit,
	.ndo_open		= unet_dev_open,
	.ndo_stop		= unet_dev_close,
	.ndo_start_xmit		= unet_dev_xmit,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= unet_dev_poll_controller,
#endif
	.ndo_get_stats64	= unet_dev_get_stats64,
};

void unet_entity_dev_cleanup(struct unet_entity *ue)
{
	struct unet_dev_priv *udp;
	bool has_rtnl_lock = rtnl_is_locked();

	if (!ue->dev)
		return;

	if (!has_rtnl_lock)
		rtnl_lock();

	udp = netdev_priv(ue->dev);

	unet_entity_put(udp->ue);
	unregister_netdevice(ue->dev);

	if (!has_rtnl_lock)
		rtnl_unlock();
}

void unet_entity_ip_deliver(struct unet_entity *ue, const void *data, int size)
{
	struct net_device *dev = ue->dev;
	struct sk_buff *skb;

	if (!dev || !data || size <= 0)
		return;

	skb = __netdev_alloc_skb(dev, size, GFP_KERNEL);
	if (!skb)
		return;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);

	if (skb_linearize(skb))
		return;
	__skb_set_length(skb, size);
	skb_copy_to_linear_data(skb, data, size);

	netif_rx(skb);
}
