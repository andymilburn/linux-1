/*
 * net/unet/eth_media.c: Ethernet bearer support for uNet
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

#include "core.h"
#include "bearer.h"

#include <linux/if_arp.h>	/* for hardware types */
#include <linux/if_ether.h>
#include <linux/ctype.h>
#include <linux/sched/signal.h>

static const char bcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct unet_eth_media {
	struct unet_bearer *b;
	unsigned char dest[ETH_ALEN];
};

static ssize_t unet_eth_dest_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t len)
{
	struct net_device *netdev = to_net_dev(dev);
	struct unet_bearer *b = unet_bearer_dev_get(netdev);
	struct unet_eth_media *em = b->media_instance;
	struct net *net = dev_net(netdev);
	size_t count = len;
	ssize_t ret;
	unsigned char mac[ETH_ALEN], val;
	char c;
	const char *s;
	int i, j;

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	/* ignore trailing newline */
	if (len >  0 && buf[len - 1] == '\n')
		--count;

	memset(mac, 0, sizeof(mac));

	s = buf;
	for (i = 0; i < ETH_ALEN; i++) {
		val = 0;

		/* skip over seperators */
		if (*s == ':')
			s++;

		for (j = 0; j < 2; j++) {
			c = *s++;

			/* must be a digit */
			if (!isdigit(c) && !isxdigit(c))
				return -EINVAL;

			c = toupper(c);

			val <<= 4;
			if (c >= 'A')
				val |= 10 + (c - 'A');
			else
				val |= (c - '0');
		}
		mac[i] = val;
	}

	if (!rtnl_trylock())
		return restart_syscall();

	memcpy(em->dest, mac, ETH_ALEN);


	rtnl_unlock();

	return ret < 0 ? ret : len;
}

static ssize_t unet_eth_dest_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	const struct net_device *netdev = to_net_dev(dev);
	struct unet_bearer *b = unet_bearer_dev_get(netdev);
	struct unet_eth_media *em = b->media_instance;
	char *s = buf;

	(void)b;

	if (!rtnl_trylock())
		return restart_syscall();

	s += sprintf(s, "%pM\n", em->dest);

	rtnl_unlock();

	return (ssize_t)(s - buf);
}
static DEVICE_ATTR_RW(unet_eth_dest);

bool unet_eth_is_supported(const struct net_device *dev)
{
	/* ethernet like devices */
	return dev->type == ARPHRD_ETHER    ||
	       /* dev->type == ARPHRD_LOOPBACK || */	/* remove loopback */
	       dev->type == ARPHRD_IPGRE    ||
	       /* dev->type == ARPHRD_SIT      || */	/* remove sit for testing */
	       dev->type == ARPHRD_TUNNEL;
}

static int unet_eth_sysfs_create(struct unet_eth_media *em)
{
	struct unet_bearer *b = em->b;
	struct net_device *dev;
	int err;

	dev = unet_dev_bearer_get(b);
	if (!dev)
		return -EINVAL;

	err = device_create_file(&dev->dev, &dev_attr_unet_eth_dest);
	if (err)
		return err;

	return 0;
}

static void unet_eth_sysfs_remove(struct unet_eth_media *em)
{
	struct net_device *dev;

	dev = unet_dev_bearer_get(em->b);

	device_remove_file(&dev->dev, &dev_attr_unet_eth_dest);
}

static int unet_eth_bearer_register(struct unet_bearer *b)
{
	struct unet_eth_media *em;
	int err;

	em = kzalloc(sizeof(*em), GFP_KERNEL);
	if (!em)
		return -ENOMEM;

	em->b = b;
	err = unet_eth_sysfs_create(em);
	if (err)
		goto out;

	b->media_instance = em;

	pr_info("%s OK\n", __func__);

	return 0;
out:
	kfree(em);
	return err;
}

static void unet_eth_bearer_unregister(struct unet_bearer *b)
{
	struct unet_eth_media *em = b->media_instance;

	unet_eth_sysfs_remove(em);

	b->media_instance = NULL;
	kfree(em);

	pr_info("%s OK\n", __func__);
}

/* Convert Ethernet address (media address format) to string */
static int unet_eth_addr2str(struct unet_media_addr *addr,
			     char *strbuf, int bufsz)
{
	if (bufsz < 18)	/* 18 = strlen("aa:bb:cc:dd:ee:ff\0") */
		return 1;

	sprintf(strbuf, "%pM", addr->value);
	return 0;
}

/* Convert raw mac address format to media addr format */
static int unet_eth_raw2addr(struct unet_bearer *b,
			     struct unet_media_addr *addr,
			     const void *msg)
{
	memset(addr, 0, sizeof(*addr));
	ether_addr_copy(addr->value, msg);
	addr->media_id = UNET_MEDIA_TYPE_ETH;
	addr->broadcast = !memcmp(addr->value, bcast_mac, ETH_ALEN);
	return 0;
}

const void *unet_eth_generator_dest_addr(struct unet_bearer *b)
{
	struct unet_eth_media *em = b->media_instance;

	return em->dest;
}

const void *unet_eth_pta_dest_addr(struct unet_bearer *b)
{
	return bcast_mac;
}

const void *unet_eth_bta_dest_addr(struct unet_bearer *b)
{
	return bcast_mac;
}

const void *unet_eth_skb_dest_addr(struct unet_bearer *b, struct sk_buff *skb)
{
	return eth_hdr(skb)->h_dest;
}

const void *unet_eth_skb_source_addr(struct unet_bearer *b, struct sk_buff *skb)
{
	return eth_hdr(skb)->h_source;
}

/* Ethernet media registration info */
const struct unet_media unet_eth_media_info = {
	.is_supported		= unet_eth_is_supported,
	.bearer_register	= unet_eth_bearer_register,
	.bearer_unregister	= unet_eth_bearer_unregister,
	.addr2str		= unet_eth_addr2str,
	.raw2addr		= unet_eth_raw2addr,
	.generator_dest_addr	= unet_eth_generator_dest_addr,
	.pta_dest_addr		= unet_eth_pta_dest_addr,
	.bta_dest_addr		= unet_eth_bta_dest_addr,
	.skb_dest_addr		= unet_eth_skb_dest_addr,
	.skb_source_addr	= unet_eth_skb_source_addr,
	.type_id		= UNET_MEDIA_TYPE_ETH,
	.hwaddr_len		= ETH_ALEN,
	.name			= "eth"
};
