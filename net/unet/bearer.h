/*
 * net/unet/bearer.h: Include file for uNet bearer code
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

#ifndef _UNET_BEARER_H
#define _UNET_BEARER_H

#include <linux/unet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>

#define UNET_MAX_MEDIA	1

/* media info */
#define UNET_MEDIA_INFO_SIZE	32

/* Supported UNET media types */
#define UNET_MEDIA_TYPE_ETH	1

struct unet_media_addr {
	u8 value[UNET_MEDIA_INFO_SIZE];
	u8 media_id;
	u8 broadcast;
};

/* minimum bearer MTU */
#define UNET_MIN_BEARER_MTU		128	/* XXX bogus, check */

/* leave at this this headroom when sending */
#define UNET_BEARER_MTU_HEADROOM	64

#define UNET_MAX_BEARERS      3

struct unet_bearer;

struct unet_media {
	bool (*is_supported)(const struct net_device *dev);
	int (*bearer_register)(struct unet_bearer *b);
	void (*bearer_unregister)(struct unet_bearer *b);

	int (*addr2str)(struct unet_media_addr *addr,
			char *strbuf,
			int bufsz);
	int (*raw2addr)(struct unet_bearer *b,
			struct unet_media_addr *addr,
			const void *raw);
	const void *(*generator_dest_addr)(struct unet_bearer *b);
	const void *(*pta_dest_addr)(struct unet_bearer *b);
	const void *(*bta_dest_addr)(struct unet_bearer *b);
	const void *(*skb_dest_addr)(struct unet_bearer *b,
				     struct sk_buff *skb);
	const void *(*skb_source_addr)(struct unet_bearer *b,
				       struct sk_buff *skb);
	u32 type_id;
	u32 hwaddr_len;
	char name[UNET_MAX_MEDIA_NAME];
};

struct unet_bearer;

struct unet_ifaddr {
	struct unet_ifaddr *ifa_next;
	struct unet_bearer *ifa_bearer;
	struct unet_addr ifa_addr;
};

struct unet_bearer {
	struct net_device __rcu *dev_ptr;
	const struct unet_media *media;
	void *media_instance;			/* private use by media */
	u32 mtu;

	struct unet_ifaddr *ifa_list;		/* unet ifaddr chain */

	struct unet_media_addr addr;
	char name[UNET_MAX_BEARER_NAME];
	struct unet_media_addr bcast_addr;
	struct rcu_head rcu;
	unsigned long up;

	/* statistics */
	struct {
		/* receive packet counters */
		unsigned long rx_bca;
		unsigned long rx_pta;
		unsigned long rx_ptp;
		unsigned long rx_x;
		unsigned long rx_seq;

		/* transmit packet counters */
		unsigned long tx_bca;
		unsigned long tx_pta;
		unsigned long tx_ptp;
		unsigned long tx_x;
		unsigned long tx_seq;
	} stat;
};

struct unet_bearer_names {
	char media_name[UNET_MAX_MEDIA_NAME];
	char if_name[UNET_MAX_IF_NAME];
};

static inline struct net_device *unet_dev_bearer_get(
		const struct unet_bearer *b)
{
	if (!b)
		return NULL;

	return b->dev_ptr;
}

static inline struct unet_bearer *unet_bearer_dev_get(
		const struct net_device *dev)
{
	if (!dev)
		return NULL;

	return dev->unet_ptr;
}

static inline struct unet_bearer *unet_skb_bearer_get(struct sk_buff *skb)
{
	return unet_bearer_dev_get(skb->dev);
}

void unet_rcv(struct net *net, struct sk_buff *skb, struct unet_bearer *b);

extern const struct unet_media unet_eth_media_info;

void unet_media_addr_printf(char *buf, int len, struct unet_media_addr *a);

struct unet_bearer *unet_bearer_find(struct net *net, const char *name);
const struct unet_media *unet_media_find(const char *name);
int unet_bearer_setup(void);
void unet_bearer_cleanup(void);

int unet_bearer_send(struct unet_bearer *b, const void *dest, struct sk_buff *skb);
int unet_bearer_send_list(struct unet_bearer *b, const void *dest,
		struct sk_buff_head *list);

static inline bool unet_mtu_bad(struct net_device *dev, unsigned int reserve)
{
	if (dev->mtu >= UNET_MIN_BEARER_MTU + reserve)
		return false;
	netdev_warn(dev, "MTU too low for unet bearer\n");
	return true;
}

#endif	/* _UNET_BEARER_H */
