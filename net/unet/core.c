/*
 * net/unet/core.c: uNet core code
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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/configfs.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <linux/atomic.h>
#include <linux/random.h>
#include <linux/ctype.h>
#include <linux/log2.h>
#include <linux/uuid.h>
#include <linux/crc16.h>
#include <linux/key.h>
#include <crypto/public_key.h>
#include <keys/system_keyring.h>
#include <keys/asymmetric-type.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <crypto/rng.h>
#include <linux/rtnetlink.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/preempt.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>

/* default values in milliseconds */
#define UNET_UNREGISTERED_APCR_MIN_TIMEOUT	250
#define UNET_UNREGISTERED_APCR_MAX_TIMEOUT	30000
#define UNET_REGISTERED_APCR_TIMEOUT		1000
#define UNET_UNREGISTERED_APCA_TIMEOUT		500
#define UNET_ALIVE_TIMEOUT			60000	/* 1 minute */
#define UNET_REGISTER_TIMEOUT			500
#define UNET_REGISTER_RETRIES			3
#define UNET_REJECT_BACKOFF			30000	/* 30secs */
#define UNET_HOUSEKEEPING_TIMEOUT		1000	/* 1 sec */
#define UNET_CHILD_IDLE_TIMEOUT			30000	/* 30secs */
#define UNET_CHILD_TO_BE_TIMEOUT		5000	/* 5secs */
#define UNET_KEEPALIVE_MAX			3	/* 3 maximum keepalives */
#define UNET_KEEPALIVE_PERIOD			1000	/* one keepalive every sec */
#define UNET_REPLY_APCA_TIMEOUT			1000	/* 1sec */

int unet_net_id __read_mostly;

/* this is our root */
struct unet_addr unet_root_addr = {
	.parent_prefix_len = 0,
	.parent_id_len = 0,
	.prefix_len = 1,
	.id_len = 1,
	.addr_buffer = { '0', '0' }
};

/* initialize to -1 to get 0 as first value of atomic_inc_return */
static atomic_t unet_net_next_index = ATOMIC_INIT(-1);

static struct kmem_cache *unet_entity_cache;

static int unet_entity_send_to_visible_one(struct unet_bearer *b,
		struct unet_entity *orig_ue, struct unet_entity *dest_ue,
		struct unet_conn_entry *uce,
		uint32_t message_type, const void *data, size_t data_sz)
{
	struct sk_buff_head list;
	const void *dest;
	int err;

	__skb_queue_head_init(&list);
	err = unet_construct_visible_list(&list, b, orig_ue, dest_ue, uce,
					  message_type, data, data_sz);
	if (err) {
		unet_entity_err(orig_ue, "%s: Failed to construct (%d)\n",
				__func__, err);
		return err;
	}

	if (dest_ue) {
		b = dest_ue->b;
		dest = dest_ue->media_addr.value;
	} else
		dest = b->media->pta_dest_addr(b);

	err = unet_bearer_send_list(b, dest, &list);
	if (err) {
		unet_entity_err(orig_ue, "%s: Failed to send (%d)\n",
				__func__, err);
	}

	return err;
}

int unet_entity_send_to_visible(struct unet_entity *orig_ue,
				struct unet_entity *dest_ue,
				struct unet_conn_entry *uce,
				uint32_t message_type,
				const void *data, size_t data_sz)
{
	struct net *net = unet_entity_net(orig_ue);
	struct net_device *dev;
	struct unet_bearer *b;
	int first_err, err;
	bool has_rtnl_lock = false; // rtnl_is_locked();

	/* only local entities can send */
	if (orig_ue->type != unet_entity_type_local)
		return -EINVAL;

	if (!dest_ue) {
		first_err = 0;

		if (!has_rtnl_lock)
			rtnl_lock();
		for_each_netdev(net, dev) {
			b = unet_bearer_dev_get(dev);

			/* interfaces with no unet media this will be NULL */
			if (!b)
				continue;

			/* interface must be UP */
			if (!(dev->flags & IFF_UP))
				continue;

			err = unet_entity_send_to_visible_one(b, orig_ue, NULL,
					NULL, message_type, data, data_sz);
			if (!first_err && err)
				first_err = err;
		}
		if (!has_rtnl_lock)
			rtnl_unlock();

		err = first_err;
	} else {
		err = unet_entity_send_to_visible_one(dest_ue->b, orig_ue,
				dest_ue, uce, message_type, data, data_sz);
	}

	return err;
}

/*
 * in strict hierarchical mode we always send via directly
 * attached parent or children. In loose mode, if we have
 * a visible destinator we use that
 * Note that loose mode is off when we're in secure mode
 */
struct unet_entity *
unet_entity_get_destination(struct unet_entity *ue, struct unet_addr *dest_ua)
{
	struct unet_entity *ue_next_hop = NULL;
	struct unet_net *un;

	if (!ue || !dest_ua)
		return NULL;

	un = unet_entity_unet(ue);

	if (!un->strict_hierarchical_routing)
		ue_next_hop = unet_entity_lookup_by_addr(un, dest_ua);

	if (!ue_next_hop)
		ue_next_hop = unet_entity_get_next_hop(ue, dest_ua);

	if (!ue_next_hop)
		ue_next_hop = unet_entity_get_parent(ue);

	return ue_next_hop;
}

int unet_entity_send(struct unet_entity *orig_ue,
		     struct unet_addr *orig_ua, struct unet_addr *dest_ua,
		     uint32_t message_type, const void *data, size_t data_sz)
{
	struct unet_net *un;
	struct unet_entity *ue_next_hop = NULL;
	struct sk_buff_head list;
	struct list_head x_list;
	struct unet_x_entry *x_addr_sender = NULL, *x_next_hop = NULL;
	struct unet_x_entry *x_keepalive = NULL;
	struct unet_conn_entry *uce = NULL;
	struct unet_frame_params ufp;
	unsigned long tmout;
	char *str;
	int err = 0;

	__skb_queue_head_init(&list);

	str = unet_addr_to_str(GFP_KERNEL, dest_ua);
	if (!str) {
		unet_entity_err(orig_ue, "Can't get dest_ua name\n");
		err = -ENOMEM;
		goto out_free;
	}

	x_addr_sender = kmem_cache_alloc(unet_x_entry_cache, GFP_KERNEL);
	if (!x_addr_sender) {
		unet_entity_err(orig_ue, "Can't allocate x_addr_sender\n");
		err = -ENOMEM;
		goto out_free;
	}

	x_next_hop = kmem_cache_alloc(unet_x_entry_cache, GFP_KERNEL);
	if (!x_next_hop) {
		unet_entity_err(orig_ue, "Can't allocate x_next_hop\n");
		err = -ENOMEM;
		goto out_free;
	}

	x_keepalive = kmem_cache_alloc(unet_x_entry_cache, GFP_KERNEL);
	if (!x_keepalive) {
		unet_entity_err(orig_ue, "Can't allocate x_keepalive\n");
		err = -ENOMEM;
		goto out_free;
	}

	un = unet_entity_unet(orig_ue);
	BUG_ON(!un);

	ue_next_hop = unet_entity_get_destination(orig_ue, dest_ua);
	if (!ue_next_hop) {
		unet_router_err(orig_ue, "No next hop - drop now\n");
		/* TODO should queue to the entity for when we do have a parent */
		err = -EHOSTUNREACH;
		goto out_unlock;
	}

	uce = unet_conn_entry_lookup(orig_ue, ue_next_hop);

	INIT_LIST_HEAD(&x_list);

	/* if we need a keep-alive send it */
	if (uce && unet_conn_state_needs_keep_alive(uce->state)) {

		tmout = uce->keepalive_tx_time + msecs_to_jiffies(un->keepalive_period);

		if (!uce->keepalive_count || time_after(jiffies, tmout)) {

			x_keepalive->type = UNET_X_KEEP_ALIVE;
			get_random_bytes(x_keepalive->nonce, sizeof(x_keepalive->nonce));
			list_add_tail(&x_keepalive->node, &x_list);
			if (uce->keepalive_count < un->keepalive_max)
				uce->keepalive_count++;
			uce->keepalive_tx_time = jiffies;
		}
	}

	if (!orig_ua)
		orig_ua = orig_ue ? unet_entity_addr(orig_ue) : NULL;

	memset(&ufp, 0, sizeof(ufp));

	ufp.b = ue_next_hop->b;
	ufp.sender_ue = orig_ue;
	ufp.next_hop_ue = ue_next_hop;
	ufp.uce = uce;
	ufp.orig_ua = orig_ua;
	ufp.dest_ua = dest_ua;
	ufp.x_list = &x_list;
	ufp.message_type = message_type;
	ufp.data = data;
	ufp.data_sz = data_sz;

	/* for now don't send timestamps (maybe sent when uce tells us to) */
	ufp.no_timestamp = 1;

	err = unet_construct_frame_list(&list, &ufp);
	if (err) {
		unet_entity_err(orig_ue, "Failed to construct message\n");
		goto out_unlock;
	}

	err = unet_bearer_send_list(ue_next_hop->b, ue_next_hop->media_addr.value, &list);
	if (err) {
		unet_entity_err(orig_ue, "Failed to send message(s)\n");
		goto out_unlock;
	}

	err = 0;

out_unlock:
	if (uce)
		unet_conn_entry_put(uce);

out_free:
	if (x_keepalive)
		kmem_cache_free(unet_x_entry_cache, x_keepalive);
	if (x_next_hop)
		kmem_cache_free(unet_x_entry_cache, x_next_hop);
	if (x_addr_sender)
		kmem_cache_free(unet_x_entry_cache, x_addr_sender);

	kfree(str);

	if (ue_next_hop)
		unet_entity_put(ue_next_hop);

	/* purge anything not consumed */
	if (err)
		__skb_queue_purge(&list);

	return err;
}

/* NOTE pretty inefficient but it works for now */
int unet_entity_send_msg(struct unet_entity *orig_ue,
			 struct unet_addr *orig_ua, struct unet_addr *dest_ua,
			 uint32_t message_type, struct msghdr *msg, int size)
{
	struct sk_buff *skb;
	int err;

	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	err = memcpy_from_msg(skb_put(skb, size), msg, size);

	if (!err)
		err = unet_entity_send(orig_ue, orig_ua, dest_ua, message_type,
				       skb->data, skb->len);

	kfree_skb(skb);

	return err;
}

int unet_entity_forward(struct unet_entity *ue, struct unet_entity *ue_next_hop,
		struct sk_buff *skb_orig)
{
	struct unet_net *un;
	struct unet_skb_cb *ucb;
	struct sk_buff *skb;
	struct sk_buff_head list;
	struct unet_conn_entry *uce = NULL;
	struct list_head x_list;
	struct unet_x_entry *x_keepalive = NULL;
	unsigned long tmout;
	int err = 0, dont_purge = 0;

	if (!ue || !skb_orig)
		return -EINVAL;

	un = unet_entity_unet(ue);

	ucb = UNET_SKB_CB(skb_orig);
	/* check for magic */
	if (WARN_ON(ucb->magic != UNET_SKB_CB_MAGIC))
		return -EINVAL;

	__skb_queue_head_init(&list);

	INIT_LIST_HEAD(&x_list);

	/* is it on the list? */
	uce = unet_conn_entry_lookup(ue, ue_next_hop);

	/* if we need a keep-alive send it */
	if (uce && unet_conn_state_needs_keep_alive((uce->state))) {

		tmout = uce->keepalive_tx_time + msecs_to_jiffies(un->keepalive_period);

		if (!uce->keepalive_count || time_after(jiffies, tmout)) {

			x_keepalive = kmem_cache_alloc(unet_x_entry_cache, GFP_KERNEL);
			if (!x_keepalive) {
				unet_entity_err(ue, "Can't allocate x_keepalive\n");
				err = -ENOMEM;
				goto out_unlock;
			}

			x_keepalive->type = UNET_X_KEEP_ALIVE;
			get_random_bytes(x_keepalive->nonce, sizeof(x_keepalive->nonce));
			list_add_tail(&x_keepalive->node, &x_list);
			if (uce->keepalive_count < un->keepalive_max)
				uce->keepalive_count++;
			uce->keepalive_tx_time = jiffies;
		}
	}

	err = unet_construct_forwarding_frame_list(&list, ue, ue_next_hop, uce,
						   &x_list, skb_orig);
	if (err) {
		unet_entity_err(ue, "%s: Failed to construct forwarding frame\n",
				__func__);
		err = PTR_ERR(skb);
		goto out_unlock;
	}

	/* TODO check MTU limit */
	err = unet_bearer_send_list(ue_next_hop->b,
				    ue_next_hop->media_addr.value, &list);
	if (err) {
		unet_entity_err(ue, "%s: Failed to send\n", __func__);
		dont_purge = 1;
	}
	err = 0;

out_unlock:

	if (uce)
		unet_conn_entry_put(uce);

	if (x_keepalive)
		kmem_cache_free(unet_x_entry_cache, x_keepalive);

	/* purge anything not consumed */
	if (err && !dont_purge)
		__skb_queue_purge(&list);

	return err;
}

void unet_entity_send_to_all_visible_children(struct unet_entity *ue,
		uint32_t message_type, const void *data, size_t data_sz)
{
	struct unet_conn_entry *uce, **uce_tab;
	int count, i;

	if (!ue)
		return;

	/* no children? */
	count = unet_entity_count_children(ue);
	if (count <= 0)
		return;

	uce_tab = kmalloc(count * sizeof(*uce_tab), GFP_ATOMIC);
	if (WARN_ON(!uce_tab))
		return;

	/* send to all children that are instantiated */
	rcu_read_lock();
	i = 0;
	unet_entity_for_each_conn_entry_rcu(ue, uce) {
		if (!unet_conn_entry_is_child(uce))
			continue;
		if (i >= count) {
			unet_entity_err(ue, "%s: At least one child over\n",
					__func__);
			break;
		}
		uce_tab[i] = unet_conn_entry_get(uce);
		i++;
	}
	rcu_read_unlock();

	while (i > 0) {
		uce = uce_tab[--i];
		unet_entity_send_to_visible(ue, uce->ue, uce, message_type,
					    data, data_sz);
		unet_conn_entry_put(uce);
	}

	kfree(uce_tab);
}

bool unet_entity_i_can_be_router(struct unet_entity *ue,
               struct unet_entity *dest_ue)
{
	struct unet_entity_prop *prop;

	if (!ue)
		return false;

	prop = &ue->ae.prop;
	if (!prop->can_be_router)
		return false;

	/* if checking without a destinator */
	if (dest_ue == NULL)
		return true;
	return true;
}

struct unet_entity *__unet_get_first_local_entity(struct unet_net *un)
{
	struct unet_entity *ue, *uet = NULL;

	rcu_read_lock();
	unet_for_each_local_entity_rcu(un, ue) {
		uet = ue;
		break;
	}
	ue = NULL;
	if (uet)
		ue = __unet_entity_get(uet);
	rcu_read_unlock();

	return ue;
}

int unet_entity_set_parent_by_addr(struct unet_entity *ue, struct unet_addr *ua)
{
	struct unet_conn_entry *uce;
	struct unet_entity *ue_parent = NULL;
	int err;

	/* we reparent only locals */
	if (ue->type != unet_entity_type_local)
		return -EINVAL;

	ue_parent = unet_entity_lookup_by_addr(unet_entity_unet(ue), ua);
	if (!ue_parent)
		return -EINVAL;

	err = 0;
	/* already parent */
	if (unet_entity_is_parent(ue, ue_parent))
		goto out;

	/* don't allow transitional states */
	if (ue->state != unet_entity_state_unregistered &&
	    ue->state != unet_entity_state_registered) {
		err = -EBUSY;
		goto out;
	}

	uce = unet_conn_entry_lookup(ue, ue_parent);
	if (uce) {
		unet_conn_entry_put(uce);
		unet_conn_entry_destroy(uce);
		uce = NULL;
		/* TODO send disconnect? */
	}

	if (ue->state == unet_entity_state_registered)
		unet_set_entity_state(ue, unet_entity_state_unregistered);

	/* we're unregistered */
	unet_set_entity_state(ue, unet_entity_state_registration_pending);

	uce = unet_conn_entry_create(ue, ue_parent,
			unet_conn_state_parent_connected);
	if (IS_ERR(uce)) {
		err = PTR_ERR(uce);
		uce = NULL;
	}
out:
	if (ue_parent)
		unet_entity_put(ue_parent);

	return err;
}

void unet_entity_disconnect(struct unet_entity *ue)
{
	if (ue->state != unet_entity_state_disconnected)
		unet_set_entity_state(ue, unet_entity_state_disconnected);
}

void unet_entity_reconnect(struct unet_entity *ue)
{
	if (ue->state == unet_entity_state_disconnected)
		unet_set_entity_state(ue, unet_entity_state_unregistered);
}

void unet_entity_reparent(struct unet_entity *ue)
{
	struct unet_entity *ue_parent;

	ue_parent = unet_entity_get_parent(ue);

	if (ue_parent && ue->state == unet_entity_state_registered) {
		/* go to unregistered */
		unet_set_entity_state(ue, unet_entity_state_unregistered);
		/* and add the old router as one that has rejected us */
		unet_entity_add_router(ue, ue_parent);
		unet_entity_router_rejected_us(ue, ue_parent);
	}

	if (ue_parent)
		unet_entity_put(ue_parent);
}

static void unet_local_entity_housekeeping(struct unet_entity *ue)
{
	struct unet_net *un = unet_entity_unet(ue);
	unsigned long child_jiffies, idle_jiffies, to_be_jiffies;
	struct unet_conn_entry *uce, *ucen;

	/* only on local */
	if (!ue || ue->type != unet_entity_type_local)
		return;

	/* make sure we are in a state we're supposed to */
	if (ue->state != unet_entity_state_unregistered &&
	    ue->state != unet_entity_state_registration_pending &&
	    ue->state != unet_entity_state_registered)
		return;

	idle_jiffies = msecs_to_jiffies(un->child_idle_timeout);
	to_be_jiffies = msecs_to_jiffies(un->child_to_be_timeout);

	spin_lock(&ue->conn_list_lock);
	unet_entity_for_each_conn_entry_safe(ue, uce, ucen) {

		switch (uce->state) {
		case unet_conn_state_child_to_be:
			child_jiffies = uce->creation_time + idle_jiffies;
			if (time_before(jiffies, child_jiffies))
				break;

			__unet_conn_entry_unlink(uce);
			spin_unlock(&ue->conn_list_lock);

			unet_conn_entry_destroy(uce);

			spin_lock(&ue->conn_list_lock);
			break;

		case unet_conn_state_child_connected:
			/* still time? */
			child_jiffies = uce->last_rx_time + idle_jiffies;
			if (time_before(jiffies, child_jiffies))
				break;

			spin_unlock(&ue->conn_list_lock);

			unet_conn_entry_set_state(uce,
					unet_conn_state_child_connected_past_timeout);

			spin_lock(&ue->conn_list_lock);
			break;

		case unet_conn_state_child_connected_past_timeout:
			if (uce->keepalive_count < un->keepalive_max)
				break;

			__unet_conn_entry_unlink(uce);
			spin_unlock(&ue->conn_list_lock);

			unet_conn_entry_destroy(uce);

			spin_lock(&ue->conn_list_lock);
			break;

		default:
			break;
		}
	}
	spin_unlock(&ue->conn_list_lock);
}

void unet_entity_housekeeping(struct unet_entity *ue)
{
	if (!ue)
		return;

	if (ue->type == unet_entity_type_local)
		unet_local_entity_housekeeping(ue);
}

struct unet_entity *unet_entity_alloc(gfp_t flags)
{
	struct unet_entity *ue;

	ue = kmem_cache_alloc(unet_entity_cache, flags);
	if (!ue)
		return ERR_PTR(-ENOMEM);

	/* inefficient but works for now */
	memset(ue, 0, sizeof(*ue));

	return ue;
}

void unet_entity_free(struct unet_entity *ue)
{
	if (!ue)
		return;

	unet_entity_dev_cleanup(ue);
	unet_entity_next_hop_cleanup(ue);
	unet_entity_router_cleanup(ue);
	unet_entity_conn_cleanup(ue);
	kmem_cache_free(unet_entity_cache, ue);
}

void unet_entity_release(struct kobject *kobj)
{
	struct unet_entity *ue = to_unet_entity(kobj);

	if (unet_entity_refcount_debug(ue))
		printk(KERN_INFO "unet: %-*s %p %-*s\n",
				UNET_DEBUG_REF_TYPE_SPAN, "UE",
				ue,
				UNET_DEBUG_REF_FUNC_SPAN, __func__);

	unet_entity_free(ue);
}

static u32 unet_entity_address_entry_key_hash(const void *data, u32 len, u32 seed)
{
	const struct unet_addr *ua = data;

	return unet_addr_hash(ua, seed);
}

static u32 unet_entity_address_entry_hash(const void *data, u32 len, u32 seed)
{
	const struct unet_entity_address_entry *ueae = data;

	return unet_entity_address_entry_key_hash(&ueae->prop.ua, len, seed);
}

static int unet_entity_address_entry_cmp(struct rhashtable_compare_arg *arg,
				     const void *obj)
{
	const struct unet_entity_address_entry *ueae = obj;

	return !unet_hash_addr_eq(&ueae->prop.ua, arg->key);
}

static const struct rhashtable_params unet_entity_addr_rht_params = {
	.nelem_hint		= 6,
	.head_offset		= offsetof(struct unet_entity_address_entry, node),
	.key_offset		= offsetof(struct unet_entity_address_entry, prop.ua),
	.max_size		= 64,
	.min_size		= 8,
	.automatic_shrinking	= true,
	.hashfn			= unet_entity_address_entry_key_hash,
	.obj_hashfn		= unet_entity_address_entry_hash,
	.obj_cmpfn		= unet_entity_address_entry_cmp,
};

struct unet_entity *
__unet_entity_lookup_by_addr(struct unet_net *un,
		const struct unet_addr *ua)
{
	struct unet_entity_address_entry *ueae;
	struct unet_entity *ue = NULL;

	if (!ua || !unet_addr_is_valid(ua))
		return NULL;

	rcu_read_lock();
	ueae = rhashtable_lookup(&un->entity_addr_rht, ua,
			unet_entity_addr_rht_params);
	if (ueae)
		ue = __unet_entity_get(unet_address_entry_to_entity(ueae));
	rcu_read_unlock();

	return ue;
}

int __unet_entity_unlink(struct unet_entity *ue)
{
	struct unet_entity_address_entry *ueae;
	struct unet_net *un;
	int err;

	if (!ue)
		return -EINVAL;

	un = unet_entity_unet(ue);

	lockdep_assert_held_once(&un->entity_list_lock);

	ueae = &ue->ae;
	err = rhashtable_remove_fast(&un->entity_addr_rht, &ueae->node,
			unet_entity_addr_rht_params);
	if (!err) {
		list_del(&ue->node);
		WRITE_ONCE(ue->unlinked, true);
	}

	return err;
}

void __unet_entity_destroy(struct unet_entity *ue)
{
	struct unet_net *un;
	int err;

	if (!ue)
		return;

	un = unet_entity_unet(ue);

	if (!READ_ONCE(ue->unlinked)) {
		if (WARN_ON(spin_is_locked(&un->entity_list_lock)))
			return;

		spin_lock(&un->entity_list_lock);
		err = __unet_entity_unlink(ue);
		spin_unlock(&un->entity_list_lock);

		if (WARN_ON(err))
			return;
	}

	if (ue->type == unet_entity_type_local) {
		unet_entity_remove_all_routers(ue, true);
		unet_entity_remove_all_conn(ue);
		unet_entity_remove_all_next_hops(ue);

		skb_queue_purge(&ue->tx_ip_skb_list);
	}
	unet_entity_stop_all_timeouts(ue);
	unet_entity_crypto_cleanup(ue);
	unet_entity_destroy_sysfs(ue);
	unet_entity_put(ue);
}

void unet_entity_fire_timeout_event(struct unet_entity *ue,
		enum unet_fsm_event_type type)
{
	struct unet_fsm_event ufe;

	memset(&ufe, 0, sizeof(ufe));

	ufe.type = type;
	ufe.dest_ue = ue;
	unet_entity_fsm(unet_entity_net(ue), &ufe);
}

#define unet_entity_timeout(_name) \
void unet_entity_start_##_name##_timeout(struct unet_entity *ue, \
		unsigned long timeout) \
{ \
	struct unet_net *un = unet_entity_unet(ue); \
	ue->_name##_timeout = timeout; \
	mod_delayed_work(un->workqueue, &ue->_name##_timeout_dwork, timeout); \
	if (!ue->_name##_timeout_active) \
		ue->_name##_timeout_active = true; \
} \
void unet_entity_stop_##_name##_timeout(struct unet_entity *ue) \
{ \
	if (ue->_name##_timeout_active) { \
		ue->_name##_timeout_active = false; \
		cancel_delayed_work(&ue->_name##_timeout_dwork); \
	} \
} \
bool unet_entity_is_##_name##_timeout_running(struct unet_entity *ue) \
{ \
	return ue->_name##_timeout_active; \
} \
void unet_entity_##_name##_timeout_dwork(struct work_struct *work) \
{ \
	struct delayed_work *delayed_work = to_delayed_work(work); \
	struct unet_entity *ue = container_of(delayed_work, struct unet_entity, \
			_name##_timeout_dwork); \
	ue->_name##_timeout_active = false; \
	if (!test_and_set_bit(unet_fsm_event_type_##_name##_timeout, &ue->pending_events)) \
		unet_kthread_schedule(unet_entity_unet(ue)); \
}

/* local */
unet_entity_timeout(apcr);
unet_entity_timeout(apca);
unet_entity_timeout(register);
unet_entity_timeout(housekeeping);
/* remote */
unet_entity_timeout(alive);

bool unet_entity_is_a_match(struct unet_entity *ue,
			    struct unet_entity *check_ue,
			    enum unet_conn_type check_type,
			    enum unet_conn_link_state check_link_state)
{
	struct unet_conn_entry *uce;
	enum unet_conn_type type;
	enum unet_conn_link_state link_state;
	bool result;

	if (!ue || !check_ue)
		return false;

	if (ue->type != unet_entity_type_local)
		return false;

	uce = unet_conn_entry_lookup(ue, check_ue);
	if (!uce)
		return false;

	type = unet_conn_state_to_type(uce->state);
	link_state = unet_conn_state_to_link_state(uce->state);

	/* match on a type and link state */
	result = (check_type == unet_conn_type_unknown || check_type == type) &&
		 (check_link_state == unet_conn_link_state_unknown ||
		  check_link_state == link_state);

	unet_conn_entry_put(uce);

	return result;
}

int unet_entity_count_children(struct unet_entity *ue)
{
	int count;
	struct unet_conn_entry *uce;

	if (!ue)
		return 0;

	if (ue->type != unet_entity_type_local)
		return 0;

	count = 0;
	rcu_read_lock();
	unet_entity_for_each_conn_entry_rcu(ue, uce) {
		/* do not count children to be */
		if (unet_conn_entry_is_child(uce))
			count++;
	}
	rcu_read_unlock();

	return count;
}

int unet_entity_get_n_children(struct unet_entity *ue)
{
	if (!ue)
		return 0;

	if (ue->type == unet_entity_type_remote)
		return ue->ae.prop.n_children;

	return unet_entity_count_children(ue);
}

int unet_entity_get_n_routers(struct unet_entity *ue)
{
	if (!ue)
		return 0;

	if (ue->type == unet_entity_type_remote)
		return ue->ae.prop.n_routers;

	return unet_entity_count_routers(ue);
}


struct unet_entity *
__unet_entity_get_parent(struct unet_entity *ue)
{
	struct unet_conn_entry *uce;
	struct unet_entity *ue_conn;

	uce = __unet_entity_get_conn_entry(ue,
			unet_conn_state_unknown,
			unet_conn_type_parent,
			unet_conn_link_state_connected);
	if (!uce)
		return NULL;

	ue_conn = __unet_entity_get(uce->ue);
	__unet_conn_entry_put(uce);

	return ue_conn;
}

struct unet_entity *
__unet_entity_get_registering_router(struct unet_entity *ue)
{
	struct unet_conn_entry *uce;
	struct unet_entity *ue_conn;

	uce = __unet_entity_get_conn_entry(ue,
			unet_conn_state_parent_to_be,
			unet_conn_type_unknown,
			unet_conn_link_state_unknown);
	if (!uce)
		return NULL;

	ue_conn = __unet_entity_get(uce->ue);
	__unet_conn_entry_put(uce);

	return ue_conn;
}

void unet_entity_mark_child_alive(struct unet_entity *ue,
		struct unet_entity *child_ue)
{
	struct unet_conn_entry *uce;
	enum unet_conn_type type;

	if (!ue || !child_ue || ue->type != unet_entity_type_local)
		return;

	uce = unet_conn_entry_lookup(ue, child_ue);
	/* if it doesn't exist, no problem */
	if (!uce)
		return;

	/* only mark alive if it's a child */
	type = unet_conn_state_to_type(uce->state);

	/* change to connected */
	if (type == unet_conn_type_child) {
		unet_conn_entry_set_state(uce, unet_conn_state_child_connected);
		uce->last_rx_time = jiffies;
	}

	unet_conn_entry_put(uce);
}

bool unet_entity_needs_keep_alive(struct unet_entity *ue,
		struct unet_entity *next_hop_ue)
{
	struct unet_conn_entry *uce;
	bool result;

	if (!ue || !next_hop_ue)
		return false;

	uce = unet_conn_entry_lookup(ue, next_hop_ue);
	if (!uce)
		return false;

	result = unet_conn_state_needs_keep_alive(uce->state);

	unet_conn_entry_put(uce);

	return result;
}

bool unet_entity_can_i_be_router(struct unet_entity *ue,
		struct unet_entity *check_ue,
		bool *send_reply)
{
	struct unet_conn_entry *uce = NULL;
	struct unet_entity_prop *prop;
	struct unet_next_hop_entry *unhe;
	bool result = false;

	/* by default don't sent reply */
	if (send_reply)
		*send_reply = false;

	if (!ue || !check_ue)
		goto out;

	/* only when I'm local */
	if (ue->type != unet_entity_type_local)
		goto out;

	/* must be in a state to do so */
	if (ue->state != unet_entity_state_unregistered &&
	    ue->state != unet_entity_state_registration_pending &&
	    ue->state != unet_entity_state_registered)
		goto out;

#if 0
	/* we can't be routers there */
	if (unet_entity_is_parent(ue, check_ue) ||
	    unet_entity_is_registering_router(ue, check_ue))
		goto out;
#endif

	/* check if we have a hop to there */
	unhe = unet_next_hop_entry_lookup(ue, unet_entity_addr(check_ue));

	/* if we have this entity is reachable via a child so... no */
	if (unhe) {
		unet_next_hop_entry_put(unhe);
		goto out;
	}

	/* find if there's an entry already */
	uce = unet_conn_entry_lookup(ue, check_ue);

	/* if it exists and it's something other than pending */
	if (uce && uce->state != unet_conn_state_child_to_be)
		goto out;

	/* at this point the entity can be graced with a reply */
	if (send_reply)
		*send_reply = true;

	/* TODO maybe we need something more elaborate here? */

	/* finally am I configured to do so? */
	prop = &ue->ae.prop;
	if (!prop->can_be_router)
		goto out;

	result = true;
out:
	if (uce)
		unet_conn_entry_put(uce);

	/* we can offer to be a router for the entity */
	return result;
}

struct unet_entity *
unet_entity_create(struct unet_net *un, enum unet_entity_type type)
{
	struct unet_entity *ue = NULL;
	int err;

	/* allocate entity */
	ue = unet_entity_alloc(GFP_KERNEL);
	if (IS_ERR_OR_NULL(ue)) {
		if (!ue)
			err = -ENOMEM;
		goto out_fail_alloc;
	}

	/* initialize to default values */
	ue->type = type;
	ue->state = unet_entity_state_unknown;

	write_pnet(&ue->net, unet_to_net(un));

	if (ue->type == unet_entity_type_local) {
		/* TODO consolidate due to state */
		INIT_DELAYED_WORK(&ue->apcr_timeout_dwork, unet_entity_apcr_timeout_dwork);
		INIT_DELAYED_WORK(&ue->apca_timeout_dwork, unet_entity_apca_timeout_dwork);
		INIT_DELAYED_WORK(&ue->register_timeout_dwork, unet_entity_register_timeout_dwork);

		INIT_DELAYED_WORK(&ue->housekeeping_timeout_dwork, unet_entity_housekeeping_timeout_dwork);

		skb_queue_head_init(&ue->tx_ip_skb_list);

		/* initialize connection */
		err = unet_entity_conn_setup(ue);
		if (err)
			goto out_fail_conn;

		/* initialize router */
		err = unet_entity_router_setup(ue);
		if (err)
			goto out_fail_router;

		/* initialize next hop table */
		err = unet_entity_next_hop_setup(ue);
		if (err)
			goto out_fail_next_hop;

	} else {
		INIT_DELAYED_WORK(&ue->alive_timeout_dwork, unet_entity_alive_timeout_dwork);
	}

	return ue;

out_fail_next_hop:
	unet_entity_router_cleanup(ue);
out_fail_router:
	unet_entity_conn_cleanup(ue);
out_fail_conn:
	unet_entity_free(ue);
out_fail_alloc:
	return ERR_PTR(err);
}

struct unet_entity *
__unet_local_entity_create(struct unet_net *un, const struct unet_entity_cfg *uec)
{
	struct unet_entity *ue = NULL;
	struct unet_entity_address_entry *ueae;
	struct unet_entity_prop *prop;
	int err;

	if (!uec)
		return ERR_PTR(-EINVAL);

	ue = unet_entity_create(un, unet_entity_type_local);
	if (IS_ERR_OR_NULL(ue)) {
		if (!ue)
			err = -ENOMEM;
		else
			err = PTR_ERR(ue);
		goto out_no_entity;
	}

	/* post setup config */
	ueae = &ue->ae;

	/* fill-in prop */
	prop = &ueae->prop;
	unet_addr_copy(&prop->ua, &uec->ua);
	prop->dev_class = uec->dev_class;
	prop->can_be_router = uec->can_be_router;
	prop->n_children = 0;
	prop->n_routers = 0;

	/* copy force parent */
	unet_addr_copy(&ue->force_parent_ua, &uec->force_parent_ua);

	/* copy forced MTU */
	ue->forced_mtu = uec->forced_mtu;

	/* setup crypto for this local entity */
	err = unet_local_entity_crypto_setup(ue, uec);
	if (err)
		goto out_fail_crypto;

	err = unet_entity_create_sysfs(ue);
	if (err)
		goto out_fail_sysfs;

	/* insert to the hash table & list */
	spin_lock(&un->entity_list_lock);
	err = rhashtable_insert_fast(&un->entity_addr_rht, &ueae->node,
			unet_entity_addr_rht_params);
	if (!err)
		list_add_tail(&ue->node, &un->local_entity_list);
	spin_unlock(&un->entity_list_lock);

	if (err)
		goto out_fail_rht;

	/* commit state change */
	unet_set_entity_state(ue, unet_entity_state_unregistered);

	/* and we're done */
	synchronize_rcu();

	return ue;

out_fail_rht:
	unet_entity_destroy_sysfs(ue);
out_fail_sysfs:
	unet_entity_crypto_cleanup(ue);
out_fail_crypto:
	unet_entity_free(ue);
out_no_entity:

	return ERR_PTR(err);
}

int
unet_entity_update_from_packet(struct unet_entity *ue,
		struct sk_buff *skb, struct unet_packet_header *uph)
{
	struct unet_entity_prop *prop;
	int changed = 0;

	if (!ue)
		return -EINVAL;

	/* we never update local entity prop from packet header */
	if (ue->type == unet_entity_type_local)
		return -EINVAL;

	prop = &ue->ae.prop;

	if (uph->prop.has_dev_class && prop->dev_class != uph->prop.dev_class) {
		prop->dev_class = uph->prop.dev_class;
		changed |= UNET_PROP_CHANGE_DEV_CLASS;
	}
	if (uph->prop.has_i_can_be_router &&
			prop->can_be_router != uph->prop.i_can_be_router) {
		prop->can_be_router = uph->prop.i_can_be_router;
		changed |= UNET_PROP_CHANGE_I_CAN_BE_ROUTER;
	}
	if (uph->prop.has_n_children &&
			prop->n_children != uph->prop.n_children) {
		prop->n_children = uph->prop.n_children;
		changed |= UNET_PROP_CHANGE_N_CHILDREN;
	}
	if (uph->prop.has_n_routers &&
			prop->n_routers != uph->prop.n_routers) {
		prop->n_routers = uph->prop.n_routers;
		changed |= UNET_PROP_CHANGE_N_ROUTERS;
	}

	changed |= unet_entity_update_trust_bundle(ue, skb, uph);

	/* if (changed)
		unet_entity_info(ue, "prop update%s%s%s%s%s%s\n",
			(changed & UNET_PROP_CHANGE_DEV_CLASS) ?
				" class" : "",
			(changed & UNET_PROP_CHANGE_I_CAN_BE_ROUTER) ?
				" i-can-be-router" : "",
			(changed & UNET_PROP_CHANGE_N_CHILDREN) ?
				" children" : "",
			(changed & UNET_PROP_CHANGE_N_ROUTERS) ?
				" routers" : "",
			(changed & UNET_PROP_CHANGE_CERT) ?
				" cert" : "",
			(changed & UNET_PROP_CHANGE_ENCRYPTED) ?
				" encrypted" : ""); */

	return changed;
}

/* create a remote entity */
struct unet_entity *
__unet_remote_entity_create(struct unet_net *un, struct sk_buff *skb)
{
	struct unet_skb_cb *ucb;
	struct unet_packet_header *uph;
	struct unet_entity_address_entry *ueae;
	struct unet_entity *ue;
	struct unet_addr *ua;
	struct unet_entity_prop *prop;
	int err;

	if (!skb)
		return ERR_PTR(-EINVAL);

	/* get packet header */
	ucb = UNET_SKB_CB(skb);
	if (ucb->magic != UNET_SKB_CB_MAGIC || !ucb->uph)
		return ERR_PTR(-EINVAL);
	uph = ucb->uph;

	ua = &uph->pta_ptp.orig;

	ue = unet_entity_lookup_by_addr(un, ua);
	if (ue) {
		err = -EEXIST;
		unet_entity_put(ue);
		ue = NULL;
		goto out_no_entity;
	}

	ue = unet_entity_create(un, unet_entity_type_remote);
	if (IS_ERR_OR_NULL(ue)) {
		if (!ue)
			err = -EINVAL;
		else
			err = PTR_ERR(ue);
		goto out_no_entity;
	}

	/* post setup config */
	ueae = &ue->ae;

	/* fill-in prop */
	prop = &ueae->prop;
	unet_addr_copy(&prop->ua, ua);
	/* TODO verify defaults */
	prop->dev_class = UNET_DEV_CLASS_SMART_PHONE;
	prop->can_be_router = false;
	prop->n_children = 0;
	prop->n_routers = 0;

	unet_remote_entity_crypto_setup(ue);

	err = unet_entity_create_sysfs(ue);
	if (err)
		goto out_fail_sysfs;

	/* insert to the hash table & list */
	spin_lock(&un->entity_list_lock);
	err = rhashtable_insert_fast(&un->entity_addr_rht, &ueae->node,
			unet_entity_addr_rht_params);
	if (!err)
		list_add_tail(&ue->node, &un->remote_entity_list);
	spin_unlock(&un->entity_list_lock);

	if (err)
		goto out_fail_rht;
	synchronize_rcu();

	return ue;

out_fail_rht:
	unet_entity_destroy_sysfs(ue);
out_fail_sysfs:
	unet_entity_free(ue);
out_no_entity:

	return ERR_PTR(err);
}

int unet_entity_setup(struct net *net)
{
	struct unet_net *un = unet_net(net);
	int err;

	err = rhashtable_init(&un->entity_addr_rht, &unet_entity_addr_rht_params);
	if (err)
		return err;

	unet_entity_cache = KMEM_CACHE(unet_entity, 0);
	if (!unet_entity_cache) {
		err = -ENOMEM;
		goto out_no_entity_cache;
	}

	return 0;

out_no_entity_cache:
	rhashtable_destroy(&un->entity_addr_rht);
	return err;
}

void unet_entity_cleanup(struct net *net)
{
	struct unet_net *un = unet_net(net);

	kmem_cache_destroy(unet_entity_cache);
	rhashtable_destroy(&un->entity_addr_rht);
}

void unet_kthread_schedule(struct unet_net *un)
{
	wake_up_all(&un->kthread_wq);
}

static void unet_kthread_process(struct unet_net *un)
{
	struct sk_buff *skb;
	struct unet_entity *ue, *uet;
	int nr;

	/* process any pending skbs */
	while ((skb = skb_dequeue(&un->rx_skb_list)) != NULL)
		unet_rx_handle_skb_slow(skb);

	/* handle entity objects */
	spin_lock(&un->entity_list_lock);

	/* handle local entity events */
	unet_for_each_local_entity_safe(un, ue, uet) {
		spin_unlock(&un->entity_list_lock);

		while (ue->pending_events) {
			nr = __ffs(ue->pending_events);
			clear_bit(nr, &ue->pending_events);
			unet_entity_fire_timeout_event(ue, nr);
		}

		while ((skb = skb_dequeue(&ue->tx_ip_skb_list)) != NULL)
			unet_tx_ip_handle_skb(ue, skb);

		spin_lock(&un->entity_list_lock);
	}

	/* handle remote entity events */
	unet_for_each_remote_entity_safe(un, ue, uet) {
		spin_unlock(&un->entity_list_lock);

		while (ue->pending_events) {
			nr = __ffs(ue->pending_events);
			clear_bit(nr, &ue->pending_events);
			unet_entity_fire_timeout_event(ue, nr);
		}

		spin_lock(&un->entity_list_lock);
	}
	spin_unlock(&un->entity_list_lock);
}

static int unet_kthread_run(void *data)
{
	struct unet_net *un = data;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	set_user_nice(current, -10);

	add_wait_queue(&un->kthread_wq, &wait);
	while (!kthread_should_stop()) {
		unet_kthread_process(un);
		wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
	}
	remove_wait_queue(&un->kthread_wq, &wait);

	return 0;
}

static int __net_init unet_init_net(struct net *net)
{
	struct unet_net *un = unet_net(net);
	int err, i;

	write_pnet(&un->net, net);
	un->index = atomic_inc_return(&unet_net_next_index);

	/* entities */
	spin_lock_init(&un->entity_list_lock);
	INIT_LIST_HEAD(&un->local_entity_list);
	INIT_LIST_HEAD(&un->remote_entity_list);

	/* app */
	INIT_LIST_HEAD(&un->app_list);
	spin_lock_init(&un->app_list_lock);
	ida_init(&un->app_ephemeral_ida);

	skb_queue_head_init(&un->rx_skb_list);
	init_waitqueue_head(&un->kthread_wq);

	/* initial values of global tunables */
	un->alive_timeout = UNET_ALIVE_TIMEOUT;
	un->apcr_min_timeout = UNET_UNREGISTERED_APCR_MIN_TIMEOUT;
	un->apcr_max_timeout = UNET_UNREGISTERED_APCR_MAX_TIMEOUT;
	un->apcr_timeout = UNET_REGISTERED_APCR_TIMEOUT;
	un->apca_timeout = UNET_UNREGISTERED_APCA_TIMEOUT;
	un->register_timeout = UNET_REGISTER_TIMEOUT;
	un->register_retries = UNET_REGISTER_RETRIES;
	un->reject_backoff = UNET_REJECT_BACKOFF;
	un->random_score_policy = false;
	un->children_count_policy = true;
	un->only_forward_from_valid_senders = true;
	un->relay_disconnect_announce_upstream = true;
	un->try_reconnect_to_children = true;
	un->force_relay_rfdr_upstream = false;
	un->force_relay_da_upstream = false;
	un->strict_hierarchical_routing = true;
	un->housekeeping_timeout = UNET_HOUSEKEEPING_TIMEOUT;
	un->child_idle_timeout = UNET_CHILD_IDLE_TIMEOUT;
	un->child_to_be_timeout = UNET_CHILD_TO_BE_TIMEOUT;
	un->keepalive_max = UNET_KEEPALIVE_MAX;
	un->keepalive_period = UNET_KEEPALIVE_PERIOD;
	un->reply_apca_timeout = UNET_REPLY_APCA_TIMEOUT;

	un->syslog_packet_dump = false;
	un->syslog_fsm_dump = false;
	un->syslog_conn_dump = false;
	un->syslog_crypto_dump = false;
	un->syslog_router_dump = false;
	un->syslog_bearer_dump = false;
	un->syslog_refcount_dump = false;

	for (i = 0; i < ARRAY_SIZE(un->bearer_list); i++)
		un->bearer_list[i] = NULL;

	INIT_HLIST_HEAD(&un->raw_head);
	rwlock_init(&un->raw_lock);

	INIT_HLIST_HEAD(&un->dgram_head);
	rwlock_init(&un->dgram_lock);

	un->workqueue = create_singlethread_workqueue("unet-events");
	if (!un->workqueue) {
		pr_err("%s: Failed on creating workqueue\n",
				__func__);
		err = -ENOMEM;
		goto err_fail_wq;
	}

	err = unet_proc_create(net);
	if (err) {
		pr_err("%s: Failed on /proc setup\n", __func__);
		goto err_fail_proc;
	}

	err = unet_configfs_create(net);
	if (err) {
		pr_err("%s: Failed on configfs setup\n", __func__);
		goto err_fail_configfs;
	}

	err = unet_entity_setup(net);
	if (err) {
		pr_err("%s: Failed on entity setup\n", __func__);
		goto err_fail_entity;
	}

	err = unet_router_entry_setup(net);
	if (err) {
		pr_err("%s: Failed on router entry setup\n", __func__);
		goto err_fail_router_entry;
	}

	err = unet_next_hop_entry_setup(net);
	if (err) {
		pr_err("%s: Failed on next hop entry setup\n", __func__);
		goto err_fail_next_hop_entry;
	}

	err = unet_conn_entry_setup(net);
	if (err) {
		pr_err("%s: Failed on con entry setup\n", __func__);
		goto err_fail_conn_entry;
	}

	err = unet_crypto_setup(net);
	if (err) {
		pr_err("%s: Failed on crypto setup\n", __func__);
		goto err_fail_crypto;
	}

	err = unet_app_entry_setup(net);
	if (err) {
		pr_err("%s: Failed on app entry setup\n", __func__);
		goto err_fail_app_entry;
	}

	err = unet_dev_setup(net);
	if (err) {
		pr_err("%s: Failed on unet dev setup\n", __func__);
		goto err_fail_dev;
	}

	un->kthread = kthread_run(unet_kthread_run, un, "unetd%d", un->index);
	if (IS_ERR(un->kthread)) {
		err = PTR_ERR(un->kthread);
		un->kthread = NULL;
		goto err_fail_kthread;
	}

	return 0;
err_fail_kthread:
	unet_dev_cleanup(net);
err_fail_dev:
	unet_app_entry_cleanup(net);
err_fail_app_entry:
	unet_crypto_cleanup(net);
err_fail_crypto:
	unet_conn_entry_cleanup(net);
err_fail_conn_entry:
	unet_next_hop_entry_cleanup(net);
err_fail_next_hop_entry:
	unet_router_entry_cleanup(net);
err_fail_router_entry:
	unet_entity_cleanup(net);
err_fail_entity:
	unet_configfs_destroy(net);
err_fail_configfs:
	unet_proc_destroy(net);
err_fail_proc:
	destroy_workqueue(un->workqueue);
err_fail_wq:
	return err;
}

static void __net_exit unet_exit_net(struct net *net)
{
	struct unet_net *un = unet_net(net);
	struct sk_buff *skb;

	/* nothing */
	pr_info("%s\n", __func__);

	/* Wait for socket readers to complete */
	synchronize_net();

	kthread_stop(un->kthread);

	unet_dev_cleanup(net);
	unet_app_entry_cleanup(net);
	unet_crypto_cleanup(net);
	unet_conn_entry_cleanup(net);
	unet_next_hop_entry_cleanup(net);
	unet_router_entry_cleanup(net);
	unet_entity_cleanup(net);
	unet_configfs_destroy(net);
	unet_proc_destroy(net);

	/* clear any pending skbs */
	while ((skb = skb_dequeue(&un->rx_skb_list)) != NULL) {
		unet_skb_cb_cleanup(skb);
		kfree_skb(skb);
	}

	ida_destroy(&un->app_ephemeral_ida);

	flush_workqueue(un->workqueue);
	destroy_workqueue(un->workqueue);
	un->workqueue = NULL;
}

static struct pernet_operations unet_net_ops = {
	.init = unet_init_net,
	.exit = unet_exit_net,
	.id   = &unet_net_id,
	.size = sizeof(struct unet_net),
};

static int __init unet_init(void)
{
	int err;

	pr_info("Starting (" UNET_MOD_VER ")\n");

	err = unet_kobj_setup();
	if (err)
		goto out_kobj;

	err = unet_socket_setup();
	if (err)
		goto out_socket;

	err = register_pernet_subsys(&unet_net_ops);
	if (err)
		goto out_pernet;

	err = unet_bearer_setup();
	if (err)
		goto out_bearer;

	err = unet_packet_setup();
	if (err)
		goto out_packet;

	pr_info("uNet activated\n");
	return 0;
out_packet:
	unet_bearer_cleanup();
out_bearer:
	unregister_pernet_subsys(&unet_net_ops);
out_pernet:
	unet_socket_cleanup();
out_socket:
	unet_kobj_cleanup();
out_kobj:
	pr_err("uNet failed to activate\n");
	return err;
}

static void __exit unet_exit(void)
{
	unet_packet_cleanup();
	unet_bearer_cleanup();
	unregister_pernet_subsys(&unet_net_ops);
	unet_socket_cleanup();
	unet_kobj_cleanup();

	pr_info("uNet deactivated\n");
}

module_init(unet_init);
module_exit(unet_exit);

MODULE_DESCRIPTION("uNet: Autonomous Network Architecture Protocol");
MODULE_LICENSE("Dual BSD/GPL");		/* TODO review */
MODULE_VERSION(UNET_MOD_VER);
