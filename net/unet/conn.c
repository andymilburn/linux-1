/*
 * net/unet/conn.c: uNet conn entry methods
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
#include "utils.h"
#include "conn.h"
#include "sysfs.h"

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>

static struct kmem_cache *unet_conn_entry_cache;

int unet_conn_entry_setup(struct net *net)
{
	unet_conn_entry_cache = KMEM_CACHE(unet_conn_entry, 0);
	if (!unet_conn_entry_cache)
		return -ENOMEM;
	return 0;
}

void unet_conn_entry_cleanup(struct net *net)
{
	kmem_cache_destroy(unet_conn_entry_cache);
}

struct unet_conn_entry *unet_conn_entry_alloc(gfp_t flags)
{
	struct unet_conn_entry *uce;

	uce = kmem_cache_alloc(unet_conn_entry_cache, flags);
	if (!uce)
		return ERR_PTR(-ENOMEM);

	/* inefficient but works for now */
	memset(uce, 0, sizeof(*uce));
	uce->state = unet_conn_state_unknown;

	return uce;
}

void unet_conn_entry_free(struct unet_conn_entry *uce)
{
	if (!uce)
		return;

	/* always clear this */
	kfree(uce->utb.blob);
	kfree(uce->scratch);
	kmem_cache_free(unet_conn_entry_cache, uce);
}

void unet_conn_entry_release(struct kobject *kobj)
{
	struct unet_conn_entry *uce = to_unet_conn_entry(kobj);

	if (unet_conn_entry_refcount_debug(uce))
		printk(KERN_INFO "unet: %-*s %p %-*s\n",
				UNET_DEBUG_REF_TYPE_SPAN, "UCE",
				uce,
				UNET_DEBUG_REF_FUNC_SPAN, __func__);

	unet_entity_put(uce->local_ue);
	unet_entity_put(uce->ue);

	unet_conn_entry_free(uce);
}

int unet_entity_conn_setup(struct unet_entity *ue)
{
	if (!ue)
		return -EINVAL;

	INIT_LIST_HEAD(&ue->conn_list);
	spin_lock_init(&ue->conn_list_lock);
	/* conn_kset is initialized after kobject_init */

	return 0;
}

void unet_entity_conn_cleanup(struct unet_entity *ue)
{
	/* conn_kset is destroyed when the entity is destroyed */
}

struct unet_conn_entry *
__unet_conn_entry_lookup(struct unet_entity *ue, struct unet_entity *conn_ue)
{
	struct unet_conn_entry *uce, *uce_found = NULL;

	rcu_read_lock();
	unet_entity_for_each_conn_entry_rcu(ue, uce) {
		if (uce->ue == conn_ue) {
			uce_found = uce;
			break;
		}
	}
	uce = NULL;
	if (uce_found)
		uce = __unet_conn_entry_get(uce_found);

	rcu_read_unlock();

	return uce;
}

struct unet_conn_entry *
__unet_conn_entry_create(struct unet_entity *ue, struct unet_entity *conn_ue,
			 enum unet_conn_state state)
{
	struct unet_conn_entry *uce;
	enum unet_conn_type type;
	int err;

	type = unet_conn_state_to_type(state);
	if (!ue || !conn_ue || ue->type != unet_entity_type_local ||
	    (type != unet_conn_type_child && type != unet_conn_type_parent))
		return ERR_PTR(-EINVAL);

	/* is it on the list? it's an error if it is */
	uce = unet_conn_entry_lookup(ue, conn_ue);
	if (uce) {
		unet_conn_entry_put(uce);
		return ERR_PTR(-EEXIST);
	}

	uce = unet_conn_entry_alloc(GFP_KERNEL);
	if (!uce)
		return ERR_PTR(-ENOMEM);

	uce->state = unet_conn_state_unknown;
	uce->local_ue = ue;
	uce->ue = conn_ue;
	uce->creation_time = jiffies;

	err = unet_conn_entry_create_sysfs(ue, uce);
	if (err)
		goto out_fail_sysfs;

	unet_entity_get(uce->local_ue);
	unet_entity_get(uce->ue);

	spin_lock(&ue->conn_list_lock);
	list_add_tail(&uce->node, &ue->conn_list);
	spin_unlock(&ue->conn_list_lock);

	unet_conn_entry_set_state(uce, state);

	unet_conn_info(uce, "created\n");

	return uce;

out_fail_sysfs:
	unet_conn_entry_free(uce);
	return ERR_PTR(err);
}

int __unet_conn_entry_unlink(struct unet_conn_entry *uce)
{
	struct unet_entity *ue;

	if (!uce)
		return -EINVAL;

	ue = unet_conn_entry_to_entity(uce);
	lockdep_assert_held_once(&ue->conn_list_lock);

	list_del(&uce->node);

	WRITE_ONCE(uce->unlinked, true);

	return 0;
}

void __unet_conn_entry_destroy(struct unet_conn_entry *uce)
{
	struct unet_entity *ue;
	enum unet_conn_type type;
	enum unet_conn_link_state link_state;

	if (!uce)
		return;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue)
		return;

	if (!READ_ONCE(uce->unlinked)) {
		if (WARN_ON(spin_is_locked(&ue->conn_list_lock)))
			return;

		spin_lock(&ue->conn_list_lock);
		__unet_conn_entry_unlink(uce);
		spin_unlock(&ue->conn_list_lock);
	}


	type = unet_conn_state_to_type(uce->state);
	link_state = unet_conn_state_to_link_state(uce->state);

	if (link_state == unet_conn_link_state_connected) {
		switch (type) {
		case unet_conn_type_child:
			unet_entity_remove_next_hops_via_entity(ue, uce->ue);
			unet_entity_sysfs_remove_child(ue, uce->ue);
			break;
		case unet_conn_type_parent:
			unet_entity_sysfs_set_parent(ue, NULL);
			break;
		default:
			break;
		}
	}

	unet_conn_entry_cleanup_crypto(uce);
	unet_conn_entry_cleanup_reassembly(uce);

	kfree(uce->utb.blob);
	memset(&uce->utb, 0, sizeof(uce->utb));
	kfree(uce->scratch);
	uce->scratch = NULL;

	unet_conn_entry_destroy_sysfs(uce);

	__unet_conn_entry_put(uce);
}

static bool __conn_match(const struct unet_conn_entry *uce,
				enum unet_conn_state match_state,
				enum unet_conn_type match_type,
				enum unet_conn_link_state match_link_state)
{

	if (match_state != unet_conn_state_unknown)
		return match_state == uce->state;

	return (match_type == unet_conn_type_unknown ||
		match_type == unet_conn_state_to_type(uce->state)) &&
	       (match_link_state == unet_conn_link_state_unknown ||
		match_link_state == unet_conn_state_to_link_state(uce->state));
}

void unet_entity_remove_all_conn_match(struct unet_entity *ue,
		enum unet_conn_state state,
		enum unet_conn_type type,
		enum unet_conn_link_state link_state)
{
	struct unet_conn_entry *uce, *ucen;

	if (!ue || ue->type != unet_entity_type_local)
		return;

	spin_lock(&ue->conn_list_lock);
	unet_entity_for_each_conn_entry_safe(ue, uce, ucen) {
		if (!__conn_match(uce, state, type, link_state))
			continue;
		__unet_conn_entry_unlink(uce);

		spin_unlock(&ue->conn_list_lock);

		unet_conn_entry_destroy(uce);

		spin_lock(&ue->conn_list_lock);
	}
	spin_unlock(&ue->conn_list_lock);
}

void unet_entity_remove_all_conn(struct unet_entity *ue)
{
	unet_entity_remove_all_conn_match(ue,
			unet_conn_state_unknown,
			unet_conn_type_unknown,
			unet_conn_link_state_unknown);
}

const char *unet_conn_state_txt(enum unet_conn_state state)
{
	switch (state) {
	case unet_conn_state_unknown:
		return "unknown";
	case unet_conn_state_child_to_be:
		return "child-to-be";
	case unet_conn_state_child_connected:
		return "child-connected";
	case unet_conn_state_child_connected_past_timeout:
		return "child-connected-past-timeout";
	case unet_conn_state_child_disconnected:
		return "child-disconnected";
	case unet_conn_state_parent_to_be:
		return "parent-to-be";
	case unet_conn_state_parent_connected:
		return "parent-connected";
	case unet_conn_state_parent_connected_past_timeout:
		return "parent-connected-past-timeout";
	case unet_conn_state_parent_disconnected:
		return "parent-disconnected";
	default:
		break;
	}
	return "*unknown-state*";
}

const char *unet_conn_type_txt(enum unet_conn_type type)
{
	switch (type) {
	case unet_conn_type_unknown:
		return "unknown";
	case unet_conn_type_child:
		return "child";
	case unet_conn_type_parent:
		return "parent";
	}
	return "*unknown-type*";
}

const char *unet_conn_link_state_txt(enum unet_conn_link_state link_state)
{
	switch (link_state) {
	case unet_conn_link_state_unknown:
		return "unknown";
	case unet_conn_link_state_connected:
		return "connected";
	case unet_conn_link_state_disconnected:
		return "disconnected";
	}
	return "*unknown-link-state*";
}

void unet_conn_entry_set_state(struct unet_conn_entry *uce,
			       enum unet_conn_state state)
{
	struct unet_entity *ue, *conn_ue;
	enum unet_conn_state old_state;
	enum unet_conn_type type, old_type;
	enum unet_conn_link_state link_state, old_link_state;

	if (!uce)
		return;

	/* no state change */
	if (uce->state == state)
		return;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue)
		return;
	conn_ue = uce->ue;

	old_state = uce->state;
	old_type = unet_conn_state_to_type(old_state);
	old_link_state = unet_conn_state_to_link_state(old_state);

	/* are we switching types? */
	type = unet_conn_state_to_type(state);

	/* warn when changing types */
	if (old_type != type && old_state != unet_conn_state_unknown) {
		unet_conn_info(uce, "performing %s -> %s type transition\n",
			unet_conn_type_txt(old_type), unet_conn_type_txt(type));
	}

	/* commit to new state */
	uce->state = state;

	unet_conn_info(uce, "state %s -> %s\n",
		unet_conn_state_txt(old_state), unet_conn_state_txt(state));

	link_state = unet_conn_state_to_link_state(state);

	/* when link state doesn't change don't do anything more */
	if (old_link_state == link_state)
		return;

	unet_conn_info(uce, "link-state %s -> %s\n",
			unet_conn_link_state_txt(old_link_state),
			unet_conn_link_state_txt(link_state));

	switch (old_link_state) {
	case unet_conn_link_state_connected:
		/* common link cleanup */
		unet_conn_entry_cleanup_crypto(uce);
		unet_conn_entry_cleanup_reassembly(uce);
		/* specific type cleanup */
		switch (old_type) {
		case unet_conn_type_child:
			unet_entity_remove_next_hops_via_entity(ue, uce->ue);
			unet_entity_sysfs_remove_child(ue, conn_ue);
			break;
		case unet_conn_type_parent:
			unet_entity_sysfs_set_parent(ue, NULL);
			break;
		default:
			break;
		}
		break;
	case unet_conn_link_state_unknown:
	case unet_conn_link_state_disconnected:
		/* nothing to do when link was disconnected */
		break;
	}

	/* handle new link state */
	switch (link_state) {
	case unet_conn_link_state_connected:
		switch (type) {
		case unet_conn_type_child:
			unet_entity_sysfs_add_child(ue, conn_ue);
			break;
		case unet_conn_type_parent:
			unet_entity_sysfs_set_parent(ue, conn_ue);
			break;
		default:
			break;
		}
		/* common */
		unet_conn_entry_setup_reassembly(uce);
		if (unet_conn_entry_is_secure(uce))
			unet_conn_entry_setup_crypto(uce);

		/* update time */
		uce->last_rx_time = jiffies;
		/* clear keepalive count */
		uce->keepalive_count = 0;
		uce->keepalive_tx_time = 0;
		break;

	case unet_conn_link_state_unknown:
	case unet_conn_link_state_disconnected:
		/* going disconnected? nothing to do */
		break;
	default:
		break;
	}
}

int unet_conn_entry_setup_reassembly(struct unet_conn_entry *uce)
{
	enum unet_conn_type type;

	if (!uce)
		return -EINVAL;

	/* verify connection type */
	type = unet_conn_state_to_type(uce->state);
	if (type != unet_conn_type_parent &&
	    type != unet_conn_type_child)
		return -EINVAL;

	if (uce->frag_skb)
		kfree_skb(uce->frag_skb);
	uce->frag_skb = NULL;
	uce->frag_map = 0;
	uce->n_frags = 0;
	uce->frag_crc = 0;

	return 0;
}

void unet_conn_entry_cleanup_reassembly(struct unet_conn_entry *uce)
{
	if (!uce)
		return;

	if (uce->frag_skb)
		kfree_skb(uce->frag_skb);
	uce->frag_skb = NULL;
	uce->frag_map = 0;
	uce->n_frags = 0;
	uce->frag_crc = 0;
}

const char *unet_conn_entry_state_txt(enum unet_conn_state state)
{
	switch (state) {
	case unet_conn_state_unknown:
		return "unknown";
	case unet_conn_state_child_to_be:
		return "child_to_be";
	case unet_conn_state_child_connected:
		return "child_connected";
	case unet_conn_state_child_connected_past_timeout:
		return "child_connected_past_timeout";
	case unet_conn_state_child_disconnected:
		return "child_disconnected";
	case unet_conn_state_parent_to_be:
		return "parent_to_be";
	case unet_conn_state_parent_connected:
		return "parent_connected";
	case unet_conn_state_parent_connected_past_timeout:
		return "parent_connected_past_timeout";
	case unet_conn_state_parent_disconnected:
		return "parent_disconnected";
	default:
		break;
	}
	return "*BAD-STATE*";
}

const char *unet_conn_entry_type_txt(enum unet_conn_type type)
{
	switch (type) {
	case unet_conn_type_unknown:
		return "unknown";
	case unet_conn_type_child:
		return "child";
	case unet_conn_type_parent:
		return "parent";
	default:
		break;
	}
	return "*BAD-TYPE*";
}

struct unet_entity *
unet_conn_entry_to_entity(struct unet_conn_entry *uce)
{
	/* it's the parent of the kset which is our parent */
	if (!uce || !uce->kobj.parent || !uce->kobj.parent->parent)
		return NULL;

	return uce->local_ue;
}

struct unet_net *
unet_conn_entry_unet(struct unet_conn_entry *uce)
{
	if (!uce || !uce->local_ue)
		return NULL;

	return unet_entity_unet(uce->local_ue);
}

struct unet_conn_entry *
__unet_entity_get_conn_entry(struct unet_entity *ue,
			     enum unet_conn_state state,
			     enum unet_conn_type type,
			     enum unet_conn_link_state link_state)
{
	struct unet_conn_entry *uce, *uce_match = NULL;
	int nr_matches;
	bool match;

	if (!ue)
		return NULL;

	rcu_read_lock();
	nr_matches = 0;
	unet_entity_for_each_conn_entry_rcu(ue, uce) {
		match = __conn_match(uce, state, type, link_state);
		if (match && !uce_match)
			uce_match = uce;

		if (match)
			nr_matches++;
	}
	if (uce_match)
		__unet_conn_entry_get(uce_match);
	rcu_read_unlock();

	if (nr_matches > 1) {
		unet_entity_warn(ue, "Multiple matches for state=%s type=%s link-state=%s\n",
				 unet_conn_state_txt(state), unet_conn_type_txt(type),
				 unet_conn_link_state_txt(link_state));
	}

	return uce_match;
}
