/*
 * net/unet/next_hop.c: uNet next hop methods
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
#include "next_hop.h"
#include "sysfs.h"

#include <linux/module.h>
#include <linux/string.h>

static struct kmem_cache *unet_next_hop_entry_cache;

static u32 unet_next_hop_entry_key_hash(const void *data, u32 len, u32 seed)
{
	const struct unet_addr *ua = data;

	return unet_addr_hash(ua, seed);
}

static u32 unet_next_hop_entry_hash(const void *data, u32 len, u32 seed)
{
	const struct unet_next_hop_entry *unhe = data;

	return unet_next_hop_entry_key_hash(&unhe->ua, len, seed);
}

static int unet_next_hop_entry_cmp(struct rhashtable_compare_arg *arg,
				     const void *obj)
{
	const struct unet_next_hop_entry *unhe = obj;

	return !unet_hash_addr_eq(&unhe->ua, arg->key);
}

static const struct rhashtable_params unet_next_hop_entry_rht_params = {
	.nelem_hint		= 6,
	.head_offset		= offsetof(struct unet_next_hop_entry, rnode),
	.key_offset		= offsetof(struct unet_next_hop_entry, ua),
	.max_size		= 64,
	.min_size		= 8,
	.automatic_shrinking	= true,
	.hashfn			= unet_next_hop_entry_key_hash,
	.obj_hashfn		= unet_next_hop_entry_hash,
	.obj_cmpfn		= unet_next_hop_entry_cmp,
};

int unet_entity_next_hop_setup(struct unet_entity *ue)
{
	if (!ue)
		return -EINVAL;

	/* initialize next-hop list */
	INIT_LIST_HEAD(&ue->next_hop_list);
	spin_lock_init(&ue->next_hop_lock);

	/* initialize hash table */
	return rhashtable_init(&ue->next_hop_rht,
			&unet_next_hop_entry_rht_params);
}

void unet_entity_next_hop_cleanup(struct unet_entity *ue)
{
	if (!ue)
		return;

	rhashtable_destroy(&ue->next_hop_rht);
}

int unet_next_hop_entry_setup(struct net *net)
{
	unet_next_hop_entry_cache = KMEM_CACHE(unet_next_hop_entry, 0);
	if (!unet_next_hop_entry_cache)
		return -ENOMEM;
	return 0;
}

void unet_next_hop_entry_cleanup(struct net *net)
{
	kmem_cache_destroy(unet_next_hop_entry_cache);
}

struct unet_next_hop_entry *unet_next_hop_entry_alloc(gfp_t flags)
{
	struct unet_next_hop_entry *unhe;

	unhe = kmem_cache_alloc(unet_next_hop_entry_cache, flags);
	if (!unhe)
		return ERR_PTR(-ENOMEM);

	/* inefficient but works for now */
	memset(unhe, 0, sizeof(*unhe));

	return unhe;
}

void unet_next_hop_entry_free(struct unet_next_hop_entry *unhe)
{
	if (!unhe)
		return;

	kmem_cache_free(unet_next_hop_entry_cache, unhe);
}

void unet_next_hop_entry_release(struct kref *kref)
{
	struct unet_next_hop_entry *unhe = to_unet_next_hop_entry(kref);

	if (unet_next_hop_entry_refcount_debug(unhe))
		printk(KERN_INFO "unet: %-*s %p %-*s\n",
				UNET_DEBUG_REF_TYPE_SPAN, "UNHE",
				unhe,
				UNET_DEBUG_REF_FUNC_SPAN, __func__);

	if (unhe->ua_str != unhe->ua_str_buf)
		kfree(unhe->ua_str);
	unet_entity_put(unhe->ue);
	unet_entity_put(unhe->ue_nh);

	unet_next_hop_entry_free(unhe);
}

struct unet_net *unet_next_hop_entry_unet(struct unet_next_hop_entry *unhe)
{
	if (!unhe || !unhe->ue)
		return NULL;

	return unet_entity_unet(unhe->ue);
}

struct unet_next_hop_entry *
__unet_next_hop_entry_lookup(struct unet_entity *ue, struct unet_addr *ua)
{
	struct unet_next_hop_entry *unhe;

	if (!ue || !ua)
		return NULL;

	rcu_read_lock();
	unhe = rhashtable_lookup(&ue->next_hop_rht, ua,
			unet_next_hop_entry_rht_params);
	if (unhe)
		unhe = unet_next_hop_entry_get(unhe);
	rcu_read_unlock();

	return unhe;
}

struct unet_next_hop_entry *
__unet_next_hop_entry_create(struct unet_entity *ue, struct unet_addr *ua,
		       struct unet_entity *ue_nh)
{
	struct unet_next_hop_entry *unhe;
	char *str = NULL;
	int err;

	str = unet_addr_to_str(GFP_KERNEL, ua);
	if (!str)
		return ERR_PTR(-ENOMEM);

	unhe = unet_next_hop_entry_alloc(GFP_KERNEL);
	if (!unhe) {
		err = -ENOMEM;
		goto out_fail_alloc;
	}

	kref_init(&unhe->kref);
	unhe->ue = unet_entity_get(ue);
	unhe->ue_nh = unet_entity_get(ue_nh);
	unet_addr_copy(&unhe->ua, ua);
	unhe->add_time = jiffies;

	if ((strlen(str) + 1) <= sizeof(unhe->ua_str_buf)) {
		strcpy(unhe->ua_str_buf, str);
		unhe->ua_str = unhe->ua_str_buf;
		kfree(str);
		str = NULL;
	} else
		unhe->ua_str = str;

	/* insert to the hash table */
	spin_lock(&ue->next_hop_lock);
	err = rhashtable_insert_fast(&ue->next_hop_rht, &unhe->rnode,
			unet_next_hop_entry_rht_params);
	if (!err)
		list_add_tail(&unhe->node, &ue->next_hop_list);
	spin_unlock(&ue->next_hop_lock);

	if (err)
		goto out_fail_rht;

	return unhe;

out_fail_rht:
	unet_entity_put(unhe->ue);
	unet_entity_put(unhe->ue_nh);
	if (unhe->ua_str != unhe->ua_str_buf)
		kfree(unhe->ua_str);
	unet_next_hop_entry_free(unhe);
out_fail_alloc:
	if (str)
		kfree(str);
	return ERR_PTR(err);
}

int unet_next_hop_entry_update(struct unet_next_hop_entry *unhe,
			       struct unet_entity *ue_nh)
{
	struct unet_entity *uet;

	if (!unhe || !ue_nh)
		return -EINVAL;

	/* refresh add time */
	unhe->add_time = jiffies;
	if (unhe->ue_nh != ue_nh) {
		uet = unhe->ue_nh;
		unhe->ue_nh = unet_entity_get(ue_nh);
		unet_entity_put(uet);
	}
	return 0;
}

int unet_entity_add_next_hop(struct unet_entity *ue, struct unet_addr *ua,
		struct unet_entity *ue_nh)
{
	struct unet_next_hop_entry *unhe;
	int err;

	if (!ue || !ue_nh || !ua || ue->type != unet_entity_type_local)
		return -EINVAL;

	/* next_hop already exists - add it */
	unhe = unet_next_hop_entry_lookup(ue, ua);
	if (unhe) {
		err = unet_next_hop_entry_update(unhe, ue_nh);
		unet_next_hop_entry_put(unhe);
	} else {
		unhe = unet_next_hop_entry_create(ue, ua, ue_nh);
		if (IS_ERR(unhe))
			err = PTR_ERR(unhe);
		else
			err = 0;
	}
	return err;
}

int __unet_next_hop_entry_unlink(struct unet_next_hop_entry *unhe)
{
	struct unet_entity *ue;
	int err;

	ue = unhe->ue;

	lockdep_assert_held_once(&ue->next_hop_lock);

	err = rhashtable_remove_fast(&ue->next_hop_rht, &unhe->rnode,
			unet_next_hop_entry_rht_params);
	if (!err) {
		list_del(&unhe->node);

		WRITE_ONCE(unhe->unlinked, true);
	}

	return err;
}

void __unet_next_hop_entry_destroy(struct unet_next_hop_entry *unhe)
{
	struct unet_entity *ue;
	int err;

	if (!unhe || !unhe->ue)
		return;

	ue = unhe->ue;

	if (!READ_ONCE(unhe->unlinked)) {
		if (WARN_ON(spin_is_locked(&ue->next_hop_lock)))
			return;

		spin_lock(&ue->next_hop_lock);
		err = __unet_next_hop_entry_unlink(unhe);
		spin_unlock(&ue->next_hop_lock);

		if (WARN_ON(err))
			return;
	}

	__unet_next_hop_entry_put(unhe);
}

void unet_entity_remove_next_hop_by_addr(struct unet_entity *ue,
		struct unet_addr *ua)
{
	struct unet_next_hop_entry *unhe;

	if (!ue || ue->type != unet_entity_type_local || !ua)
		return;

	unhe = unet_next_hop_entry_lookup(ue, ua);
	if (unhe) {
		unet_next_hop_entry_put(unhe);
		unet_next_hop_entry_destroy(unhe);
	}
}

void unet_entity_remove_next_hops_via_entity(struct unet_entity *ue,
		struct unet_entity *ue_nh)
{
	struct unet_next_hop_entry *unhe, *unhet;

	if (!ue || !ue_nh || ue->type != unet_entity_type_local)
		return;

	spin_lock(&ue->next_hop_lock);
	unet_entity_for_each_next_hop_entry_safe(ue, unhe, unhet) {
		if (unhe->ue_nh != ue_nh)
			continue;
		__unet_next_hop_entry_unlink(unhe);
		spin_unlock(&ue->next_hop_lock);

		unet_next_hop_entry_destroy(unhe);

		spin_lock(&ue->next_hop_lock);
	}
	spin_unlock(&ue->next_hop_lock);
}

void unet_entity_remove_all_next_hops(struct unet_entity *ue)
{
	struct unet_next_hop_entry *unhe, *unhet;

	if (!ue || ue->type != unet_entity_type_local)
		return;

	spin_lock(&ue->next_hop_lock);
	unet_entity_for_each_next_hop_entry_safe(ue, unhe, unhet) {
		__unet_next_hop_entry_unlink(unhe);
		spin_unlock(&ue->next_hop_lock);

		unet_next_hop_entry_destroy(unhe);

		spin_lock(&ue->next_hop_lock);
	}
	spin_unlock(&ue->next_hop_lock);
}

void unet_entity_remove_all_next_hops_via_entity(struct unet_net *un,
		struct unet_entity *ue_nh)
{
	struct unet_entity *ue, *uen;

	spin_lock(&un->entity_list_lock);
	list_for_each_entry_safe(ue, uen, &un->local_entity_list, node) {
		spin_unlock(&un->entity_list_lock);

		unet_entity_remove_next_hops_via_entity(ue, ue_nh);

		spin_lock(&un->entity_list_lock);
	}
	spin_unlock(&un->entity_list_lock);
}

struct unet_entity *
unet_entity_get_next_hop(struct unet_entity *ue, struct unet_addr *ua)
{
	struct unet_next_hop_entry *unhe;
	struct unet_entity *ue_nh;

	unhe = unet_next_hop_entry_lookup(ue, ua);
	if (!unhe)
		return NULL;

	ue_nh = unet_entity_get(unhe->ue_nh);
	unet_next_hop_entry_put(unhe);

	return ue_nh;
}
