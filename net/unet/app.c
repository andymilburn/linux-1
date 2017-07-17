/*
 * net/unet/app.c: uNet app methods
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
#include "app.h"
#include "sysfs.h"

#include <linux/module.h>
#include <linux/string.h>

struct unet_net *unet_app_entry_unet(struct unet_app_entry *uae)
{
	if (!uae)
		return NULL;

	return unet_net(unet_app_entry_net(uae));
}

static struct kmem_cache *unet_app_entry_cache;

static u32 unet_app_entry_key_hash(const void *data, u32 len, u32 seed)
{
	const struct unet_addr *ua = data;

	return unet_addr_app_hash(ua, seed);
}

static u32 unet_app_entry_hash(const void *data, u32 len, u32 seed)
{
	const struct unet_app_entry *unhe = data;

	return unet_app_entry_key_hash(&unhe->ua, len, seed);
}

static int unet_app_entry_cmp(struct rhashtable_compare_arg *arg,
				     const void *obj)
{
	const struct unet_app_entry *unhe = obj;

	return !unet_hash_addr_app_eq(&unhe->ua, arg->key);
}

static const struct rhashtable_params unet_app_entry_rht_params = {
	.nelem_hint		= 6,
	.head_offset		= offsetof(struct unet_app_entry, rnode),
	.key_offset		= offsetof(struct unet_app_entry, ua),
	.max_size		= 64,
	.min_size		= 8,
	.automatic_shrinking	= true,
	.hashfn			= unet_app_entry_key_hash,
	.obj_hashfn		= unet_app_entry_hash,
	.obj_cmpfn		= unet_app_entry_cmp,
};

int unet_app_entry_setup(struct net *net)
{
	struct unet_net *un = unet_net(net);
	int err;

	err = rhashtable_init(&un->app_addr_rht, &unet_app_entry_rht_params);
	if (err)
		return err;

	unet_app_entry_cache = KMEM_CACHE(unet_app_entry, 0);
	if (!unet_app_entry_cache) {
		err = -ENOMEM;
		goto out_no_app_entry_cache;
	}
	return 0;

out_no_app_entry_cache:
	rhashtable_destroy(&un->app_addr_rht);
	return err;
}

void unet_app_entry_cleanup(struct net *net)
{
	struct unet_net *un = unet_net(net);

	kmem_cache_destroy(unet_app_entry_cache);
	rhashtable_destroy(&un->app_addr_rht);
}

struct unet_app_entry *unet_app_entry_alloc(gfp_t flags)
{
	struct unet_app_entry *uae;

	uae = kmem_cache_alloc(unet_app_entry_cache, flags);
	if (!uae)
		return ERR_PTR(-ENOMEM);

	/* inefficient but works for now */
	memset(uae, 0, sizeof(*uae));

	return uae;
}

void unet_app_entry_free(struct unet_app_entry *uae)
{
	if (!uae)
		return;

	kmem_cache_free(unet_app_entry_cache, uae);
}

void unet_app_entry_release(struct kobject *kobj)
{
	struct unet_app_entry *uae = to_unet_app_entry(kobj);

	if (unet_app_entry_refcount_debug(uae))
		printk(KERN_INFO "unet: %-*s %p %-*s\n",
				UNET_DEBUG_REF_TYPE_SPAN, "UAE",
				uae,
				UNET_DEBUG_REF_FUNC_SPAN, __func__);

	unet_app_entry_free(uae);
}

struct unet_app_entry *
__unet_app_entry_lookup(struct unet_net *un, struct unet_addr *ua)
{
	struct unet_app_entry *uae;

	if (!un || !ua)
		return NULL;

	rcu_read_lock();
	uae = rhashtable_lookup(&un->app_addr_rht, ua,
			unet_app_entry_rht_params);

	if (uae)
		uae = __unet_app_entry_get(uae);
	rcu_read_unlock();

	return uae;
}

struct unet_app_entry *__unet_app_entry_create(struct unet_net *un,
					       struct unet_entity_cfg *uec)
{
	struct unet_app_entry *uae;
	int err;

	if (!un || !uec)
		return ERR_PTR(-EINVAL);

	/* app already exists - add it */
	uae = unet_app_entry_lookup(un, &uec->ua);
	if (uae) {
		unet_app_entry_put(uae);
		return ERR_PTR(-EEXIST);
	}

	uae = unet_app_entry_alloc(GFP_KERNEL);
	if (!uae)
		return ERR_PTR(-ENOMEM);

	write_pnet(&uae->net, unet_to_net(un));
	unet_addr_copy(&uae->ua, &uec->ua);
	uae->ephemeral_id = -1;	/* not ephemeral */

	/* TODO crypto */

	err = unet_app_entry_create_sysfs(uae);
	if (err)
		goto out_fail_sysfs;

	/* insert to the hash table */
	spin_lock(&un->app_list_lock);
	err = rhashtable_insert_fast(&un->app_addr_rht, &uae->rnode,
			unet_app_entry_rht_params);
	if (!err)
		list_add_tail(&uae->node, &un->app_list);
	spin_unlock(&un->app_list_lock);

	if (err)
		goto out_fail_rht;

	return uae;

out_fail_rht:
	unet_app_entry_destroy_sysfs(uae);
out_fail_sysfs:
	unet_app_entry_free(uae);
	return ERR_PTR(err);
}

struct unet_app_entry *__unet_app_entry_create_ephemeral(struct unet_net *un)
{
	struct unet_app_entry *uae;
	int err, id;
	char idbuf[22];	/* good for 64 bit */
	struct unet_addr *ua;

	if (!un)
		return ERR_PTR(-EINVAL);

	ua = kzalloc(sizeof(*ua), GFP_KERNEL);
	if (!ua)
		return ERR_PTR(-ENOMEM);

	err = ida_simple_get(&un->app_ephemeral_ida, 0, INT_MAX, GFP_KERNEL);
	if (err < 0)
		goto out_fail_ida;
	id = err;

	snprintf(idbuf, sizeof(idbuf), "%d", id);

	unet_addr_fill(ua, NULL, 0, NULL, 0,
			"#", 1, idbuf, strlen(idbuf));

	uae = unet_app_entry_alloc(GFP_KERNEL);
	if (!uae) {
		err = -ENOMEM;
		goto out_fail_alloc;
	}

	write_pnet(&uae->net, unet_to_net(un));
	unet_addr_copy(&uae->ua, ua);
	uae->ephemeral_id = id;

	err = unet_app_entry_create_sysfs(uae);
	if (err)
		goto out_fail_sysfs;

	/* insert to the hash table */
	spin_lock(&un->app_list_lock);
	err = rhashtable_insert_fast(&un->app_addr_rht, &uae->rnode,
			unet_app_entry_rht_params);
	if (!err)
		list_add_tail(&uae->node, &un->app_list);
	spin_unlock(&un->app_list_lock);

	if (err)
		goto out_fail_rht;

	return uae;

out_fail_rht:
	unet_app_entry_destroy_sysfs(uae);
out_fail_sysfs:
	unet_app_entry_free(uae);
out_fail_alloc:
	ida_simple_remove(&un->app_ephemeral_ida, id);
out_fail_ida:
	kfree(ua);
	return ERR_PTR(err);
}

int __unet_app_entry_unlink(struct unet_app_entry *uae)
{
	struct unet_net *un;
	int err;

	un = unet_app_entry_unet(uae);
	lockdep_assert_held_once(&un->app_list_lock);

	err = rhashtable_remove_fast(&un->app_addr_rht, &uae->rnode,
			unet_app_entry_rht_params);
	if (!err) {
		list_del(&uae->node);
		WRITE_ONCE(uae->unlinked, true);
	}

	return err;
}


void __unet_app_entry_destroy(struct unet_app_entry *uae)
{
	struct unet_net *un;
	int err;

	if (!uae)
		return;

	un = unet_app_entry_unet(uae);

	if (!READ_ONCE(uae->unlinked)) {
		if (WARN_ON(spin_is_locked(&un->app_list_lock)))
			return;

		spin_lock(&un->app_list_lock);
		err = __unet_app_entry_unlink(uae);
		spin_unlock(&un->app_list_lock);

		if (WARN_ON(err))
			return;
	}

	if (uae->ephemeral_id != -1)
		ida_simple_remove(&un->app_ephemeral_ida, uae->ephemeral_id);

	unet_app_entry_destroy_sysfs(uae);

	__unet_app_entry_put(uae);
}
