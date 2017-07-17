/*
 * net/unet/router.c: uNet router methods
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
#include "router.h"
#include "sysfs.h"

#include <linux/module.h>
#include <linux/string.h>
#include <linux/lockdep.h>

static struct kmem_cache *unet_router_entry_cache;

int unet_router_entry_setup(struct net *net)
{
	unet_router_entry_cache = KMEM_CACHE(unet_router_entry, 0);
	if (!unet_router_entry_cache)
		return -ENOMEM;
	return 0;
}

void unet_router_entry_cleanup(struct net *net)
{
	kmem_cache_destroy(unet_router_entry_cache);
}

int unet_entity_router_setup(struct unet_entity *ue)
{
	if (!ue)
		return -EINVAL;

	INIT_LIST_HEAD(&ue->routers_list);
	spin_lock_init(&ue->routers_list_lock);
	return 0;
}

void unet_entity_router_cleanup(struct unet_entity *ue)
{
	/* nothing */
}

struct unet_router_entry *unet_router_entry_alloc(gfp_t flags)
{
	struct unet_router_entry *ure;

	ure = kmem_cache_alloc(unet_router_entry_cache, flags);
	if (!ure)
		return ERR_PTR(-ENOMEM);

	/* inefficient but works for now */
	memset(ure, 0, sizeof(*ure));

	return ure;
}

void unet_router_entry_free(struct unet_router_entry *ure)
{
	if (!ure)
		return;

	kmem_cache_free(unet_router_entry_cache, ure);
}

void unet_router_entry_release(struct kref *kref)
{
	struct unet_router_entry *ure = to_unet_router_entry(kref);

	if (unet_router_entry_refcount_debug(ure))
		printk(KERN_INFO "unet: %-*s %p %-*s\n",
				UNET_DEBUG_REF_TYPE_SPAN, "URE",
				ure,
				UNET_DEBUG_REF_FUNC_SPAN, __func__);

	unet_entity_put(ure->ue);
	unet_entity_put(ure->router_ue);

	unet_router_entry_free(ure);
}

struct unet_net *unet_router_entry_unet(struct unet_router_entry *ure)
{
	if (!ure || !ure->ue)
		return NULL;

	return unet_entity_unet(ure->ue);
}

struct unet_router_entry *
__unet_router_entry_lookup(struct unet_entity *ue, struct unet_entity *router_ue)
{
	struct unet_router_entry *ure, *ure_found = NULL;

	rcu_read_lock();
	unet_entity_for_each_router_entry_rcu(ue, ure) {
		if (ure->ue == router_ue) {
			ure_found = ure;
			break;
		}
	}
	ure = ure_found ? unet_router_entry_get(ure_found) : NULL;
	rcu_read_unlock();

	return ure;
}

int unet_entity_count_routers(struct unet_entity *ue)
{
	struct unet_router_entry *ure;
	int count;

	if (WARN_ON(!ue))
		return -EINVAL;

	if (WARN_ON(ue->type != unet_entity_type_local))
		return -EINVAL;

	count = 0;
	unet_entity_for_each_router_entry(ue, ure) {
		if (ure->rejected_us)
			continue;
		count++;
	}
	return count;
}

void __unet_router_entry_unlink(struct unet_router_entry *ure)
{
	struct unet_entity *ue;

	ue = ure->ue;
	lockdep_assert_held_once(&ue->routers_list_lock);

	list_del(&ure->node);

	WRITE_ONCE(ure->unlinked, true);
}

void __unet_router_entry_link(struct unet_router_entry *ure)
{
	struct unet_router_entry *uret;
	struct unet_entity *ue;

	ue = ure->ue;
	lockdep_assert_held_once(&ue->routers_list_lock);

	unet_entity_for_each_router_entry(ue, uret) {
		if (ure->parenting_score > uret->parenting_score) {
			/* add it before */
			list_add(&ure->node, &uret->node);
			goto done;
		}
	}
	list_add_tail(&ure->node, &ue->routers_list);
done:
	WRITE_ONCE(ure->unlinked, false);
}

struct unet_router_entry *
__unet_router_entry_create(struct unet_entity *ue, struct unet_entity *router_ue)
{
	struct unet_router_entry *ure;

	ure = unet_router_entry_alloc(GFP_KERNEL);
	if (!ure)
		return ERR_PTR(-ENOMEM);

	kref_init(&ure->kref);
	ure->ue = unet_entity_get(ue);
	ure->router_ue = unet_entity_get(router_ue);
	ure->rejected_us = false;
	ure->creation_time = jiffies;
	ure->parenting_score = unet_entity_parenting_score_from_prop(ue,
					&ure->router_ue->ae.prop);

	unet_entity_sysfs_add_router(ue, router_ue);

	spin_lock(&ue->routers_list_lock);
	__unet_router_entry_link(ure);
	spin_unlock(&ue->routers_list_lock);

	return ure;
}

void __unet_router_entry_destroy(struct unet_router_entry *ure)
{
	struct unet_entity *ue;

	if (!ure || !ure->ue)
		return;

	ue = ure->ue;

	if (!READ_ONCE(ure->unlinked)) {
		if (WARN_ON(spin_is_locked(&ue->routers_list_lock)))
			return;

		spin_lock(&ue->routers_list_lock);
		__unet_router_entry_unlink(ure);
		spin_unlock(&ue->routers_list_lock);
	}

	__unet_router_entry_put(ure);
}

int unet_entity_add_router(struct unet_entity *ue, struct unet_entity *router_ue)
{
	struct unet_router_entry *ure;

	if (!ue || !router_ue || ue->type != unet_entity_type_local)
		return -EINVAL;

	/* if it doesn't exist create it */
	ure = unet_router_entry_lookup(ue, router_ue);
	if (!ure) {
		ure = unet_router_entry_create(ue, router_ue);
		if (IS_ERR(ure))
			return PTR_ERR(ure);

		unet_router_info(ue, "create %s as router score=0x%llx\n",
				unet_entity_name(ure->router_ue),
				ure->parenting_score);

	} else {
		/* since we're adding means he accepts us */
		ure->rejected_us = false;
		ure->parenting_score = unet_entity_parenting_score_from_prop(ue,
						&ure->router_ue->ae.prop);

		spin_lock(&ue->routers_list_lock);
		__unet_router_entry_unlink(ure);
		__unet_router_entry_link(ure);
		spin_unlock(&ue->routers_list_lock);

		unet_router_entry_put(ure);

		unet_router_info(ue, "updated %s as router score=0x%llx\n",
				unet_entity_name(ure->router_ue),
				ure->parenting_score);
	}

	return 0;
}

void unet_entity_remove_router(struct unet_entity *ue,
		struct unet_entity *router_ue)
{
	struct unet_router_entry *ure;

	if (!ue || !router_ue || ue->type != unet_entity_type_local)
		return;

	ure = unet_router_entry_lookup(ue, router_ue);
	/* this is cool, it's a NOP */
	if (!ure)
		return;
	unet_router_entry_put(ure);

	unet_router_info(ue, "removed %s as router score=0x%llx\n",
			unet_entity_name(ure->router_ue),
			ure->parenting_score);

	spin_lock(&ue->routers_list_lock);
	__unet_router_entry_unlink(ure);
	spin_unlock(&ue->routers_list_lock);

	unet_router_entry_put(ure);
}

void unet_entity_remove_all_routers(struct unet_entity *ue, bool remove_rej)
{
	struct unet_router_entry *ure, *uret;

	if (WARN_ON(!ue))
		return;

	if (WARN_ON(ue->type != unet_entity_type_local))
		return;

	spin_lock(&ue->routers_list_lock);
	unet_entity_for_each_router_entry_safe(ue, ure, uret) {
		if (!remove_rej && ure->rejected_us) {
			if (time_before(jiffies, ure->rejection_clear))
				continue;
			/* rejection time is over, update */
			ure->rejected_us = false;
			/* and fall through to remove */
		}
		__unet_router_entry_unlink(ure);
		spin_unlock(&ue->routers_list_lock);

		unet_router_entry_destroy(ure);

		spin_lock(&ue->routers_list_lock);
	}
	spin_unlock(&ue->routers_list_lock);
}

struct unet_conn_entry *unet_entity_can_be_router(struct unet_entity *ue,
		struct unet_entity *check_ue)
{
	struct unet_router_entry *ure;
	struct unet_entity_prop *prop;
	struct unet_conn_entry *uce;
	bool conn_created, accepted;
	int err;

	if (!ue || !check_ue)
		return NULL;

	uce = unet_conn_entry_lookup(ue, check_ue);

	/* if a connection entry exists and is connected */
	if (uce && (unet_conn_entry_is_parent(uce) ||
		    unet_conn_entry_is_child(uce))) {
		goto out_fail;
	}

	/* if we have a force parent use it */
	prop = &ue->ae.prop;

	/* check score, if 0 means it's ineligible */
	if (!unet_entity_parenting_score_from_prop(ue, &check_ue->ae.prop))
		goto out_fail;

	/* check if the router has rejected us (and time has not passed) */
	ure = unet_router_entry_lookup(ue, check_ue);

	/* if he previously rejected us but now it's ok */
	if (ure && ure->rejected_us &&
	    time_after(jiffies, ure->rejection_clear))
		ure->rejected_us = false;

	accepted = !ure || (!ure->rejected_us && ure->parenting_score);

	if (ure)
		unet_router_entry_put(ure);

	if (!accepted)
		goto out_fail;

	if (uce) {
		unet_router_info(ue, "router conn entry (as parent) exists\n");
		if (uce->state != unet_conn_state_parent_to_be)
			unet_conn_entry_set_state(uce,
				unet_conn_state_parent_to_be);
		conn_created = false;
	} else {
		uce = unet_conn_entry_create(ue, check_ue,
				     unet_conn_state_parent_to_be);
		conn_created = true;
	}

	if (IS_ERR_OR_NULL(uce)) {
		unet_entity_err(ue, "can't create conn entry for router %s\n",
				unet_entity_name(check_ue));
		uce = NULL;
		goto out_fail;
	}

	/* secure mode? we have to verify */
	unet_router_info(ue, "router %s is in %ssecure %strusted mode\n",
			unet_entity_name(check_ue),
			unet_conn_entry_is_secure(uce) ? "" : "non-",
			unet_conn_entry_is_trusted(uce) ? "" : "non-");

	/* more to do if we're secure */
	if (unet_conn_entry_is_secure(uce)) {
		if (unet_remote_entity_is_decrypt_pending(check_ue)) {
			err = unet_entity_decrypt_pending(ue, check_ue);
			if (err) {
				unet_router_err(ue, "failed to decrypt on %s\n",
						unet_entity_name(check_ue));
				goto out_fail;
			}
		}

		unet_conn_entry_update_nonce1(uce);

		if (!uce->has_nonce1) {
			unet_entity_err(ue, "Needed NONCE1 for %s missing\n",
					unet_entity_name(check_ue));
			goto out_fail;
		}
	}

	/* one more reference when we've created it */
	if (conn_created)
		unet_conn_entry_get(uce);

	return uce;

out_fail:
	if (uce) {
		if (conn_created)
			unet_conn_entry_destroy(uce);
		else
			unet_conn_entry_put(uce);
	}
	return NULL;
}

struct unet_conn_entry *unet_entity_select_router(struct unet_entity *ue)
{
	struct unet_net *un = unet_entity_unet(ue);
	struct unet_router_entry *ure, *uren;
	struct unet_entity *ue_router;
	struct unet_conn_entry *uce = NULL;

	spin_lock(&ue->routers_list_lock);
	if (un->syslog_router_dump) {
		unet_entity_for_each_router_entry(ue, ure) {
			unet_router_info(ue, "%s score=0x%llx\n",
					unet_entity_name(ure->router_ue),
					ure->parenting_score);
		}
	}

	unet_entity_for_each_router_entry_safe(ue, ure, uren) {
		ue_router = ure->router_ue;
		spin_unlock(&ue->routers_list_lock);

		uce = unet_entity_can_be_router(ue, ue_router);
		if (uce)
			goto found;

		spin_lock(&ue->routers_list_lock);
	}
	spin_unlock(&ue->routers_list_lock);

found:
	if (uce) {
		if (un->syslog_router_dump)
			unet_router_info(ue, "%s selected\n",
					unet_entity_name(uce->ue));
		return uce;
	}

	return NULL;
}

void unet_entity_router_rejected_us(struct unet_entity *ue,
		struct unet_entity *router_ue)
{
	struct unet_net *un;
	struct unet_router_entry *ure;

	if (!ue || !router_ue || ue->type != unet_entity_type_local)
		return;

	ure = unet_router_entry_lookup(ue, router_ue);
	if (!ure)
		return;

	un = unet_entity_unet(ue);

	/* mark rejection & time where we're clear */
	ure->rejected_us = true;
	ure->rejection_clear = jiffies + un->reject_backoff;

	unet_router_entry_put(ure);
}

uint64_t unet_entity_parenting_score_from_prop(struct unet_entity *ue,
		struct unet_entity_prop *prop)
{
	struct unet_net *un;
	uint64_t score;
	uint32_t children;
	struct unet_addr *force_ua;

	if (!ue || !prop)
		return 0;

	/* if it can't be router score is 0 */
	if (!prop->can_be_router)
		return 0;

	/* get force router address (if it exists) */
	force_ua = &ue->force_parent_ua;
	if (!unet_addr_is_valid(force_ua))
		force_ua = NULL;

	/* using forced router? */
	if (force_ua) {
		if (unet_addr_eq(force_ua, &prop->ua))
			return (uint64_t)-1LLU;
		return 0;
	}

	un = unet_entity_unet(ue);

	/* get low-order 32 bits */
	if (!un->random_score_policy)
		score = unet_addr_hash(&prop->ua, JHASH_INITVAL);
	else
		score = prandom_u32();	/* pseudo random, good enough for this */

	/* guard against 0 (we use it as a mark of failure) */
	if (score == 0)
		score = 1;

	/* the 5 upper bits are log2(children-count) */
	if (un->children_count_policy) {
		children = prop->n_children;
		score |= ((uint64_t)(32 - ilog2(children))) << 32;
	}

	/* TODO add trust bits */

	return score;
}
