/*
 * net/unet/next_hop.h: uNet next hop entry definitions
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

#ifndef _UNET_NEXT_HOP_H
#define _UNET_NEXT_HOP_H

#include <linux/unet.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>

struct unet_entity;

#define UNET_NEXT_HOP_ENTRY_UA_STR_SMALL	32

struct unet_next_hop_entry {
	struct kref kref;
	struct rhash_head rnode;
	struct rcu_head rcu;
	struct list_head node;
	bool unlinked;
	struct unet_addr ua;
	char *ua_str;	/* may point to ua_str_buf if < UA_STR_SMALL */
	struct unet_entity *ue;
	struct unet_entity *ue_nh;
	unsigned long add_time;
	char ua_str_buf[UNET_NEXT_HOP_ENTRY_UA_STR_SMALL];
};

#define to_unet_next_hop_entry(_k) \
	container_of(_k, struct unet_next_hop_entry, kref)

static inline struct unet_next_hop_entry *
__unet_next_hop_entry_get(struct unet_next_hop_entry *unhe)
{
	if (!unhe || !kref_get_unless_zero(&unhe->kref))
		return NULL;
	return unhe;
}

void unet_next_hop_entry_release(struct kref *kref);

static inline void __unet_next_hop_entry_put(struct unet_next_hop_entry *unhe)
{
	if (unhe)
		kref_put(&unhe->kref, unet_next_hop_entry_release);
}

struct unet_net *unet_next_hop_entry_unet(struct unet_next_hop_entry *unhe);

#if !IS_ENABLED(CONFIG_UNET_REFCOUNT_DEBUG)

#define unet_next_hop_entry_refcount_debug(_unhet) 0
#define __unet_next_hop_entry_debug_ref(__unhet, _caller) do { } while(0)

#define unet_next_hop_entry_create(_ue, _ua, _ue_nh) __unet_next_hop_entry_create(_ue, _ua, _ue_nh)
#define unet_next_hop_entry_destroy(_unhe) __unet_next_hop_entry_destroy(_unhe)
#define unet_next_hop_entry_get(_unhe) __unet_next_hop_entry_get(_unhe)
#define unet_next_hop_entry_put(_unhe) __unet_next_hop_entry_put(_unhe)
#define unet_next_hop_entry_lookup(_ue, _ua) __unet_next_hop_entry_lookup(_ue, _ua)
#else

#define unet_next_hop_entry_refcount_debug(_unhet0) \
	({ \
	 	struct unet_next_hop_entry *__unhet0 = (_unhet0); \
	 	\
		!IS_ERR_OR_NULL(__unhet0) && \
	 		unet_net_refcount_debug(unet_next_hop_entry_unet(__unhet0)); \
	})

#define __unet_next_hop_entry_debug_ref(_unhet, _caller, _pre_delta, _post_delta) \
	do { \
		struct unet_next_hop_entry *__unhet = (_unhet); \
		if (unet_next_hop_entry_refcount_debug(__unhet)) { \
			unsigned int __r = refcount_read(&__unhet->kref.refcount); \
			unsigned int __rpre = __r + (_pre_delta); \
			unsigned int __rpost = __r + (_post_delta); \
			const char *__name0 = kobject_name(&__unhet->ue->kobj); \
			const char *__name1 = kobject_name(&__unhet->ue_nh->kobj); \
			const char *__caller = #_caller; \
			const char *__kind = "UNHE"; \
			const char *__file = strrchr(__FILE__, '/'); \
			\
			if (__rpre < 0) \
				__rpre = 0; \
			if (__rpost < 0) \
				__rpost = 0; \
			__file = __file ? __file + 1 : __FILE__; \
			printk(KERN_INFO "unet: %-*s %p %-*s %*s-%-*s ref %d -> %d %*s() %s:%d\n", \
				UNET_DEBUG_REF_TYPE_SPAN, __kind, __unhet, \
				UNET_DEBUG_REF_FUNC_SPAN, __caller, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name0, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name1, \
				__rpre, __rpost, \
				UNET_DEBUG_REF_FUNC_SPAN, __func__, \
				__file, __LINE__); \
		} \
	} while(0)

#define unet_next_hop_entry_create(_ue, _ua, _nh_ue) \
	({ \
		struct unet_next_hop_entry *__unhe; \
		__unhe = __unet_next_hop_entry_create(_ue, _ua, _nh_ue); \
	 	__unet_next_hop_entry_debug_ref(__unhe, unet_next_hop_entry_create, -INT_MAX, 0); \
	 	__unhe; \
	})
#define unet_next_hop_entry_destroy(_unhe) \
	({ \
		struct unet_next_hop_entry *__unhe = (_unhe); \
	 	__unet_next_hop_entry_debug_ref(__unhe, unet_next_hop_entry_destroy, 0, 0); \
		__unet_next_hop_entry_destroy(__unhe); \
	})
#define unet_next_hop_entry_get(_unhe) \
	({ \
		struct unet_next_hop_entry *__unhe = (_unhe); \
	 	__unet_next_hop_entry_debug_ref(__unhe, unet_next_hop_entry_get, 0, 1); \
		__unet_next_hop_entry_get(__unhe); \
	})
#define unet_next_hop_entry_put(_unhe) \
	({ \
		struct unet_next_hop_entry *__unhe = (_unhe); \
	 	__unet_next_hop_entry_debug_ref(__unhe, unet_next_hop_entry_put, 0, -1); \
		__unet_next_hop_entry_put(__unhe); \
	})
#define unet_next_hop_entry_lookup(_ue, _ua) \
	({ \
		struct unet_next_hop_entry *__unhe; \
		__unhe = __unet_next_hop_entry_lookup(_ue, _ua); \
	 	__unet_next_hop_entry_debug_ref(__unhe, unet_next_hop_entry_lookup, -1, 0); \
		__unhe; \
	})
#endif

int unet_next_hop_entry_setup(struct net *net);
void unet_next_hop_entry_cleanup(struct net *net);

int unet_entity_next_hop_setup(struct unet_entity *ue);
void unet_entity_next_hop_cleanup(struct unet_entity *ue);

struct unet_next_hop_entry *unet_next_hop_entry_alloc(gfp_t flags);
void unet_next_hop_entry_free(struct unet_next_hop_entry *unhe);

struct unet_next_hop_entry *
__unet_next_hop_entry_create(struct unet_entity *ue, struct unet_addr *ua,
		       struct unet_entity *ue_nh);
void __unet_next_hop_entry_destroy(struct unet_next_hop_entry *unhe);

#define unet_entity_for_each_next_hop_entry(_ue, _unhe) \
	list_for_each_entry(_unhe, &(_ue)->next_hop_list, node)

#define unet_entity_for_each_next_hop_entry_safe(_ue, _unhe, _unhen) \
	list_for_each_entry_safe(_unhe, _unhen, &(_ue)->next_hop_list, node)

#define unet_entity_for_each_next_hop_entry_rcu(_ue, _unhe) \
	list_for_each_entry_rcu(_unhe, &(_ue)->next_hop_list, node)

struct unet_next_hop_entry *
__unet_next_hop_entry_lookup(struct unet_entity *ue, struct unet_addr *ua);
int unet_entity_add_next_hop(struct unet_entity *ue, struct unet_addr *ua,
		struct unet_entity *ue_nh);
void unet_entity_remove_next_hop_by_addr(struct unet_entity *ue,
		struct unet_addr *ua);
void unet_entity_remove_next_hops_via_entity(struct unet_entity *ue,
		struct unet_entity *ue_nh);
void unet_entity_remove_all_next_hops(struct unet_entity *ue);
void unet_entity_remove_all_next_hops_via_entity(struct unet_net *un,
		struct unet_entity *ue_nh);

struct unet_entity *
unet_entity_get_next_hop(struct unet_entity *ue, struct unet_addr *ua);

#endif
