/*
 * net/unet/router.h: uNet router entry definitions
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

#ifndef _UNET_ROUTER_H
#define _UNET_ROUTER_H

#include <linux/unet.h>

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>

struct unet_entity;
struct unet_entity_prop;
struct unet_conn_entry;

struct unet_router_entry {
	struct kref kref;
	struct list_head node;
	struct unet_entity *ue;
	struct unet_entity *router_ue;
	unsigned long creation_time;
	bool rejected_us;
	unsigned long rejection_clear;
	bool unlinked;

	/* parenting score of this entity against us */
	uint64_t parenting_score;
};

#define to_unet_router_entry(_k) \
	container_of(_k, struct unet_router_entry, kref)

static inline struct unet_router_entry *
__unet_router_entry_get(struct unet_router_entry *ure)
{
	if (!ure || !kref_get_unless_zero(&ure->kref))
		return NULL;
	return ure;
}

void unet_router_entry_release(struct kref *kref);

static inline void __unet_router_entry_put(struct unet_router_entry *ure)
{
	if (ure)
		kref_put(&ure->kref, unet_router_entry_release);
}

struct unet_net *unet_router_entry_unet(struct unet_router_entry *ure);

struct unet_router_entry *
__unet_router_entry_lookup(struct unet_entity *ue, struct unet_entity *router_ue);

#if !IS_ENABLED(CONFIG_UNET_REFCOUNT_DEBUG)

#define unet_router_entry_refcount_debug(_uret) 0
#define __unet_router_entry_debug_ref(__uret, _caller) do { } while(0)

#define unet_router_entry_create(_ue, _router_ue) __unet_router_entry_create(_ue, _router_ue)
#define unet_router_entry_destroy(_ure) __unet_router_entry_destroy(_ure)
#define unet_router_entry_get(_ure) __unet_router_entry_get(_ure)
#define unet_router_entry_put(_ure) __unet_router_entry_put(_ure)
#define unet_router_entry_lookup(_ue, _router_ue) __unet_router_entry_lookup(_ue, _router_ue)

#else

#define unet_router_entry_refcount_debug(_uret0) \
	({ \
	 	struct unet_router_entry *__uret0 = (_uret0); \
	 	\
		!IS_ERR_OR_NULL(__uret0) && \
	 		unet_net_refcount_debug(unet_router_entry_unet(__uret0)); \
	})

#define __unet_router_entry_debug_ref(_uret, _caller, _pre_delta, _post_delta) \
	do { \
		struct unet_router_entry *__uret = (_uret); \
		if (unet_router_entry_refcount_debug(__uret)) { \
			unsigned int __r = refcount_read(&__uret->kref.refcount); \
			unsigned int __rpre = __r + (_pre_delta); \
			unsigned int __rpost = __r + (_post_delta); \
			const char *__name0 = kobject_name(&__uret->ue->kobj); \
			const char *__name1 = kobject_name(&__uret->router_ue->kobj); \
			const char *__caller = #_caller; \
			const char *__kind = "URE"; \
			const char *__file = strrchr(__FILE__, '/'); \
			\
			if (__rpre < 0) \
				__rpre = 0; \
			if (__rpost < 0) \
				__rpost = 0; \
			__file = __file ? __file + 1 : __FILE__; \
			printk(KERN_INFO "unet: %-*s %p %-*s %*s-%-*s ref %d -> %d %*s() %s:%d\n", \
				UNET_DEBUG_REF_TYPE_SPAN, __kind, __uret, \
				UNET_DEBUG_REF_FUNC_SPAN, __caller, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name0, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name1, \
				__rpre, __rpost, \
				UNET_DEBUG_REF_FUNC_SPAN, __func__, \
				__file, __LINE__); \
		} \
	} while(0)

#define unet_router_entry_create(_ue, _router_ue) \
	({ \
		struct unet_router_entry *__ure; \
		__ure = __unet_router_entry_create(_ue, _router_ue); \
	 	__unet_router_entry_debug_ref(__ure, unet_router_entry_create, -INT_MAX, 0); \
	 	__ure; \
	})
#define unet_router_entry_destroy(_ure) \
	({ \
		struct unet_router_entry *__ure = (_ure); \
	 	__unet_router_entry_debug_ref(__ure, unet_router_entry_destroy, 0, 0); \
		__unet_router_entry_destroy(__ure); \
	})
#define unet_router_entry_get(_ure) \
	({ \
		struct unet_router_entry *__ure = (_ure); \
	 	__unet_router_entry_debug_ref(__ure, unet_router_entry_get, 0, 1); \
		__unet_router_entry_get(__ure); \
	})
#define unet_router_entry_put(_ure) \
	({ \
		struct unet_router_entry *__ure = (_ure); \
	 	__unet_router_entry_debug_ref(__ure, unet_router_entry_put, 0, -1); \
		__unet_router_entry_put(__ure); \
	})
#define unet_router_entry_lookup(_ue, _ua) \
	({ \
		struct unet_router_entry *__ure; \
		__ure = __unet_router_entry_lookup(_ue, _ua); \
	 	__unet_router_entry_debug_ref(__ure, unet_router_entry_lookup, -1, 0); \
		__ure; \
	})
#endif

int unet_router_entry_setup(struct net *net);
void unet_router_entry_cleanup(struct net *net);

int unet_entity_router_setup(struct unet_entity *ue);
void unet_entity_router_cleanup(struct unet_entity *ue);

struct unet_router_entry *unet_router_entry_alloc(gfp_t flags);
void unet_router_entry_free(struct unet_router_entry *ure);

struct unet_router_entry *
__unet_router_entry_create(struct unet_entity *ue, struct unet_entity *router_ue);
void __unet_router_entry_destroy(struct unet_router_entry *ure);

void __unet_router_entry_link(struct unet_router_entry *ure);
void __unet_router_entry_unlink(struct unet_router_entry *ure);

int unet_entity_add_router(struct unet_entity *ue,
			   struct unet_entity *router_ue);
void unet_entity_remove_router(struct unet_entity *ue,
			       struct unet_entity *router_ue);
void unet_entity_remove_all_routers(struct unet_entity *ue, bool remove_rej);

struct unet_conn_entry *unet_entity_can_be_router(struct unet_entity *ue,
		struct unet_entity *check_ue);

struct unet_conn_entry *unet_entity_select_router(struct unet_entity *ue);
void unet_entity_router_rejected_us(struct unet_entity *ue,
		struct unet_entity *router_ue);
int unet_entity_count_routers(struct unet_entity *ue);
uint64_t unet_entity_parenting_score_from_prop(struct unet_entity *ue,
		struct unet_entity_prop *prop);

#define unet_entity_for_each_router_entry(_ue, _ure) \
	list_for_each_entry(_ure, &(_ue)->routers_list, node)

#define unet_entity_for_each_router_entry_rcu(_ue, _ure) \
	list_for_each_entry_rcu(_ure, &(_ue)->routers_list, node)

#define unet_entity_for_each_router_entry_safe(_ue, _ure, _uren) \
	list_for_each_entry_safe(_ure, _uren, &(_ue)->routers_list, node)

#endif
