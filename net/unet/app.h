/*
 * net/unet/app.h: uNet app definitions
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

#ifndef _UNET_APP_H
#define _UNET_APP_H

#include <linux/unet.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

struct unet_entity;
struct unet_net;

struct unet_app_entry {
	struct kobject kobj;
	struct rcu_head rcu;

	struct list_head node;
	struct rhash_head rnode;
	bool unlinked;

	possible_net_t net;
	struct unet_addr ua;

	/* TODO crypto stuff */
	key_ref_t cert_key;
	unsigned int cert_key_enc_size;
	void *cert_blob;
	unsigned int cert_blob_size;
	uint16_t cert_blob_crc;
	bool keys_trusted;
	key_ref_t priv_key;
	unsigned int priv_key_dec_size;
	bool keys_verified;

	int ephemeral_id;
};

#define to_unet_app_entry(_k) \
	container_of(_k, struct unet_app_entry, kobj)

static inline struct unet_addr *unet_app_entry_addr(struct unet_app_entry *uae)
{
	if (!uae)
		return NULL;

	return &uae->ua;
}

static inline const char *unet_app_entry_name(struct unet_app_entry *uae)
{
	if (!uae)
		return "(NULL)";

	return kobject_name(&uae->kobj);
}

static inline struct net *unet_app_entry_net(const struct unet_app_entry *uae)
{
	return read_pnet(&uae->net);
}

static inline struct unet_app_entry *__unet_app_entry_get(struct unet_app_entry *uae)
{
	struct kobject *kobj;

	if (!uae)
		return NULL;

	kobj = kobject_get /* _unless_zero */ (&uae->kobj);
	if (!kobj)
		return NULL;

	return to_unet_app_entry(kobj);
}

static inline void __unet_app_entry_put(struct unet_app_entry *uae)
{
	if (uae)
		kobject_put(&uae->kobj);
}

#if !IS_ENABLED(CONFIG_UNET_REFCOUNT_DEBUG)

#define unet_app_entry_refcount_debug(_uaet) 0
#define __unet_app_entry_debug_ref(__uaet, _caller) do { } while(0)

#define unet_app_entry_create(_un, _uec) __unet_app_entry_create(_un, _uec)
#define unet_app_entry_create_ephemeral(_un) __unet_app_entry_create_ephemeral(_un)
#define unet_app_entry_destroy(_uae) __unet_app_entry_destroy(_uae)
#define unet_app_entry_get(_uae) __unet_app_entry_get(_uae)
#define unet_app_entry_put(_uae) __unet_app_entry_put(_uae)
#define unet_app_entry_lookup(_ue, _app_ue) __unet_app_entry_lookup(_ue, _app_ue)

#else

#define unet_app_entry_refcount_debug(_uaet0) \
	({ \
	 	struct unet_app_entry *__uaet0 = (_uaet0); \
	 	\
		!IS_ERR_OR_NULL(__uaet0) && \
	 		unet_net_refcount_debug(unet_app_entry_unet(__uaet0)); \
	})

#define __unet_app_entry_debug_ref(_uaet, _caller, _pre_delta, _post_delta) \
	do { \
		struct unet_app_entry *__uaet = (_uaet); \
		if (unet_app_entry_refcount_debug(__uaet)) { \
			unsigned int __r = refcount_read(&__uaet->kobj.kref.refcount); \
			unsigned int __rpre = __r + (_pre_delta); \
			unsigned int __rpost = __r + (_post_delta); \
			const char *__name = kobject_name(&__uaet->kobj); \
			const char *__caller = #_caller; \
			const char *__kind = "UAE"; \
			const char *__file = strrchr(__FILE__, '/'); \
			\
			if (__rpre < 0) \
				__rpre = 0; \
			if (__rpost < 0) \
				__rpost = 0; \
			__file = __file ? __file + 1 : __FILE__; \
			printk(KERN_INFO "unet: %-*s %p %-*s %*s%*s ref %u -> %u %*s() %s:%d\n", \
				UNET_DEBUG_REF_TYPE_SPAN, __kind, __uaet, \
				UNET_DEBUG_REF_FUNC_SPAN, __caller, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN + 1, "", \
				__rpre, __rpost, \
				UNET_DEBUG_REF_FUNC_SPAN, __func__, \
				__file, __LINE__); \
		} \
	} while(0)

#define unet_app_entry_create(_un, _uec) \
	({ \
		struct unet_app_entry *__uae; \
		__uae = __unet_app_entry_create(_un, _uec); \
	 	__unet_app_entry_debug_ref(__uae, unet_app_entry_create, -INT_MAX, 0); \
	 	__uae; \
	})
#define unet_app_entry_create_ephemeral(_un) \
	({ \
		struct unet_app_entry *__uae; \
		__uae = __unet_app_entry_create_ephemeral(_un); \
	 	__unet_app_entry_debug_ref(__uae, unet_app_entry_create_ephemeral, -INT_MAX, 0); \
	 	__uae; \
	})
#define unet_app_entry_destroy(_uae) \
	({ \
		struct unet_app_entry *__uae = (_uae); \
	 	__unet_app_entry_debug_ref(__uae, unet_app_entry_destroy, 0, 0); \
		__unet_app_entry_destroy(__uae); \
	})
#define unet_app_entry_get(_uae) \
	({ \
		struct unet_app_entry *__uae = (_uae); \
	 	__unet_app_entry_debug_ref(__uae, unet_app_entry_get, 0, 1); \
		__unet_app_entry_get(_uae); \
	})
#define unet_app_entry_put(_uae) \
	({ \
		struct unet_app_entry *__uae = (_uae); \
	 	__unet_app_entry_debug_ref(__uae, unet_app_entry_get, 0, -1); \
		__unet_app_entry_put(_uae); \
	})
#define unet_app_entry_lookup(_un, _ua) \
	({ \
		struct unet_app_entry *__uae; \
		__uae = __unet_app_entry_lookup(_un, _ua); \
	 	__unet_app_entry_debug_ref(__uae, unet_app_entry_lookup, -1, 0); \
		__uae; \
	})
#endif

struct unet_net *unet_app_entry_unet(struct unet_app_entry *uae);

int unet_app_entry_setup(struct net *net);
void unet_app_entry_cleanup(struct net *net);

struct unet_app_entry *unet_app_entry_alloc(gfp_t flags);
void unet_app_entry_free(struct unet_app_entry *uae);
void unet_app_entry_release(struct kobject *kobj);

#define unet_for_each_app_entry(_un, _ue) \
	list_for_each_entry(_ue, &(_un)->app_list, node)

#define unet_for_each_app_entry_safe(_un, _ue, _uen) \
	list_for_each_entry_safe(_ue, _uen, &(_un)->app_list, node)

#define unet_for_each_app_entry_rcu(_un, _ue) \
	list_for_each_entry_rcu(_ue, &(_un)->app_list, node)

struct unet_app_entry *
__unet_app_entry_lookup(struct unet_net *un, struct unet_addr *ua);

struct unet_app_entry *__unet_app_entry_create(struct unet_net *un,
					       struct unet_entity_cfg *uec);
struct unet_app_entry *__unet_app_entry_create_ephemeral(struct unet_net *un);

int __unet_app_entry_unlink(struct unet_app_entry *uae);
void __unet_app_entry_destroy(struct unet_app_entry *uae);

#endif
