/*
 * net/unet/conn.h: uNet conn entry definitions
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

#ifndef _UNET_CONN_H
#define _UNET_CONN_H

#include <linux/unet.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <crypto/aead.h>
#include <linux/kobject.h>

struct unet_entity;
struct unet_crypto_params;

/* connection is from an entity to a visible entity */
/* the parent and the children (or children to be) are connections */
enum unet_conn_state {
	/* unknown; just created */
	unet_conn_state_unknown,
	/* not yet baked */
	unet_conn_state_child_to_be,
	/* child is baked */
	unet_conn_state_child_connected,
	unet_conn_state_child_connected_past_timeout,
	unet_conn_state_child_disconnected,
	/* parent not yet baked */
	unet_conn_state_parent_to_be,
	/* parent is baked */
	unet_conn_state_parent_connected,
	unet_conn_state_parent_connected_past_timeout,
	unet_conn_state_parent_disconnected,
};

static inline bool unet_conn_state_needs_keep_alive(enum unet_conn_state state)
{
	return state == unet_conn_state_child_connected_past_timeout ||
	       state == unet_conn_state_child_disconnected ||
	       state == unet_conn_state_parent_connected_past_timeout ||
	       state == unet_conn_state_parent_disconnected;
}

enum unet_conn_type {
	unet_conn_type_unknown,
	unet_conn_type_child,
	unet_conn_type_parent,
};

enum unet_conn_link_state {
	unet_conn_link_state_unknown,
	unet_conn_link_state_connected,
	unet_conn_link_state_disconnected,
};

struct unet_conn_entry {
	struct kobject kobj;

	struct list_head node;
	bool unlinked;

	struct unet_entity *local_ue;
	struct unet_entity *ue;
	enum unet_conn_state state;
	unsigned long creation_time;
	unsigned long last_tx_time;
	unsigned long last_rx_time;
	unsigned int keepalive_count;
	unsigned long keepalive_tx_time;	/* last keep alive sent time */
	struct unet_trust_blob utb;		/* peer last sent tb */
	void *scratch;
	unsigned int scratch_size;

	/* security nonces */
	uint8_t nonce1[UNET_TB_NONCE_SIZE];
	uint8_t nonce2[UNET_TB_NONCE_SIZE];

	/* reassembly */
	uint64_t frag_map;
	uint8_t n_frags;
	struct sk_buff *frag_skb;
	uint16_t frag_crc;
	uint16_t frag_fullsize;

	/* crypto */
	uint8_t ck[UNET_MAX_KEY_SIZE];
	uint8_t pk[UNET_MAX_KEY_SIZE];
	uint8_t civ[UNET_MAX_IV_SIZE];
	uint8_t piv[UNET_MAX_IV_SIZE];
	uint8_t decbuf[UNET_MAX_TB_DECRYPT_SIZE];
	uint8_t dec_nonce1[UNET_TB_NONCE_SIZE];
	uint8_t dec_nonce2[UNET_TB_NONCE_SIZE];

	struct crypto_aead *tx_aead;
	struct crypto_aead *rx_aead;
	struct aead_request *tx_req;
	struct aead_request *rx_req;
	const struct unet_crypto_params *ucp;
	unsigned int iv_len;
	unsigned int blk_size;

	unsigned int keychain_size;
	uint8_t keychain[UNET_MAX_KEYCHAIN_SIZE];

	uint8_t has_keychain : 1;
	uint8_t has_nonce1 : 1;
	uint8_t has_nonce2 : 1;
	uint8_t has_ck : 1;
	uint8_t has_sk : 1;
	uint8_t has_dec_nonce1 : 1;
	uint8_t has_dec_nonce2 : 1;
	uint8_t crypto_ready : 1;
};

#define to_unet_conn_entry(_k) \
	container_of(_k, struct unet_conn_entry, kobj)

struct unet_entity *unet_conn_entry_to_entity(struct unet_conn_entry *uce);
struct unet_net *unet_conn_entry_unet(struct unet_conn_entry *uce);

static inline enum unet_conn_type
unet_conn_state_to_type(enum unet_conn_state state)
{
	switch (state) {
	case unet_conn_state_child_to_be:
	case unet_conn_state_child_connected:
	case unet_conn_state_child_connected_past_timeout:
	case unet_conn_state_child_disconnected:
		return unet_conn_type_child;
	case unet_conn_state_parent_to_be:
	case unet_conn_state_parent_connected:
	case unet_conn_state_parent_connected_past_timeout:
	case unet_conn_state_parent_disconnected:
		return unet_conn_type_parent;
	default:
		break;
	}
	return unet_conn_type_unknown;
}

static inline enum unet_conn_link_state
unet_conn_state_to_link_state(enum unet_conn_state state)
{
	switch (state) {
	case unet_conn_state_child_to_be:
	case unet_conn_state_parent_to_be:
		return unet_conn_link_state_disconnected;
	case unet_conn_state_child_connected:
	case unet_conn_state_child_connected_past_timeout:
	case unet_conn_state_child_disconnected:
	case unet_conn_state_parent_connected:
	case unet_conn_state_parent_connected_past_timeout:
	case unet_conn_state_parent_disconnected:
		return unet_conn_link_state_connected;
	default:
		break;
	}
	return unet_conn_link_state_unknown;
}

static inline struct unet_conn_entry *__unet_conn_entry_get(struct unet_conn_entry *uce)
{
	struct kobject *kobj;

	if (!uce)
		return NULL;
	kobj = kobject_get /* _unless_zero */ (&uce->kobj);
	if (!kobj)
		return NULL;
	return to_unet_conn_entry(kobj);
}

static inline void __unet_conn_entry_put(struct unet_conn_entry *uce)
{
	if (uce)
		kobject_put(&uce->kobj);
}

#if !IS_ENABLED(CONFIG_UNET_REFCOUNT_DEBUG)

#define unet_conn_entry_refcount_debug(_ucet) 0
#define __unet_conn_entry_debug_ref(__ucet, _caller) do { } while(0)

#define unet_conn_entry_create(_local_ue, _conn_ue, _state) \
	__unet_conn_entry_create(_local_ue, _conn_ue, _state)
#define unet_conn_entry_destroy(_uce) __unet_conn_entry_destroy(_uce)
#define unet_conn_entry_get(_uce) __unet_conn_entry_get(_uce)
#define unet_conn_entry_put(_uce) __unet_conn_entry_put(_uce)
#define unet_conn_entry_lookup(_ue, _conn_ue) __unet_conn_entry_lookup(_ue, _conn_ue)
#define unet_entity_get_conn_entry(_ue, _state, _type, _link_state) \
	__unet_entity_get_conn_entry(_ue, _state, _type, _link_state)

#else

#define unet_conn_entry_refcount_debug(_ucet0) \
	({ \
	 	struct unet_conn_entry *__ucet0 = (_ucet0); \
	 	\
		!IS_ERR_OR_NULL(__ucet0) && \
	 		unet_net_refcount_debug(unet_conn_entry_unet(__ucet0)); \
	})

#define __unet_conn_entry_debug_ref(_ucet, _caller, _pre_delta, _post_delta) \
	do { \
		struct unet_conn_entry *__ucet = (_ucet); \
		if (unet_conn_entry_refcount_debug(__ucet)) { \
			unsigned int __r = refcount_read(&__ucet->kobj.kref.refcount); \
			unsigned int __rpre = __r + (_pre_delta); \
			unsigned int __rpost = __r + (_post_delta); \
			const char *__name0 = kobject_name(&__ucet->local_ue->kobj); \
			const char *__name1 = kobject_name(&__ucet->ue->kobj); \
			const char *__caller = #_caller; \
			const char *__kind = "UCE"; \
			const char *__file = strrchr(__FILE__, '/'); \
			\
			if (__rpre < 0) \
				__rpre = 0; \
			if (__rpost < 0) \
				__rpost = 0; \
			__file = __file ? __file + 1 : __FILE__; \
			printk(KERN_INFO "unet: %-*s %p %-*s %*s-%-*s ref %u -> %u %*s() %s:%d\n", \
				UNET_DEBUG_REF_TYPE_SPAN, __kind, __ucet, \
				UNET_DEBUG_REF_FUNC_SPAN, __caller, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name0, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name1, \
				__rpre, __rpost, \
				UNET_DEBUG_REF_FUNC_SPAN, __func__, \
				__file, __LINE__); \
		} \
	} while(0)

#define unet_conn_entry_create(_local_ue, _conn_ue, _state) \
	({ \
		struct unet_conn_entry *__uce; \
		__uce = __unet_conn_entry_create(_local_ue, _conn_ue, _state); \
	 	__unet_conn_entry_debug_ref(__uce, unet_conn_entry_create, -INT_MAX, 0); \
	 	__uce; \
	})
#define unet_conn_entry_destroy(_uce) \
	({ \
		struct unet_conn_entry *__uce = (_uce); \
	 	__unet_conn_entry_debug_ref(__uce, unet_conn_entry_destroy, 0, 0); \
		__unet_conn_entry_destroy(__uce); \
	})
#define unet_conn_entry_get(_uce) \
	({ \
		struct unet_conn_entry *__uce = (_uce); \
	 	__unet_conn_entry_debug_ref(__uce, unet_conn_entry_get, 0, 1); \
		__unet_conn_entry_get(_uce); \
	})
#define unet_conn_entry_put(_uce) \
	({ \
		struct unet_conn_entry *__uce = (_uce); \
	 	__unet_conn_entry_debug_ref(__uce, unet_conn_entry_put, 0, -1); \
		__unet_conn_entry_put(_uce); \
	})
#define unet_conn_entry_lookup(_ue, _conn_ue) \
	({ \
		struct unet_conn_entry *__uce; \
		__uce = __unet_conn_entry_lookup(_ue, _conn_ue); \
	 	__unet_conn_entry_debug_ref(__uce, unet_conn_entry_lookup, -1, 0); \
		__uce; \
	})
#define unet_entity_get_conn_entry(_ue, _state, _type, _link_state) \
	({ \
		struct unet_conn_entry *__uce; \
		__uce = __unet_entity_get_conn_entry(_ue, _state, _type, _link_state); \
	 	__unet_conn_entry_debug_ref(__uce, unet_entity_get_conn_entry, -1, 0); \
		__uce; \
	})
#endif

int unet_conn_entry_setup(struct net *net);
void unet_conn_entry_cleanup(struct net *net);

int unet_entity_conn_setup(struct unet_entity *ue);
void unet_entity_conn_cleanup(struct unet_entity *ue);

struct unet_conn_entry *unet_conn_entry_alloc(gfp_t flags);
void unet_conn_entry_free(struct unet_conn_entry *uce);
void unet_conn_entry_release(struct kobject *kobj);

struct unet_conn_entry *
__unet_conn_entry_lookup(struct unet_entity *ue, struct unet_entity *ue_conn);
struct unet_conn_entry *
__unet_conn_entry_create(struct unet_entity *local_ue, struct unet_entity *conn_ue,
		       enum unet_conn_state state);

int __unet_conn_entry_unlink(struct unet_conn_entry *uce);
void __unet_conn_entry_destroy(struct unet_conn_entry *uce);

void unet_entity_remove_all_conn_match(struct unet_entity *ue,
		enum unet_conn_state state, enum unet_conn_type type,
		enum unet_conn_link_state link_state);
void unet_entity_remove_all_conn(struct unet_entity *ue);

static inline void unet_entity_remove_all_parents(struct unet_entity *ue)
{
	unet_entity_remove_all_conn_match(ue,
			unet_conn_state_unknown,
			unet_conn_type_parent,
			unet_conn_link_state_unknown);
}

void unet_conn_entry_set_state(struct unet_conn_entry *uce,
			       enum unet_conn_state state);

int unet_conn_entry_setup_reassembly(struct unet_conn_entry *uce);
void unet_conn_entry_cleanup_reassembly(struct unet_conn_entry *uce);

#define unet_entity_for_each_conn_entry(_ue, _uce) \
	list_for_each_entry(_uce, &(_ue)->conn_list, node)

#define unet_entity_for_each_conn_entry_safe(_ue, _uce, _ucen) \
	list_for_each_entry_safe(_uce, _ucen, &(_ue)->conn_list, node)

#define unet_entity_for_each_conn_entry_rcu(_ue, _uce) \
	list_for_each_entry_rcu(_uce, &(_ue)->conn_list, node)

const char *unet_conn_entry_state_txt(enum unet_conn_state state);
const char *unet_conn_entry_type_txt(enum unet_conn_type type);
const char *unet_conn_entry_link_state_txt(enum unet_conn_link_state link_state);

static inline bool unet_conn_entry_is_parent(struct unet_conn_entry *uce)
{
	enum unet_conn_type type;
	enum unet_conn_link_state link_state;

	if (!uce)
		return false;

	type = unet_conn_state_to_type(uce->state);
	link_state = unet_conn_state_to_link_state(uce->state);
	return type == unet_conn_type_parent &&
	       link_state == unet_conn_link_state_connected;
}

static inline bool unet_conn_entry_is_child(struct unet_conn_entry *uce)
{
	enum unet_conn_type type;
	enum unet_conn_link_state link_state;

	if (!uce)
		return false;

	type = unet_conn_state_to_type(uce->state);
	link_state = unet_conn_state_to_link_state(uce->state);
	return type == unet_conn_type_parent &&
	       link_state == unet_conn_link_state_connected;
}

static inline bool unet_conn_entry_is_parent_to_be(struct unet_conn_entry *uce)
{
	if (!uce)
		return false;

	return uce->state == unet_conn_state_parent_to_be;
}

static inline bool unet_conn_entry_is_child_to_be(struct unet_conn_entry *uce)
{
	if (!uce)
		return false;

	return uce->state == unet_conn_state_child_to_be;
}

struct unet_conn_entry *
__unet_entity_get_conn_entry(struct unet_entity *ue,
			     enum unet_conn_state state,
			     enum unet_conn_type type,
			     enum unet_conn_link_state link_state);

#endif
