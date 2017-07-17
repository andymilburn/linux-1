/*
 * net/unet/core.h: uNet core global declarations
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

#ifndef _UNET_CORE_H
#define _UNET_CORE_H

#include <linux/unet.h>

//#include <asm/hardirq.h>
#include <crypto/aead.h>
#include <crypto/public_key.h>
#include <keys/system_keyring.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/idr.h>
#include <linux/in.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/rhashtable.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/wait.h>
#include <linux/if.h>

#include "crypto.h"
#include "packet.h"
#include "bearer.h"
#include "router.h"
#include "next_hop.h"
#include "conn.h"
#include "socket.h"
#include "app.h"
#include "dev.h"

#define UNET_MOD_VER "0.1"

extern int unet_net_id __read_mostly;

extern struct unet_addr unet_root_addr;

struct unet_entity_prop {
	struct unet_addr ua;
	unsigned int dev_class;
	bool can_be_router;
	unsigned int n_children;
	unsigned int n_routers;
};

struct unet_entity_cfg {
	struct unet_addr ua;
	unsigned int dev_class;
	bool can_be_router;
	struct unet_addr force_parent_ua;
	key_ref_t cert_key;
	void *cert_blob;
	unsigned int cert_blob_size;

	key_ref_t priv_key;

	/* true when own cert verifies again trust chain */
	bool keys_trusted;
	/* true when private & public keys match */
	bool keys_verified;

	/* forced outgoing mtu */
	unsigned int forced_mtu;

	/* link device? */
	char devname[IFNAMSIZ];
};

enum unet_entity_type {
	unet_entity_type_local,
	unet_entity_type_remote,
};

struct unet_entity;

/*
 * A single address entry for an entity
 * It contains a single address origininating from this entity
 */
struct unet_entity_address_entry {
	struct rhash_head node;
	struct unet_entity_prop prop;
};

#define unet_address_entry_to_entity(_ueae) \
	container_of(_ueae, struct unet_entity, ae)

struct unet_entity;
struct unet_crypto_params;

/* maximum 8 chain of trust certs allowed */
#define UNET_TRUST_CHAIN_MAX	8

struct unet_net {
	possible_net_t net;

	int index;	/* index number (used for debugging) */

	struct unet_bearer __rcu *bearer_list[UNET_MAX_BEARERS + 1];

	/* entities */
	spinlock_t entity_list_lock;
	struct list_head local_entity_list;
	struct list_head remote_entity_list;
	struct rhashtable entity_addr_rht;

	/* app entries */
	spinlock_t app_list_lock;
	struct list_head app_list;
	struct rhashtable app_addr_rht;
	struct ida app_ephemeral_ida;

	/* workqueue */
	struct workqueue_struct *workqueue;

	/* configuration */
	unsigned int alive_timeout;	/* in milli-seconds */
	unsigned int apcr_min_timeout;	/* defaults */
	unsigned int apcr_max_timeout;
	unsigned int apcr_timeout;
	unsigned int apca_timeout;
	unsigned int register_timeout;
	unsigned int register_retries;
	unsigned int reject_backoff;	/* time which we honor rejection */

	bool random_score_policy;
	bool children_count_policy;
	bool only_forward_from_valid_senders;
	bool relay_disconnect_announce_upstream;
	bool try_reconnect_to_children;
	bool force_relay_rfdr_upstream;
	bool force_relay_da_upstream;
	bool strict_hierarchical_routing;

	unsigned int housekeeping_timeout;
	unsigned int child_idle_timeout;
	unsigned int child_to_be_timeout;
	unsigned int keepalive_max;
	unsigned int keepalive_period;	/* period between sending KAs */
	unsigned int reply_apca_timeout;

	/* crypto keyring */
	char *config_keys_name;
	struct key *config_keys;
	char *remote_keys_name;
	struct key *remote_keys;
	/* the trust chain */
	key_ref_t trust_chain[UNET_TRUST_CHAIN_MAX];
	unsigned int alg_count;
	uint8_t alg[UNET_CRYPTO_ALG_COUNT];

	/* socket stuff */
	struct hlist_head raw_head;
	rwlock_t raw_lock;

	struct hlist_head dgram_head;
	rwlock_t dgram_lock;

	/* slow path task */
	struct task_struct *kthread;
	/* the wait queue for the slow path task */
	wait_queue_head_t kthread_wq;

	/* the list of received packets for deferred processing */
	struct sk_buff_head rx_skb_list;

	/* should be in debugfs? */
	bool syslog_packet_dump;
	bool syslog_fsm_dump;
	bool syslog_conn_dump;
	bool syslog_crypto_dump;
	bool syslog_router_dump;
	bool syslog_bearer_dump;
	bool syslog_refcount_dump;

	/* pseudo netdev to make iproute happy */
	struct net_device *unet_dev;
};

void unet_kthread_schedule(struct unet_net *un);

enum unet_entity_state {
	/* state when first created */
	unet_entity_state_unknown,
	/* local entity states */
	unet_entity_state_unregistered,
	unet_entity_state_registration_pending,
	unet_entity_state_registered,
	unet_entity_state_disconnected,
	unet_entity_state_error,
};

struct unet_entity {
	struct kobject kobj;
	struct rcu_head rcu;

	enum unet_entity_type type;
	enum unet_entity_state state;

	possible_net_t net;
	struct list_head node;

	spinlock_t lock;

	volatile unsigned long pending_events;

	/* address entry of this entity */
	struct unet_entity_address_entry ae;
	bool unlinked;

	/* cert & private key (when available) */
	key_ref_t cert_key;
	unsigned int cert_key_enc_size;
	void *cert_blob;
	unsigned int cert_blob_size;
	uint16_t cert_blob_crc;
	bool keys_trusted;

	union {	/* unnamed union */
		struct {	/* local entity */
			/* for APCR */
			struct delayed_work apcr_timeout_dwork;
			unsigned long apcr_timeout;	/* non-zero when active */
			bool apcr_timeout_active;

			/* time to wait collecting APCAs */
			struct delayed_work apca_timeout_dwork;
			unsigned long apca_timeout;
			bool apca_timeout_active;

			/* time before sending another register */
			struct delayed_work register_timeout_dwork;
			unsigned long register_timeout;
			bool register_timeout_active;
			unsigned int register_retries;

			/* housekeeping timeout */
			struct delayed_work housekeeping_timeout_dwork;
			unsigned long housekeeping_timeout;
			bool housekeeping_timeout_active;

			/* connections (children parents and children to be) */
			struct list_head conn_list;
			struct kset *conn_kset;
			spinlock_t conn_list_lock;

			/* router entries (sorted) */
			struct list_head routers_list;
			spinlock_t routers_list_lock;

			/* last RC uuid (for detecting loops) */
			unsigned char rc_uuid[16];

			/* next-hop entries */
			struct list_head next_hop_list;
			/* hash table for fast lookup */
			struct rhashtable next_hop_rht;
			spinlock_t next_hop_lock;

			/* when configured locally as such */
			struct unet_addr force_parent_ua;

			/* force a maximum MTU to all outgoing frames */
			unsigned int forced_mtu;

			key_ref_t priv_key;
			unsigned int priv_key_dec_size;
			bool keys_verified;

			/* netdev for tunneling */
			struct net_device *dev;
			struct sk_buff_head tx_ip_skb_list;
		};

		struct {	/* remote entity */
			/* for keeping alive (non local) */
			struct delayed_work alive_timeout_dwork;
			unsigned long alive_timeout;
			bool alive_timeout_active;

			/* bearer of last packet */
			struct unet_bearer *b;
			/* media address of last packet */
			struct unet_media_addr media_addr;

			/* trust blob in progress */
			struct unet_trust_blob utb;
		};
	};
};

#define to_unet_entity(_k) \
	container_of(_k, struct unet_entity, kobj)

static inline struct unet_addr *unet_entity_addr(struct unet_entity *ue)
{
	if (!ue)
		return NULL;

	return &ue->ae.prop.ua;
}

static inline const char *unet_entity_name(struct unet_entity *ue)
{
	if (!ue)
		return "(NULL)";

	return kobject_name(&ue->kobj);
}

static inline struct unet_net *unet_net(struct net *net)
{
	return net_generic(net, unet_net_id);
}

static inline struct net *unet_to_net(struct unet_net *un)
{
	return read_pnet(&un->net);
}

static inline struct net *unet_entity_net(const struct unet_entity *ue)
{
	return read_pnet(&ue->net);
}

static inline struct unet_net *unet_entity_unet(struct unet_entity *ue)
{
	if (!ue)
		return NULL;

	return unet_net(unet_entity_net(ue));
}

static inline struct unet_entity *__unet_entity_get(struct unet_entity *ue)
{
	struct kobject *kobj;

	if (!ue || READ_ONCE(ue->unlinked))
		return NULL;
	kobj = kobject_get /* _unless_zero */ (&ue->kobj);
	if (!kobj)
		return NULL;
	return to_unet_entity(kobj);
}

static inline void __unet_entity_put(struct unet_entity *ue)
{
	if (ue)
		kobject_put(&ue->kobj);
}

void unet_entity_release(struct kobject *kobj);

#define UNET_DEBUG_REF_TYPE_SPAN	4
#define UNET_DEBUG_REF_FUNC_SPAN	34
#define UNET_DEBUG_REF_ENTITY_NAME_SPAN 10

#if !IS_ENABLED(CONFIG_UNET_REFCOUNT_DEBUG)

#define unet_net_refcount_debug(_un) 0
#define unet_entity_refcount_debug(_ue) 0
#define __unet_entity_debug_ref(__uet, _caller) do { } while(0)

#define unet_local_entity_create(_un, _uec) __unet_local_entity_create(_un, _uec)
#define unet_remote_entity_create(_un, _skb) __unet_remote_entity_create(_un, _skb)
#define unet_entity_destroy(_ue) __unet_entity_destroy(_ue)
#define unet_entity_get(_ue) __unet_entity_get(_ue)
#define unet_entity_put(_ue) __unet_entity_put(_ue)
#define unet_entity_lookup_by_addr(_un, _ua) __unet_entity_lookup_by_addr(_un, _ua)
#define unet_get_first_local_entity(_un) __unet_get_first_local_entity(_un)
#define unet_entity_get_parent(_ue) __unet_entity_get_parent(_ue)
#define unet_entity_get_registering_router(_ue) __unet_entity_get_registering_router(_ue)

#else

#define unet_net_refcount_debug(_unt) \
	({ \
		struct unet_net *__unt = (_unt); \
	 	__unt && __unt->syslog_refcount_dump; \
	})

#define unet_entity_refcount_debug(_uet0) \
	({ \
	 	struct unet_entity *__uet0 = (_uet0); \
	 	\
		!IS_ERR_OR_NULL(__uet0) && \
	 		unet_net_refcount_debug(unet_entity_unet(__uet0)); \
	})

#define __unet_entity_debug_ref(_uet, _caller, _pre_delta, _post_delta) \
	do { \
		struct unet_entity *__uet = (_uet); \
		if (unet_entity_refcount_debug(__uet)) { \
			unsigned int __r = refcount_read(&__uet->kobj.kref.refcount); \
			unsigned int __rpre = __r + (_pre_delta); \
			unsigned int __rpost = __r + (_post_delta); \
			const char *__name = kobject_name(&__uet->kobj); \
			const char *__caller = #_caller; \
			const char *__kind = "UE"; \
			const char *__file = strrchr(__FILE__, '/'); \
			\
			if (__rpre < 0) \
				__rpre = 0; \
			if (__rpost < 0) \
				__rpost = 0; \
			__file = __file ? __file + 1 : __FILE__; \
			printk(KERN_INFO "unet: %-*s %p %-*s %*s%*s ref %d -> %d %*s() %s:%d\n", \
				UNET_DEBUG_REF_TYPE_SPAN, __kind, __uet, \
				UNET_DEBUG_REF_FUNC_SPAN, __caller, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN, __name, \
				UNET_DEBUG_REF_ENTITY_NAME_SPAN + 1, "", \
				__rpre, __rpost, \
				UNET_DEBUG_REF_FUNC_SPAN, __func__, \
				__file, __LINE__); \
		} \
	} while(0)

#define unet_local_entity_create(_un, _uec) \
	({ \
		struct unet_entity *__ue; \
		__ue = __unet_local_entity_create(_un, _uec); \
		__unet_entity_debug_ref(__ue, unet_local_entity_create, -INT_MAX, 0); \
	 	__ue; \
	})
#define unet_remote_entity_create(_un, _skb) \
	({ \
		struct unet_entity *__ue; \
		__ue = __unet_remote_entity_create(_un, _skb); \
		__unet_entity_debug_ref(__ue, unet_remote_entity_create, -INT_MAX, 0); \
	 	__ue; \
	})
#define unet_entity_destroy(_ue) \
	({ \
		struct unet_entity *__ue = (_ue); \
		__unet_entity_debug_ref(__ue, unet_entity_destroy, 0, 0); \
		__unet_entity_destroy(__ue); \
	})
#define unet_entity_get(_ue) \
	({ \
		struct unet_entity *__ue = (_ue); \
		__unet_entity_debug_ref(__ue, unet_entity_get, 0, 1); \
		__unet_entity_get(__ue); \
	})
#define unet_entity_put(_ue) \
	({ \
		struct unet_entity *__ue = (_ue); \
		__unet_entity_debug_ref(__ue, unet_entity_put, 0, -1); \
		__unet_entity_put(__ue); \
	})
#define unet_entity_lookup_by_addr(_un, _ua) \
	({ \
		struct unet_entity *__ue; \
		__ue = __unet_entity_lookup_by_addr(_un, _ua); \
		__unet_entity_debug_ref(__ue, unet_entity_lookup_by_addr, -1, 0); \
		__ue; \
	})
#define unet_get_first_local_entity(_un) \
	({ \
		struct unet_entity *__ue; \
		__ue = __unet_get_first_local_entity(_un); \
		__unet_entity_debug_ref(__ue, unet_entity_get_first_local_entity, -1, 0); \
		__ue; \
	})
#define unet_entity_get_parent(_ue) \
	({ \
		struct unet_entity *__ue; \
		\
		__ue = __unet_entity_get_parent(_ue); \
		__unet_entity_debug_ref(__ue, unet_entity_get_parent, -1, 0); \
		__ue; \
	})
#define unet_entity_get_registering_router(_ue) \
	({ \
		struct unet_entity *__ue; \
		\
		__ue = __unet_entity_get_registering_router(_ue); \
		__unet_entity_debug_ref(__ue, unet_entity_get_registering_router, -1, 0); \
		__ue; \
	})
#endif

#define unet_for_each_local_entity(_un, _ue) \
	list_for_each_entry(_ue, &(_un)->local_entity_list, node)

#define unet_for_each_local_entity_safe(_un, _ue, _uen) \
	list_for_each_entry_safe(_ue, _uen, &(_un)->local_entity_list, node)

#define unet_for_each_local_entity_rcu(_un, _ue) \
	list_for_each_entry_rcu(_ue, &(_un)->local_entity_list, node)

#define unet_for_each_remote_entity(_un, _ue) \
	list_for_each_entry(_ue, &(_un)->remote_entity_list, node)

#define unet_for_each_remote_entity_safe(_un, _ue, _uen) \
	list_for_each_entry_safe(_ue, _uen, &(_un)->remote_entity_list, node)

#define unet_for_each_remote_entity_rcu(_un, _ue) \
	list_for_each_entry_rcu(_ue, &(_un)->remote_entity_list, node)

bool unet_entity_is_a_match(struct unet_entity *ue,
			    struct unet_entity *check_ue,
			    enum unet_conn_type type,
			    enum unet_conn_link_state link_state);

static inline bool
unet_entity_is_child(struct unet_entity *ue, struct unet_entity *check_ue)
{
	return unet_entity_is_a_match(ue, check_ue, unet_conn_type_child,
				      unet_conn_link_state_connected);
}

static inline bool
unet_entity_is_parent(struct unet_entity *ue, struct unet_entity *check_ue)
{
	return unet_entity_is_a_match(ue, check_ue, unet_conn_type_parent,
				      unet_conn_link_state_connected);
}

int unet_entity_count_children(struct unet_entity *ue);

int unet_entity_get_n_children(struct unet_entity *ue);
int unet_entity_get_n_routers(struct unet_entity *ue);

void unet_entity_mark_child_alive(struct unet_entity *ue,
		struct unet_entity *ue_conn);
bool unet_entity_needs_keep_alive(struct unet_entity *ue,
		struct unet_entity *next_hop_ue);

void unet_entity_send_to_all_visible_children(struct unet_entity *ue,
		uint32_t message_type, const void *data, size_t data_sz);
bool unet_entity_can_i_be_router(struct unet_entity *ue,
				 struct unet_entity *ue_child,
				 bool *send_reply);

struct unet_entity *unet_entity_alloc(gfp_t flags);
void unet_entity_free(struct unet_entity *ue);

struct unet_entity *
__unet_entity_get_parent(struct unet_entity *ue);
struct unet_entity *
__unet_entity_get_registering_router(struct unet_entity *ue);

#define UNET_PROP_CHANGE_DEV_CLASS		BIT(0)
#define UNET_PROP_CHANGE_I_CAN_BE_ROUTER	BIT(1)
#define UNET_PROP_CHANGE_N_CHILDREN		BIT(2)
#define UNET_PROP_CHANGE_N_ROUTERS		BIT(3)
#define UNET_PROP_CHANGE_CERT			BIT(4)
#define UNET_PROP_CHANGE_ENCRYPTED		BIT(5)

int unet_entity_update_from_packet(struct unet_entity *ue,
		struct sk_buff *skb, struct unet_packet_header *uph);

struct unet_entity *
unet_entity_create(struct unet_net *un, enum unet_entity_type type);

/* remove from lists */
int __unet_entity_unlink(struct unet_entity *ue);
/* perform destroy and a put */
void __unet_entity_destroy(struct unet_entity *ue);

struct unet_entity *
__unet_local_entity_create(struct unet_net *un, const struct unet_entity_cfg *uec);

struct unet_entity *
__unet_remote_entity_create(struct unet_net *un, struct sk_buff *skb);

struct unet_entity *
__unet_entity_lookup_by_addr(struct unet_net *un, const struct unet_addr *ua);

struct unet_entity *
unet_entity_get_destination(struct unet_entity *ue, struct unet_addr *dest_ua);

int unet_entity_send_to_visible(struct unet_entity *orig_ue,
				struct unet_entity *dest_ue,
				struct unet_conn_entry *uce,
				uint32_t message_type, const void *data,
				size_t data_sz);
int unet_entity_send(struct unet_entity *orig_ue,
		     struct unet_addr *orig_ua, struct unet_addr *dest_ua,
		     uint32_t message_type, const void *data, size_t data_sz);
int unet_entity_send_msg(struct unet_entity *orig_ue,
			 struct unet_addr *orig_ua, struct unet_addr *dest_ua,
			 uint32_t message_type, struct msghdr *msg, int size);
int unet_entity_forward(struct unet_entity *ue_sender,
			struct unet_entity *ue_next_hop,
			struct sk_buff *skb);

bool unet_entity_i_can_be_router(struct unet_entity *ue,
				 struct unet_entity *dest_ue);

bool unet_entity_reference(struct unet_entity *ue,
			   struct unet_entity *check_ue);
bool unet_entity_referenced_by_local_entity(struct unet_entity *ue);

int unet_entity_prune_remotes(struct unet_net *un);

struct unet_entity *__unet_get_first_local_entity(struct unet_net *un);

/* method to reparent for tests; not part of the protocol */
int unet_entity_set_parent_by_addr(struct unet_entity *ue, struct unet_addr *ua);

void unet_entity_disconnect(struct unet_entity *ue);
void unet_entity_reconnect(struct unet_entity *ue);
void unet_entity_reparent(struct unet_entity *ue);

void unet_entity_housekeeping(struct unet_entity *ue);

int unet_entity_reserve_dgram_mt(struct unet_entity *ue, int mt,
				 gfp_t flags);
void unet_entity_unreserve_dgram_mt(struct unet_entity *ue, int mt);

#define unet_entity_timeout_decl(_name) \
void unet_entity_start_##_name##_timeout(struct unet_entity *ue, \
		unsigned long timeout); \
void unet_entity_stop_##_name##_timeout(struct unet_entity *ue); \
bool unet_entity_is_##_name##_timeout_running(struct unet_entity *ue); \
void unet_entity_##_name##_timeout_dwork(struct work_struct *work)

enum unet_fsm_event_type;
void unet_entity_fire_timeout_event(struct unet_entity *ue,
		enum unet_fsm_event_type type);

unet_entity_timeout_decl(apcr);
unet_entity_timeout_decl(apca);
unet_entity_timeout_decl(register);
unet_entity_timeout_decl(housekeeping);

unet_entity_timeout_decl(alive);

#endif
