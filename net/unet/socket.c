/*
 * net/unet/socket.c: UNET socket code
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

#include <net/sock.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rwlock.h>
#include <linux/sysfs.h>
#include <linux/unet.h>

#include "core.h"
#include "bearer.h"
#include "utils.h"

static int unet_raw_hash(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);

	if (!un)
		return -ENOTSUPP;

	write_lock_bh(&un->raw_lock);
	sk_add_node(sk, &un->raw_head);
	sock_prot_inuse_add(net, sk->sk_prot, 1);
	write_unlock_bh(&un->raw_lock);

	return 0;
}

static void unet_raw_unhash(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);

	if (!un)
		return;

	write_lock_bh(&un->raw_lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(net, sk->sk_prot, -1);
	write_unlock_bh(&un->raw_lock);
}

static void unet_raw_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

static int unet_raw_bind(struct sock *sk, struct sockaddr *_uaddr, int len)
{
	struct unet_sock *usk = unet_sk(sk);
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);
	struct sockaddr_unet *sun = (struct sockaddr_unet *)_uaddr;
	struct unet_entity *ue = NULL;
	int err = 0;

	if (!un)
		return -ENOTSUPP;

	if (sun->sunet_family != AF_UNET)
		return -EINVAL;

	lock_sock(sk);

	/* lookup entity */
	ue = unet_entity_lookup_by_addr(un, &sun->sunet_addr.addr);
	if (!ue || ue->type != unet_entity_type_local) {
		err = -ENODEV;
		goto out;
	}
	usk->bound_ue = ue;

	usk->rcv_sua.sunet_family = AF_UNET;
	usk->rcv_sua.sunet_addr.message_type = 0;	/* do not use mt */
	unet_addr_copy(&usk->rcv_sua.sunet_addr.addr, &sun->sunet_addr.addr);

	sk_dst_reset(sk);
out:

	if (err && ue)
		unet_entity_put(ue);

	release_sock(sk);

	return err;
}

static int unet_dgram_bind(struct sock *sk, struct sockaddr *_uaddr, int len)
{
	struct unet_sock *usk = unet_sk(sk);
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);
	struct sockaddr_unet *sun = (struct sockaddr_unet *)_uaddr;
	struct unet_entity *ue = NULL;
	struct unet_addr *ua, *ua_ue, *ua_uae;
	struct unet_app_entry *uae = NULL;
	int mt;
	int err = 0;

	if (!un)
		return -ENOTSUPP;

	/* lookup entity */
	ua = &sun->sunet_addr.addr;
	mt = (int)sun->sunet_addr.message_type;

	/* verify that the address makes sense */
	if (sun->sunet_family != AF_UNET || !unet_addr_is_valid(ua))
		return -EINVAL;

	/* cannot bind message type that's reserved for system */
	if (mt && (mt < UNET_MSG_USER_START || mt >= UNET_MSG_USER_END))
		return -EINVAL;

	/* should we use an ephemeral endpoint? */
	if (unet_addr_is_zero_zero(ua)) {
		uae = unet_app_entry_create_ephemeral(un);
		if (IS_ERR(uae))
			return PTR_ERR(uae);
	}

	lock_sock(sk);

	/* auto bind? */
	if (!unet_addr_has_parent(ua)) {
		/* get the first entity */
		ue = unet_get_first_local_entity(un);
		if (!ue) {
			pr_info("%s: can't find first local entity\n", __func__);
			err = -ENETUNREACH;
			goto out;
		}
	} else {
		/* we have a full address, get the originating entity */
		ue = unet_entity_lookup_by_addr(un, ua);
		if (!ue || ue->type != unet_entity_type_local) {
			pr_info("%s: can't find local entity\n", __func__);
			err = -ENODEV;
			goto out;
		}
	}

	/* do we need to get an existing id? */
	if (!uae) {
		uae = unet_app_entry_lookup(un, ua);
		if (!uae) {
			pr_info("%s: can't find app entry\n", __func__);
			err = -ENODEV;
			goto out;
		}
	}

	ua_ue = unet_entity_addr(ue);
	ua_uae = unet_app_entry_addr(uae);

	usk->bound_ue = ue;
	usk->bound_uae = uae;

	usk->rcv_sua.sunet_family = AF_UNET;
	usk->rcv_sua.sunet_addr.message_type = mt;
	unet_addr_fill(&usk->rcv_sua.sunet_addr.addr,
			unet_addr_prefix(ua_ue),  ua_ue->prefix_len,
			unet_addr_id(ua_ue),      ua_ue->id_len,
			unet_addr_prefix(ua_uae), ua_uae->prefix_len,
			unet_addr_id(ua_uae),     ua_uae->id_len);

	sk_dst_reset(sk);
out:
	release_sock(sk);

	if (err && ue)
		unet_entity_put(ue);

	/* destroy ephemeral */
	if (err && uae) {
		if (uae->ephemeral_id != -1)
			unet_app_entry_destroy(uae);
		else
			unet_app_entry_put(uae);
	}

	return err;
}

static int unet_dgram_connect(struct sock *sk, struct sockaddr *_uaddr, int len)
{
	struct unet_sock *usk = unet_sk(sk);
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);
	struct sockaddr_unet *sun = (struct sockaddr_unet *)_uaddr;
	struct unet_entity *ue = NULL;
	struct unet_app_entry *uae = NULL;
	struct unet_addr *ua_ue, *ua_uae;
	int mt;
	int err = 0;

	if (!un)
		return -ENOTSUPP;

	if (sun->sunet_family != AF_UNET ||
	    !unet_addr_is_valid(&sun->sunet_addr.addr))
		return -EINVAL;

	/* make sure the message type is in the user range */
	mt = sun->sunet_addr.message_type;
	if (mt < UNET_MSG_USER_START || mt >= UNET_MSG_USER_END)
		return -EINVAL;

	lock_sock(sk);

	/* auto bind? */
	if (!usk->bound_ue) {
		err = -ENOTSUPP;

		/* get the first */
		ue = unet_get_first_local_entity(un);
		if (!ue) {
			err = -ENETUNREACH;
			goto out;
		}

		uae = unet_app_entry_create_ephemeral(un);
		if (IS_ERR(uae)) {
			err = PTR_ERR(uae);
			goto out;
		}

		usk->rcv_sua.sunet_family = AF_UNET;
		/* same message type as what we're connecting to */
		usk->rcv_sua.sunet_addr.message_type = sun->sunet_addr.message_type;

		ua_ue = unet_entity_addr(ue);
		ua_uae = unet_app_entry_addr(uae);

		usk->bound_ue = ue;
		usk->bound_uae = uae;

		usk->rcv_sua.sunet_family = AF_UNET;
		usk->rcv_sua.sunet_addr.message_type = mt;
		unet_addr_fill(&usk->rcv_sua.sunet_addr.addr,
				unet_addr_prefix(ua_ue),  ua_ue->prefix_len,
				unet_addr_id(ua_ue),      ua_ue->id_len,
				unet_addr_prefix(ua_uae), ua_uae->prefix_len,
				unet_addr_id(ua_uae),     ua_uae->id_len);
	}
	/* OK, we can put it down as a remote entity */
	usk->rua.sunet_family = AF_UNET;
	usk->rua.sunet_addr.message_type = sun->sunet_addr.message_type;
	unet_addr_copy(&usk->rua.sunet_addr.addr, &sun->sunet_addr.addr);

	err = 0;
out:

	if (err && ue)
		unet_entity_put(ue);

	/* destroy ephemeral */
	if (err && uae) {
		if (uae->ephemeral_id != -1)
			unet_app_entry_destroy(uae);
		else
			unet_app_entry_put(uae);
	}

	release_sock(sk);

	return err;
}

static int unet_dgram_disconnect(struct sock *sk, int flags)
{
	struct unet_sock *usk = unet_sk(sk);

	lock_sock(sk);
	memset(&usk->rua, 0, sizeof(usk->rua));
	release_sock(sk);

	return 0;
}

static int unet_common_init(struct sock *sk)
{
	return 0;
}

static int unet_dgram_hash(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);

	if (!un)
		return -ENOTSUPP;

	write_lock_bh(&un->dgram_lock);
	sk_add_node(sk, &un->dgram_head);
	sock_prot_inuse_add(net, sk->sk_prot, 1);
	write_unlock_bh(&un->dgram_lock);

	return 0;
}

static void unet_dgram_unhash(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);

	if (!un)
		return;

	write_lock_bh(&un->dgram_lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(net, sk->sk_prot, -1);
	write_unlock_bh(&un->dgram_lock);
}

#if 0
static struct sock *__unet_lookup(struct net *net, struct sock *sk,
		unsigned short proto,
		struct unet_addr *rua, struct unet_addr *lua)
{
	struct unet_sock *usk = unet_sk(sk);

	sk_for_each_from(sk) {
		usk = unet_sk(sk);
		if (net_eq(sock_net(sk), net) &&
		    (!rua || unet_addr_eq(rua, &usk->rua.sunet_addr.addr)) &&
		    (!lua || unet_addr_eq(lua, &usk->rcv_sua.sunet_addr.addr)))
		    return sk;
	}
	return NULL;
}
#endif

static int unet_dgram_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct unet_sock *usk;
	struct unet_entity *ue;
	struct unet_app_entry *uae;
	struct unet_addr *orig_ua, *dest_ua;
	int mt, err;
	bool connected;

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	usk = unet_sk(sk);

	lock_sock(sk);
	connected = unet_addr_is_valid(&usk->rua.sunet_addr.addr);

	if (!connected && !msg->msg_name) {
		err = -EDESTADDRREQ;
		goto out;
	}
	if (connected && msg->msg_name) {
		err = -EISCONN;
		goto out;
	}

	ue = usk->bound_ue;
	uae = usk->bound_uae;

	/* we don't support ephemeral binds on sendmsg */
	if (!ue || !uae) {
		err = -ENXIO;
		goto out_unlock;
	}
	orig_ua = &usk->rcv_sua.sunet_addr.addr;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_unet *, sun, msg->msg_name);

		if (sun->sunet_family != AF_UNET) {
			err = -EINVAL;
			goto out_unlock;
		}

		mt = sun->sunet_addr.message_type;
		dest_ua = &sun->sunet_addr.addr;

		if (mt < UNET_MSG_USER_START || mt >= UNET_MSG_USER_END ||
		    !unet_addr_is_valid(dest_ua)) {
			err = -EINVAL;
			goto out_unlock;
		}

	} else {
		mt = usk->rua.sunet_addr.message_type;;
		dest_ua = &usk->rua.sunet_addr.addr;
	}

	err = unet_entity_send_msg(ue, orig_ua, dest_ua, mt, msg, size);

out_unlock:

out:
	release_sock(sk);

	return err;
}

static int unet_dgram_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		       int noblock, int flags, int *addr_len)
{
	struct unet_skb_cb *ucb;
	size_t copied = 0;
	int err = -EOPNOTSUPP;
	struct sk_buff *skb;
	DECLARE_SOCKADDR(struct sockaddr_unet *, sun, msg->msg_name);
	struct unet_addr *orig_ua;
	struct unet_packet_header *uph;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	ucb = UNET_SKB_CB(skb);

	/* it has to be a valid UCB */
	if (WARN_ON(ucb->magic != UNET_SKB_CB_MAGIC))
		goto done;

	uph = ucb->uph;

	/* trim headers and trailers from the buffer */
	skb_pull(skb, ucb->data_offset);
	skb_trim(skb, ucb->size);

	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	err = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (err)
		goto done;

	sock_recv_ts_and_drops(msg, sk, skb);

	if (sun) {
		orig_ua = unet_packet_get_orig_addr(uph);

		sun->sunet_family = AF_UNET;
		sun->sunet_addr.message_type = unet_packet_message_type(uph);
		unet_addr_copy(&sun->sunet_addr.addr, orig_ua);
		*addr_len = sizeof(*sun);
	}

	if (flags & MSG_TRUNC)
		copied = skb->len;
done:
	unet_skb_cb_cleanup(skb);
	skb_free_datagram(sk, skb);
out:
	if (err)
		return err;
	return copied;
}

static void unet_dgram_close(struct sock *sk, long timeout)
{
	struct unet_entity *ue;
	struct unet_sock *usk;

	usk = unet_sk(sk);

	lock_sock(sk);
	if (usk->bound_uae) {
		if (usk->bound_uae->ephemeral_id != -1)
			unet_app_entry_destroy(usk->bound_uae);
		else
			unet_app_entry_put(usk->bound_uae);
		usk->bound_uae = NULL;
	}
	if (usk->bound_ue) {
		ue = usk->bound_ue;
		unet_entity_put(ue);
		usk->bound_ue = NULL;
	}
	release_sock(sk);

	sk_common_release(sk);
}


static int unet_raw_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct net *net = sock_net(sk);
	struct unet_net *un = unet_net(net);
	struct unet_sock *usk;
	struct unet_entity *ue = NULL;
	struct unet_addr *ua;
	int mt, err;

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	usk = unet_sk(sk);

	lock_sock(sk);

	if (usk->bound_ue)
		ue = usk->bound_ue;
	else
		ue = unet_get_first_local_entity(un);

	if (!ue) {
		err = -ENXIO;
		goto out;
	}

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_unet *, sun, msg->msg_name);

		mt = sun->sunet_addr.message_type;
		ua = &sun->sunet_addr.addr;

		err = unet_entity_send_msg(ue, NULL, ua, mt, msg, size);
	} else
		err = -EDESTADDRREQ;

out:
	if (ue && ue != usk->bound_ue)
		unet_entity_put(ue);

	release_sock(sk);

	return err;
}

static int unet_raw_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		       int noblock, int flags, int *addr_len)
{
	size_t copied = 0;
	int err = -EOPNOTSUPP;
	struct sk_buff *skb;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	err = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (err)
		goto done;

	sock_recv_ts_and_drops(msg, sk, skb);

	if (flags & MSG_TRUNC)
		copied = skb->len;
done:
	skb_free_datagram(sk, skb);
out:
	if (err)
		return err;
	return copied;
}

void unet_raw_deliver(struct net *net, struct sk_buff *skb)
{
	struct unet_net *un = unet_net(net);
	struct unet_skb_cb *ucb;
	struct sock *sk;
	struct unet_sock *usk;
	struct sk_buff *clone;
	struct unet_addr *orig_ua, *dest_ua, *rua, *sua;
	int err;

	if (WARN_ON(!un))
		return;

	ucb = UNET_SKB_CB(skb);

	/* check for magic */
	if (WARN_ON(ucb->magic != UNET_SKB_CB_MAGIC))
		return;

	orig_ua = unet_packet_get_orig_addr(ucb->uph);
	dest_ua = unet_packet_get_dest_addr(ucb->uph);

	/* originator must always exist */
	if (WARN_ON(!orig_ua))
		return;

	read_lock_bh(&un->raw_lock);

	sk_for_each(sk, &un->raw_head) {

		bh_lock_sock(sk);

		usk = unet_sk(sk);

		rua = &usk->rua.sunet_addr.addr;
		sua = &usk->rcv_sua.sunet_addr.addr;

		if ((!unet_addr_is_valid(rua) || unet_addr_eq(orig_ua, rua)) &&
		    (!dest_ua || !unet_addr_is_valid(sua) || unet_addr_eq(dest_ua, sua)) &&
		    (clone = unet_skb_clone(skb, false, GFP_KERNEL))) {

			err = sock_queue_rcv_skb(sk, clone);
			if (err < 0) {
				pr_err("%s: failed to queue skb\n", __func__);
				kfree_skb(clone);
			}
		}
		bh_unlock_sock(sk);
	}
	read_unlock_bh(&un->raw_lock);
}

void unet_entity_deliver(struct unet_entity *ue, uint32_t mt, struct sk_buff *skb)
{
	struct unet_net *un;
	struct unet_skb_cb *ucb;
	struct sock *sk;
	struct unet_sock *usk;
	struct sk_buff *clone;
	struct unet_addr *orig_ua, *dest_ua, *rua, *sua;
	uint32_t smt;
	int err;

	un = unet_entity_unet(ue);

	ucb = UNET_SKB_CB(skb);

	/* check for magic */
	if (WARN_ON(ucb->magic != UNET_SKB_CB_MAGIC))
		return;

	orig_ua = unet_packet_get_orig_addr(ucb->uph);
	dest_ua = unet_packet_get_dest_addr(ucb->uph);

	/* originator and destinator must always exist */
	if (WARN_ON(!orig_ua || !dest_ua))
		return;

	read_lock_bh(&un->dgram_lock);

	sk_for_each(sk, &un->dgram_head) {

		bh_lock_sock(sk);

		usk = unet_sk(sk);

		rua = &usk->rua.sunet_addr.addr;
		sua = &usk->rcv_sua.sunet_addr.addr;
		smt = usk->rcv_sua.sunet_addr.message_type;

		if ((!unet_addr_is_valid(rua) || unet_addr_eq(orig_ua, rua)) &&
		    unet_addr_eq(dest_ua, sua) && mt == smt &&
		    (clone = unet_skb_clone(skb, true, GFP_ATOMIC))) {

			err = sock_queue_rcv_skb(sk, clone);
			if (err < 0) {
				pr_err("%s: failed to queue skb\n", __func__);
				kfree_skb(clone);
			}
		}
		bh_unlock_sock(sk);
	}
	read_unlock_bh(&un->dgram_lock);
}

static int unet_sock_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sock *sk = sock->sk;

	if (sk->sk_prot->bind)
		return sk->sk_prot->bind(sk, uaddr, len);

	return sock_no_bind(sock, uaddr, len);
}

static int unet_sock_sendmsg(struct socket *sock, struct msghdr *msg,
				   size_t len)
{
	struct sock *sk = sock->sk;

	return sk->sk_prot->sendmsg(sk, msg, len);
}

static int unet_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		sock->sk = NULL;
		sk->sk_prot->close(sk, 0);
	}
	return 0;
}

static int unet_sock_connect(struct socket *sock, struct sockaddr *vaddr,
			     int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (addr_len < sizeof(vaddr->sa_family))
		return -EINVAL;

	if (vaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

	if (sk->sk_prot->connect)
		return sk->sk_prot->connect(sk, vaddr, addr_len);

	return sock_no_connect(sock, vaddr, addr_len, flags);
}

static int unet_sock_getname(struct socket *sock, struct sockaddr *uaddr,
			     int *uaddr_len, int peer)
{
	struct sock *sk = sock->sk;
	struct unet_sock *usk = unet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_unet *, sun, uaddr);

	sun->sunet_family = AF_UNET;
	if (peer) {
		if (!unet_addr_is_valid(&usk->rua.sunet_addr.addr))
			return -ENOTCONN;
		sun->sunet_addr.message_type = usk->rua.sunet_addr.message_type;
		unet_addr_copy(&sun->sunet_addr.addr, &usk->rua.sunet_addr.addr);
	} else {
		sun->sunet_addr.message_type = usk->rcv_sua.sunet_addr.message_type;
		unet_addr_copy(&sun->sunet_addr.addr, &usk->rcv_sua.sunet_addr.addr);
	}
	*uaddr_len = sizeof(*sun);
	return 0;
}

static const struct proto_ops unet_raw_ops = {
	.owner		= THIS_MODULE,
	.family		= AF_UNET,
	.release	= unet_sock_release,
	.bind		= unet_sock_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= unet_sock_getname,
	.poll		= datagram_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.sendmsg	= unet_sock_sendmsg,
	.recvmsg	= sock_common_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = sock_no_setsockopt,
	.compat_getsockopt = sock_no_getsockopt,
#endif
};

static const struct proto_ops unet_dgram_ops = {
	.owner		= THIS_MODULE,
	.family		= AF_UNET,
	.release	= unet_sock_release,
	.bind		= unet_sock_bind,
	.connect	= unet_sock_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= unet_sock_getname,
	.poll		= datagram_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.sendmsg	= unet_sock_sendmsg,
	.recvmsg	= sock_common_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = sock_no_setsockopt,
	.compat_getsockopt = sock_no_getsockopt,
#endif
};

static struct proto unet_raw_proto = {
	.name		= "UNET-RAW",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct unet_sock),
	.init		= unet_common_init,
	.close		= unet_raw_close,
	.bind		= unet_raw_bind,
	.sendmsg	= unet_raw_sendmsg,
	.recvmsg	= unet_raw_recvmsg,
	.hash		= unet_raw_hash,
	.unhash		= unet_raw_unhash,
};

static struct proto unet_dgram_proto = {
	.name		= "UNET-DGRAM",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct unet_sock),
	.init		= unet_common_init,
	.close		= unet_dgram_close,
	.bind		= unet_dgram_bind,
	.sendmsg	= unet_dgram_sendmsg,
	.recvmsg	= unet_dgram_recvmsg,
	.hash		= unet_dgram_hash,
	.unhash		= unet_dgram_unhash,
	.connect	= unet_dgram_connect,
	.disconnect	= unet_dgram_disconnect,
};

static int unet_sk_create(struct net *net, struct socket *sock,
			  int protocol, int kern)
{
	struct proto *proto;
	const struct proto_ops *ops;
	struct sock *sk = NULL;
	struct unet_sock *usk;
	int err;

	/* Validate arguments */
	if (unlikely(protocol != 0))
		return -EAFNOSUPPORT;

	switch (sock->type) {
	case SOCK_DGRAM:
		proto = &unet_dgram_proto;
		ops = &unet_dgram_ops;
		break;
	case SOCK_RAW:
		proto = &unet_raw_proto;
		ops = &unet_raw_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	/* Allocate socket's protocol area */
	sk = sk_alloc(net, AF_UNET, GFP_KERNEL, proto, kern);
	if (!sk)
		return -ENOMEM;

	usk = unet_sk(sk);
	memset(&usk->rua, 0, sizeof(usk->rua));
	memset(&usk->rcv_sua, 0, sizeof(usk->rcv_sua));

	sock->ops = ops;
	sock_init_data(sock, sk);

	if (sk->sk_prot->hash) {
		err = sk->sk_prot->hash(sk);
		if (err)
			goto out_err;
	}

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err)
			goto out_err;
	}

	return 0;

out_err:
	if (sk)
		sk_common_release(sk);
	return err;
}

static const struct net_proto_family unet_family_ops = {
	.owner		= THIS_MODULE,
	.family		= AF_UNET,
	.create		= unet_sk_create
};

int unet_socket_setup(void)
{
	int err;

	pr_info("%s:\n", __func__);

	err = proto_register(&unet_raw_proto, 1);
	if (err) {
		pr_err("Failed to register UNET protocol type\n");
		goto out_no_raw_proto;
	}

	err = proto_register(&unet_dgram_proto, 1);
	if (err) {
		pr_err("Failed to register UNET protocol type\n");
		goto out_no_dgram_proto;
	}

	err = sock_register(&unet_family_ops);
	if (err) {
		pr_err("Failed to register UNET socket type\n");
		goto out_no_sock;
	}
	return 0;

out_no_sock:
	proto_unregister(&unet_dgram_proto);
out_no_dgram_proto:
	proto_unregister(&unet_raw_proto);
out_no_raw_proto:
	return err;
}

void unet_socket_cleanup(void)
{
	pr_info("%s:\n", __func__);

	sock_unregister(unet_family_ops.family);
	proto_unregister(&unet_dgram_proto);
	proto_unregister(&unet_raw_proto);
}
