/*
 * net/unet/fsm.c: UNET FSM (finite state machine)
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
#include <linux/uuid.h>

#include "core.h"
#include "bearer.h"
#include "fsm.h"
#include "utils.h"
#include "socket.h"
#include "dev.h"

int unet_fsm_create_orig_entity_if_needed(struct unet_net *un,
		struct unet_fsm_event *ufe)
{
	struct unet_addr *orig_ua, *dest_ua;
	uint32_t message_type;
	int err;

	message_type = unet_packet_message_type(ufe->uph);
	if (!unet_message_should_create_entity(message_type))
		return 0;

	/* verity that we have what we need */
	if (!ufe->uph || !ufe->b || !ufe->skb || !ufe->orig_ua) {
		pr_err("%s: Non-valid fsm_event\n", __func__);
		return -EINVAL;
	}

	/* test if entity already exists */
	if (ufe->orig_ue) {
		/* this is not an error */
		/* TODO check if info stored is the same */
		return 0;
	}

	/* get original address */
	orig_ua = ufe->orig_ua;
	dest_ua = ufe->dest_ua;

	if (!unet_addr_is_valid(orig_ua) || unet_addr_has_parent(orig_ua)) {
		pr_err("%s: Cannot create entity from APCR with bad orig ua\n",
				__func__);
		return -EINVAL;
	}

	if (dest_ua && (!unet_addr_is_valid(orig_ua) ||
			unet_addr_has_parent(orig_ua))) {
		pr_err("%s: Cannot create entity from APCA with bad dest ua\n",
				__func__);
		return -EINVAL;
	}

	/* create a new entity */
	ufe->orig_ue = unet_remote_entity_create(un, ufe->skb);
	if (IS_ERR(ufe->orig_ue)) {
		err = PTR_ERR(ufe->orig_ue);
		ufe->orig_ue = NULL;
		pr_err("%s: Cannot create entity from APCR (err=%d)\n",
				__func__, err);
		return err;
	}
	/* mark it as fresh */
	ufe->orig_ue_fresh = true;

	return 0;
}

int unet_fsm_update_orig_entity_if_needed(struct net *net,
		struct unet_fsm_event *ufe)
{
	struct unet_entity *ue;
	uint32_t message_type;
	int err;

	/* it must exist and it must be remote */
	ue = ufe->orig_ue;
	if (!ue || ue->type != unet_entity_type_remote)
		return 0;


	/* update prop on on proper message types */
	message_type = unet_packet_message_type(ufe->uph);
	if (!unet_message_should_update_prop(message_type))
		return 0;

	/* verity that we have what we need */
	if (!ufe->uph || !ufe->skb || !ufe->orig_ua) {
		pr_err("%s: Non-valid update\n", __func__);
		return -EINVAL;
	}

	/* update properties with the ones in the packet header */
	err = unet_entity_update_from_packet(ue, ufe->skb, ufe->uph);

	if (err < 0) {
		pr_err("%s: Error updating properties\n", __func__);
		return -EINVAL;
	}
	ufe->orig_ue_prop_changed = err;

	return 0;
}

int unet_entity_fsm(struct net *net, struct unet_fsm_event *ufe)
{
	struct unet_net *un = unet_net(net);
	struct unet_entity *ue, *ue_sib, *ue_next_hop = NULL, *ue_parent = NULL;
	struct unet_conn_entry *uce;
	struct unet_entity_prop *uep;
	unsigned long timeout;
	bool accept, i_can_be_router, send_reply, has_accepted, created;
	bool da_known_orig, sib_is_child;
	uint32_t message_type;
	char *uuid_str;
	int err, ret;

	switch (ufe->type) {
	case unet_fsm_event_type_pta_frame_recv:
	case unet_fsm_event_type_ptp_frame_recv:
		message_type = unet_packet_message_type(ufe->uph);
		switch (message_type) {
		case UNET_MSG_APCR:

			if (!ufe->dest_ue || !ufe->orig_ue)
				goto bad_fsm_event;

			ue = ufe->dest_ue;
			uep = &ue->ae.prop;
			ue_sib = ufe->orig_ue;

			if (ue->type != unet_entity_type_local)
				break;

			/* do not move along unless we have the full cert */
			if (unet_entity_cert_rx_in_progress(ue_sib))
				break;

			uce = NULL;
			created = false;

			/* reply only to non-parents (or non-registering routers) */
			i_can_be_router = unet_entity_can_i_be_router(ue,
						ue_sib, &send_reply);
			if (i_can_be_router) {
				uce = unet_conn_entry_lookup(ue, ue_sib);
				if (uce) {
					unet_fsm_info(ue, "APCR from %s which I know about\n",
							unet_entity_name(ue_sib));

					/* we rate limit replies */
					timeout = uce->last_tx_time +
							msecs_to_jiffies(un->reply_apca_timeout);
					if (time_before(jiffies, timeout))
						send_reply = false; 

				} else {
					unet_fsm_info(ue, "APCR from %s which I create\n",
							unet_entity_name(ue_sib));

					uce = unet_conn_entry_create(ue, ue_sib,
							unet_conn_state_child_to_be);
					if (IS_ERR_OR_NULL(uce)) {
						unet_fsm_info(ue, "Failed to create child entry for %s\n",
							unet_entity_name(ue_sib));
						send_reply = false;
						uce = NULL;
					}

					/* generate nonce1 */
					if (uce && unet_conn_entry_is_secure(uce))
						unet_conn_entry_generate_nonce1(uce);

					created = !!uce;
				}

			} else {
				unet_fsm_info(ue, "APCR from %s which I can't be router\n",
						unet_entity_name(ue_sib));
			}

			if (uce && send_reply) {
				uce->last_tx_time = jiffies;

				unet_fsm_info(ue, "sending%s APCA reply to %s\n",
						unet_conn_entry_is_secure(uce) ?
							" secure" : "",
						unet_entity_name(ue_sib));

				unet_entity_send_to_visible(ue, ue_sib, uce,
							    UNET_MSG_APCA, NULL, 0);
			}

			if (uce && !created)
				unet_conn_entry_put(uce);

			break;

		case UNET_MSG_APCA:

			if (!ufe->dest_ue || !ufe->orig_ue)
				goto bad_fsm_event;

			ue = ufe->dest_ue;
			ue_sib = ufe->orig_ue;
			if (!ue_sib)
				break;

			/* only for local entities from now on */
			if (ue->type != unet_entity_type_local)
				break;

			/* do not move along unless we have the full cert */
			if (unet_entity_cert_rx_in_progress(ue_sib))
				break;

			/* only on unregistered state */
			if (ue->state == unet_entity_state_unregistered) {
				uce = unet_entity_can_be_router(ue, ue_sib);
				if (!uce) {
					if (!ufe->uph->prop.has_i_can_be_router ||
					    !ufe->uph->prop.i_can_be_router) {
						unet_fsm_info(ue, "APCA %s has rejected us\n",
								unet_entity_name(ue_sib));
						unet_entity_add_router(ue, ue_sib);
						unet_entity_router_rejected_us(ue, ue_sib);
					} else {
						unet_fsm_info(ue, "APCA %s can't be router\n",
								unet_entity_name(ue_sib));
					}
				} else {
					unet_fsm_info(ue, "APCA %s can be router\n",
							unet_entity_name(ue_sib));
					unet_entity_add_router(ue, ue_sib);
					if (!unet_entity_is_apca_timeout_running(ue))
						unet_entity_start_apca_timeout(ue, un->apca_timeout);
				}

				if (uce)
					unet_conn_entry_put(uce);
			}
			break;

		case UNET_MSG_R:
			if (!ufe->dest_ue || !ufe->orig_ue)
				goto bad_fsm_event;

			ue = ufe->dest_ue;
			ue_sib = ufe->orig_ue;

			if (ue->type != unet_entity_type_local)
				break;

			/* we start by trusting it */
			accept = false;
			uce = unet_conn_entry_lookup(ue, ue_sib);
			if (!uce || uce->state != unet_conn_state_child_to_be) {
				/* bad state same as not existing */
				unet_fsm_info(ue, "R from %s without entry - ignoring\n",
						unet_entity_name(ue_sib));
				/* ignore completely */
			} else {

				/* if not secure we accept */
				accept = true;

				/* if it's secure then the nonce1's must match */
				if (unet_conn_entry_is_secure(uce))
					accept = unet_conn_entry_nonce1_match(uce);

				unet_fsm_info(ue, "R from %s - %s\n",
					unet_entity_name(ue_sib),
					accept ? "accept" : "reject");

				if (accept) {
					/* update nonce2 */
					if (unet_conn_entry_is_secure(uce))
						unet_conn_entry_update_nonce2(uce);
					unet_conn_entry_set_state(uce,
							unet_conn_state_child_connected);
				}

				unet_entity_send_to_visible(ue, ue_sib, uce,
							    UNET_MSG_RR, NULL, 0);
			}

			if (uce)
				unet_conn_entry_put(uce);

			break;

		case UNET_MSG_RR:

			if (!ufe->dest_ue || !ufe->orig_ue)
				goto bad_fsm_event;

			ue = ufe->dest_ue;
			ue_sib = ufe->orig_ue;

			if (ue->type != unet_entity_type_local)
				break;

			/* only on registration pending state */
			if (ue->state != unet_entity_state_registration_pending)
				break;

			uce = unet_conn_entry_lookup(ue, ue_sib);
			if (!uce) {
				unet_fsm_err(ue, "RR from %s (which is unknown)\n",
						unet_entity_name(ue_sib));
				break;
			}

			has_accepted = ufe->uph->prop.has_response &&
				       ufe->uph->prop.response;

			/* on secure mode verify the nonces match */
			if (has_accepted && unet_conn_entry_is_secure(uce))
				has_accepted = unet_conn_entry_nonce2_match(uce);

			if (has_accepted) {
				unet_fsm_info(ue, "accepted REGISTER from %s\n",
						unet_entity_name(ue_sib));

				/* set registering router as parent */
				unet_conn_entry_set_state(uce,
						unet_conn_state_parent_connected);

				unet_set_entity_state(ue, unet_entity_state_registered);
			} else {
				unet_fsm_info(ue, "rejected REGISTER for %s\n",
						unet_entity_name(ue_sib));

				/* state change will trigger APCR xmit */
				unet_set_entity_state(ue, unet_entity_state_unregistered);
			}

			if (uce)
				unet_conn_entry_put(uce);

			break;

			/* all other messages including RFDR & DA */

		default:

			/* FSM caller must have dealt with this */
			ue = ufe->next_hop_ue;
			if (!ue)
				ue = ufe->dest_ue;
			if (!ue || !ufe->dest_ua || !ufe->orig_ua)
				goto bad_fsm_event;

			if (ue->type != unet_entity_type_local)
				break;

			/* originator was me? loop! */
			if (ue && ufe->orig_ue == ue) {
				unet_fsm_info(ue, "WARNING: Routing loop detected!. Drop.\n");
				/* TODO reparent? */
				break;
			}

			ue_parent = unet_entity_get_parent(ue);

			/* sending from a visible entity? */
			ue_sib = ufe->sender_ue;
			if (!ue_sib)
				ue_sib = ufe->orig_ue;

			/* whether we knew the originator of a Disconnect-Announce */
			da_known_orig = false;

			sib_is_child = unet_entity_is_child(ue, ue_sib);

			/* note child activity */
			if (sib_is_child)
				unet_entity_mark_child_alive(ue, ue_sib);

			/* pre-handle checks */
			switch (message_type) {

			case UNET_MSG_RFDR:
				/* accept only if the immediate sender is our child */
				if (!ue_sib) {
					unet_fsm_info(ue, "RFDR from an unknown entity, dropping.\n");
					goto dont_fwd;
				}
				if (!sib_is_child) {
					unet_fsm_info(ue, "RFDR from an non-child entity (%s), dropping.\n",
							unet_entity_name(ue_sib));
					goto dont_fwd;
				}

				/* unconditionally add the originator addr to next-hop */
				err = unet_entity_add_next_hop(ue, ufe->orig_ua, ue_sib);
				if (err) {
					unet_fsm_err(ue, "RFDR from (%s), failed to add a next hop entry.\n",
							unet_entity_name(ue_sib));
				}

				break;

			case UNET_MSG_DA:
				/* do we know the originator as a directly reachable entity? */
				if (!ufe->orig_ue)
					break;

				/* we knew the originator, mark it for forwarding */
				da_known_orig = true;

				/* it's a primary (directly reachable) */
				uce = unet_conn_entry_lookup(ue, ufe->orig_ue);
				if (uce) {
					if (unet_conn_entry_is_child(uce)) {
						unet_fsm_info(ue, "Disconnect-Announce from child %s\n",
								unet_entity_name(ufe->orig_ue));
						unet_conn_entry_put(uce);
						unet_conn_entry_destroy(uce);
						uce = NULL;
					} else if (unet_conn_entry_is_parent(uce) ||
						   unet_conn_entry_is_parent_to_be(uce)) {
						unet_fsm_info(ue, "Disconnect-Announce from %s %s\n",
								unet_entity_is_parent(ue, ufe->orig_ue) ?
									"parent" : "registering-router",
								unet_entity_name(ufe->orig_ue));
						unet_conn_entry_put(uce);
						uce = NULL;
						unet_set_entity_state(ue, unet_entity_state_unregistered);
					} else
						unet_conn_entry_put(uce);
				}
				break;

			case UNET_MSG_RC:
				if (!ue_parent || !ufe->orig_ue || ue_parent != ufe->orig_ue) {
					unet_fsm_info(ue, "RC not from parent entity\n");
					goto dont_fwd;
				}
				break;

			case UNET_MSG_ACK:
				break;
			}

			/* final destination? */
			if (ue == ufe->dest_ue) {

				/* handle end destination */
				switch (message_type) {
				case UNET_MSG_ERQ:
					if (!ufe->data || !ufe->size)
						unet_entity_info(ue, "ERQ no data.\n");
					else
						unet_entity_info(ue, "ERQ %u bytes [%*phN%s] (hash %08x)\n",
							ufe->size,
							ufe->size > 8 ? 8 : ufe->size,
							ufe->data,
							ufe->size > 8 ? " ..." : "",
							jhash(ufe->data, ufe->size, JHASH_INITVAL));

					unet_entity_send(ue, NULL, ufe->orig_ua, UNET_MSG_ERP, ufe->data, ufe->size);
					break;
				case UNET_MSG_ERP:
					if (!ufe->data || !ufe->size)
						unet_entity_info(ue, "ERP no data.\n");
					else
						unet_entity_info(ue, "ERP %u bytes [%*phN%s] (hash %08x)\n",
							ufe->size,
							ufe->size > 8 ? 8 : ufe->size,
							ufe->data,
							ufe->size > 8 ? " ..." : "",
							jhash(ufe->data, ufe->size, JHASH_INITVAL));
					break;
				case UNET_MSG_SNK:
					unet_entity_info(ue, "Sink for me. Stop.\n");
					break;
				case UNET_MSG_RFDR:
					unet_fsm_info(ue, "RFDR for me. Stop.\n");
					break;
				case UNET_MSG_DA:
					unet_fsm_info(ue, "Disconnect-Announce for me. Stop.\n");
					break;
				case UNET_MSG_RC:
					unet_fsm_info(ue, "Reconnect for me. Sending RFDR upstream & RC to children.\n");

					/* check for circularity */
					if (ufe->uph->prop.has_reconnect_nonce) {

						uuid_str = kmalloc(UUID_STRING_LEN + 1, GFP_KERNEL);
						if (!uuid_str) {
							unet_fsm_err(ue, "Failed to allocate UUID string\n");
							goto dont_fwd;
						}

						unet_uuid_to_str(ue->rc_uuid, uuid_str, sizeof(uuid_str));
						/* if it matches, we're in trouble */
						ret = strcmp(ufe->uph->prop.reconnect_nonce, uuid_str);
						kfree(uuid_str);

						if (!ret) {
							unet_fsm_info(ue, "WARNING: RC circularity detected\n");
							goto dont_fwd;
						}
					}

					unet_entity_send(ue, NULL, &unet_root_addr,
							 UNET_MSG_RFDR, NULL, 0);

					generate_random_uuid(ue->rc_uuid);
					unet_entity_send_to_all_visible_children(ue,
								UNET_MSG_RC, NULL, 0);

					break;
				case UNET_MSG_ACK:
					if (!unet_entity_is_child(ue, ue_sib))
						unet_fsm_info(ue, "ACK not from child %s. Drop.\n",
								unet_entity_name(ufe->orig_ue));
					else
						unet_fsm_info(ue, "ACK for me. It is never forwarded.\n");
					break;

					/* IP packet */
				case UNET_MSG_IP:
					unet_entity_ip_deliver(ue, ufe->data, ufe->size);
					break;

				default:
					if (message_type >= UNET_MSG_USER_START &&
					    message_type  < UNET_MSG_USER_END)
						unet_entity_deliver(ue, message_type, ufe->skb);
					break;
				}
				goto dont_fwd;
			}

			/* get next hop (can be parent) */
			ue_next_hop = unet_entity_get_destination(ue, ufe->dest_ua);

			/* post-handle (fwd) checks */
			switch (message_type) {
			case UNET_MSG_RFDR:

				/* if the originator exists and is not our child, don't forward */
				if (ufe->orig_ue && !sib_is_child) {

					if (un->force_relay_rfdr_upstream) {
						unet_fsm_info(ue, "RFDR from a known originator forced fwd.\n");
						break;
					}
					unet_fsm_info(ue, "RFDR from a known originator. Stop.\n");
					goto dont_fwd;
				}

				/* forward RFDR only upstream */
				if (ue_next_hop != ue_parent) {
					unet_fsm_info(ue, "RFDR only forwards to parent. Stop.\n");
					goto dont_fwd;
				}
				break;

			case UNET_MSG_DA:
				/* unconditionally add the originator addr to next-hop */
				unet_entity_remove_next_hop_by_addr(ue, ufe->orig_ua);

				/* forward DA only upstream */
				if (ue_next_hop != ue_parent) {
					unet_fsm_info(ue, "DA only forwards to parent. Stop.\n");
					goto dont_fwd;
				}

				if (!un->relay_disconnect_announce_upstream || !da_known_orig) {
					if (un->force_relay_da_upstream) {
						unet_fsm_info(ue, "DA forcing upstream fwd.\n");
						break;
					}
					unet_fsm_info(ue, "DA not-forwarding. Stop.\n");
					goto dont_fwd;
				}
				break;

			case UNET_MSG_RC:
				/* Reconnects are never forwarded */
				unet_fsm_info(ue, "RC is never forwarded\n");
				goto dont_fwd;

			case UNET_MSG_ACK:
				/* ACKs are never forwarded */
				unet_fsm_info(ue, "ACK is never forwarded\n");
				goto dont_fwd;

			default:
				/* meh, no next hop, break early */
				if (!ue_next_hop)
					break;

				/* all-others - first check strict check option */
				if (!un->only_forward_from_valid_senders)
					break;

				/* forward upstream only if we have a sender entry */
				if (ue_next_hop == ue_parent && !ue_sib) {
					unet_fsm_info(ue, "Not forwarding upstream from unknown sender. Stop\n");
					goto dont_fwd;
				}
				/* forward downstream only to children */
				if (ue_next_hop != ue_parent && !unet_entity_is_child(ue, ue_next_hop)) {
					unet_fsm_info(ue, "Not forwarding downstream to non-child. Stop\n");
					goto dont_fwd;
				}
				break;
			}

			if (ue_next_hop) {
				unet_fsm_info(ue, "Forwarding to %s %s\n",
						ue_next_hop == ue_parent ? "parent" : "peer",
						unet_entity_name(ue_next_hop));
				unet_entity_forward(ue, ue_next_hop, ufe->skb);
			} else
				unet_fsm_info(ue, "No next-hop to forward to. Stop.\n");

dont_fwd:
			if (ue_next_hop)
				unet_entity_put(ue_next_hop);

			if (ue_parent)
				unet_entity_put(ue_parent);

			break;

		}
		break;

		/* we got a keep-alive */
	case unet_fsm_event_type_keepalive:

		/* FSM caller must have dealt with this */
		ue = ufe->next_hop_ue;
		if (!ue)
			ue = ufe->dest_ue;
		if (!ue || !ufe->dest_ua || !ufe->orig_ua)
			goto bad_fsm_event;

		if (ue->type != unet_entity_type_local)
			break;

		/* originator was me? loop! */
		if (ue && ufe->orig_ue == ue)
			break;

		/* sending from a visible entity? */
		ue_sib = ufe->sender_ue;
		if (!ue_sib)
			ue_sib = ufe->orig_ue;

		uce = unet_conn_entry_lookup(ue, ue_sib);

		/* send to directly visible */
		unet_entity_send_to_visible(ue, ue_sib, uce,
				            UNET_MSG_ACK, NULL, 0);

		if (uce) {
			unet_conn_entry_put(uce);
			uce = NULL;
		}

		break;

	case unet_fsm_event_type_apcr_timeout:
		ue = ufe->dest_ue;
		if (!ue)
			goto bad_fsm_event;

		if (ue->state == unet_entity_state_unregistered) {
			/* double period */
			timeout = ue->apcr_timeout * 2;
			/* clamp */
			if (timeout >= un->apcr_max_timeout)
				timeout = un->apcr_max_timeout;
		} else if (ue->state == unet_entity_state_registered)
			timeout = un->apcr_timeout;
		else
			timeout = 0;

		if (timeout) {
			unet_entity_send_to_visible(ue, NULL, NULL,
						    UNET_MSG_APCR, NULL, 0);
			unet_entity_start_apcr_timeout(ue, timeout);
		}

		break;

	case unet_fsm_event_type_apca_timeout:
		ue = ufe->dest_ue;
		if (!ue)
			goto bad_fsm_event;

		if (ue->state == unet_entity_state_unregistered) {

			/* select best router */
			uce = unet_entity_select_router(ue);
			if (!uce) {
				/* Can happen when possible routers end up
				 * as children, so they get removed from the router
				 * list. It's a normal case.
				 */
				unet_fsm_info(ue, "No router found (or conn entry), just continue\n");
				unet_entity_start_apcr_timeout(ue, un->apcr_min_timeout);
			} else {
				if (unet_conn_entry_is_secure(uce))
					unet_conn_entry_generate_nonce2(uce);
				if (uce->state != unet_conn_state_parent_to_be)
					unet_conn_entry_set_state(uce, unet_conn_state_parent_to_be);
				unet_set_entity_state(ue, unet_entity_state_registration_pending);
				unet_conn_entry_put(uce);
			}
		}

		break;

	case unet_fsm_event_type_register_timeout:
		ue = ufe->dest_ue;
		if (!ue)
			goto bad_fsm_event;

		if (ue->state == unet_entity_state_registration_pending) {

			uce = unet_entity_get_conn_entry(ue,
					unet_conn_state_parent_to_be,
					unet_conn_type_unknown,
					unet_conn_link_state_unknown);

			if (uce) {
				if (ue->register_retries < un->register_retries) {
					/* if under the retry limit, resend */
					unet_fsm_info(ue, "resending REGISTER\n");
					ue->register_retries++;
				} else {
					unet_fsm_info(ue, "failed REGISTER\n");
					ue->register_retries = 0;

					unet_conn_entry_put(uce);
					unet_conn_entry_destroy(uce);
					uce = NULL;

					/* select best router and set it as parent */
					uce = unet_entity_select_router(ue);
				}
			}

			/* if we have a registering router send REGISTER */
			if (uce) {
				unet_entity_start_register_timeout(ue, un->register_timeout);
				unet_entity_send_to_visible(ue, uce->ue, uce,
							    UNET_MSG_R, NULL, 0);
				unet_conn_entry_put(uce);
			} else
				unet_set_entity_state(ue, unet_entity_state_unregistered);
		}

		break;

	case unet_fsm_event_type_housekeeping_timeout:
		ue = ufe->dest_ue;
		if (!ue)
			goto bad_fsm_event;

		if (ue->type != unet_entity_type_local)
			break;

		/* we take care of chores here */
		unet_entity_housekeeping(ue);

		/* and again */
		unet_entity_start_housekeeping_timeout(ue, un->housekeeping_timeout);

		break;

	default:
		/* TODO handle everything else */
		break;
	}

	return 0;

bad_fsm_event:
	unet_fsm_info(ue, "bad FSM event\n");
	return -EINVAL;
}

int unet_rx_handle_skb_slow(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct unet_bearer *b = unet_bearer_dev_get(dev);
	struct net *net = dev_net(dev);
	struct unet_net *un = unet_net(net);
	struct unet_x_entry *uxe;
	struct unet_skb_cb *ucb;
	struct unet_packet_header *uph;
	struct unet_fsm_event ufe;
	struct unet_entity *ue, *uet, *orig_ue, *dest_ue;
	struct unet_conn_entry *uce = NULL;
	enum unet_fsm_event_type save_event_type;
	struct unet_media_addr media_addr;
	bool decrypted = false, reassembled = false;
	uint32_t message_type;
	unsigned int x_hdrsz;
	uint16_t frag_fullsize, frag_crc;
	uint8_t n_frags, frag;
	unsigned int ft;	/* short-hand for frame type*/
	int err;

process_again:
	/* zero out everything */
	memset(&ufe, 0, sizeof(ufe));

	/* TODO this is suboptimal, but simplifies decoding */
	if (unlikely(!pskb_may_pull(skb, skb->len))) {
		netdev_err(dev, "%s: Can't pull skb\n",
				__func__);
		err = -EINVAL;
		goto out;
	}

	/* prepare skb */
	err = unet_skb_cb_prepare(skb, GFP_KERNEL, decrypted);
	if (err) {
		netdev_err(dev, "%s: Can't prepare skb CB\n",
				__func__);
		goto out;
	}

	if (un->syslog_packet_dump)
		unet_skb_dump_rx(b, skb, decrypted);

	ucb = UNET_SKB_CB(skb);
	uph = ucb->uph;

	ft = uph->frame_type;
	/* if I don't know what to do with this frame drop */
	if (ft & UNET_UNKNOWN_INTERNAL) {
		net_err_ratelimited("%s: %s: unknown frame type 0x%02x\n",
				__func__, dev->name, uph->frame_type & 0xff);
		goto out_clean_skb;
	}

	/* is it encrypted? we have to find the conn entry */
	if (ft & (UNET_ENCRYPTED_INTERNAL | UNET_FRAGMENT_INTERNAL)) {

		if ((ft & UNET_ENCRYPTED_INTERNAL) && decrypted) {
			net_err_ratelimited("%s: %s: recursive decryption error\n",
					__func__, dev->name);
			goto out_clean_skb;
		}

		if ((ft & UNET_FRAGMENT_INTERNAL) && reassembled) {
			net_err_ratelimited("%s: %s: recursive decryption error\n",
					__func__, dev->name);
			goto out_clean_skb;
		}

		/* initialize those */
		n_frags = 0;
		frag = 0;
		frag_crc = 0;
		frag_fullsize = 0;

		/* handle X entries (after main frame) */
		list_for_each_entry(uxe, &ucb->x_list, node) {
			if (uxe->type == UNET_X_ADDRESS_SENDER && !ufe.sender_ua)
				ufe.sender_ua = &uxe->addr;
			else if (uxe->type == UNET_X_ADDRESS_NEXT_HOP && !ufe.next_hop_ua)
				ufe.next_hop_ua = &uxe->addr;
			else if (uxe->type == UNET_X_FRAGMENT) {
				frag_fullsize = uxe->frag.full_size;
				frag_crc = uxe->frag.crc;
				n_frags = uxe->frag.n_frags;
				frag = uxe->frag.frag;
			}
		}

		/* we need both sender and next hop for this to work */
		if (!ufe.sender_ua || !ufe.next_hop_ua) {
			net_err_ratelimited("%s: %s: can't find conn entry (sender, next_hop)\n",
					__func__, dev->name);
			goto out_clean_skb;
		}

		ufe.sender_ue = unet_entity_lookup_by_addr(un, ufe.sender_ua);
		ufe.next_hop_ue = unet_entity_lookup_by_addr(un, ufe.next_hop_ua);

		if (!ufe.sender_ue || !ufe.next_hop_ue) {
			net_err_ratelimited("%s: %s: can't find sender, next_hop lookup\n",
					__func__, dev->name);
			goto out_clean_skb;
		}

		uce = unet_conn_entry_lookup(ufe.next_hop_ue, ufe.sender_ue);
		if (!uce) {
			net_err_ratelimited("%s: %s: can't find conn entry\n",
					__func__, dev->name);
			goto out_clean_skb;
		}

		x_hdrsz = ucb->data_offset;

		/* clean the previous data */
		unet_skb_cb_cleanup(skb);

		/* NOTE encryption must take place before reassembly */
		if (ft & UNET_ENCRYPTED_INTERNAL) {
			skb = unet_conn_entry_decrypt_skb(uce, skb, x_hdrsz);
			if (IS_ERR(skb)) {
				net_err_ratelimited("%s: %s: can't decrypt\n",
						__func__, dev->name);
				err = PTR_ERR(skb);
				skb = NULL;
				goto out_clean_skb;
			}
			decrypted = true;

		} else if (ft & UNET_FRAGMENT_INTERNAL) {

			/* check if we found the frag x-frame */
			if (!n_frags || !frag_fullsize || frag >= n_frags) {
				net_err_ratelimited("%s: %s: bad fragment data\n",
						__func__, dev->name);
				err = -EINVAL;
				goto out_clean_skb;
			}

			skb = unet_entity_reassemble_skb(ufe.next_hop_ue,
							 ufe.sender_ue,
							 skb, x_hdrsz,
							 frag, n_frags,
							 frag_fullsize,
							 frag_crc); 

			/* reassembly not complete? just return */
			if (!skb) {
				err = 0;
				goto out_clean_skb;
			}

			if (IS_ERR(skb)) {
				net_err_ratelimited("%s: %s: can't reassemble\n",
						__func__, dev->name);
				err = PTR_ERR(skb);
				skb = NULL;
				goto out_clean_skb;
			}

			reassembled = true;
		}

		if (uce)
			unet_conn_entry_put(uce);
		if (ufe.sender_ue)
			unet_entity_put(ufe.sender_ue);
		if (ufe.next_hop_ue)
			unet_entity_put(ufe.next_hop_ue);

		uce = NULL;
		ufe.sender_ue = NULL;
		ufe.next_hop_ue = NULL;

		goto process_again;
	}

	/* construct fsm event for the frame type */
	ufe.type = unet_fsm_event_type_from_frame_type(uph->frame_type);
	if (ufe.type == unet_fsm_event_type_error) {
		net_err_ratelimited("%s: %s: bad frame type\n",
				__func__, dev->name);
		goto out_clean_skb;
	}

	message_type = unet_packet_message_type(uph);

	/* fill in all possible info so that the handler don't need to do it */
	ufe.b = b;
	ufe.skb = skb;
	ufe.size = ucb->size;
	if (ufe.size)
		ufe.data = unet_skb_data_offset_to_ptr(skb, ucb->data_offset);
	else
		ufe.data = NULL;
	ufe.uph = uph;
	ufe.x_list = &ucb->x_list;

	/* get originator */
	ufe.orig_ua = unet_packet_get_orig_addr(uph);
	/* get destinator */
	ufe.dest_ua = unet_packet_get_dest_addr(uph);

	/* validate that no orig/dest parents exists on visible only */
	if (unet_message_is_visible_only(message_type)) {
		if (ufe.orig_ua && unet_packet_has_orig_parent(uph)) {
			net_err_ratelimited("%s: %s: orig parent on visible only\n",
					__func__, dev->name);
			goto out_clean_skb;
		}
		if (ufe.dest_ua && unet_packet_has_dest_parent(uph)) {
			net_err_ratelimited("%s: %s: dest parent on visible only\n",
					__func__, dev->name);
			goto out_clean_skb;
		}
	}

	if (ufe.orig_ua)
		ufe.orig_ue = unet_entity_lookup_by_addr(un, ufe.orig_ua);

	if (ufe.dest_ua)
		ufe.dest_ue = unet_entity_lookup_by_addr(un, ufe.dest_ua);

	/* get and save media address */
	memset(&media_addr, 0, sizeof(media_addr));
	err = b->media->raw2addr(b, &media_addr, b->media->skb_source_addr(b, skb));
	if (err) {
		net_err_ratelimited("%s: %s: Failed to get media source address\n",
				__func__, dev->name);
		goto out_clean_skb;
	}
	ufe.media_addr = &media_addr;

	/* hook to the raw socket interface */
	unet_raw_deliver(net, skb);

	/* create an entity if it should be */
	err = unet_fsm_create_orig_entity_if_needed(un, &ufe);
	if (err) {
		net_err_ratelimited("%s: %s: Failed to create entity\n",
				__func__, dev->name);
		goto out_clean_skb;
	}

	/* update entity properties */
	err = unet_fsm_update_orig_entity_if_needed(net, &ufe);
	if (err) {
		net_err_ratelimited("%s: %s: Failed to update entity\n",
				__func__, dev->name);
		goto out_clean_skb;
	}

	/* handle X entries (after main frame) */
	list_for_each_entry(uxe, &ucb->x_list, node) {
		if (uxe->type == UNET_X_ADDRESS_SENDER && !ufe.sender_ua)
			ufe.sender_ua = &uxe->addr;
		else if (uxe->type == UNET_X_ADDRESS_NEXT_HOP && !ufe.next_hop_ua)
			ufe.next_hop_ua = &uxe->addr;
		else if (uxe->type == UNET_X_KEEP_ALIVE && !ufe.keepalive_nonce)
			ufe.keepalive_nonce = uxe->nonce;
	}

	if (ufe.sender_ua)
		ufe.sender_ue = unet_entity_lookup_by_addr(un, ufe.sender_ua);

	if (ufe.next_hop_ua)
		ufe.next_hop_ue = unet_entity_lookup_by_addr(un, ufe.next_hop_ua);

	/* get sender UE */
	if (ufe.sender_ue)
		ue = ufe.sender_ue;
	else if (!ufe.sender_ua)
		ue = ufe.orig_ue;
	if (ue && !reassembled) {
		/* bearer changed? generate event */
		if (ue->b && ue->b != b) {
			/* save event type */
			save_event_type = ufe.type;
			ufe.type = unet_fsm_event_type_entity_bearer_change;
			err = unet_entity_fsm(net, &ufe);
			if (err) {
				unet_fsm_err(ue, "dev-%s: FSM failed for bearer change\n",
						netdev_name(dev));
				goto out_clean_skb;
			}
			ufe.type = save_event_type;
			ue->b = NULL;	/* clear bearer to force update of mac */
		}

		/* TODO more efficient mac address comparisons and saving */
		if (!ue->b) {	/* first time */
			ue->b = b;	/* save bearer for remote */
			memcpy(&ue->media_addr, &media_addr, sizeof(media_addr));
			unet_fsm_info(ue, "dev-%s: setting mac to %pM\n",
					netdev_name(dev), ue->media_addr.value);
		} else if (memcmp(&ue->media_addr, &media_addr, sizeof(media_addr))){
			/* TODO same bearer, check if mac-addr changed */
			/* ignore for now */
			memcpy(&ue->media_addr, &media_addr, sizeof(media_addr));
			unet_fsm_info(ue, "dev-%s: updating mac to %pM\n",
					netdev_name(dev), ue->media_addr.value);
		}
	}

	/* got a new cert - instantiate */
	if (ufe.orig_ue && ufe.orig_ue_prop_changed) {
		orig_ue = ufe.orig_ue;
		dest_ue = ufe.dest_ue;

		if (ufe.orig_ue_prop_changed & UNET_PROP_CHANGE_CERT)
			err = unet_entity_update_remote_cert(orig_ue,
					orig_ue->utb.type,
					orig_ue->utb.tb_cert,
					orig_ue->utb.tb_cert_size);

		if (ufe.orig_ue_prop_changed & UNET_PROP_CHANGE_ENCRYPTED) {

			if (dest_ue && orig_ue->utb.tb_decrypt_pending) {
				err = unet_entity_decrypt_remote(dest_ue, orig_ue,
					orig_ue->utb.tb_enc_type,
					orig_ue->utb.tb_enc,
					orig_ue->utb.tb_enc_size);
				if (!err)
					orig_ue->utb.tb_decrypt_pending = false;
			}

		}
	}


	/* if there's no destinator entity, deliver to all local entities */
	if (!ufe.dest_ue && !ufe.next_hop_ue) {
		/* pass the APCR to every local entity */
		spin_lock(&un->entity_list_lock);
		unet_for_each_local_entity_safe(un, ue, uet) {
			ufe.dest_ue = unet_entity_get(ue);
			spin_unlock(&un->entity_list_lock);

			err = unet_entity_fsm(net, &ufe);

			unet_entity_put(ufe.dest_ue);
			ufe.dest_ue = NULL;

			if (err) {
				net_err_ratelimited("%s: %s: FSM failed for broadcast\n",
						__func__, dev->name);
				goto out_clean_skb;
			}

			spin_lock(&un->entity_list_lock);
		}
		spin_unlock(&un->entity_list_lock);
	} else {
		/* pass it to the FSM */
		err = unet_entity_fsm(net, &ufe);
		if (err) {
			net_err_ratelimited("%s: %s: FSM failed for frame\n",
					__func__, dev->name);
			goto out_clean_skb;
		}

		if (ufe.keepalive_nonce) {
			ufe.type = unet_fsm_event_type_keepalive;

			err = unet_entity_fsm(net, &ufe);
			if (err) {
				net_err_ratelimited("%s: %s: FSM failed for x-frame\n",
						__func__, dev->name);
				goto out_clean_skb;
			}
		}
	}

out_clean_skb:
	if (uce)
		unet_conn_entry_put(uce);

	if (ufe.orig_ue && !ufe.orig_ue_fresh)
		unet_entity_put(ufe.orig_ue);

	if (ufe.dest_ue)
		unet_entity_put(ufe.dest_ue);

	if (ufe.next_hop_ue)
		unet_entity_put(ufe.next_hop_ue);

	if (ufe.sender_ue)
		unet_entity_put(ufe.sender_ue);

	if (skb)
		unet_skb_cb_cleanup(skb);

out:
	if (skb)
		kfree_skb(skb);

	return err;
}

int unet_rx_handle_skb(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	struct unet_net *un = unet_net(net);
	struct sk_buff *skbn;

	/* TODO fast path processing? */
	skbn = skb_clone(skb, GFP_ATOMIC);
	if (!skbn)
		return -ENOMEM;

	skb_queue_tail(&un->rx_skb_list, skbn);
	unet_kthread_schedule(un);
	return 0;
}

int unet_tx_ip_handle_skb(struct unet_entity *ue, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct unet_dev_priv *udp = netdev_priv(dev);
	int err;

	err = unet_entity_send(ue, unet_entity_addr(ue), &udp->cfg.remote_ua,
			       UNET_MSG_IP, skb->data, skb->len);

	if (err) {
		skb_tx_error(skb);
		kfree_skb(skb);
	} else
		consume_skb(skb);

	return err;
}

const char *unet_entity_state_txt(enum unet_entity_state state)
{
	switch (state) {
	case unet_entity_state_unknown:
		return "unknown";
	case unet_entity_state_unregistered:
		return "unregistered";
	case unet_entity_state_registration_pending:
		return "registration_pending";
	case unet_entity_state_registered:
		return "registered";
	case unet_entity_state_disconnected:
		return "disconnected";
	case unet_entity_state_error:
		return "error";
	default:
		break;
	}
	return "*BAD-STATE*";
}

void unet_entity_stop_all_timeouts(struct unet_entity *ue)
{
	if (!ue)
		return;

	if (ue->type == unet_entity_type_local) {
		unet_entity_stop_apcr_timeout(ue);
		unet_entity_stop_apca_timeout(ue);
		unet_entity_stop_register_timeout(ue);
		unet_entity_stop_housekeeping_timeout(ue);
	} else
		unet_entity_stop_alive_timeout(ue);
}

/* must be under rcu_read_lock and must hold the ue->lock */
void unet_set_entity_state(struct unet_entity *ue,
		enum unet_entity_state state)
{
	struct unet_net *un = unet_net(unet_entity_net(ue));
	enum unet_entity_state old_state = ue->state;
	struct unet_entity *ue_parent;
	struct unet_entity *ue_router;
	struct unet_conn_entry *uce;

	/* nag if transitioning to the same state */
	if (WARN_ON(ue->state == state))
		return;

	/* state changes only for local entities */
	if (ue->type != unet_entity_type_local) {
		ue->state = state;
		goto done;
	}

	switch (state) {
	case unet_entity_state_unregistered:
		ue->state = state;
		unet_entity_remove_all_routers(ue, false);
		unet_entity_remove_all_parents(ue);
		unet_entity_send_to_visible(ue, NULL, NULL,
					    UNET_MSG_APCR, NULL, 0);
		unet_entity_start_apcr_timeout(ue, un->apcr_min_timeout);
		unet_entity_start_housekeeping_timeout(ue, un->housekeeping_timeout);
		break;
	case unet_entity_state_registration_pending:
		ue_router = unet_entity_get_registering_router(ue);
		if (!ue_router) {
			unet_entity_err(ue, "Can't find registering router\n");
			goto bad_fsm;
		}

		ue->state = state;

		unet_entity_stop_apcr_timeout(ue);
		ue->register_retries = 0;
		unet_entity_start_register_timeout(ue, un->register_timeout);

		uce = unet_conn_entry_lookup(ue, ue_router);

		unet_entity_send_to_visible(ue, ue_router, uce, UNET_MSG_R, NULL, 0);

		if (uce) {
			unet_conn_entry_put(uce);
			uce = NULL;
		}

		unet_entity_put(ue_router);
		ue_router = NULL;

		break;

	case unet_entity_state_registered:
		unet_entity_stop_register_timeout(ue);

		ue->state = state;

		/* kick everything upstream */
		unet_entity_send(ue, NULL, &unet_root_addr,
					UNET_MSG_RFDR, NULL, 0);
		/* TODO: send periodically? start timeout? */

		if (!un->try_reconnect_to_children)
			break;

		generate_random_uuid(ue->rc_uuid);
		unet_entity_send_to_all_visible_children(ue,
				UNET_MSG_RC, NULL, 0);
		break;

	case unet_entity_state_disconnected:

		/* this travels upstream */
		ue_parent = unet_entity_get_parent(ue);
		if (ue_parent) {
			unet_entity_send(ue, NULL, &unet_root_addr,
					 UNET_MSG_DA, NULL, 0);
			unet_entity_put(ue_parent);
			ue_parent = NULL;
		}

		unet_entity_send_to_all_visible_children(ue,
				UNET_MSG_DA, NULL, 0);

		ue->state = state;

		unet_entity_remove_all_routers(ue, false);
		unet_entity_remove_all_conn(ue);
		unet_entity_remove_all_next_hops(ue);
		unet_entity_stop_apcr_timeout(ue);
		unet_entity_stop_apca_timeout(ue);
		unet_entity_stop_register_timeout(ue);
		unet_entity_stop_housekeeping_timeout(ue);
		break;

	default:
		ue->state = state;
		break;
	}

done:
	unet_fsm_info(ue, "state change %s -> %s\n",
				unet_entity_state_txt(old_state),
				unet_entity_state_txt(state));

	return;

bad_fsm:
	unet_fsm_info(ue, "bad state transition from %d -> %d\n",
			ue->state, state);
}
