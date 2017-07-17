/*
 * net/unet/fsm.h: Include file for uNet FSM (finite state machine)
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

#ifndef _UNET_FSM_H
#define _UNET_FSM_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/unet.h>
#include <linux/net.h>

struct unet_entity;
struct unet_packet_header;
struct unet_x_entry;
struct unet_bearer;
struct unet_media_addr;

int unet_rx_handle_skb(struct sk_buff *skb);
int unet_rx_handle_skb_slow(struct sk_buff *skb);

int unet_tx_ip_handle_skb(struct unet_entity *ue, struct sk_buff *skb);

enum unet_fsm_event_type {
	unet_fsm_event_type_error,	/* error type */

	/* packets */
	unet_fsm_event_type_x_frame_recv,
	unet_fsm_event_type_bta_frame_recv,
	unet_fsm_event_type_pta_frame_recv,
	unet_fsm_event_type_ptp_frame_recv,
	/* timeouts */
	unet_fsm_event_type_apcr_timeout,
	unet_fsm_event_type_alive_timeout,
	unet_fsm_event_type_apca_timeout,
	unet_fsm_event_type_register_timeout,
	/* keepalive */
	unet_fsm_event_type_keepalive,
	/* not handled yet */
	unet_fsm_event_type_iface_change,
	unet_fsm_event_type_entity_bearer_change,
	unet_fsm_event_type_media_address_change,
	unet_fsm_event_type_housekeeping_timeout,
	/* IP bridging */
	unet_fsm_event_type_ip_xmit,
	/* TODO add others */
};

#define unet_fsm_event_type_timeout_start unet_fsm_event_type_apcr_timeout
#define unet_fsm_event_type_timeout_end unet_fsm_event_type_register_timeout

#define unet_fsm_event_is_timeout(_ev) ({ \
		int __ev = (int)(_ev); \
		__ev >= unet_fsm_event_type_timeout_start && \
			__ev <= unet_fsm_event_type_timeout_end; \
	})

struct unet_fsm_event {
	enum unet_fsm_event_type type;
	struct unet_bearer *b;		/* when applicable */
	struct sk_buff *skb;		/* when applicable */
	const void *data;		/* skb's data window */
	unsigned int size;		/* skb's data window size */
	struct unet_packet_header *uph; /* for all other frames */
	struct list_head *x_list;	/* the list of all x frames */
	struct unet_x_entry *uxe;	/* current x frame */
	struct unet_addr *orig_ua;
	struct unet_addr *dest_ua;
	struct unet_addr *sender_ua;	/* from X_ADDRESS_SENDER */
	struct unet_addr *next_hop_ua;	/* X_ADDRESS_NEXT_HOP */
	struct unet_entity *orig_ue;
	bool orig_ue_fresh;		/* true if it was created from packet */
	unsigned int orig_ue_prop_changed;	/* properties that changed */ 
	struct unet_entity *dest_ue;
	struct unet_entity *sender_ue;			/* from X_ADDRESS_SENDER */
	struct unet_entity *next_hop_ue;		/* X_ADDRESS_NEXT_HOP */
	struct unet_media_addr *media_addr;
	uint8_t *keepalive_nonce;
};

int unet_fsm_create_entity_if_needed(struct net *net,
				     struct unet_fsm_event *ufe);
int unet_entity_fsm(struct net *net, struct unet_fsm_event *ufe);

static inline enum unet_fsm_event_type
unet_fsm_event_type_from_frame_type(uint8_t frame_type)
{
	switch (frame_type) {
	case UNET_BTA:	/* beacon */
		return unet_fsm_event_type_bta_frame_recv;
	case UNET_PTA:
		return unet_fsm_event_type_pta_frame_recv;
	case UNET_PTP:
		return unet_fsm_event_type_ptp_frame_recv;
	default:
		/* nothing */
		break;
	}
	return unet_fsm_event_type_error;
}

void unet_entity_stop_all_timeouts(struct unet_entity *ue);

/* transition to a new state */
void unet_set_entity_state(struct unet_entity *ue,
			   enum unet_entity_state state);
void unet_entity_start_apcr_timeout(struct unet_entity *ue,
				    unsigned long timeout);
void unet_entity_stop_apcr_timeout(struct unet_entity *ue);

const char *unet_entity_state_txt(enum unet_entity_state state);

#endif
