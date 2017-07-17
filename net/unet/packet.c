/*
 * net/unet/packet.c: uNet packet generation
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

#include <linux/jhash.h>
#include <linux/crc16.h>
#include <linux/bitops.h>

#include "core.h"
#include "bearer.h"
#include "packet.h"
#include "utils.h"
#include "router.h"

/* caches for commonly used structures */
struct kmem_cache *unet_packet_header_cache;
struct kmem_cache *unet_x_entry_cache;

static void *unet_trust_bundle_put(struct unet_entity *orig_ue,
		struct unet_entity *dest_ue,
		struct unet_conn_entry *uce,
		uint32_t message_type, uint8_t n_chunks, uint8_t chunk,
		uint16_t *crc, uint8_t *tb_type,
		uint16_t *tbfullsz, void *p)
{
	void *tb = NULL, *cert = NULL;
	void *encout = NULL, *encin = NULL;
	uint16_t certsz, tbsz, chunksz = 0;
	unsigned int allocsz, encsz;
	struct kernel_pkey_params pkp;
	uint16_t tmp_crc, tmp_tbfullsz;
	uint8_t tmp_type;
	int err = -EINVAL;

	if (!crc)
		crc = &tmp_crc;
	if (!tb_type)
		tb_type = &tmp_type;
	if (!tbfullsz)
		tbfullsz = &tmp_tbfullsz;

	if (!uce && dest_ue) {
		unet_entity_err(orig_ue, "No conn entry for %s\n",
				unet_entity_name(dest_ue));
		p = ERR_PTR(-EINVAL);
		goto out;
	}

	cert = orig_ue->cert_blob;
	certsz = orig_ue->cert_blob_size;
	if (!cert || !certsz) {
		p = ERR_PTR(-EINVAL);
		goto out;
	}
	tb = NULL;

	switch (message_type) {
	case UNET_MSG_APCR:
		*tb_type = UNET_TB_TYPE_X509_CERT;
		*tbfullsz = certsz;
		tb = cert;
		break;
	case UNET_MSG_APCA:
		if (!dest_ue || !uce || !uce->has_nonce1) {
			p = ERR_PTR(-EINVAL);
			goto out;
		}
		*tb_type = UNET_TB_TYPE_X509_CERT_NONCE1;
		*tbfullsz = certsz + uce->ue->cert_key_enc_size;
		break;
	case UNET_MSG_R:
		if (!dest_ue || !uce || !uce->has_nonce1 || !uce->has_nonce2) {
			p = ERR_PTR(-EINVAL);
			goto out;
		}
		*tb_type = UNET_TB_TYPE_NONCE1_NONCE2;
		*tbfullsz = uce->ue->cert_key_enc_size;
		break;
	case UNET_MSG_RR:
		if (!dest_ue || !uce || !uce->has_nonce2) {
			p = ERR_PTR(-EINVAL);
			goto out;
		}
		*tb_type = UNET_TB_TYPE_NONCE2;
		*tbfullsz = uce->ue->cert_key_enc_size;
		break;
	default:
		p = ERR_PTR(-EINVAL);
		goto out;
	}

	/* allocate scratch buffer if we need it */
	if (!tb && uce && (!uce->scratch || uce->scratch_size < *tbfullsz)) {
		kfree(uce->scratch);
		uce->scratch_size = 0;
		allocsz = orig_ue->cert_blob_size +
			  orig_ue->cert_key_enc_size +
			  dest_ue->cert_key_enc_size;
		allocsz = PAGE_ALIGN(allocsz);
		uce->scratch = kmalloc(allocsz, GFP_KERNEL);
		if (!uce->scratch) {
			p = ERR_PTR(-ENOMEM);
			goto out;
		}
		uce->scratch_size = allocsz;
	}

	/* copy the cert + material to the scratch buffer */
	switch (*tb_type) {
	case UNET_TB_TYPE_X509_CERT:
		break;
	case UNET_TB_TYPE_X509_CERT_NONCE1:
		tb = uce->scratch;
		memcpy(tb, cert, certsz);
		encout = tb + certsz;
		encin = uce->nonce1;
		encsz = UNET_TB_NONCE_SIZE;
		break;
	case UNET_TB_TYPE_NONCE1_NONCE2:
		tb = uce->scratch + UNET_TB_NONCE_SIZE * 2;
		memcpy(uce->scratch, uce->nonce1, UNET_TB_NONCE_SIZE);
		memcpy(uce->scratch + UNET_TB_NONCE_SIZE, uce->nonce2,
				UNET_TB_NONCE_SIZE);
		encin = uce->scratch;
		encsz = UNET_TB_NONCE_SIZE * 2;
		encout = tb;
		break;
	case UNET_TB_TYPE_NONCE2:
		tb = uce->scratch + UNET_TB_NONCE_SIZE;
		encout = tb + certsz;
		encin = uce->nonce2;
		encsz = UNET_TB_NONCE_SIZE;
		encout = tb;
		break;
	default:
		encin = NULL;
		encout = NULL;
		break;
	}

	if (!tb) {
		p = ERR_PTR(-EINVAL);
		goto out;
	}

	/* only encrypt on the first chunk */
	if (encin && encout && chunk == 0) {
		/* encrypt nonce with remote's key */
		memset(&pkp, 0, sizeof(pkp));
		pkp.key = key_ref_to_ptr(uce->ue->cert_key);
		pkp.encoding = "pkcs1";
		pkp.hash_algo = "sha256";
		pkp.in_len = encsz;
		pkp.out_len = uce->ue->cert_key_enc_size;
		err = encrypt_blob(&pkp, encin, encout);
		if (err < 0) {
			unet_entity_err(orig_ue, "Failed to encrypt\n");
			p = ERR_PTR(err);
			goto out;
		}
	}

	*crc = crc16(0, tb, *tbfullsz);

	if (n_chunks) {
		/* the chunks up until the last are equal sized */
		/* while the last one get the remaining data */
		chunksz = *tbfullsz / n_chunks;
		tb += chunk * chunksz;
		if (chunk < (n_chunks - 1))
			tbsz = chunksz;
		else
			tbsz = *tbfullsz - chunksz * (n_chunks - 1);
	} else
		tbsz = *tbfullsz;

	p = uput16(tbsz, p);
	p = uput(tb, tbsz, p);

out:
	return p;
}

int unet_update_frame_size_params(struct unet_frame_params *ufp)
{
	struct unet_entity *ue, *nh;
	int err;

	ue = ufp->sender_ue;
	nh = ufp->next_hop_ue;

	ufp->x_hdrsz = ufp->x_userhdrsz;

	/* encrypted, if some x-frames are not present they must be added */
	if (ufp->encrypted && !ufp->will_fragment) {
		if (!ufp->xe_present) 
			ufp->x_hdrsz += UNET_XE_HDR_MIN;
	}

	/* always adding next hop and sender */
	if (unet_message_should_append_next_hop_sender(ufp->message_type)) {

		/* TODO maybe optimize? */
		if (nh && !ufp->xnh_present)
			ufp->x_hdrsz += UNET_XA_HDR_MIN +
					nh->ae.prop.ua.prefix_len +
					nh->ae.prop.ua.id_len;
		if (ue && !ufp->xsnd_present)
			ufp->x_hdrsz += UNET_XA_HDR_MIN +
					ue->ae.prop.ua.prefix_len +
					ue->ae.prop.ua.id_len;
	}

	/* size of the non-x part */
	ufp->pldsz = ufp->pta_ptp_hdrsz + ufp->tb_hdrsz +
		     ufp->tlv_hdrsz + ufp->data_sz;
	ufp->size = ufp->x_hdrsz + ufp->pldsz;

	/* calculate the encryption payload size */
	if (ufp->encrypted && !ufp->will_fragment) {
		err = unet_conn_entry_encrypted_size(ufp->uce, ufp->pldsz);
		if (err < 0)
			return err;
		ufp->epldsz = err;
		ufp->esize = ufp->x_hdrsz + ufp->epldsz;
	} else {
		ufp->epldsz = ufp->pldsz;
		ufp->esize = ufp->size;
	}

	if (!ufp->dev && ufp->b)
		ufp->dev = ufp->b->dev_ptr;	/* XXX RCU? */

	if (ufp->dev)
		ufp->devsz = ufp->dev->hard_header_len + ufp->esize;
	else
		ufp->devsz = ufp->esize;

	return 0;
}

static int unet_calculate_frame_params_x_hdrsz(struct unet_frame_params *ufp)
{
	struct unet_x_entry *uxe;

	/* clear xlist scan variables */
	ufp->xe_present = 0;
	ufp->xnh_present = 0;
	ufp->xsnd_present = 0;

	/* calculate the amount of space the x-frames take */
	ufp->x_hdrsz = 0;
	if (ufp->x_list) {
		list_for_each_entry(uxe, ufp->x_list, node) {
			/* XF frame should not be added by users */
			if (!UNET_X_IS_HANDLED(uxe->type) ||
			    UNET_X_IS_XF(uxe->type))
				return -EINVAL;

			if (UNET_X_IS_XA(uxe->type)) {
				ufp->x_hdrsz += UNET_XA_HDR_MIN +
						uxe->addr.prefix_len +
						uxe->addr.id_len;
				if (!ufp->xnh_present &&
				    uxe->type == UNET_X_ADDRESS_NEXT_HOP)
					ufp->xnh_present = 1;
				if (!ufp->xsnd_present &&
				    uxe->type == UNET_X_ADDRESS_SENDER)
					ufp->xsnd_present = 1;
			} else if (UNET_X_IS_XE(uxe->type)) {
				ufp->x_hdrsz += UNET_XE_HDR_MIN;
				if (!ufp->xe_present &&
				    uxe->type == UNET_X_ENCRYPTED)
					ufp->xe_present = 1;
			} else if (UNET_X_IS_XN(uxe->type))
				ufp->x_hdrsz += UNET_XN_HDR_MIN;
			else if (UNET_X_IS_XH(uxe->type))
				ufp->x_hdrsz += UNET_XH_HDR_MIN;
		}
	}

	ufp->x_userhdrsz = ufp->x_hdrsz;

	/* if it's not encrypted you shouldn't pass X_E */
	if (!ufp->encrypted && ufp->xe_present)
		return -EINVAL;

	return 0;
}

int unet_calculate_frame_size_params(struct unet_frame_params *ufp)
{
	struct unet_entity *ue, *nh;
	unsigned int chunksz;
	int err;

	if (!ufp->orig_ua)
		return -EINVAL;

	/* if there are chunks, verify */
	if (ufp->n_chunks > 0 && ufp->chunk >= ufp->n_chunks)
		return -EINVAL;

	/* get short hand variables */
	ue = ufp->sender_ue;
	nh = ufp->next_hop_ue;

	/* sender must exist */
	if (!ue)
		return -EINVAL;

	/* the entity types must match */
	if (ue->type != unet_entity_type_local ||
	    (nh && nh->type != unet_entity_type_remote))
		return -EINVAL;

	/* start filling in flags */
	ufp->flags = 0;

	/* fill in originator parent flag */
	if (ufp->orig_ua->parent_prefix_len || ufp->orig_ua->parent_id_len)
		ufp->flags |= UNET_F_ORIG_PARENT;

	/* fill in destinator parent flag */
	if (ufp->dest_ua &&
	    (ufp->dest_ua->parent_prefix_len || ufp->dest_ua->parent_id_len))
		ufp->flags |= UNET_F_DEST_PARENT;

	/* turn on trust bit on APCR/APCA if we have the keys */
	if (ue && ue->keys_verified && ue->cert_blob &&
	    (ufp->message_type == UNET_MSG_APCR ||
	     ufp->message_type == UNET_MSG_APCA))
		ufp->flags |= UNET_F_TRUST;

	if (ufp->uce) {
		ufp->secure = unet_conn_entry_is_secure(ufp->uce);
		ufp->trusted = unet_conn_entry_is_trusted(ufp->uce);
		ufp->crypto_ready = unet_conn_entry_is_crypto_ready(ufp->uce);
	}

	/* if we have a connection entry and is secure turn trust on R/RR */
	if (ufp->secure && (ufp->message_type == UNET_MSG_R ||
			    ufp->message_type == UNET_MSG_RR))
		ufp->flags |= UNET_F_TRUST;

	/* remove timestamp? */
	if (ufp->no_timestamp)
		ufp->flags |= UNET_F_NO_TIMESTAMP;

	/* set when we have to encrypt */
	ufp->encrypted = ufp->crypto_ready &&
			 unet_message_can_be_encrypted(ufp->message_type);

	/* calculate the size of the xhdr */
	err = unet_calculate_frame_params_x_hdrsz(ufp);
	if (err)
		return err;

	/* calculate size of PTA/PTP header */
	ufp->pta_ptp_hdrsz = PTx_FIXED_HDR;

	if (ufp->dest_ua) {
		if (ufp->flags & UNET_F_DEST_PARENT)
			ufp->pta_ptp_hdrsz += UNET_UA_MIN;
		ufp->pta_ptp_hdrsz += UNET_UA_MIN;
	}

	if (ufp->flags & UNET_F_ORIG_PARENT)
		ufp->pta_ptp_hdrsz += UNET_UA_MIN;
	ufp->pta_ptp_hdrsz += UNET_UA_MIN;

	if (ufp->dest_ua) {
		if (ufp->flags & UNET_F_DEST_PARENT)
			ufp->pta_ptp_hdrsz += ufp->dest_ua->parent_prefix_len +
					      ufp->dest_ua->parent_id_len;

		ufp->pta_ptp_hdrsz += ufp->dest_ua->prefix_len +
				      ufp->dest_ua->id_len;
	}

	if (ufp->flags & UNET_F_ORIG_PARENT)
		ufp->pta_ptp_hdrsz += ufp->orig_ua->parent_prefix_len +
				      ufp->orig_ua->parent_id_len;

	ufp->pta_ptp_hdrsz += ufp->orig_ua->prefix_len +
			      ufp->orig_ua->id_len;

	if (!(ufp->flags & UNET_F_NO_TIMESTAMP))
		ufp->pta_ptp_hdrsz += UNET_MASTER_TIMESTAMP_SZ +
				      UNET_FIRING_TIME_SZ;

	/* these kind of messages are local and need an entity */
	if (!ue && unet_message_requires_local_entity(ufp->message_type))
		return -EINVAL;

	/* fragmentation requested with no trust bundle? can't do */
	if (ufp->n_chunks && !(ufp->flags & UNET_F_TRUST))
		return -EINVAL;

	/* calculate size (of possibly fragmented) trust bundle */
	ufp->tb_hdrsz = 0;
	ufp->tb_type = UNET_TB_TYPE_UNKNOWN;
	if (ufp->flags & UNET_F_TRUST) {

		switch (ufp->message_type) {
		case UNET_MSG_APCR:
			ufp->tb_fullsz = ue->cert_blob_size;
			ufp->tb_type = UNET_TB_TYPE_X509_CERT;
			break;
		case UNET_MSG_APCA:
			ufp->tb_fullsz = ue->cert_blob_size + nh->cert_key_enc_size;
			ufp->tb_type = UNET_TB_TYPE_X509_CERT_NONCE1;
			break;
		case UNET_MSG_R:
			ufp->tb_fullsz = nh->cert_key_enc_size;
			ufp->tb_type = UNET_TB_TYPE_NONCE1_NONCE2;
			break;
		case UNET_MSG_RR:
			ufp->tb_fullsz = nh->cert_key_enc_size;
			ufp->tb_type = UNET_TB_TYPE_NONCE2;
			break;
		default:
			return -EINVAL;
		}

		ufp->tb_hdrsz = UNET_HDR_MIN_TRUST_BUNDLE;
		if (ufp->n_chunks) {
			/* the chunks up until the last are equal sized */
			/* while the last one get the remaining data */
			chunksz = ufp->tb_fullsz / ufp->n_chunks;
			if (ufp->chunk < (ufp->n_chunks - 1))
				ufp->tb_hdrsz += chunksz;
			else
				ufp->tb_hdrsz += ufp->tb_fullsz -
						 chunksz * (ufp->n_chunks - 1);
		} else
			ufp->tb_hdrsz += ufp->tb_fullsz;
	}

	/* calculate TLV header size */
	switch (ufp->message_type) {
	case UNET_MSG_APCR:
	case UNET_MSG_APCA:
		ufp->tlv_hdrsz = UNET_HDR_MIN_TLV;

		/* I can be router */
		if (unet_entity_i_can_be_router(ue, nh))
			ufp->tlv_hdrsz += UNET_MIN_TAG_LEN;

		/* N children */
		ufp->tlv_hdrsz += UNET_MIN_TAG_LEN + sizeof(uint32_t);

		/* version */
		ufp->tlv_hdrsz += UNET_MIN_TAG_LEN + strlen(UNET_MOD_VER);

		/* dev-class */
		ufp->tlv_hdrsz += UNET_MIN_TAG_LEN + sizeof(uint32_t);

		/* N routers */
		ufp->tlv_hdrsz += UNET_MIN_TAG_LEN + sizeof(uint32_t);

		/* on trust enabled always send trust extra */
		if (ufp->flags & UNET_F_TRUST) {
			ufp->tlv_hdrsz += UNET_MIN_TAG_LEN +
					  UNET_TAG_TRUST_EXTRA_SIZE;
			ufp->tlv_hdrsz += UNET_MIN_TAG_LEN +
					  UNET_TAG_TRUST_BUNDLE_TYPE_SIZE;
		}

		break;

	case UNET_MSG_R:
		ufp->tlv_hdrsz = 0;

		/* on trust enabled always send trust extra */
		if (ufp->flags & UNET_F_TRUST) {
			ufp->tlv_hdrsz += UNET_HDR_MIN_TLV;
			ufp->tlv_hdrsz += UNET_MIN_TAG_LEN +
					  UNET_TAG_TRUST_BUNDLE_TYPE_SIZE;
		}
		break;

	case UNET_MSG_RR:
		ufp->tlv_hdrsz = UNET_HDR_MIN_TLV;

		/* response */
		ufp->tlv_hdrsz += UNET_MIN_TAG_LEN + sizeof(uint8_t);

		/* trust bundle info */
		if (ufp->flags & UNET_F_TRUST)
			ufp->tlv_hdrsz += UNET_MIN_TAG_LEN +
					  UNET_TAG_TRUST_BUNDLE_TYPE_SIZE;
	
		break;

	case UNET_MSG_RC:
		ufp->tlv_hdrsz = UNET_HDR_MIN_TLV;
		ufp->tlv_hdrsz += UNET_MIN_TAG_LEN + UUID_STRING_LEN;
		break;

	default:
		ufp->tlv_hdrsz = 0;
		break;
	}

	/* turn on extend bit if TLVs exist */
	if (ufp->tlv_hdrsz)
		ufp->flags |= UNET_F_EXTEND;

	return unet_update_frame_size_params(ufp);
}

static int unet_update_frame_size_params_tb_chunk(struct unet_frame_params *ufp,
		unsigned int chunk, unsigned int n_chunks)
{
	unsigned int chunksz;

	if (n_chunks > 0 && chunk >= n_chunks)
		return -EINVAL;

	if (!(ufp->flags & UNET_F_TRUST))
		return -EINVAL;

	ufp->chunk = chunk;
	ufp->n_chunks = n_chunks;

	ufp->tb_hdrsz = UNET_HDR_MIN_TRUST_BUNDLE;
	if (ufp->n_chunks) {
		/* the chunks up until the last are equal sized */
		/* while the last one get the remaining data */
		chunksz = ufp->tb_fullsz / ufp->n_chunks;
		if (ufp->chunk < (ufp->n_chunks - 1))
			ufp->tb_hdrsz += chunksz;
		else
			ufp->tb_hdrsz += ufp->tb_fullsz -
						chunksz * (ufp->n_chunks - 1);
	} else
		ufp->tb_hdrsz += ufp->tb_fullsz;

	return unet_update_frame_size_params(ufp);
}

static int unet_update_frame_size_params_get_n_chunks(struct unet_frame_params *ufp,
		unsigned int mtu)
{
	unsigned int n_chunks, chunksz, devsz;

	/* iteratively get the best fragmentation point */
	for (n_chunks = 2; n_chunks < UNET_TB_MAX_FRAGMENTS; n_chunks++) {

		chunksz = ufp->tb_fullsz -
			 (ufp->tb_fullsz / n_chunks) * (n_chunks - 1);
		devsz = ufp->x_hdrsz + ufp->pta_ptp_hdrsz +
			ufp->tlv_hdrsz + chunksz;

		/* MTU is larger, we're done */
		if (mtu >= devsz + UNET_BEARER_MTU_HEADROOM)
			return n_chunks;
	}

	return -E2BIG;
}

static int unet_perform_fragmentation(struct sk_buff_head *list,
			       struct unet_frame_params *ufp,
			       unsigned int mtu,
			       struct sk_buff *skb)
{
	struct unet_net *un;
	struct unet_entity *ue, *nh;
	unsigned int x_hdrsz, frag, n_frags;
	unsigned int len, elen, reserve, offset, copysz;
	unsigned int fragsz, last_fragsz, efragsz, last_efragsz;
	struct sk_buff *nskb;
	struct unet_addr *ua;
	uint16_t crc;
	void *p;
	int err;

	/* get short hand variables */
	ue = ufp->sender_ue;
	nh = ufp->next_hop_ue;

	un = unet_entity_unet(ue);

	/* dump the unfragmented packet */
	if (un->syslog_packet_dump &&
	    unet_skb_cb_prepare(skb, GFP_KERNEL, true) == 0) {
		unet_skb_dump_tx(nh->b, skb, nh->media_addr.value, true);
		unet_skb_cb_cleanup(skb);
	}

	reserve = ufp->dev ? ufp->dev->hard_header_len : 32;

	/* calculate size tack-on x-frames */
	x_hdrsz = 0;
	if (ufp->encrypted)
		x_hdrsz += UNET_XE_HDR_MIN;
	x_hdrsz += UNET_XF_HDR_MIN +
		   UNET_XA_HDR_MIN +
			nh->ae.prop.ua.prefix_len +
			nh->ae.prop.ua.id_len +
		   UNET_XA_HDR_MIN +
			ue->ae.prop.ua.prefix_len +
			ue->ae.prop.ua.id_len;

	crc = crc16(0, skb->data, skb->len);

	/* first estimate of number of fragments */
	n_frags = (skb->len + x_hdrsz) / mtu;
	if (n_frags < 2)
		n_frags = 2;

	fragsz = 0;
	last_fragsz = 0;
	efragsz = 0;
	last_efragsz = 0;

	/* find break point */
	while (n_frags < 64) {
		fragsz = skb->len / n_frags;
		/* the last fragment is the largest */
		last_fragsz = skb->len - fragsz * (n_frags - 1);

		if (ufp->encrypted) {
			err = unet_conn_entry_encrypted_size(ufp->uce, fragsz);
			if (err < 0)
				return err;
			efragsz = err;
			err = unet_conn_entry_encrypted_size(ufp->uce,
							     last_fragsz);
			if (err < 0)
				return err;
			last_efragsz = err;
			err = 0;
		} else {
			efragsz = fragsz;
			last_efragsz = last_fragsz;
		}
		if (reserve + x_hdrsz + last_efragsz < mtu)
			break;
		n_frags++;
	}
	if (n_frags >= 64)
		return -E2BIG;

	for (frag = 0; frag < n_frags; frag++) {
		len = x_hdrsz;
		elen = x_hdrsz;
		if (frag < (n_frags - 1)) {
			len += fragsz;
			elen += efragsz;
		} else {
			len += last_fragsz;
			elen += last_efragsz;
		}
		if (ufp->dev)
			nskb = __netdev_alloc_skb(ufp->dev, elen + reserve,
						GFP_KERNEL);
		else
			nskb = alloc_skb(elen + reserve, GFP_KERNEL);

		if (!nskb) {
			unet_entity_err(ue, "%s: failed to allocate skb\n",
					__func__);
			err = -ENOMEM;
			break;
		}

		err = skb_linearize(nskb);
		if (err) {
			unet_entity_err(ue, "%s: failed to linearize skb\n",
					__func__);
			break;
		}

		/* reserve headroom */
		skb_reserve(nskb, reserve);

		/* get buffer */
		p = skb_put(nskb, len);

		p = uput8(UNET_X, p);
		p = uput8(UNET_X_ADDRESS_NEXT_HOP, p);
		ua = unet_entity_addr(nh);
		p = uput8(ua->prefix_len, p);
		p = uput8(ua->id_len, p);
		p = uput(unet_addr_prefix(ua), ua->prefix_len, p);
		p = uput(unet_addr_id(ua), ua->id_len, p);

		p = uput8(UNET_X, p);
		p = uput8(UNET_X_ADDRESS_SENDER, p);
		ua = unet_entity_addr(ue);
		p = uput8(ua->prefix_len, p);
		p = uput8(ua->id_len, p);
		p = uput(unet_addr_prefix(ua), ua->prefix_len, p);
		p = uput(unet_addr_id(ua), ua->id_len, p);

		if (ufp->encrypted) {
			p = uput8(UNET_X, p);
			p = uput8(UNET_X_ENCRYPTED, p);
		}

		/* fragment must be last to stop parsing */
		p = uput8(UNET_X, p);
		p = uput8(UNET_X_FRAGMENT, p);
		p = uput16(crc, p);
		p = uput16(skb->len, p);	/* original size */
		p = uput8(n_frags, p);
		p = uput8(frag, p);

		offset = fragsz * frag;

		copysz = len - x_hdrsz;

		BUG_ON(offset >= skb->len);
		BUG_ON(offset + copysz > skb->len);
		BUG_ON(x_hdrsz + copysz > nskb->len);

		/* copy fragment data */
		skb_copy_from_linear_data_offset(skb, offset, p, copysz);

		if (ufp->encrypted) {

			/* dump before forwarding */
			if (un->syslog_packet_dump &&
			    unet_skb_cb_prepare(nskb, GFP_KERNEL, true) == 0) {
				unet_skb_dump_tx(nh->b, nskb,
						 nh->media_addr.value, true);
				unet_skb_cb_cleanup(nskb);
			}

			nskb = unet_conn_entry_encrypt_skb(ufp->uce, nskb,
							   x_hdrsz);
			/* on error the skb is consumed anyway */
			if (IS_ERR(nskb)) {
				unet_entity_err(ue, "%s: failed to encrypt frame\n",
						__func__);
				err = PTR_ERR(nskb);
				break;
			}
		}
		__skb_queue_tail(list, nskb);
	}

	/* on error, purge */
	if (err)
		__skb_queue_purge(list);

	kfree(skb);

	return err;
}

struct sk_buff *
unet_entity_reassemble_skb(struct unet_entity *ue,
			   struct unet_entity *sender_ue,
			   struct sk_buff *skb,
			   unsigned int x_hdrsz,
			   uint8_t frag, uint8_t n_frags,
			   uint16_t fullsize, uint16_t crc)
{
	struct unet_conn_entry *uce = NULL;
	enum unet_conn_type type;
	unsigned int fragsz, thisfragsz, thisskbsz, offset, reserve;
	struct sk_buff *nskb;
	int err;

	err = -EINVAL;

	/* check against known limits */
	if (!ue || !sender_ue || !skb || !n_frags ||
	    !fullsize || frag >= n_frags || n_frags > 64)
		goto out_free_skb;

	/* calculate the size that this frag should have */
	fragsz = fullsize / n_frags;
	if (frag < (n_frags - 1))
		thisfragsz = fragsz;
	else
		thisfragsz = fullsize - fragsz * (n_frags - 1);

	thisskbsz = skb->len - x_hdrsz;
	if (thisskbsz != thisfragsz) {
		unet_entity_warn(ue, "bad fragment size %u (should be %u)\n",
				thisskbsz, thisfragsz);
		goto out_free_skb;
	}

	uce = unet_conn_entry_lookup(ue, sender_ue);
	if (!uce)
		goto out_free_skb;

	/* verify connection type */
	type = unet_conn_state_to_type(uce->state);
	if (type != unet_conn_type_parent &&
	    type != unet_conn_type_child)
		goto out_free_skb;

	/* change in parameters? clean up */
	if (uce->n_frags != n_frags || uce->frag_crc != crc ||
	    uce->frag_fullsize != fullsize) {
		kfree_skb(uce->frag_skb);
		uce->frag_skb = NULL;
		uce->frag_map = 0;
		uce->n_frags = 0;
		uce->frag_crc = 0;
		uce->frag_fullsize = 0;
	}

	/* any new fragment? */
	if (!uce->frag_map) {
		if (skb->dev) {
			reserve = skb->dev->hard_header_len;
			nskb = __netdev_alloc_skb(skb->dev, fullsize + reserve,
						  GFP_KERNEL);
		} else {
			reserve = 32;
			nskb = alloc_skb(fullsize + reserve, GFP_KERNEL);
		}
		if (!nskb) {
			unet_entity_err(ue, "!skb of %u bytes\n",
					fullsize + 32);
			err = -ENOMEM;
			goto out_free_skb;
		}
		/* reserve headroom */
		skb_reserve(nskb, reserve);
		skb_put(nskb, fullsize);

		uce->frag_skb = nskb;
		uce->frag_fullsize = fullsize;
		uce->n_frags = n_frags;
		uce->frag_crc = crc;
	}

	/* duplicate fragment? */
	if (uce->frag_map & BIT_ULL(frag)) {
		unet_entity_warn(ue, "duplicate fragment #%u\n", frag);
		err = 0;
		goto out_free_skb;
	}

	offset = frag * fragsz;

	/* copy packet data without the x-header */
	skb_copy_from_linear_data_offset(skb, x_hdrsz,
					 uce->frag_skb->data + offset, 
					 thisfragsz);
	uce->frag_map |= BIT_ULL(frag);

	/* free the skb */
	kfree_skb(skb);

	/* if not everything received return 0 */
	if (uce->frag_map != (BIT_ULL(n_frags) - 1)) {
		nskb = NULL;
		goto out;
	}

	/* we got everything; crc the skb */
	crc = crc16(0, uce->frag_skb->data, uce->frag_skb->len);
	if (crc != uce->frag_crc) {
		unet_entity_warn(ue, "bad CRC 0x%04x (should be 0x%04x)\n",
				crc, uce->frag_crc);

		kfree_skb(uce->frag_skb);
		nskb = NULL;
	} else {
		unet_entity_warn(ue, "frame reassembled with %u bytes\n",
				uce->frag_skb->len);

		nskb = uce->frag_skb;
	}

	uce->frag_skb = NULL;
	uce->frag_map = 0;
	uce->n_frags = 0;
	uce->frag_crc = 0;
	uce->frag_fullsize = 0;
out:
	unet_conn_entry_put(uce);

	return nskb;

out_free_skb:
	if (uce)
		unet_conn_entry_put(uce);
	if (skb)
		kfree_skb(skb);
	return ERR_PTR(err);
}

int unet_construct_frame_params(struct sk_buff_head *list,
				struct unet_frame_params *ufp)
{
	struct unet_net *un;
	struct unet_entity *ue, *nh;
	struct sk_buff *skb;
	void *p, *pstart;
	struct unet_x_entry *uxe;
	char uuid_str[UUID_STRING_LEN + 1];
	struct unet_addr *ua;
	unsigned int mtu, reserve;
	int err;

	if (!list || !ufp)
		return -EINVAL;

	/* shorthand */
	ue = ufp->sender_ue;
	nh = ufp->next_hop_ue;

	un = unet_entity_unet(ue);

	mtu = 0;
	if (ufp->dev) {
		mtu = ufp->dev->mtu;
		if (ue->forced_mtu && mtu > ue->forced_mtu)
			mtu = ue->forced_mtu;
	}
	/* return error if an output device is provided and over the MTU */
	if (mtu && mtu < ufp->devsz + UNET_BEARER_MTU_HEADROOM) {

		ufp->will_fragment = 1;

		if (ufp->dont_fragment) {
			unet_entity_err(ue, "%s: %s MTU is %u < frame size %u + headroom %u\n",
				__func__, netdev_name(ufp->dev),
				mtu, ufp->devsz, UNET_BEARER_MTU_HEADROOM);
			return -E2BIG;
		}

		/* update frame parameters now */
		err = unet_update_frame_size_params(ufp);
		if (err) {
			unet_entity_err(ue, "%s: failed to update frame size params\n",
				       __func__);
			return err;
		}
	}

	if (ufp->dev) {
		reserve = ufp->dev->hard_header_len;
		skb = __netdev_alloc_skb(ufp->dev, ufp->devsz + reserve,
					 GFP_KERNEL);
	} else {
		reserve = 32;	/* hardcoded headroom */
		/* allocate with some headroom */
		skb = alloc_skb(ufp->devsz + reserve, GFP_KERNEL);
	}

	if (!skb)
		return -ENOMEM;

	/* reserve headroom */
	skb_reserve(skb, reserve);

	p = skb_put(skb, ufp->size);
	pstart = p;

	uuid_str[0] = '\0';

	if (ufp->x_list) {
		list_for_each_entry(uxe, ufp->x_list, node) {

			/* only handle known packet types */
			if (!UNET_X_IS_HANDLED(uxe->type)) 
				continue;

			/* we do not want XF frames out at all */
			if (UNET_X_IS_XF(uxe->type))
				continue;

			p = uput8(UNET_X, p);
			p = uput8(uxe->type, p);
			if (UNET_X_IS_XA(uxe->type)) {
				ua = &uxe->addr;
				p = uput8(ua->prefix_len, p);
				p = uput8(ua->id_len, p);
				p = uput(unet_addr_prefix(ua),
					 ua->prefix_len, p);
				p = uput(unet_addr_id(ua), ua->id_len, p);
			} else if (UNET_X_IS_XN(uxe->type))
				p = uput(uxe->nonce, sizeof(uxe->nonce), p);
			else if (UNET_X_IS_XH(uxe->type))
				p = uput16(uxe->hop_count, p);
			else if (UNET_X_IS_XE(uxe->type))
				;	/* nothing */
		}
	}

	/* if encrypted and the required tags are not present add them */
	if (ufp->encrypted && !ufp->will_fragment) {
		if (!ufp->xe_present) {
			p = uput8(UNET_X, p);
			p = uput8(UNET_X_ENCRYPTED, p);
		}
	}

	if (unet_message_should_append_next_hop_sender(ufp->message_type)) {

		/* always adding next hop and sender */
		if (nh && !ufp->xnh_present) {
			p = uput8(UNET_X, p);
			p = uput8(UNET_X_ADDRESS_NEXT_HOP, p);
			ua = unet_entity_addr(nh);
			p = uput8(ua->prefix_len, p);
			p = uput8(ua->id_len, p);
			p = uput(unet_addr_prefix(ua), ua->prefix_len, p);
			p = uput(unet_addr_id(ua), ua->id_len, p);
		}
		if (ue && !ufp->xsnd_present) {
			p = uput8(UNET_X, p);
			p = uput8(UNET_X_ADDRESS_SENDER, p);
			ua = unet_entity_addr(ue);
			p = uput8(ua->prefix_len, p);
			p = uput8(ua->id_len, p);
			p = uput(unet_addr_prefix(ua), ua->prefix_len, p);
			p = uput(unet_addr_id(ua), ua->id_len, p);
		}
	}

	p = uput8(ufp->dest_ua ? UNET_PTP : UNET_PTA, p);
	p = uput8(ufp->flags, p);
	p = uput32(ufp->pldsz, p);
	p = uput32(ufp->message_type, p);
	if (ufp->dest_ua) {
		if (ufp->flags & UNET_F_DEST_PARENT) {
			p = uput8(ufp->dest_ua->parent_prefix_len, p);
			p = uput8(ufp->dest_ua->parent_id_len, p);
		}
		p = uput8(ufp->dest_ua->prefix_len, p);
		p = uput8(ufp->dest_ua->id_len, p);
	}
	if (ufp->flags & UNET_F_ORIG_PARENT) {
		p = uput8(ufp->orig_ua->parent_prefix_len, p);
		p = uput8(ufp->orig_ua->parent_id_len, p);
	}
	p = uput8(ufp->orig_ua->prefix_len, p);
	p = uput8(ufp->orig_ua->id_len, p);
	if (ufp->dest_ua) {
		if (ufp->flags & UNET_F_DEST_PARENT) {
			p = uput(unet_addr_parent_prefix(ufp->dest_ua),
					ufp->dest_ua->parent_prefix_len, p);
			p = uput(unet_addr_parent_id(ufp->dest_ua),
					ufp->dest_ua->parent_id_len, p);
		}
		p = uput(unet_addr_prefix(ufp->dest_ua),
				ufp->dest_ua->prefix_len, p);
		p = uput(unet_addr_id(ufp->dest_ua),
				ufp->dest_ua->id_len, p);
	}
	if (ufp->flags & UNET_F_ORIG_PARENT) {
		p = uput(unet_addr_parent_prefix(ufp->orig_ua),
				ufp->orig_ua->parent_prefix_len, p);
		p = uput(unet_addr_parent_id(ufp->orig_ua),
				ufp->orig_ua->parent_id_len, p);
	}
	p = uput(unet_addr_prefix(ufp->orig_ua), ufp->orig_ua->prefix_len, p);
	p = uput(unet_addr_id(ufp->orig_ua), ufp->orig_ua->id_len, p);

	if (!(ufp->flags & UNET_F_NO_TIMESTAMP)) {
		p = uput64(ufp->master_ts, p);
		p = uput64(ufp->firing_ts, p);
	}

	if (ufp->flags & UNET_F_TRUST) {
		p = unet_trust_bundle_put(ue, nh, ufp->uce,
					  ufp->message_type,
					  ufp->n_chunks, ufp->chunk,
					  &ufp->tb_crc, NULL, NULL, p);
		if (IS_ERR(p)) {
			kfree(skb);
			return PTR_ERR(p);
		}
	}

	/* TLVs */
	if (ufp->flags & UNET_F_EXTEND) {
		p = uput16(ufp->tlv_hdrsz - sizeof(uint16_t), p);

		switch (ufp->message_type) {
		case UNET_MSG_APCR:
		case UNET_MSG_APCA:
			if (unet_entity_i_can_be_router(ue, nh))
				p = uputtag(UNET_TAG_I_CAN_BE_ROUTER, 0, p);

			p = uputtag(UNET_TAG_N_CHILDREN, sizeof(uint32_t), p);
			p = uput32(unet_entity_count_children(ue), p);

			p = uputtag(UNET_TAG_VERSION, strlen(UNET_MOD_VER), p);
			p = uput(UNET_MOD_VER, strlen(UNET_MOD_VER), p);

			p = uputtag(UNET_TAG_DEV_CLASS, sizeof(uint32_t), p);
			p = uput32(ue->ae.prop.dev_class, p);

			p = uputtag(UNET_TAG_N_ROUTERS, sizeof(uint32_t), p);
			p = uput32(unet_entity_count_routers(ue), p);

			if (ufp->flags & UNET_F_TRUST) {

				p = uputtag(UNET_TAG_TRUST_EXTRA,
					    UNET_TAG_TRUST_EXTRA_SIZE, p);

				p = uput16(ufp->tb_crc, p);
				p = uput16(ufp->tb_fullsz, p);
				p = uput8(ufp->n_chunks, p);
				p = uput8(ufp->chunk, p);

				p = uputtag(UNET_TAG_TRUST_BUNDLE_TYPE,
					    UNET_TAG_TRUST_BUNDLE_TYPE_SIZE, p);
				p = uput8(ufp->tb_type, p);
			}

			break;

		case UNET_MSG_R:
			if (ufp->flags & UNET_F_TRUST) {
				p = uputtag(UNET_TAG_TRUST_BUNDLE_TYPE,
					    UNET_TAG_TRUST_BUNDLE_TYPE_SIZE, p);
				p = uput8(ufp->tb_type, p);
			}
			break;

		case UNET_MSG_RR:
			p = uputtag(UNET_TAG_RESPONSE, sizeof(uint8_t), p);
			/* we have accepted if we already put it up as child */
			p = uput8(unet_entity_is_child(ue, nh), p);	

			if (ufp->flags & UNET_F_TRUST) {
				p = uputtag(UNET_TAG_TRUST_BUNDLE_TYPE,
					    UNET_TAG_TRUST_BUNDLE_TYPE_SIZE, p);
				p = uput8(ufp->tb_type, p);
			}
			break;

		case UNET_MSG_RC:
			unet_uuid_to_str(ue->rc_uuid, uuid_str, sizeof(uuid_str));
			p = uputtag(UNET_TAG_RECONNECT_NONCE, UUID_STRING_LEN, p);
			p = uputstr(uuid_str, p);
			break;
		}
	}

	if (ufp->data && ufp->data_sz > 0)
		p = uput(ufp->data, ufp->data_sz, p);

	/* if size is larger than the non encrypted, it's encrypted */
	if (ufp->encrypted && !ufp->will_fragment) {

		/* dump before forwarding */
		if (un->syslog_packet_dump &&
		    unet_skb_cb_prepare(skb, GFP_KERNEL, true) == 0) {
			unet_skb_dump_tx(nh->b, skb, nh->media_addr.value, true);
			unet_skb_cb_cleanup(skb);
		}

		skb = unet_conn_entry_encrypt_skb(ufp->uce, skb, ufp->x_hdrsz);
		/* on error the skb is consumed anyway */
		if (IS_ERR(skb)) {
			unet_entity_err(ue, "%s: failed to encrypt frame\n",
					__func__);
			return PTR_ERR(skb);
		}
	}

	/* no fragmentation, queue and we're done */
	if (!ufp->will_fragment) {
		__skb_queue_tail(list, skb);
		return 0;
	}

	/* cannot fragment without a connection entry */
	if (!ufp->uce) {
		unet_entity_err(ue, "%s: cannot fragment without a conn\n",
				__func__);
		goto out_err_frag;
	}

	return unet_perform_fragmentation(list, ufp, mtu, skb);

out_err_frag:
	kfree_skb(skb);
	return -E2BIG;
}

int unet_construct_frame_list(struct sk_buff_head *list,
			      struct unet_frame_params *ufp)
{
	int err;

	if (!list || !ufp || !ufp->sender_ue)
		return -EINVAL;

	err = unet_calculate_frame_size_params(ufp);
	if (err < 0) {
		unet_entity_err(ufp->sender_ue, "%s: failed to calculate frame size\n",
				__func__);
		return err;
	}

	err = unet_construct_frame_params(list, ufp);
	if (err) {
		unet_entity_err(ufp->sender_ue, "%s: failed to construct frame\n",
				__func__);
		return err;
	}

	return 0;
}

int unet_construct_forwarding_frame_list(
		struct sk_buff_head *list,
		struct unet_entity *ue, struct unet_entity *ue_next_hop,
		struct unet_conn_entry *uce,
		struct list_head *x_frame_list,
		struct sk_buff *skb_orig)
{
	struct unet_net *un;
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb_orig);
	struct sk_buff *skb;
	struct unet_x_entry *uxe;
	unsigned int mtu, x_orig_hdrsz;
	struct unet_frame_params ufp;
	struct unet_addr *ua;
	uint16_t hop_count;
	void *p;
	int err;

	if (!ue || !ue_next_hop || !ue_next_hop->b || !uce)
		return -EINVAL;

	/* sanity check that the control buffer fits */
	BUG_ON(sizeof(*ucb) > sizeof(skb->cb));

	/* check for magic */
	if (ucb->magic != UNET_SKB_CB_MAGIC) {
		unet_entity_err(ue, "%s: failed(0)\n",
				__func__);
		return -EINVAL;
	}

	un = unet_entity_unet(ue);

	memset(&ufp, 0, sizeof(ufp));

	/* general init */
	ufp.b = ue_next_hop->b;
	ufp.sender_ue = ue;
	ufp.next_hop_ue = ue_next_hop;
	ufp.uce = uce;
	ufp.orig_ua = unet_entity_addr(ue);
	ufp.dest_ua = unet_entity_addr(ue_next_hop);
	ufp.x_list = x_frame_list;

	/* get security bits */
	ufp.secure = unet_conn_entry_is_secure(ufp.uce);
	ufp.trusted = unet_conn_entry_is_trusted(ufp.uce);
	ufp.crypto_ready = unet_conn_entry_is_crypto_ready(ufp.uce);
	ufp.encrypted = ufp.crypto_ready;

	/* get size of xframe preamble and hop count */
	x_orig_hdrsz = ucb->xhdr_size;
	hop_count = 0;
	list_for_each_entry(uxe, &ucb->x_list, node) {
		if (uxe->type == UNET_X_HOP_COUNT)
			hop_count = uxe->hop_count;
	}

	/* protect for overflow */
	if (hop_count + 1 != 0)
		hop_count++;

	err = unet_calculate_frame_params_x_hdrsz(&ufp);
	if (err) {
		unet_entity_err(ue, "%s: failed to calculate x_hdrsz\n",
				__func__);
		goto out;
	}

	/* always add the hop */
	ufp.x_hdrsz += UNET_XH_HDR_MIN;
	ufp.x_userhdrsz = ufp.x_hdrsz;

	ufp.data_sz = skb_orig->len - x_orig_hdrsz;

	ufp.pldsz = skb_orig->len - x_orig_hdrsz;
	ufp.size = ufp.x_hdrsz + ufp.pldsz;

	/* no timestamps on forwarding */
	ufp.no_timestamp = 1;

	err = unet_update_frame_size_params(&ufp);
	if (err) {
		unet_entity_err(ue, "Can't update frame size params %s\n",
				unet_entity_name(ue_next_hop));
		goto out;
	}

	/* we don't need a headroom on a fragment */
	mtu = ufp.dev->mtu;
	if (ue->forced_mtu && mtu > ue->forced_mtu)
		mtu = ue->forced_mtu;
	ufp.will_fragment = mtu < ufp.devsz;

	/* once more to take into account the fragment bit */
	err = unet_update_frame_size_params(&ufp);
	if (err) {
		unet_entity_err(ue, "Can't update frame size params %s\n",
				unet_entity_name(ue_next_hop));
		goto out;
	}

	skb = __netdev_alloc_skb(ufp.dev, ufp.devsz, GFP_KERNEL);
	if (!skb) {
		unet_entity_err(ue, "failed to allocate skb\n");
		err = -ENOMEM;
		goto out;
	}

	skb_reserve(skb, ufp.dev->hard_header_len);
	p = skb_put(skb, ufp.size);

	/* put x-frames in front */
	if (x_frame_list) {
		list_for_each_entry(uxe, x_frame_list, node) {

			/* only handle XA & XN packet types */
			if (!UNET_X_IS_HANDLED(uxe->type))
				continue;

			/* do not pass fragments or hops */
			if (UNET_X_IS_XF(uxe->type) ||
			    UNET_X_IS_XH(uxe->type))
				continue;

			p = uput8(UNET_X, p);
			p = uput8(uxe->type, p);
			if (UNET_X_IS_XA(uxe->type)) {
				p = uput8(uxe->addr.prefix_len, p);
				p = uput8(uxe->addr.id_len, p);
				p = uput(unet_addr_prefix(&uxe->addr), uxe->addr.prefix_len, p);
				p = uput(unet_addr_id(&uxe->addr), uxe->addr.id_len, p);
			} else if (UNET_X_IS_XN(uxe->type))
				p = uput(uxe->nonce, sizeof(uxe->nonce), p);
			else if (UNET_X_IS_XH(uxe->type))
				p = uput16(uxe->hop_count, p);
			else if (UNET_X_IS_XE(uxe->type))
				;	/* nothing */
		}
	}

	/* always put down hop count */
	p = uput8(UNET_X, p);
	p = uput8(UNET_X_HOP_COUNT, p);
	p = uput16(hop_count, p);

	if (!ufp.xnh_present) {
		p = uput8(UNET_X, p);
		p = uput8(UNET_X_ADDRESS_NEXT_HOP, p);
		ua = unet_entity_addr(ue_next_hop);
		p = uput8(ua->prefix_len, p);
		p = uput8(ua->id_len, p);
		p = uput(unet_addr_prefix(ua), ua->prefix_len, p);
		p = uput(unet_addr_id(ua), ua->id_len, p);
	}
	if (!ufp.xsnd_present) {
		p = uput8(UNET_X, p);
		p = uput8(UNET_X_ADDRESS_SENDER, p);
		ua = unet_entity_addr(ue);
		p = uput8(ua->prefix_len, p);
		p = uput8(ua->id_len, p);
		p = uput(unet_addr_prefix(ua), ua->prefix_len, p);
		p = uput(unet_addr_id(ua), ua->id_len, p);
	}

	if (ufp.encrypted && !ufp.will_fragment) {
		p = uput8(UNET_X, p);
		p = uput8(UNET_X_ENCRYPTED, p);
	}

	/* copy packet data without the x-header */
	skb_copy_from_linear_data_offset(skb_orig, x_orig_hdrsz, p, 
					 skb_orig->len - x_orig_hdrsz);

	if (ufp.encrypted && !ufp.will_fragment) {
		/* dump before forwarding */
		if (un->syslog_packet_dump &&
		    unet_skb_cb_prepare(skb, GFP_KERNEL, true) == 0) {
			unet_skb_dump_tx(ue_next_hop->b, skb, ue_next_hop->media_addr.value, true);
			unet_skb_cb_cleanup(skb);
		}

		skb = unet_conn_entry_encrypt_skb(ufp.uce, skb, ufp.x_hdrsz);
		if (IS_ERR(skb)) {
			unet_entity_err(ue, "%s: Failed to encrypt forwarding frame\n",
					__func__);
			err = PTR_ERR(skb);
			goto out;
		}
	}

	/* a single frame, we're out */
	if (!ufp.will_fragment) {
		__skb_queue_tail(list, skb);
		err = 0;
	} else {
		/* and forward */
		err = unet_perform_fragmentation(list, &ufp, mtu, skb);
	}
out:
	return err;
}

int unet_construct_visible_list(
		struct sk_buff_head *list, struct unet_bearer *b,
		struct unet_entity *orig_ue, struct unet_entity *dest_ue,
		struct unet_conn_entry *uce,
		uint32_t message_type, const void *data, size_t data_sz)
{
	unsigned int n_chunks, chunk;
	struct unet_frame_params ufp;
	unsigned int mtu;
	int err;

	if (!list || !orig_ue)
		return -EINVAL;

	if (!b) {
		if (!dest_ue)
			return -EINVAL;
		b = dest_ue->b;
	}

	if (!b)
		return -EINVAL;
    

	memset(&ufp, 0, sizeof(ufp));
	ufp.b = b;
	ufp.sender_ue = orig_ue;
	ufp.next_hop_ue = dest_ue;
	ufp.uce = uce;
	ufp.orig_ua = orig_ue ? unet_entity_addr(orig_ue) : NULL;
	ufp.dest_ua = dest_ue ? unet_entity_addr(dest_ue) : NULL;
	ufp.message_type = message_type;
	ufp.data = data;
	ufp.data_sz = data_sz;
	/* if don't have a payload no timestamp */
	ufp.no_timestamp = !data_sz;

	err = unet_calculate_frame_size_params(&ufp);
	if (err)
		goto out;

	/* under the MTU size? send as is */
	mtu = 0;
	if (ufp.dev) {
		mtu = ufp.dev->mtu;
		if (orig_ue->forced_mtu && mtu > orig_ue->forced_mtu)
			mtu = orig_ue->forced_mtu;
	}
	if (!ufp.dev || (mtu && ufp.devsz < mtu)) {
		err = unet_construct_frame_params(list, &ufp);
		if (err) {
			pr_info("%s: Failed to construct frame\n",
					__func__);
		}
		goto out;
	}

	/* we need to fragment (but we only support this on APCR/APCA */
	if (ufp.message_type == UNET_MSG_APCR || 
	    ufp.message_type == UNET_MSG_APCA) {


		/* we don't support data window fragmentation yet */
		if (ufp.data || ufp.data_sz) {
			err = -E2BIG;
			goto out;
		}

		/* get n_chunk point */
		err = unet_update_frame_size_params_get_n_chunks(&ufp, mtu);
		if (err < 0)
			goto out;


		n_chunks = err;
		err = 0;
		for (chunk = 0; chunk < n_chunks; chunk++) {

			err = unet_update_frame_size_params_tb_chunk(&ufp,
					chunk, n_chunks);
			if (err) {
				unet_entity_err(orig_ue,
						"Can't update tb chunk\n");
				goto out;
			}

			err = unet_construct_frame_params(list, &ufp);
			if (err)
				goto out;
		}
	} else {
		unet_entity_err(orig_ue, "fragmentation not supported\n");

		err = -E2BIG;
	}
out:
	/* on error, purge */
	if (err)
		__skb_queue_purge(list);

	return err;
}

static const void *unet_tag_decode_bool(const void *tag, uint8_t tag_len,
		bool *v)
{
	uint8_t t;

	/* valid lengths is 0 and 1 */
	if (tag_len > 1)
		return ERR_PTR(-EINVAL);

	/* tag exists (but no content? set to true */
	if (tag_len == 0) {
		*v = true;
		return tag;
	}

	tag = uget8(&t, tag);
	*v = !!t;	/* zero false, anything else true */
	return tag;
}

static const void *unet_tag_decode_u32(const void *tag, uint8_t tag_len,
		uint32_t *v)
{
	if (tag_len != sizeof(uint32_t))
		return ERR_PTR(-EINVAL);
	return uget32(v, tag);
}

static const void *unet_tag_decode_u16(const void *tag, uint8_t tag_len,
		uint16_t *v)
{
	if (tag_len != sizeof(uint16_t))
		return ERR_PTR(-EINVAL);
	return uget16(v, tag);
}

static const void *unet_tag_decode_u8(const void *tag, uint8_t tag_len,
		uint8_t *v)
{
	if (tag_len != sizeof(uint8_t))
		return ERR_PTR(-EINVAL);
	return uget8(v, tag);
}

static const void *unet_tag_decode_str(const void *tag, uint8_t tag_len,
		char *str, int str_max)
{
	if (tag_len + 1 > str_max)
		return ERR_PTR(-EINVAL);
	tag = uget(str, tag_len, tag);
	str[tag_len] = '\0';
	return tag;
}

/* -- unused so commented out for now
static const void *unet_tag_decode_data(const void *tag, uint8_t tag_len,
		void *data, size_t *data_size)
{
	if (tag_len > *data_size)
		return ERR_PTR(-EINVAL);
	*data_size = tag_len;
	return uget(data, tag_len, tag);
}
*/

static const void *unet_tlv_decode(const void *tlv, uint16_t tlv_len,
				      struct unet_packet_header *uph)
{
	const void *p = tlv;
	const void *e = tlv + tlv_len;
	const void *pp;
	uint32_t tag;
	uint8_t tag_len;

	/* iterate over the TLV tags */
	while ((e - p) >= UNET_MIN_TAG_LEN) {
		p = ugettag(&tag, &tag_len, p);

		/* print_hex_dump(KERN_INFO, "tag ",
				DUMP_PREFIX_OFFSET, 16, 1, p - 4, tag_len + 4, true); */

		if ((e - p) < tag_len) {
			pr_err("%s: PTA/PTP malformed tag %06x\n",
					__func__, tag);
			return ERR_PTR(-EINVAL);
		}

		switch (tag) {
		case UNET_TAG_I_CAN_BE_ROUTER:
			uph->prop.has_i_can_be_router = 1;
			pp = unet_tag_decode_bool(p, tag_len, &uph->prop.i_can_be_router);
			break;
		case UNET_TAG_N_CHILDREN:
			uph->prop.has_n_children = 1;
			pp = unet_tag_decode_u32(p, tag_len, &uph->prop.n_children);
			break;
		case UNET_TAG_VERSION:
			uph->prop.has_version = 1;
			pp = unet_tag_decode_str(p, tag_len,
					uph->prop.version,
					sizeof(uph->prop.version));
			break;
		case UNET_TAG_DEV_CLASS:
			uph->prop.has_dev_class = 1;
			pp = unet_tag_decode_u32(p, tag_len, &uph->prop.dev_class);
			break;
		case UNET_TAG_N_ROUTERS:
			uph->prop.has_n_routers = 1;
			pp = unet_tag_decode_u32(p, tag_len, &uph->prop.n_routers);
			break;
		case UNET_TAG_RECEIVE_PORT:
			uph->prop.has_receive_port = 1;
			pp = unet_tag_decode_u16(p, tag_len, &uph->prop.receive_port);
			break;
		case UNET_TAG_REQUESTED_NAME:
			uph->prop.has_requested_name = 1;
			pp = unet_tag_decode_str(p, tag_len,
					uph->prop.requested_name,
					sizeof(uph->prop.requested_name));
			break;
		case UNET_TAG_RESPONSE:
			uph->prop.has_response = 1;
			pp = unet_tag_decode_bool(p, tag_len, &uph->prop.response);
			break;
		case UNET_TAG_TOPOLOGY_CHANGE_TYPE:
			uph->prop.has_topo_change_type = 1;
			pp = unet_tag_decode_u8(p, tag_len, &uph->prop.topo_change_type);
			break;
		case UNET_TAG_DIAGNOSTIC_STRING:
			uph->prop.has_diagnostic_string = 1;
			pp = unet_tag_decode_str(p, tag_len,
					uph->prop.diagnostic_string,
					sizeof(uph->prop.diagnostic_string));
			break;
		case UNET_TAG_RECONNECT_NONCE:
			uph->prop.has_reconnect_nonce = 1;
			pp = unet_tag_decode_str(p, tag_len,
					uph->prop.reconnect_nonce,
					sizeof(uph->prop.reconnect_nonce));
			break;

		case UNET_TAG_TRUST_EXTRA:
			uph->prop.has_trust_extra = 1;

			if (tag_len != UNET_TAG_TRUST_EXTRA_SIZE) {
				pp = ERR_PTR(-EINVAL);
				break;
			}
			pp = uget16(&uph->prop.trust_extra.crc, p);
			pp = uget16(&uph->prop.trust_extra.full_size, pp);
			pp = uget8(&uph->prop.trust_extra.n_chunks, pp);
			pp = uget8(&uph->prop.trust_extra.chunk, pp);
			break;

		case UNET_TAG_TRUST_BUNDLE_TYPE:
			uph->prop.has_trust_bundle_type = 1;
			pp = unet_tag_decode_u8(p, tag_len, &uph->prop.trust_bundle_type);
			break;

		default:
			pr_warn("%s: skipping unknown tag with value %06x\n",
					__func__, tag);
			pp = NULL;
			break;
		}
		if (pp && IS_ERR(pp)) {
			pr_err("%s: TAG %c%c%c is invalid\n", __func__,
				(tag >> 16) & 0xff, (tag >> 8) & 0xff,
				tag & 0xff);
			return pp;
		}
		p += tag_len;
	}
	if (e != p)
		pr_warn("%s: undecoded chunk of %lu bytes left\n",
				__func__, e - p);

	/* always return that */
	return tlv + tlv_len;
}

static void unet_packet_dump_x_entry(struct sk_buff *skb, struct unet_x_entry *uxe)
{
	const char *xframe_txt;
	char *str;

	if (UNET_X_IS_XA(uxe->type)) {
		switch (uxe->type) {
		case UNET_X_ADDRESS_SENDER:
			xframe_txt = "XA-ADDR-SENDER";
			break;
		case UNET_X_ADDRESS_NEXT_HOP:
			xframe_txt = "XA-ADDR-NEXT-HOP";
			break;
		default:
			xframe_txt = "XA-UNKNOWN";
			break;
		}

		str = unet_addr_to_str(GFP_KERNEL, &uxe->addr);
		if (str)
			pr_info("%-18s %s\n", xframe_txt, str);
		kfree(str);
	} else if (UNET_X_IS_XN(uxe->type)) {
		switch (uxe->type) {
		case UNET_X_KEEP_ALIVE:
			xframe_txt = "XN-KEEP-ALIVE";
			break;
		default:
			xframe_txt = "XN-UNKNOWN";
			break;
		}
		pr_info("%-18s %*phN\n",
			xframe_txt,
			(int)sizeof(uxe->nonce), uxe->nonce);
	} else if (UNET_X_IS_XH(uxe->type)) {
		switch (uxe->type) {
		case UNET_X_HOP_COUNT:
			xframe_txt = "XH-HOP-COUNT";
			break;
		default:
			xframe_txt = "XH-UNKNOWN";
			break;
		}
		pr_info("%-18s %u\n",
			xframe_txt, uxe->hop_count);
	} else if (UNET_X_IS_XE(uxe->type)) {
		switch (uxe->type) {
		case UNET_X_ENCRYPTED:
			xframe_txt = "XE-ENCRYPTED";
			break;
		default:
			xframe_txt = "XE-UNKNOWN";
			break;
		}
		pr_info("%-18s\n", xframe_txt);
	} else if (UNET_X_IS_XF(uxe->type)) {
		switch (uxe->type) {
		case UNET_X_FRAGMENT:
			xframe_txt = "XF-FRAGMENT";
			break;
		default:
			xframe_txt = "XF-UNKNOWN";
			break;
		}
		pr_info("%-18s frag #%u/%u size=%u crc=0x%04x\n", xframe_txt,
				uxe->frag.frag, uxe->frag.n_frags,
				uxe->frag.full_size, uxe->frag.crc);
	}
}

static const char *message_type_txt(uint32_t message_type)
{
	switch (message_type) {
	case UNET_MSG_APCR:
		return "APCR";
	case UNET_MSG_APCA:
		return "APCA";
	case UNET_MSG_R:
		return "R";
	case UNET_MSG_RR:
		return "RR";
	case UNET_MSG_RA:
		return "RA";
	case UNET_MSG_RRA:
		return "RRA";
	case UNET_MSG_VNR:
		return "VNR";
	case UNET_MSG_VNA:
		return "VNA";
	case UNET_MSG_DA:
		return "DA";
	case UNET_MSG_RC:
		return "RC";
	case UNET_MSG_ACK:
		return "ACK";
	case UNET_MSG_RFDR:
		return "RFDR";
	case UNET_MSG_ERQ:
		return "ERQ";
	case UNET_MSG_ERP:
		return "ERP";
	case UNET_MSG_SNK:
		return "SNK";
	case UNET_MSG_IP:
		return "IP";
	}
	return "UNKNOWN";
}

static const char *dev_class_txt(uint32_t dev_class)
{
	switch (dev_class) {
	case UNET_DEV_CLASS_SMART_PHONE:
		return "SMART_PHONE";
	case UNET_DEV_CLASS_PAD:
		return "PAD";
	case UNET_DEV_CLASS_LINUX_BOX:
		return "LINUX_BOX";
	case UNET_DEV_CLASS_OSX_BOX:
		return "OSX_BOX";
	case UNET_DEV_CLASS_PC_BOX:
		return "PC_BOX";
	case UNET_DEV_CLASS_ROUTER:
		return "ROUTER";
	}
	return "UNKNOWN";
}

static const char *topo_change_type_txt(uint8_t topo_change_type)
{
	switch (topo_change_type) {
	case UNET_TOP_CHANGE_TYPE_NEW_PARENT:
		return "NEW_PARENT";
	case UNET_TOP_CHANGE_TYPE_NEW_CHILD:
		return "NEW_CHILD";
	case UNET_TOP_CHANGE_TYPE_DISCONNECTION:
		return "DISCONNECTION";
	case UNET_TOP_CHANGE_TYPE_NEW_NEXT_HOP:
		return "NEW_NEXT_HOP";
	case UNET_TOP_CHANGE_TYPE_NEW_NAME_ANNOUNCED:
		return "NEW_NAME_ANNOUNCED";
	}
	return "UNKNOWN";
}

static const char *trust_bundle_type_txt(uint8_t topo_change_type)
{
	switch (topo_change_type) {
	case UNET_TB_TYPE_X509_CERT:
		return "X509";
	case UNET_TB_TYPE_X509_CERT_NONCE1:
		return "(X509+NONCE1)";
	case UNET_TB_TYPE_NONCE1_NONCE2:
		return "(NONCE1+NONCE2)";
	case UNET_TB_TYPE_NONCE2:
		return "(NONCE2)";
	}
	return "UNKNOWN";
}

static void unet_packet_dump_header(struct sk_buff *skb, bool decrypted)
{
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	struct unet_packet_header *uph;
	struct unet_addr *orig_ua, *dest_ua;
	char *str_orig, *str_dest, *str_ts;
	const void *tb;
	unsigned int tbsz;
	const void *p = NULL;
	unsigned int size = 0;

	if (ucb->magic != UNET_SKB_CB_MAGIC)
		return;
	uph = ucb->uph;

	if (uph->frame_type &
	    (UNET_ENCRYPTED_INTERNAL | UNET_UNKNOWN_INTERNAL |
	     UNET_FRAGMENT_INTERNAL )) {
		p = unet_skb_data_offset_to_ptr(skb, ucb->data_offset);
		if (!p) {
			pr_err("%s: failed to get pointer to encrypted data\n",
					__func__);
			return;
		}
		size = ucb->size;
	}

	/* encrypted data */
	if ((uph->frame_type & UNET_ENCRYPTED_INTERNAL) && !decrypted) {
		pr_info("encrypted-data %u bytes [%*phN%s] (hash %08x)\n",
				size, size > 8 ? 8 : size, p,
				size > 8 ? " ..." : "",
				jhash(p, size, JHASH_INITVAL));
		return;
	}

	/* unknown frame */
	if (uph->frame_type & UNET_FRAGMENT_INTERNAL) {
		pr_info("fragment-data %u bytes [%*phN%s] (hash %08x)\n",
				size, size > 8 ? 8 : size, p,
				size > 8 ? " ..." : "",
				jhash(p, size, JHASH_INITVAL));
		return;
	}

	/* unknown frame */
	if (uph->frame_type & UNET_UNKNOWN_INTERNAL) {
		pr_info("unknown-data %u bytes [%*phN%s] (hash %08x)\n",
				size, size > 8 ? 8 : size, p,
				size > 8 ? " ..." : "",
				jhash(p, size, JHASH_INITVAL));
		return;
	}

	/* check if valid */
	if (!UNET_IS_VALID(uph->frame_type)) {
		pr_err("%s: Bad frame type %d\n", __func__,
				uph->frame_type);
		return;
	}

	/* we don't handle X frames */
	if (uph->frame_type == UNET_X) {
		pr_err("%s: Can't dump X frame\n", __func__);
		return;
	}

	if (uph->frame_type != UNET_BTA && uph->frame_type != UNET_PTP &&
			uph->frame_type != UNET_PTA) {
		pr_err("%s: can only dump BTA/PTA/PTP frames\n", __func__);
		return;
	}

	if (uph->frame_type == UNET_BTA) {
		orig_ua = &uph->bta.beacon;
		str_orig = unet_addr_to_str(GFP_KERNEL, orig_ua);
		if (str_orig)
			pr_info("BTA orig=%s\n", str_orig);
		kfree(str_orig);
		return;
	}

	/* PTA/PTP */

	if (uph->frame_type == UNET_PTP)
		dest_ua = &uph->pta_ptp.dest;
	else
		dest_ua = NULL;
	orig_ua = &uph->pta_ptp.orig;

	str_orig = unet_addr_to_str(GFP_KERNEL, orig_ua);
	if (dest_ua)
		str_dest = unet_addr_to_str(GFP_KERNEL, dest_ua);
	else
		str_dest = NULL;

	if (!(uph->pta_ptp.flags & UNET_F_NO_TIMESTAMP))
		str_ts = kasprintf(GFP_KERNEL, " mt=%llu ft=%llu",
				uph->pta_ptp.master_timestamp,
				uph->pta_ptp.firing_time);
	else
		str_ts = NULL;

	pr_info("%s %s%s%s%s%s %c%c%s\n",
			uph->frame_type == UNET_PTA ? "PTA" : "PTP",
			message_type_txt(uph->pta_ptp.message_type),
			str_dest ? " dest=" : "",
			str_dest ? str_dest : "",
			str_orig ? " orig=" : "",
			str_orig ? str_orig : "",
			(uph->pta_ptp.flags & UNET_F_TRUST) ? 'T' : '-',
			(uph->pta_ptp.flags & UNET_F_EXTEND) ? 'X' : '-',
			str_ts ? str_ts : "");

	kfree(str_ts);
	kfree(str_dest);
	kfree(str_orig);

	if (uph->prop.has_trust_bundle) {
		tbsz = uph->pta_ptp.tb_size;
		tb = unet_skb_data_offset_to_ptr(skb,
				uph->pta_ptp.tb_skb_offset);
		if (tb)
			pr_info("\t TB %u bytes [%*phN%s] (hash %08x)\n",
				tbsz, tbsz > 8 ? 8 : tbsz,
				tb, tbsz > 8 ? " ..." : "",
				jhash(tb, tbsz, JHASH_INITVAL));
	}

	if (uph->prop.has_i_can_be_router)
		pr_info("\t- %-20s = %s\n", "I-CAN-BE-ROUTER",
				uph->prop.i_can_be_router ? "true" : "false");
	if (uph->prop.has_n_children)
		pr_info("\t- %-20s = %u\n", "N-CHILDREN",
				uph->prop.n_children);
	if (uph->prop.has_version)
		pr_info("\t- %-20s = \"%s\"\n", "VERSION",
				uph->prop.version);
	if (uph->prop.has_dev_class)
		pr_info("\t- %-20s = %u (%s)\n", "DEV-CLASS",
				uph->prop.dev_class,
				dev_class_txt(uph->prop.dev_class));
	if (uph->prop.has_n_routers)
		pr_info("\t- %-20s = %u\n", "N-ROUTERS",
				uph->prop.n_routers);
	if (uph->prop.has_bw_avg_load)
		pr_info("\t- %-20s = %u\n", "BW-AVG-LOAD",
				uph->prop.bw_avg_load);
	if (uph->prop.has_receive_port)
		pr_info("\t- %-20s = %u\n", "RECEIVE-PORT",
				uph->prop.receive_port);
	if (uph->prop.has_requested_name)
		pr_info("\t- %-20s = \"%s\"\n", "REQUESTED-NAME",
				uph->prop.requested_name);
	if (uph->prop.has_response)
		pr_info("\t- %-20s = %s\n", "RESPONSE",
				uph->prop.response ? "true" : "false");
	if (uph->prop.has_topo_change_type)
		pr_info("\t- %-20s = %u (%s)\n", "TOPO-CHANGE-TYPE",
				uph->prop.topo_change_type,
				topo_change_type_txt(uph->prop.topo_change_type));
	if (uph->prop.has_diagnostic_string)
		pr_info("\t- %-20s = \"%s\"\n", "DIAGNOSTIC-STRING",
				uph->prop.diagnostic_string);
	if (uph->prop.has_reconnect_nonce)
		pr_info("\t- %-20s = \"%s\"\n", "RECONNECT-NONCE",
				uph->prop.reconnect_nonce);
	if (uph->prop.has_trust_extra)
		pr_info("\t- %-20s : CRC=%04x FS=%u N=%u #=%u\n",
				"TRUST-EXTRA",
				uph->prop.trust_extra.crc,
				uph->prop.trust_extra.full_size,
				uph->prop.trust_extra.n_chunks,
				uph->prop.trust_extra.chunk);
	if (uph->prop.has_trust_bundle_type)
		pr_info("\t- %-20s = %u (%s)\n", "TRUST-BUNDLE-TYPE",
				uph->prop.trust_bundle_type,
				trust_bundle_type_txt(uph->prop.trust_bundle_type));
}

struct sk_buff *unet_skb_clone(struct sk_buff *skb, bool copy_hdr, gfp_t flags)
{
	struct unet_skb_cb *ucb, *nucb;
	struct unet_x_entry *uxe, *uxen;
	struct sk_buff *nskb;

	ucb = UNET_SKB_CB(skb);

	nskb = skb_clone(skb, flags);
	if (!nskb)
		return NULL;

	/* not a unet skb; just return it */
	if (ucb->magic != UNET_SKB_CB_MAGIC)
		return nskb;

	nucb = UNET_SKB_CB(nskb);
	/* verify that the copied bits are right */
	BUG_ON(nucb->magic != UNET_SKB_CB_MAGIC);

	/* the cb is copied by the pointers are not valid */
	INIT_LIST_HEAD(&nucb->x_list);
	if (!copy_hdr) {
		nucb->uph = NULL;
	} else {
		nucb->uph = kmem_cache_alloc(unet_packet_header_cache, flags);
		if (!nucb->uph)
			goto out_fail;
		/* copy header; pretty inneficient */
		memcpy(nucb->uph, ucb->uph, sizeof(*nucb->uph));

		/* and the x frames */
		list_for_each_entry(uxe, &ucb->x_list, node) {
			uxen = kmem_cache_alloc(unet_x_entry_cache, flags);
			if (!uxen)
				goto out_fail;
			memcpy(uxen, uxe, sizeof(*uxe));
			list_add_tail(&uxen->node, &nucb->x_list);
		}
	}
	return nskb;

out_fail:
	list_for_each_entry_safe_reverse(uxe, uxen, &nucb->x_list, node)
		kmem_cache_free(unet_x_entry_cache, uxe);

	if (nucb->uph)
		kmem_cache_free(unet_packet_header_cache, nucb->uph);

	kfree_skb(nskb);
	return NULL;
}

int unet_packet_setup(void)
{
	unet_packet_header_cache = KMEM_CACHE(unet_packet_header, 0);
	if (!unet_packet_header_cache)
		goto out_no_packet_header;

	unet_x_entry_cache = KMEM_CACHE(unet_x_entry, 0);
	if (!unet_x_entry_cache)
		goto out_no_x_entry;

	return 0;

out_no_x_entry:
	kmem_cache_destroy(unet_packet_header_cache);
out_no_packet_header:
	pr_err("%s: Failed to create mem cache(s)\n", __func__);
	return -ENOMEM;
}

void unet_packet_cleanup(void)
{
	if (unet_x_entry_cache)
		kmem_cache_destroy(unet_x_entry_cache);

	if (unet_packet_header_cache)
		kmem_cache_destroy(unet_packet_header_cache);
}

static int unet_skb_cb_prepare_x(struct sk_buff *skb, gfp_t flags,
		bool *encp, bool *fragp)
{
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	const void *p, *e;
	uint8_t prefix_len, id_len;
	uint8_t frame_type, xframe_type;
	bool fragment = false;
	struct unet_x_entry *uxe = NULL;
	int err;

	p = unet_skb_data_offset_to_ptr(skb, ucb->data_offset);
	if (!p)
		return -EINVAL;
	e = p + ucb->size;

	/* by default not encrypted */
	if (encp)
		*encp = false;

	/* neither is a fragment */
	if (fragp)
		*fragp = false;

	/* consume x-frames that are prepended */
	while (!fragment) {

		/* must have 1 byte at least */
		if ((e - p) < 1) {
			pr_err("%s: Packet too small (frame-type)\n", __func__);
			err = -EINVAL;
			goto err_out;
		}

		/* get the frame type */
		p = uget8(&frame_type, p);
		if (frame_type != UNET_X) {
			p--;	/* back-track */
			break;
		}

		/* x-type */
		if ((e - p) < 1) {
			pr_err("%s: Packet too small (xframe-type)\n",
					__func__);
			err = -EINVAL;
			goto err_out;
		}
		p = uget8(&xframe_type, p);

		/* allocate xentry */
		uxe = kmem_cache_alloc(unet_x_entry_cache, flags);
		if (!uxe) {
			pr_err("%s: Failed to allocate x-entry\n", __func__);
			err = -ENOMEM;
			goto err_out;
		}

		if (UNET_X_IS_XA(xframe_type)) {
			/* prefix-len, id-len */
			if ((e - p) < (1 + 1)) {
				pr_err("%s: Packet too small (XA len 0)\n",
						__func__);
				err = -EINVAL;
				goto err_out;
			}
			p = uget8(&prefix_len, p);
			p = uget8(&id_len, p);
			if ((e - p) < (prefix_len + id_len)) {
				pr_err("%s: Packet too small (XA len 1)\n",
						__func__);
				err = -EINVAL;
				goto err_out;
			}
			/* fill in address */
			err = unet_addr_fill(&uxe->addr,
					NULL, 0, NULL, 0,
					p, prefix_len, p + prefix_len, id_len);
			if (err) {
				pr_err("%s: Address malformed (XA)\n",
						__func__);
				err = -EINVAL;
				goto err_out;
			}
			uxe->type = xframe_type;
			p += prefix_len + id_len;

		} else if (UNET_X_IS_XN(xframe_type)) {
			/* XN has a nonce of 6 */
			if ((e - p) < sizeof(uxe->nonce)) {
				pr_err("%s: Packet too small (XN nonce)\n",
						__func__);
				err = -EINVAL;
				goto err_out;
			}
			uxe->type = xframe_type;
			p = uget(uxe->nonce, sizeof(uxe->nonce), p);
		} else if (UNET_X_IS_XH(xframe_type)) {
			/* XH has a hop_count of 2 bytes */
			if ((e - p) < sizeof(uxe->hop_count)) {
				pr_err("%s: Packet too small (XH hop_count)\n",
						__func__);
				err = -EINVAL;
				goto err_out;
			}
			uxe->type = xframe_type;
			p = uget16(&uxe->hop_count, p);
		} else if (UNET_X_IS_XE(xframe_type)) {
			uxe->type = xframe_type;
			/* no payload for the encrypted tag */
			if (xframe_type == UNET_X_ENCRYPTED && encp)
				*encp = true;
		} else if (UNET_X_IS_XF(xframe_type)) {
			uxe->type = xframe_type;
			if ((e - p) < sizeof(uxe->frag)) {
				pr_err("%s: Packet too small (XH hop_count)\n",
						__func__);
				err = -EINVAL;
				goto err_out;
			}
			if (xframe_type == UNET_X_FRAGMENT) {
				p = uget16(&uxe->frag.crc, p);
				p = uget16(&uxe->frag.full_size, p);
				p = uget8(&uxe->frag.n_frags, p);
				p = uget8(&uxe->frag.frag, p);
				fragment = true;
			}
		} else {
			pr_err("%s: Unknown xframe-type %u\n", __func__,
					xframe_type);
			err = -EINVAL;
			goto err_out;
		}

		/* add it to the control block x list */
		list_add_tail(&uxe->node, &ucb->x_list);
		uxe = NULL;
	}

	if (fragment && fragp)
		*fragp = true;

	/* recompute length of remaining non-x frame */
	ucb->size = e - p;
	ucb->data_offset = unet_skb_ptr_to_data_offset(skb, p);
	/* keep size of the xhdr area around */
	ucb->xhdr_size = ucb->data_offset;
	return 0;

err_out:
	/* something went wrong, cleanup */
	if (uxe)
		kmem_cache_free(unet_x_entry_cache, uxe);
	return err;
}

static int unet_skb_cb_prepare_bta(struct sk_buff *skb, gfp_t flags)
{
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	struct unet_packet_header *uph;
	const void *packet, *p, *e, *pe;
	uint8_t packet_length;
	uint8_t frame_type, prefix_len, id_len;
	int err;

	p = unet_skb_data_offset_to_ptr(skb, ucb->data_offset);
	if (!p)
		return -EINVAL;
	e = p + ucb->size;
	packet = p;

	uph = kmem_cache_alloc(unet_packet_header_cache, flags);
	if (!uph) {
		pr_err("%s: Failed to allocate packet header\n", __func__);
		return -ENOMEM;
	}
	ucb->uph = uph;
	unet_packet_header_clear(uph);

	if ((e - packet) < UNET_BTA_HDR_MIN) {
		pr_err("%s: BTA packet header too small\n", __func__);
		return -EINVAL;
	}

	p = uget8(&frame_type, packet);
	uph->frame_type = frame_type;
	p = uget8(&packet_length, p);

	/* check whether packet length data is correct */
	pe = packet + packet_length;
	if (pe > e) {
		pr_err("%s: BTA bad length exceeds buffer (%lu > %lu)\n",
				__func__, pe - packet, e - packet);
		return -EINVAL;
	}

	/* garbage after packet end */
	if (pe < e) {
		pr_err("%s: BTA contains %lu garbage octets\n",
				__func__, e - pe);
		/* clamp packet end here */
		e = pe;
	}

	p = uget8(&prefix_len, p);
	p = uget8(&id_len, p);
	if ((e - p) < (prefix_len + id_len)) {
		pr_info("%s: BTA packet too short (id)\n", __func__);
		return -EINVAL;
	}

	err = unet_addr_fill(&uph->bta.beacon, NULL, 0, NULL, 0,
				p, prefix_len, p + prefix_len, id_len);
	if (err) {
		pr_err("%s: BTA can't decode beacon addr\n", __func__);
		return -EINVAL;
	}
	/* skip over prefix.id */
	p += prefix_len + id_len;

	/* TODO beacon does not have TLVs (verify) */

	/* update length according to packet length */
	ucb->size = e - p;
	ucb->data_offset = unet_skb_ptr_to_data_offset(skb, p);
	return 0;
}

static int unet_skb_cb_prepare_pta_ptp(struct sk_buff *skb, gfp_t flags)
{
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	struct unet_packet_header *uph;
	const void *packet, *p, *e, *pe;
	const void *orig_p_prefix, *orig_p_id;
	const void *dest_p_prefix, *dest_p_id;
	const void *orig_prefix, *orig_id;
	const void *dest_prefix, *dest_id;
	uint8_t orig_p_prefix_len, orig_p_id_len;
	uint8_t dest_p_prefix_len, dest_p_id_len;
	uint8_t orig_prefix_len, orig_id_len;
	uint8_t dest_prefix_len, dest_id_len;
	uint8_t frame_type;
	uint16_t tlv_len;
	int min_hdr, err;

	p = unet_skb_data_offset_to_ptr(skb, ucb->data_offset);
	if (!p)
		return -EINVAL;
	e = p + ucb->size;
	packet = p;

	uph = kmem_cache_alloc(unet_packet_header_cache, flags);
	if (!uph) {
		pr_err("%s: Failed to allocate packet header\n", __func__);
		return -ENOMEM;
	}
	ucb->uph = uph;
	unet_packet_header_clear(uph);

	/* zero out these */
	orig_p_prefix_len = orig_p_id_len = 0;
	dest_p_prefix_len = dest_p_id_len = 0;
	orig_prefix_len = orig_id_len = 0;
	dest_prefix_len = dest_id_len = 0;

	orig_p_prefix = orig_p_id = NULL;
	dest_p_prefix = dest_p_id = NULL;
	orig_prefix = orig_id = NULL;
	dest_prefix = dest_id = NULL;

	p = uget8(&frame_type, packet);
	uph->frame_type = frame_type;

	if (uph->frame_type == UNET_PTA)
		min_hdr = UNET_PTA_HDR_MIN;
	else if (uph->frame_type == UNET_PTP)
		min_hdr = UNET_PTP_HDR_MIN;
	else {
		pr_err("%s: Neither PTA or PTP packet\n", __func__);
		return -EINVAL;
	}

	/* check that the flags byte is there */
	if ((e - p) < 1) {
		pr_err("%s: PTA/PTP packet header too small (0)\n", __func__);
		return -EINVAL;
	}

	p = uget8(&uph->pta_ptp.flags, p);

	if (uph->frame_type == UNET_PTP &&
			(uph->pta_ptp.flags & UNET_F_DEST_PARENT))
		min_hdr += UNET_HDR_MIN_DEST_PARENT;
	if (uph->pta_ptp.flags & UNET_F_ORIG_PARENT)
		min_hdr += UNET_HDR_MIN_ORIG_PARENT;
	if (uph->pta_ptp.flags & UNET_F_TRUST)
		min_hdr += UNET_HDR_MIN_TRUST_BUNDLE;
	if (uph->pta_ptp.flags & UNET_F_EXTEND)
		min_hdr += UNET_HDR_MIN_TLV;

	if (!(uph->pta_ptp.flags & UNET_F_NO_TIMESTAMP))
		min_hdr += UNET_MASTER_TIMESTAMP_SZ + UNET_FIRING_TIME_SZ;

	/* check against minimum packet header size */
	if ((e - packet) < min_hdr) {
		pr_err("%s: PTA/PTP packet header too small (1)\n", __func__);
		return -EINVAL;
	}

	p = uget32(&uph->pta_ptp.packet_length, p);

	/* check whether packet length data is correct */
	pe = packet + uph->pta_ptp.packet_length;
	if (pe > e) {
		pr_err("%s: PTA/PTP bad length exceeds buffer (%lu > %lu)\n",
				__func__, pe - packet, e - packet);
		return -EINVAL;
	}

	/* garbage after packet end */
	if (pe < e) {
		pr_err("%s: PTA/PTP contains %lu garbage octets\n",
				__func__, e - pe);
		/* clamp packet end here */
		e = pe;
	}

	p = uget32(&uph->pta_ptp.message_type, p);
	if (uph->frame_type == UNET_PTP) {
		if (uph->pta_ptp.flags & UNET_F_DEST_PARENT) {
			p = uget8(&dest_p_prefix_len, p);
			p = uget8(&dest_p_id_len, p);
		}
		p = uget8(&dest_prefix_len, p);
		p = uget8(&dest_id_len, p);

	}
	if (uph->pta_ptp.flags & UNET_F_ORIG_PARENT) {
		p = uget8(&orig_p_prefix_len, p);
		p = uget8(&orig_p_id_len, p);
	}
	p = uget8(&orig_prefix_len, p);
	p = uget8(&orig_id_len, p);

	/* PTP frame */
	if (uph->frame_type == UNET_PTP) {

		/* dest parent exists */
		if ((uph->pta_ptp.flags & UNET_F_DEST_PARENT)) {
			if ((e - p) < (dest_p_prefix_len + dest_p_id_len)) {
				pr_err("%s: PTP dest parent too small\n",
						__func__);
				return -EINVAL;
			}
			dest_p_prefix = p;
			dest_p_id = dest_p_prefix + dest_p_prefix_len;
			p += dest_p_prefix_len + dest_p_id_len;
		}

		/* dest parent */
		if ((e - p) < (dest_prefix_len + dest_id_len)) {
			pr_err("%s: PTP dest parent too small\n",
					__func__);
			return -EINVAL;
		}
		dest_prefix = p;
		dest_id = dest_prefix + dest_prefix_len;
		err = unet_addr_fill(&uph->pta_ptp.dest,
				dest_p_prefix, dest_p_prefix_len,
				dest_p_id, dest_p_id_len,
				dest_prefix, dest_prefix_len,
				dest_id, dest_id_len);

		if (err) {
			pr_err("%s: PTP cant't decode dest addr\n",
					__func__);
			return -EINVAL;
		}
		p += dest_prefix_len + dest_id_len;
	}

	/* orig parent exists */
	if ((uph->pta_ptp.flags & UNET_F_ORIG_PARENT)) {
		if ((e - p) < (orig_p_prefix_len + orig_p_id_len)) {
			pr_err("%s: PTP orig parent too small\n",
					__func__);
			return -EINVAL;
		}
		orig_p_prefix = p;
		orig_p_id = orig_p_prefix + orig_p_prefix_len;
		p += orig_p_prefix_len + orig_p_id_len;
	}

	/* orig parent */
	if ((e - p) < (orig_prefix_len + orig_id_len)) {
		pr_err("%s: PTP orig parent too small\n",
				__func__);
		return -EINVAL;
	}
	orig_prefix = p;
	orig_id = orig_prefix + orig_prefix_len;
	err = unet_addr_fill(&uph->pta_ptp.orig,
			orig_p_prefix, orig_p_prefix_len,
			orig_p_id, orig_p_id_len,
			orig_prefix, orig_prefix_len,
			orig_id, orig_id_len);
	if (err) {
		pr_err("%s: PTP can't decode orig addr\n",
				__func__);
		return -EINVAL;
	}
	p += orig_prefix_len + orig_id_len;

	if (!(uph->pta_ptp.flags & UNET_F_NO_TIMESTAMP)) {
		/* master-time-stamp & firing-time */
		if ((e - p) < (UNET_MASTER_TIMESTAMP_SZ	+ UNET_FIRING_TIME_SZ)) {
			pr_err("%s: PTA/PTP short packet (master-ts/firing-time)\n",
					__func__);
			return -EINVAL;
		}
		p = uget64(&uph->pta_ptp.master_timestamp, p);
		p = uget64(&uph->pta_ptp.firing_time, p);
	}

	if (uph->pta_ptp.flags & UNET_F_TRUST) {
		p = uget16(&uph->pta_ptp.tb_size, p);
		if ((e - p) < uph->pta_ptp.tb_size) {	/* tb-length */
			pr_err("%s: PTA/PTP short packet TRUST BUNDLE (0)\n",
					__func__);
			return -EINVAL;
		}
		SKB_LINEAR_ASSERT(skb);
		/* make an offset relative to the start of the skb */
		uph->pta_ptp.tb_skb_offset = unet_skb_ptr_to_data_offset(skb, p);
		p += uph->pta_ptp.tb_size;
		
		/* makes things easier */
		uph->prop.has_trust_bundle = 1;
	}

	if (uph->pta_ptp.flags & UNET_F_EXTEND) {
		if ((e - p) < 2) {	/* tlv-length */
			pr_err("%s: PTA/PTP short packet TLV (0)\n",
					__func__);
			return -EINVAL;
		}
		p = uget16(&tlv_len, p);

		if ((e - p) < tlv_len) {
			pr_err("%s: PTA/PTP short packet TLV (1) %ld/%d\n",
					__func__, (e - p), tlv_len);

			/* print_hex_dump(KERN_INFO, "tlv ",
				DUMP_PREFIX_OFFSET, 16, 1, p, (e - p), true); */

			return -EINVAL;
		}

		/* print_hex_dump(KERN_INFO, "tlv ",
				DUMP_PREFIX_OFFSET, 16, 1, p, tlv_len, true); */

		p = unet_tlv_decode(p, tlv_len, uph);
		if (IS_ERR(p)) {
			pr_err("%s: PTA/PTP TLV error %ld\n", __func__,
					PTR_ERR(p));

			return PTR_ERR(p);
		}
	}

	/* update length according to packet length */
	ucb->size = e - p;
	ucb->data_offset = unet_skb_ptr_to_data_offset(skb, p);
	return 0;
}

void unet_skb_cb_cleanup(struct sk_buff *skb)
{
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	struct unet_x_entry *uxe, *uxen;

	/* verify that it's ours */
	if (ucb->magic != UNET_SKB_CB_MAGIC)
		return;

	/* free any x-frames */
	list_for_each_entry_safe_reverse(uxe, uxen, &ucb->x_list, node)
		kmem_cache_free(unet_x_entry_cache, uxe);

	/* free packet header */
	if (ucb->uph)
		kmem_cache_free(unet_packet_header_cache, ucb->uph);

	/* we're done with the packet */
	ucb->magic = 0;
}

int unet_skb_cb_prepare(struct sk_buff *skb, gfp_t flags,
		bool was_decrypted)
{
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	uint8_t frame_type;
	const void *p;
	int err;
	struct unet_packet_header *uph;
	bool encrypted, was_fragment;

	/* sanity check that the control buffer fits */
	BUG_ON(sizeof(*ucb) > sizeof(skb->cb));

	/* if magic is set, we've prepared this buffer before */
	if (ucb->magic == UNET_SKB_CB_MAGIC)
		return 0;

	ucb->magic = UNET_SKB_CB_MAGIC;
	INIT_LIST_HEAD(&ucb->x_list);
	ucb->uph = NULL;

	/* we use the ucb data member as a decode pointer */
	ucb->data_offset = 0;
	ucb->size = skb->len;

	err = unet_skb_cb_prepare_x(skb, flags, &encrypted, &was_fragment);
	if (err) {
		pr_err("%s: unet_skb_cb_prepare_x error (%d)\n",
				__func__, err);
		goto err_out;
	}

	/* if encrypted (or a fragment) we're done */
	if ((encrypted && !was_decrypted) || was_fragment) {
		uph = kmem_cache_alloc(unet_packet_header_cache, flags);
		if (!uph) {
			pr_err("%s: Failed to allocate packet header\n", __func__);
			err = -ENOMEM;
			goto err_out;
		}
		ucb->uph = uph;
		unet_packet_header_clear(uph);
		/* note that we process encryption before fragmentation */
		uph->frame_type = 0;
		if (encrypted && !was_decrypted)
			uph->frame_type |= UNET_ENCRYPTED_INTERNAL;
		if (was_fragment)
			uph->frame_type |= UNET_FRAGMENT_INTERNAL;
		return 0;
	}

	p = unet_skb_data_offset_to_ptr(skb, ucb->data_offset);
	if (!p) {
		err = -EINVAL;
		goto err_out;
	}

	/* we should have at least one byte */
	if (ucb->size < 1) {
		pr_err("%s: frame too small\n", __func__);
		err = -EINVAL;
		goto err_out;
	}

	(void)uget8(&frame_type, p);

	switch (frame_type) {
	case UNET_BTA:
		err = unet_skb_cb_prepare_bta(skb, flags);
		break;
	case UNET_PTA:
	case UNET_PTP:
		err = unet_skb_cb_prepare_pta_ptp(skb, flags);
		break;
	/*
	 * We don't handle this one yet
	 *
	 * case UNET_SEQ:
	 * 	break;
	 */
	default:
		pr_err("%s: Unknown frame-type %d\n", __func__,
				frame_type);

		uph = kmem_cache_alloc(unet_packet_header_cache, flags);
		if (!uph) {
			pr_err("%s: Failed to allocate packet header\n", __func__);
			err = -ENOMEM;
			goto err_out;
		}
		ucb->uph = uph;
		unet_packet_header_clear(uph);
		uph->frame_type = UNET_UNKNOWN_INTERNAL | frame_type;
		return 0;
	}

	if (err)
		goto err_out;

	return 0;

err_out:
	/* cleanup the control block */
	unet_skb_cb_cleanup(skb);
	return err;
}

static void unet_skb_dump_common(struct unet_bearer *b, struct sk_buff *skb,
		bool decrypted)
{
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	struct unet_x_entry *uxe;
	const void *p;
	unsigned int size;

	/* dump x-entries */
	list_for_each_entry(uxe, &ucb->x_list, node)
		unet_packet_dump_x_entry(skb, uxe);
	if (ucb->uph) {
		unet_packet_dump_header(skb, decrypted);
		if ((ucb->uph->frame_type & UNET_UNKNOWN_INTERNAL) ||
		    ((ucb->uph->frame_type & UNET_ENCRYPTED_INTERNAL) &&
		     	!decrypted) ||
		    (ucb->uph->frame_type & UNET_FRAGMENT_INTERNAL))
			return;
	}

	size = ucb->size;
	if (size > 0) {
		p = unet_skb_data_offset_to_ptr(skb, ucb->data_offset);
		if (!p)
			return;

		pr_info("data %u bytes [%*phN%s] (hash %08x)\n",
				size, size > 8 ? 8 : size, p,
				size > 8 ? " ..." : "",
				jhash(p, size, JHASH_INITVAL));
	}
}

void unet_skb_dump_rx(struct unet_bearer *b, struct sk_buff *skb,
		bool decrypted)
{
	static const char *banner = "uNet Rx";
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	struct net_device *dev = unet_dev_bearer_get(b);
	const struct unet_media *media = b ? b->media : NULL;

	/* must be a prepared packet */
	if (ucb->magic != UNET_SKB_CB_MAGIC)
		return;

	if (!media || media->type_id != UNET_MEDIA_TYPE_ETH)
		pr_info("%s-%s:\n", banner, dev ? netdev_name(dev) : "");
	else
		pr_info("%s-%s: src %pM dst %pM\n",
				banner, netdev_name(dev),
				media->skb_source_addr(b, skb),
				media->skb_dest_addr(b, skb));

	unet_skb_dump_common(b, skb, decrypted);
}

void unet_skb_dump_tx(struct unet_bearer *b, struct sk_buff *skb,
		const void *dest, bool decrypted)
{
	static const char *banner = "uNet Tx";
	struct unet_skb_cb *ucb = UNET_SKB_CB(skb);
	const struct unet_media *media = b ? b->media : NULL;
	struct net_device *dev = unet_dev_bearer_get(b);

	if (ucb->magic != UNET_SKB_CB_MAGIC)
		return;

	if (!media || media->type_id != UNET_MEDIA_TYPE_ETH)
		pr_info("%s-%s\n", banner, dev ? netdev_name(dev) : "");
	else
		pr_info("%s-%s: src %pM dst %pM\n",
				banner, netdev_name(dev),
				dev->dev_addr, dest);

	unet_skb_dump_common(b, skb, decrypted);
}

struct unet_addr *unet_packet_get_orig_addr(struct unet_packet_header *uph)
{
	struct unet_addr *ua;

	switch (uph->frame_type) {
	case UNET_BTA:
		ua = &uph->bta.beacon;
		break;
	case UNET_PTA:
	case UNET_PTP:
		ua = &uph->pta_ptp.orig;
		break;
	default:
		return NULL;
	}

	/* validity check */
	if (!ua || !ua->id_len)
		return NULL;

	return ua;
}

struct unet_addr *unet_packet_get_dest_addr(struct unet_packet_header *uph)
{
	struct unet_addr *ua;

	switch (uph->frame_type) {
	case UNET_PTP:
		ua = &uph->pta_ptp.dest;
		break;
	default:
		return NULL;
	}

	/* validity check */
	if (!ua || !ua->id_len)
		return NULL;

	return ua;
}
