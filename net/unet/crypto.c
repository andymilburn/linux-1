/*
 * net/unet/core.c: uNet crypto and trust management
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
#include "packet.h"
#include "utils.h"
#include "crypto.h"

#include <linux/module.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/crc16.h>
#include <linux/key.h>
#include <linux/rtnetlink.h>
#include <crypto/public_key.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <crypto/rng.h>
#include <keys/system_keyring.h>
#include <keys/asymmetric-type.h>

bool unet_entity_has_cert(struct unet_entity *ue)
{
	return ue->cert_blob && ue->cert_blob_size;
}

bool unet_entity_is_trusted(struct unet_entity *ue)
{
	return unet_entity_has_cert(ue) && ue->keys_trusted;
}

bool unet_entity_cert_rx_in_progress(struct unet_entity *ue)
{
	struct unet_trust_blob *utb;

	if (!ue || ue->type != unet_entity_type_remote)
		return false;

	utb = &ue->utb;
	return utb->blob && !utb->valid;
}

bool unet_entity_cert_rx_valid(struct unet_entity *ue)
{
	struct unet_trust_blob *utb;

	if (!ue || ue->type != unet_entity_type_remote)
		return false;

	utb = &ue->utb;
	return utb->blob && utb->valid;
}

bool unet_conn_entry_is_secure(struct unet_conn_entry *uce)
{
	struct unet_entity *ue;

	if (!uce)
		return false;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue || !uce->ue)
		return false;

	return ue->keys_verified && unet_entity_has_cert(uce->ue);
}

bool unet_conn_entry_is_trusted(struct unet_conn_entry *uce)
{
	struct unet_entity *ue;

	if (!uce)
		return false;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue || !uce->ue)
		return false;

	return ue->keys_verified && ue->keys_trusted &&
	       uce->ue->keys_trusted;
}

bool unet_conn_entry_is_crypto_ready(struct unet_conn_entry *uce)
{
	struct unet_entity *ue;

	if (!uce)
		return false;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue || !uce->ue)
		return false;

	return uce->crypto_ready;
}

int unet_conn_entry_compute_keychain(struct unet_conn_entry *uce)
{
	struct unet_entity *ue;
	struct crypto_ahash *tfm = NULL;
	struct ahash_request *req = NULL;
	struct unet_addr *ua_parent, *ua_child;
	enum unet_conn_type type;
	struct scatterlist sg[4];
	int err, psize, parent_size, child_size;

	if (!uce)
		return -EINVAL;

	type = unet_conn_state_to_type(uce->state);
	if (type != unet_conn_type_parent &&
	    type != unet_conn_type_child)
		return -EINVAL;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue || !uce->ue)
		return -EINVAL;

	/* we must have that */
	if (!uce->has_nonce1 || !uce->has_nonce2)
		return -ENOENT;

	if (type == unet_conn_type_parent) {
		ua_child = unet_entity_addr(ue);
		ua_parent = unet_entity_addr(uce->ue);
	} else {
		ua_parent = unet_entity_addr(ue);
		ua_child = unet_entity_addr(uce->ue);
	}

	tfm = crypto_alloc_ahash("sha512", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		unet_entity_err(ue, "failed to load sha512 hash (%d)\n",
				err);
		goto out_err;
	}

	if (crypto_ahash_digestsize(tfm) > sizeof(uce->keychain)) {
		unet_entity_err(ue, "digest size too large\n");
		err = -EINVAL;
		goto out_err;
	}

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		unet_entity_err(ue, "failed to get hash req\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* no gaps between address buffer and length fields */
	parent_size = offsetof(struct unet_addr, addr_buffer) +
			unet_addr_buffer_len(ua_parent);
	child_size = offsetof(struct unet_addr, addr_buffer) +
			unet_addr_buffer_len(ua_child);

	sg_init_table(sg, 4);
	sg_set_buf(&sg[0], uce->nonce1, UNET_TB_NONCE_SIZE);
	sg_set_buf(&sg[1], uce->nonce2, UNET_TB_NONCE_SIZE);
	sg_set_buf(&sg[2], ua_parent, parent_size);
	sg_set_buf(&sg[3], ua_child, child_size);

	psize = UNET_TB_NONCE_SIZE * 2 + parent_size + child_size;

	ahash_request_set_crypt(req, sg, uce->keychain, psize);
	err = crypto_ahash_digest(req);
	if (err != 0) {
		unet_entity_err(ue, "failed to perform hash digest\n");
		err = -ENOMEM;
		goto out_err;
	}
	uce->has_keychain = 1;

	uce->keychain_size = crypto_ahash_digestsize(tfm);

out_err:
	if (req)
		ahash_request_free(req);
	if (tfm)
		crypto_free_ahash(tfm);
	return err;
}

int unet_conn_entry_get_key(struct unet_conn_entry *uce,
			    enum unet_key_type ktype,
			    void *buf, int size)
{
	struct unet_entity *ue;
	struct crypto_rng *rng = NULL;
	uint8_t discard[32];
	int err, pos, start, maxsz, chunk;
	unsigned int key_len, iv_len;
	const char *alg;

	if (!uce || !buf || !size)
		return -EINVAL;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue || !uce->ue)
		return -EINVAL;

	key_len = uce->ucp->key_len;
	iv_len = uce->iv_len;

	/* each key is in a specific point in the random stream */
	switch (ktype) {
	case unet_key_type_parent_key:
		start = 0;
		maxsz = key_len;
		break;
	case unet_key_type_child_key:
		start = key_len;
		maxsz = key_len;
		break;
	case unet_key_type_parent_iv:
		start = key_len * 2;
		maxsz = iv_len;
		break;
	case unet_key_type_child_iv:
		start = key_len * 2 + iv_len;
		maxsz = iv_len;
		break;
	default:
		return -EINVAL;
	}

	if (!uce->has_keychain) {
		err = unet_conn_entry_compute_keychain(uce);
		if (err)
			return err;
	}

	alg = "ansi_cprng";
	rng = crypto_alloc_rng(alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(rng)) {
		unet_entity_err(ue, "could not allocate RNG handle for %s\n",
				alg);
		err = PTR_ERR(rng);
		goto out_err;
	}

	err = crypto_rng_reset(rng, uce->keychain, uce->keychain_size);
	if (err) {
		unet_entity_err(ue, "failed to reset rng (%d)\n", err);
		goto out_err;
	}

	/* discard until we get to the start */
	pos = 0;
	while (pos < start) {
		chunk = start - pos;
		if (chunk > sizeof(discard))
			chunk = sizeof(discard);
		err = crypto_rng_get_bytes(rng, discard, chunk);
		if (err != 0) {
			unet_entity_err(ue, "error rng discard (%d)\n", err);
			goto out_err;
		}
		pos += chunk;
	}

	if (size > maxsz)
		err = crypto_rng_get_bytes(rng, buf, maxsz);
	else
		err = crypto_rng_get_bytes(rng, buf, size);

	/* fill in over the limit with zeroes */
	if (err == 0 && size > maxsz)
		memset(buf + maxsz, 0, size - maxsz);

out_err:
	crypto_free_rng(rng);

	return err;
}

int unet_conn_entry_setup_crypto(struct unet_conn_entry *uce)
{
	struct unet_entity *ue;
	struct unet_net *un;
	const struct unet_crypto_params *ucp;
	uint8_t crypto_algo;
	struct crypto_aead *tx_aead = NULL, *rx_aead = NULL;
	struct aead_request *tx_req = NULL, *rx_req = NULL;
	unsigned int tx_ivlen, rx_ivlen, tx_blksz, rx_blksz;
	enum unet_conn_type type;
	uint8_t *tx_key, *rx_key;
	uint8_t *tx_iv, *rx_iv;
	int err = 0;

	if (!uce)
		return -EINVAL;

	/* verify connection type */
	type = unet_conn_state_to_type(uce->state);
	if (type != unet_conn_type_parent &&
	    type != unet_conn_type_child)
		return -EINVAL;

	ue = unet_conn_entry_to_entity(uce);
	if (!ue || !uce->ue)
		return -EINVAL;

	if (!unet_conn_entry_is_secure(uce))
		return -EINVAL;

	/* spit out a warning if we're re-initializing */
	if (uce->crypto_ready)
		unet_entity_warn(ue, "re-initializing crypto for %s\n",
				unet_entity_name(uce->ue));

	/* hardcoded for now */
	crypto_algo = UNET_CRYPTO_ALG_GCM_AES;

	if (crypto_algo >= UNET_CRYPTO_ALG_COUNT)
		return -EINVAL;

	un = unet_entity_unet(ue);

	/* get the algo parameters */
	ucp = unet_crypto_get_algo_params(un, crypto_algo);
	if (!ucp)
		return -EINVAL;

	/* verify key length is not too large */
	if (ucp->key_len > UNET_MAX_KEY_SIZE)
		return -EINVAL;

	/* both nonces must exist */
	if (!uce->has_nonce1 || !uce->has_nonce2)
		return -EINVAL;

	err = unet_conn_entry_compute_keychain(uce);
	if (err)
		return err;

	unet_crypto_info(uce, "initializing crypto algo #%d (%s)\n",
			crypto_algo, ucp->alg_txt);

	tx_aead = crypto_alloc_aead(ucp->alg_txt, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tx_aead)) {
		unet_entity_err(ue, "Failed to allocate tx_aead\n");
		err = PTR_ERR(tx_aead);
		goto out_err;
	}

	rx_aead = crypto_alloc_aead(ucp->alg_txt, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(rx_aead)) {
		unet_entity_err(ue, "Failed to allocate rx_aead\n");
		err = PTR_ERR(rx_aead);
		goto out_err;
	}

	tx_req = aead_request_alloc(tx_aead, GFP_KERNEL);
	if (!tx_req) {
		unet_entity_err(ue, "Failed to allocate tx_req\n");
		err = -ENOMEM;
		goto out_err;
	}

	rx_req = aead_request_alloc(rx_aead, GFP_KERNEL);
	if (!rx_req) {
		unet_entity_err(ue, "Failed to allocate rx_req\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* read IV sizes */
	tx_ivlen = crypto_aead_ivsize(tx_aead);
	rx_ivlen = crypto_aead_ivsize(rx_aead);
	tx_blksz = crypto_aead_blocksize(tx_aead);
	rx_blksz = crypto_aead_blocksize(rx_aead);

	if (tx_ivlen > UNET_MAX_IV_SIZE ||
	    rx_ivlen > UNET_MAX_IV_SIZE) {
		unet_entity_err(ue, "IV sizes too large\n");
		err = -EINVAL;
		goto out_err;
	}

	if (tx_ivlen != rx_ivlen) {
		unet_entity_err(ue, "IV len mismatch (bad algos?)\n");
		err = -EINVAL;
		goto out_err;
	}

	if (tx_blksz != rx_blksz || !is_power_of_2(tx_blksz)) {
		unet_entity_err(ue, "block size mismatch (bad algos?)\n");
		err = -EINVAL;
		goto out_err;
	}

	/* the key is the sha of our address and the nonce */

	/* clear all flags */
	crypto_aead_clear_flags(tx_aead, ~0);
	crypto_aead_clear_flags(rx_aead, ~0);

	if (type == unet_conn_type_parent) {
		/* we transmit to parent we receive from him */
		tx_key = uce->pk;
		rx_key = uce->ck;
		tx_iv  = uce->piv;
		rx_iv  = uce->civ;
	} else {
		/* we transmit to child we receive from it */
		tx_key = uce->ck;
		rx_key = uce->pk;
		tx_iv  = uce->civ;
		rx_iv  = uce->piv;
	}

	/* commit */
	if (uce->tx_aead)
		crypto_free_aead(uce->tx_aead);
	if (uce->rx_aead)
		crypto_free_aead(uce->rx_aead);
	uce->rx_aead = rx_aead;
	uce->tx_aead = tx_aead;
	uce->rx_req = rx_req;
	uce->tx_req = tx_req;
	uce->iv_len = tx_ivlen;	/* same as rx_ivlen */
	uce->blk_size = tx_blksz;	/* same as rx_blksz */
	uce->ucp = ucp;

	/* get keys */
	err = unet_conn_entry_get_key(uce, unet_key_type_parent_key,
					uce->pk, ucp->key_len);
	if (err != 0) {
		unet_entity_err(ue, "failed to get parent_key (%d)\n", err);
		goto out_err;
	}
	err = unet_conn_entry_get_key(uce, unet_key_type_child_key,
					uce->ck, ucp->key_len);
	if (err != 0) {
		unet_entity_err(ue, "failed to get child_key (%d)\n", err);
		goto out_err;
	}
	err = unet_conn_entry_get_key(uce, unet_key_type_parent_iv,
					uce->piv, rx_ivlen);
	if (err != 0) {
		unet_entity_err(ue, "failed to get parent_iv (%d)\n", err);
		goto out_err;
	}
	err = unet_conn_entry_get_key(uce, unet_key_type_child_iv,
					uce->civ, rx_ivlen);
	if (err != 0) {
		unet_entity_err(ue, "failed to get child_iv (%d)\n", err);
		goto out_err;
	}

	unet_crypto_info(uce, "pk  %2d bytes %*phN\n",
			ucp->key_len, ucp->key_len, uce->pk);

	unet_crypto_info(uce, "ck  %2d bytes %*phN\n",
			ucp->key_len, ucp->key_len, uce->ck);

	unet_crypto_info(uce, "piv %2d bytes %*phN\n",
			tx_ivlen, tx_ivlen, uce->piv);

	unet_crypto_info(uce, "civ %2d bytes %*phN\n",
			rx_ivlen, rx_ivlen, uce->civ);

	err = crypto_aead_setkey(tx_aead, tx_key, ucp->key_len);
	if (err != 0) {
		unet_entity_err(ue, "setkey('tx') failed (%d) %08x\n",
			       err, crypto_aead_get_flags(tx_aead));
		goto out_err;
	}

	err = crypto_aead_setkey(rx_aead, rx_key, ucp->key_len);
	if (err != 0) {
		unet_entity_err(ue, "setkey('rx') failed (%d) %08x\n",
			       err, crypto_aead_get_flags(rx_aead));
		goto out_err;
	}

	err = crypto_aead_setauthsize(tx_aead, ucp->auth_len);
	if (err != 0) {
		unet_entity_err(ue, "setauthsize('tx') failed (%d)\n",
			       err);
		goto out_err;
	}

	err = crypto_aead_setauthsize(rx_aead, ucp->auth_len);
	if (err != 0) {
		unet_entity_err(ue, "setauthsize('rx') failed (%d)\n",
			       err);
		goto out_err;
	}

	uce->crypto_ready = 1;

	return 0;

out_err:
	if (tx_aead)
		crypto_free_aead(tx_aead);
	if (rx_aead)
		crypto_free_aead(rx_aead);

	return err;
}

void unet_conn_entry_cleanup_crypto(struct unet_conn_entry *uce)
{
	if (!uce)
		return;

	if (uce->tx_req) {
		aead_request_free(uce->tx_req);
		uce->tx_req = NULL;
	}
	if (uce->rx_req) {
		aead_request_free(uce->rx_req);
		uce->rx_req = NULL;
	}
	if (uce->tx_aead) {
		crypto_free_aead(uce->tx_aead);
		uce->tx_aead = NULL;
	}
	if (uce->rx_aead) {
		crypto_free_aead(uce->rx_aead);
		uce->rx_aead = NULL;
	}
}

int unet_conn_entry_encrypted_size(struct unet_conn_entry *uce,
				   unsigned int size)
{
	if (!uce)
		return -EINVAL;

	size = ALIGN(size, uce->blk_size);

	/* if the block size is not 1, then we append a strip byte */
	return size + uce->ucp->auth_len + (uce->blk_size > 1 ? 1 : 0);
}

int unet_conn_entry_generate_nonce1(struct unet_conn_entry *uce)
{
	if (!uce || !unet_conn_entry_is_secure(uce))
		return -EINVAL;

	/* initialize our nonce */
	get_random_bytes(uce->nonce1, UNET_TB_NONCE_SIZE);
	uce->has_nonce1 = 1;
	unet_crypto_info(uce, "NONCE1 %*phN\n",
			UNET_TB_NONCE_SIZE, uce->nonce1);
	return 0;
}

int unet_conn_entry_update_nonce1(struct unet_conn_entry *uce)
{
	if (!uce || !unet_conn_entry_is_secure(uce))
		return -EINVAL;

	/* NOP if we don't have it yet */
	if (!uce->has_dec_nonce1)
		return 0;

	memcpy(uce->nonce1, uce->dec_nonce1, UNET_TB_NONCE_SIZE);
	uce->has_nonce1 = 1;
	unet_crypto_info(uce, "NONCE1 %*phN\n", UNET_TB_NONCE_SIZE,
			 uce->nonce1);
	return 0;
}

int unet_conn_entry_generate_nonce2(struct unet_conn_entry *uce)
{
	if (!uce || !unet_conn_entry_is_secure(uce))
		return -EINVAL;

	/* initialize our nonce */
	get_random_bytes(uce->nonce2, UNET_TB_NONCE_SIZE);
	uce->has_nonce2 = 1;
	unet_crypto_info(uce, "NONCE2 %*phN\n",
			UNET_TB_NONCE_SIZE, uce->nonce2);
	return 0;
}

int unet_conn_entry_update_nonce2(struct unet_conn_entry *uce)
{
	if (!uce || !unet_conn_entry_is_secure(uce))
		return -EINVAL;

	/* NOP if we don't have it yet */
	if (!uce->has_dec_nonce2)
		return 0;

	memcpy(uce->nonce2, uce->dec_nonce2, UNET_TB_NONCE_SIZE);
	uce->has_nonce2 = 1;
	unet_crypto_info(uce, "NONCE2 %*phN\n", UNET_TB_NONCE_SIZE,
			 uce->nonce2);
	return 0;
}

bool unet_conn_entry_nonce1_match(struct unet_conn_entry *uce)
{
	return uce && unet_conn_entry_is_secure(uce) &&
	       uce->has_nonce1 && uce->has_dec_nonce1 &&
	       !memcmp(uce->nonce1, uce->dec_nonce1, UNET_TB_NONCE_SIZE);
}

bool unet_conn_entry_nonce2_match(struct unet_conn_entry *uce)
{
	return uce && unet_conn_entry_is_secure(uce) &&
	       uce->has_nonce2 && uce->has_dec_nonce2 &&
	       !memcmp(uce->nonce2, uce->dec_nonce2, UNET_TB_NONCE_SIZE);
}

/* this is complicated enough to require it's own method */
int unet_entity_update_trust_bundle(struct unet_entity *ue,
		struct sk_buff *skb, struct unet_packet_header *uph)
{
	struct unet_trust_blob *utb;
	struct unet_entity_prop *prop;
	int changed = 0;
	unsigned int tbsz, fulltbsz, chunk, n_chunks, chunksz;
	const void *tb;
	uint16_t crc;
	uint8_t tb_type;

	if (!ue || !skb || !uph || ue->type != unet_entity_type_remote)
		return -EINVAL;

	utb = &ue->utb;

	prop = &ue->ae.prop;

	/* no trust bundle? */
	if (!uph->prop.has_trust_bundle)
		goto no_trust;

	if (!uph->prop.has_trust_bundle_type)
		tb_type = UNET_TB_TYPE_X509_CERT;
	else
		tb_type = uph->prop.trust_bundle_type;

	/* we don't want to generate keys everytime */
	/* so we have to verify if certs change */

	tbsz = uph->pta_ptp.tb_size;
	/* get pointer to the data */
	tb = unet_skb_data_offset_to_ptr(skb, uph->pta_ptp.tb_skb_offset);
	if (!tb) {
		unet_entity_warn(ue, "bad trust bundle offset\n");
		goto no_trust;
	}

	/* full trust bundle is differs if trust extra info exists */
	fulltbsz = uph->prop.has_trust_extra ?
			uph->prop.trust_extra.full_size : tbsz;

	if (fulltbsz < tbsz || fulltbsz > SZ_16K) {
		unet_entity_warn(ue, "illegal trust bundle sizes\n");
		goto no_trust;
	}

	if (!uph->prop.has_trust_extra) {
		/* mark that the whole cert has been received */
		n_chunks = 1;
		chunk = 0;
	} else {
		/* we received one (random) chunk */
		n_chunks = uph->prop.trust_extra.n_chunks;
		chunk = uph->prop.trust_extra.chunk;
	}
	/* verify chunk */
	if (n_chunks >= 16 || chunk >= n_chunks) {
		unet_entity_warn(ue, "illegal trust bundle chunks\n");
		goto no_trust;
	}

	/* verify that we received the correct amount */
	if (chunk < (n_chunks - 1))
		chunksz = fulltbsz / n_chunks;
	else
		chunksz = fulltbsz - (fulltbsz / n_chunks) *
					(n_chunks - 1);

	/* have we received the exact amount? */
	if (chunksz != tbsz) {
		unet_entity_warn(ue, "illegal trust bundle chunk size\n");
		goto no_trust;
	}

	/* do we have a WIP cert already? clear it if it differs */
	if (utb->blob &&
		(utb->blob_size != fulltbsz ||
		 utb->n_chunks != n_chunks ||
		 utb->type != tb_type ||
		 (uph->prop.has_trust_extra &&
			utb->blob_crc != uph->prop.trust_extra.crc))) {

		unet_fsm_info(ue, "wip cert data changed; new\n");
		kfree(utb->blob);
		memset(utb, 0, sizeof(*utb));
	}

	/* OK, we have a new cert incoming */
	if (!utb->blob) {
		/* allocate space enough to hold the full cert */
		utb->blob = kmalloc(fulltbsz, GFP_KERNEL);
		if (!utb->blob) {
			unet_entity_warn(ue, "failed to allocate cert wip blob\n");
			goto no_trust;
		}
		utb->blob_size = fulltbsz;
		utb->n_chunks = n_chunks;
		utb->frag_map = 0;
		if (uph->prop.has_trust_extra)
			utb->blob_crc = uph->prop.trust_extra.crc;
		else
			utb->blob_crc = 0;
		utb->type = tb_type;
	}

	/* do we have this chunk? ignore then */
	if ((utb->frag_map & BIT(chunk)) &&
	    !memcmp(utb->blob + chunk * (fulltbsz / n_chunks), tb, chunksz))
		return 0;

	unet_fsm_info(ue, "received chunk #%d\n", chunk);
	utb->frag_map |= BIT(chunk);

	/* copy the blob where it should go */
	memcpy(utb->blob + chunk * (fulltbsz / n_chunks), tb, tbsz);

	/* not all have been received? */
	if (utb->frag_map != (BIT(n_chunks) - 1))
		return 0;

	/* one last check to handle fragmentation errors */
	crc = crc16(0, utb->blob, fulltbsz);
	if (uph->prop.has_trust_extra) {
		if (crc != utb->blob_crc) {
			unet_entity_err(ue, "trust CRC error 0x%04x != 0x%04x\n",
					crc, utb->blob_crc);
			goto bail_out;
		}
	} else
		utb->blob_crc = crc;

	utb->valid = true;
	unet_fsm_info(ue, "Got the complete trust bundle\n");

	switch (utb->type) {
	case UNET_TB_TYPE_X509_CERT:
		utb->tb_cert = utb->blob;
		utb->tb_cert_size = utb->blob_size;
		utb->tb_enc = NULL;
		utb->tb_enc_size = 0;
		utb->tb_decrypt_pending = false;
		changed |= UNET_PROP_CHANGE_CERT;
		break;

	case UNET_TB_TYPE_X509_CERT_NONCE1:
		utb->tb_cert = utb->blob;
		if (!ue->cert_key) {
			/* first time we see this CERT */
			unet_entity_err(ue, "New key! - pretend it cover whole TB\n");
			utb->tb_cert_size = utb->blob_size;
			utb->tb_enc = NULL;
			utb->tb_enc_size = 0;
			utb->tb_enc_type = unet_encrypted_type_nonce1;
			/* both have changed */
			changed |= UNET_PROP_CHANGE_CERT | UNET_PROP_CHANGE_ENCRYPTED;
			utb->tb_decrypt_pending = true;
			break;
		}

		if (utb->blob_size < ue->cert_key_enc_size) {
			unet_entity_err(ue, "blob size (%u) > cert-key enc size (%u)\n",
					utb->blob_size, ue->cert_key_enc_size);
			goto no_trust;
		}
		/* the size of the other cert is the blob - our enc size */
		utb->tb_cert_size = utb->blob_size - ue->cert_key_enc_size;
		changed |= UNET_PROP_CHANGE_CERT;

		utb->tb_enc = utb->blob + utb->tb_cert_size;
		utb->tb_enc_size = ue->cert_key_enc_size;
		utb->tb_enc_type = unet_encrypted_type_nonce1;
		changed |= UNET_PROP_CHANGE_ENCRYPTED;	/* encrypted stuff */
		utb->tb_decrypt_pending = true;
		break;

	case UNET_TB_TYPE_NONCE1_NONCE2:
		utb->tb_cert = NULL;
		utb->tb_cert_size = 0;
		utb->tb_enc = utb->blob;
		utb->tb_enc_size = ue->cert_key_enc_size;
		utb->tb_enc_type = unet_encrypted_type_nonce1_nonce2;
		changed |= UNET_PROP_CHANGE_ENCRYPTED;	/* encrypted stuff */
		utb->tb_decrypt_pending = true;
		break;

	case UNET_TB_TYPE_NONCE2:
		utb->tb_cert = NULL;
		utb->tb_cert_size = 0;
		utb->tb_enc = utb->blob;
		utb->tb_enc_size = ue->cert_key_enc_size;
		utb->tb_enc_type = unet_encrypted_type_nonce2;
		changed |= UNET_PROP_CHANGE_ENCRYPTED;	/* encrypted stuff */
		utb->tb_decrypt_pending = true;
		break;
	}

	/* if cert hasn't changed don't report it */
	if (utb->tb_cert && ue->cert_blob &&
	    utb->tb_cert_size == ue->cert_blob_size &&
	    !memcmp(utb->tb_cert, ue->cert_blob, utb->tb_cert_size))
		changed &= ~UNET_PROP_CHANGE_CERT;

	return changed;

no_trust:
	/*
	 * we don't have a trust bundle but we did have one earlier?
	 * the caller must determine if something funny is going on
	 */
	if (unet_entity_has_cert(ue))
		changed = UNET_PROP_CHANGE_CERT;

	/* fall-through */
bail_out:
	if (utb->blob) {
		/* put away our keys (NULL is okay) */
		kfree(utb->blob);
		memset(utb, 0, sizeof(*utb));
	}

	return changed;
}

int unet_entity_update_remote_cert(struct unet_entity *ue,
		uint8_t type, const void *blob, unsigned int blob_size)
{
	struct unet_net *un = unet_entity_unet(ue);
	struct kernel_pkey_params pkp;
	struct kernel_pkey_query pki;
	struct key *k0, *k1;
	const union key_payload *payload;
	const struct public_key_signature *sig;
	key_ref_t key;
	char *desc;
	void *new_blob;
	int i, err = 0;
	bool trusted = false;

	if (!ue || ue->type != unet_entity_type_remote)
		return -EINVAL;

	if (!blob)
		goto update_cert;

	/* do not instantiate if there's a key and the blobs match */
	if (ue->cert_blob && ue->cert_blob_size == blob_size &&
		!memcmp(ue->cert_blob, blob, blob_size)) {
		return 0;
	}

	new_blob = kmemdup(blob, blob_size, GFP_KERNEL);
	if (!new_blob) {
		unet_entity_err(ue, "Failed to allocate cert blob\n");
		return -ENOMEM;
	}

	/* OK, we're good to go now */
	key = key_create_or_update(make_key_ref(un->remote_keys, 1),
					"asymmetric", NULL, blob, blob_size,
					((KEY_POS_ALL & ~KEY_POS_SETATTR) |
					KEY_USR_VIEW | KEY_USR_READ),
					KEY_ALLOC_NOT_IN_QUOTA |
					KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		unet_entity_err(ue, "Failed to load X.509 certificate (%d)\n", err);
		goto out_fail;
	}
	desc = key_ref_to_ptr(key)->description;

	/* verify that it does support encryption */
	memset(&pkp, 0, sizeof(pkp));
	memset(&pki, 0, sizeof(pki));
	pkp.key = key_ref_to_ptr(key);
	pkp.encoding = "raw";
	err = query_asymmetric_key(&pkp, &pki);
	if (err) {
		unet_entity_err(ue, "Can't query certificate '%s' (%d)\n",
				desc, err);
		goto out_fail;
	}
	/* we have to support those to work */
	if (!(pki.supported_ops & (KEYCTL_SUPPORTS_ENCRYPT |
					KEYCTL_SUPPORTS_VERIFY))) {
		unet_entity_err(ue, "certificate '%s' does not support encrypt/verify\n",
				desc);
		err = -EINVAL;
		goto out_fail;
	}

	unet_fsm_info(ue, "Loaded X.509 cert '%s'\n",
			key_ref_to_ptr(key)->description);

	/* verify that it's signed properly (if there's a trust chain) */
	if (un->trust_chain[0]) {
		/* k1 is the entity key */
		k1 = key_ref_to_ptr(key);
		payload = &k1->payload;
		sig = payload->data[asym_auth];
		if (!sig->auth_ids[0] && !sig->auth_ids[1]) {
			unet_entity_warn(ue, "cert '%s' has no auth_id\n",
					k1->description);
			err = -EINVAL;
			goto out_fail;
		}

		err = 0;
		for (i = 0; i < ARRAY_SIZE(un->trust_chain); i++) {
			if (!un->trust_chain[i])
				continue;
			k0 = key_ref_to_ptr(un->trust_chain[i]);

			/* try until root */
			err = verify_signature(k0, sig);
			if (err == 0)
				break;
		}
		if (err) {
			unet_entity_err(ue, "cert '%s' fails verification (%d)\n",
					k1->description, err);
			goto out_fail;
		}

		unet_fsm_info(ue, "trusted cert '%s'\n",
				key_ref_to_ptr(key)->description);
		trusted = true;
	}

update_cert:
	if (ue->cert_blob) {
		if (ue->cert_key) {
			unet_fsm_info(ue, "Removing cert '%s'\n",
				key_ref_to_ptr(ue->cert_key)->description);
			key_ref_put(ue->cert_key);
			ue->cert_key = NULL;
		}
		kfree(ue->cert_blob);
	}

	/* if the updated cert is from an APCA an encrypted NONCE1 follows */
	if (type == UNET_TB_TYPE_X509_CERT_NONCE1) {
		blob_size -= pki.max_enc_size;
		/* point the encrypted area to the new blob */
		ue->utb.tb_enc = new_blob + blob_size;
		ue->utb.tb_enc_size = pki.max_enc_size;
		ue->utb.tb_enc_type = unet_encrypted_type_nonce1;
		ue->utb.tb_decrypt_pending = true;
		/* rely on the decryption taking place after cert install */
	}

	ue->cert_key = key;
	ue->cert_key_enc_size = pki.max_enc_size;
	ue->cert_blob = new_blob;
	ue->cert_blob_size = blob_size;
	ue->cert_blob_crc = crc16(0, ue->cert_blob, ue->cert_blob_size);
	ue->keys_trusted = trusted;

	return 0;

out_fail:
	kfree(new_blob);
	return err;
}

int unet_entity_decrypt_remote(struct unet_entity *ue,
		struct unet_entity *ue_sender,
		enum unet_encrypted_type type,
		const void *blob, unsigned int size)
{
	struct unet_conn_entry *uce;
	struct kernel_pkey_params pkp;
	unsigned int decsz = 0;
	int err;

	if (!ue || !ue_sender || !blob)
		return -EINVAL;

	if (ue->type != unet_entity_type_local || !ue->priv_key)
		return -EINVAL;

	uce = unet_conn_entry_lookup(ue, ue_sender);
	if (!uce) {
		/* this may happen during establishment */
		unet_fsm_info(ue, "can't find connection entry for %s\n",
				unet_entity_name(ue_sender));
		err = -ENOENT;
		goto out;
	}

	err = -EINVAL;
	if (!unet_conn_entry_is_secure(uce)) {
		unet_crypto_err(uce, "Not secure connection with %s\n",
				unet_entity_name(ue_sender));
		goto out;
	}

	switch (type) {
	case unet_encrypted_type_nonce1:
		decsz = UNET_TB_NONCE_SIZE;
		break;
	case unet_encrypted_type_nonce1_nonce2:
		decsz = UNET_TB_NONCE_SIZE * 2;
		break;
	case unet_encrypted_type_nonce2:
		decsz = UNET_TB_NONCE_SIZE;
		break;
	default:
		goto out;
	}

	if (decsz > sizeof(uce->decbuf)) {
		unet_crypto_err(uce, "not enough decrypt space\n");
		goto out;
	}

	/* OK, let's decrypt */
	memset(&pkp, 0, sizeof(pkp));
	pkp.key = key_ref_to_ptr(ue->priv_key);
	pkp.encoding = "pkcs1";
	pkp.hash_algo = "sha256";
	pkp.in_len = size;
	pkp.out_len = decsz;
	err = decrypt_blob(&pkp, blob, uce->decbuf);
	if (err < 0) {
		unet_entity_err(ue, "Failed to decrypt\n");
		goto out;
	}

	/* OK set up pointers */
	switch (type) {
	case unet_encrypted_type_nonce1:
		memcpy(uce->dec_nonce1, uce->decbuf, UNET_TB_NONCE_SIZE);
		uce->has_dec_nonce1 = 1;
		unet_crypto_info(uce, "decrypted nonce1\n");
		err = 0;
		break;
	case unet_encrypted_type_nonce1_nonce2:
		memcpy(uce->dec_nonce1, uce->decbuf, UNET_TB_NONCE_SIZE);
		memcpy(uce->dec_nonce2, uce->decbuf + UNET_TB_NONCE_SIZE,
					UNET_TB_NONCE_SIZE);
		uce->has_dec_nonce1 = 1;
		uce->has_dec_nonce2 = 1;
		unet_crypto_info(uce, "decrypted nonce1,2\n");
		err = 0;
		break;
	case unet_encrypted_type_nonce2:
		memcpy(uce->dec_nonce2, uce->decbuf, UNET_TB_NONCE_SIZE);
		uce->has_dec_nonce2 = 1;
		unet_crypto_info(uce, "decrypted nonce2\n");
		err = 0;
		break;
	default:
		err = -EINVAL;
		break;
	}

out:
	if (uce)
		unet_conn_entry_put(uce);

	return err;
}

bool unet_remote_entity_is_decrypt_pending(struct unet_entity *ue)
{
	if (!ue || ue->type != unet_entity_type_remote)
		return false;
	return ue->utb.tb_decrypt_pending;
}

int unet_entity_decrypt_pending(struct unet_entity *ue,
				struct unet_entity *ue_sender)
{
	int err;

	if (!ue || ue->type != unet_entity_type_local ||
	    !ue_sender || ue_sender->type != unet_entity_type_remote)
		return -EINVAL;

	err = 0;
	/* nothing to decrypt? it's OK */
	if (unet_remote_entity_is_decrypt_pending(ue_sender)) {
		/* we're good, now decrypt */
		err = unet_entity_decrypt_remote(ue, ue_sender,
			ue_sender->utb.tb_enc_type,
			ue_sender->utb.tb_enc,
			ue_sender->utb.tb_enc_size);
		ue_sender->utb.tb_decrypt_pending = false;

	}

	if (err)
		unet_entity_err(ue, "%s: failed to decrypt on %s\n", __func__,
				unet_entity_name(ue_sender));

	return err;
}

static const struct unet_crypto_params
unet_crypto_params_arr[UNET_CRYPTO_ALG_COUNT] = {
	[UNET_CRYPTO_ALG_GCM_AES] = {
		.alg_txt	= "gcm(aes)",
		.key_len	= 16,
		.auth_len	= 16,
	},
	[UNET_CRYPTO_ALG_HMAC_SHA1_ECB_AES] = {
		.alg_txt	= "authenc(hmac(sha256),ecb(aes))",
		.key_len	= 16,
		.auth_len	= 20,
	},
	[UNET_CRYPTO_ALG_HMAC_SHA1_CTR_AES] = {
		.alg_txt	= "authenc(hmac(sha256),ecb(aes))",
		.key_len	= 16,
		.auth_len	= 20,
	},
};

const struct unet_crypto_params *
unet_crypto_get_algo_params(struct unet_net *un, uint8_t algo)
{
	const struct unet_crypto_params *ucp;
	unsigned int i;

	if (!un)
		return NULL;

	ucp = unet_crypto_params_arr;
	for (i = 0; i < un->alg_count; i++) {
		if (un->alg[i] == algo)
			break;
	}
	if (i >= un->alg_count)
		return NULL;

	if (i >= ARRAY_SIZE(unet_crypto_params_arr))
		return NULL;

	return &unet_crypto_params_arr[i];
}

int unet_crypto_setup(struct net *net)
{
	struct unet_net *un = unet_net(net);
	const char *alg;
	int i, err;

	if (un->index == 0) {
		un->config_keys_name = kstrdup(".unet_config_keys",
				GFP_KERNEL);
		un->remote_keys_name = kstrdup(".unet_remote_keys",
				GFP_KERNEL);
	} else {
		un->config_keys_name = kasprintf(GFP_KERNEL,
				".unet_config_keys%d", un->index);
		un->remote_keys_name = kasprintf(GFP_KERNEL,
				".unet_remote_keys%d", un->index);
	}

	if (!un->config_keys_name || !un->remote_keys_name) {
		err = -ENOMEM;
		goto out_no_name;
	}

	/* config-keys all open for now; deal with this later */
	un->config_keys = keyring_alloc(un->config_keys_name,
			      KUIDT_INIT(0), KGIDT_INIT(0), current_cred(),
			      KEY_POS_ALL | KEY_USR_ALL,
			      KEY_ALLOC_NOT_IN_QUOTA,
			      NULL, NULL);
	if (IS_ERR(un->config_keys)) {
		err = PTR_ERR(un->config_keys);
		un->config_keys = NULL;
		goto out_no_config_keyring;
	}

	/* remote-keys all open for now; deal with this later */
	un->remote_keys = keyring_alloc(un->remote_keys_name,
			      KUIDT_INIT(0), KGIDT_INIT(0), current_cred(),
			      KEY_POS_ALL | KEY_USR_ALL,
			      KEY_ALLOC_NOT_IN_QUOTA,
			      NULL, NULL);
	if (IS_ERR(un->remote_keys)) {
		err = PTR_ERR(un->remote_keys);
		un->remote_keys = NULL;
		goto out_no_remote_keyring;
	}

	un->alg_count = 0;
	for (i = 0; i < ARRAY_SIZE(unet_crypto_params_arr); i++) {
		alg = unet_crypto_params_arr[i].alg_txt;
		if (!alg)
			continue;

		if (!crypto_has_alg(alg, 0, CRYPTO_ALG_ASYNC)) {
			pr_warn("no availability of crypto alg #%d (%s)\n",
					i, alg);
			continue;
		}
		pr_warn("crypto alg #%d (%s) is available\n",
				i, alg);
		un->alg[un->alg_count] = i;
		un->alg_count++;
	}

	alg = "ansi_cprng";
	if (!crypto_has_alg(alg, 0, CRYPTO_ALG_ASYNC)) {
		pr_warn("no availability of crypto alg (%s)\n",
				 alg);
	}

	return 0;

out_no_remote_keyring:
	key_put(un->config_keys);
out_no_config_keyring:
	kfree(un->remote_keys_name);
	un->remote_keys_name = NULL;
	kfree(un->config_keys_name);
	un->config_keys_name = NULL;
out_no_name:
	return err;
}

void unet_crypto_cleanup(struct net *net)
{
	struct unet_net *un = unet_net(net);

	key_put(un->remote_keys);
	key_put(un->config_keys);
	kfree(un->remote_keys_name);
	kfree(un->config_keys_name);
}

int unet_local_entity_crypto_setup(struct unet_entity *ue,
				   const struct unet_entity_cfg *uec)
{
	struct kernel_pkey_params pkp;
	struct kernel_pkey_query pki;
	int err;

	if (!ue || !uec || ue->type != unet_entity_type_local)
		return -EINVAL;

	/* get cert key and ref it (NULL is okay) */
	ue->cert_key = uec->cert_key;
	(void)key_get(key_ref_to_ptr(ue->cert_key));

	/* get private key and ref it (NULL is okay) */
	ue->priv_key = uec->priv_key;
	(void)key_get(key_ref_to_ptr(ue->priv_key));

	if (ue->cert_key) {
		memset(&pkp, 0, sizeof(pkp));
		memset(&pki, 0, sizeof(pki));
		pkp.key = key_ref_to_ptr(ue->cert_key);
		pkp.encoding = "raw";
		err = query_asymmetric_key(&pkp, &pki);
		if (err)
			return err;
		ue->cert_key_enc_size = pki.max_enc_size;
	}

	if (ue->priv_key) {
		memset(&pkp, 0, sizeof(pkp));
		memset(&pki, 0, sizeof(pki));
		pkp.key = key_ref_to_ptr(ue->priv_key);
		pkp.encoding = "raw";
		err = query_asymmetric_key(&pkp, &pki);
		if (err)
			return err;
		ue->priv_key_dec_size = pki.max_dec_size;
	}

	/* we need the cert-blob */
	ue->cert_blob = uec->cert_blob;
	if (ue->cert_blob) {
		ue->cert_blob_size = uec->cert_blob_size;
		ue->cert_blob_crc = crc16(0, ue->cert_blob,
					  ue->cert_blob_size);
	}

	ue->keys_trusted = uec->keys_trusted;
	ue->keys_verified = uec->keys_verified;

	return 0;
}

void unet_remote_entity_crypto_setup(struct unet_entity *ue)
{
	if (!ue ||ue->type != unet_entity_type_remote)
		return;

	memset(&ue->utb, 0, sizeof(ue->utb));
}

void unet_entity_crypto_cleanup(struct unet_entity *ue)
{
	if (!ue)
		return;

	key_ref_put(ue->cert_key);
	kfree(ue->cert_blob);
	if (ue->type == unet_entity_type_local)
		key_ref_put(ue->priv_key);
	else
		kfree(ue->utb.blob);
}

struct sk_buff *unet_conn_entry_encrypt_skb(struct unet_conn_entry *uce,
					    struct sk_buff *skb,
					    unsigned int x_hdrsz)
{
	enum unet_conn_type type;
	struct sk_buff *nskb;
	struct scatterlist sg;
	unsigned int headroom, origsize, isize, overhead;
	unsigned int enc_len;
	uint8_t *tx_iv, *p;
	int err;

	if (!uce || !skb || !unet_conn_entry_is_crypto_ready(uce))
		return ERR_PTR(-EINVAL);

	/* verify connection type */
	type = unet_conn_state_to_type(uce->state);
	if (type != unet_conn_type_parent &&
	    type != unet_conn_type_child)
		return ERR_PTR(-EINVAL);

	err = unet_conn_entry_encrypted_size(uce, skb->len - x_hdrsz);
	if (err < 0)
		return ERR_PTR(err);
	enc_len = err;

	headroom = x_hdrsz + enc_len - skb->len;
	if (skb_tailroom(skb) < headroom) {
		nskb = skb_copy_expand(skb, skb_headroom(skb), headroom,
				       GFP_KERNEL);
		if (likely(nskb)) {
			consume_skb(skb);
			skb = nskb;
		} else {
			unet_conn_err(uce, "encrypt: failed to grow skb\n");
			kfree_skb(skb);
			return ERR_PTR(-ENOMEM);
		}
	} else {
		skb = skb_unshare(skb, GFP_KERNEL);
		if (!skb) {
			unet_conn_err(uce, "encrypt: failed to unshare skb\n");
			return ERR_PTR(-ENOMEM);
		}
	}

	if (type == unet_conn_type_parent)
		tx_iv  = uce->piv;
	else
		tx_iv  = uce->civ;

	origsize = skb->len - x_hdrsz;
	if (uce->blk_size > 1)
		isize = ALIGN(origsize, uce->blk_size);
	else
		isize = origsize;

	overhead = isize + uce->ucp->auth_len - origsize;

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, skb->data, x_hdrsz + isize + uce->ucp->auth_len);

	aead_request_set_crypt(uce->tx_req, &sg, &sg, isize, tx_iv);
	aead_request_set_ad(uce->tx_req, x_hdrsz);

	unet_crypto_info(uce, "%-8s  %2d bytes %*phN\n", "xhdr",
			x_hdrsz, x_hdrsz, skb->data);
	unet_crypto_info(uce, "%-8s  %2d bytes %*phN\n", "input",
			isize, isize, skb->data + x_hdrsz);

	err = crypto_aead_encrypt(uce->tx_req);
	if (err != 0) {
		unet_crypto_err(uce, "failed to encrypt skb\n");
		consume_skb(skb);
		return ERR_PTR(err);
	}

	unet_crypto_info(uce, "%-8s  %2d bytes %*phN\n", "auth",
			uce->ucp->auth_len, uce->ucp->auth_len,
			skb->data + x_hdrsz + isize);

	unet_crypto_info(uce, "overhead=%u bytes\n", overhead);

	/* advance over the overhead */
	skb_put(skb, overhead);

	/* if block size > 1 put a discard size */
	if (uce->blk_size > 1) {
		p = skb_put(skb, 1);
		*p = isize - origsize;
	}

	return skb;
}

struct sk_buff *unet_conn_entry_decrypt_skb(struct unet_conn_entry *uce,
					    struct sk_buff *skb,
					    unsigned int x_hdrsz)
{
	enum unet_conn_type type;
	struct scatterlist sg;
	uint8_t *rx_iv;
	uint8_t discsz;
	unsigned int isize;
	int err;

	if (!uce || !skb || !unet_conn_entry_is_crypto_ready(uce))
		return ERR_PTR(-EINVAL);

	/* verify connection type */
	type = unet_conn_state_to_type(uce->state);
	if (type != unet_conn_type_parent &&
	    type != unet_conn_type_child)
		return ERR_PTR(-EINVAL);

	/* we don't need to allocate anything, the encrypted skb is larger */
	skb = skb_unshare(skb, GFP_KERNEL);
	if (!skb) {
		unet_crypto_err(uce, "failed to unshare skb\n");
		return ERR_PTR(-ENOMEM);
	}
	/* make sure it's linear */
	err = skb_linearize(skb);
	if (err) {
		kfree_skb(skb);
		return ERR_PTR(err);
	}

	if (type == unet_conn_type_parent)
		rx_iv  = uce->civ;
	else
		rx_iv  = uce->piv;

	/* if we're using block size > 1 decrease by 1 */
	discsz = 0;
	if (uce->blk_size > 1) {
		/* get the discard count at the end */
		skb_copy_from_linear_data_offset(skb, skb->len - 1,
				&discsz, 1);
		skb_trim(skb, skb->len - 1);
	}

	isize = skb->len - x_hdrsz;

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, skb->data, x_hdrsz + isize);

	aead_request_set_crypt(uce->rx_req, &sg, &sg, isize, rx_iv);
	aead_request_set_ad(uce->rx_req, x_hdrsz);

	unet_crypto_info(uce, "%-8s  %2d bytes %*phN\n", "xhdr",
			x_hdrsz, x_hdrsz, skb->data);
	unet_crypto_info(uce, "%-8s  %2d bytes %*phN\n", "input",
			isize, isize, skb->data + x_hdrsz);

	err = crypto_aead_decrypt(uce->rx_req);
	if (err != 0) {
		unet_crypto_err(uce, "failed to decrypt skb\n");
		consume_skb(skb);
		return ERR_PTR(err);
	}

	/* now set buffer size to the correct one */
	skb_trim(skb, x_hdrsz + isize - uce->ucp->auth_len - discsz);

	return skb;
}
