/*
 * net/unet/crypto.h: uNet crypto and trust management
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

#ifndef _UNET_CRYPTO_H
#define _UNET_CRYPTO_H

#include <linux/unet.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/net.h>

#include <linux/key.h>
#include <crypto/public_key.h>
#include <keys/system_keyring.h>
#include <crypto/aead.h>

/* maximum 8 chain of trust certs allowed */
#define UNET_TRUST_CHAIN_MAX	8

struct unet_crypto_params {
	const char *alg_txt;
	unsigned int key_len;
	unsigned int auth_len;
};

enum unet_encrypted_type {
	unet_encrypted_type_none,
	unet_encrypted_type_nonce1,
	unet_encrypted_type_nonce1_nonce2,
	unet_encrypted_type_nonce2,
};

struct unet_trust_blob {
	/* maximum is 16 fragments (bits) */
	uint16_t frag_map;
	uint8_t n_chunks;
	void *blob;
	unsigned int blob_size;
	uint16_t blob_crc;
	bool valid;
	uint8_t type;	/* trust bundle type */
	/* decoded after reception and bundle type */
	void *tb_cert;
	unsigned int tb_cert_size;
	void *tb_enc;
	unsigned int tb_enc_size;
	enum unet_encrypted_type tb_enc_type;
	bool tb_decrypt_pending;
};

#define UNET_MAX_KEY_SIZE			32	/* maximum is 32 bytes of key */
#define UNET_MAX_IV_SIZE			32	/* maximum is 32 bytes of IV */
#define UNET_MAX_KEYCHAIN_SIZE			64	/* maximum is 64 bytes (512bits) */
#define UNET_MAX_TB_DECRYPT_SIZE		(UNET_TB_NONCE_SIZE * 2)

struct unet_entity;
struct unet_conn_entry;
struct unet_net;
struct unet_packet_header;
struct unet_entity_cfg;

enum unet_key_type {
	unet_key_type_parent_key,
	unet_key_type_child_key,
	unet_key_type_parent_iv,
	unet_key_type_child_iv,
};

bool unet_entity_has_cert(struct unet_entity *ue);
bool unet_entity_is_trusted(struct unet_entity *ue);
bool unet_entity_cert_rx_in_progress(struct unet_entity *ue);
bool unet_entity_cert_rx_valid(struct unet_entity *ue);

bool unet_conn_entry_is_secure(struct unet_conn_entry *uce);
bool unet_conn_entry_is_trusted(struct unet_conn_entry *uce);
bool unet_conn_entry_is_crypto_ready(struct unet_conn_entry *uce);
int unet_conn_entry_compute_keychain(struct unet_conn_entry *uce);
int unet_conn_entry_get_key(struct unet_conn_entry *uce,
			    enum unet_key_type ktype,
			    void *buf, int size);
int unet_conn_entry_setup_crypto(struct unet_conn_entry *uce);
void unet_conn_entry_cleanup_crypto(struct unet_conn_entry *uce);
int unet_conn_entry_encrypted_size(struct unet_conn_entry *uce,
				   unsigned int size);

int unet_conn_entry_generate_nonce1(struct unet_conn_entry *uce);
int unet_conn_entry_update_nonce1(struct unet_conn_entry *uce);
int unet_conn_entry_generate_nonce2(struct unet_conn_entry *uce);
int unet_conn_entry_update_nonce2(struct unet_conn_entry *uce);
bool unet_conn_entry_nonce1_match(struct unet_conn_entry *uce);
bool unet_conn_entry_nonce2_match(struct unet_conn_entry *uce);

const struct unet_crypto_params *
unet_crypto_get_algo_params(struct unet_net *un, uint8_t algo);

int unet_entity_update_trust_bundle(struct unet_entity *ue,
		struct sk_buff *skb, struct unet_packet_header *uph);
int unet_entity_update_remote_cert(struct unet_entity *ue,
		uint8_t type, const void *blob, unsigned int blob_size);
int unet_entity_decrypt_remote(struct unet_entity *ue,
		struct unet_entity *ue_sender,
		enum unet_encrypted_type type,
		const void *blob, unsigned int size);
bool unet_remote_entity_is_decrypt_pending(struct unet_entity *ue);
int unet_entity_decrypt_pending(struct unet_entity *ue,
				struct unet_entity *ue_sender);

int unet_crypto_setup(struct net *net);
void unet_crypto_cleanup(struct net *net);

int unet_local_entity_crypto_setup(struct unet_entity *ue,
				   const struct unet_entity_cfg *uec);
void unet_remote_entity_crypto_setup(struct unet_entity *ue);
void unet_entity_crypto_cleanup(struct unet_entity *ue);

struct sk_buff *unet_conn_entry_encrypt_skb(struct unet_conn_entry *uce,
					    struct sk_buff *skb,
					    unsigned int x_hdrsz);
struct sk_buff *unet_conn_entry_decrypt_skb(struct unet_conn_entry *uce,
					    struct sk_buff *skb,
					    unsigned int x_hdrsz);

#endif
