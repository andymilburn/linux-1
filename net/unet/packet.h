/*
 * net/unet/packet.h: uNet packet definitions
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

#ifndef _UNET_PACKET_H
#define _UNET_PACKET_H

#include <linux/unet.h>

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <asm/unaligned.h>

struct unet_entity;
struct unet_conn_entry;
struct sk_buff;

#define PTx_FIXED_HDR	(	\
	1 + /* frame-type    */	\
	1 + /* flags         */	\
	4 + /* packet-length */ \
	4 ) /* message-type  */

/*
 * Anatomy of a uNet Packet (deduced from FrameIntoBytes)
 *
 * [XFrame|[XFrame|..]][BTA|PTA|PTP]
 *
 * FrameType::= 1 octet
 *  BTAPacketFrameType	0
 *  PTAPacketFrameType	1
 *  PTPPacketFrameType	2
 *  XFrameType          3
 *  SegPacketFrameType  4
 *
 * XFrameType::= 1 octet
 * 	XFTypeExtraAddressSender	200	(XAFrame)
 * 	XFTypeExtraAddressNextHop	201	(XAFrame)
 *	XFTypeKeepAlive			202	(XNFrame)
 *	XFTypeHopCount			203	(XHFrame)
 *
 * BTAFrame:
 *     +----------------------+
 *     | FrameType (0)        | 1 byte
 *     +----------------------+
 *     | packet-length        | 1 byte
 *     +----------------------+
 *     | beacon-ID-prefix-len | 1 byte
 *     +----------------------+
 *     | beacon-ID-len        | 1 byte
 *     +----------------------+
 *     | beacon-<prefix><id>  | beacon-ID-prefix-len + beacon-ID-len bytes
 *     +----------------------+
 *
 * PTAFrame:
 *     +----------------------+
 *     | FrameType (1)        | 1 byte
 *     +----------------------+
 *     | - D - - T - - E      | 1 byte (ORIG_PARENT TRUST PROPERTY)
 *     +----------------------+
 *     | packet-length        | 4 bytes
 *     +----------------------+
 *     | message-type         | 4 bytes
 *     +----------------------+
 *
 *     Optional (if it has ORIG_PARENT)
 *     +---------------------------+
 *     | orig-parent-ID-prefix-len | 1 byte (strlen(prefix))
 *     +---------------------------+
 *     | orig-parent-ID-len        | 1 byte (strlen(prefixedID) - (strlen(prefix))
 *     +---------------------------+
 *
 *     +---------------------------+
 *     | orig-ID-prefix-len        | 1 byte (strlen(prefix))
 *     +---------------------------+
 *     | orig-ID-len               | 1 byte (strlen(prefixedID) - (strlen(prefix))
 *     +---------------------------+
 *
 *     Optional (if it has ORIG_PARENT)
 *     +---------------------------+
 *     | orig-parent-<prefix><id>  | ID-prefix-len + ID-len bytes
 *     +---------------------------+
 *
 *     +---------------------------+
 *     | orig-<prefix><id>         | ID-prefix-len + ID-len bytes
 *     +---------------------------+
 *
 *     +----------------------+
 *     | masterTimeStamp      | 8 bytes
 *     +----------------------+
 *     | firingTime           | 8 bytes
 *     +----------------------+
 *
 *     Optional (if it has TRUST_BUNDLE)
 *     +----------------------+
 *     | trust-bundle-len     | 4 bytes (size of trust bundle)
 *     +----------------------+
 *     | trust-bundle-data    | trust-bundle-len
 *     +----------------------+
 *
 *     Optional (if EXTEND)
 *
 *     +----------------------+
 *     | TLV-properties-len   | 2 bytes
 *     +----------------------+
 *     | TLV properties       | (see properties)
 *     +----------------------+
 *
 *     Optional (if data)
 *     +----------------------+
 *     | data                 | size in bytes is deduced by using packet_len
 *     +----------------------+
 *
 * PTPFrame:
 *     +----------------------+
 *     | FrameType (1)        | 1 byte
 *     +----------------------+
 *     | - D P - T - - E      | 1 byte (DEST_PARENT ORIG_PARENT TRUST EXTEND)
 *     +----------------------+
 *     | packet-length        | 4 bytes
 *     +----------------------+
 *     | message-type         | 4 bytes
 *     +----------------------+
 *
 *     Optional (if it has DEST_PARENT)
 *     +---------------------------+
 *     | dest-parent-ID-prefix-len | 1 byte (strlen(prefix))
 *     +---------------------------+
 *     | dest-parent-ID-len        | 1 byte (strlen(prefixedID) - (strlen(prefix))
 *     +---------------------------+
 *
 *     +---------------------------+
 *     | dest-ID-prefix-len        | 1 byte (strlen(prefix))
 *     +---------------------------+
 *     | dest-ID-len               | 1 byte (strlen(prefixedID) - (strlen(prefix))
 *     +---------------------------+
 *
 *     Optional (if it has ORIG_PARENT)
 *     +---------------------------+
 *     | orig-parent-ID-prefix-len | 1 byte (strlen(prefix))
 *     +---------------------------+
 *     | orig-parent-ID-len        | 1 byte (strlen(prefixedID) - (strlen(prefix))
 *     +---------------------------+
 *
 *     +---------------------------+
 *     | orig-ID-prefix-len        | 1 byte (strlen(prefix))
 *     +---------------------------+
 *     | orig-ID-len               | 1 byte (strlen(prefixedID) - (strlen(prefix))
 *     +---------------------------+
 *
 *     Optional (if it has DEST_PARENT)
 *     +---------------------------+
 *     | dest-parent-<prefix><id>  | ID-prefix-len + ID-len bytes
 *     +---------------------------+
 *
 *     +---------------------------+
 *     | dest-<prefix><id>         | ID-prefix-len + ID-len bytes
 *     +---------------------------+
 *
 *     Optional (if it has ORIG_PARENT)
 *     +---------------------------+
 *     | orig-parent-<prefix><id>  | ID-prefix-len + ID-len bytes
 *     +---------------------------+
 *
 *     +---------------------------+
 *     | orig-<prefix><id>         | ID-prefix-len + ID-len bytes
 *     +---------------------------+
 *
 *     +----------------------+
 *     | masterTimeStamp      | 8 bytes
 *     +----------------------+
 *     | firingTime           | 8 bytes
 *     +----------------------+
 *
 *     Optional (if it has TRUST_BUNDLE)
 *     +----------------------+
 *     | trust-bundle-len     | 4 bytes (size of trust bundle)
 *     +----------------------+
 *     | trust-bundle-data    | trust-bundle-len
 *     +----------------------+
 *
 *     Optional (if EXTEND)
 *
 *     +----------------------+
 *     | TLV-properties-len   | 2 bytes
 *     +----------------------+
 *     | TLV properties       | (see properties)
 *     +----------------------+
 *
 *     Optional (if data)
 *     +----------------------+
 *     | data                 | size in bytes is deduced by using packet_len
 *     +----------------------+
 *
 * XAFrame:
 *     +------------------+
 *     | FrameType (3)    | 1 byte
 *     +------------------+
 *     | XFType (200|201) | 1 byte
 *     +------------------+
 *     | ID-prefix-len    | 1 byte (strlen(prefix))
 *     +------------------+
 *     | ID-len           | 1 byte (strlen(prefixedID) - (strlen(prefix))
 *     +------------------+
 *     | <prefix><id>     | ID-prefix-len + ID-len bytes
 *     +------------------+
 *
 * XNFrame:
 *     +------------------+
 *     | FrameType (3)    | 1 byte
 *     +------------------+
 *     | XFType (202)     | 1 byte
 *     +------------------+
 *     |     nonce        | 6 bytes
 *     +------------------+
 *
 * XHFrame:
 *     +------------------+
 *     | FrameType (3)    | 1 byte
 *     +------------------+
 *     | XFType (203)     | 1 byte
 *     +------------------+
 *     |    hop-count     | 2 bytes
 *     +------------------+
 *
 * TLV Properties:
 *
 * Each tag block is preceeded by a 2 byte length field.
 * General format is 3 byte tag + 1 byte length
 *
 * MsgType:
 * 	"mtp", X, X
 *
 * ICanBeRouter:
 * 	"icr", 1, <0, 1> - byte
 *
 * NChildren:
 * 	"nch", 4, <nr> - uint32
 *
 * UNETVersion:
 * 	"vrs", len, <version string>
 *
 * DevClass:
 * 	"dtp", 1, <device class enum>
 *
 * NRouters:
 * 	"nrs", 4, <nr> - uint32
 *
 * BandwidthAvgLoad:
 *	"bwl", 4, <nr> (0-1 encoded fixed math)
 *
 * ReceivePort:
 *	"rpo", 2, <port>	(port when using unet over IP)
 *
 * OriginAddress:
 * 	"oad", X, X
 *
 * DestinationAddress:
 *	"dad", X, X
 *
 * NextHop:
 * 	"nhp", X, X
 *
 * PriorHop:
 * 	"php", X, X
 *
 * HopCount:
 * 	"hpc", X, X
 *
 * RequestedName:
 * 	"rnm", len, <string>
 *
 * TracePath:
 * 	"tph", X, X
 *
 * TracePathString:
 * 	"tps", X, X
 *
 * Relay:
 * 	"rly", X, X
 *
 * CrazyTestList:
 * 	"cts", X, X
 *
 * Response:
 * 	"rsp", 1, <0, 1> byte
 *
 * TopologyChangeType:
 * 	"tct", 1, <NewParent=0|NewChild=1|Disconnection=2|NewNextHop=3|NewNameAnnounced=4>
 *
 * DiagnosticString
 * 	"dst", len, <string>
 *
 * ReconnectNonce:
 * 	"rcn", len, <nonce>
 *
 * TrustBundle:
 * 	"tbn", X, X
 *
 * TrustBundleLength
 * 	"tbl", X, X
 *
 * TrustBundleExtra
 * 	"tbx", 4, <tb-crc16> 2, <full-size> 2, <n_chunks> 1, <chunk> 1
 *
 * TrustBundleType
 * 	"tbt", 1, <tb-type>
 */

/* uNet packet types */
#define UNET_BTA		0
#define UNET_PTA		1
#define UNET_PTP		2
#define UNET_X			3
#define UNET_SEQ		4

/* set when an x-frame is a FRAGMENT */
#define UNET_FRAGMENT_INTERNAL	BIT(18)
/* set when an x-frame with an unknown frame type is found */
#define UNET_UNKNOWN_INTERNAL	BIT(17)
/* set when an x-frame with XE_ENCRYPTED is found */
#define UNET_ENCRYPTED_INTERNAL	BIT(16)

#define UNET_IS_VALID(_x) \
	({ \
		uint8_t __x = (_x); \
		__x >= UNET_BTA	&& __x <= UNET_SEQ; \
	})

/* frame-type, flags, prefix-len, id-len */
#define UNET_BTA_HDR_MIN	(1 + 1 + 1 + 1)

/* frame-type, flags, packet-length, message-type,
 * prefix-len, id-len,
 */
#define UNET_PTA_HDR_MIN	(1 + 1 + 4 + 4 + 1 + 1)

/* optional minimum header size when ORIG_PARENT flags is set
 * parent-prefix-len, parent-id-len
 */
#define UNET_PTA_HDR_MIN_ORIG_PARENT	(1 + 1)

/* frame-type, flags, packet-length, message-type,
 * dest-prefix-len, dest-id-len, orig-prefix-len, orig-id-len
 */
#define UNET_PTP_HDR_MIN	(1 + 1 + 4 + 4 + 1 + 1 + 1 + 1)

/* optional minimum header size when DEST_PARENT flags is set
 * dest-parent-prefix-len, dest-parent-id-len
 */
#define UNET_HDR_MIN_DEST_PARENT	(1 + 1)

/* optional minimum header size when ORIG_PARENT flags is set
 * orig-parent-prefix-len, orig-parent-id-len
 */
#define UNET_HDR_MIN_ORIG_PARENT	(1 + 1)

/* minimum trust bundle size (prepended length field) */
#define UNET_HDR_MIN_TRUST_BUNDLE	2

/* TLV header is prepended with a 2 byte length field */
#define UNET_HDR_MIN_TLV		2

/* frame-type, x-type, prefix-len, id-len */
#define UNET_XA_HDR_MIN		(1 + 1 + 1 + 1)

/* frame-type, x-type, nonce */
#define UNET_XN_HDR_MIN		(1 + 1 + 6)	/* TODO verify nonce is 6 always */

/* frame-type, x-type, hop-count */
#define UNET_XH_HDR_MIN		(1 + 1 + 2)

/* frame-type, x-type */
#define UNET_XE_HDR_MIN		(1 + 1)

/* frame-type, x-type, crc, full_size, n_frags, frag# */
#define UNET_XF_HDR_MIN		(1 + 1 + 2 + 2 + 1 + 1)

/* prefix-len, id-len */
#define UNET_UA_MIN		(1 + 1)

#define UNET_MASTER_TIMESTAMP_SZ	8
#define UNET_FIRING_TIME_SZ		8

/* PTA/PTP flag bits */
#define UNET_F_NO_TIMESTAMP	BIT(7)	/* no timestamps */
#define UNET_F_DEST_PARENT	BIT(6)	/* dest parent exists */
#define UNET_F_ORIG_PARENT	BIT(5)	/* orig parent exists */
#define UNET_F_DONT_FRAGMENT	BIT(4)	/* do not fragment packet */
#define UNET_F_TRUST		BIT(3)	/* trust bundle in packet */
#define UNET_F_ONLY_TRUSTED	BIT(2)	/* packet traverses trusted */
#define UNET_F_ENCRYPTED	BIT(1)	/* the payload is encrypted */
#define UNET_F_EXTEND		BIT(0)	/* tlv area exist */

/* X-Frame types */
#define UNET_X_ADDRESS_SENDER	200
#define UNET_X_ADDRESS_NEXT_HOP	201
#define UNET_X_KEEP_ALIVE	202
#define UNET_X_HOP_COUNT	203
#define UNET_X_ENCRYPTED	204
#define UNET_X_FRAGMENT		205

#define UNET_X_IS_XA(_x)	\
	({ \
	  	uint8_t __x = (_x); \
	  	__x == UNET_X_ADDRESS_SENDER || \
	 		__x == UNET_X_ADDRESS_NEXT_HOP; \
	})

#define UNET_X_IS_XN(_x)	\
	({ \
	  	uint8_t __x = (_x); \
	  	__x == UNET_X_KEEP_ALIVE; \
	})

#define UNET_X_IS_XH(_x)	\
	({ \
	  	uint8_t __x = (_x); \
	  	__x == UNET_X_HOP_COUNT; \
	})

#define UNET_X_IS_XE(_x)	\
	({ \
	  	uint8_t __x = (_x); \
	  	__x == UNET_X_ENCRYPTED; \
	})

#define UNET_X_IS_XF(_x)	\
	({ \
		uint8_t __x = (_x); \
		__x == UNET_X_FRAGMENT; \
	})

#define UNET_X_IS_HANDLED(_x) \
	({ \
		uint8_t __x = (_x); \
		__x >= UNET_X_ADDRESS_SENDER && __x <= UNET_X_FRAGMENT; \
	})


/* minimum frame is an X frame */
#define UNET_MIN_FRAME		4

/* uNet is LE */
#define UNET_MAKE_TAG(a, b, c) \
	 (((uint32_t)(c) << 16) | ((uint32_t)(b) << 8) | (uint32_t)(a))

#define UNET_GET_TAG(_p) \
	 ({ \
	  	const uint8_t *__p = (_p); \
	  	UNET_MAKE_TAG(__p[0], __p[1], __p[2]); \
	  })

#define UNET_PUT_TAG_LEN(_p, _t, _l) \
	 ({ \
		uint8_t *__p = (_p); \
		uint32_t __t = (_t); \
		__p[0] = (uint8_t)__t; \
		__p[1] = (uint8_t)(__t >> 8); \
		__p[2] = (uint8_t)(__t >> 16); \
		__p[3] = (uint8_t)(_l); \
	  	__p + 4; \
	  })

#define UNET_MIN_TAG_LEN	4
#define UNET_MAX_TAG_LEN	256

/* known valid tags */
#define UNET_TAG_I_CAN_BE_ROUTER	UNET_MAKE_TAG('i', 'c', 'r')
#define UNET_TAG_N_CHILDREN		UNET_MAKE_TAG('n', 'c', 'h')
#define UNET_TAG_VERSION		UNET_MAKE_TAG('v', 'r', 's')
#define UNET_TAG_DEV_CLASS		UNET_MAKE_TAG('d', 't', 'p')
#define UNET_TAG_N_ROUTERS		UNET_MAKE_TAG('n', 'r', 's')
#define UNET_TAG_BANDWIDTH_AVG_LOAD	UNET_MAKE_TAG('b', 'w', 'l')
#define UNET_TAG_RECEIVE_PORT		UNET_MAKE_TAG('r', 'p', 'o')
#define UNET_TAG_REQUESTED_NAME		UNET_MAKE_TAG('r', 'n', 'm')
#define UNET_TAG_RESPONSE		UNET_MAKE_TAG('r', 's', 'p')
#define UNET_TAG_TOPOLOGY_CHANGE_TYPE	UNET_MAKE_TAG('t', 'c', 't')
#define UNET_TAG_DIAGNOSTIC_STRING	UNET_MAKE_TAG('d', 's', 't')
#define UNET_TAG_RECONNECT_NONCE	UNET_MAKE_TAG('r', 'c', 'n')

/* TODO these are defined but not used (verify and remove) */
#define UNET_TAG_MSG_TYPE		UNET_MAKE_TAG('m', 't', 'p')
#define UNET_TAG_ORIGIN_ADDRESS		UNET_MAKE_TAG('o', 'a', 'd')
#define UNET_TAG_DESTINATION_ADDRESS	UNET_MAKE_TAG('d', 'a', 'd')
#define UNET_TAG_NEXT_HOP		UNET_MAKE_TAG('n', 'h', 'p')
#define UNET_TAG_PRIOR_HOP		UNET_MAKE_TAG('p', 'h', 'p')
#define UNET_TAG_HOP_COUNT		UNET_MAKE_TAG('h', 'p', 'c')
#define UNET_TAG_TRACE_PATH		UNET_MAKE_TAG('t', 'p', 'h')
#define UNET_TAG_TRACE_PATH_STRING	UNET_MAKE_TAG('t', 'p', 's')
#define UNET_TAG_RELAY			UNET_MAKE_TAG('r', 'l', 'y')
#define UNET_TAG_CRAZY_TEST_LIST	UNET_MAKE_TAG('c', 't', 's')
#define UNET_TAG_TRUST_BUNDLE		UNET_MAKE_TAG('t', 'b', 'n')
#define UNET_TAG_TRUST_BUNDLE_LENGTH	UNET_MAKE_TAG('t', 'b', 'l')

/* proposed extensions */
#define UNET_TAG_TRUST_EXTRA		UNET_MAKE_TAG('t', 'b', 'x')
#define UNET_TAG_TRUST_EXTRA_SIZE	(sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t) * 2)
#define UNET_TAG_TRUST_BUNDLE_TYPE	UNET_MAKE_TAG('t', 'b', 't')
#define UNET_TAG_TRUST_BUNDLE_TYPE_SIZE	1

#define UNET_TB_TYPE_UNKNOWN			0
#define UNET_TB_TYPE_X509_CERT			1	/* X509 cert (APCR) */
#define UNET_TB_TYPE_X509_CERT_NONCE1		2	/* X509 cert encypted by APCR cert + NONCE (APCA) */
#define UNET_TB_TYPE_NONCE1_NONCE2		3	/* NONCE1 + NONCE2 encrypted (R) */
#define UNET_TB_TYPE_NONCE2			4	/* NONCE2 encrypted (RR) */

#define UNET_TB_NONCE_SIZE			32	/* the nonce is exactly this long */

#define UNET_TB_MAX_FRAGMENTS			8	/* 8 fragments are more than enough */

#define UNET_CRYPTO_ALG_GCM_AES			0
#define UNET_CRYPTO_ALG_HMAC_SHA1_ECB_AES	1
#define UNET_CRYPTO_ALG_HMAC_SHA1_CTR_AES	2
#define UNET_CRYPTO_ALG_COUNT			3

/* DevClass */
#define UNET_DEV_CLASS_SMART_PHONE	0
#define UNET_DEV_CLASS_PAD		1
#define UNET_DEV_CLASS_LINUX_BOX	2
#define UNET_DEV_CLASS_OSX_BOX		3
#define UNET_DEV_CLASS_PC_BOX		4
#define UNET_DEV_CLASS_ROUTER		5
#define UNET_DEV_CLASS_MAX		6

/* TopologyChangeType */
#define UNET_TOP_CHANGE_TYPE_NEW_PARENT		0
#define UNET_TOP_CHANGE_TYPE_NEW_CHILD		1
#define UNET_TOP_CHANGE_TYPE_DISCONNECTION	2
#define UNET_TOP_CHANGE_TYPE_NEW_NEXT_HOP	3
#define UNET_TOP_CHANGE_TYPE_NEW_NAME_ANNOUNCED	4

/* message types */
#define UNET_MSG_NONE			0	/* no message type exists in packet */

#define UNET_MSG_APCR			1	/* AvailablePhysicalConnectionRequest */
#define UNET_MSG_APCA			2	/* AvailablePhysicalConnectionAnnounce */
#define UNET_MSG_R			3	/* Register */
#define UNET_MSG_RR			4	/* RegisterResponse */
#define UNET_MSG_RA			5	/* RegisterAnnounce */
#define UNET_MSG_RRA			6	/* RequestRegisterAnnounce */
#define UNET_MSG_VNR			7	/* ValidateNameRequest */
#define UNET_MSG_VNA			8	/* ValidateNameAnnounce */
#define UNET_MSG_DA			9	/* DisconnectAnnounce */
#define UNET_MSG_RC			10	/* Reconnect */
#define UNET_MSG_ACK			11	/* Acknowledge */
#define UNET_MSG_RFDR			12	/* RouteForDestinationRequest */
#define UNET_MSG_ERQ			13	/* echo request */
#define UNET_MSG_ERP			14	/* echo reply */
#define UNET_MSG_SNK			15	/* sink (no reply) */

#define UNET_MSG_IP			16	/* this is an IP packet */

/* message should create a remote entity (if it doesn't exist) */
static inline bool unet_message_should_create_entity(uint32_t message_type)
{
	return message_type == UNET_MSG_APCR ||
	       message_type == UNET_MSG_APCA;
}

/* message may update the entity properties */
static inline bool unet_message_should_update_prop(uint32_t message_type)
{
	return message_type == UNET_MSG_APCR ||
	       message_type == UNET_MSG_APCA ||
	       message_type == UNET_MSG_R    ||
	       message_type == UNET_MSG_RR;
}

/* on outgoing message should next_hop & address sender be added */
static inline bool
unet_message_should_append_next_hop_sender(uint32_t message_type)
{
	return message_type != UNET_MSG_APCR &&
	       message_type != UNET_MSG_APCA &&
	       message_type != UNET_MSG_R    &&
	       message_type != UNET_MSG_RR;
}

/* message is visible only (no orig/dest parents allowed) */
static inline bool unet_message_is_visible_only(uint32_t message_type)
{
	return message_type == UNET_MSG_APCR ||
	       message_type == UNET_MSG_APCA ||
	       message_type == UNET_MSG_R    ||
	       message_type == UNET_MSG_RR   ||
	       message_type == UNET_MSG_RFDR ||
	       message_type == UNET_MSG_DA   ||
	       message_type == UNET_MSG_RC   ||
	       message_type == UNET_MSG_ACK;
}

/* can the outgoing message be encrypted */
static inline bool
unet_message_can_be_encrypted(uint32_t message_type)
{
	return message_type != UNET_MSG_APCR &&
	       message_type != UNET_MSG_APCA &&
	       message_type != UNET_MSG_R    &&
	       message_type != UNET_MSG_RR;
}

/* outgoing message requires a local entity */
static inline bool
unet_message_requires_local_entity(uint32_t message_type)
{
	return message_type == UNET_MSG_APCR ||
	       message_type == UNET_MSG_APCA ||
	       message_type == UNET_MSG_R    ||
	       message_type == UNET_MSG_RR   ||
	       message_type == UNET_MSG_RC   ||
	       message_type == UNET_MSG_ACK;
}

/* user reserved message area */
#define UNET_MSG_USER_START		1024
#define UNET_MSG_USER_END		(INT_MAX-1)
#define UNET_MSG_EPHEMERAL_START	49152
#define UNET_MSG_EPHEMERAL_END		65535

struct unet_entity;

static inline void *uput8(uint8_t v, void *p)
{
	*(u8 *)p = v;
	return p + sizeof(uint8_t);
}

static inline void *uput16(uint16_t v, void *p)
{
	put_unaligned_le16(v, p);
	return p + sizeof(uint16_t);
}

static inline void *uput32(uint32_t v, void *p)
{
	put_unaligned_le32(v, p);
	return p + sizeof(uint32_t);
}

static inline void *uput(const void *data, unsigned int len, void *p)
{
	memcpy(p, data, len);
	return p + len;
}

static inline void *uputstr(const char *str, void *p)
{
	unsigned int len = strlen(str);
	memcpy(p, str, len);
	return p + len;
}

static inline void *uput64(uint64_t v, void *p)
{
	put_unaligned_le64(v, p);
	return p + sizeof(uint64_t);
}

static inline void *uputtag(uint32_t tag, uint8_t len, void *p)
{
	return uput32((tag << 8) | len, p);
}

static inline const void *uget8(uint8_t *v, const void *p)
{
	*v = *(const u8 *)p;
	return p + sizeof(uint8_t);
}

static inline const void *uget16(uint16_t *v, const void *p)
{
	*v = get_unaligned_le16(p);
	return p + sizeof(uint16_t);
}

static inline const void *uget32(uint32_t *v, const void *p)
{
	*v = get_unaligned_le32(p);
	return p + sizeof(uint32_t);
}

static inline const void *uget64(uint64_t *v, const void *p)
{
	*v = get_unaligned_le64(p);
	return p + sizeof(uint64_t);
}

static inline const void *uget(void *data, unsigned int len, const void *p)
{
	memcpy(data, p, len);
	return p + len;
}

/* NOTE: no ugetstr */

static inline const void *ugettag(uint32_t *tag, uint8_t *len, const void *p)
{
	uint32_t tag_len;
	tag_len = get_unaligned_le32(p);
	*tag = tag_len >> 8;
	*len = (uint8_t)tag_len;
	return p + sizeof(uint32_t);
}

struct unet_frame_params {
	/* inputs */
	struct unet_entity *sender_ue;
	struct unet_entity *next_hop_ue;
	struct unet_bearer *b;
	struct net_device *dev;
	struct unet_addr *orig_ua;
	struct unet_addr *dest_ua;
	struct list_head *x_list;
	uint32_t message_type;
	uint64_t master_ts;
	uint64_t firing_ts;
	const void *data;
	size_t data_sz;
	/* trust bundle fragmentation */
	unsigned int n_chunks;
	unsigned int chunk;
	/* generic frame fragmentation */
	unsigned int n_frags;
	unsigned int frag;
	/* this is filled if set to NULL */
	struct unet_conn_entry *uce;
	/* those are filled in */
	uint8_t flags;
	unsigned int x_userhdrsz;	/* x size of what was passed */
	unsigned int x_hdrsz;		/* x size including auto-gen */
	unsigned int pta_ptp_hdrsz;
	unsigned int tlv_hdrsz;
	unsigned int tb_hdrsz;
	unsigned int tb_fullsz;
	uint8_t tb_type;		/* type of the trust bundle */
	uint16_t tb_crc;
	unsigned int pldsz;		/* size without the x-headers */
	unsigned int epldsz;		/* payload size when encrypted */
	unsigned int size;		/* non encrypted full size */
	unsigned int esize;		/* encypted  full size */
	unsigned int devsz;		/* transmitted size on the device */

	/* flags set while processing */
	unsigned int secure : 1;	/* unet_conn_entry_is_secure() */
	unsigned int trusted : 1;	/* unet_conn_entry_is_trusted() */
	unsigned int crypto_ready : 1;	/* unet_entity_conn_is_crypto_ready */
	unsigned int encrypted : 1;	/* encryption requested */
	unsigned int xe_present : 1;	/* X_ENCRYPTED present */
	unsigned int xnh_present : 1;	/* X_NEXT_HOP present */
	unsigned int xsnd_present : 1;	/* X_SENDER present */
	unsigned int will_fragment : 1;	/* too large, fragmentation req. */
	/* set by caller */
	unsigned int dont_fragment : 1;	/* do not try to fragment */
	unsigned int no_timestamp : 1;	/* don't add timestamps */
};

int unet_calculate_frame_size_params(struct unet_frame_params *ufp);
int unet_construct_frame_params(struct sk_buff_head *list,
				struct unet_frame_params *ufp);

int unet_construct_frame_list(struct sk_buff_head *list,
			      struct unet_frame_params *ufp);

int unet_construct_visible_list(
		struct sk_buff_head *list, struct unet_bearer *b,
		struct unet_entity *orig_ue, struct unet_entity *dest_ue,
		struct unet_conn_entry *uce,
		uint32_t message_type, const void *data, size_t data_sz);

int unet_construct_forwarding_frame_list(
		struct sk_buff_head *list,
		struct unet_entity *ue, struct unet_entity *ue_next_hop,
		struct unet_conn_entry *uce,
		struct list_head *x_frame_list,
		struct sk_buff *skb_orig);

struct unet_x_entry {
	struct list_head node;
	uint8_t type;	/* x-frame-type */
	/* anonymous union */
	union {
		struct unet_addr addr;
		uint8_t nonce[6];
		uint16_t hop_count;
		struct {
			/* NOTE ordered so that there are no gaps */
			uint16_t crc;
			uint16_t full_size;
			uint8_t n_frags;
			uint8_t frag;
		} frag;
	};
};

/* exploded unet packet */
struct unet_packet_header {
	/* when valid frame only 8 low bits are used */
	unsigned int frame_type;
	/* anonymous union */
	union {
		struct {
			struct unet_addr beacon;
		} bta;
		struct {
			uint8_t flags;
			/* TODO packet length should not be here? */
			uint32_t packet_length;
			uint32_t message_type;
			struct unet_addr dest;
			struct unet_addr orig;
			uint64_t master_timestamp;
			uint64_t firing_time;

			uint32_t tb_skb_offset;
			uint16_t tb_size;

		} pta_ptp;
	};
	/* when flags have X bit set we fill these properties */
	struct {
		/* note anonymous structs and unions */
		union {
			struct {
				uint32_t has_i_can_be_router	: 1;
				uint32_t has_n_children		: 1;
				uint32_t has_version		: 1;
				uint32_t has_dev_class		: 1;
				uint32_t has_n_routers		: 1;
				uint32_t has_bw_avg_load	: 1;
				uint32_t has_receive_port	: 1;
				uint32_t has_requested_name	: 1;
				uint32_t has_response		: 1;
				uint32_t has_topo_change_type	: 1;
				uint32_t has_diagnostic_string  : 1;
				uint32_t has_reconnect_nonce	: 1;
				uint32_t has_trust_bundle	: 1;	/* easier to be here */
				uint32_t has_trust_extra	: 1;
				uint32_t has_trust_bundle_type	: 1;
			};
			uint32_t has_flag_bits;	/* for fast cleanup */
		};

		bool i_can_be_router;
		uint32_t n_children;
		char version[UNET_MAX_TAG_LEN + 1];
		uint32_t dev_class;
		uint32_t n_routers;
		uint32_t bw_avg_load;
		uint16_t receive_port;
		char requested_name[UNET_MAX_TAG_LEN + 1];
		bool response;
		uint8_t topo_change_type;
		char diagnostic_string[UNET_MAX_TAG_LEN + 1];
		char reconnect_nonce[UNET_MAX_TAG_LEN + 1];
		struct {
			uint16_t crc;
			uint16_t full_size;
			uint8_t n_chunks;
			uint8_t chunk;
		} trust_extra;
		uint8_t trust_bundle_type;
	} prop;
};

static inline int
unet_skb_ptr_to_data_offset(const struct sk_buff *skb, const void *p)
{
	if (!skb || !p || skb_is_nonlinear(skb) ||
	    p < (const void *)skb->head ||
	    p >= (const void *)skb_end_pointer(skb))
		return -EINVAL;
	if (p < (const void *)skb->data)
		return -ERANGE;
	return p - (const void *)skb->data;
}

static inline const void *
unet_skb_data_offset_to_ptr(const struct sk_buff *skb, unsigned int offset)
{
	const void *p;

	if (!skb || skb_is_nonlinear(skb))
		return NULL;
	p = skb->data + offset;
	if (p >= (const void *)skb_end_pointer(skb))
		return NULL;
	return p;
}

/* fast clear of packet header (only zero the tlv has bits) */
static inline void unet_packet_header_clear(struct unet_packet_header *uph)
{
	uph->pta_ptp.dest.parent_prefix_len = 0;
	uph->pta_ptp.dest.parent_id_len = 0;
	uph->pta_ptp.dest.prefix_len = 0;
	uph->pta_ptp.dest.id_len = 0;
	uph->pta_ptp.orig.parent_prefix_len = 0;
	uph->pta_ptp.orig.parent_id_len = 0;
	uph->pta_ptp.orig.prefix_len = 0;
	uph->pta_ptp.orig.id_len = 0;
	uph->pta_ptp.tb_size = 0;
	uph->prop.has_flag_bits = 0;
}

/* must be less than 48 bytes (sizeof(skb->cb)) */
struct unet_skb_cb {
	uint32_t magic;				/* magic value for sanity */
	uint32_t size;				/* data size */
	uint32_t data_offset;			/* to data window data */
	uint32_t xhdr_size;			/* size of the xhdr area */
	struct unet_packet_header *uph;		/* decoded packet header */
	struct list_head x_list;		/* xframes linked list */
};

#define UNET_SKB_CB(__skb) ((struct unet_skb_cb *)&((__skb)->cb[0]))
#define UNET_SKB_CB_MAGIC  0x554E4554	/* 'U', 'N', 'E', 'T' */

/* clone a unet skb (and the control block */
struct sk_buff *unet_skb_clone(struct sk_buff *skb, bool copy_hdr, gfp_t flags);

int unet_packet_setup(void);
void unet_packet_cleanup(void);
int unet_skb_cb_prepare(struct sk_buff *skb, gfp_t flags,
		bool was_decrypted);
void unet_skb_cb_cleanup(struct sk_buff *skb);

void unet_skb_dump_rx(struct unet_bearer *b, struct sk_buff *skb,
		bool decrypted);
void unet_skb_dump_tx(struct unet_bearer *b, struct sk_buff *skb,
		const void *dest, bool decrypted);

struct unet_addr *unet_packet_get_dest_addr(struct unet_packet_header *uph);
struct unet_addr *unet_packet_get_orig_addr(struct unet_packet_header *uph);

static inline bool unet_packet_has_orig_parent(struct unet_packet_header *uph)
{
	return !!(uph->pta_ptp.flags & UNET_F_ORIG_PARENT);
}

static inline bool unet_packet_has_dest_parent(struct unet_packet_header *uph)
{
	return !!(uph->pta_ptp.flags & UNET_F_DEST_PARENT);
}

static inline uint32_t unet_packet_message_type(struct unet_packet_header *uph)
{
	if (uph->frame_type != UNET_PTA && uph->frame_type != UNET_PTP)
		return UNET_MSG_NONE;	/* no message in those packets */
	return uph->pta_ptp.message_type;
}

extern struct kmem_cache *unet_packet_header_cache;
extern struct kmem_cache *unet_x_entry_cache;

struct sk_buff *
unet_entity_reassemble_skb(struct unet_entity *ue,
			   struct unet_entity *ue_sender,
			   struct sk_buff *skb,
			   unsigned int x_hdrsz,
			   uint8_t frag, uint8_t n_frags,
			   uint16_t fullsize, uint16_t crc);

#endif
