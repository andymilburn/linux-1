/*
 * net/unet/utils.h: uNet utility methods
 *
 * Copyright (c) 2016-2017, uNet Inc.
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

#ifndef _UNET_UTILS_H
#define _UNET_UTILS_H

#include <linux/unet.h>
#include <linux/types.h>

struct unet_entity;
struct unet_bearer;
struct unet_conn_entry;

char *unet_addr_to_str(gfp_t gfp, const struct unet_addr *ua);
int unet_str_to_addr(const char *str, int size, struct unet_addr *ua);
struct unet_addr *unet_str_to_addr_alloc(gfp_t gfp, const char *str, int size);

/* unet printk helpers */
__printf(3, 4)
void unet_entity_printk(const char *level, struct unet_entity *ue,
		const char *fmt, ...);
__printf(3, 4)
void unet_bearer_printk(const char *level, struct unet_bearer *b,
		const char *fmt, ...);
__printf(3, 4)
void unet_conn_entry_printk(const char *level, struct unet_conn_entry *uce,
		const char *fmt, ...);

__printf(2, 3)
void unet_entity_emerg(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_entity_alert(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_entity_crit(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_entity_err(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_entity_warn(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_entity_notice(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_entity_info(struct unet_entity *ue, const char *format, ...);

__printf(2, 3)
void unet_bearer_emerg(struct unet_bearer *b, const char *format, ...);
__printf(2, 3)
void unet_bearer_alert(struct unet_bearer *b, const char *format, ...);
__printf(2, 3)
void unet_bearer_crit(struct unet_bearer *b, const char *format, ...);
__printf(2, 3)
void unet_bearer_err(struct unet_bearer *b, const char *format, ...);
__printf(2, 3)
void unet_bearer_warn(struct unet_bearer *b, const char *format, ...);
__printf(2, 3)
void unet_bearer_notice(struct unet_bearer *b, const char *format, ...);
__printf(2, 3)
void unet_bearer_info(struct unet_bearer *b, const char *format, ...);

__printf(2, 3)
void unet_fsm_err(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_fsm_info(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_conn_err(struct unet_conn_entry *uce, const char *format, ...);
__printf(2, 3)
void unet_conn_info(struct unet_conn_entry *uce, const char *format, ...);
__printf(2, 3)
void unet_crypto_err(struct unet_conn_entry *uce, const char *format, ...);
__printf(2, 3)
void unet_crypto_info(struct unet_conn_entry *uce, const char *format, ...);
__printf(2, 3)
void unet_router_err(struct unet_entity *ue, const char *format, ...);
__printf(2, 3)
void unet_router_info(struct unet_entity *ue, const char *format, ...);

__printf(2, 3)
void unet_bearer_state_err(struct unet_bearer *b, const char *format, ...);
__printf(2, 3)
void unet_bearer_state_info(struct unet_bearer *b, const char *format, ...);

static inline int unet_uuid_to_str(unsigned char uuid[16],
				   char *str, size_t size)
{
	return scnprintf(str, size, "%02x%02x%02x%02x-%02x%02x-"
		"%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			uuid[ 0], uuid[ 1], uuid[ 2], uuid[ 3],
			uuid[ 4], uuid[ 5], uuid[ 6], uuid[ 7],
			uuid[ 8], uuid[ 9], uuid[10], uuid[11],
			uuid[12], uuid[13], uuid[14], uuid[15]);
}

u32 unet_addr_hash(const struct unet_addr *ua, u32 seed);
bool unet_hash_addr_eq(const struct unet_addr *ua1, const struct unet_addr *ua2);

u32 unet_addr_app_hash(const struct unet_addr *ua, u32 seed);
bool unet_hash_addr_app_eq(const struct unet_addr *ua1, const struct unet_addr *ua2);

static inline gfp_t unet_gfp_flags(void)
{
	return (preempt_count() || rcu_preempt_depth() || in_atomic() || irqs_disabled()) ?
		GFP_ATOMIC : GFP_KERNEL;
}

#endif
