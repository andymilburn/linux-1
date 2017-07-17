/*
 * net/unet/utils.c: uNet utility methods
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
#include "utils.h"

#include <linux/unet.h>
#include <linux/module.h>
#include <linux/ctype.h>

static const char *hex = "0123456789abcdef";

static inline bool is_valid_ua_addr_char(const char c)
{
	return c  > ' ' && c <= '~' &&
	       c != ':' && c != '/' && c != '.' && c != '$';
}

char *unet_addr_to_str(gfp_t gfp, const struct unet_addr *ua)
{
	int i, len, alloclen;
	char c, *d, *str;
	const char *s;
	bool use_hex;

	if (!ua)
		return NULL;

	/*
	 * if the whole address is ascii with non of [~:/.$]
	 * then output as address as a string
	 */
	len = unet_addr_buffer_len(ua);
	s = ua->addr_buffer;
	for (i = 0; i < len; i++) {
		c = *s++;
		if (!is_valid_ua_addr_char(c))
			break;
	}

	use_hex = i < len;

	if (use_hex)
		alloclen = len * 2 + 5; /* $.:.\0 */
	else
		alloclen = len + 4;     /* .:.\0 */

	str = kmalloc(alloclen, gfp);
	if (!str)
		return NULL;
	d = str;
	s = ua->addr_buffer;	/* laid out in sequence, utilize */

	if (use_hex)
		*d++ = '$';

#undef OUTPUT_CHUNK
#define OUTPUT_CHUNK(_l) \
	do { \
		len = (_l); \
		for (i = 0; i < len; i++) { \
			c = *s++; \
			if (!use_hex) \
				*d++ = c; \
			else { \
				*d++ = hex[((unsigned int)c >> 4) & 15]; \
				*d++ = hex[ (unsigned int)c       & 15]; \
			} \
		} \
	} while(0)

	if (ua->parent_prefix_len && ua->parent_id_len) {
		OUTPUT_CHUNK(ua->parent_prefix_len);
		*d++ = '.';
		OUTPUT_CHUNK(ua->parent_id_len);
		*d++ = ':';
	}
	OUTPUT_CHUNK(ua->prefix_len);
	*d++ = '.';
	OUTPUT_CHUNK(ua->id_len);
	*d = '\0';

#undef OUTPUT_CHUNK
	return str;
}

int unet_str_to_addr(const char *str, int size, struct unet_addr *ua)
{
	const char *s, *se;
	u8 *d, *e;
	int dots, colons;
	const char *dotsp[2];
	const char *colonp;
	char c;
	bool is_hex;

	if (size == -1)
		size = strlen(str);
	while (size > 0 && isspace(str[size-1]))
		size--;
	se = str + size;

	if (size <= 1)
		return -EINVAL;

	/* hex address? */
	if (*str == '$') {
		str++;
		is_hex = true;
	} else
		is_hex = false;

	dotsp[0] = dotsp[1] = NULL;
	colonp = NULL;

	dots = 0;
	colons = 0;
	for (s = str; s < se; s++) {
		c = *s;
		if (c == '.') {
			/* no more than 2 dots */
			if (dots > 1)
				return -EINVAL;
			/* second dot must be preceded by a colon */
			if (dots == 1 && colons == 0)
				return -EINVAL;
			dotsp[dots++] = s;
		} else if (c == ':') {
			/* no more than 1 colon */
			if (colons > 0)
				return -EINVAL;
			/* we must have encountered a dot already */
			if (dots == 0)
				return -EINVAL;
			colonp = s;
			colons++;
		} else if (is_hex) {
			/* hex-address and is not a hex digit */
			if (!isxdigit(c) && !isdigit(c))
				return -EINVAL;
		} else {
			/* if it's not a valid addr */
			if (!is_valid_ua_addr_char(c))
				return -EINVAL;
		}
	}

	/* at least one dot must be present (prefix is mandatory) */
	if (dots == 0)
		return -EINVAL;

	/* we have a valid address string */
	s = str;
	d = ua->addr_buffer;
	e = d + sizeof(ua->addr_buffer);

#undef CONVERT_CHUNK
#define CONVERT_CHUNK(_len) \
	({	\
		int len = (_len); \
		u8 *ds = d; \
		u8 v; \
		while (len > 0) { \
			if (is_hex) { \
				/* there must be two bytes at least */ \
				if (len < 2) { \
					pr_info("%s:%d\n", __FILE__, __LINE__); \
					return -EINVAL; \
				} \
				c = *s++; \
				if (c >= '0' && c <= '9') \
					v = c - '0'; \
				else \
					v = 10 + (tolower(c) - 'a'); \
				v <<= 4; \
				c = *s++; \
				if (c >= '0' && c <= '9') \
					v |= c - '0'; \
				else \
					v |= 10 + (tolower(c) - 'a'); \
				len -= 2; \
			} else { \
				v = *s++; \
				len--; \
			} \
			*d++ = v; \
		} \
		d - ds; \
	})

	/* we have a parent type address */
	dots = 0;
	if (colonp) {
		ua->parent_prefix_len = CONVERT_CHUNK(dotsp[dots] - s);
		s++;
		ua->parent_id_len = CONVERT_CHUNK(colonp - s);
		s++;
		dots++;
	} else {
		ua->parent_prefix_len = 0;
		ua->parent_id_len = 0;
	}
	ua->prefix_len = CONVERT_CHUNK(dotsp[dots] - s);
	s++;
	ua->id_len = CONVERT_CHUNK(se - s);

#undef CONVERT_CHUNK
	return 0;
}

struct unet_addr *unet_str_to_addr_alloc(gfp_t gfp, const char *str, int size)
{
	struct unet_addr *ua;
	int err;

	ua = kzalloc(sizeof(*ua), gfp);
	if (!ua)
		return ERR_PTR(-ENOMEM);
	err = unet_str_to_addr(str, size, ua);
	if (err) {
		kfree(ua);
		return ERR_PTR(err);
	}
	return ua;
}

static void __unet_entity_printk(const char *level, struct unet_entity *ue,
				 const char *pfx, struct va_format *vaf)
{
	printk("%sunet%s%s%s %s: %pV", level,
			pfx ? "-" : ":",
			pfx ? pfx : "",
			pfx ? ":" : "",
			unet_entity_name(ue),
			vaf);
}

void unet_entity_printk(const char *level, struct unet_entity *ue,
			const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	__unet_entity_printk(level, ue, NULL, &vaf);

	va_end(args);
}

static void __unet_conn_entry_printk(const char *level, struct unet_conn_entry *uce,
				 const char *pfx, struct va_format *vaf)
{
	struct unet_entity *ue = unet_conn_entry_to_entity(uce);

	printk("%sunet%s%s%s %s-%s: %pV", level,
			pfx ? "-" : ":",
			pfx ? pfx : "",
			pfx ? ":" : "",
			unet_entity_name(ue), unet_entity_name(uce->ue),
			vaf);
}

void unet_conn_entry_printk(const char *level, struct unet_conn_entry *uce,
			const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	__unet_conn_entry_printk(level, uce, NULL, &vaf);

	va_end(args);
}

static void __unet_bearer_printk(const char *level, struct unet_bearer *b,
				 const char *pfx, struct va_format *vaf)
{
	printk("%sunet%s%s%s %s: %pV", level,
			pfx ? "-" : ":",
			pfx ? pfx : "",
			pfx ? ":" : "",
			b->name,
			vaf);
}

void unet_bearer_printk(const char *level, struct unet_bearer *b,
			const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	__unet_bearer_printk(level, b, NULL, &vaf);

	va_end(args);
}

#define define_unet_entity_printk_level(func, level)		\
void func(struct unet_entity *ue, const char *fmt, ...)		\
{								\
	struct va_format vaf;					\
	va_list args;						\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	__unet_entity_printk(level, ue, NULL, &vaf);		\
								\
	va_end(args);						\
}

define_unet_entity_printk_level(unet_entity_emerg, KERN_EMERG);
define_unet_entity_printk_level(unet_entity_alert, KERN_ALERT);
define_unet_entity_printk_level(unet_entity_crit, KERN_CRIT);
define_unet_entity_printk_level(unet_entity_err, KERN_ERR);
define_unet_entity_printk_level(unet_entity_warn, KERN_WARNING);
define_unet_entity_printk_level(unet_entity_notice, KERN_NOTICE);
define_unet_entity_printk_level(unet_entity_info, KERN_INFO);

#define define_unet_bearer_printk_level(func, level)		\
void func(struct unet_bearer *b, const char *fmt, ...)		\
{								\
	struct va_format vaf;					\
	va_list args;						\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	__unet_bearer_printk(level, b, NULL, &vaf);		\
								\
	va_end(args);						\
}

define_unet_bearer_printk_level(unet_bearer_emerg, KERN_EMERG);
define_unet_bearer_printk_level(unet_bearer_alert, KERN_ALERT);
define_unet_bearer_printk_level(unet_bearer_crit, KERN_CRIT);
define_unet_bearer_printk_level(unet_bearer_err, KERN_ERR);
define_unet_bearer_printk_level(unet_bearer_warn, KERN_WARNING);
define_unet_bearer_printk_level(unet_bearer_notice, KERN_NOTICE);
define_unet_bearer_printk_level(unet_bearer_info, KERN_INFO);

#define define_unet_entity_dump_printk_level(func, dump, level) \
void func(struct unet_entity *ue, const char *fmt, ...)		\
{								\
	struct unet_net *un = unet_entity_unet(ue);		\
	struct va_format vaf;					\
	va_list args;						\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	if (un->syslog_##dump##_dump)				\
		__unet_entity_printk(level, ue, #dump, &vaf);	\
								\
	va_end(args);						\
}

define_unet_entity_dump_printk_level(unet_fsm_err, fsm, KERN_ERR);
define_unet_entity_dump_printk_level(unet_fsm_info, fsm, KERN_INFO);
define_unet_entity_dump_printk_level(unet_router_err, router, KERN_ERR);
define_unet_entity_dump_printk_level(unet_router_info, router, KERN_INFO);

#define define_unet_bearer_dump_printk_level(func, dump, level) \
void func(struct unet_bearer *b, const char *fmt, ...)		\
{								\
	struct net_device *dev = unet_dev_bearer_get(b);	\
	struct net *net = dev_net(dev);				\
	struct unet_net *un = unet_net(net);			\
	struct va_format vaf;					\
	va_list args;						\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	if (un->syslog_##dump##_dump)				\
		__unet_bearer_printk(level, b, #dump, &vaf);	\
								\
	va_end(args);						\
}

define_unet_bearer_dump_printk_level(unet_bearer_state_err, bearer, KERN_ERR);
define_unet_bearer_dump_printk_level(unet_bearer_state_info, bearer, KERN_INFO);

#define define_unet_conn_dump_printk_level(func, dump, level) \
void func(struct unet_conn_entry *uce, const char *fmt, ...)	\
{								\
	struct unet_entity *ue = unet_conn_entry_to_entity(uce);\
	struct unet_net *un = unet_entity_unet(ue);		\
	struct va_format vaf;					\
	va_list args;						\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	if (un->syslog_##dump##_dump)				\
		__unet_conn_entry_printk(level, uce, #dump, &vaf);\
								\
	va_end(args);						\
}

define_unet_conn_dump_printk_level(unet_conn_err, conn, KERN_ERR);
define_unet_conn_dump_printk_level(unet_conn_info, conn, KERN_INFO);
define_unet_conn_dump_printk_level(unet_crypto_err, crypto, KERN_ERR);
define_unet_conn_dump_printk_level(unet_crypto_info, crypto, KERN_INFO);

/* hashes the most significant part of the address */
u32 unet_addr_hash(const struct unet_addr *ua, u32 seed)
{
	unsigned int len;

	/* if we have a parent then this is the key */
	if (unet_addr_has_parent(ua))
		len = ua->parent_prefix_len + ua->parent_id_len;
	else
		len = ua->prefix_len + ua->id_len;

	seed = jhash(&len, sizeof(len), seed);
	seed = jhash(ua->addr_buffer, len, seed);

	return seed;
}

bool unet_hash_addr_eq(const struct unet_addr *ua1, const struct unet_addr *ua2)
{
	unsigned int len1, len2;

	if (ua1 == ua2)
		return true;

	/* if we have a parent then this is the key */
	if (unet_addr_has_parent(ua1))
		len1 = ua1->parent_prefix_len + ua1->parent_id_len;
	else
		len1 = ua1->prefix_len + ua1->id_len;

	if (unet_addr_has_parent(ua2))
		len2 = ua2->parent_prefix_len + ua2->parent_id_len;
	else
		len2 = ua2->prefix_len + ua2->id_len;

	/* lengths and contents must match */
	return len1 == len2 && !memcmp(ua1->addr_buffer, ua2->addr_buffer, len1);
}

/* hashes the least significant part of the address */
u32 unet_addr_app_hash(const struct unet_addr *ua, u32 seed)
{
	unsigned int len;

	/* if we have a parent then this is the key */
	len = ua->prefix_len + ua->id_len;

	seed = jhash(&len, sizeof(len), seed);
	/* NOTE id follows prefix always so we use this */
	seed = jhash(unet_addr_prefix((void *)ua), len, seed);

	return seed;
}

bool unet_hash_addr_app_eq(const struct unet_addr *ua1, const struct unet_addr *ua2)
{
	unsigned int len1, len2;

	if (ua1 == ua2)
		return true;

	len1 = ua1->prefix_len + ua1->id_len;
	len2 = ua2->prefix_len + ua2->id_len;

	/* lengths and contents must match */
	/* NOTE id follows prefix always so we use this */
	return len1 == len2 &&
	       !memcmp(unet_addr_prefix((void *)ua1),
		       unet_addr_prefix((void *)ua2), len1);
}
