/*
 * net/unet/sysfs.c: uNet sysfs/kobj code
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
#include "bearer.h"
#include "fsm.h"
#include "utils.h"
#include "router.h"
#include "next_hop.h"
#include "conn.h"
#include "app.h"

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/ctype.h>
#include <linux/atomic.h>

/* root kobject */
struct kobject *unet_kobj;

struct kset *unet_local_entities_kset;
struct kset *unet_remote_entities_kset;
struct kset *unet_app_entries_kset;

struct unet_entity_attribute {
	struct attribute attr;
	ssize_t (*show)(struct unet_entity *ue, struct unet_entity_attribute *attr, char *buf);
	ssize_t (*store)(struct unet_entity *ue, struct unet_entity_attribute *attr, const char *buf, size_t count);
};
#define to_unet_entity_attr(x) container_of(x, struct unet_entity_attribute, attr)

#define UNET_ENTITY_ATTR(_name, _mode, _show, _store) \
	struct unet_entity_attribute unet_entity_attr_##_name = \
		__ATTR(_name, _mode, _show, _store)
#define UNET_ENTITY_ATTR_RW(_name) \
	struct unet_entity_attribute unet_entity_attr_##_name = \
		__ATTR(_name, (S_IWUSR | S_IRUGO), \
			unet_entity_##_name##_show, unet_entity_##_name##_store)
#define UNET_ENTITY_ATTR_RO(_name) \
	struct unet_entity_attribute unet_entity_attr_##_name = \
		__ATTR(_name, S_IRUGO, \
			unet_entity_##_name##_show, NULL)
#define UNET_ENTITY_ATTR_WO(_name) \
	struct unet_entity_attribute unet_entity_attr_##_name = \
		__ATTR(_name, S_IWUSR, \
			NULL, unet_entity_##_name##_store)

static ssize_t unet_entity_attr_show(struct kobject *kobj,
			     struct attribute *attr,
			     char *buf)
{
	struct unet_entity_attribute *attribute;
	struct unet_entity *ue;

	attribute = to_unet_entity_attr(attr);
	ue = to_unet_entity(kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(ue, attribute, buf);
}

static ssize_t unet_entity_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t len)
{
	struct unet_entity_attribute *attribute;
	struct unet_entity *ue;

	attribute = to_unet_entity_attr(attr);
	ue = to_unet_entity(kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(ue, attribute, buf, len);
}

static ssize_t unet_entity_refcount_show(struct unet_entity *ue,
		struct unet_entity_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n",
			refcount_read(&ue->kobj.kref.refcount));
}
UNET_ENTITY_ATTR_RO(refcount);

static ssize_t unet_entity_state_show(struct unet_entity *ue,
		struct unet_entity_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", unet_entity_state_txt(ue->state));
}
UNET_ENTITY_ATTR_RO(state);

static ssize_t unet_entity_type_show(struct unet_entity *ue,
		struct unet_entity_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", ue->type == unet_entity_type_local ?
					"local" : "remote");
}
UNET_ENTITY_ATTR_RO(type);

static ssize_t unet_entity_n_children_show(struct unet_entity *ue,
		struct unet_entity_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", unet_entity_get_n_children(ue));
}
UNET_ENTITY_ATTR_RO(n_children);

static ssize_t unet_entity_n_routers_show(struct unet_entity *ue,
		struct unet_entity_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", unet_entity_get_n_routers(ue));
}
UNET_ENTITY_ATTR_RO(n_routers);

static ssize_t unet_entity_ping_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	struct unet_addr *ua = NULL;
	const char *s, *e, *data;
	size_t data_sz, ua_sz;

	s = buf;
	e = s + count;
	while (*s && !isspace(*s))
		s++;
	if (*s) {
		ua_sz = s - buf;
		while (*s && isspace(*s))
			s++;
		data = s;
		data_sz = e - s;
	} else {
		data = NULL;
		data_sz = 0;
		ua_sz = count;
	}

	ua = unet_str_to_addr_alloc(GFP_KERNEL, buf, ua_sz);
	if (IS_ERR(ua)) {
		unet_entity_info(ue, "Failed to convert to unet address\n");
		return PTR_ERR(ua);
	}

	unet_entity_send(ue, NULL, ua, UNET_MSG_ERQ, data, data_sz);

	kfree(ua);

	return count;
}
UNET_ENTITY_ATTR_WO(ping);

static ssize_t unet_entity_sink_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	struct unet_addr *ua = NULL;

	ua = unet_str_to_addr_alloc(GFP_KERNEL, buf, count);
	if (IS_ERR(ua)) {
		unet_entity_info(ue, "Failed to convert to unet address\n");
		return PTR_ERR(ua);
	}

	unet_entity_send(ue, NULL, ua, UNET_MSG_SNK, NULL, 0);

	kfree(ua);

	return count;
}
UNET_ENTITY_ATTR_WO(sink);

static ssize_t unet_entity_set_parent_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	struct unet_addr *ua;
	int err;

	ua = unet_str_to_addr_alloc(GFP_KERNEL, buf, count);
	if (IS_ERR(ua)) {
		unet_entity_info(ue, "Failed to convert to unet address\n");
		return PTR_ERR(ua);
	}

	err = unet_entity_set_parent_by_addr(ue, ua);

	kfree(ua);

	if (err) {
		unet_entity_info(ue, "Failed to set parent\n");
		return err;
	}

	return count;
}
UNET_ENTITY_ATTR_WO(set_parent);

static ssize_t unet_entity_apcr_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	unet_entity_send_to_visible(ue, NULL, NULL, UNET_MSG_APCR, NULL, 0);

	return count;
}
UNET_ENTITY_ATTR_WO(apcr);

static ssize_t unet_entity_rfdr_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	unet_entity_send(ue, NULL, &unet_root_addr, UNET_MSG_RFDR, NULL, 0);

	return count;
}
UNET_ENTITY_ATTR_WO(rfdr);

static ssize_t unet_entity_stop_apcr_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	unet_entity_stop_apcr_timeout(ue);
	return count;
}
UNET_ENTITY_ATTR_WO(stop_apcr);

static ssize_t unet_entity_disconnect_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	unet_entity_disconnect(ue);
	return count;
}
UNET_ENTITY_ATTR_WO(disconnect);

static ssize_t unet_entity_reconnect_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	unet_entity_reconnect(ue);
	return count;
}
UNET_ENTITY_ATTR_WO(reconnect);

static ssize_t unet_entity_reparent_store(struct unet_entity *ue,
		struct unet_entity_attribute *attr, const char *buf,
		size_t count)
{
	unet_entity_reparent(ue);
	return count;
}
UNET_ENTITY_ATTR_WO(reparent);

static ssize_t unet_entity_keys_verified_show(struct unet_entity *ue,
		struct unet_entity_attribute *attr, char *buf)
{
	if (ue->type != unet_entity_type_local)
		return -EINVAL;
	return sprintf(buf, "%u\n", ue->keys_verified ? 1 : 0);
}
UNET_ENTITY_ATTR_RO(keys_verified);

static ssize_t unet_entity_keys_trusted_show(struct unet_entity *ue,
		struct unet_entity_attribute *attr, char *buf)
{
	if (ue->type != unet_entity_type_local)
		return -EINVAL;
	return sprintf(buf, "%u\n", ue->keys_trusted ? 1 : 0);
}
UNET_ENTITY_ATTR_RO(keys_trusted);

static struct attribute *unet_local_entity_default_attrs[] = {
	&unet_entity_attr_refcount.attr,
	&unet_entity_attr_state.attr,
	&unet_entity_attr_type.attr,
	&unet_entity_attr_n_children.attr,
	&unet_entity_attr_n_routers.attr,
	&unet_entity_attr_ping.attr,
	&unet_entity_attr_sink.attr,
	&unet_entity_attr_set_parent.attr,
	&unet_entity_attr_apcr.attr,
	&unet_entity_attr_rfdr.attr,
	&unet_entity_attr_stop_apcr.attr,
	&unet_entity_attr_disconnect.attr,
	&unet_entity_attr_reconnect.attr,
	&unet_entity_attr_reparent.attr,
	&unet_entity_attr_keys_verified.attr,
	&unet_entity_attr_keys_trusted.attr,
	NULL
};

static struct attribute *unet_remote_entity_default_attrs[] = {
	&unet_entity_attr_refcount.attr,
	&unet_entity_attr_type.attr,
	&unet_entity_attr_n_children.attr,
	&unet_entity_attr_n_routers.attr,
	NULL
};

/* Our custom sysfs_ops that we will associate with our ktype later on */
const struct sysfs_ops unet_entity_sysfs_ops = {
	.show = unet_entity_attr_show,
	.store = unet_entity_attr_store,
};

struct kobj_type unet_local_entity_ktype = {
	.sysfs_ops = &unet_entity_sysfs_ops,
	.release = unet_entity_release,
	.default_attrs = unet_local_entity_default_attrs,
};

struct kobj_type unet_remote_entity_ktype = {
	.sysfs_ops = &unet_entity_sysfs_ops,
	.release = unet_entity_release,
	.default_attrs = unet_remote_entity_default_attrs,
};

static struct attribute *null_attrs[] = {
	NULL
};

static const struct attribute_group children_group = {
	.name = "children",
	.attrs = null_attrs,
};

static const struct attribute_group routers_group = {
	.name = "routers",
	.attrs = null_attrs,
};

int unet_entity_create_sysfs(struct unet_entity *ue)
{
	struct kset *kset;
	struct kobj_type *ktype;
	struct unet_addr *ua;
	char *str;
	int err;

	ua = unet_entity_addr(ue);

	/* make sure that the address property can be displayed */
	str = unet_addr_to_str(GFP_KERNEL, ua);
	if (!str)
		return -ENOMEM;

	if (ue->type == unet_entity_type_local) {
		kset = unet_local_entities_kset;
		ktype = &unet_local_entity_ktype;
	} else {
		kset = unet_remote_entities_kset;
		ktype = &unet_remote_entity_ktype;
	}

	ue->kobj.kset = kset;
	err = kobject_init_and_add(&ue->kobj, ktype, NULL, "%s", str);

	kfree(str);

	if (err)
		return err;

	/* create non-default attributes here */
	if (ue->type == unet_entity_type_local) {
		err = sysfs_create_group(&ue->kobj, &children_group);
		if (err)
			goto err_fail_children_group;

		err = sysfs_create_group(&ue->kobj, &routers_group);
		if (err)
			goto err_fail_routers_group;

		/* setup ksets for other objects that we're their parent */
		ue->conn_kset = kset_create_and_add("conn", NULL, &ue->kobj);
		if (!ue->conn_kset) {
			err = -ENOMEM;
			goto err_fail_conn_kset;
		}
	}

	return 0;

err_fail_conn_kset:
	sysfs_remove_group(&ue->kobj, &routers_group);
err_fail_routers_group:
	sysfs_remove_group(&ue->kobj, &children_group);
err_fail_children_group:
	/* nothing to do here */
	return err;
}

void unet_entity_destroy_sysfs(struct unet_entity *ue)
{
	if (ue->type == unet_entity_type_local) {
		/* remove ksets */
		kset_unregister(ue->conn_kset);

		/* remove non-default attributes here */
		sysfs_remove_group(&ue->kobj, &routers_group);
		sysfs_remove_group(&ue->kobj, &children_group);
	}
}

/* conn entry */
struct unet_conn_entry_attribute;

struct unet_conn_entry_attribute {
	struct attribute attr;
	ssize_t (*show)(struct unet_conn_entry *uce, struct unet_conn_entry_attribute *attr, char *buf);
	ssize_t (*store)(struct unet_conn_entry *uce, struct unet_conn_entry_attribute *attr, const char *buf, size_t count);
};
#define to_unet_conn_entry_attr(x) container_of(x, struct unet_conn_entry_attribute, attr)

#define UNET_CONN_ENTRY_ATTR(_name, _mode, _show, _store) \
	struct unet_conn_entry_attribute unet_conn_entry_attr_##_name = \
		__ATTR(_name, _mode, _show, _store)
#define UNET_CONN_ENTRY_ATTR_RW(_name) \
	struct unet_conn_entry_attribute unet_conn_entry_attr_##_name = \
		__ATTR(_name, (S_IWUSR | S_IRUGO), \
			unet_conn_entry_##_name##_show, unet_conn_entry_##_name##_store)
#define UNET_CONN_ENTRY_ATTR_RO(_name) \
	struct unet_conn_entry_attribute unet_conn_entry_attr_##_name = \
		__ATTR(_name, S_IRUGO, \
			unet_conn_entry_##_name##_show, NULL)
#define UNET_CONN_ENTRY_ATTR_WO(_name) \
	struct unet_conn_entry_attribute unet_conn_entry_attr_##_name = \
		__ATTR(_name, S_IWUSR, \
			NULL, unet_conn_entry_##_name##_store)

static ssize_t unet_conn_entry_attr_show(struct kobject *kobj,
			     struct attribute *attr,
			     char *buf)
{
	struct unet_conn_entry_attribute *attribute;
	struct unet_conn_entry *uce;

	attribute = to_unet_conn_entry_attr(attr);
	uce = to_unet_conn_entry(kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(uce, attribute, buf);
}

static ssize_t unet_conn_entry_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t len)
{
	struct unet_conn_entry_attribute *attribute;
	struct unet_conn_entry *uce;

	attribute = to_unet_conn_entry_attr(attr);
	uce = to_unet_conn_entry(kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(uce, attribute, buf, len);
}

static ssize_t unet_conn_entry_refcount_show(struct unet_conn_entry *uce,
		struct unet_conn_entry_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n",
			refcount_read(&uce->kobj.kref.refcount));
}
UNET_CONN_ENTRY_ATTR_RO(refcount);

static ssize_t unet_conn_entry_state_show(struct unet_conn_entry *uce,
		struct unet_conn_entry_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", unet_conn_entry_state_txt(uce->state));
}
UNET_CONN_ENTRY_ATTR_RO(state);

static ssize_t unet_conn_entry_type_show(struct unet_conn_entry *uce,
		struct unet_conn_entry_attribute *attr, char *buf)
{
	enum unet_conn_type type;

	type = unet_conn_state_to_type(uce->state);
	return sprintf(buf, "%s\n", unet_conn_entry_type_txt(type));
}
UNET_CONN_ENTRY_ATTR_RO(type);

static ssize_t unet_conn_entry_secure_show(struct unet_conn_entry *uce,
		struct unet_conn_entry_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", unet_conn_entry_is_secure(uce) ? 1 : 0);
}
UNET_CONN_ENTRY_ATTR_RO(secure);

static struct attribute *unet_conn_entry_default_attrs[] = {
	&unet_conn_entry_attr_refcount.attr,
	&unet_conn_entry_attr_state.attr,
	&unet_conn_entry_attr_type.attr,
	&unet_conn_entry_attr_secure.attr,
	NULL
};

/* Our custom sysfs_ops that we will associate with our ktype later on */
const struct sysfs_ops unet_conn_entry_sysfs_ops = {
	.show = unet_conn_entry_attr_show,
	.store = unet_conn_entry_attr_store,
};

struct kobj_type unet_conn_entry_ktype = {
	.sysfs_ops = &unet_conn_entry_sysfs_ops,
	.release = unet_conn_entry_release,
	.default_attrs = unet_conn_entry_default_attrs,
#if 0
	/* TODO namespace operations */
	.child_ns_type = ,
	.namespace = ,
#endif
};

int unet_conn_entry_create_sysfs(struct unet_entity *ue,
				 struct unet_conn_entry *uce)
{
	int err;

	uce->kobj.kset = ue->conn_kset;
	err = kobject_init_and_add(&uce->kobj, &unet_conn_entry_ktype,
			NULL, "%s", kobject_name(&uce->ue->kobj));
	if (WARN_ON(err))
		return err;

	err = sysfs_create_link_nowarn(&uce->kobj, &uce->ue->kobj, "entity");
	if (WARN_ON(err))
		return err;

	return 0;
}

void unet_conn_entry_destroy_sysfs(struct unet_conn_entry *uce)
{
	sysfs_remove_link(&uce->kobj, "entity");

	/* nothing */
}

void unet_entity_sysfs_set_parent(struct unet_entity *ue,
		struct unet_entity *ue_parent)
{
	int err;
	struct unet_conn_entry *uce;

	if (WARN_ON(!ue))
		return;

	if (!ue_parent)
		sysfs_remove_link(&ue->kobj, "parent");
	else {
		uce = unet_conn_entry_lookup(ue, ue_parent);
		if (WARN_ON(!uce))
			return;

		err = sysfs_create_link(&ue->kobj, &uce->kobj, "parent");
		WARN_ON(err);

		unet_conn_entry_put(uce);
	}
}

void unet_entity_sysfs_add_child(struct unet_entity *ue,
		struct unet_entity *child_ue)
{
	struct unet_conn_entry *uce;
	int err;

	if (WARN_ON(!ue))
		return;

	if (WARN_ON(!child_ue))
		return;

	uce = unet_conn_entry_lookup(ue, child_ue);
	if (WARN_ON(!uce))
		return;

	err = sysfs_add_link_to_group(&ue->kobj, "children",
			&uce->kobj, kobject_name(&child_ue->kobj));

	WARN_ON(err);

	unet_conn_entry_put(uce);
}

void unet_entity_sysfs_remove_child(struct unet_entity *ue,
		struct unet_entity *child_ue)
{
	if (WARN_ON(!ue))
		return;

	if (WARN_ON(!child_ue))
		return;

	sysfs_remove_link_from_group(&ue->kobj, "children",
			kobject_name(&child_ue->kobj));
}

void unet_entity_sysfs_add_router(struct unet_entity *ue,
		struct unet_entity *router_ue)
{
	int err;

	if (WARN_ON(!ue))
		return;

	if (WARN_ON(!router_ue))
		return;

	err = sysfs_add_link_to_group(&ue->kobj, "routers",
			&router_ue->kobj, kobject_name(&router_ue->kobj));
	WARN_ON(err);
}

void unet_entity_sysfs_remove_router(struct unet_entity *ue,
		struct unet_entity *router_ue)
{
	if (WARN_ON(!ue))
		return;

	if (WARN_ON(!router_ue))
		return;

	sysfs_remove_link_from_group(&ue->kobj, "routers",
			kobject_name(&router_ue->kobj));
}

void unet_entity_sysfs_set_registering_router(struct unet_entity *ue,
		struct unet_entity *ue_router)
{
	int err;

	if (WARN_ON(!ue))
		return;

	if (!ue_router)
		sysfs_remove_link(&ue->kobj, "registering-router");
	else {
		err = sysfs_create_link(&ue->kobj, &ue_router->kobj,
				"registering-router");
		WARN_ON(err);
	}
}

/* app entry */
struct unet_app_entry_attribute;

struct unet_app_entry_attribute {
	struct attribute attr;
	ssize_t (*show)(struct unet_app_entry *uae, struct unet_app_entry_attribute *attr, char *buf);
	ssize_t (*store)(struct unet_app_entry *uae, struct unet_app_entry_attribute *attr, const char *buf, size_t count);
};
#define to_unet_app_entry_attr(x) container_of(x, struct unet_app_entry_attribute, attr)

#define UNET_APP_ENTRY_ATTR(_name, _mode, _show, _store) \
	struct unet_app_entry_attribute unet_app_entry_attr_##_name = \
		__ATTR(_name, _mode, _show, _store)
#define UNET_APP_ENTRY_ATTR_RW(_name) \
	struct unet_app_entry_attribute unet_app_entry_attr_##_name = \
		__ATTR(_name, (S_IWUSR | S_IRUGO), \
			unet_app_entry_##_name##_show, unet_app_entry_##_name##_store)
#define UNET_APP_ENTRY_ATTR_RO(_name) \
	struct unet_app_entry_attribute unet_app_entry_attr_##_name = \
		__ATTR(_name, S_IRUGO, \
			unet_app_entry_##_name##_show, NULL)
#define UNET_APP_ENTRY_ATTR_WO(_name) \
	struct unet_app_entry_attribute unet_app_entry_attr_##_name = \
		__ATTR(_name, S_IWUSR, \
			NULL, unet_app_entry_##_name##_store)

static ssize_t unet_app_entry_attr_show(struct kobject *kobj,
			     struct attribute *attr,
			     char *buf)
{
	struct unet_app_entry_attribute *attribute;
	struct unet_app_entry *uae;

	attribute = to_unet_app_entry_attr(attr);
	uae = to_unet_app_entry(kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(uae, attribute, buf);
}

static ssize_t unet_app_entry_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t len)
{
	struct unet_app_entry_attribute *attribute;
	struct unet_app_entry *uae;

	attribute = to_unet_app_entry_attr(attr);
	uae = to_unet_app_entry(kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(uae, attribute, buf, len);
}

static ssize_t unet_app_entry_refcount_show(struct unet_app_entry *uae,
		struct unet_app_entry_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n",
			refcount_read(&uae->kobj.kref.refcount));
}
UNET_APP_ENTRY_ATTR_RO(refcount);

static struct attribute *unet_app_entry_default_attrs[] = {
	&unet_app_entry_attr_refcount.attr,
	NULL
};

const struct sysfs_ops unet_app_entry_sysfs_ops = {
	.show = unet_app_entry_attr_show,
	.store = unet_app_entry_attr_store,
};

struct kobj_type unet_app_entry_ktype = {
	.sysfs_ops = &unet_app_entry_sysfs_ops,
	.release = unet_app_entry_release,
	.default_attrs = unet_app_entry_default_attrs,
};

int unet_app_entry_create_sysfs(struct unet_app_entry *uae)
{
	struct unet_addr *ua;
	char *str;
	int err;

	if (!uae)
		return -EINVAL;

	ua = unet_app_entry_addr(uae);

	/* make sure that the address property can be displayed */
	str = unet_addr_to_str(GFP_KERNEL, ua);
	if (!str)
		return -ENOMEM;

	uae->kobj.kset = unet_app_entries_kset;
	err = kobject_init_and_add(&uae->kobj, &unet_app_entry_ktype,
				   NULL, "%s", str);
	kfree(str);

	return err;
}

void unet_app_entry_destroy_sysfs(struct unet_entity *uae)
{
}

static ssize_t common_dump_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf,
		size_t count, struct unet_net *un, size_t bp_offset)
{
	bool what;
	int err;

	if (!un)
		return -ENODEV;

	if (count < 1)
		return -EINVAL;

	err = kstrtobool(buf, &what);
	if (err)
		return err;

	*(bool *)((void *)un + bp_offset) = what;

	return count;
}

#define UNET_ATTR_SYSLOG_DUMP(_name) \
static ssize_t unet_syslog_##_name##_dump_store(struct kobject *kobj, \
		struct kobj_attribute *attr, const char *buf, \
		size_t count) \
{ \
	return common_dump_store(kobj, attr, buf, count, \
				 unet_net(&init_net), \
				 offsetof(struct unet_net, \
					  syslog_##_name##_dump)); \
} \
struct kobj_attribute unet_attr_syslog_##_name##_dump = \
	__ATTR_WO(unet_syslog_##_name##_dump);

UNET_ATTR_SYSLOG_DUMP(packet);
UNET_ATTR_SYSLOG_DUMP(fsm);
UNET_ATTR_SYSLOG_DUMP(conn);
UNET_ATTR_SYSLOG_DUMP(crypto);
UNET_ATTR_SYSLOG_DUMP(router);
UNET_ATTR_SYSLOG_DUMP(bearer);
UNET_ATTR_SYSLOG_DUMP(refcount);

static const struct attribute *unet_default_attrs[] = {
	&unet_attr_syslog_packet_dump.attr,
	&unet_attr_syslog_fsm_dump.attr,
	&unet_attr_syslog_conn_dump.attr,
	&unet_attr_syslog_crypto_dump.attr,
	&unet_attr_syslog_router_dump.attr,
	&unet_attr_syslog_bearer_dump.attr,
	&unet_attr_syslog_refcount_dump.attr,
	NULL
};

int unet_sysfs_setup(struct net *net)
{
	return 0;
}

void unet_sysfs_cleanup(struct net *net)
{
}

int unet_kobj_setup(void)
{
	int err;

	unet_kobj = kobject_create_and_add("unet", NULL);
	if (!unet_kobj)
		goto no_unet_kobj;

	unet_local_entities_kset = kset_create_and_add("local-entities", NULL, unet_kobj);
	if (!unet_local_entities_kset)
		goto no_local_kset;

	unet_remote_entities_kset = kset_create_and_add("remote-entities", NULL, unet_kobj);
	if (!unet_remote_entities_kset)
		goto no_remote_kset;

	unet_app_entries_kset = kset_create_and_add("app-entries", NULL, unet_kobj);
	if (!unet_app_entries_kset)
		goto no_app_kset;

	err = sysfs_create_files(unet_kobj, unet_default_attrs);
	if (err)
		goto no_sysfs_files;

	return 0;
no_sysfs_files:
	kset_unregister(unet_app_entries_kset);
no_app_kset:
	kset_unregister(unet_remote_entities_kset);
no_remote_kset:
	kset_unregister(unet_local_entities_kset);
no_local_kset:
	kobject_put(unet_kobj);
no_unet_kobj:
	return -ENOMEM;
}

void unet_kobj_cleanup(void)
{
	sysfs_remove_files(unet_kobj, unet_default_attrs);
	kset_unregister(unet_app_entries_kset);
	kset_unregister(unet_remote_entities_kset);
	kset_unregister(unet_local_entities_kset);
	kobject_put(unet_kobj);
}
