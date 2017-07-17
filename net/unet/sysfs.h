/*
 * net/unet/sysfs.h: uNet sysfs/kobj declarations
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

#ifndef _UNET_SYSFS_H
#define _UNET_SYSFS_H

#include <linux/net_namespace.h>
#include <linux/kobject.h>
#include <linux/kobject_ns.h>
#include <linux/sysfs.h>

struct unet_entity;
struct unet_conn_entry;

/* root unet kobject */
extern struct kobject *unet_kobj;

extern struct kset *unet_local_entities_kset;
extern struct kset *unet_remote_entities_kset;

extern const struct sysfs_ops unet_entity_sysfs_ops;
extern struct kobj_type unet_entity_ktype;

int unet_sysfs_setup(struct net *net);
void unet_sysfs_cleanup(struct net *net);
int unet_kobj_setup(void);
void unet_kobj_cleanup(void);

int unet_entity_create_sysfs(struct unet_entity *ue);
void unet_entity_destroy_sysfs(struct unet_entity *ue);
void unet_entity_sysfs_set_parent(struct unet_entity *ue,
		struct unet_entity *ue_parent);
void unet_entity_sysfs_add_child(struct unet_entity *ue,
		struct unet_entity *parent_ue);
void unet_entity_sysfs_remove_child(struct unet_entity *ue,
		struct unet_entity *parent_ue);
void unet_entity_sysfs_add_router(struct unet_entity *ue,
		struct unet_entity *ue_router);
void unet_entity_sysfs_remove_router(struct unet_entity *ue,
		struct unet_entity *ue_router);
void unet_entity_sysfs_set_registering_router(struct unet_entity *ue,
		struct unet_entity *ue_router);

/* conn entries */
int unet_conn_entry_create_sysfs(struct unet_entity *ue,
				 struct unet_conn_entry *uce);
void unet_conn_entry_destroy_sysfs(struct unet_conn_entry *uce);

/* app */
int unet_app_entry_create_sysfs(struct unet_app_entry *uae);
void unet_app_entry_destroy_sysfs(struct unet_app_entry *uae);

#endif
