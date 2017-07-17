/*
 * net/unet/configfs.c: uNet configfs methods
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
#include "configfs.h"
#include "utils.h"

#include <linux/module.h>
#include <linux/configfs.h>

#include <linux/key.h>
#include <crypto/public_key.h>
#include <keys/system_keyring.h>
#include <keys/asymmetric-type.h>

#ifdef CONFIG_CONFIGFS_FS

enum cfs_unet_item_kind {
	cfs_unet_item_kind_entity,
	cfs_unet_item_kind_app
};

/* same for entity config and app config */
struct cfs_unet_item {
	struct config_item	item;

	u8			prefix_len;
	u8			id_len;

	u8			prefix[256];
	u8			id[256];

	bool			enable;
	struct unet_entity_cfg	cfg;

	/* private keys do not have descriptions */
	char			*priv_key_name;

	enum cfs_unet_item_kind	kind;

	union {
		/* when enabled the entity is created */
		struct unet_entity	*entity;
		struct unet_app_entry	*app;
	};
};

static inline struct cfs_unet_item *to_cfs_unet_item(struct config_item *item)
{
	return item ? container_of(item, struct cfs_unet_item, item) : NULL;
}

static struct config_item *cfs_unet_common_group_make_item(
		struct config_group *group, const char *name,
		struct config_item_type *type,
		enum cfs_unet_item_kind kind);
static void cfs_unet_common_group_drop_item(struct config_group *group,
		struct config_item *item);

static ssize_t cfs_unet_item_enable_store(struct config_item *item,
		const char *page, size_t count)
{
	struct unet_net *un = unet_net(&init_net);	/* namespace? */
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	int err;
	bool new_enable;
	struct unet_entity *ue;
	struct unet_app_entry *uae;

	err = kstrtobool(page, &new_enable);
	if (err)
		return err;

	if (new_enable == ui->enable)
		return count;

	/* on enable */
	if (new_enable) {
		err = unet_addr_fill(&ui->cfg.ua,
				NULL, 0, NULL, 0,
				ui->prefix, ui->prefix_len,
				ui->id, ui->id_len);
		if (err)
			return err;

		/* must be valid and not have a parent */
		if (!unet_addr_is_valid(&ui->cfg.ua) ||
		    unet_addr_has_parent(&ui->cfg.ua))
			return -EINVAL;
	}

	err = 0;

	switch (ui->kind) {
	case cfs_unet_item_kind_entity:
		if (new_enable) {
			ue = unet_local_entity_create(un, &ui->cfg);
			if (!IS_ERR(ue))
				ui->entity = ue;
			else
				err = PTR_ERR(ue);
		} else {
			unet_entity_destroy(ui->entity);
			ui->entity = NULL;
		}
		break;
	case cfs_unet_item_kind_app:
		if (new_enable) {
			uae = unet_app_entry_create(un, &ui->cfg);
			if (!IS_ERR(uae))
				ui->app = uae;
			else
				err = PTR_ERR(uae);
		} else {
			unet_app_entry_destroy(ui->app);
			ui->app = NULL;
		}
		break;
	default:
		err = -EINVAL;
		break;
	}

	if (err)
		return err;

	ui->enable = new_enable;

	return count;
}

static ssize_t cfs_unet_item_enable_show(struct config_item *item,
		char *page)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return sprintf(page, "%s\n", ui->enable ? "yes" : "no");
}

static ssize_t cfs_unet_item_dev_class_store(struct config_item *item,
		const char *page, size_t count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	int err;
	unsigned int new_dev_class;

	if (ui->enable)
		return -EBUSY;

	err = kstrtouint(page, 10, &new_dev_class);
	if (err)
		return err;

	if (new_dev_class >= UNET_DEV_CLASS_MAX)
		return -EINVAL;

	ui->cfg.dev_class = new_dev_class;

	return count;
}

static ssize_t cfs_unet_item_dev_class_show(struct config_item *item,
		char *page)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return sprintf(page, "%u\n", ui->cfg.dev_class);
}

static ssize_t cfs_unet_item_can_be_router_store(struct config_item *item,
		const char *page, size_t count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	int err;
	bool new_can_be_router;

	if (ui->enable)
		return -EBUSY;

	err = kstrtobool(page, &new_can_be_router);
	if (err)
		return err;

	ui->cfg.can_be_router = new_can_be_router;
	return count;
}

static ssize_t cfs_unet_item_can_be_router_show(struct config_item *item,
		char *page)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return sprintf(page, "%s\n", ui->cfg.can_be_router ? "yes" : "no");
}

static ssize_t cfs_unet_item_force_parent_show(struct config_item *item,
		char *page)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	struct unet_addr *ua = &ui->cfg.force_parent_ua;
	char *str;
	ssize_t ret;

	if (ua->id_len == 0)
		return -EINVAL;

	str = unet_addr_to_str(GFP_KERNEL, &ui->cfg.force_parent_ua);
	if (!str)
		return -EINVAL;

	ret = snprintf(page, PAGE_SIZE, "%s\n", str);
	kfree(str);
	return ret;
}

static ssize_t cfs_unet_item_force_parent_store(struct config_item *item,
		const char *page, size_t count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	struct unet_addr *ua = &ui->cfg.force_parent_ua;
	int err;

	if (ui->enable)
		return -EBUSY;

	if (count > 0 && *page == '-') {
		memset(ua, 0, sizeof(*ua));
	} else {
		err = unet_str_to_addr(page, count, &ui->cfg.force_parent_ua);
		if (err)
			return err;
	}

	return count;
}

static ssize_t cfs_unet_item_forced_mtu_store(struct config_item *item,
		const char *page, size_t count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	int err;
	unsigned int new_forced_mtu;

	if (ui->enable)
		return -EBUSY;

	err = kstrtouint(page, 10, &new_forced_mtu);
	if (err)
		return err;

	ui->cfg.forced_mtu = new_forced_mtu;
	return count;
}

static ssize_t cfs_unet_item_forced_mtu_show(struct config_item *item,
		char *page)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return sprintf(page, "%u\n", ui->cfg.forced_mtu);
}

static ssize_t cfs_unet_item_devname_show(struct config_item *item,
		char *page)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return snprintf(page, PAGE_SIZE, "%s\n", ui->cfg.devname);
}

static ssize_t cfs_unet_item_devname_store(struct config_item *item,
		const char *page, size_t count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	size_t len;

	if (ui->enable)
		return -EBUSY;

	/* remove new lines */
	len = count;
	while (len > 0 && page[len-1] == '\n')
		len--;

	if (len >= sizeof(ui->cfg.devname) - 1)
		return -E2BIG;

	memcpy(ui->cfg.devname, page, len);
	ui->cfg.devname[len] = '\0';

	return count;
}


ssize_t cfs_unet_item_read_generic(struct config_item *item, void *buf,
		size_t max_count, u8 *where, u8 *where_len, int max_len)
{
	/* first read with buf zero is size probe */
	if (!buf)
		return *where_len;

	/* max_count can be 0 */
	if (*where_len > max_count)
		return -ENOSPC;

	memcpy(buf, where, *where_len);

	return *where_len;
}

ssize_t cfs_unet_item_write_generic(struct config_item *item, const void *buf,
		size_t count, u8 *where, u8 *where_len, int max_len)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	/* if the address is enabled, don't allow modification */
	if (ui->enable)
		return -EBUSY;

	/* check if too large */
	if (count > max_len)
		return -ENOSPC;

	memcpy(where, buf, count);
	*where_len = count;

	return count;
}

ssize_t cfs_unet_item_prefix_read(struct config_item *item, void *buf,
		size_t max_count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return cfs_unet_item_read_generic(item, buf, max_count,
			ui->prefix, &ui->prefix_len,
			ARRAY_SIZE(ui->prefix));
}

ssize_t cfs_unet_item_prefix_write(struct config_item *item, const void *buf,
		size_t count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return cfs_unet_item_write_generic(item, buf, count,
			ui->prefix, &ui->prefix_len,
			ARRAY_SIZE(ui->prefix));
}

ssize_t cfs_unet_item_id_read(struct config_item *item, void *buf,
		size_t max_count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return cfs_unet_item_read_generic(item, buf, max_count,
			ui->id, &ui->id_len,
			ARRAY_SIZE(ui->id));
}

ssize_t cfs_unet_item_id_write(struct config_item *item, const void *buf,
		size_t count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	return cfs_unet_item_write_generic(item, buf, count,
			ui->id, &ui->id_len,
			ARRAY_SIZE(ui->id));
}

/* verify that the keys are proper */
static int cfs_unet_item_verify_keys(struct cfs_unet_item *ui)
{
	struct unet_net *un = unet_net(&init_net);
	const union key_payload *payload;
	const struct public_key_signature *sig;
	struct key *k0, *k1;
	uint8_t nonce[32];
	struct kernel_pkey_params pkp;
	struct kernel_pkey_query pki;
	void *encbuf = NULL, *decbuf = NULL;
	int encsz, decsz;
	int i, err;

	/* assume that nothing is trusted/verified */
	ui->cfg.keys_verified = false;
	ui->cfg.keys_trusted = false;

	/* verify that it's signed properly (if there's a trust chain) */
	if (ui->cfg.cert_key && un->trust_chain[0]) {
		/* k1 is the entity key */
		k1 = key_ref_to_ptr(ui->cfg.cert_key);
		payload = &k1->payload;
		sig = payload->data[asym_auth];
		if (!sig->auth_ids[0] && !sig->auth_ids[1]) {
			pr_err("cert '%s' has no auth_id\n", k1->description);
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
			pr_info("cert '%s' fails verification\n",
					k1->description);
			goto out_fail;
		}

		/* key is trusted */
		ui->cfg.keys_trusted = true;
	}

	err = 0;

	if (ui->cfg.cert_key && ui->cfg.priv_key) {

		memset(&pkp, 0, sizeof(pkp));
		memset(&pki, 0, sizeof(pki));
		pkp.key = key_ref_to_ptr(ui->cfg.cert_key);
		pkp.encoding = "raw";
		err = query_asymmetric_key(&pkp, &pki);
		if (err) {
			pr_err("Can't query certificate\n");
			goto out_fail;
		}
		encsz = pki.max_enc_size;

		encbuf = kmalloc(encsz, GFP_KERNEL);
		if (!encbuf) {
			pr_err("Can't allocate encoding buffer of %d bytes\n",
				encsz);
			err = -ENOMEM;
			goto out_fail;
		}
		memset(encbuf, 0xaa, encsz);

		memset(&pkp, 0, sizeof(pkp));
		memset(&pki, 0, sizeof(pki));
		pkp.key = key_ref_to_ptr(ui->cfg.priv_key);
		pkp.encoding = "raw";
		err = query_asymmetric_key(&pkp, &pki);
		if (err) {
			pr_err("Can't query private key\n");
			goto out_fail;
		}
		decsz = pki.max_dec_size;

		decbuf = kmalloc(decsz, GFP_KERNEL);
		if (!decbuf) {
			pr_err("Can't allocate decoding buffer of %d bytes\n",
				decsz);
			err = -ENOMEM;
			goto out_fail;
		}
		memset(decbuf, 0x55, decsz);

		/* get a random nonce */
		get_random_bytes(nonce, sizeof(nonce));

		memset(&pkp, 0, sizeof(pkp));
		pkp.key = key_ref_to_ptr(ui->cfg.cert_key);
		pkp.encoding = "pkcs1";
		pkp.hash_algo = "sha256";
		pkp.in_len = sizeof(nonce);
		pkp.out_len = encsz;
		err = encrypt_blob(&pkp, nonce, encbuf);
		if (err < 0) {
			pr_err("Failed to encrypt\n");
			goto out_fail;
		}
		encsz = err;

		memset(&pkp, 0, sizeof(pkp));
		pkp.key = key_ref_to_ptr(ui->cfg.priv_key);
		pkp.encoding = "pkcs1";
		pkp.hash_algo = "sha256";
		pkp.in_len = encsz;
		pkp.out_len = decsz;
		err = decrypt_blob(&pkp, encbuf, decbuf);
		if (err < 0) {
			pr_err("Failed to decrypt\n");
			goto out_fail;
		}
		decsz = err;

		pr_debug("nonce %*phN\n", (int)sizeof(nonce), nonce);
		pr_debug("enc   %*phN\n", encsz, encbuf);
		pr_debug("dec   %*phN\n", decsz, decbuf);

		/* now test whether the results differ */
		if (decsz != sizeof(nonce) ||
			memcmp(nonce, decbuf, sizeof(nonce))) {

			pr_err("Private/public key mismatch\n");
			err = -EINVAL;
			goto out_fail;
		}
		err = 0;

		ui->cfg.keys_verified = true;
	}

out_fail:
	kfree(encbuf);
	kfree(decbuf);

	return err;
}

/* NOTE: you can't read the cert, only read it's description */
ssize_t cfs_unet_item_cert_read(struct config_item *item, void *buf,
		size_t max_count)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	const char *desc;

	/* if no key always return 0 */
	if (!ui->cfg.cert_key)
		return 0;

	desc = key_ref_to_ptr(ui->cfg.cert_key)->description;

	/* first read with buf zero is size probe */
	if (!buf)
		return strlen(desc) + 2;

	return scnprintf(buf, max_count, "%s\n", desc);
}

ssize_t cfs_unet_item_cert_write(struct config_item *item, const void *buf,
		size_t count)
{
	struct unet_net *un = unet_net(&init_net);
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	key_ref_t key = NULL, oldkey;
	void *blob = NULL;
	unsigned int blob_size = 0;
	struct kernel_pkey_params pkp;
	struct kernel_pkey_query pki;
	char *desc;
	int err;

	if (ui->enable)
		return -EBUSY;

	/* remove key? */
	if (count == 1 && *(char *)buf == '-')
		goto store_key;

	blob = kmemdup(buf, count, GFP_KERNEL);
	if (!blob) {
		pr_err("Failed to allocate cert memory\n");
		err = -ENOMEM;
		goto out_fail;
	}
	blob_size = count;

	key = key_create_or_update(make_key_ref(un->config_keys, 1),
					"asymmetric", NULL, blob, blob_size,
					((KEY_POS_ALL & ~KEY_POS_SETATTR) |
					KEY_USR_VIEW | KEY_USR_READ),
					KEY_ALLOC_NOT_IN_QUOTA |
					KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		pr_err("Failed to load X.509 certificate (%d)\n",
				err);
		goto out_fail;
	}

	/* verify that it does support encryption */
	memset(&pkp, 0, sizeof(pkp));
	memset(&pki, 0, sizeof(pki));
	pkp.key = key_ref_to_ptr(key);
	pkp.encoding = "raw";
	err = query_asymmetric_key(&pkp, &pki);
	if (err) {
		pr_err("Can't query certificate '%s' (%d)\n",
				desc, err);
		goto out_fail;
	}
	/* we have to support those to work */
	if (!(pki.supported_ops & (KEYCTL_SUPPORTS_ENCRYPT |
					KEYCTL_SUPPORTS_VERIFY))) {
		pr_err("certificate '%s' does not support encrypt/verify\n",
				desc);
		err = -EINVAL;
		goto out_fail;
	}

	pr_info("Loaded X.509 cert '%s'\n",
		key_ref_to_ptr(key)->description);

store_key:
	/* release the previous key (work on NULL too) */
	oldkey = ui->cfg.cert_key;
	ui->cfg.cert_key = key;

	err = cfs_unet_item_verify_keys(ui);
	if (err) {
		ui->cfg.cert_key = oldkey;
		goto out_fail;
	}
	kfree(ui->cfg.cert_blob);
	ui->cfg.cert_blob = blob;
	ui->cfg.cert_blob_size = blob_size;

	key_ref_put(oldkey);

	return count;

out_fail:
	key_ref_put(key);
	kfree(blob);
	return err;
}

ssize_t cfs_unet_item_privkey_write(struct config_item *item, const void *buf,
		size_t count)
{
	struct unet_net *un = unet_net(&init_net);
	struct cfs_unet_item *ui = to_cfs_unet_item(item);
	char *desc;
	key_ref_t key = NULL, oldkey;
	char *priv_key_name = NULL;
	struct kernel_pkey_params pkp;
	struct kernel_pkey_query pki;
	int err;

	if (ui->enable)
		return -EBUSY;

	/* remove key? */
	if (count == 1 && *(char *)buf == '-')
		goto store_key;

	priv_key_name = kasprintf(GFP_KERNEL, "unet-%s", item->ci_name);
	if (!priv_key_name) {
		err = -ENOMEM;
		goto out_fail;
	}

	key = key_create_or_update(make_key_ref(un->config_keys, 1),
					"asymmetric", priv_key_name,
					buf, count,
					((KEY_POS_ALL & ~KEY_POS_SETATTR) |
					KEY_USR_VIEW),
					KEY_ALLOC_NOT_IN_QUOTA |
					KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		pr_err("Failed to load private key (%d)\n", err);
		goto out_fail;
	}
	desc = key_ref_to_ptr(key)->description;

	/* verify that it does support decryption */
	memset(&pkp, 0, sizeof(pkp));
	memset(&pki, 0, sizeof(pki));
	pkp.key = key_ref_to_ptr(key);
	pkp.encoding = "raw";
	err = query_asymmetric_key(&pkp, &pki);
	if (err) {
		pr_err("Can't query certificate '%s' (%d)\n",
				desc, err);
		key_ref_put(key);
		return err;
	}
	/* we have to support those to work */
	if (!(pki.supported_ops & (KEYCTL_SUPPORTS_DECRYPT |
					KEYCTL_SUPPORTS_SIGN))) {
		pr_err("key '%s' does not support decrypt/sign\n",
				desc);
		err = -EINVAL;
		goto out_fail;
	}

	pr_info("Loaded private key '%s'\n", desc);

store_key:
	/* release the previous key (work on NULL too) */
	oldkey = ui->cfg.priv_key;
	ui->cfg.priv_key = key;

	err = cfs_unet_item_verify_keys(ui);
	if (err) {
		ui->cfg.priv_key = oldkey;
		goto out_fail;
	}

	key_ref_put(oldkey);
	kfree(ui->priv_key_name);

	ui->priv_key_name = priv_key_name;

	return count;

out_fail:
	kfree(priv_key_name);
	key_ref_put(key);
	return err;
}

CONFIGFS_ATTR(cfs_unet_item_, enable);
CONFIGFS_ATTR(cfs_unet_item_, dev_class);
CONFIGFS_ATTR(cfs_unet_item_, can_be_router);
CONFIGFS_ATTR(cfs_unet_item_, force_parent);
CONFIGFS_ATTR(cfs_unet_item_, forced_mtu);
CONFIGFS_ATTR(cfs_unet_item_, devname);

static struct configfs_attribute *cfs_unet_entities_item_attrs[] = {
	&cfs_unet_item_attr_enable,
	&cfs_unet_item_attr_dev_class,
	&cfs_unet_item_attr_can_be_router,
	&cfs_unet_item_attr_force_parent,
	&cfs_unet_item_attr_forced_mtu,
	&cfs_unet_item_attr_devname,
	NULL,
};

CONFIGFS_BIN_ATTR(cfs_unet_item_, prefix, NULL, 256);
CONFIGFS_BIN_ATTR(cfs_unet_item_, id, NULL, 256);
CONFIGFS_BIN_ATTR(cfs_unet_item_, cert, NULL, SZ_64K);
CONFIGFS_BIN_ATTR_WO(cfs_unet_item_, privkey, NULL, SZ_64K);

static struct configfs_bin_attribute *cfs_unet_entities_item_bin_attrs[] = {
	&cfs_unet_item_attr_prefix,
	&cfs_unet_item_attr_id,
	&cfs_unet_item_attr_cert,
	&cfs_unet_item_attr_privkey,
	NULL,
};

static void cfs_unet_release(struct config_item *item)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	kfree(ui);
}

static struct configfs_item_operations cfs_unet_entities_item_ops = {
	.release		= cfs_unet_release,
};

static struct config_item_type cfs_unet_entities_type = {
	.ct_item_ops	= &cfs_unet_entities_item_ops,
	.ct_attrs	= cfs_unet_entities_item_attrs,
	.ct_bin_attrs	= cfs_unet_entities_item_bin_attrs,
	.ct_owner	= THIS_MODULE,
};

struct config_group unet_cfs_entities_group;

static struct config_item *cfs_unet_entities_group_make_item(
		struct config_group *group, const char *name)
{
	return cfs_unet_common_group_make_item(group, name,
					       &cfs_unet_entities_type,
					       cfs_unet_item_kind_entity);
}

static void cfs_unet_entities_group_drop_item(struct config_group *group,
		struct config_item *item)
{
	cfs_unet_common_group_drop_item(group, item);
}

static struct configfs_group_operations unet_entities_group_ops = {
	.make_item	= cfs_unet_entities_group_make_item,
	.drop_item	= cfs_unet_entities_group_drop_item,
};

static struct config_item_type unet_entities_type = {
	.ct_group_ops   = &unet_entities_group_ops,
	.ct_owner       = THIS_MODULE,
};

static struct configfs_attribute *cfs_unet_apps_item_attrs[] = {
	&cfs_unet_item_attr_enable,
	NULL,
};

static struct configfs_bin_attribute *cfs_unet_apps_item_bin_attrs[] = {
	&cfs_unet_item_attr_prefix,
	&cfs_unet_item_attr_id,
	&cfs_unet_item_attr_cert,
	&cfs_unet_item_attr_privkey,
	NULL,
};

static struct configfs_item_operations cfs_unet_apps_item_ops = {
	.release		= cfs_unet_release,
};

static struct config_item_type cfs_unet_apps_type = {
	.ct_item_ops	= &cfs_unet_apps_item_ops,
	.ct_attrs	= cfs_unet_apps_item_attrs,
	.ct_bin_attrs	= cfs_unet_apps_item_bin_attrs,
	.ct_owner	= THIS_MODULE,
};

struct config_group unet_cfs_apps_group;

static struct config_item *cfs_unet_apps_group_make_item(
		struct config_group *group, const char *name)
{
	return cfs_unet_common_group_make_item(group, name,
					       &cfs_unet_apps_type,
					       cfs_unet_item_kind_app);
}

static void cfs_unet_apps_group_drop_item(struct config_group *group,
		struct config_item *item)
{
	cfs_unet_common_group_drop_item(group, item);
}

static struct configfs_group_operations unet_apps_group_ops = {
	.make_item	= cfs_unet_apps_group_make_item,
	.drop_item	= cfs_unet_apps_group_drop_item,
};

static struct config_item_type unet_apps_type = {
	.ct_group_ops   = &unet_apps_group_ops,
	.ct_owner       = THIS_MODULE,
};

static struct config_item *cfs_unet_common_group_make_item(
		struct config_group *group, const char *name,
		struct config_item_type *type,
		enum cfs_unet_item_kind kind)
{
	struct cfs_unet_item *ui;
	struct unet_addr *ua;

	ui = kzalloc(sizeof(*ui), GFP_KERNEL);
	if (!ui)
		return ERR_PTR(-ENOMEM);

	ui->kind = kind;

	config_item_init_type_name(&ui->item, name, type);

	/* try to make an address out of the name */
	ua = &ui->cfg.ua;
	if (unet_str_to_addr(name, -1, ua) || unet_addr_has_parent(ua)) {
		/* couldn't do it, no worries */
		memset(ua, 0, sizeof(*ua));
	} else {
		/* nice, a name, just fill it in */
		ui->prefix_len = ua->prefix_len;
		memcpy(ui->prefix, unet_addr_prefix(ua), ui->prefix_len);
		ui->id_len = ua->id_len;
		memcpy(ui->id, unet_addr_id(ua), ui->id_len);
	}

	switch (kind) {
	case cfs_unet_item_kind_entity:
		/* default is Linux box */
		ui->cfg.dev_class = UNET_DEV_CLASS_LINUX_BOX;
		/* can be router by default */
		ui->cfg.can_be_router = true;
		break;
	case cfs_unet_item_kind_app:
		/* nothing */
		break;
	}

	return &ui->item;
}

static void cfs_unet_common_group_drop_item(struct config_group *group,
		struct config_item *item)
{
	struct cfs_unet_item *ui = to_cfs_unet_item(item);

	switch (ui->kind) {
	case cfs_unet_item_kind_entity:
		if (ui->entity) {
			unet_entity_destroy(ui->entity);
			ui->entity = NULL;
		}
		break;
	case cfs_unet_item_kind_app:
		if (ui->app) {
			unet_app_entry_destroy(ui->app);
			ui->app = NULL;
		}
		break;
	}

	kfree(ui->priv_key_name);
	kfree(ui->cfg.cert_blob);
	key_ref_put(ui->cfg.cert_key);
	key_ref_put(ui->cfg.priv_key);

	config_item_put(&ui->item);
}


/* global configuration */
static ssize_t cfs_unet_common_uint_store(struct config_item *item,
		const char *page, size_t count, unsigned int *valp)
{
	int err;
	unsigned int new_val;

	err = kstrtouint(page, 10, &new_val);
	if (err)
		return err;
	*valp = new_val;
	return count;
}

static ssize_t cfs_unet_common_uint_show(struct config_item *item,
		char *page, unsigned int *valp)
{
	return sprintf(page, "%u\n", *valp);
}

static ssize_t cfs_unet_common_bool_store(struct config_item *item,
		const char *page, size_t count, bool *valp)
{
	int err;
	bool new_val;

	if (count < 1)
		return -EINVAL;

	err = kstrtobool(page, &new_val);
	if (err)
		return err;
	*valp = new_val;
	return count;
}

static ssize_t cfs_unet_common_bool_show(struct config_item *item,
		char *page, bool *valp)
{
	return sprintf(page, "%u\n", *valp ? 1 : 0);
}

/* convenience macro for root attributes */
#define UNET_DECLARE_UINT_RW_ATTR(_n) \
static ssize_t cfs_unet_ ## _n ## _store(struct config_item *item, \
		const char *page, size_t count) \
{ \
	struct unet_net *un = unet_net(&init_net);	/* TODO namespace? */ \
	if (!un) \
		return -EINVAL; \
	return cfs_unet_common_uint_store(item, page, count, &un-> _n ); \
} \
static ssize_t cfs_unet_ ## _n ## _show(struct config_item *item, \
		char *page) \
{ \
	struct unet_net *un = unet_net(&init_net);	/* TODO namespace? */ \
	if (!un) \
		return -EINVAL; \
	return cfs_unet_common_uint_show(item, page, &un-> _n ); \
} \
CONFIGFS_ATTR(cfs_unet_, _n )

#define UNET_DECLARE_BOOL_RW_ATTR(_n) \
static ssize_t cfs_unet_ ## _n ## _store(struct config_item *item, \
		const char *page, size_t count) \
{ \
	struct unet_net *un = unet_net(&init_net);	/* TODO namespace? */ \
	if (!un) \
		return -EINVAL; \
	return cfs_unet_common_bool_store(item, page, count, &un-> _n ); \
} \
static ssize_t cfs_unet_ ## _n ## _show(struct config_item *item, \
		char *page) \
{ \
	struct unet_net *un = unet_net(&init_net);	/* TODO namespace? */ \
	if (!un) \
		return -EINVAL; \
	return cfs_unet_common_bool_show(item, page, &un-> _n ); \
} \
CONFIGFS_ATTR(cfs_unet_, _n )

UNET_DECLARE_UINT_RW_ATTR(alive_timeout);
UNET_DECLARE_UINT_RW_ATTR(apcr_min_timeout);
UNET_DECLARE_UINT_RW_ATTR(apcr_max_timeout);
UNET_DECLARE_UINT_RW_ATTR(apcr_timeout);
UNET_DECLARE_UINT_RW_ATTR(apca_timeout);
UNET_DECLARE_UINT_RW_ATTR(register_timeout);
UNET_DECLARE_UINT_RW_ATTR(register_retries);
UNET_DECLARE_UINT_RW_ATTR(reject_backoff);
UNET_DECLARE_BOOL_RW_ATTR(random_score_policy);
UNET_DECLARE_BOOL_RW_ATTR(children_count_policy);
UNET_DECLARE_BOOL_RW_ATTR(only_forward_from_valid_senders);
UNET_DECLARE_BOOL_RW_ATTR(relay_disconnect_announce_upstream);
UNET_DECLARE_BOOL_RW_ATTR(try_reconnect_to_children);
UNET_DECLARE_BOOL_RW_ATTR(force_relay_rfdr_upstream);
UNET_DECLARE_BOOL_RW_ATTR(force_relay_da_upstream);
UNET_DECLARE_BOOL_RW_ATTR(strict_hierarchical_routing);
UNET_DECLARE_UINT_RW_ATTR(housekeeping_timeout);
UNET_DECLARE_UINT_RW_ATTR(child_idle_timeout);
UNET_DECLARE_UINT_RW_ATTR(child_to_be_timeout);
UNET_DECLARE_UINT_RW_ATTR(keepalive_max);
UNET_DECLARE_UINT_RW_ATTR(keepalive_period);

static struct configfs_attribute *cfs_unet_attrs[] = {
	&cfs_unet_attr_alive_timeout,
	&cfs_unet_attr_apcr_min_timeout,
	&cfs_unet_attr_apcr_max_timeout,
	&cfs_unet_attr_apcr_timeout,
	&cfs_unet_attr_apca_timeout,
	&cfs_unet_attr_register_timeout,
	&cfs_unet_attr_register_retries,
	&cfs_unet_attr_reject_backoff,
	&cfs_unet_attr_random_score_policy,
	&cfs_unet_attr_children_count_policy,
	&cfs_unet_attr_only_forward_from_valid_senders,
	&cfs_unet_attr_relay_disconnect_announce_upstream,
	&cfs_unet_attr_try_reconnect_to_children,
	&cfs_unet_attr_force_relay_rfdr_upstream,
	&cfs_unet_attr_force_relay_da_upstream,
	&cfs_unet_attr_strict_hierarchical_routing,
	&cfs_unet_attr_housekeeping_timeout,
	&cfs_unet_attr_child_idle_timeout,
	&cfs_unet_attr_child_to_be_timeout,
	&cfs_unet_attr_keepalive_max,
	&cfs_unet_attr_keepalive_period,
	NULL,
};

/* NOTE: you can't read the cert, only read it's description */
ssize_t cfs_unet_trust_chain_read(struct config_item *item, void *buf,
		size_t max_count)
{
	struct unet_net *un = unet_net(&init_net);	/* TODO namespace? */
	key_ref_t key;
	void *s, *e;
	char *desc;
	int i;
	ssize_t count;

	if (buf) {
		s = buf;
		e = s + max_count;
	} else {
		s = NULL;
		e = NULL;
	}

	count = 0;
	for (i = 0; i < ARRAY_SIZE(un->trust_chain); i++) {
		key = un->trust_chain[i];
		if (!key)
			break;
		desc = key_ref_to_ptr(key)->description;
		count += strlen(desc) + 1;
		if (s)
			s += scnprintf(s, e - s, "%s\n", desc);
	}
	if (!buf)
		return count + 1;

	return s - buf;
}

static void purge_trust_chain_certs(struct unet_net *un)
{
	int i;
	key_ref_t key;

	/* remove in opposite order */
	for (i = ARRAY_SIZE(un->trust_chain) - 1; i >= 0; i--) {
		key = un->trust_chain[i];
		if (!key)
			continue;
		key_ref_put(key);
		un->trust_chain[i] = NULL;
	}
}

ssize_t cfs_unet_trust_chain_write(struct config_item *item, const void *buf,
		size_t count)
{
	struct unet_net *un = unet_net(&init_net);	/* TODO namespace? */
	key_ref_t key;
	struct key *k0, *k1;
	const u8 *p, *end;
	size_t plen;
	int err, i;
	const union key_payload *payload;
	const struct public_key_signature *sig;
	struct kernel_pkey_params pkp;
	struct kernel_pkey_query pki;
	char *desc;

	purge_trust_chain_certs(un);

	/* remove previous short */
	if (count == 1 && *(char *)buf == '-')
		return count;

	pr_notice("Loading uNet trust-chain certificates\n");

	p = buf;
	end = p + count;
	i = 0;
	while (p < end && i < ARRAY_SIZE(un->trust_chain)) {
		/* Each cert begins with an ASN.1 SEQUENCE tag and must be more
		 * than 256 bytes in size.
		 */
		if (end - p < 4 || (p[0] != 0x30 && p[1] != 0x82)) {
			err = -EINVAL;
			goto fail_cert;
		}
		plen = (p[2] << 8) | p[3];
		plen += 4;
		if (plen > end - p) {
			err = -EINVAL;
			goto fail_cert;
		}

		key = key_create_or_update(make_key_ref(un->config_keys, 1),
					   "asymmetric", NULL, p, plen,
					   ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
					   KEY_USR_VIEW | KEY_USR_READ),
					   KEY_ALLOC_NOT_IN_QUOTA |
					   KEY_ALLOC_BYPASS_RESTRICTION);
		if (IS_ERR(key)) {
			err = PTR_ERR(key);
			pr_err("Problem loading trust chain X.509 certificate #%d (%ld)\n",
			       i, PTR_ERR(key));
			goto fail_cert;
		}
		desc = key_ref_to_ptr(key)->description;

		/* verify that it does support verify */
		memset(&pkp, 0, sizeof(pkp));
		memset(&pki, 0, sizeof(pki));
		pkp.key = key_ref_to_ptr(key);
		pkp.encoding = "raw";
		err = query_asymmetric_key(&pkp, &pki);
		if (err) {
			pr_err("Can't query certificate #%d '%s' (%d)\n",
				       i, desc, err);
			key_ref_put(key);
			goto fail_cert;
		}
		/* we have to support those to work */
		if (!(pki.supported_ops & (KEYCTL_SUPPORTS_ENCRYPT |
					   KEYCTL_SUPPORTS_VERIFY))) {
			pr_err("certificate '%s' does not support encrypt/verify\n",
				       desc);
			key_ref_put(key);
			err = -EINVAL;
			goto fail_cert;
		}

		pr_notice("Loaded X.509 cert #%d '%s'\n", i, desc);
		un->trust_chain[i++] = key;

		p += plen;
	}
	pr_notice("Trust chain contains #%d keys - verifying trust.\n", i);

	/* note trust walking work backwards */
	while (i >= 2) {
		k0 = key_ref_to_ptr(un->trust_chain[i - 1]);
		k1 = key_ref_to_ptr(un->trust_chain[i - 2]);

		payload = &k1->payload;
		sig = payload->data[asym_auth];
		if (!sig->auth_ids[0] && !sig->auth_ids[1]) {
			pr_err("cert '%s' has no auth_id\n", k1->description);
			goto fail_cert;
		}

		err = verify_signature(k0, sig);
		if (err) {
			pr_err("cert '%s' (#%d) failed to verify against '%s' (#%d)\n",
					k1->description, i - 2,
					k0->description, i - 1);
			goto fail_cert;
		}
		pr_info("cert '%s' (#%d) verifies against '%s' (#%d)\n",
				k1->description, i - 2,
				k0->description, i - 1);
		i--;
	}

	return count;

fail_cert:
	purge_trust_chain_certs(un);
	return err;
}

CONFIGFS_BIN_ATTR(cfs_unet_, trust_chain, NULL, SZ_256K);

static struct configfs_bin_attribute *cfs_unet_bin_attrs[] = {
	&cfs_unet_attr_trust_chain,
	NULL,
};

static struct configfs_group_operations unet_cfs_ops = {
	/* empty - we don't allow anything to be created */
};

static struct config_item_type unet_cfs_type = {
	.ct_group_ops   = &unet_cfs_ops,
	.ct_attrs	= cfs_unet_attrs,
	.ct_bin_attrs	= cfs_unet_bin_attrs,
	.ct_owner       = THIS_MODULE,
};

static struct configfs_subsystem unet_cfs_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "unet",
			.ci_type = &unet_cfs_type,
		},
	},
	.su_mutex = __MUTEX_INITIALIZER(unet_cfs_subsys.su_mutex),
};

int unet_configfs_create(struct net *net)
{
	config_group_init(&unet_cfs_subsys.su_group);

	config_group_init_type_name(&unet_cfs_entities_group, "entities",
			&unet_entities_type);
	configfs_add_default_group(&unet_cfs_entities_group,
		&unet_cfs_subsys.su_group);

	config_group_init_type_name(&unet_cfs_apps_group, "apps",
			&unet_apps_type);
	configfs_add_default_group(&unet_cfs_apps_group,
		&unet_cfs_subsys.su_group);

	return configfs_register_subsystem(&unet_cfs_subsys);
}

void unet_configfs_destroy(struct net *net)
{
	/* nothing for now */
}

#endif
