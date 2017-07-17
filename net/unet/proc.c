/*
 * net/unet/proc.c: uNet proc methods
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
#include "proc.h"
#include "utils.h"

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#ifdef CONFIG_PROC_FS

static void *unet_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct net *net = seq_file_net(seq);
	struct unet_net *un = net_generic(net, unet_net_id);
	struct unet_entity *ue;
	loff_t i;

	spin_lock(&un->entity_list_lock);

	if (!un)
		return NULL;

	if (!*pos)
		return SEQ_START_TOKEN;

	i = 1;
	list_for_each_entry(ue, &un->local_entity_list, node) {
		if (i++ == *pos)
			return ue;
	}

	return NULL;
}

static void *unet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct net *net = seq_file_net(seq);
	struct unet_net *un = net_generic(net, unet_net_id);
	struct unet_entity *ue;

	ue = v;
	if (ue == SEQ_START_TOKEN)
		ue = list_entry(un->local_entity_list.next, typeof(*ue), node);
	else
		ue = list_entry(ue->node.next, typeof(*ue), node);
	if (&ue->node == &un->local_entity_list)
		ue = NULL;
	++*pos;
	return ue;
}

static void unet_seq_stop(struct seq_file *seq, void *v)
{
	struct net *net = seq_file_net(seq);
	struct unet_net *un = net_generic(net, unet_net_id);

	spin_unlock(&un->entity_list_lock);
}

static int unet_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq_file_net(seq);
	struct unet_entity *ue;
	struct unet_addr *ua;
	char *str;

	(void)net;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "T Entity address\n");
	else {
		ue = v;

		switch (ue->type) {
		case unet_entity_type_local:
			seq_printf(seq, "L");
			break;
		case unet_entity_type_remote:
			seq_printf(seq, "R");
			break;
		}
		ua = unet_entity_addr(ue);
		str = unet_addr_to_str(GFP_KERNEL, ua);
		if (str)
			seq_puts(seq, str);
		kfree(str);
		rcu_read_unlock();
		seq_printf(seq, "\n");
	}

	return 0;
}

static const struct seq_operations unet_seq_ops = {
	.start  = unet_seq_start,
	.next   = unet_seq_next,
	.stop   = unet_seq_stop,
	.show   = unet_seq_show,
};

static int unet_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &unet_seq_ops,
			    sizeof(struct seq_net_private));
}

static const struct file_operations unet_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= unet_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
};

int unet_proc_create(struct net *net)
{
	if (!proc_create("unet", 0, net->proc_net, &unet_seq_fops)) {
		pr_err("%s: Failed to create /proc/net/unet\n", __func__);
		return -ENOMEM;
	}
	return 0;
}

void unet_proc_destroy(struct net *net)
{
	remove_proc_entry("unet", net->proc_net);
}
#endif
