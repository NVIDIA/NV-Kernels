/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AppArmor security module
 *
 * This file contains AppArmor ipc mediation function definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2017 Canonical Ltd.
 */

#ifndef __AA_IPC_H
#define __AA_IPC_H

#include <linux/msg.h>
#include <linux/sched.h>
#include "inode.h"
#include "perms.h"

struct aa_profile;

#define AA_PTRACE_TRACE		MAY_WRITE
#define AA_PTRACE_READ		MAY_READ
#define AA_MAY_BE_TRACED	AA_MAY_APPEND
#define AA_MAY_BE_READ		AA_MAY_CREATE
#define PTRACE_PERM_SHIFT	2

#define AA_PTRACE_PERM_MASK (AA_PTRACE_READ | AA_PTRACE_TRACE | \
			     AA_MAY_BE_READ | AA_MAY_BE_TRACED)
#define AA_SIGNAL_PERM_MASK (MAY_READ | MAY_WRITE)

#define AA_SFS_SIG_MASK "hup int quit ill trap abrt bus fpe kill usr1 " \
	"segv usr2 pipe alrm term stkflt chld cont stop stp ttin ttou urg " \
	"xcpu xfsz vtalrm prof winch io pwr sys emt lost"

int aa_may_ptrace(struct aa_label *tracer, struct aa_label *tracee,
		  u32 request);
int aa_may_signal(struct aa_label *sender, struct aa_label *target, int sig);

#define AA_AUDIT_POSIX_MQUEUE_MASK (AA_MAY_WRITE | AA_MAY_READ |    \
				    AA_MAY_CREATE | AA_MAY_DELETE | \
				    AA_MAY_OPEN | AA_MAY_SETATTR |  \
				    AA_MAY_GETATTR)


struct aa_msg_sec {
	struct aa_label *label;
};

struct aa_ipc_sec {
	struct aa_label *label;
};

static inline struct aa_ipc_sec *apparmor_ipc(const struct kern_ipc_perm *ipc)
{
	return ipc->security + apparmor_blob_sizes.lbs_ipc;
}

static inline struct aa_msg_sec *apparmor_msg_msg(const struct msg_msg *msg_msg)
{
	return msg_msg->security + apparmor_blob_sizes.lbs_msg_msg;
}


static inline bool is_mqueue_sb(struct super_block *sb)
{
	if (!sb)
		pr_warn("mqueue sb == NULL\n");
	if (!sb && !sb->s_type->name)
		pr_warn("mqueue sb name == NULL\n");
	return sb && sb->s_type->name && strcmp(sb->s_type->name, "mqueue") == 0;
}

static inline bool is_mqueue_inode(struct inode *i)
{
	struct aa_inode_sec *isec;

	if (!i)
		return false;

	isec = apparmor_inode(i);
	return isec && isec->sclass == AA_CLASS_POSIX_MQUEUE;
}

int aa_profile_mqueue_perm(struct aa_profile *profile,
			   const struct path *path,
			   u32 request, char *buffer,
			   struct common_audit_data *sa);

int aa_mqueue_perm(const char *op, struct aa_label *label,
		   const struct path *path, u32 request);

#endif /* __AA_IPC_H */
