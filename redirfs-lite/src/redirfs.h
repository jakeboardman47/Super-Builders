/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _REDIRFS_H
#define _REDIRFS_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/uidgid.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#define RFL_NAME            "redirfs"
#define RFL_PROC_DIR        "redirfs"
#define RFL_PROC_RULES      "rules"
#define RFL_PATH_MAX        4096
#define RFL_RULE_BUCKETS    256
#define RFL_AUDIT_MAX       8

#define RFL_ID_ANY          ((u32)-1)

#define rfl_pr_info(fmt, ...)  pr_info(RFL_NAME ": " fmt, ##__VA_ARGS__)
#define rfl_pr_warn(fmt, ...)  pr_warn(RFL_NAME ": " fmt, ##__VA_ARGS__)
#define rfl_pr_err(fmt, ...)   pr_err(RFL_NAME ": " fmt, ##__VA_ARGS__)

struct rfl_rule {
	struct hlist_node node;
	struct rcu_head rcu;
	char *src;            /* virtual path apps see */
	char *dst;            /* real path on disk */
	size_t src_len;
	size_t dst_len;
	u32 uid;              /* RFL_ID_ANY for wildcard */
	u32 gid;              /* RFL_ID_ANY for wildcard */
	u64 hits;
};

int  rfl_rules_init(void);
void rfl_rules_exit(void);
const struct rfl_rule *rfl_rule_lookup(const char *path, kuid_t uid, kgid_t gid);
const struct rfl_rule *rfl_rule_lookup_by_dst(const char *path, kuid_t uid, kgid_t gid);
int  rfl_rule_add(const char *src, const char *dst, u32 uid, u32 gid);
int  rfl_rule_del(const char *src);
void rfl_rules_clear(void);
int  rfl_rules_seq_show(struct seq_file *m, void *v);

int  rfl_syms_init(void);
void *rfl_sym(const char *name);

int  rfl_hook_getname_init(void);
void rfl_hook_getname_exit(void);

int  rfl_hook_dpath_init(void);
void rfl_hook_dpath_exit(void);

int  rfl_proc_init(void);
void rfl_proc_exit(void);

extern bool rfl_audit_enabled;

#endif /* _REDIRFS_H */
