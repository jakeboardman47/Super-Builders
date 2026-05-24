/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _REDIRFS_FULL_H
#define _REDIRFS_FULL_H

#include <linux/types.h>
#include <linux/printk.h>
#include <linux/list.h>

#define RFF_NAME            "redirfs-full"
#define RFF_PROC_DIR        "redirfs"
#define RFF_PATH_MAX        4096

#define rff_pr_info(fmt, ...)  pr_info(RFF_NAME ": " fmt, ##__VA_ARGS__)
#define rff_pr_warn(fmt, ...)  pr_warn(RFF_NAME ": " fmt, ##__VA_ARGS__)
#define rff_pr_err(fmt, ...)   pr_err(RFF_NAME ": " fmt, ##__VA_ARGS__)

/* ---------------- subsystem registration --------------------------------
 * Each subsystem (sel, maps, smaps, fd, status, task, avc, ns, redir)
 * registers via rff_register_subsys() during module init. The registry
 * drives /proc/redirfs/config readback and per-subsystem enable toggles.
 */
struct rff_subsys {
	struct list_head node;
	const char *name;
	int  (*init)(void);
	void (*exit)(void);
	bool enabled;
	bool initialized;
	u64  hits;
};

int  rff_register_subsys(struct rff_subsys *s);
void rff_subsys_set_hit(struct rff_subsys *s);
bool rff_subsys_enabled(struct rff_subsys *s);

/* ---------------- symbol bootstrap --------------------------------------
 * Same kallsyms_lookup_name bootstrap pattern as redirfs-lite.
 */
int  rff_syms_init(void);
void *rff_sym(const char *name);

/* ---------------- proc control plane ------------------------------------ */
int  rff_proc_init(void);
void rff_proc_exit(void);

/* ---------------- selpol subsystem --------------------------------------
 * Hooks SELinux policy queries to mask known root-tool contexts and
 * "dirty rule" tuples added by KSU/Magisk/LSPosed/etc.
 */
extern struct rff_subsys rff_sel_subsys;
int  rff_sel_init(void);
void rff_sel_exit(void);

#endif /* _REDIRFS_FULL_H */
