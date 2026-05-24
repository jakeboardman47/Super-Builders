// SPDX-License-Identifier: GPL-2.0
/*
 * SELinux policy-query hooks.
 *
 * Defeats Duck Detector's SelinuxProcAttrCurrentProbe and (partially)
 * SelinuxContextValidityProbe by:
 *
 *   1. kretprobe on selinux_setprocattr (LSM hook for /proc/PID/attr/* writes)
 *      - Args are KERNEL pointers (security_setprocattr already memdup_user'd).
 *      - At entry: filter by name=="current"; memcpy the value into our slot.
 *      - At return: if the stashed buffer matches a known root-tool context
 *        (u:r:ksu:s0, u:r:magisk:s0, ...), force the return value to -EINVAL.
 *        From the caller's POV, the context write failed exactly as it would
 *        on a clean kernel.
 *
 *      (The earlier plan to hook a fictitious "sel_write_current" was wrong;
 *      that symbol doesn't exist. The /proc/PID/attr/current write path goes
 *      through proc_pid_attr_write → security_setprocattr → selinux_setprocattr.)
 *
 *   2. kretprobe on sel_write_access
 *      - At entry, copy the user buffer (format: "<scon> <tcon>
 *        <tclass> <perm>") and stash.
 *      - At return, if the stashed query references a dirty type, we
 *        DON'T touch the return value of write() itself — it's just
 *        the byte count of the write. The access decision is read
 *        back via subsequent read() from the same fd. v1 covers
 *        write-side only; read-side scrubbing is phase 1b.
 *
 * Hook 1 reads kernel memory; hook 2's entry handler still uses
 * copy_from_user because sel_write_access takes a __user buffer directly.
 *
 * If hide_from_root is on, we skip the spoof when the caller is EUID 0 —
 * matches the redirfs-lite policy of "root sees real state".
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/sched.h>

#include "../redirfs.h"
#include "sel_dirty.h"

/* Module parameter: when true, leave root-owned writes alone. Mirrors the
 * redirfs-lite hide_from_root semantics. Default ON. */
static bool sel_hide_from_root = true;
module_param_named(sel_hide_from_root, sel_hide_from_root, bool, 0644);
MODULE_PARM_DESC(sel_hide_from_root,
	"Skip SELinux spoof for EUID=0 callers (default: true)");

/* Per-call context the entry handler stashes for the return handler. */
struct sel_ctx_slot {
	char buf[256];   /* SELinux contexts are short; ≥128 is plenty */
	size_t len;
	bool root_caller;
	bool is_current; /* selinux_setprocattr called with name="current" */
};

/* ------------------------------------------------------------------------
 * Hook 1: selinux_setprocattr — LSM hook for writes to /proc/<pid>/attr/*
 *
 * The kernel path: write() → proc_pid_attr_write → security_setprocattr →
 *   selinux_setprocattr(const char *name, void *value, size_t size).
 *
 * Note vs the earlier (broken) plan to hook a fictitious "sel_write_current":
 *   - name and value are KERNEL pointers; security_setprocattr already did
 *     memdup_user() on the user buffer, so we read directly with memcpy.
 *   - name == "current" is the path Duck Detector's probe hits. We also see
 *     exec/fscreate/keycreate/sockcreate/prev through this hook, but we only
 *     act on "current" to keep behaviour tight; widen later if needed.
 * ------------------------------------------------------------------------ */

static int selinux_setprocattr_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct sel_ctx_slot *ctx = (struct sel_ctx_slot *)ri->data;
	const char *name;
	const char *value;
	size_t sz;

#if defined(CONFIG_ARM64)
	/* arm64 AAPCS: x0=name, x1=value, x2=size — all KERNEL pointers */
	name  = (const char *)regs->regs[0];
	value = (const char *)regs->regs[1];
	sz    = (size_t)regs->regs[2];
#elif defined(CONFIG_X86_64)
	name  = (const char *)regs->di;
	value = (const char *)regs->si;
	sz    = (size_t)regs->dx;
#else
	name = value = NULL;
	sz = 0;
#endif

	ctx->root_caller = uid_eq(current_euid(), GLOBAL_ROOT_UID);
	ctx->len = 0;
	ctx->buf[0] = '\0';
	ctx->is_current = false;

	if (!name || strcmp(name, "current") != 0)
		return 0;
	ctx->is_current = true;

	if (!value || sz == 0 || sz >= sizeof(ctx->buf))
		return 0;

	memcpy(ctx->buf, value, sz);
	ctx->buf[sz] = '\0';
	ctx->len = sz;
	return 0;
}

static int selinux_setprocattr_ret(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct sel_ctx_slot *ctx = (struct sel_ctx_slot *)ri->data;
	long ret = (long)regs_return_value(regs);

	if (!ctx->is_current)
		return 0;

	/* Honour root-bypass policy */
	if (READ_ONCE(sel_hide_from_root) && ctx->root_caller)
		return 0;

	/* If the write succeeded AND the user wrote a dirty context, force
	 * the syscall to look like it would on a clean kernel (-EINVAL). */
	if (ret >= 0 && rff_sel_ctx_is_dirty(ctx->buf, ctx->len)) {
		regs_set_return_value(regs, (unsigned long)(long)-EINVAL);
		rff_subsys_set_hit(&rff_sel_subsys);
		rff_pr_info("setprocattr(current): masked dirty ctx (%zd→EINVAL)\n",
			    ret);
	}
	return 0;
}

static struct kretprobe krp_selinux_setprocattr = {
	.kp.symbol_name  = "selinux_setprocattr",
	.handler         = selinux_setprocattr_ret,
	.entry_handler   = selinux_setprocattr_entry,
	.data_size       = sizeof(struct sel_ctx_slot),
	.maxactive       = 16,
};

/* ------------------------------------------------------------------------
 * Hook 2: sel_write_access — writes to /sys/fs/selinux/access
 *
 * Phase 1a: detect-and-log only. We capture the query buffer at entry; if
 * it references a dirty type, we log it but do NOT spoof the result. The
 * actual AV decision lives in seq_file private state that subsequent
 * read() calls drain — defeating that requires a sibling kretprobe on the
 * read side. Deferred to phase 1b.
 * ------------------------------------------------------------------------ */

static int sel_write_access_entry(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct sel_ctx_slot *ctx = (struct sel_ctx_slot *)ri->data;
	const char __user *ubuf;
	size_t sz;

#if defined(CONFIG_ARM64)
	ubuf = (const char __user *)regs->regs[1];
	sz   = (size_t)regs->regs[2];
#elif defined(CONFIG_X86_64)
	ubuf = (const char __user *)regs->si;
	sz   = (size_t)regs->dx;
#else
	ubuf = NULL;
	sz = 0;
#endif

	ctx->root_caller = uid_eq(current_euid(), GLOBAL_ROOT_UID);
	ctx->len = 0;
	ctx->buf[0] = '\0';

	if (!ubuf || sz == 0 || sz >= sizeof(ctx->buf))
		return 0;
	if (!copy_from_user(ctx->buf, ubuf, sz)) {
		ctx->buf[sz] = '\0';
		ctx->len = sz;
	}
	return 0;
}

static int sel_write_access_ret(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct sel_ctx_slot *ctx = (struct sel_ctx_slot *)ri->data;

	if (READ_ONCE(sel_hide_from_root) && ctx->root_caller)
		return 0;

	if (ctx->len > 0 && rff_sel_ctx_contains_dirty_type(ctx->buf, ctx->len)) {
		rff_subsys_set_hit(&rff_sel_subsys);
		rff_pr_info("sel_write_access: dirty type observed (len=%zu) — read-side scrub pending\n",
			    ctx->len);
	}
	return 0;
}

static struct kretprobe krp_sel_write_access = {
	.kp.symbol_name  = "sel_write_access",
	.handler         = sel_write_access_ret,
	.entry_handler   = sel_write_access_entry,
	.data_size       = sizeof(struct sel_ctx_slot),
	.maxactive       = 16,
};

/* ------------------------------------------------------------------------
 * Subsystem registration
 * ------------------------------------------------------------------------ */

struct rff_subsys rff_sel_subsys = {
	.name        = "selpol",
	.init        = rff_sel_init,
	.exit        = rff_sel_exit,
	.enabled     = true,
	.initialized = false,
	.hits        = 0,
};

int rff_sel_init(void)
{
	int ret_access;
	int ret;

	ret = register_kretprobe(&krp_selinux_setprocattr);
	if (ret < 0) {
		rff_pr_err("selpol: register_kretprobe(selinux_setprocattr) failed (%d)\n",
			   ret);
		return ret;
	}

	ret_access = register_kretprobe(&krp_sel_write_access);
	if (ret_access < 0) {
		rff_pr_warn("selpol: register_kretprobe(sel_write_access) failed (%d) — "
			    "continuing without read-side hint\n", ret_access);
		/* not fatal */
	}

	rff_pr_info("selpol: armed (selinux_setprocattr%s)\n",
		    ret_access == 0 ? " + sel_write_access" : "");
	return 0;
}

void rff_sel_exit(void)
{
	unregister_kretprobe(&krp_sel_write_access);
	unregister_kretprobe(&krp_selinux_setprocattr);
	if (krp_selinux_setprocattr.nmissed || krp_sel_write_access.nmissed)
		rff_pr_warn("selpol: kretprobe missed counts: setprocattr=%u access=%u\n",
			    krp_selinux_setprocattr.nmissed,
			    krp_sel_write_access.nmissed);
}
