// SPDX-License-Identifier: GPL-2.0
/*
 * SELinux policy-query hooks.
 *
 * Defeats Duck Detector's SelinuxProcAttrCurrentProbe and (partially)
 * SelinuxContextValidityProbe by:
 *
 *   1. kretprobe on sel_write_current
 *      - At entry, copy the user buffer into a per-instance slot.
 *      - At return, if the stashed buffer matches a known root-tool
 *        context (u:r:ksu:s0, u:r:magisk:s0, ...), force the return
 *        value to -EINVAL. From the caller's POV, the context lookup
 *        failed the same way it would on a clean kernel.
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
 * The hook entry-handler reads userspace memory. This is safe from a
 * kretprobe because:
 *   - kprobes run in the calling task's context (write syscall path).
 *   - The userspace page is paged in (the caller just wrote it).
 *   - copy_from_user is the canonical primitive; works under kprobe.
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
};

/* ------------------------------------------------------------------------
 * Hook 1: sel_write_current — writes to /proc/<pid>/attr/{current,exec,...}
 * ------------------------------------------------------------------------ */

static int sel_write_current_entry(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct sel_ctx_slot *ctx = (struct sel_ctx_slot *)ri->data;
	const char __user *ubuf;
	size_t sz;

#if defined(CONFIG_ARM64)
	/* sel_write_current(struct file *, const char __user *, size_t, loff_t *)
	 * arm64: x0=file, x1=buf, x2=size */
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

static int sel_write_current_ret(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct sel_ctx_slot *ctx = (struct sel_ctx_slot *)ri->data;
	long ret = (long)regs_return_value(regs);

	/* Honour root-bypass policy */
	if (READ_ONCE(sel_hide_from_root) && ctx->root_caller)
		return 0;

	/* If the write succeeded AND the user wrote a dirty context, force
	 * the syscall to look like it would on a clean kernel (-EINVAL). */
	if (ret >= 0 && rff_sel_ctx_is_dirty(ctx->buf, ctx->len)) {
		regs_set_return_value(regs, (unsigned long)(long)-EINVAL);
		rff_subsys_set_hit(&rff_sel_subsys);
		rff_pr_info("sel_write_current: masked dirty context (%zd→EINVAL)\n",
			    ret);
	}
	return 0;
}

static struct kretprobe krp_sel_write_current = {
	.kp.symbol_name  = "sel_write_current",
	.handler         = sel_write_current_ret,
	.entry_handler   = sel_write_current_entry,
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
	int ret;

	ret = register_kretprobe(&krp_sel_write_current);
	if (ret < 0) {
		rff_pr_err("selpol: register_kretprobe(sel_write_current) failed (%d)\n",
			   ret);
		return ret;
	}

	ret = register_kretprobe(&krp_sel_write_access);
	if (ret < 0) {
		rff_pr_warn("selpol: register_kretprobe(sel_write_access) failed (%d) — "
			    "continuing without read-side hint\n", ret);
		/* not fatal */
	}

	rff_pr_info("selpol: armed (sel_write_current%s)\n",
		    ret == 0 ? " + sel_write_access" : "");
	return 0;
}

void rff_sel_exit(void)
{
	unregister_kretprobe(&krp_sel_write_access);
	unregister_kretprobe(&krp_sel_write_current);
	if (krp_sel_write_current.nmissed || krp_sel_write_access.nmissed)
		rff_pr_warn("selpol: kretprobe missed counts: current=%u access=%u\n",
			    krp_sel_write_current.nmissed,
			    krp_sel_write_access.nmissed);
}
