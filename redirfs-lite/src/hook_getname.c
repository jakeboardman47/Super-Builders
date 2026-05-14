// SPDX-License-Identifier: GPL-2.0
/*
 * Path redirection via kretprobe on getname_flags().
 *
 * getname_flags() copies a userspace pathname into kernel space and returns
 * a struct filename whose ->name field points at the resolved path string.
 * By replacing the returned filename with one we built via getname_kernel()
 * (which is sym-resolved at module load), the entire VFS lookup path that
 * follows operates on our redirected target. putname() balances the
 * reference the caller would otherwise leak.
 *
 * MVP scope: redirect only matching paths; per-UID/GID matched in
 * rfl_rule_lookup(). No write-side mutation; no syscall-direct fallback.
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include "redirfs.h"

static struct filename *(*p_getname_kernel)(const char *);
static void (*p_putname)(struct filename *);

static struct kretprobe krp_getname = {
	.kp.symbol_name = "getname_flags",
	.maxactive = 32,
};

static int gn_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct filename *old_fn, *new_fn;
	const struct rfl_rule *rule;
	const struct cred *cred;
	static DEFINE_RATELIMIT_STATE(rs, 5 * HZ, RFL_AUDIT_MAX);

	old_fn = (struct filename *)regs_return_value(regs);
	if (IS_ERR_OR_NULL(old_fn))
		return 0;
	if (!old_fn->name)
		return 0;

	cred = current_cred();
	rule = rfl_rule_lookup(old_fn->name, cred->fsuid, cred->fsgid);
	if (!rule)
		return 0;

	if (!p_getname_kernel || !p_putname)
		return 0;

	new_fn = p_getname_kernel(rule->dst);
	if (IS_ERR(new_fn))
		return 0;

	if (rfl_audit_enabled && __ratelimit(&rs))
		rfl_pr_info("redirect %s -> %s uid=%u pid=%d\n",
			    rule->src, rule->dst,
			    from_kuid(&init_user_ns, cred->fsuid),
			    current->pid);

	p_putname(old_fn);
	regs_set_return_value(regs, (unsigned long)new_fn);
	return 0;
}

int rfl_hook_getname_init(void)
{
	int ret;

	p_getname_kernel = rfl_sym("getname_kernel");
	p_putname        = rfl_sym("putname");

	if (!p_getname_kernel || !p_putname) {
		rfl_pr_err("symbols missing: getname_kernel=%px putname=%px\n",
			   p_getname_kernel, p_putname);
		return -ENOENT;
	}

	krp_getname.handler = gn_handler;
	ret = register_kretprobe(&krp_getname);
	if (ret < 0) {
		rfl_pr_err("register_kretprobe(getname_flags) failed (%d)\n", ret);
		return ret;
	}
	rfl_pr_info("hooked getname_flags via kretprobe\n");
	return 0;
}

void rfl_hook_getname_exit(void)
{
	unregister_kretprobe(&krp_getname);
	if (krp_getname.nmissed)
		rfl_pr_warn("kretprobe missed %u invocations\n",
			    krp_getname.nmissed);
}
