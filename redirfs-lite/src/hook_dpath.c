// SPDX-License-Identifier: GPL-2.0
/*
 * d_path spoofing — rewrite the path string written by d_path()/__d_path()
 * so /proc/PID/fd/N symlinks and /proc/PID/maps entries for a redirected
 * file show the virtual src path, not the real dst path.
 *
 * d_path() takes a {dentry,vfsmount} pair and writes the resolved path into
 * a caller-provided buffer, returning a pointer into that buffer. We hook
 * the return: if the buffer contains a path matching any rule's `dst`, we
 * overwrite it with the rule's `src`.
 *
 * Caveats:
 *   - We can't grow the buffer; if src is longer than dst, we leave the
 *     real path visible. (Pick src <= dst length when possible.)
 *   - This hook fires on every d_path call in the kernel; we keep it cheap
 *     by rejecting non-matches with a single hash lookup.
 *   - dentry_path_raw() and d_absolute_path() are sister functions; for full
 *     coverage we'd hook them too. MVP covers d_path only.
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/string.h>
#include "redirfs.h"

struct dp_ctx {
	char __user *ubuf;  /* unused: we never copy_to_user here */
	char *kbuf;
	int  buflen;
};

static struct kretprobe krp_dpath = {
	.kp.symbol_name = "d_path",
	.data_size = sizeof(struct dp_ctx),
	.maxactive = 32,
};

static int dp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dp_ctx *ctx = (struct dp_ctx *)ri->data;

#if defined(CONFIG_ARM64)
	/* arm64 calling convention: x0=path, x1=buf, x2=buflen */
	ctx->kbuf   = (char *)regs->regs[1];
	ctx->buflen = (int)regs->regs[2];
#elif defined(CONFIG_X86_64)
	ctx->kbuf   = (char *)regs->si;
	ctx->buflen = (int)regs->dx;
#else
	ctx->kbuf = NULL;
	ctx->buflen = 0;
#endif
	return 0;
}

static int dp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dp_ctx *ctx = (struct dp_ctx *)ri->data;
	char *ret_path = (char *)regs_return_value(regs);
	const struct rfl_rule *rule;
	const struct cred *cred;
	size_t plen, srclen;

	if (IS_ERR_OR_NULL(ret_path) || !ctx->kbuf || ctx->buflen <= 0)
		return 0;
	/* d_path's return pointer must lie within the caller's buffer */
	if (ret_path < ctx->kbuf || ret_path >= ctx->kbuf + ctx->buflen)
		return 0;

	plen = strnlen(ret_path, ctx->buflen - (ret_path - ctx->kbuf));
	if (plen == 0)
		return 0;

	cred = current_cred();
	/* Reverse-lookup: the buffer contains a real `dst`; find a rule whose
	 * dst matches. We piggyback on rfl_rule_lookup with a manual scan
	 * because the hash is keyed on src, not dst. For MVP we walk linearly
	 * via the rcu hash iteration helpers in rules.c. Cheaper alternative:
	 * maintain a second hash keyed on dst. Deferred.
	 */
	rule = rfl_rule_lookup_by_dst(ret_path, cred->fsuid, cred->fsgid);
	if (!rule)
		return 0;
	if (rule->src_len > plen)
		return 0;  /* won't fit without growing; skip */

	srclen = rule->src_len;
	memcpy(ret_path, rule->src, srclen);
	if (srclen < plen)
		ret_path[srclen] = '\0';
	return 0;
}

int rfl_hook_dpath_init(void)
{
	int ret;

	krp_dpath.entry_handler = dp_entry;
	krp_dpath.handler = dp_ret;
	ret = register_kretprobe(&krp_dpath);
	if (ret < 0) {
		rfl_pr_warn("register_kretprobe(d_path) failed (%d) — "
			    "d_path spoofing disabled\n", ret);
		return ret;
	}
	rfl_pr_info("hooked d_path via kretprobe\n");
	return 0;
}

void rfl_hook_dpath_exit(void)
{
	unregister_kretprobe(&krp_dpath);
}
