// SPDX-License-Identifier: GPL-2.0
/*
 * redirfs-lite: kprobe-based VFS path redirection.
 *
 * Load order:
 *   1. resolve kallsyms_lookup_name via single bootstrap kprobe
 *   2. init rule table (RCU hash)
 *   3. install /proc/redirfs/rules control plane
 *   4. install getname_flags kretprobe (path redirection)
 *   5. install d_path kretprobe (best-effort spoof)
 *
 * Unload reverses in strict opposite order; rcu_barrier() drains pending
 * rule frees before module text vanishes.
 */

#include <linux/module.h>
#include <linux/init.h>
#include "redirfs.h"

static int __init rfl_init(void)
{
	int ret;

	rfl_pr_info("loading (built %s %s)\n", __DATE__, __TIME__);

	ret = rfl_syms_init();
	if (ret)
		return ret;

	ret = rfl_rules_init();
	if (ret)
		return ret;

	ret = rfl_proc_init();
	if (ret)
		goto fail_proc;

	ret = rfl_hook_getname_init();
	if (ret)
		goto fail_getname;

	/* d_path hook is best-effort: failing to register downgrades to
	 * "redirect without spoof" rather than failing the whole module. */
	(void)rfl_hook_dpath_init();

	rfl_pr_info("loaded\n");
	return 0;

fail_getname:
	rfl_proc_exit();
fail_proc:
	rfl_rules_exit();
	return ret;
}

static void __exit rfl_exit(void)
{
	rfl_hook_dpath_exit();
	rfl_hook_getname_exit();
	rfl_proc_exit();
	rfl_rules_exit();
	rfl_pr_info("unloaded\n");
}

module_init(rfl_init);
module_exit(rfl_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("redirfs-lite contributors");
MODULE_DESCRIPTION("kprobe-based VFS path redirection (loadable, no kernel rebuild)");
MODULE_VERSION("0.1.0-mvp");
