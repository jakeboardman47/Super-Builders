// SPDX-License-Identifier: GPL-2.0
/*
 * REDIRFS-Full: comprehensive kprobe-based hiding LKM.
 *
 * Phase 1 of the staged rollout — selpol subsystem only.
 * Subsequent phases add maps/smaps/fd/status/task/avc/ns/redir subsystems.
 */

#include <linux/module.h>
#include <linux/init.h>
#include "redirfs.h"

static int __init rff_init(void)
{
	int ret;

	rff_pr_info("loading v0.1.0-phase1 (selpol)\n");

	ret = rff_syms_init();
	if (ret)
		return ret;

	ret = rff_proc_init();
	if (ret)
		goto fail_proc;

	/* Register subsystems before init so /proc/redirfs/config reads
	 * see them even on partial-init failure. */
	rff_register_subsys(&rff_sel_subsys);

	ret = rff_sel_init();
	if (ret)
		goto fail_sel;
	rff_sel_subsys.initialized = true;

	rff_pr_info("loaded\n");
	return 0;

fail_sel:
	rff_proc_exit();
fail_proc:
	return ret;
}

static void __exit rff_exit(void)
{
	if (rff_sel_subsys.initialized)
		rff_sel_exit();
	rff_proc_exit();
	rff_pr_info("unloaded\n");
}

module_init(rff_init);
module_exit(rff_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("redirfs-full contributors");
MODULE_DESCRIPTION("kprobe-based hiding LKM (Phase 1: SELinux policy queries)");
MODULE_VERSION("0.1.0-phase1");
