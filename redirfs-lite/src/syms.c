// SPDX-License-Identifier: GPL-2.0
/*
 * Bootstrap kallsyms_lookup_name() via a single kprobe.
 *
 * Since 5.7, kallsyms_lookup_name() is no longer EXPORT_SYMBOL'd, but
 * registering a kprobe on it gives us kp.addr — that IS the function's
 * address. Unregister immediately; we never want the probe to fire.
 *
 * Once we have kallsyms_lookup_name, every other symbol resolves through it.
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include "redirfs.h"

static unsigned long (*kallsyms_lookup_name_p)(const char *name);

int rfl_syms_init(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		rfl_pr_err("kprobe on kallsyms_lookup_name failed (%d)\n", ret);
		return ret;
	}

	kallsyms_lookup_name_p =
		(unsigned long (*)(const char *))kp.addr;
	unregister_kprobe(&kp);

	if (!kallsyms_lookup_name_p) {
		rfl_pr_err("kallsyms_lookup_name address NULL\n");
		return -ENOENT;
	}

	rfl_pr_info("kallsyms_lookup_name @ %px\n", kallsyms_lookup_name_p);
	return 0;
}

void *rfl_sym(const char *name)
{
	unsigned long addr;

	if (!kallsyms_lookup_name_p)
		return NULL;
	addr = kallsyms_lookup_name_p(name);
	return (void *)addr;
}
