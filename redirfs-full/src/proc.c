// SPDX-License-Identifier: GPL-2.0
/*
 * /proc/redirfs/ control plane for REDIRFS-Full.
 *
 *   /proc/redirfs/config     read: subsystem state table (name enabled hits)
 *                            write: "<name> on|off" — toggle a subsystem
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/version.h>
#include "redirfs.h"

extern struct list_head *rff_subsys_list_head(void);

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_config;

static int config_show(struct seq_file *m, void *v)
{
	struct list_head *head = rff_subsys_list_head();
	struct rff_subsys *s;

	seq_puts(m, "# redirfs-full subsystem registry\n");
	seq_puts(m, "# name      enabled  hits\n");
	list_for_each_entry(s, head, node) {
		seq_printf(m, "%-9s  %-7s  %llu\n",
			   s->name,
			   READ_ONCE(s->enabled) ? "on" : "off",
			   READ_ONCE(s->hits));
	}
	return 0;
}

static int config_open(struct inode *ino, struct file *f)
{
	return single_open(f, config_show, NULL);
}

static ssize_t config_write(struct file *f, const char __user *ubuf,
			    size_t len, loff_t *pos)
{
	char buf[64];
	char *name, *state;
	struct list_head *head;
	struct rff_subsys *s;
	bool want_enabled;
	size_t take;

	if (len == 0 || len > sizeof(buf) - 1)
		return -EINVAL;
	take = len;
	if (copy_from_user(buf, ubuf, take))
		return -EFAULT;
	buf[take] = '\0';
	/* trim trailing newline */
	while (take > 0 && (buf[take - 1] == '\n' || buf[take - 1] == ' '))
		buf[--take] = '\0';

	name = buf;
	state = strchr(buf, ' ');
	if (!state)
		return -EINVAL;
	*state++ = '\0';
	while (*state == ' ')
		state++;

	if (!strcmp(state, "on"))
		want_enabled = true;
	else if (!strcmp(state, "off"))
		want_enabled = false;
	else
		return -EINVAL;

	head = rff_subsys_list_head();
	list_for_each_entry(s, head, node) {
		if (strcmp(s->name, name) == 0) {
			WRITE_ONCE(s->enabled, want_enabled);
			rff_pr_info("config: %s = %s\n", name,
				    want_enabled ? "on" : "off");
			return (ssize_t)len;
		}
	}
	return -ENOENT;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops config_pops = {
	.proc_open    = config_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = config_write,
};
#define RFF_PROC_OPS &config_pops
#else
static const struct file_operations config_fops = {
	.owner   = THIS_MODULE,
	.open    = config_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = config_write,
};
#define RFF_PROC_OPS &config_fops
#endif

int rff_proc_init(void)
{
	/* Create /proc/redirfs if it doesn't already exist (redirfs-lite may
	 * have made it). Lookup-or-create semantics aren't directly exposed;
	 * proc_mkdir returns NULL if it exists, so we try and continue.
	 */
	proc_dir = proc_mkdir(RFF_PROC_DIR, NULL);
	/* If proc_mkdir returned NULL, the directory may pre-exist (lite is
	 * loaded). proc_create still works in that case using NULL parent
	 * with the same /proc path prefix won't — we need a real dir entry.
	 * Use proc_create within the dir we just made (if any). If lite owns
	 * the dir, our proc_create will fail; we then fall back to a flat
	 * name. */
	if (proc_dir) {
		proc_config = proc_create("config", 0600, proc_dir, RFF_PROC_OPS);
	} else {
		/* Fallback path /proc/redirfs_config */
		proc_config = proc_create("redirfs_config", 0600, NULL, RFF_PROC_OPS);
	}
	if (!proc_config) {
		if (proc_dir) {
			proc_remove(proc_dir);
			proc_dir = NULL;
		}
		return -ENOMEM;
	}
	return 0;
}

void rff_proc_exit(void)
{
	if (proc_config) {
		proc_remove(proc_config);
		proc_config = NULL;
	}
	if (proc_dir) {
		proc_remove(proc_dir);
		proc_dir = NULL;
	}
}
