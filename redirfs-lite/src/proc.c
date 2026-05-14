// SPDX-License-Identifier: GPL-2.0
/*
 * /proc/redirfs/rules — text control plane.
 *
 * Read: tabular dump of all rules (src dst uid gid hits).
 *
 * Write: line-oriented command grammar.
 *   add <src> <dst> [uid|*] [gid|*]   — install or replace a rule
 *   del <src>                          — remove all rules matching src
 *   clear                              — drop every rule
 *   audit on|off                       — toggle dmesg audit
 *
 * One command per line. Blank lines and lines starting with '#' ignored.
 * Atomic update model: each line takes effect immediately under rules_mutex.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include "redirfs.h"

bool rfl_audit_enabled = true;

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_rules;

static int rules_show(struct seq_file *m, void *v)
{
	return rfl_rules_seq_show(m, v);
}

static int rules_open(struct inode *ino, struct file *f)
{
	return single_open(f, rules_show, NULL);
}

static int parse_id(const char *tok, u32 *out)
{
	unsigned long v;

	if (!tok || !*tok)
		return -EINVAL;
	if (tok[0] == '*' && tok[1] == '\0') {
		*out = RFL_ID_ANY;
		return 0;
	}
	if (kstrtoul(tok, 10, &v) < 0)
		return -EINVAL;
	if (v >= RFL_ID_ANY)
		return -EINVAL;
	*out = (u32)v;
	return 0;
}

/* Mutates `line` in place (strsep). */
static int handle_line(char *line)
{
	char *p = line, *cmd, *a1, *a2, *a3, *a4;
	u32 uid = RFL_ID_ANY, gid = RFL_ID_ANY;

	while (*p && isspace(*p))
		p++;
	if (*p == '\0' || *p == '#')
		return 0;

	cmd = strsep(&p, " \t");
	if (!cmd)
		return -EINVAL;

	if (!strcmp(cmd, "add")) {
		a1 = strsep(&p, " \t");  /* src */
		a2 = strsep(&p, " \t");  /* dst */
		a3 = strsep(&p, " \t");  /* uid (optional) */
		a4 = strsep(&p, " \t");  /* gid (optional) */
		if (!a1 || !a2)
			return -EINVAL;
		if (a3 && parse_id(a3, &uid) < 0)
			return -EINVAL;
		if (a4 && parse_id(a4, &gid) < 0)
			return -EINVAL;
		return rfl_rule_add(a1, a2, uid, gid);
	}
	if (!strcmp(cmd, "del")) {
		a1 = strsep(&p, " \t");
		if (!a1)
			return -EINVAL;
		return rfl_rule_del(a1);
	}
	if (!strcmp(cmd, "clear")) {
		rfl_rules_clear();
		return 0;
	}
	if (!strcmp(cmd, "audit")) {
		a1 = strsep(&p, " \t");
		if (!a1)
			return -EINVAL;
		if (!strcmp(a1, "on"))
			WRITE_ONCE(rfl_audit_enabled, true);
		else if (!strcmp(a1, "off"))
			WRITE_ONCE(rfl_audit_enabled, false);
		else
			return -EINVAL;
		return 0;
	}
	return -EINVAL;
}

static ssize_t rules_write(struct file *f, const char __user *ubuf,
			   size_t len, loff_t *pos)
{
	char *buf, *line, *next;
	int ret = 0;

	if (len == 0 || len > 64 * 1024)
		return -EINVAL;
	buf = kmalloc(len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	if (copy_from_user(buf, ubuf, len)) {
		kfree(buf);
		return -EFAULT;
	}
	buf[len] = '\0';

	next = buf;
	while ((line = strsep(&next, "\n")) != NULL) {
		int r = handle_line(line);

		if (r < 0) {
			ret = r;
			break;
		}
	}
	kfree(buf);
	return ret < 0 ? ret : (ssize_t)len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops rules_pops = {
	.proc_open    = rules_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = rules_write,
};
#define RFL_PROC_OPS &rules_pops
#else
static const struct file_operations rules_fops = {
	.owner   = THIS_MODULE,
	.open    = rules_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = rules_write,
};
#define RFL_PROC_OPS &rules_fops
#endif

int rfl_proc_init(void)
{
	proc_dir = proc_mkdir(RFL_PROC_DIR, NULL);
	if (!proc_dir)
		return -ENOMEM;
	proc_rules = proc_create(RFL_PROC_RULES, 0600, proc_dir, RFL_PROC_OPS);
	if (!proc_rules) {
		proc_remove(proc_dir);
		proc_dir = NULL;
		return -ENOMEM;
	}
	return 0;
}

void rfl_proc_exit(void)
{
	if (proc_rules) {
		proc_remove(proc_rules);
		proc_rules = NULL;
	}
	if (proc_dir) {
		proc_remove(proc_dir);
		proc_dir = NULL;
	}
}
