// SPDX-License-Identifier: GPL-2.0
/*
 * Subsystem registry: each detection-counter subsystem (selpol, maps,
 * smaps, fd, status, task, avc, ns, redir) registers a struct rff_subsys.
 * The registry drives /proc/redirfs/config readback.
 */

#include <linux/list.h>
#include <linux/mutex.h>
#include "redirfs.h"

static LIST_HEAD(subsys_list);
static DEFINE_MUTEX(subsys_mutex);

int rff_register_subsys(struct rff_subsys *s)
{
	if (!s || !s->name)
		return -EINVAL;
	mutex_lock(&subsys_mutex);
	list_add_tail(&s->node, &subsys_list);
	mutex_unlock(&subsys_mutex);
	return 0;
}

void rff_subsys_set_hit(struct rff_subsys *s)
{
	if (s)
		WRITE_ONCE(s->hits, READ_ONCE(s->hits) + 1);
}

bool rff_subsys_enabled(struct rff_subsys *s)
{
	return s && READ_ONCE(s->enabled);
}

/* Used by proc.c to iterate. */
struct list_head *rff_subsys_list_head(void)
{
	return &subsys_list;
}
