// SPDX-License-Identifier: GPL-2.0
/*
 * Rule table: RCU-protected hash. Reads are lock-free; writes serialize on
 * rules_mutex. Lookup is by exact `src` path match against an FNV-1a hash.
 *
 * Per-rule UID/GID filter: RFL_ID_ANY matches any caller; otherwise must match
 * current_uid()/current_gid() exactly. (No range or set support in MVP.)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include "redirfs.h"

static DEFINE_HASHTABLE(rules_ht, 8); /* 256 buckets */
static DEFINE_MUTEX(rules_mutex);
static atomic_t rule_count = ATOMIC_INIT(0);

static u32 fnv1a(const char *s, size_t len)
{
	u32 h = 0x811c9dc5u;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= (unsigned char)s[i];
		h *= 0x01000193u;
	}
	return h;
}

static struct rfl_rule *rule_alloc(const char *src, const char *dst,
				   u32 uid, u32 gid)
{
	struct rfl_rule *r;
	size_t slen = strlen(src);
	size_t dlen = strlen(dst);

	if (slen == 0 || slen >= RFL_PATH_MAX ||
	    dlen == 0 || dlen >= RFL_PATH_MAX)
		return ERR_PTR(-EINVAL);
	if (src[0] != '/' || dst[0] != '/')
		return ERR_PTR(-EINVAL);

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);

	r->src = kmemdup_nul(src, slen, GFP_KERNEL);
	r->dst = kmemdup_nul(dst, dlen, GFP_KERNEL);
	if (!r->src || !r->dst) {
		kfree(r->src);
		kfree(r->dst);
		kfree(r);
		return ERR_PTR(-ENOMEM);
	}
	r->src_len = slen;
	r->dst_len = dlen;
	r->uid = uid;
	r->gid = gid;
	return r;
}

static void rule_free_rcu(struct rcu_head *head)
{
	struct rfl_rule *r = container_of(head, struct rfl_rule, rcu);

	kfree(r->src);
	kfree(r->dst);
	kfree(r);
}

const struct rfl_rule *rfl_rule_lookup(const char *path, kuid_t uid, kgid_t gid)
{
	struct rfl_rule *r;
	u32 key;
	size_t plen;
	u32 cuid = from_kuid(&init_user_ns, uid);
	u32 cgid = from_kgid(&init_user_ns, gid);

	if (!path)
		return NULL;
	plen = strnlen(path, RFL_PATH_MAX);
	if (plen == 0 || plen >= RFL_PATH_MAX)
		return NULL;

	key = fnv1a(path, plen);

	hash_for_each_possible_rcu(rules_ht, r, node, key) {
		if (r->src_len != plen)
			continue;
		if (memcmp(r->src, path, plen) != 0)
			continue;
		if (r->uid != RFL_ID_ANY && r->uid != cuid)
			continue;
		if (r->gid != RFL_ID_ANY && r->gid != cgid)
			continue;
		WRITE_ONCE(r->hits, READ_ONCE(r->hits) + 1);
		return r;
	}
	return NULL;
}

const struct rfl_rule *rfl_rule_lookup_by_dst(const char *path, kuid_t uid, kgid_t gid)
{
	struct rfl_rule *r;
	int bkt;
	size_t plen;
	u32 cuid = from_kuid(&init_user_ns, uid);
	u32 cgid = from_kgid(&init_user_ns, gid);

	if (!path)
		return NULL;
	plen = strnlen(path, RFL_PATH_MAX);
	if (plen == 0 || plen >= RFL_PATH_MAX)
		return NULL;

	hash_for_each_rcu(rules_ht, bkt, r, node) {
		if (r->dst_len != plen)
			continue;
		if (memcmp(r->dst, path, plen) != 0)
			continue;
		if (r->uid != RFL_ID_ANY && r->uid != cuid)
			continue;
		if (r->gid != RFL_ID_ANY && r->gid != cgid)
			continue;
		return r;
	}
	return NULL;
}

static struct rfl_rule *rule_find_locked(const char *src, u32 uid, u32 gid)
{
	struct rfl_rule *r;
	u32 key = fnv1a(src, strlen(src));
	size_t slen = strlen(src);

	hash_for_each_possible(rules_ht, r, node, key) {
		if (r->src_len == slen && memcmp(r->src, src, slen) == 0 &&
		    r->uid == uid && r->gid == gid)
			return r;
	}
	return NULL;
}

int rfl_rule_add(const char *src, const char *dst, u32 uid, u32 gid)
{
	struct rfl_rule *r, *existing;
	u32 key;

	r = rule_alloc(src, dst, uid, gid);
	if (IS_ERR(r))
		return PTR_ERR(r);

	mutex_lock(&rules_mutex);
	existing = rule_find_locked(src, uid, gid);
	if (existing) {
		hash_del_rcu(&existing->node);
		call_rcu(&existing->rcu, rule_free_rcu);
		atomic_dec(&rule_count);
	}
	key = fnv1a(src, strlen(src));
	hash_add_rcu(rules_ht, &r->node, key);
	atomic_inc(&rule_count);
	mutex_unlock(&rules_mutex);
	return 0;
}

int rfl_rule_del(const char *src)
{
	struct rfl_rule *r;
	u32 key = fnv1a(src, strlen(src));
	size_t slen = strlen(src);
	int removed = 0;
	struct hlist_node *tmp;

	mutex_lock(&rules_mutex);
	hash_for_each_possible_safe(rules_ht, r, tmp, node, key) {
		if (r->src_len == slen && memcmp(r->src, src, slen) == 0) {
			hash_del_rcu(&r->node);
			call_rcu(&r->rcu, rule_free_rcu);
			atomic_dec(&rule_count);
			removed++;
		}
	}
	mutex_unlock(&rules_mutex);
	return removed ? 0 : -ENOENT;
}

void rfl_rules_clear(void)
{
	struct rfl_rule *r;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&rules_mutex);
	hash_for_each_safe(rules_ht, bkt, tmp, r, node) {
		hash_del_rcu(&r->node);
		call_rcu(&r->rcu, rule_free_rcu);
		atomic_dec(&rule_count);
	}
	mutex_unlock(&rules_mutex);
}

int rfl_rules_seq_show(struct seq_file *m, void *v)
{
	struct rfl_rule *r;
	int bkt;

	seq_printf(m, "# redirfs-lite rules: %d entries\n",
		   atomic_read(&rule_count));
	seq_puts(m,   "# src dst uid gid hits\n");

	rcu_read_lock();
	hash_for_each_rcu(rules_ht, bkt, r, node) {
		seq_printf(m, "%s %s ", r->src, r->dst);
		if (r->uid == RFL_ID_ANY)
			seq_puts(m, "* ");
		else
			seq_printf(m, "%u ", r->uid);
		if (r->gid == RFL_ID_ANY)
			seq_puts(m, "* ");
		else
			seq_printf(m, "%u ", r->gid);
		seq_printf(m, "%llu\n", READ_ONCE(r->hits));
	}
	rcu_read_unlock();
	return 0;
}

int rfl_rules_init(void)
{
	hash_init(rules_ht);
	return 0;
}

void rfl_rules_exit(void)
{
	rfl_rules_clear();
	rcu_barrier();
}
