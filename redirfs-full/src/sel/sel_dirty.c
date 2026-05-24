// SPDX-License-Identifier: GPL-2.0
/*
 * Dirty-context / dirty-rule classification helpers.
 */

#include <linux/string.h>
#include "../redirfs.h"
#include "sel_dirty.h"

/* Build the static tables from the X-macro lists. */
#define X(s) { s, sizeof(s) - 1 },
static const struct rff_sel_ctx dirty_contexts[] = {
	RFF_DIRTY_CTX_LIST
};
#undef X
static const size_t dirty_contexts_count =
	sizeof(dirty_contexts) / sizeof(dirty_contexts[0]);

/* Type substrings — the part between the second and third ':' in
 * "u:r:<TYPE>:s0". Used for substring scan in sel_write_access query
 * buffers which contain raw context strings.
 *
 * Pre-computed at compile time via a second X-macro pass that strips the
 * "u:r:" prefix and ":s0" suffix. Simpler: just match the type token
 * surrounded by ':' delimiters.
 */
static const char * const dirty_types[] = {
	"ksu",
	"ksu_file",
	"magisk",
	"magisk_file",
	"lsposed_file",
	"droidspacesd",
	"msd_app",
	"msd_daemon",
	"xposed_data",
	"adbroot",
	"adb_data_file",
};
static const size_t dirty_types_count =
	sizeof(dirty_types) / sizeof(dirty_types[0]);

bool rff_sel_ctx_is_dirty(const char *buf, size_t len)
{
	size_t i;

	if (!buf || len == 0)
		return false;

	/* Strip trailing newline / nul if present. */
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\0' ||
			   buf[len - 1] == ' '))
		len--;

	for (i = 0; i < dirty_contexts_count; i++) {
		if (dirty_contexts[i].len == len &&
		    memcmp(dirty_contexts[i].str, buf, len) == 0)
			return true;
	}
	return false;
}

bool rff_sel_ctx_contains_dirty_type(const char *buf, size_t len)
{
	size_t i, tlen;

	if (!buf || len == 0)
		return false;

	for (i = 0; i < dirty_types_count; i++) {
		const char *t = dirty_types[i];
		tlen = strlen(t);
		/* Look for ":<type>:" or ":<type>\0" or ":<type> " — type
		 * surrounded by ':' on the left and either ':' or end on
		 * right, so substrings of longer identifiers don't match.
		 */
		const char *p = buf;
		const char *end = buf + len;
		while (p + tlen + 1 <= end) {
			const char *colon = memchr(p, ':', end - p);
			if (!colon || colon + 1 + tlen > end)
				break;
			if (memcmp(colon + 1, t, tlen) == 0) {
				char after = (colon + 1 + tlen < end)
					? *(colon + 1 + tlen) : '\0';
				if (after == ':' || after == ' ' ||
				    after == '\0' || after == '\n')
					return true;
			}
			p = colon + 1;
		}
	}
	return false;
}
