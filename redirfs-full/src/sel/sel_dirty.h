/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RFF_SEL_DIRTY_H
#define _RFF_SEL_DIRTY_H

/*
 * Static knowledge of which SELinux contexts and access-vector tuples are
 * fingerprints of root tools. Built from inspecting Duck Detector's
 * SelinuxProcAttrCurrentProbe + SelinuxContextValidityProbe targets
 * (eltavine/Duck-Detector-Refactoring, May 2026).
 */

/* --- Contexts that Duck Detector probes via /proc/self/attr/current ----- */
struct rff_sel_ctx {
	const char *str;
	size_t len;
};

/* "u:r:<TYPE>:s0" — the actual contexts added by root tools. */
#define RFF_DIRTY_CTX_LIST                                                    \
	X("u:r:ksu:s0")               /* KernelSU domain */                   \
	X("u:r:ksu_file:s0")          /* KernelSU file type */                \
	X("u:r:magisk:s0")            /* Magisk daemon */                     \
	X("u:r:magisk_file:s0")       /* Magisk file type */                  \
	X("u:r:lsposed_file:s0")      /* LSPosed file type */                 \
	X("u:r:droidspacesd:s0")      /* DroidSpaces daemon */                \
	X("u:r:msd_app:s0")           /* MSD app */                           \
	X("u:r:msd_daemon:s0")        /* MSD daemon */                        \
	X("u:r:xposed_data:s0")       /* Xposed data */

/* --- "Dirty rule" access-vector tuples ---------------------------------
 * Each entry: scon, tcon, tclass, perm. If the live policy ALLOWS this
 * access, the policy has been modified by a root tool. Counter: pretend
 * each is DENIED in the AV decision returned to userspace.
 *
 * Sourced from Duck Detector's SelinuxContextValidityProbe — there are
 * 15+ such tuples; below are the most impactful subset for v1.
 */
struct rff_sel_rule {
	const char *scon;     /* source context (suffix match on type, e.g. "system_server") */
	const char *tcon;     /* target context (same) */
	const char *tclass;   /* security class (e.g. "process", "file") */
	const char *perm;     /* permission name (e.g. "execmem", "read") */
};

#define RFF_DIRTY_RULE_LIST                                                              \
	R("system_server", "system_server",  "process",     "execmem")                  \
	R("fsck",          "fsck",            "capability",  "sys_admin")                \
	R("shell",         "su",              "process",     "transition")               \
	R("adbd",          "adbroot",         "binder",      "call")                     \
	R("untrusted_app", "magisk",          "binder",      "call")                     \
	R("untrusted_app", "ksu_file",        "file",        "read")                     \
	R("untrusted_app", "lsposed_file",    "file",        "read")                     \
	R("untrusted_app", "xposed_data",     "file",        "read")                     \
	R("zygote",        "adb_data_file",   "dir",         "search")                   \
	R("magisk",        "droidspacesd",    "process",     "transition")               \
	R("su",            "droidspacesd",    "process",     "transition")               \
	R("system_server", "droidspacesd",    "binder",      "call")                     \
	R("msd_app",       "msd_daemon",      "unix_stream_socket", "connectto")         \
	R("msd_daemon",    "msd_daemon",      "unix_stream_socket", "connectto")         \
	R("msd_daemon",    "selinuxfs",       "file",        "read")                     \
	R("msd_daemon",    "configfs",        "dir",         "search")                   \
	R("msd_daemon",    "configfs",        "file",        "write")

/* Helper: returns true if a context buffer matches any dirty context. */
bool rff_sel_ctx_is_dirty(const char *buf, size_t len);

/* Helper: returns true if a context string suffix-matches any dirty type.
 * Used by sel_write_access to scan the scon/tcon parts of the AV query. */
bool rff_sel_ctx_contains_dirty_type(const char *buf, size_t len);

#endif /* _RFF_SEL_DIRTY_H */
