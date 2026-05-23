# Duck Detector — detection inventory & counter strategy

Source: [eltavine/Duck-Detector-Refactoring](https://github.com/eltavine/Duck-Detector-Refactoring) at HEAD (cloned 2026-05-23).
337 Kotlin sources, ~30 native C++ probes. Scope below is the **SELinux + Zygote** subset called out by the user; the wider surface (TEE, bootloader, kernel, mounts, system properties, etc.) is catalogued but deferred.

Each row records: **what the probe checks → kernel data source it reads → feasibility of hiding from a loadable kernel module (no rebuild) → first-cut counter approach.**

Feasibility legend:
- **L** = Loadable-module feasible (kretprobe on the right kernel function)
- **L?** = Theoretically loadable, complex hook chain
- **P** = Needs in-tree kernel patch (e.g. struct change, new field, BPF LSM that's not enabled)
- **U** = Userspace mitigation only (Zygisk-shaped problem; Zygisk variants already do it)

---

## 1. SELinux feature (`features/selinux/data/probes/`)

| # | Probe | What it checks | Kernel data source | F | Counter sketch |
|---|---|---|---|---|---|
| 1 | `SelinuxProcAttrCurrentProbe` | Writes 9 known root-tool contexts (`u:r:ksu:s0`, `u:r:magisk:s0`, `u:r:lsposed_file:s0`, `u:r:droidspacesd:s0`, `u:r:msd_app:s0`, …) to `/proc/self/attr/current`. Clean kernel → all 9 return `EINVAL`. Modified policy → at least one returns success or non-EINVAL error. | `sel_write_current()` in `security/selinux/selinuxfs.c` | **L** | kretprobe on `sel_write_current`. Entry handler stashes the buffer; return handler, if buffer ∈ {known-leaky contexts}, forces return to `-EINVAL`. |
| 2 | `SelinuxContextValidityProbe` (oracle) | Asks live policy: do `ksu` / `ksu_file` types exist (via `security_compute_av` or `/sys/fs/selinux/access`). Yes → policy modified. | `sel_write_access()` in `selinuxfs.c`, or `security_compute_av()` | **L** | kretprobe on `sel_write_access`. Inspect the AV decision blob being written back; if the source/target context is in {`ksu`, `ksu_file`, `magisk`, `lsposed_file`, `droidspacesd`, `msd_app`, `msd_daemon`, `xposed_data`} and access was allowed, rewrite the `avd->allowed` bits to 0. |
| 3 | `SelinuxContextValidityProbe` (dirty rules) | Tests specific access rules that shouldn't exist on a clean device: `system_server execmem`, `fsck sys_admin`, `shell→su transition`, `adbd→adbroot binder call`, `magisk binder call`, `ksu_file read`, `lsposed_file read`, MSD app/daemon connect, MSD daemon selinuxfs read, MSD daemon configfs ops, `xposed_data file read`, `zygote adb_data search`, `magisk→droidspacesd transition`, `su→droidspacesd transition`, `system_server→droidspacesd binder call`. | Same as #2 | **L** | Same hook as #2. Maintain a lookup table of `(scon, tcon, tclass, perm)` tuples to mask. |
| 4 | `SelinuxAuditRuntimeProbe` | Subscribes to kernel audit messages via netlink. Looks for AVC denial messages mentioning root-tool contexts. | `audit_log_format()`, netlink `NETLINK_AUDIT` | **L?** | Hard. Either suppress AVC audit messages for these contexts (kretprobe on `avc_audit_post_callback`) or filter the netlink stream before it leaves the kernel. SUSFS does the former by patching `security/selinux/avc.c`. |
| 5 | `SelinuxAuditLogcatReader` | Reads logcat for SELinux audit lines. | Already in user space (logd); kernel logs propagate from #4. | **L** (via #4) | If #4 is fully suppressed, this passes too. |
| 6 | `AuditAvcSideChannelProbe` | Triggers a known denial-producing access, then samples whether the denial appeared in audit. Detects "audit suppression" as itself a fingerprint. | `audit_log_format()` timing/presence | **L?** | Mitigation has its own footprint — see threat model in §4. |

## 2. Zygisk feature (`features/zygisk/data/` + `cpp/zygisk/probes/`)

| # | Probe | What it checks | Kernel data source | F | Counter sketch |
|---|---|---|---|---|---|
| 7 | `smaps_probe` | Reads `/proc/self/smaps`. Any `/system/*`, `/vendor/*`, `/apex/*` executable mapping with ≥8 KB of `Private_Dirty:` or `Shared_Dirty:` → inline-hook fingerprint. | `show_smap()` in `fs/proc/task_mmu.c` | **L** | kretprobe on `show_smap`/`smap_gather_stats`. For VMAs backed by `/system|/vendor|/apex`, zero `private_dirty`/`shared_dirty` fields in the `mem_size_stats` struct before display. |
| 8 | `solist_probe` | Iterates loaded shared objects two ways: `dl_iterate_phdr` (linker view) vs `/proc/self/maps` (kernel view). Drift → injected libs. | `show_map_vma()` in `fs/proc/task_mmu.c` | **L** | kretprobe on `show_map_vma`. Filter VMA entries pointing at `/data/adb/`, KSU/Zygisk paths, or any path not in a hashed allowlist. |
| 9 | `fd_probe` | Walks `/proc/self/fd/*`. Looks for fds owned by zygisk-style sockets, anon_inode names, magisk-style fifos. | `show_fd_locks()`, `proc_pid_readlink`, `proc_fd_link` | **L** | kretprobe on `proc_fd_link`. If readlink target contains `/data/adb/`, `magisk`, `ksu`, blank it (or rewrite to a plausible-looking path). |
| 10 | `fd_trap` | Intentionally creates fds with sentinel paths, then re-enumerates `/proc/self/fd`. If a Zygisk-style fd-table sanitizer drops them → fingerprint. Detects "fd hider" as itself a fingerprint. | Same as #9 | **L?** | Avoid over-filtering — only mask known root paths, leave sentinel paths visible. See §4. |
| 11 | `namespace_probe` | Reads `/proc/self/ns/*` symlinks; compares against parent's namespaces. Mount namespace isolation → Zygisk injection. | `proc_pid_readlink` → `do_proc_readlink` | **L?** | Spoofing namespace inode is risky (breaks pid namespacing primitives). Alternative: hide the mount-namespace difference by NOT putting modules into a child namespace in the first place (this is what mountless modules a.k.a. ZeroMount already do). |
| 12 | `seccomp_probe` | Reads `/proc/self/status` for `Seccomp:` field. KSU/Zygisk may install seccomp filters. | `seq_printf` in `proc_pid_status` | **L** | kretprobe on `proc_pid_status` (`fs/proc/array.c::proc_pid_status`). Rewrite the Seccomp line value to 2 (default for Android apps). |
| 13 | `thread_probe` | Enumerates `/proc/self/task/*`; checks per-thread `comm` for known daemon names (`magiskd`, `ksud`, `zygiskd`). | `task_diag_show`, `proc_pid_readdir` | **L** | kretprobe on `proc_pid_readdir_task` to filter children. Or filter `task_diag_show` for comm matches. |
| 14 | `vmap_probe` | Reads `/proc/self/maps`, looks for unusual mapping shapes (RWX, anon-exec, suspicious-sized). | Same as #8 | **L** | Same hook as #8. |
| 15 | `linker_hook_probe` | Walks the linker's own data structures (in-process, via dlsym/asm). Detects PLT/GOT hooking. | None — process-internal only | **U** | Cannot defeat from kernel. Process needs Zygisk-style un-hook before scan, or the hooker needs to clean up. |
| 16 | `heap_entropy_probe` | Allocates many heap regions, checks ASLR entropy. Detects flat heaps (emulators) and low-entropy allocators (injected). | None — process-internal | **U** | Cannot defeat from kernel. |
| 17 | `stack_leak_probe` | Reads current stack frame, walks back. Detects unusual frames. | None — process-internal | **U** | Cannot defeat from kernel. |
| 18 | `atexit_probe` | Inspects libc's atexit handler list for injected functions. | None — process-internal | **U** | Cannot defeat from kernel. |

## 3. Out-of-scope features (catalogued for later)

| Feature | Notes |
|---|---|
| `tee` | Trusted Execution / KeyMint attestation. SafetyNet / Play Integrity flow. Defeat lives in PlayIntegrityFix, not us. |
| `kernelcheck` | `uname -r`, `/proc/version`, kernel symbol hashes. SUSFS spoofs `uname` via in-tree patch. |
| `mount` | `/proc/PID/mountinfo` scanning. SUSFS hides via in-tree patch. |
| `nativeroot` | `which su`, `/system/xbin/su`, `/data/adb/*` existence. Path-redirect with our existing **redirfs-lite** already handles much of this. |
| `dangerousapps` | PackageManager scans for known package IDs. Userspace, app-level. |
| `bootloader` | `ro.boot.flash.locked`, vbmeta state. Userspace via `getprop` — needs PIF. |
| `systemproperties` | Build props. PIF territory. |
| `lsposed`, `memory`, `virtualization`, `customrom`, `playintegrityfix` | Separate counter strategies; not LKM-shaped. |

---

## 4. Threat model: the meta-detection problem

**Counter-detection creates new fingerprints.** Duck Detector explicitly weaponizes this:

- `AuditAvcSideChannelProbe` triggers a known SELinux denial and checks if it was logged. If suppression is too aggressive, the *absence* of denials becomes the signal.
- `fd_trap` creates fds with sentinel content; if a hiding layer filtered them, the absence is the signal.
- `solist_probe` cross-checks linker view vs kernel view; consistent answers from both sides are required.

Implication: **hiding must be selective**. Blanket suppression is detectable. Counters need to mimic stock behavior precisely — including occasional minor noise that's normal on clean devices. The state-of-the-art counter modules (SUSFS, Zygisk-Next) maintain calibrated noise floors.

This pushes the bar from "hide my mods" to "make my device statistically indistinguishable from a clean one." Realistically, achieving that in a loadable kernel module is months of iteration against an evolving detector. **A reasonable goal is to pass Duck Detector v2026-05 on a Pixel 10 Pro running 6.6.138 — knowing it may break against the next release.**

---

## 5. Proposed REDIRFS-Full subsystems (LKM-feasible only)

Ordered by impact / effort ratio:

| Subsystem | Targets vectors | Effort |
|---|---|---|
| **selpol** — SELinux policy queries | #1, #2, #3 | high impact / medium effort. Single kretprobe set on `sel_write_current` + `sel_write_access`. |
| **smaps** — `/proc/PID/smaps` dirty-page hiding | #7 | medium impact / low effort. Single hook. |
| **maps** — `/proc/PID/maps` entry filtering | #8, #14 | high impact / medium effort. Need a path allowlist. |
| **fd** — `/proc/PID/fd/*` readlink filter | #9 (carefully, to not trip #10) | medium impact / medium effort. |
| **status** — `/proc/PID/status` field spoof | #12 | low impact / low effort. |
| **task** — `/proc/PID/task/*` filter | #13 | low impact / medium effort. |
| **avc** — AVC denial suppression | #4, #5 (without tripping #6) | high impact / **high** effort. Needs careful calibration. |
| **ns** — namespace symlink spoofing | #11 | low impact / **high** effort + risky. |

## 6. Recommended phased build

- **Phase 1** (1 session): `selpol` subsystem only. SELinux probe #1 + #2 + #3. Validates the project structure works; covers the user's #1 ask ("dirty SELinux modifications").
- **Phase 2** (1 session): `maps` + `smaps`. Covers Zygisk inline-hook fingerprint + injected-library visibility — the user's #2 ask ("Zygote traces").
- **Phase 3** (1 session): `status` + `task` + `fd`. The cheap process-introspection vectors.
- **Phase 4** (1+ sessions): `avc` — carefully tuned against #6 side-channel.
- **Phase 5**: WebUI integration with per-subsystem on/off toggles, hit counters, and rule lists.

Each phase produces a buildable `.ko` and a flashable KSU-Next module zip. Iteration loop is the same as redirfs-lite: edit → push → CI build → repack → flash → test.

---

## 7. Reuse from redirfs-lite

REDIRFS-Full's foundation is the redirfs-lite codebase — same symbol bootstrap (`syms.c`), RCU rule table pattern (`rules.c`), `/proc` control plane, KSU-Next module shell. New subsystems are additional hook files under `src/sel/`, `src/maps/`, etc. The path-redirect/d_path hooks from redirfs-lite stay as a `redir` subsystem.

Single `.ko`. Single zip. Per-subsystem runtime enable/disable via `/proc/redirfs/config`.
