# redirfs-lite

Loadable kernel module for VFS path redirection via kprobes. No kernel rebuild.

Operates as a **single primitive done well**: rewrite path lookups so that
opening `/virtual/path` transparently serves the contents of `/real/path`, with
per-UID/GID rule filtering. `d_path` is best-effort spoofed so `/proc/PID/fd/N`
symlinks show the virtual path.

## What this is, and what it is not

| Yes | No |
|---|---|
| Loadable kernel module (`.ko`) | Kernel patch / requires rebuild |
| Targeted (per-UID/GID rules) | Global ZeroMount-style hiding |
| Path redirect + d_path spoof | readdir injection, statfs lying, AVC suppression |
| Out-of-tree build against any GKI 6.6 / 6.12 | Stock kernels with signed-module enforcement |
| Educational / research / personal device | Production banking-app evasion at scale |

If you need the full ZeroMount feature set, use ZeroMount.

## How it works

```
userspace open("/v/foo")
        |
        v
  getname_flags(name)  ──kretprobe──┐
        |                            │  if rule matches:
        v                            ├─ putname(old_fn)
   struct filename *fn               └─ regs_return = getname_kernel("/r/bar")
        |
        v
  do_filp_open(...)  — uses our redirected fn → opens /r/bar
        |
        v
  fd returned to userspace

userspace readlink("/proc/self/fd/N")
        |
        v
  d_path(path, buf, len)  ──kretprobe──┐
                                       │  if buf contains /r/bar:
                                       └─ memcpy(buf, "/v/foo")
```

**Symbol bootstrap**: `kallsyms_lookup_name` is no longer exported (5.7+).
We register a one-shot kprobe on it, capture `kp.addr`, unregister. Every
other symbol resolves through that pointer.

## Build

CI does this automatically. For local builds against a synced kernel tree:

```
make KDIR=/path/to/common ARCH=arm64 LLVM=1 CC=clang
ls src/redirfs_lite.ko
```

`KDIR` must point at a configured kernel build tree with `.config`,
`include/`, and `scripts/` populated. Super-Builders' Bazel output qualifies
after a kernel_dist build.

## Install

```
insmod redirfs_lite.ko
ls /proc/redirfs/rules
```

Add a rule:

```
echo "add /system/etc/sentinel /data/local/tmp/shim 10001 *" > /proc/redirfs/rules
```

Rule grammar:

| Field | Meaning |
|---|---|
| `add <src> <dst> <uid> <gid>` | install (replaces existing rule on `src+uid+gid`) |
| `del <src>` | remove all rules with that src path |
| `clear` | drop every rule |
| `audit on\|off` | toggle dmesg redirect logging |

`*` matches any UID/GID. `<src>` and `<dst>` must be absolute (`/`).

## Persistence

A Magisk module template lives in `magisk-module/`. Install the `.ko`, then
the boot script does `insmod` + writes its rule set to `/proc/redirfs/rules`.
Rules don't survive reboot on their own.

## Limitations

- **MVP scope**: no `readdir` injection, no `statfs` spoofing, no SELinux xattr
  rewrite. A reader iterating the parent directory sees both `/v/foo` (if it
  actually exists) and any other entries; `/v/foo` only redirects if its
  *full path* matches a rule.
- **Direct syscall bypass**: a process invoking `openat2(AT_FDCWD, "/v/foo")`
  via `syscall(__NR_openat2, ...)` may bypass `getname_flags` on certain
  kernel paths. Production builds should also hook `do_sys_openat2`.
- **Buffer length on d_path**: we can shrink-rewrite but not grow. If your
  virtual `src` is longer than the real `dst`, the spoof for that rule
  silently no-ops; pick shorter virtual paths.
- **Kretprobe race**: 32 concurrent calls max (maxactive). On heavy I/O,
  `nmissed` will increment and some lookups will pass through unredirected.
  Acceptable for personal devices; raise `maxactive` for servers.
- **arm64 + x86_64 only.**
- **Locked kernels** (CONFIG_LOCK_DOWN_KERNEL, signed-module enforcement)
  will reject load. Custom kernels or Magisk-rooted devices are the target.

## What's missing vs ZeroMount

For visibility: ZeroMount has ~7 additional hooks we don't implement.

| ZeroMount feature | redirfs-lite | Notes |
|---|---|---|
| `getname()` redirect | ✓ | core |
| `d_path` spoof | ✓ | partial — buf-shrink only |
| readdir entry injection | ✗ | virtual files invisible to `ls` |
| Mmap dev/ino spoofing | ✗ | `/proc/PID/maps` shows real dev/ino |
| SELinux xattr injection | ✗ | redirected file uses dst's context |
| statfs spoofing | ✗ | virtual paths return source FS stats |
| Bloom filter pre-check | ✗ | hash table is fast enough for MVP |
| Write protection | ✗ | writes through virtual path hit dst |

The dimensions we differentiate on:
- **Loadable**: no kernel rebuild, no patch maintenance per LTS bump
- **Per-UID rules**: ZeroMount applies globally; this targets specific apps
- **Smaller surface**: 7 files vs ~30 patched files in ZeroMount

## Security notes

This module modifies VFS lookup. Bugs here can produce kernel crashes,
data corruption, or privilege escalation. Treat the source as untrusted
until reviewed.

Particularly:
- `regs_set_return_value` after `putname(old_fn)` must be atomic w.r.t. the
  hooked function's caller — kretprobe trampoline guarantees this on
  arm64/x86_64.
- `rfl_rule_lookup_by_dst` is O(N) over the rule table; rule sets >1000
  entries will measurably slow `d_path()` callers (and `d_path` is on the
  hot path for `getcwd`, `realpath`, etc.). Keep rule counts modest.
