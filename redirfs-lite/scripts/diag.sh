#!/system/bin/sh
# redirfs-lite — Pixel/Android kernel diagnostics
#
# What this collects:
#   - exact kernel release + build identity (vermagic target)
#   - KernelSU variant + version
#   - module signing posture (CONFIG_MODULE_SIG_FORCE etc.)
#   - vermagic string from an existing vendor module (canonical target)
#   - KSU LKM-mode capability indicators
#
# Run as root (KSU su, Magisk su, or adb root):
#   adb push diag.sh /data/local/tmp/
#   adb shell 'su -c sh /data/local/tmp/diag.sh' > diag.out
#
# Or inline:
#   adb shell 'su -c sh -' < diag.sh | tee diag.out
#
# Output is structured "[section] key: value" — easy to paste back.

set -u

section() { echo; echo "[$1]"; }
kv()      { echo "$1: $2"; }
try()     { eval "$@" 2>/dev/null || echo "(unavailable)"; }

section "00-uid"
kv "uid"      "$(id -u 2>/dev/null)"
kv "user"     "$(id -un 2>/dev/null)"
[ "$(id -u)" != "0" ] && echo "warning: not running as root — some sections will be empty"

section "01-kernel"
kv "uname-r"          "$(uname -r 2>/dev/null)"
kv "uname-v"          "$(uname -v 2>/dev/null)"
kv "uname-m"          "$(uname -m 2>/dev/null)"
kv "proc-version"     "$(cat /proc/version 2>/dev/null)"
kv "build-fingerprint" "$(getprop ro.build.fingerprint 2>/dev/null)"
kv "device-codename"  "$(getprop ro.product.device 2>/dev/null)"
kv "soc-model"        "$(getprop ro.soc.model 2>/dev/null)"
kv "android-version"  "$(getprop ro.build.version.release 2>/dev/null)"
kv "spl"              "$(getprop ro.build.version.security_patch 2>/dev/null)"

section "02-ksu-variant"
KSU_FOUND=0
for d in /data/adb/ksu /data/adb/ksud /data/adb/sukisu /data/adb/ksu-next /data/adb/wksu /data/adb/resukisu; do
	if [ -e "$d" ]; then
		kv "found-dir" "$d"
		[ -f "$d/version" ]    && kv "$d/version"  "$(cat $d/version)"
		[ -f "$d/bin/ksud" ]   && kv "ksud-info"   "$(/system/bin/sh $d/bin/ksud --version 2>&1 | head -3)"
		KSU_FOUND=1
	fi
done
[ "$KSU_FOUND" = "0" ] && echo "no /data/adb/ksu* directories"

if [ -e /data/adb/magisk ]; then
	kv "magisk-present" "yes"
	[ -x /data/adb/magisk/magisk ] && kv "magisk-version" "$(/data/adb/magisk/magisk -v 2>/dev/null)"
fi

section "03-module-loading"
kv "modules_disabled" "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)"
kv "loaded-module-count" "$(ls /sys/module 2>/dev/null | wc -l)"
kv "kallsyms-readable" "$(head -1 /proc/kallsyms 2>/dev/null | head -c 60)"
kv "kptr_restrict"    "$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"

section "04-config-flags"
# config.gz exposure varies. Try the common locations.
CFG=""
for c in /proc/config.gz /sys/kernel/config.gz /data/local/tmp/config.gz; do
	[ -r "$c" ] && CFG="$c" && break
done
if [ -n "$CFG" ]; then
	kv "config-source" "$CFG"
	zcat "$CFG" 2>/dev/null | grep -E '^CONFIG_(MODULE_SIG|MODULES=|MODULE_FORCE|MODVERSIONS|KPROBES|KALLSYMS|FTRACE|MODULE_SCMVERSION|MODULE_UNLOAD)' | sort
else
	echo "(/proc/config.gz not readable — kernel built without CONFIG_IKCONFIG_PROC)"
fi

section "05-btf"
kv "btf-vmlinux" "$([ -r /sys/kernel/btf/vmlinux ] && stat -c '%s bytes' /sys/kernel/btf/vmlinux 2>/dev/null || echo missing)"

section "06-existing-module-vermagic"
# Pull vermagic from any .ko on disk — this is the EXACT string our build must match.
KO=""
for dir in /vendor/lib/modules /vendor_dlkm/lib/modules /system/lib/modules /lib/modules /system_dlkm/lib/modules; do
	[ -d "$dir" ] || continue
	K=$(find "$dir" -maxdepth 3 -name '*.ko' -type f 2>/dev/null | head -1)
	[ -n "$K" ] && KO="$K" && break
done
if [ -n "$KO" ]; then
	kv "sample-module" "$KO"
	# vermagic is a null-separated ELF .modinfo section entry "vermagic=..."
	VM=$(strings -a "$KO" 2>/dev/null | grep '^vermagic=' | head -1)
	kv "vermagic" "$VM"
	# Also dump first few modinfo lines if modinfo binary present
	if command -v modinfo >/dev/null 2>&1; then
		modinfo "$KO" 2>/dev/null | head -8
	else
		strings -a "$KO" 2>/dev/null | grep -E '^(vermagic|name|description|license|srcversion)=' | head -8
	fi
else
	echo "no .ko found under standard module dirs"
fi

section "07-ksu-lkm-paths"
# KSU LKM-mode loads .ko via boot.img-injected init script. These paths
# indicate the device is wired for it (or has Magisk modules).
for p in /data/adb/modules /data/adb/ksu/modules /data/adb/ksu/modules.d /data/adb/modules_update; do
	if [ -d "$p" ]; then
		kv "exists" "$p"
		ls -la "$p" 2>/dev/null | head -5
	fi
done

section "08-bootloader"
kv "verified-boot" "$(getprop ro.boot.verifiedbootstate 2>/dev/null)"
kv "vbmeta-state"  "$(getprop ro.boot.vbmeta.device_state 2>/dev/null)"
kv "flash-locked"  "$(getprop ro.boot.flash.locked 2>/dev/null)"
kv "veritymode"    "$(getprop ro.boot.veritymode 2>/dev/null)"
kv "warranty-bit"  "$(getprop ro.boot.warranty_bit 2>/dev/null)"

section "09-summary"
KREL=$(uname -r 2>/dev/null)
VM=$(strings -a "$KO" 2>/dev/null | grep '^vermagic=' | head -1 | sed 's/^vermagic=//')
echo "kernel-release: $KREL"
echo "target-vermagic: $VM"
echo
echo "Paste sections 01, 02, 04, 06, 08 back to drive the build."
