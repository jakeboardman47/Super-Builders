#!/system/bin/sh
# customize.sh — runs at install time inside KernelSU-Next Manager flasher.
#
# This module targets KernelSU-Next specifically. It will install under any
# Magisk-compatible loader, but the Action button (action.sh) is a KSU-Next
# feature, and the rule-management workflow assumes the KSU-Next manager UI.
#
# We also:
#   1. Verify the .ko vermagic against an on-device sample module
#   2. Ensure /data/adb/redirfs/ exists for runtime rules
#   3. Seed rules.conf if none present

# Magisk pre-defines:
#   MODPATH = /data/adb/modules_update/<id>   (during install)
#   ui_print "..."                            (writes to recovery / Manager UI)
#   abort "..."                               (fail the install)

KO="$MODPATH/redirfs_lite.ko"

ui_print " "
ui_print "================================"
ui_print " redirfs-lite v0.1.0-mvp"
ui_print " kprobe VFS redirection for KSU-Next"
ui_print "================================"

# --- KSU variant detection ---------------------------------------------------
# KSU-Next ships ksud at /data/adb/ksu/bin/ksud and writes "next" to
# /data/adb/ksu/version (or has KSU_NEXT_VERSION exported). The exact marker
# varies by KSU-Next version, so we probe several heuristics.
KSU_VARIANT=unknown
if [ -e /data/adb/ksu ]; then
	if [ -f /data/adb/ksu/version ]; then
		KSU_VARIANT=$(cat /data/adb/ksu/version 2>/dev/null | head -1)
	fi
	# Strings probe on ksud as fallback
	if [ "$KSU_VARIANT" = "unknown" ] && [ -f /data/adb/ksu/bin/ksud ]; then
		if strings /data/adb/ksu/bin/ksud 2>/dev/null | grep -qi 'KernelSU-Next\|KSU.Next\|ksu_next'; then
			KSU_VARIANT="ksu-next (detected via ksud strings)"
		elif strings /data/adb/ksu/bin/ksud 2>/dev/null | grep -qi 'SukiSU'; then
			KSU_VARIANT="sukisu"
		fi
	fi
fi
ui_print "- detected root: $KSU_VARIANT"

if [ "$KSU_VARIANT" = "unknown" ] && [ ! -d /data/adb/magisk ]; then
	abort "! Neither KSU-Next nor Magisk detected. Install one first."
fi

# --- File sanity -------------------------------------------------------------
if [ ! -f "$KO" ]; then
	abort "! redirfs_lite.ko missing from zip"
fi

# --- Vermagic compatibility check -------------------------------------------
# Kernel uses same_magic() to compare modules. With CONFIG_MODVERSIONS, only
# the post-space portion matters: "SMP preempt mod_unload modversions aarch64"
KERNEL_VM_POST=""
SAMPLE_KO=$(find /vendor_dlkm/lib/modules /vendor/lib/modules /system/lib/modules \
	-maxdepth 3 -name '*.ko' 2>/dev/null | head -1)
if [ -n "$SAMPLE_KO" ]; then
	KERNEL_VM_POST=$(strings "$SAMPLE_KO" 2>/dev/null | grep '^vermagic=' | head -1 | \
		sed 's/^vermagic=[^ ]* //')
fi
MOD_VM_POST=$(strings "$KO" 2>/dev/null | grep '^vermagic=' | head -1 | \
	sed 's/^vermagic=[^ ]* //')

ui_print "- kernel: $(uname -r)"
ui_print "- module vermagic suffix: $MOD_VM_POST"

if [ -n "$KERNEL_VM_POST" ] && [ "$KERNEL_VM_POST" != "$MOD_VM_POST" ]; then
	ui_print "! WARNING: vermagic mismatch"
	ui_print "!   kernel : $KERNEL_VM_POST"
	ui_print "!   module : $MOD_VM_POST"
	ui_print "!   insmod will likely reject. Continuing install anyway."
	ui_print "!   Rebuild the .ko against your running kernel to fix."
fi

# --- Runtime rules directory ------------------------------------------------
mkdir -p /data/adb/redirfs
chmod 0700 /data/adb/redirfs

if [ ! -f /data/adb/redirfs/rules.conf ]; then
	cp -f "$MODPATH/rules.conf.example" /data/adb/redirfs/rules.conf
	ui_print "- seeded /data/adb/redirfs/rules.conf"
	ui_print "  edit, then tap 'Action' in KSU-Next Manager to reload"
fi

# --- Permissions ------------------------------------------------------------
set_perm "$KO"                        0 0 0644
set_perm "$MODPATH/post-fs-data.sh"   0 0 0755
set_perm "$MODPATH/service.sh"        0 0 0755 2>/dev/null
set_perm "$MODPATH/action.sh"         0 0 0755 2>/dev/null
set_perm "$MODPATH/uninstall.sh"      0 0 0755 2>/dev/null
set_perm "$MODPATH/rules.conf.example" 0 0 0644

ui_print " "
ui_print "Install complete."
ui_print "Reboot to activate, then in KSU-Next Manager:"
ui_print "  Modules → redirfs-lite → Action → reload rules"
