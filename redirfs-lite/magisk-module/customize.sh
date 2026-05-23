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

# --- Root manager detection -------------------------------------------------
# KSU, KSU-Next and Magisk all export environment variables from their
# installer wrapper:
#   $KSU = "true"          → KernelSU or KernelSU-Next
#   $KSU_VER, $KSU_VER_CODE → KSU/KSU-Next version
#   $KSU_KERNEL_VER_CODE   → kernel-side KSU version
#   $MAGISK_VER, $MAGISK_VER_CODE → Magisk
#
# If env vars aren't set (e.g. recovery install without a proper wrapper),
# fall back to filesystem probes.

ROOT_MGR=""
if [ "${KSU:-}" = "true" ]; then
	ROOT_MGR="KSU/KSU-Next (KSU_VER=${KSU_VER:-?} code=${KSU_VER_CODE:-?})"
elif [ -n "${MAGISK_VER:-}" ]; then
	ROOT_MGR="Magisk $MAGISK_VER (code=$MAGISK_VER_CODE)"
elif [ -e /data/adb/ksu ] || [ -e /data/adb/ksud ]; then
	ROOT_MGR="KSU-family (filesystem probe: /data/adb/ksu present)"
elif [ -d /data/adb/magisk ]; then
	ROOT_MGR="Magisk (filesystem probe: /data/adb/magisk present)"
fi

ui_print "- root: ${ROOT_MGR:-NOT DETECTED}"

if [ -z "$ROOT_MGR" ]; then
	ui_print "! Diagnostic: env vars and dirs ="
	ui_print "!   KSU=${KSU:-unset}"
	ui_print "!   KSU_VER=${KSU_VER:-unset}"
	ui_print "!   MAGISK_VER=${MAGISK_VER:-unset}"
	ui_print "!   /data/adb/ksu : $([ -e /data/adb/ksu ] && echo present || echo absent)"
	ui_print "!   /data/adb/ksud: $([ -e /data/adb/ksud ] && echo present || echo absent)"
	ui_print "!   /data/adb/magisk: $([ -d /data/adb/magisk ] && echo present || echo absent)"
	abort "! No root manager detected"
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
