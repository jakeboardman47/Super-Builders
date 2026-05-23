#!/system/bin/sh
# customize.sh — runs at install time inside Magisk/KSU module flasher.
#
# We use it to:
#   1. Verify the .ko's vermagic post-space portion matches the running kernel
#   2. Ensure /data/adb/redirfs exists for runtime rules
#   3. Print friendly install banner

# Magisk pre-defines:
#   MODPATH = /data/adb/modules_update/<id>   (during install)
#   ui_print "..."                            (writes to recovery UI / Manager)
#   abort "..."                               (fail the install)

KO="$MODPATH/redirfs_lite.ko"

ui_print "================================"
ui_print " redirfs-lite v0.1.0-mvp"
ui_print " kprobe-based VFS redirection"
ui_print "================================"

if [ ! -f "$KO" ]; then
	abort "! redirfs_lite.ko missing from zip"
fi

# Vermagic compatibility check — kernel uses same_magic() to compare modules.
# With CONFIG_MODVERSIONS, only the post-space portion matters
# (SMP preempt mod_unload modversions aarch64).
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
	ui_print "!   (rmmod and reflash the right .ko if it fails to load.)"
fi

# Ensure the runtime rules directory exists. The module's post-fs-data.sh
# reads /data/adb/redirfs/rules.conf at boot.
mkdir -p /data/adb/redirfs
chmod 0700 /data/adb/redirfs

# Drop an example rules file if none present (don't clobber user's existing one)
if [ ! -f /data/adb/redirfs/rules.conf ]; then
	cp -f "$MODPATH/rules.conf.example" /data/adb/redirfs/rules.conf
	ui_print "- seeded /data/adb/redirfs/rules.conf with examples"
	ui_print "- edit it then 'reboot' (or write directly to /proc/redirfs/rules)"
fi

set_perm "$KO" 0 0 0644
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh"      0 0 0755 2>/dev/null
set_perm "$MODPATH/uninstall.sh"    0 0 0755 2>/dev/null

ui_print "- install complete; reboot to activate"
