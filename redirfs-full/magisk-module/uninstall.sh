#!/system/bin/sh
# uninstall.sh — runs when the user removes the module via Manager.
#
# We do NOT rmmod here — the user might be relying on existing redirections
# in running processes, and an immediate rmmod would yank the hooks. Instead
# we let the next reboot complete the removal naturally. If you want immediate
# unload, run `rmmod redirfs_full` manually before flagging the module for
# removal.
#
# We DO remove /data/adb/redirfs/rules.conf since it's no longer driving
# anything. Comment that line out if you want to preserve it.

rm -f /data/adb/redirfs/rules.conf
rmdir /data/adb/redirfs 2>/dev/null  # only succeeds if empty
