#!/system/bin/sh
# Load redirfs_lite early, then install rules from /data/adb/redirfs/rules.conf
# if the file exists. Format: same grammar as /proc/redirfs/rules.

MODDIR="${0%/*}"
KO="$MODDIR/redirfs_lite.ko"
RULES_CONF=/data/adb/redirfs/rules.conf

[ -f "$KO" ] || exit 0
insmod "$KO" || exit 0

if [ -f "$RULES_CONF" ] && [ -w /proc/redirfs/rules ]; then
	while IFS= read -r line; do
		echo "$line" > /proc/redirfs/rules
	done < "$RULES_CONF"
fi
