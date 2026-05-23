#!/system/bin/sh
# post-fs-data.sh — runs early in boot, before zygote, after /data mounted.
#
# Order:
#   1. insmod redirfs_lite.ko (idempotent — skip if already loaded)
#   2. wait briefly for /proc/redirfs/rules to appear (module init creates it)
#   3. apply rules from /data/adb/redirfs/rules.conf
#
# All output goes to dmesg via logger so users can `dmesg | grep redirfs-mod`
# to debug boot behavior.

MODDIR="${0%/*}"
KO="$MODDIR/redirfs_lite.ko"
RULES_CONF=/data/adb/redirfs/rules.conf
TAG=redirfs-mod
LOG=/dev/kmsg

log() {
	printf '<6>%s: %s\n' "$TAG" "$1" > "$LOG" 2>/dev/null || true
}

log "post-fs-data: starting"

# Skip cleanly if module already loaded (re-running this script is harmless)
if grep -q '^redirfs_lite' /proc/modules 2>/dev/null; then
	log "post-fs-data: already loaded"
elif [ -f "$KO" ]; then
	if insmod "$KO" 2>/dev/null; then
		log "post-fs-data: insmod ok"
	else
		log "post-fs-data: insmod FAILED — see dmesg above for kernel-side reason"
		exit 0
	fi
else
	log "post-fs-data: $KO not found (module install corrupt?)"
	exit 0
fi

# Brief wait for /proc/redirfs to materialise. Module creates it during init;
# usually instant, but proc_mkdir can be deferred under heavy boot contention.
i=0
while [ ! -w /proc/redirfs/rules ] && [ $i -lt 50 ]; do
	sleep 0.1
	i=$((i + 1))
done
if [ ! -w /proc/redirfs/rules ]; then
	log "post-fs-data: /proc/redirfs/rules never appeared (init failed?)"
	exit 0
fi

# Apply rules. One line at a time so a single bad rule doesn't abort the rest.
if [ -f "$RULES_CONF" ]; then
	APPLIED=0
	FAILED=0
	while IFS= read -r line || [ -n "$line" ]; do
		# Skip blanks and comments
		case "$line" in
			''|\#*) continue ;;
		esac
		if echo "$line" > /proc/redirfs/rules 2>/dev/null; then
			APPLIED=$((APPLIED + 1))
		else
			FAILED=$((FAILED + 1))
		fi
	done < "$RULES_CONF"
	log "post-fs-data: rules applied=$APPLIED failed=$FAILED"
else
	log "post-fs-data: no rules.conf (/data/adb/redirfs/rules.conf)"
fi

log "post-fs-data: done"
