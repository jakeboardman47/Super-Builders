#!/system/bin/sh
# service.sh — runs late in boot (after boot completed, after zygote+system_server).
#
# Used for things that need a fully-up Android: reading SELinux contexts,
# resolving package UIDs by name, late re-application of rules that depend
# on userspace state.
#
# For the MVP we only re-verify the module is still loaded — if anything
# unloaded it between post-fs-data and now, log a warning so the user can
# investigate. Rules are not re-applied here (post-fs-data already did it).

TAG=redirfs-mod
LOG=/dev/kmsg

log() {
	printf '<6>%s: %s\n' "$TAG" "$1" > "$LOG" 2>/dev/null || true
}

if grep -q '^redirfs_full' /proc/modules 2>/dev/null; then
	HITS=$(awk 'NR==1{} END{}' /proc/redirfs/rules 2>/dev/null)
	log "service: module live"
else
	log "service: module NOT loaded — post-fs-data may have failed"
fi
