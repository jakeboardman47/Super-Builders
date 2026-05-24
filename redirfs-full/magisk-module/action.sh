#!/system/bin/sh
# action.sh — runs when the user taps the "Action" button in
# KernelSU-Next Manager (or Magisk Manager if it gains action support).
#
# Bound to "Reload rules" semantics:
#   1. Re-read /data/adb/redirfs/rules.conf
#   2. Apply rules atomically (clear → add) to /proc/redirfs/rules
#   3. Show before/after rule count and hit deltas
#
# Output goes to the Manager's action dialog via stdout.

MODDIR="${0%/*}"
RULES_PROC=/proc/redirfs/rules
RULES_CONF=/data/adb/redirfs/rules.conf

echo "redirfs-full — reload rules"
echo "============================"

if [ ! -e "$RULES_PROC" ]; then
	echo "[!] /proc/redirfs/rules not found"
	echo "[!] Is the kernel module loaded?"
	echo "[!] Try: insmod $MODDIR/redirfs_full.ko"
	exit 1
fi

if [ ! -f "$RULES_CONF" ]; then
	echo "[!] $RULES_CONF does not exist"
	echo "[!] Nothing to load"
	exit 1
fi

# Snapshot rule count + hits before
BEFORE_RULES=$(grep -cE '^[^#]' "$RULES_PROC" 2>/dev/null)
BEFORE_HITS=$(awk 'NR>2 {s+=$NF} END{print s+0}' "$RULES_PROC" 2>/dev/null)
echo "Before: $BEFORE_RULES rules, $BEFORE_HITS total hits"

# Atomically swap rules: clear → re-add
echo "clear" > "$RULES_PROC" 2>/dev/null || {
	echo "[!] Failed to clear current rules — running as root?"
	exit 1
}

APPLIED=0; FAILED=0
while IFS= read -r line || [ -n "$line" ]; do
	case "$line" in
		''|\#*) continue ;;
	esac
	if echo "$line" > "$RULES_PROC" 2>/dev/null; then
		APPLIED=$((APPLIED + 1))
	else
		FAILED=$((FAILED + 1))
		echo "  failed: $line"
	fi
done < "$RULES_CONF"

AFTER_RULES=$(grep -cE '^[^#]' "$RULES_PROC" 2>/dev/null)
echo "After:  $AFTER_RULES rules ($APPLIED applied, $FAILED failed)"
echo ""
echo "Current rules:"
cat "$RULES_PROC"
