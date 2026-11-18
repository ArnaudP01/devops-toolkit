#!/usr/bin/env bash
# cron_audit.sh — list every scheduled job on a Linux server, in one place.
# Usage: sudo ./cron_audit.sh
# Covers /etc/crontab, /etc/cron.d/*, each user's crontab, the cron.{hourly,daily,weekly,monthly}
# folders and systemd timers. Comments and blank lines are dropped. Run as root to see
# other users' crontabs. Handy when inheriting a server, or hunting a job that "runs by itself"
# (malware loves a user crontab).
set -uo pipefail

strip() { grep -Ev '^[[:space:]]*(#|$)' "$@" 2>/dev/null; }
section() { printf '\n== %s\n' "$*"; }

section "/etc/crontab"
strip /etc/crontab || echo "  (none)"

section "/etc/cron.d"
found=0
for f in /etc/cron.d/*; do
  [ -f "$f" ] || continue
  found=1
  lines=$(strip "$f")
  [ -n "$lines" ] && { echo "-- $f"; echo "$lines"; }
done
[ "$found" -eq 1 ] || echo "  (none)"

section "user crontabs"
found=0
for spool in /var/spool/cron/crontabs /var/spool/cron; do   # Debian/Ubuntu, then RHEL
  [ -d "$spool" ] || continue
  for f in "$spool"/*; do
    [ -f "$f" ] || continue
    lines=$(strip "$f") || true
    if [ -n "$lines" ]; then
      found=1; echo "-- $(basename "$f")"; echo "$lines"
    fi
  done
done
if [ "$found" -eq 0 ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "  (not root: showing only your own)"; crontab -l 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)' || echo "  (none)"
  else
    echo "  (none)"
  fi
fi

section "periodic folders"
for period in hourly daily weekly monthly; do
  dir="/etc/cron.$period"
  [ -d "$dir" ] || continue
  scripts=$(find "$dir" -maxdepth 1 -type f -perm -u+x ! -name '.placeholder' -printf '%f ' 2>/dev/null)
  printf '  %-8s %s\n' "$period" "${scripts:-(none)}"
done

section "systemd timers"
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/  /' || echo "  (systemd not running)"
else
  echo "  (systemctl not available)"
fi
