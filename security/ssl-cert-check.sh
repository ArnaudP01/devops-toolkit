#!/usr/bin/env bash
# ssl-cert-check.sh — print the TLS certificate expiry for host:port, warn when it is near.
# Usage: ./ssl-cert-check.sh <host> [port=443] [warn_days=30]
# Exit codes: 0 ok, 1 usage/tool error, 3 certificate expiring soon.
set -euo pipefail

host="${1:?usage: ssl-cert-check.sh <host> [port=443] [warn_days=30]}"
port="${2:-443}"
warn="${3:-30}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found" >&2; exit 1
fi

end_date=$(echo | openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null \
  | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

if [ -z "$end_date" ]; then
  echo "could not retrieve certificate for $host:$port" >&2; exit 1
fi

# Convert to epoch. GNU date (Linux) first, BSD date (macOS) as fallback.
end_epoch=$(date -d "$end_date" +%s 2>/dev/null \
  || date -j -f "%b %d %H:%M:%S %Y %Z" "$end_date" +%s 2>/dev/null)
if [ -z "${end_epoch:-}" ]; then
  echo "could not parse date: $end_date" >&2; exit 1
fi

now_epoch=$(date +%s)
days_left=$(( (end_epoch - now_epoch) / 86400 ))

printf "%s:%s  expires: %s  (%d days left)\n" "$host" "$port" "$end_date" "$days_left"
if [ "$days_left" -le "$warn" ]; then
  echo "WARNING: certificate expires in $days_left day(s) — threshold: $warn" >&2
  exit 3
fi
