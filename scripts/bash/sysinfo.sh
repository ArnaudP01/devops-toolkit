#!/usr/bin/env bash
# sysinfo.sh — quick system snapshot (OS, uptime, load, memory, disk, top procs, ports).
# Usage: ./sysinfo.sh
# Target: Linux (most commands also work on macOS with minor differences).
set -euo pipefail

CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
section() { printf "\n${BOLD}${CYAN}== %s ==${RESET}\n" "$1"; }

section "Host"
if command -v hostnamectl >/dev/null 2>&1; then
  hostnamectl | sed 's/^/  /'
else
  echo "  host: $(hostname)"
  echo "  os:   $(uname -sr)"
fi

section "Uptime / Load"
uptime | sed 's/^/  /'

if command -v free >/dev/null 2>&1; then
  section "Memory"
  free -h | sed 's/^/  /'
fi

section "Disk usage"
df -h -x tmpfs -x devtmpfs 2>/dev/null | sed 's/^/  /' || df -h | sed 's/^/  /'

section "Top 5 CPU processes"
ps -eo pid,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -n 6 | sed 's/^/  /' \
  || ps -Ao pid,pcpu,comm | head -n 6 | sed 's/^/  /'

section "Listening TCP ports"
if command -v ss >/dev/null 2>&1; then
  ss -tlnH 2>/dev/null | head -n 10 | sed 's/^/  /'
elif command -v netstat >/dev/null 2>&1; then
  netstat -tln 2>/dev/null | head -n 10 | sed 's/^/  /'
else
  echo "  (ss/netstat unavailable)"
fi
