#!/usr/bin/env bash
# ssh_audit.sh — review a Linux server's SSH exposure: daemon hardening, who can log in, with which keys.
# Usage: sudo ./ssh_audit.sh
# Reads the *effective* sshd configuration (`sshd -T`, falls back to sshd_config), then lists
# accounts that have a real login shell, their authorized_keys (type + comment, never the key)
# and any ChrootDirectory rules. Run as root to see every user's keys.
# Exit codes: 0 no findings, 1 warnings, 2 at least one failure.
set -uo pipefail

warn=0; fail=0
ok()   { printf '[OK  ] %s\n' "$*"; }
wrn()  { printf '[WARN] %s\n' "$*"; warn=$((warn + 1)); }
bad()  { printf '[FAIL] %s\n' "$*"; fail=$((fail + 1)); }
info() { printf '       %s\n' "$*"; }

# --- effective sshd settings ---------------------------------------------------------------
if command -v sshd >/dev/null 2>&1 && config=$(sshd -T 2>/dev/null); then
  source_desc="sshd -T (effective configuration)"
elif [ -r /etc/ssh/sshd_config ]; then
  # Best effort: first value wins in sshd_config; Match blocks are ignored here.
  config=$(sed -e 's/#.*//' -e '/^[[:space:]]*Match/,$d' /etc/ssh/sshd_config | awk 'NF>=2 {print tolower($1), $2}')
  source_desc="/etc/ssh/sshd_config (not effective: run as root for sshd -T)"
else
  echo "no sshd configuration found" >&2; exit 2
fi
setting() { awk -v k="$1" '$1 == k {print $2; exit}' <<<"$config"; }

echo "== sshd settings — from $source_desc"
case "$(setting permitrootlogin)" in
  yes)                                   bad "PermitRootLogin yes — root can log in with a password" ;;
  prohibit-password|without-password)    ok  "PermitRootLogin prohibit-password (keys only)" ;;
  no)                                    ok  "PermitRootLogin no" ;;
  forced-commands-only)                  ok  "PermitRootLogin forced-commands-only" ;;
  "")                                    wrn "PermitRootLogin not set — check your distribution default" ;;
  *)                                     wrn "PermitRootLogin $(setting permitrootlogin)" ;;
esac
if [ "$(setting passwordauthentication)" = "no" ]; then
  ok "PasswordAuthentication no"
else
  wrn "PasswordAuthentication is not 'no' — brute force possible, prefer keys"
fi
[ "$(setting permitemptypasswords)" = "yes" ] && bad "PermitEmptyPasswords yes"
[ "$(setting pubkeyauthentication)" = "no" ] && wrn "PubkeyAuthentication no"
tries=$(setting maxauthtries)
if [ -n "$tries" ] && [ "$tries" -gt 4 ]; then wrn "MaxAuthTries $tries (4 or less recommended)"; fi
[ "$(setting x11forwarding)" = "yes" ] && wrn "X11Forwarding yes — rarely needed on servers"
port=$(setting port); info "Port ${port:-22}"

# --- chroot rules ----------------------------------------------------------------------------
if [ -r /etc/ssh/sshd_config ]; then
  chroots=$(grep -Ei '^[[:space:]]*(Match|ChrootDirectory)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)
  if [ -n "$chroots" ]; then
    echo; echo "== Match / ChrootDirectory rules"
    while IFS= read -r line; do info "$line"; done <<<"$chroots"
  fi
fi

# --- accounts with a login shell ---------------------------------------------------------------
echo; echo "== accounts with a login shell"
while IFS=: read -r user _ uid _ _ home shell; do
  case "$shell" in */nologin|*/false|/bin/sync|/sbin/shutdown|/sbin/halt|"") continue ;; esac
  keyfile="$home/.ssh/authorized_keys"
  if [ -r "$keyfile" ]; then
    nkeys=$(grep -cE '^[^#[:space:]]' "$keyfile" || true)
    printf '  %-20s uid=%-6s %-20s %s key(s)\n' "$user" "$uid" "$shell" "$nkeys"
    # key type + comment only, never the key material
    grep -E '^[^#[:space:]]' "$keyfile" | awk '{
      for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { type=$i; comment=""; for (j = i + 2; j <= NF; j++) comment = comment " " $j; break }
      printf "       - %s%s\n", type, comment }'
  elif [ -e "$keyfile" ]; then
    printf '  %-20s uid=%-6s %-20s (authorized_keys not readable — run as root)\n' "$user" "$uid" "$shell"
  else
    printf '  %-20s uid=%-6s %-20s no authorized_keys\n' "$user" "$uid" "$shell"
  fi
  [ "$uid" = "0" ] && [ "$user" != "root" ] && bad "$user has uid 0 — a second root account"
done < /etc/passwd

echo
echo "$fail failure(s), $warn warning(s)"
[ "$fail" -gt 0 ] && exit 2
[ "$warn" -gt 0 ] && exit 1
exit 0
