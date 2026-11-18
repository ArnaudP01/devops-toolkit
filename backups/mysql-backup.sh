#!/usr/bin/env bash
# mysql-backup.sh — dump every MySQL/MariaDB database to its own compressed file, keep the last N.
# Usage: ./mysql-backup.sh <dest_dir> [keep=7]
# Credentials: put them in a client option file instead of the command line, e.g. ~/.my.cnf
#   [client]
#   user=backup
#   password=...
# or point MYSQL_DEFAULTS_FILE at another file (chmod 600). System schemas are skipped;
# set INCLUDE_MYSQL=1 to also dump the `mysql` schema (users, grants).
# Each dump is consistent (--single-transaction for InnoDB) and checked with `gzip -t`.
# Exit codes: 0 all databases dumped, 1 usage/tool error, 3 at least one dump failed.
set -euo pipefail

dest="${1:?usage: mysql-backup.sh <dest_dir> [keep=7]}"
keep="${2:-7}"
case "$keep" in ''|*[!0-9]*) echo "keep must be a number" >&2; exit 1 ;; esac

for tool in mysql mysqldump gzip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool not found" >&2; exit 1; }
done

opts=()
[ -n "${MYSQL_DEFAULTS_FILE:-}" ] && opts+=("--defaults-extra-file=$MYSQL_DEFAULTS_FILE")

skip='^(information_schema|performance_schema|sys|mysql)$'
[ "${INCLUDE_MYSQL:-0}" = "1" ] && skip='^(information_schema|performance_schema|sys)$'

mkdir -p "$dest"
chmod 700 "$dest"
umask 077
stamp=$(date +%Y%m%d-%H%M%S)
failed=0

databases=$(mysql ${opts[@]+"${opts[@]}"} -N -B -e 'SHOW DATABASES' | grep -Ev "$skip" || true)
if [ -z "$databases" ]; then
  echo "no databases to back up (check credentials)" >&2; exit 1
fi

while IFS= read -r db; do
  out="$dest/${db}-${stamp}.sql.gz"
  if mysqldump ${opts[@]+"${opts[@]}"} --single-transaction --quick --routines --triggers --events \
       --databases "$db" | gzip -c > "$out" && gzip -t "$out"; then
    printf 'ok      %-30s %s\n' "$db" "$(du -h "$out" | cut -f1)"
    # retention: keep the newest $keep dumps of this database
    find "$dest" -maxdepth 1 -name "${db}-*.sql.gz" -printf '%T@ %p\n' 2>/dev/null \
      | sort -rn | tail -n +"$((keep + 1))" | cut -d' ' -f2- | xargs -r rm -f --
  else
    echo "FAILED  $db" >&2
    rm -f "$out"
    failed=$((failed + 1))
  fi
done <<<"$databases"

echo "done: $(wc -l <<<"$databases") database(s), $failed failure(s), kept last $keep per database in $dest"
[ "$failed" -eq 0 ] || exit 3
