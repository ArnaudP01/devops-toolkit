#!/usr/bin/env bash
# backup.sh — create a timestamped compressed backup of a directory and keep the last N.
# Usage: ./backup.sh <source_dir> <dest_dir> [keep=7]
set -euo pipefail

src="${1:?usage: backup.sh <source_dir> <dest_dir> [keep=7]}"
dest="${2:?usage: backup.sh <source_dir> <dest_dir> [keep=7]}"
keep="${3:-7}"

[ -d "$src" ] || { echo "source not found: $src" >&2; exit 1; }
mkdir -p "$dest"

name=$(basename "$src")
stamp=$(date +%Y%m%d-%H%M%S)
archive="$dest/${name}-${stamp}.tar.gz"

tar -czf "$archive" -C "$(dirname "$src")" "$name"
echo "created: $archive ($(du -h "$archive" | cut -f1))"

# Retention: keep only the newest $keep archives for this source.
ls -1t "$dest/${name}-"*.tar.gz 2>/dev/null | tail -n +$((keep + 1)) | while read -r old; do
  rm -f "$old"
  echo "pruned:  $old"
done

echo "retention: keeping last $keep archive(s)."
