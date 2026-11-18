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
# The timestamp in the name sorts chronologically, so the glob order is oldest first.
archives=("$dest/${name}-"*.tar.gz)
excess=$(( ${#archives[@]} - keep ))
for (( i = 0; i < excess; i++ )); do
  rm -f "${archives[$i]}"
  echo "pruned:  ${archives[$i]}"
done

echo "retention: keeping last $keep archive(s)."
