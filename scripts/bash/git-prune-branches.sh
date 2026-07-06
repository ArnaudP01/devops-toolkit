#!/usr/bin/env bash
# git-prune-branches.sh — delete local branches already merged into main/master.
# Safe: only branches detected as merged are removed (git branch -d).
# Usage: ./git-prune-branches.sh   (run from inside a git repository)
set -euo pipefail

git rev-parse --git-dir >/dev/null 2>&1 || { echo "not a git repository" >&2; exit 1; }

base="main"
git rev-parse --verify main >/dev/null 2>&1 || base="master"
current=$(git rev-parse --abbrev-ref HEAD)

echo "Base branch: $base"

git branch --merged "$base" \
  | grep -vE '^\*|[[:space:]]*'"$base"'$' \
  | while read -r branch; do
      branch=$(echo "$branch" | xargs)
      [ -z "$branch" ] && continue
      [ "$branch" = "$current" ] && continue
      git branch -d "$branch"
      echo "deleted: $branch"
    done || true

echo "done."
