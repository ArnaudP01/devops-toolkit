#!/usr/bin/env bash
# docker-cleanup.sh — reclaim disk space by removing unused Docker artefacts.
# Usage: ./docker-cleanup.sh [--dry-run] [--volumes]
#   --dry-run    show what would be removed without deleting
#   --volumes    also remove unused volumes (use with care!)
set -euo pipefail

DRY_RUN=0
INCLUDE_VOLUMES=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)  DRY_RUN=1 ;;
    --volumes)  INCLUDE_VOLUMES=1 ;;
    -h|--help)  sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2; exit 1
fi

run() {
  echo "+ $*"
  [ "$DRY_RUN" -eq 0 ] && "$@"
}

echo "Reclaimable space BEFORE:"
docker system df || true

if [ "$INCLUDE_VOLUMES" -eq 1 ]; then
  run docker system prune -a --volumes -f
else
  run docker system prune -a -f
fi

echo
echo "Space AFTER:"
[ "$DRY_RUN" -eq 0 ] && docker system df || echo "  (dry-run: nothing removed)"
