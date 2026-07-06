#!/usr/bin/env python3
"""List the largest files under a directory tree."""
import argparse
from pathlib import Path


def largest_files(root: Path, limit: int = 20) -> list[tuple[int, Path]]:
    files: list[tuple[int, Path]] = []
    for entry in root.rglob("*"):
        if entry.is_file():
            try:
                files.append((entry.stat().st_size, entry))
            except OSError:
                continue
    files.sort(reverse=True)
    return files[:limit]


def human(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def main() -> None:
    p = argparse.ArgumentParser(description="Find the largest files in a directory.")
    p.add_argument("directory", type=Path)
    p.add_argument("-n", "--limit", type=int, default=20)
    args = p.parse_args()
    if not args.directory.is_dir():
        p.error(f"not a directory: {args.directory}")

    for size, path in largest_files(args.directory, args.limit):
        print(f"{human(size):>10}  {path}")


if __name__ == "__main__":
    main()
