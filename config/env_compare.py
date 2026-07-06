#!/usr/bin/env python3
"""Compare two .env files and report keys that are missing or extra.

Exit code: 0 if the key sets are identical, 1 if they differ.
"""
import argparse
import sys
from pathlib import Path


def parse_env(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip()
    return data


def main() -> int:
    p = argparse.ArgumentParser(description="Diff two .env files by key.")
    p.add_argument("file_a", type=Path)
    p.add_argument("file_b", type=Path)
    args = p.parse_args()
    for f in (args.file_a, args.file_b):
        if not f.is_file():
            p.error(f"file not found: {f}")

    a = parse_env(args.file_a)
    b = parse_env(args.file_b)
    only_a = set(a) - set(b)
    only_b = set(b) - set(a)

    print(f"Keys only in {args.file_a.name}: {sorted(only_a) or 'none'}")
    print(f"Keys only in {args.file_b.name}: {sorted(only_b) or 'none'}")
    return 0 if not (only_a or only_b) else 1


if __name__ == "__main__":
    sys.exit(main())
