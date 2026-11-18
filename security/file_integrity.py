#!/usr/bin/env python3
"""Take a fingerprint of a directory tree, then report what was added, removed or changed.

Typical use: right after cleaning a hacked site (or deploying a release), record a
baseline. Later - from cron, or when something feels off - check the tree against it:
a new .php file in a theme or a modified core file shows up immediately.

  init   hash every file (SHA-256) and write the manifest (JSON)
  check  compare the tree with a manifest; list added / removed / modified files

Keep the manifest *outside* the tree you watch (an attacker who can write the site can
rewrite a manifest stored next to it), and exclude folders that change by design.

Usage:
  python security/file_integrity.py init  /var/www/site -o ~/site.manifest.json \\
      --exclude "wp-content/uploads/*" --exclude "*/cache/*"
  python security/file_integrity.py check /var/www/site ~/site.manifest.json

Exit code: 0 unchanged, 1 changes found, 2 usage error.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import time
from pathlib import Path

CHUNK = 1024 * 1024


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in patterns)


def fingerprint(root: Path, exclude: list[str] | None = None) -> dict[str, dict]:
    """Map relative POSIX path -> {sha256, size, mode} for every regular file."""
    exclude = exclude or []
    files: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if excluded(rel, exclude) or not path.is_file() or path.is_symlink():
                continue
            st = path.stat()
            files[rel] = {"sha256": sha256(path), "size": st.st_size, "mode": oct(st.st_mode & 0o7777)}
    return files


def compare(baseline: dict[str, dict], current: dict[str, dict]) -> dict[str, list[str]]:
    common = baseline.keys() & current.keys()
    return {
        "added": sorted(current.keys() - baseline.keys()),
        "removed": sorted(baseline.keys() - current.keys()),
        "modified": sorted(p for p in common if baseline[p]["sha256"] != current[p]["sha256"]),
        "mode_changed": sorted(p for p in common if baseline[p]["sha256"] == current[p]["sha256"]
                               and baseline[p]["mode"] != current[p]["mode"]),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fingerprint a directory tree and detect changes.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("init", help="write a manifest for ROOT")
    pi.add_argument("root", type=Path)
    pi.add_argument("-o", "--output", type=Path, required=True, help="manifest file to write")
    pi.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="relative path pattern to skip (repeatable)")
    pc = sub.add_parser("check", help="compare ROOT with a manifest")
    pc.add_argument("root", type=Path)
    pc.add_argument("manifest", type=Path)
    pc.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    if not args.root.is_dir():
        p.error(f"not a directory: {args.root}")

    if args.cmd == "init":
        files = fingerprint(args.root, args.exclude)
        manifest = {"root": str(args.root.resolve()), "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "exclude": args.exclude, "files": files}
        args.output.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        print(f"{len(files)} files fingerprinted -> {args.output}")
        return 0

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    changes = compare(manifest["files"], fingerprint(args.root, manifest.get("exclude", [])))
    total = sum(len(v) for v in changes.values())
    if args.json:
        print(json.dumps(changes, indent=2))
    else:
        for kind, paths in changes.items():
            for path in paths:
                print(f"{kind.upper():12} {path}")
        print(f"\n{total} change(s) since baseline of {manifest.get('created', '?')}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
