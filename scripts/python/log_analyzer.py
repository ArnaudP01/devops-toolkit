#!/usr/bin/env python3
"""Summarize an access log: top client IPs and HTTP status-code distribution.

Tolerant regex parse of a Common-Log-Format-ish line; lines it cannot parse are skipped.
"""
import argparse
import re
from collections import Counter
from pathlib import Path

# 1.2.3.4 - - [17/Jul/2008:...] "GET /path HTTP/1.1" 200 1234
LINE = re.compile(r'^(?P<ip>\S+).*?"\S+ \S+ \S+" (?P<status>\d{3}) ')


def analyze(path: Path) -> tuple[Counter, Counter]:
    ips: Counter = Counter()
    statuses: Counter = Counter()
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE.search(line)
            if not m:
                continue
            ips[m["ip"]] += 1
            statuses[m["status"]] += 1
    return ips, statuses


def main() -> None:
    p = argparse.ArgumentParser(description="Summarize an access log.")
    p.add_argument("logfile", type=Path)
    p.add_argument("--top", type=int, default=10)
    args = p.parse_args()
    if not args.logfile.is_file():
        p.error(f"file not found: {args.logfile}")

    ips, statuses = analyze(args.logfile)
    total = sum(statuses.values())
    print(f"Parsed {total} request(s).\n")

    print(f"Top {args.top} client IPs:")
    for ip, count in ips.most_common(args.top):
        print(f"  {count:>7}  {ip}")

    print("\nStatus codes:")
    for status in sorted(statuses):
        print(f"  {status}: {statuses[status]}")


if __name__ == "__main__":
    main()
