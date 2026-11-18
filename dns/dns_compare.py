#!/usr/bin/env python3
"""Compare a zone's records on two name servers before you switch NS (or move DNS host).

Zone transfers (AXFR) are usually locked down, so this asks both servers - directly,
without recursion - the same questions for a list of names and record types, and prints
every difference. Run it after copying a zone to a new DNS provider and before changing
the delegation at the registrar: whatever shows up here is what would break.

Default names: @ www mail webmail autodiscover ftp _dmarc  (+ --names, --names-file)
Default types: A AAAA CNAME MX TXT NS                    (--types to change)
SOA is skipped on purpose: serials differ between providers by design.

Usage:
  python dns/dns_compare.py example.com --old ns1.oldhost.net --new ns1.newhost.com
  python dns/dns_compare.py example.com --old 192.0.2.53 --new 198.51.100.53 \\
      --names shop api default._domainkey --types A CNAME TXT

Exit code: 0 identical, 1 differences found, 2 a server refused or failed to answer.
"""
from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dns_audit  # noqa: E402  (shared stdlib DNS client)

DEFAULT_NAMES = ["@", "www", "mail", "webmail", "autodiscover", "ftp", "_dmarc"]
DEFAULT_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
TYPE_LABELS = {v: k for k, v in dns_audit.TYPE_NAMES.items()}

RecordSet = dict[tuple[str, str], set[str]]  # (fqdn, TYPE) -> values


def fqdn(name: str, zone: str) -> str:
    zone = zone.rstrip(".")
    if name in ("@", ""):
        return zone
    name = name.rstrip(".")
    return name if name == zone or name.endswith("." + zone) else f"{name}.{zone}"


def format_value(rtype: int, value: object) -> str:
    """Canonical text for one record so both servers' answers compare equal."""
    if rtype == dns_audit.TYPE_MX:
        prio, host = value
        return f"{prio} {host.lower().rstrip('.')}"
    if rtype in (dns_audit.TYPE_CNAME, dns_audit.TYPE_NS):
        return str(value).lower().rstrip(".")
    if rtype == dns_audit.TYPE_TXT:
        return f'"{value}"'
    return str(value)


def answers_to_set(resp: dns_audit.Response) -> set[str]:
    return {f"{TYPE_LABELS.get(t, t)} {format_value(t, v)}" for t, v in resp.answers
            if t != dns_audit.TYPE_SOA}


def diff(old: RecordSet, new: RecordSet) -> list[str]:
    """Human-readable lines for every (name, type) whose answers differ."""
    lines = []
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key, set()), new.get(key, set())
        if a == b:
            continue
        name, rtype = key
        lines.append(f"{name} {rtype}")
        lines += [f"    - {v}   (only on old)" for v in sorted(a - b)]
        lines += [f"    + {v}   (only on new)" for v in sorted(b - a)]
    return lines


def collect(server_ip: str, names: list[str], types: list[str], zone: str,
            timeout: float) -> tuple[RecordSet, list[str]]:
    records: RecordSet = {}
    errors: list[str] = []
    for name in names:
        host = fqdn(name, zone)
        for t in types:
            resp = None
            for _ in range(3):  # UDP gets lost now and then: retry before blaming the server
                try:
                    resp = dns_audit.query(host, dns_audit.TYPE_NAMES[t], server_ip,
                                           recursion=False, timeout=timeout)
                    break
                except (OSError, ValueError) as exc:
                    last_error = exc.__class__.__name__
            if resp is None:
                errors.append(f"{host} {t}: {last_error} (3 attempts)")
                continue
            if resp.rcode not in (0, 3):  # NOERROR / NXDOMAIN are both valid answers
                errors.append(f"{host} {t}: {resp.status}")
                continue
            records[(host, t)] = answers_to_set(resp)
    return records, errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Diff a zone's records between two name servers.")
    p.add_argument("zone", help="zone name, e.g. example.com")
    p.add_argument("--old", required=True, help="current name server (hostname or IP)")
    p.add_argument("--new", required=True, help="new name server (hostname or IP)")
    p.add_argument("--names", nargs="*", default=[], help="extra names to compare (relative or FQDN)")
    p.add_argument("--names-file", help="file with one name per line")
    p.add_argument("--types", nargs="*", default=DEFAULT_TYPES, choices=sorted(set(DEFAULT_TYPES) | {"SOA"}))
    p.add_argument("--timeout", type=float, default=3.0)
    args = p.parse_args(argv)

    names = DEFAULT_NAMES + args.names
    if args.names_file:
        names += Path(args.names_file).read_text(encoding="utf-8").split()
    names = list(dict.fromkeys(names))

    try:
        old_ip, new_ip = socket.gethostbyname(args.old), socket.gethostbyname(args.new)
    except OSError as exc:
        p.error(f"cannot resolve server: {exc}")

    old, old_err = collect(old_ip, names, args.types, args.zone, args.timeout)
    new, new_err = collect(new_ip, names, args.types, args.zone, args.timeout)
    for side, errs in (("old", old_err), ("new", new_err)):
        for e in errs:
            print(f"[ERROR] {side}: {e}")

    lines = diff(old, new)
    print("\n".join(lines) if lines else "No differences.")
    print(f"\n{len(names)} names x {len(args.types)} types compared: "
          f"{args.old} ({old_ip}) vs {args.new} ({new_ip})")
    if old_err or new_err:
        return 2
    return 1 if lines else 0


if __name__ == "__main__":
    sys.exit(main())
