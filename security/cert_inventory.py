#!/usr/bin/env python3
"""Inventory the TLS certificates of many hosts: who expires first, who is broken.

The multi-host big brother of ssl-cert-check.sh. For each host it connects, reads the
certificate the server really presents and reports, sorted by days left:
  - days until expiry       (WARN under --warn days, FAIL under --crit or expired)
  - whether the hostname is covered by the certificate's names (SAN)
  - whether the chain is trusted by this machine
  - issuer and expiry date

Hosts come from the command line and/or a file (one `host` or `host:port` per line,
`#` comments allowed). Use --json to feed a monitoring system or a dashboard.

Usage:
  python security/cert_inventory.py example.com mail.example.com:465
  python security/cert_inventory.py -f hosts.txt --warn 21 --crit 7 --json

Exit code: 0 all good, 1 warnings only, 2 at least one failure.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass


@dataclass
class CertInfo:
    host: str
    port: int
    level: str = "OK"
    days_left: int | None = None
    not_after: str = ""
    issuer: str = ""
    names: list[str] | None = None
    covered: bool | None = None
    trusted: bool | None = None
    error: str = ""


def parse_target(target: str) -> tuple[str, int]:
    host, _, port = target.strip().partition(":")
    return host, int(port) if port else 443


def name_matches(hostname: str, pattern: str) -> bool:
    """RFC 6125 matching: exact, or a left-most '*' covering exactly one label."""
    hostname, pattern = hostname.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, rest = hostname.partition(".")
        return bool(head) and rest == pattern[2:]
    return hostname == pattern


def cert_names(cert: dict) -> list[str]:
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if sans:
        return sans
    return [v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"]


def issuer_name(cert: dict) -> str:
    fields = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    return fields.get("organizationName") or fields.get("commonName", "")


def classify(info: CertInfo, warn: int, crit: int) -> str:
    if info.error and info.days_left is None:
        return "FAIL"
    if info.days_left is not None and info.days_left < crit:
        return "FAIL"
    if info.covered is False or info.trusted is False:
        return "FAIL"
    if info.days_left is not None and info.days_left < warn:
        return "WARN"
    return "OK"


def _decode_der(der: bytes) -> dict:
    """Decode a certificate that failed verification (stdlib has no public DER parser)."""
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path)  # stable private helper
    finally:
        os.unlink(path)


def inspect(host: str, port: int, timeout: float = 8.0, now: float | None = None) -> CertInfo:
    info = CertInfo(host, port)
    cert: dict = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # we check names ourselves, to report rather than abort
        with socket.create_connection((host, port), timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
        info.trusted = True
    except ssl.SSLCertVerificationError as exc:
        info.trusted = False
        info.error = exc.verify_message or str(exc)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with socket.create_connection((host, port), timeout) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = _decode_der(tls.getpeercert(binary_form=True))
        except (OSError, ValueError, AttributeError) as exc2:
            info.error += f"; could not read certificate: {exc2}"
            return info
    except (OSError, ValueError) as exc:
        info.error = f"{exc.__class__.__name__}: {exc}"
        return info

    info.not_after = cert.get("notAfter", "")
    if info.not_after:
        expires = ssl.cert_time_to_seconds(info.not_after)
        info.days_left = int((expires - (now or time.time())) // 86400)
    info.names = cert_names(cert)
    info.covered = any(name_matches(host, n) for n in info.names)
    info.issuer = issuer_name(cert)
    return info


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Inventory TLS certificates across many hosts.")
    p.add_argument("targets", nargs="*", help="host or host:port")
    p.add_argument("-f", "--file", help="file with one host[:port] per line")
    p.add_argument("--warn", type=int, default=21, help="warn under N days (default 21)")
    p.add_argument("--crit", type=int, default=7, help="fail under N days (default 7)")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    targets = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets += [ln.split("#")[0].strip() for ln in fh if ln.split("#")[0].strip()]
    if not targets:
        p.error("give at least one host, or -f FILE")

    def run(t: str) -> CertInfo:
        info = inspect(*parse_target(t), timeout=args.timeout)
        info.level = classify(info, args.warn, args.crit)
        return info

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        infos = list(pool.map(run, dict.fromkeys(targets)))
    infos.sort(key=lambda i: (i.days_left is not None, i.days_left if i.days_left is not None else 0))

    if args.json:
        print(json.dumps([asdict(i) for i in infos], indent=2))
    else:
        print(f"{'LEVEL':5} {'DAYS':>5}  {'HOST':40} {'ISSUER':24} NOTES")
        for i in infos:
            notes = []
            if i.covered is False:
                notes.append("name not covered")
            if i.error:
                notes.append(i.error)
            days = "-" if i.days_left is None else str(i.days_left)
            print(f"{i.level:5} {days:>5}  {i.host + ':' + str(i.port):40} {i.issuer[:24]:24} {'; '.join(notes)}")
    levels = {i.level for i in infos}
    return 2 if "FAIL" in levels else 1 if "WARN" in levels else 0


if __name__ == "__main__":
    sys.exit(main())
