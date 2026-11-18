#!/usr/bin/env python3
"""Compare a website on its old and new server *before* switching DNS.

Each URL path is requested twice - once from the old IP, once from the new IP - with the
real Host header and TLS SNI, exactly as a browser will after the DNS change. Redirects
are not followed, so a broken rewrite rule shows up as a different status or Location.

Compared per path:
  status code  (FAIL if different)   e.g. 200 on old, 404 on new: missing rewrite rules
  Location     (FAIL if different)   redirect loops, http/https or www mix-ups
  <title>      (WARN if different)   a default page or an error page served instead
  body size    (WARN if > --size-tolerance %, default 20)

The new server often has no valid certificate yet (it cannot get one before the DNS
switch): certificate errors are reported once and the comparison continues unverified.

Usage:
  python web/migration_check.py example.com --old 203.0.113.10 --new 198.51.100.20
  python web/migration_check.py example.com --old 203.0.113.10 --new 198.51.100.20 \\
      --paths / /contact /wp-login.php --sitemap --limit 200

Exit code: 0 identical, 1 warnings only, 2 at least one failure.
"""
from __future__ import annotations

import argparse
import http.client
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
LOC_RE = re.compile(rb"<loc>\s*(.*?)\s*</loc>", re.I | re.S)
OK, WARN, FAIL = "OK", "WARN", "FAIL"


@dataclass
class Page:
    status: int = 0
    location: str = ""
    title: str = ""
    size: int = 0
    error: str = ""
    cert_error: str = ""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed IP while sending SNI/Host for the real hostname."""

    def __init__(self, host: str, ip: str, port: int, context: ssl.SSLContext, timeout: float):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def fetch(host: str, ip: str, path: str, scheme: str = "https", timeout: float = 10.0,
          max_body: int = 5_000_000) -> Page:
    """GET one path from one IP, without following redirects."""
    page = Page()
    contexts = [ssl.create_default_context()]
    if scheme == "https":
        unverified = ssl.create_default_context()
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        contexts.append(unverified)
    for ctx in contexts:
        if scheme == "https":
            conn = _PinnedHTTPSConnection(host, ip, 443, ctx, timeout)
        else:
            conn = _PinnedHTTPConnection(host, ip, 80, timeout)
        try:
            conn.request("GET", path, headers={"Host": host, "User-Agent": "migration-check/1.0",
                                               "Accept-Encoding": "identity"})
            resp = conn.getresponse()
            body = resp.read(max_body)
            page.status = resp.status
            page.location = resp.getheader("Location", "") or ""
            page.size = len(body)
            match = TITLE_RE.search(body)
            if match:
                page.title = " ".join(match.group(1).decode("utf-8", "replace").split())[:120]
            return page
        except ssl.SSLCertVerificationError as exc:
            page.cert_error = exc.verify_message or str(exc)
        except (OSError, http.client.HTTPException) as exc:
            page.error = f"{exc.__class__.__name__}: {exc}"
            return page
        finally:
            conn.close()
    return page


def normalize_location(location: str, host: str) -> str:
    """Make 'https://host/a' and '/a' comparable."""
    parts = urlsplit(location)
    if parts.netloc.lower() == host.lower():
        return parts.path + (f"?{parts.query}" if parts.query else "")
    return location


def compare(path: str, old: Page, new: Page, host: str, size_tolerance: float) -> list[tuple[str, str]]:
    """Return (level, message) findings for one path."""
    if old.error or new.error:
        if old.error and new.error:
            return [(WARN, f"{path}: unreachable on both servers")]
        side, err = ("old", old.error) if old.error else ("new", new.error)
        return [(FAIL, f"{path}: {side} server error - {err}")]
    findings = []
    if old.status != new.status:
        findings.append((FAIL, f"{path}: status {old.status} -> {new.status}"))
    if normalize_location(old.location, host) != normalize_location(new.location, host):
        findings.append((FAIL, f"{path}: redirect '{old.location}' -> '{new.location}'"))
    if old.title != new.title:
        findings.append((WARN, f"{path}: title '{old.title}' -> '{new.title}'"))
    if old.size and abs(new.size - old.size) / old.size * 100 > size_tolerance:
        findings.append((WARN, f"{path}: size {old.size} -> {new.size} bytes"))
    return findings or [(OK, f"{path}: {new.status} {new.title or ''}".rstrip())]


def sitemap_paths(xml: bytes, host: str) -> list[str]:
    """Extract same-host paths from a sitemap (or sitemap index) document."""
    paths = []
    for raw in LOC_RE.findall(xml):
        url = urlsplit(raw.decode("utf-8", "replace").strip())
        if url.netloc.lower() in (host.lower(), "") and url.path:
            paths.append(url.path + (f"?{url.query}" if url.query else ""))
    return paths


def discover_from_sitemap(host: str, ip: str, scheme: str, timeout: float, limit: int) -> list[str]:
    """Read /sitemap.xml from the old server; follow one level of sitemap index."""
    found: list[str] = []
    queue = ["/sitemap.xml"]
    seen = set()
    while queue and len(found) < limit:
        sm = queue.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        body = _fetch_body(host, ip, sm, scheme, timeout)
        for p in sitemap_paths(body, host):
            if p.endswith(".xml"):
                queue.append(p)
            elif p not in found:
                found.append(p)
    return found[:limit]


def _fetch_body(host: str, ip: str, path: str, scheme: str, timeout: float) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    conn = (_PinnedHTTPSConnection(host, ip, 443, ctx, timeout) if scheme == "https"
            else _PinnedHTTPConnection(host, ip, 80, timeout))
    try:
        conn.request("GET", path, headers={"Host": host, "Accept-Encoding": "identity"})
        resp = conn.getresponse()
        return resp.read(10_000_000) if resp.status == 200 else b""
    except (OSError, http.client.HTTPException):
        return b""
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compare a site on its old and new server before a DNS switch.")
    p.add_argument("host", help="site hostname, e.g. www.example.com")
    p.add_argument("--old", required=True, help="IP of the current server")
    p.add_argument("--new", required=True, help="IP of the new server")
    p.add_argument("--paths", nargs="*", default=["/"], help="paths to compare (default: /)")
    p.add_argument("--paths-file", help="file with one path per line")
    p.add_argument("--sitemap", action="store_true", help="also compare every URL of /sitemap.xml (old server)")
    p.add_argument("--limit", type=int, default=100, help="max sitemap URLs (default 100)")
    p.add_argument("--scheme", choices=("https", "http"), default="https")
    p.add_argument("--size-tolerance", type=float, default=20.0, help="size difference %% that warns (default 20)")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--quiet", action="store_true", help="only print differences")
    args = p.parse_args(argv)

    paths = list(args.paths)
    if args.paths_file:
        with open(args.paths_file, encoding="utf-8") as fh:
            paths += [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    if args.sitemap:
        paths += discover_from_sitemap(args.host, args.old, args.scheme, args.timeout, args.limit)
    paths = list(dict.fromkeys(paths))  # dedupe, keep order

    def both(path: str) -> tuple[str, Page, Page]:
        return (path, fetch(args.host, args.old, path, args.scheme, args.timeout),
                fetch(args.host, args.new, path, args.scheme, args.timeout))

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(both, paths))

    cert_notes = {(side, pg.cert_error) for _, o, n in results for side, pg in (("old", o), ("new", n))
                  if pg.cert_error}
    for side, err in sorted(cert_notes):
        print(f"[NOTE] {side} server certificate not valid for {args.host}: {err} (compared unverified)")

    levels = set()
    for path, old, new in results:
        for level, message in compare(path, old, new, args.host, args.size_tolerance):
            levels.add(level)
            if not (args.quiet and level == OK):
                print(f"[{level:4}] {message}")
    print(f"\n{len(results)} path(s) compared: {args.old} (old) vs {args.new} (new)")
    return 2 if FAIL in levels else 1 if WARN in levels else 0


if __name__ == "__main__":
    sys.exit(main())
