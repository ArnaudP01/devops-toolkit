#!/usr/bin/env python3
"""Audit a domain's DNS health with a tiny built-in DNS client (stdlib only, no dig needed).

Two checks:

  ns    Ask every authoritative name server for the zone's SOA, directly and without
        recursion. Catches the classic "it works from here but not from there" bugs:
        a secondary that answers REFUSED (zone never created on it), a lame delegation
        (server not authoritative) or SOA serials out of sync (zone transfers stuck).

  mail  Check the records that decide whether a domain's e-mail is delivered or spoofed:
        MX, SPF (one record, sane `all`, <= 10 DNS lookups), DMARC policy and optional
        DKIM selectors.

Usage:
  python dns/dns_audit.py ns example.com
  python dns/dns_audit.py mail example.com --dkim-selector default --dkim-selector google
  python dns/dns_audit.py mail example.com --resolver 9.9.9.9

Exit code: 0 all good, 1 warnings only, 2 at least one failure.
"""
from __future__ import annotations

import argparse
import random
import re
import socket
import struct
import sys
from dataclasses import dataclass, field

# Record types we know how to decode.
TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_MX, TYPE_TXT, TYPE_AAAA = 1, 2, 5, 6, 15, 16, 28
TYPE_NAMES = {"A": TYPE_A, "AAAA": TYPE_AAAA, "CNAME": TYPE_CNAME, "NS": TYPE_NS,
              "SOA": TYPE_SOA, "MX": TYPE_MX, "TXT": TYPE_TXT}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

OK, WARN, FAIL = "OK", "WARN", "FAIL"


# --------------------------------------------------------------------------- DNS wire format
@dataclass
class Response:
    rcode: int
    authoritative: bool
    truncated: bool
    answers: list[tuple[int, object]] = field(default_factory=list)

    @property
    def status(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}")

    def values(self, rtype: int) -> list:
        return [v for t, v in self.answers if t == rtype]


def build_query(name: str, qtype: int, recursion: bool = True, qid: int | None = None) -> bytes:
    """Encode a single-question DNS query."""
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    flags = 0x0100 if recursion else 0x0000  # RD bit
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("idna") for label in name.rstrip(".").split(".") if label
    ) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)  # class IN


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) domain name. Returns (name, offset after the name)."""
    labels: list[str] = []
    jumped_end = None
    for _ in range(128):  # guard against pointer loops
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if jumped_end is None:
                jumped_end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length == 0:
            return ".".join(labels), (jumped_end if jumped_end is not None else offset + 1)
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    raise ValueError("DNS name compression loop")


def _decode_rdata(data: bytes, rtype: int, start: int, length: int) -> object:
    rdata = data[start : start + length]
    if rtype == TYPE_A:
        return socket.inet_ntoa(rdata)
    if rtype == TYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (TYPE_NS, TYPE_CNAME):
        return read_name(data, start)[0]
    if rtype == TYPE_MX:
        return struct.unpack("!H", rdata[:2])[0], read_name(data, start + 2)[0]
    if rtype == TYPE_SOA:
        mname, off = read_name(data, start)
        rname, off = read_name(data, off)
        serial = struct.unpack("!I", data[off : off + 4])[0]
        return {"mname": mname, "rname": rname, "serial": serial}
    if rtype == TYPE_TXT:  # one record = several <len><bytes> strings, joined
        parts, i = [], 0
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1 : i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    return rdata


def parse_response(data: bytes) -> Response:
    _qid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    resp = Response(rcode=flags & 0x000F, authoritative=bool(flags & 0x0400),
                    truncated=bool(flags & 0x0200))
    offset = 12
    for _ in range(qdcount):
        _, offset = read_name(data, offset)
        offset += 4
    for _ in range(ancount):
        _, offset = read_name(data, offset)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        resp.answers.append((rtype, _decode_rdata(data, rtype, offset, rdlen)))
        offset += rdlen
    return resp


def query(name: str, qtype: int, server: str, recursion: bool = True,
          timeout: float = 3.0) -> Response:
    """Send one query over UDP, retry over TCP if the answer is truncated."""
    packet = build_query(name, qtype, recursion)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(4096)
    resp = parse_response(data)
    if resp.truncated:
        with socket.create_connection((server, 53), timeout=timeout) as s:
            s.sendall(struct.pack("!H", len(packet)) + packet)
            size = struct.unpack("!H", _recv_exact(s, 2))[0]
            resp = parse_response(_recv_exact(s, size))
    return resp


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by DNS server")
        buf += chunk
    return buf


# --------------------------------------------------------------------------- pure checks
Finding = tuple[str, str]  # (level, message)


def check_ns_answers(results: dict[str, Response | str]) -> list[Finding]:
    """Evaluate the SOA answer of each authoritative server (or the error it raised)."""
    findings: list[Finding] = []
    serials: dict[str, int] = {}
    primaries: set[str] = set()
    for ns, res in sorted(results.items()):
        if isinstance(res, str):
            findings.append((FAIL, f"{ns}: unreachable ({res})"))
        elif res.rcode != 0:
            hint = " - zone not configured on this server?" if res.status == "REFUSED" else ""
            findings.append((FAIL, f"{ns}: {res.status}{hint}"))
        elif not res.authoritative:
            findings.append((FAIL, f"{ns}: not authoritative for the zone (lame delegation)"))
        elif not res.values(TYPE_SOA):
            findings.append((FAIL, f"{ns}: authoritative answer without SOA record"))
        else:
            soa = res.values(TYPE_SOA)[0]
            serials[ns] = soa["serial"]
            primaries.add(soa["mname"].lower())
            findings.append((OK, f"{ns}: authoritative, serial {serials[ns]}"))
    if len(primaries) > 1:
        # Several DNS providers each run their own primary: serials are not comparable.
        findings.append((WARN, f"servers name {len(primaries)} different primaries "
                               "(multi-provider DNS?) - check both copies of the zone match"))
    elif len(set(serials.values())) > 1:
        findings.append((FAIL, "SOA serials differ between servers - zone transfer lagging or broken"))
    elif serials and len(serials) == len(results):
        findings.append((OK, f"all {len(serials)} servers agree on serial {next(iter(serials.values()))}"))
    if len(results) < 2:
        findings.append((WARN, "fewer than 2 name servers - no redundancy"))
    return findings


# Mechanisms/modifiers that cost a DNS lookup (RFC 7208 section 4.6.4).
SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def spf_mechanism(term: str) -> str:
    """'~include:_spf.example.com' -> 'include', 'a/24' -> 'a', '-all' -> 'all'."""
    return re.split(r"[:=/]", term.lstrip("+-~?").lower(), maxsplit=1)[0]


def check_spf(txt_records: list[str]) -> list[Finding]:
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf:
        return [(FAIL, "SPF: no v=spf1 record - anyone can send as this domain")]
    if len(spf) > 1:
        return [(FAIL, f"SPF: {len(spf)} v=spf1 records - receivers treat this as an error (merge them)")]
    terms = spf[0].split()[1:]
    findings: list[Finding] = [(OK, f"SPF: {spf[0]}")]
    lookups = sum(1 for t in terms if spf_mechanism(t) in SPF_LOOKUP_MECHANISMS)
    if lookups > 10:
        findings.append((FAIL, f"SPF: {lookups} DNS lookups at top level (limit is 10)"))
    elif lookups > 7:
        findings.append((WARN, f"SPF: {lookups}/10 DNS lookups at top level (includes add more)"))
    if any(spf_mechanism(t) == "ptr" for t in terms):
        findings.append((WARN, "SPF: 'ptr' is deprecated (RFC 7208) and slow"))
    all_terms = [t for t in terms if spf_mechanism(t) == "all"]
    has_redirect = any(spf_mechanism(t) == "redirect" for t in terms)
    if not all_terms and not has_redirect:
        findings.append((WARN, "SPF: no 'all' mechanism - unlisted senders are not rejected"))
    elif all_terms:
        qualifier = all_terms[-1][0] if all_terms[-1][0] in "+-~?" else "+"
        if qualifier == "+":
            findings.append((FAIL, "SPF: '+all' authorizes every server on the Internet"))
        elif qualifier == "?":
            findings.append((WARN, "SPF: '?all' is neutral - spoofed mail is not flagged"))
    return findings


def parse_tags(record: str) -> dict[str, str]:
    """Parse 'k=v; k2=v2' (DMARC / DKIM) into a dict with lowercase keys."""
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(txt_records: list[str]) -> list[Finding]:
    dmarc = [t for t in txt_records if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not dmarc:
        return [(WARN, "DMARC: no record at _dmarc - no policy, no reports")]
    if len(dmarc) > 1:
        return [(FAIL, f"DMARC: {len(dmarc)} records - receivers ignore all of them")]
    tags = parse_tags(dmarc[0])
    policy = tags.get("p", "").lower()
    findings: list[Finding] = [(OK, f"DMARC: {dmarc[0]}")]
    if policy not in ("none", "quarantine", "reject"):
        findings.append((FAIL, f"DMARC: invalid or missing policy p={policy or '?'}"))
    elif policy == "none":
        findings.append((WARN, "DMARC: p=none only monitors - move to quarantine/reject once reports are clean"))
    if "rua" not in tags:
        findings.append((WARN, "DMARC: no rua= address - you will not receive aggregate reports"))
    return findings


def check_dkim(selector: str, txt_records: list[str]) -> list[Finding]:
    keys = [t for t in txt_records if "p=" in t.replace(" ", "")]
    if not keys:
        return [(FAIL, f"DKIM {selector}: no key published")]
    tags = parse_tags(keys[0])
    if not tags.get("p"):
        return [(FAIL, f"DKIM {selector}: key revoked (empty p=)")]
    return [(OK, f"DKIM {selector}: {tags.get('k', 'rsa')} key published ({len(tags['p'])} base64 chars)")]


def check_mx(mx_records: list[tuple[int, str]]) -> list[Finding]:
    if not mx_records:
        return [(WARN, "MX: none - the domain cannot receive e-mail")]
    listed = ", ".join(f"{prio} {host}" for prio, host in sorted(mx_records))
    return [(OK, f"MX: {listed}")]


# --------------------------------------------------------------------------- commands
def run_ns(domain: str, resolver: str, timeout: float) -> list[Finding]:
    ns_hosts = query(domain, TYPE_NS, resolver, timeout=timeout).values(TYPE_NS)
    if not ns_hosts:
        return [(FAIL, f"no NS records found for {domain}")]
    results: dict[str, Response | str] = {}
    for ns in ns_hosts:
        try:
            ip = socket.gethostbyname(ns)
            results[ns] = query(domain, TYPE_SOA, ip, recursion=False, timeout=timeout)
        except (OSError, ValueError) as exc:
            results[ns] = exc.__class__.__name__ if not str(exc) else str(exc)
    return check_ns_answers(results)


def run_mail(domain: str, resolver: str, timeout: float, selectors: list[str]) -> list[Finding]:
    def txt(name: str) -> list[str]:
        return query(name, TYPE_TXT, resolver, timeout=timeout).values(TYPE_TXT)

    findings = check_mx(query(domain, TYPE_MX, resolver, timeout=timeout).values(TYPE_MX))
    findings += check_spf(txt(domain))
    findings += check_dmarc(txt(f"_dmarc.{domain}"))
    for sel in selectors:
        findings += check_dkim(sel, txt(f"{sel}._domainkey.{domain}"))
    return findings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit a domain's name servers or mail DNS records.")
    p.add_argument("check", choices=("ns", "mail"), help="what to audit")
    p.add_argument("domain")
    p.add_argument("--resolver", default="1.1.1.1", help="recursive resolver to use (default 1.1.1.1)")
    p.add_argument("--timeout", type=float, default=3.0, help="seconds per query (default 3)")
    p.add_argument("--dkim-selector", action="append", default=[], metavar="SEL",
                   help="DKIM selector to check (repeatable), e.g. default, google, selector1")
    args = p.parse_args(argv)

    try:
        if args.check == "ns":
            findings = run_ns(args.domain, args.resolver, args.timeout)
        else:
            findings = run_mail(args.domain, args.resolver, args.timeout, args.dkim_selector)
    except (OSError, ValueError) as exc:
        print(f"query failed via {args.resolver}: {exc}", file=sys.stderr)
        return 2

    for level, message in findings:
        print(f"[{level:4}] {message}")
    levels = {level for level, _ in findings}
    return 2 if FAIL in levels else 1 if WARN in levels else 0


if __name__ == "__main__":
    sys.exit(main())
