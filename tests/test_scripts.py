"""Unit tests for the Python scripts (imported as modules via conftest)."""

import string
from pathlib import Path

import disk_top
import env_compare
import log_analyzer
import password_gen
import port_scanner


# --- password_gen -----------------------------------------------------------
def test_password_length():
    assert len(password_gen.generate(length=24)) == 24


def test_password_has_uppercase_and_symbols_by_default():
    pw = password_gen.generate(length=60)
    assert any(c.isupper() for c in pw)
    assert any(c in password_gen.SYMBOLS for c in pw)


def test_password_no_uppercase():
    pw = password_gen.generate(length=60, uppercase=False)
    assert not any(c.isupper() for c in pw)
    assert any(c in string.digits for c in pw)  # still has digits


# --- env_compare ------------------------------------------------------------
def test_parse_env_ignores_comments_and_blanks(tmp_path: Path):
    f = tmp_path / "a.env"
    f.write_text("# comment\n\nKEY1=value1\nKEY2 = value2\n")
    assert env_compare.parse_env(f) == {"KEY1": "value1", "KEY2": "value2"}


def test_env_diff_logic(tmp_path: Path):
    a = tmp_path / "a.env"
    b = tmp_path / "b.env"
    a.write_text("A=1\nB=2\nC=3\n")
    b.write_text("A=1\nB=2\nD=4\n")
    keys_a = set(env_compare.parse_env(a))
    keys_b = set(env_compare.parse_env(b))
    assert keys_a - keys_b == {"C"}
    assert keys_b - keys_a == {"D"}


# --- log_analyzer -----------------------------------------------------------
def test_log_analyzer_counts(tmp_path: Path):
    log = tmp_path / "access.log"
    log.write_text(
        '1.2.3.4 - - [10/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
        '1.2.3.4 - - [10/Jul/2026:12:00:01 +0000] "GET /a HTTP/1.1" 200 1234\n'
        '5.6.7.8 - - [10/Jul/2026:12:00:02 +0000] "POST /b HTTP/1.1" 500 1234\n'
        "this line does not match and is skipped\n"
    )
    ips, statuses = log_analyzer.analyze(log)
    assert sum(statuses.values()) == 3
    assert ips.most_common(1)[0] == ("1.2.3.4", 2)
    assert statuses["200"] == 2
    assert statuses["500"] == 1


# --- disk_top ---------------------------------------------------------------
def test_disk_top_orders_by_size(tmp_path: Path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 10_000)
    small = tmp_path / "small.bin"
    small.write_bytes(b"y" * 10)
    result = disk_top.largest_files(tmp_path, limit=10)
    assert result[0][1] == big
    assert result[0][0] == 10_000
    assert all(isinstance(size, int) for size, _ in result)


# --- port_scanner -----------------------------------------------------------
def test_port_scanner_closed_port():
    # Port 1 on loopback is virtually always closed/refused on CI runners.
    assert port_scanner.is_open("127.0.0.1", 1, timeout=0.2) is False


# --- dns_audit --------------------------------------------------------------
import struct  # noqa: E402

import dns_audit  # noqa: E402


def _name(n: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def _rr(rtype: int, rdata: bytes) -> bytes:
    # owner = pointer to the question name at offset 12
    return b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata


def _response(answers: list, rcode: int = 0, aa: bool = True) -> bytes:
    flags = 0x8000 | (0x0400 if aa else 0) | rcode
    header = struct.pack("!HHHHHH", 1, flags, 1, len(answers), 0, 0)
    question = _name("example.com") + struct.pack("!HH", 6, 1)
    return header + question + b"".join(answers)


def test_build_query_encodes_name_and_flags():
    q = dns_audit.build_query("example.com", dns_audit.TYPE_SOA, recursion=False, qid=7)
    assert q[:4] == struct.pack("!HH", 7, 0)  # id, RD bit off
    assert q[12:] == _name("example.com") + struct.pack("!HH", 6, 1)


def test_parse_soa_with_name_compression():
    rdata = b"\xc0\x0c" + _name("hostmaster.example.com") + struct.pack("!IIIII", 2026111801, 1, 2, 3, 4)
    resp = dns_audit.parse_response(_response([_rr(dns_audit.TYPE_SOA, rdata)]))
    soa = resp.values(dns_audit.TYPE_SOA)[0]
    assert resp.authoritative and resp.status == "NOERROR"
    assert soa["mname"] == "example.com" and soa["serial"] == 2026111801


def test_parse_txt_joins_character_strings():
    rdata = b"\x05v=spf" + b"\x07 -all!!"
    resp = dns_audit.parse_response(_response([_rr(dns_audit.TYPE_TXT, rdata)]))
    assert resp.values(dns_audit.TYPE_TXT) == ["v=spf -all!!"]


def _soa_resp(serial: int, mname: str = "ns1.example.com", rcode: int = 0, aa: bool = True):
    r = dns_audit.Response(rcode=rcode, authoritative=aa, truncated=False)
    if rcode == 0:
        r.answers.append((dns_audit.TYPE_SOA, {"mname": mname, "rname": "h", "serial": serial}))
    return r


def _levels(findings):
    return [lvl for lvl, _ in findings]


def test_ns_all_in_sync():
    f = dns_audit.check_ns_answers({"ns1": _soa_resp(5), "ns2": _soa_resp(5)})
    assert "FAIL" not in _levels(f) and "WARN" not in _levels(f)


def test_ns_refused_secondary_and_serial_mismatch():
    f = dns_audit.check_ns_answers({"ns1": _soa_resp(5), "ns2": _soa_resp(0, rcode=5)})
    assert any("REFUSED" in m for _, m in f)
    f = dns_audit.check_ns_answers({"ns1": _soa_resp(5), "ns2": _soa_resp(4)})
    assert any(lvl == "FAIL" and "serials differ" in m for lvl, m in f)


def test_ns_lame_delegation_and_multi_provider():
    f = dns_audit.check_ns_answers({"ns1": _soa_resp(5), "ns2": _soa_resp(5, aa=False)})
    assert any("lame" in m for _, m in f)
    f = dns_audit.check_ns_answers({"a": _soa_resp(1, "x.net"), "b": _soa_resp(9, "y.org")})
    assert "FAIL" not in _levels(f) and "WARN" in _levels(f)


def test_spf_rules():
    assert _levels(dns_audit.check_spf([])) == ["FAIL"]
    assert "FAIL" in _levels(dns_audit.check_spf(["v=spf1 -all", "v=spf1 mx -all"]))
    assert "FAIL" in _levels(dns_audit.check_spf(["v=spf1 +all"]))
    assert "WARN" in _levels(dns_audit.check_spf(["v=spf1 mx"]))
    assert _levels(dns_audit.check_spf(["google-site-verification=x", "v=spf1 mx a ~all"])) == ["OK"]
    many = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " -all"
    assert "FAIL" in _levels(dns_audit.check_spf([many]))


def test_spf_mechanism_parsing():
    assert dns_audit.spf_mechanism("~include:_spf.example.com") == "include"
    assert dns_audit.spf_mechanism("a/24") == "a"
    assert dns_audit.spf_mechanism("-all") == "all"
    assert dns_audit.spf_mechanism("ip4:1.2.3.4") == "ip4"


def test_dmarc_and_dkim_rules():
    assert _levels(dns_audit.check_dmarc([])) == ["WARN"]
    assert "WARN" in _levels(dns_audit.check_dmarc(["v=DMARC1; p=none; rua=mailto:a@b.c"]))
    assert _levels(dns_audit.check_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.c"])) == ["OK"]
    assert _levels(dns_audit.check_dkim("s1", ["v=DKIM1; k=rsa; p=MIIBIj"])) == ["OK"]
    assert _levels(dns_audit.check_dkim("s1", ["v=DKIM1; p="])) == ["FAIL"]
    assert _levels(dns_audit.check_dkim("s1", [])) == ["FAIL"]


# --- php_malware_scan -------------------------------------------------------
import php_malware_scan as pms  # noqa: E402

# Built by concatenation so this test file itself contains no malware signature.
EVAL_DECODE = "<?php " + "ev" + "al(" + "base64" + "_decode($x)); ?>"
REQUEST_EXEC = "<?php " + "sys" + "tem($" + "_GET['c']); ?>"
REQUEST_FUNC = "<?php $" + "_POST['f']($" + "_POST['a']); ?>"
CLEAN = "<?php\necho 'hello';\n$data = json_decode($raw, true);\n"


def _indicators(findings):
    return {f.indicator for f in findings}


def test_scan_text_flags_classic_backdoors():
    assert "eval-of-decoded-data" in _indicators(pms.scan_text("a.php", EVAL_DECODE))
    assert "request-data-executed" in _indicators(pms.scan_text("a.php", REQUEST_EXEC))
    assert "request-data-as-function" in _indicators(pms.scan_text("a.php", REQUEST_FUNC))


def test_scan_text_clean_file_and_offscreen_code():
    assert pms.scan_text("ok.php", CLEAN) == []
    padded = "<?php" + " " * 300 + "$a=1;"
    assert "code-pushed-off-screen" in _indicators(pms.scan_text("p.php", padded))


def test_scan_text_obfuscation():
    blob = "<?php $p = '" + "QUJD" * 150 + "';"
    assert "long-base64-blob" in _indicators(pms.scan_text("b.php", blob))
    chain = "<?php $f = " + ".".join(["chr(101)"] * 10) + ";"
    assert "chr-chain" in _indicators(pms.scan_text("c.php", chain))


def test_scan_tree_location_rules(tmp_path: Path):
    (tmp_path / "wp-content" / "uploads" / "2026").mkdir(parents=True)
    (tmp_path / "wp-content" / "uploads" / "2026" / "x.php").write_text(CLEAN)
    (tmp_path / "favicon.ico").write_bytes(b"\x00\x00" + EVAL_DECODE.encode())
    (tmp_path / ".cache.php").write_text(CLEAN)
    (tmp_path / "index.php").write_text(CLEAN)
    found = {(f.path.replace("\\", "/"), f.indicator) for f in pms.scan_tree(tmp_path)}
    assert ("wp-content/uploads/2026/x.php", "php-file-in-upload-or-media-folder") in found
    assert ("favicon.ico", "php-code-in-image-file") in found
    assert (".cache.php", "hidden-php-file") in found
    assert not any(p == "index.php" for p, _ in found)


def test_main_exit_codes(tmp_path: Path, capsys):
    (tmp_path / "index.php").write_text(CLEAN)
    assert pms.main([str(tmp_path)]) == 0
    # A clean file in uploads/ is enough to trigger a high finding (no AV-bait on disk).
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "x.php").write_text(CLEAN)
    assert pms.main([str(tmp_path), "--json"]) == 1
    assert "php-file-in-upload-or-media-folder" in capsys.readouterr().out


# --- migration_check ----------------------------------------------------------
import migration_check as mc  # noqa: E402


def test_migration_normalize_location():
    assert mc.normalize_location("https://example.com/a?b=1", "example.com") == "/a?b=1"
    assert mc.normalize_location("/a?b=1", "example.com") == "/a?b=1"
    assert mc.normalize_location("https://other.org/a", "example.com") == "https://other.org/a"


def test_migration_compare_levels():
    same = mc.Page(200, "", "Home", 1000)
    assert _levels(mc.compare("/", same, mc.Page(200, "", "Home", 1050), "x", 20)) == ["OK"]
    assert "FAIL" in _levels(mc.compare("/", same, mc.Page(404, "", "Not found", 300), "x", 20))
    assert "WARN" in _levels(mc.compare("/", same, mc.Page(200, "", "Apache2 Default Page", 1000), "x", 20))
    assert "WARN" in _levels(mc.compare("/", same, mc.Page(200, "", "Home", 100), "x", 20))
    redirect_old = mc.Page(301, "https://x/new", "", 0)
    assert _levels(mc.compare("/old", redirect_old, mc.Page(301, "/new", "", 0), "x", 20)) == ["OK"]
    assert "FAIL" in _levels(mc.compare("/", same, mc.Page(error="timeout"), "x", 20))


def test_migration_sitemap_paths():
    xml = (b"<urlset><url><loc>https://example.com/</loc></url>"
           b"<url><loc> https://example.com/blog?p=2 </loc></url>"
           b"<url><loc>https://cdn.other.net/x</loc></url>"
           b"<sitemap><loc>https://example.com/post-sitemap.xml</loc></sitemap></urlset>")
    assert mc.sitemap_paths(xml, "example.com") == ["/", "/blog?p=2", "/post-sitemap.xml"]


# --- cert_inventory -------------------------------------------------------------
import cert_inventory as ci  # noqa: E402


def test_cert_name_matching():
    assert ci.name_matches("www.example.com", "*.example.com")
    assert not ci.name_matches("example.com", "*.example.com")
    assert not ci.name_matches("a.b.example.com", "*.example.com")
    assert ci.name_matches("Example.COM.", "example.com")


def test_cert_names_and_issuer():
    cert = {"subject": ((("commonName", "cn.example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"))}
    assert ci.cert_names(cert) == ["example.com", "*.example.com"]
    assert ci.cert_names({"subject": cert["subject"]}) == ["cn.example.com"]
    assert ci.issuer_name(cert) == "Let's Encrypt"


def test_cert_classify_and_targets():
    good = ci.CertInfo("h", 443, days_left=60, covered=True, trusted=True)
    assert ci.classify(good, 21, 7) == "OK"
    assert ci.classify(ci.CertInfo("h", 443, days_left=10, covered=True, trusted=True), 21, 7) == "WARN"
    assert ci.classify(ci.CertInfo("h", 443, days_left=-1, covered=True, trusted=True), 21, 7) == "FAIL"
    assert ci.classify(ci.CertInfo("h", 443, days_left=60, covered=False, trusted=True), 21, 7) == "FAIL"
    assert ci.classify(ci.CertInfo("h", 443, error="refused"), 21, 7) == "FAIL"
    assert ci.parse_target("mail.example.com:465") == ("mail.example.com", 465)
    assert ci.parse_target("example.com") == ("example.com", 443)


# --- dns_compare ----------------------------------------------------------------
import dns_compare  # noqa: E402


def test_dns_compare_fqdn_and_format():
    assert dns_compare.fqdn("@", "example.com.") == "example.com"
    assert dns_compare.fqdn("www", "example.com") == "www.example.com"
    assert dns_compare.fqdn("api.example.com.", "example.com") == "api.example.com"
    assert dns_compare.format_value(dns_audit.TYPE_MX, (10, "MX1.Example.com.")) == "10 mx1.example.com"
    assert dns_compare.format_value(dns_audit.TYPE_TXT, "v=spf1 -all") == '"v=spf1 -all"'


def test_dns_compare_diff():
    old = {("example.com", "A"): {"A 192.0.2.1"}, ("www.example.com", "CNAME"): {"CNAME example.com"}}
    new = {("example.com", "A"): {"A 198.51.100.1"}, ("www.example.com", "CNAME"): {"CNAME example.com"}}
    lines = dns_compare.diff(old, new)
    assert lines[0] == "example.com A"
    assert any("- A 192.0.2.1" in ln for ln in lines) and any("+ A 198.51.100.1" in ln for ln in lines)
    assert dns_compare.diff(old, old) == []


def test_dns_parse_aaaa():
    rdata = bytes.fromhex("20010db8000000000000000000000001")
    resp = dns_audit.parse_response(_response([_rr(dns_audit.TYPE_AAAA, rdata)]))
    assert resp.values(dns_audit.TYPE_AAAA) == ["2001:db8::1"]
    assert dns_compare.answers_to_set(resp) == {"AAAA 2001:db8::1"}


# --- file_integrity -------------------------------------------------------------
import file_integrity as fi  # noqa: E402


def test_file_integrity_detects_changes(tmp_path: Path):
    site = tmp_path / "site"
    (site / "cache").mkdir(parents=True)
    (site / "index.php").write_text("v1")
    (site / "old.php").write_text("bye")
    (site / "cache" / "c.tmp").write_text("x")
    baseline = fi.fingerprint(site, ["cache/*"])
    assert set(baseline) == {"index.php", "old.php"}

    (site / "index.php").write_text("v2")
    (site / "old.php").unlink()
    (site / "new.php").write_text("hi")
    (site / "cache" / "c.tmp").write_text("changed, but excluded")
    changes = fi.compare(baseline, fi.fingerprint(site, ["cache/*"]))
    assert changes["added"] == ["new.php"]
    assert changes["removed"] == ["old.php"]
    assert changes["modified"] == ["index.php"]


def test_file_integrity_cli(tmp_path: Path, capsys):
    site = tmp_path / "site"
    site.mkdir()
    (site / "a.txt").write_text("a")
    manifest = tmp_path / "m.json"
    assert fi.main(["init", str(site), "-o", str(manifest)]) == 0
    assert fi.main(["check", str(site), str(manifest)]) == 0
    (site / "b.txt").write_text("b")
    assert fi.main(["check", str(site), str(manifest), "--json"]) == 1
    assert '"b.txt"' in capsys.readouterr().out
