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
