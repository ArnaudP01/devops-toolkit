#!/usr/bin/env python3
"""Generate cryptographically strong passwords using the `secrets` module."""
import argparse
import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{}"


def generate(length: int = 20, symbols: bool = True, uppercase: bool = True) -> str:
    alphabet = string.ascii_lowercase + string.digits
    if uppercase:
        alphabet += string.ascii_uppercase
    if symbols:
        alphabet += SYMBOLS
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main() -> None:
    p = argparse.ArgumentParser(description="Generate a strong random password.")
    p.add_argument("-l", "--length", type=int, default=20)
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--no-upper", action="store_true")
    p.add_argument("-n", "--count", type=int, default=1, help="number of passwords to print")
    args = p.parse_args()
    if args.length < 4:
        p.error("length must be at least 4")
    for _ in range(args.count):
        print(generate(args.length, not args.no_symbols, not args.no_upper))


if __name__ == "__main__":
    main()
