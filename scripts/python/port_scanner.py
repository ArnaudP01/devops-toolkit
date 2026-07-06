#!/usr/bin/env python3
"""Scan a host for open TCP ports (concurrent, dependency-free)."""
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor


def is_open(host: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def scan(host: str, ports: range, timeout: float = 0.5, workers: int = 100) -> list[int]:
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: (p, is_open(host, p, timeout)), ports))
    for port, ok in results:
        if ok:
            open_ports.append(port)
    return open_ports


def main() -> None:
    p = argparse.ArgumentParser(description="Scan a host for open TCP ports.")
    p.add_argument("host", help="hostname or IP")
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--end", type=int, default=1024)
    p.add_argument("--timeout", type=float, default=0.5)
    p.add_argument("--workers", type=int, default=100)
    args = p.parse_args()

    ports = range(args.start, args.end + 1)
    found = scan(args.host, ports, args.timeout, args.workers)
    if found:
        print(f"Open ports on {args.host}: {', '.join(map(str, found))}")
    else:
        print(f"No open ports on {args.host} in range {args.start}-{args.end}")


if __name__ == "__main__":
    main()
