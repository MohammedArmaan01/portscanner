#!/usr/bin/env python3
"""
portscanner.py — Intermediate TCP port scanner
Features: threading, banner grabbing, service detection, clean output
Usage:  python3 portscanner.py <host> [options]
        python3 portscanner.py scanme.nmap.org -p 1-1000 -t 200
"""

import socket
import argparse
import concurrent.futures
import sys
import json
from datetime import datetime

# ─── Common services (port → name) ───────────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    27017: "MongoDB",
}

# ─── Banner grab probes (sent to trigger a response) ─────────────────────────
BANNER_PROBES = {
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    21:   b"",   # FTP sends banner on connect
    22:   b"",   # SSH sends banner on connect
    25:   b"EHLO scanner\r\n",
    110:  b"",   # POP3 sends banner on connect
    143:  b"",   # IMAP sends banner on connect
}


def resolve_host(host: str) -> str:
    """Resolve hostname to IP, exit cleanly on failure."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {host}")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """
    Attempt to grab a service banner.
    Returns cleaned banner string or empty string.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # Send a probe if we have one, otherwise just wait for banner
            probe = BANNER_PROBES.get(port, b"\r\n")
            if probe:
                s.sendall(probe)

            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # Collapse whitespace, take first line only
            first_line = banner.splitlines()[0] if banner else ""
            return first_line[:80]  # cap at 80 chars
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict | None:
    """
    Attempt TCP connect to ip:port.
    Returns result dict if open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))

        if result == 0:
            service = COMMON_SERVICES.get(port, "unknown")
            banner = ""
            if grab:
                banner = grab_banner(ip, port, timeout)
            return {
                "port":    port,
                "state":   "open",
                "service": service,
                "banner":  banner,
            }
    except Exception:
        pass
    return None


def parse_ports(port_str: str) -> list[int]:
    """
    Parse port argument into a list of ints.
    Supports:
      - single port:  "80"
      - range:        "1-1024"
      - list:         "22,80,443"
      - mixed:        "22,80,100-200"
    """
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def print_banner(host: str, ip: str, port_count: int, threads: int):
    print()
    print("=" * 60)
    print(f"  Port Scanner")
    print(f"  Target : {host} ({ip})")
    print(f"  Ports  : {port_count} ports")
    print(f"  Threads: {threads}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<15} BANNER")
    print("  " + "-" * 56)


def print_result(r: dict):
    port_str   = f"{r['port']}/tcp"
    state_str  = r["state"]
    service    = r["service"]
    banner     = r["banner"]
    print(f"  {port_str:<8} {state_str:<8} {service:<15} {banner}")


def print_summary(open_ports: list[dict], elapsed: float):
    print("  " + "-" * 56)
    print(f"\n  {len(open_ports)} open port(s) found in {elapsed:.2f}s")
    print("=" * 60)
    print()


def save_json(results: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  [+] Results saved to {filename}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Python port scanner — TCP connect with banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 portscanner.py scanme.nmap.org
  python3 portscanner.py 192.168.1.1 -p 1-1024 -t 300
  python3 portscanner.py example.com -p 22,80,443,3306 --no-banner
  python3 portscanner.py 10.0.0.1 -p 1-65535 -t 500 --json results.json
        """
    )
    parser.add_argument("host",                              help="Target hostname or IP")
    parser.add_argument("-p", "--ports",   default="1-1024", help="Port range/list (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=150, help="Thread count (default: 150)")
    parser.add_argument("--timeout",       type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--no-banner",     action="store_true",     help="Skip banner grabbing (faster)")
    parser.add_argument("--json",          metavar="FILE",          help="Save results to JSON file")
    args = parser.parse_args()

    ip          = resolve_host(args.host)
    ports       = parse_ports(args.ports)
    grab        = not args.no_banner
    open_ports  = []
    start_time  = datetime.now()

    print_banner(args.host, ip, len(ports), args.threads)

    # ── Threaded scan ──────────────────────────────────────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, args.timeout, grab): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print_result(result)

    # ── Sort results by port number ────────────────────────────────────────
    open_ports.sort(key=lambda r: r["port"])

    elapsed = (datetime.now() - start_time).total_seconds()
    print_summary(open_ports, elapsed)

    # ── Optional JSON export ───────────────────────────────────────────────
    if args.json:
        payload = {
            "host":       args.host,
            "ip":         ip,
            "scanned_at": start_time.isoformat(),
            "elapsed_s":  round(elapsed, 2),
            "open_ports": open_ports,
        }
        save_json(payload, args.json)


if __name__ == "__main__":
    main()
