#!/usr/bin/env python3
"""
external_scan.py — external IP detection and port scanning
Detects public IP and scans major ports externally.

Usage:
    python3 scripts/external_scan.py
"""

import json
import subprocess
import sys
from datetime import datetime, timezone

# Major ports to scan externally
MAJOR_PORTS = [
    20,    # FTP-DATA
    21,    # FTP
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    465,   # SMTPS
    587,   # SMTP (submission)
    993,   # IMAPS
    995,   # POP3S
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    8080,  # HTTP (alt)
    8443,  # HTTPS (alt)
    27017, # MongoDB
]


def get_public_ip() -> str:
    """Get public IP via external service."""
    services = [
        ("https://api.ipify.org", "text"),
        ("https://api.my-ip.io/ip", "text"),
        ("https://ifconfig.me", "text"),
    ]

    for url, response_type in services:
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", url],
                capture_output=True,
                text=True,
                timeout=10,
            )
            ip = result.stdout.strip()
            if ip and _is_valid_ip(ip):
                return ip
        except Exception:
            continue

    return None


def _is_valid_ip(ip: str) -> bool:
    """Basic IPv4 validation."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def scan_external_ports(public_ip: str) -> list[dict]:
    """Scan major ports on public IP, return open ports."""
    if not public_ip:
        return []

    port_list = ",".join(str(p) for p in MAJOR_PORTS)

    try:
        result = subprocess.run(
            [
                "nmap",
                "-p", port_list,
                "-sV",
                "--open",
                "-T4",
                "-oX", "-",
                public_ip,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )

        return _parse_nmap_xml(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"[warning] External port scan timed out", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print(f"[warning] External port scan failed: {e.stderr}", file=sys.stderr)
        return []
    except FileNotFoundError:
        print("[warning] nmap not found", file=sys.stderr)
        return []


def _parse_nmap_xml(xml: str) -> list[dict]:
    """Parse nmap XML and return open ports."""
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml)
        ports = []

        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            port_entry = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state.get("state"),
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
            }
            ports.append(port_entry)

        return ports
    except Exception as e:
        print(f"[warning] Failed to parse nmap XML: {e}", file=sys.stderr)
        return []


def build_output(public_ip: str, open_ports: list[dict]) -> dict:
    """Build structured output."""
    return {
        "meta": {
            "tool": "claude-snoop",
            "mode": "external",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "public_ip": public_ip,
        "open_ports": open_ports,
    }


def main():
    print("[*] Detecting public IP...", file=sys.stderr)
    public_ip = get_public_ip()

    if not public_ip:
        result = {
            "error": "Could not detect public IP. Ensure curl is available.",
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    print(f"[+] Public IP: {public_ip}", file=sys.stderr)

    print(f"[*] Scanning {len(MAJOR_PORTS)} major ports...", file=sys.stderr)
    open_ports = scan_external_ports(public_ip)

    output = build_output(public_ip, open_ports)
    print(json.dumps(output, indent=2))

    if open_ports:
        print(f"[!] {len(open_ports)} open port(s) found externally", file=sys.stderr)


if __name__ == "__main__":
    main()
