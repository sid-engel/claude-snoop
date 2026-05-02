#!/usr/bin/env python3
"""
scan.py — nmap wrapper for claude-snoop
Returns structured JSON for consumption by the report generator.

Usage:
    python3 scan.py --target 192.168.1.0/24 --mode discovery
    python3 scan.py --target 192.168.1.0/24 --mode ports
"""

import argparse
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


SCAN_MODES = {
    "discovery": {
        "description": "Host discovery sweep — find live hosts on the subnet",
        "flags": ["-sn", "--send-eth", "-T4"],
    },
    "ports": {
        "description": "Port and service enumeration on live hosts",
        "flags": ["-sV", "-T5", "--open", "--top-ports", "100", "--min-rate", "1000"],
    },
}

SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']


def check_nmap():
    """Verify nmap is available."""
    try:
        subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def run_nmap(target: str, flags: list[str]) -> str:
    """Run nmap with XML output and return raw XML."""
    cmd = ["nmap"] + flags + ["-oX", "-", target]
    try:
        start = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        elapsed = time.time() - start
        # Show elapsed time to stderr so it doesn't interfere with JSON output
        print(f"[nmap] scan completed in {elapsed:.1f}s", file=sys.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[error] nmap failed: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def parse_discovery(xml: str) -> list[dict]:
    """Parse host discovery XML into structured host list."""
    root = ET.fromstring(xml)
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        entry = {"ip": None, "hostname": None, "mac": None, "vendor": None}

        for addr in host.findall("address"):
            addrtype = addr.get("addrtype")
            if addrtype == "ipv4":
                entry["ip"] = addr.get("addr")
            elif addrtype == "mac":
                entry["mac"] = addr.get("addr")
                entry["vendor"] = addr.get("vendor")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                entry["hostname"] = hn.get("name")

        if entry["ip"]:
            hosts.append(entry)

    return hosts


def parse_ports(xml: str) -> list[dict]:
    """Parse port/service scan XML into structured results."""
    root = ET.fromstring(xml)
    results = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")

        if not ip:
            continue

        ports = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
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

        # Extract OS info (best match by accuracy)
        os_info = None
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch_list = os_elem.findall("osmatch")
            if osmatch_list:
                # Get osmatch with highest accuracy
                best_match = max(
                    osmatch_list,
                    key=lambda m: float(m.get("accuracy", 0)),
                )
                os_name = best_match.get("name")
                os_accuracy = best_match.get("accuracy")
                if os_name:
                    os_info = {
                        "name": os_name,
                        "accuracy": float(os_accuracy) if os_accuracy else 0,
                    }

        results.append({
            "ip": ip,
            "open_ports": ports,
            "os": os_info,
        })

    return results


def build_output(mode: str, target: str, data: list) -> dict:
    """Wrap results in a standard envelope."""
    return {
        "meta": {
            "tool": "claude-snoop",
            "mode": mode,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "results": data,
    }


def main():
    parser = argparse.ArgumentParser(
        description="claude-snoop nmap scanner — outputs structured JSON"
    )
    parser.add_argument("--target", required=True, help="Target IP, range, or subnet")
    parser.add_argument(
        "--mode",
        required=True,
        choices=SCAN_MODES.keys(),
        help="Scan mode",
    )
    parser.add_argument(
        "--os-detect",
        action="store_true",
        help="Enable OS detection and hostname resolution (requires root)",
    )
    args = parser.parse_args()

    if not check_nmap():
        print(json.dumps({
            "error": "nmap not found. Install nmap and ensure it's in your PATH."
        }))
        sys.exit(1)

    mode_config = SCAN_MODES[args.mode]
    flags = mode_config["flags"].copy()

    # Add flags based on mode and os_detect flag
    if args.os_detect:
        if args.mode == "ports":
            flags.append("-O")  # OS detection (requires root)
        flags.append("-R")  # Force reverse DNS resolution for all hosts (works in any mode)

    xml_output = run_nmap(args.target, flags)

    if args.mode == "discovery":
        data = parse_discovery(xml_output)
    else:
        data = parse_ports(xml_output)

    output = build_output(args.mode, args.target, data)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
