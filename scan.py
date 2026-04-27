#!/usr/bin/env python3
"""
scan.py — nmap wrapper for claude-snoop
Returns structured JSON for consumption by the report generator.

Usage:
    python3 scan.py --target 192.168.1.0/24 --mode discovery
    python3 scan.py --target 192.168.1.0/24 --mode ports
    python3 scan.py --target 192.168.1.1 --mode vulns
"""

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime


SCAN_MODES = {
    "discovery": {
        "description": "Host discovery sweep — find live hosts on the subnet",
        "flags": ["-sn", "-T4", "--open"],
    },
    "ports": {
        "description": "Port and service enumeration on live hosts",
        "flags": ["-sV", "-T5", "--open", "--top-ports", "100", "--min-rate", "1000"],
    },
    "vulns": {
        "description": "Vulnerability check using nmap scripts",
        "flags": ["-sV", "-T5", "--min-rate", "1000", "--script=vuln"],
    },
    "quick": {
        "description": "Quick scan — top 1000 ports, service detection",
        "flags": ["-sV", "-T4", "--open"],
    },
}


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
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
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

        results.append({"ip": ip, "open_ports": ports})

    return results


def parse_vulns(xml: str) -> list[dict]:
    """Parse vuln script output into structured findings."""
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

        findings = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_id = port.get("portid")
                for script in port.findall("script"):
                    script_id = script.get("id")
                    output = script.get("output", "")

                    # Basic severity heuristic based on script name/output
                    severity = "informational"
                    output_lower = output.lower()
                    if any(w in output_lower for w in ["vulnerable", "critical", "exploit"]):
                        severity = "high"
                    elif any(w in output_lower for w in ["warning", "weak", "deprecated"]):
                        severity = "medium"
                    elif any(w in output_lower for w in ["state:", "detected", "enabled"]):
                        severity = "low"

                    findings.append({
                        "port": int(port_id),
                        "script": script_id,
                        "output": output.strip(),
                        "severity": severity,
                    })

        if findings:
            results.append({"ip": ip, "findings": findings})

    return results


def build_output(mode: str, target: str, data: list) -> dict:
    """Wrap results in a standard envelope."""
    return {
        "meta": {
            "tool": "claude-snoop",
            "mode": mode,
            "target": target,
            "timestamp": datetime.utcnow().isoformat() + "Z",
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
        "--list-modes",
        action="store_true",
        help="List available scan modes and exit",
    )
    args = parser.parse_args()

    if args.list_modes:
        for mode, config in SCAN_MODES.items():
            print(f"  {mode:12} {config['description']}")
        sys.exit(0)

    if not check_nmap():
        print(json.dumps({
            "error": "nmap not found. Install nmap and ensure it's in your PATH."
        }))
        sys.exit(1)

    mode_config = SCAN_MODES[args.mode]
    xml_output = run_nmap(args.target, mode_config["flags"])

    if args.mode == "discovery":
        data = parse_discovery(xml_output)
    elif args.mode == "ports":
        data = parse_ports(xml_output)
    elif args.mode == "vulns":
        data = parse_vulns(xml_output)
    elif args.mode == "quick":
        data = parse_ports(xml_output)  # quick uses port parser
    else:
        data = []

    output = build_output(args.mode, args.target, data)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
