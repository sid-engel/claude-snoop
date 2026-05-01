#!/usr/bin/env python3
"""
orchestrate.py — claude-snoop orchestration engine
Runs discovery → parallel port scans → combined findings → report

Usage:
    python3 scripts/orchestrate.py --target 192.168.1.0/24 --output report.pdf --title "Audit"
    python3 scripts/orchestrate.py --target 192.168.1.0/24 --workers 5
"""

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


def format_elapsed(seconds: float) -> str:
    """Format elapsed time as human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"


def run_discovery(target: str, root: bool = False) -> tuple[dict, float]:
    """Run discovery scan, return parsed results and elapsed time."""
    print(f"[*] Discovery scan on {target}...")
    start = time.time()
    try:
        cmd = ["python3", "scripts/scan.py", "--target", target, "--mode", "discovery"]
        if root:
            cmd.append("--os-detect")  # Also enables -R for hostname detection
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        elapsed = time.time() - start
        return json.loads(result.stdout), elapsed
    except subprocess.CalledProcessError as e:
        print(f"[error] Discovery failed: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"[error] Discovery timed out", file=sys.stderr)
        sys.exit(1)


def run_port_scan(host_ip: str, root: bool = False) -> tuple[str, dict]:
    """Run port scan on single host, return (ip, parsed_results)."""
    try:
        cmd = ["python3", "scripts/scan.py", "--target", host_ip, "--mode", "ports"]
        if root:
            cmd.append("--os-detect")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,  # 5 min per host (nmap can be slow)
        )
        return (host_ip, json.loads(result.stdout))
    except subprocess.TimeoutExpired:
        print(f"[warning] Port scan timed out for {host_ip}", file=sys.stderr)
        return (host_ip, {"meta": {}, "results": []})
    except subprocess.CalledProcessError as e:
        print(f"[warning] Port scan failed for {host_ip}: {e.stderr}", file=sys.stderr)
        return (host_ip, {"meta": {}, "results": []})


def run_external_scan() -> tuple[dict, float]:
    """Run external port scan, return parsed results and elapsed time."""
    print("[*] External scan (public IP + major ports)...")
    start = time.time()
    try:
        result = subprocess.run(
            ["python3", "scripts/external_scan.py"],
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )
        elapsed = time.time() - start
        return json.loads(result.stdout), elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        print(f"[warning] External scan timed out", file=sys.stderr)
        return {"error": "timeout"}, elapsed
    except subprocess.CalledProcessError as e:
        elapsed = time.time() - start
        print(f"[warning] External scan failed: {e.stderr}", file=sys.stderr)
        return {"error": str(e)}, elapsed


def combine_findings(target: str, discovery_output: dict, port_outputs: list, external_output: dict = None) -> dict:
    """Combine discovery, port scans, and external scan into findings structure."""

    # Extract discovery results
    discovery_results = discovery_output.get("results", [])

    # Combine port scan results from all hosts
    port_results = []
    for port_output in port_outputs:
        port_results.extend(port_output.get("results", []))

    # Build combined findings
    combined = {
        "meta": {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool": "claude-snoop",
        },
        "discovery": {
            "results": discovery_results,
        },
        "ports": {
            "results": port_results,
        },
    }

    # Add external scan data if available
    if external_output and "error" not in external_output:
        combined["external"] = {
            "public_ip": external_output.get("public_ip"),
            "open_ports": external_output.get("open_ports", []),
        }

    return combined


def main():
    parser = argparse.ArgumentParser(description="claude-snoop orchestrator")
    parser.add_argument("--target", required=True, help="Target IP, range, or subnet")
    parser.add_argument("--output", default="output/report.pdf", help="Output PDF path")
    parser.add_argument("--title", help="Report title (defaults to target)")
    parser.add_argument("--workers", type=int, default=4, help="Parallel port scan workers (default: 4)")
    parser.add_argument("--external", type=lambda x: x.lower() in ('true', '1', 'yes'), default=True, help="Scan public IP for open ports (default: true)")
    parser.add_argument("--root", type=lambda x: x.lower() in ('true', '1', 'yes'), default=False, help="Enable OS detection and hostname resolution (requires root, default: false)")
    args = parser.parse_args()

    title = args.title or f"Audit — {args.target}"

    # Create output directory
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Log configuration
    print(f"[*] Configuration:")
    print(f"    Target: {args.target}")
    print(f"    Workers: {args.workers}")
    print(f"    External scan: {'enabled' if args.external else 'disabled'}")
    print(f"    OS detection: {'enabled (requires root)' if args.root else 'disabled'}")
    print(f"    Output: {args.output}")

    # Step 1: Host discovery
    discovery_output, discovery_elapsed = run_discovery(args.target, args.root)
    discovery_results = discovery_output.get("results", [])

    if not discovery_results:
        print("[!] No hosts discovered. Exiting.")
        sys.exit(0)

    print(f"[+] Found {len(discovery_results)} host(s) in {format_elapsed(discovery_elapsed)}")

    # Step 2: Parallel port scans + external scan (concurrent)
    print(f"[*] Scanning open ports ({args.workers} parallel workers)...")
    port_outputs = []
    external_output = None
    port_scan_start = time.time()
    port_scans_completed = 0
    total_port_scans = len(discovery_results)
    external_elapsed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Submit all scan tasks
        futures = {}
        for host in discovery_results:
            ip = host.get("ip")
            if ip:
                future = executor.submit(run_port_scan, ip, args.root)
                futures[future] = ("port", ip)

        # Submit external scan concurrently if enabled
        if args.external:
            external_future = executor.submit(run_external_scan)
            futures[external_future] = ("external", None)

        # Collect results as they complete
        for future in as_completed(futures):
            task_type, task_id = futures[future]
            if task_type == "port":
                ip, output = future.result()
                port_outputs.append(output)
                port_scans_completed += 1
                print(f"    [+] {ip} complete ({port_scans_completed}/{total_port_scans})")
            elif task_type == "external":
                external_output, external_elapsed = future.result()

    port_scans_elapsed = time.time() - port_scan_start

    # Step 3: Combine findings
    combined = combine_findings(args.target, discovery_output, port_outputs, external_output)

    # Count open ports
    total_ports = sum(
        len(host.get("open_ports", []))
        for host in combined["ports"]["results"]
    )

    external_ports = 0
    if "external" in combined:
        external_ports = len(combined["external"].get("open_ports", []))

    # Step 4: Write findings
    findings_path = output_dir / "findings.json"
    findings_path.write_text(json.dumps(combined, indent=2))
    print(f"[+] Findings written to {findings_path}")

    # Report results
    print()
    print(f"[✓] Discovery & port scans complete")
    print(f"    Hosts discovered: {len(discovery_results)} ({format_elapsed(discovery_elapsed)})")
    print(f"    Port scans: {format_elapsed(port_scans_elapsed)}")
    print(f"    Open ports found: {total_ports}")
    if external_ports > 0:
        print(f"    External ports open: {external_ports} ({format_elapsed(external_elapsed)})")
    print(f"    Findings: {findings_path}")
    print(f"[*] Claude will now analyze vulnerabilities and generate the PDF report...")


if __name__ == "__main__":
    main()
