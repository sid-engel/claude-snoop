# 🐾 claude-snoop

> ⚠️ **Super vibe coded. Super developmental**

AI-powered network audit tool built on [Claude Code](https://claude.ai/code). Orchestrates host discovery, port scanning, and vulnerability analysis — then generates a customizable PDF report.

---

## Quick Start

```bash
# Scan a subnet, get PDF report
./claude-snoop.sh --target 192.168.1.0/24 --title "Client Network"
```

Output → `output/report.pdf`

---

## How It Works

Shell wrapper invokes Claude Code with instructions from CLAUDE.md. Claude then:

1. **Discovery** — Runs nmap host discovery scan to find live IPs on subnet (optionally with reverse DNS for hostnames via `--root true`)
2. **Port Scan** — Runs nmap service enumeration on each host (parallel, configurable workers; optionally with OS detection and hostname resolution via `--root true`)
3. **External Scan** (optional) — Detects public IP and scans major ports externally (enabled by default, can be disabled with `--external false`)
4. **Combine Findings** — Merges discovery + port scan + external scan results into `output/findings.json`
5. **Vulnerability Analysis** — Analyzes detected service versions for known CVEs, critical vulns, available updates using training knowledge
6. **Inject Vulns** — Adds vulnerability findings to `findings.json`
7. **Generate PDF Report** — Local Python script (`generate_report.py`) reads findings.json + design.md config, generates styled HTML + PDF via weasyprint with:
   - Cover page (title, target, timestamp)
   - Executive summary (host count, port count, external port count, vuln count)
   - Host discovery table (IP, hostname, operating system)
   - Open ports & services per host (port, protocol, product, version)
   - External ports scan (if public ports found)
   - Vulnerabilities & updates per service (CVE, severity, details)

---

## Requirements

- `nmap` — port/service scanning
- `python3` — orchestration and reporting
- `claude` CLI — launched automatically by wrapper script
- Python deps: `weasyprint>=60.0` (PDF generation)

Install deps:
```bash
pip install -r requirements.txt
```

---

## Usage

### Wrapper Script

```bash
./claude-snoop.sh --target <TARGET> [OPTIONS]
```

**Required:**
- `--target <IP/subnet>` — Target IP, range, or subnet (e.g., `192.168.1.0/24`, `10.0.0.1`)

**Optional:**
- `--title <title>` — Report title (default: `"Network Audit — <TARGET>"`)
- `--workers <N>` — Parallel port scan workers (default: `4`)
- `--external true|false` — Scan public IP for open ports (default: `true`)
- `--root true|false` — Enable OS detection and hostname resolution via reverse DNS (default: `false`, requires root/sudo)

**Examples:**
```bash
./claude-snoop.sh --target 192.168.1.0/24
./claude-snoop.sh --target 192.168.1.0/24 --title "Acme Corp Audit"
./claude-snoop.sh --target 192.168.1.0/24 --title "Acme Corp Audit" --workers 8
./claude-snoop.sh --target 192.168.1.0/24 --external false
sudo ./claude-snoop.sh --target 192.168.1.0/24 --root true
```

---

## Output Files

- `output/findings.json` — Raw scan results + vulnerability analysis in JSON
- `output/report.pdf` — Formatted audit report with tables and styling

---

## Architecture

**Hybrid Architecture**
- `claude-snoop.sh` (wrapper) invokes Claude Code with CLAUDE.md instructions
- Claude handles: vulnerability analysis (training knowledge)
- Python handles: scanning, orchestration, report generation

**Components**

`scripts/scan.py` — nmap wrapper
- Parses nmap XML output to JSON
- Modes: `discovery` (host sweep), `ports` (service enumeration)
- Supports `--os-detect` flag to enable OS detection (`-O`) and hostname resolution (`-R`) via nmap

`scripts/orchestrate.py` — scan coordinator
- Runs discovery scan on target (with optional `--root` for hostname resolution)
- Runs parallel port scans (configurable workers, default 4; with optional `--root` for OS detection + hostname resolution)
- Optionally runs external IP scan (concurrent with port scans)
- Combines results into `output/findings.json`

`scripts/generate_report.py` — report generator
- Reads `output/findings.json` + `config/design.md`
- Generates styled HTML from findings data
- Calls weasyprint to convert HTML → PDF
- Handles cover page, tables, severity badges, external ports section

`config/design.md` — report styling config
- YAML: colors, fonts, spacing, severity badges, branding
- Python script reads this config to style the report

`CLAUDE.md` — orchestration instructions
- Instructions for Claude: run scans, analyze vulns, inject findings, trigger report generation
- Claude focuses on vulnerability analysis (domain expertise)

---

## Vulnerability Analysis

After port scans complete, Claude analyzes detected service versions (e.g., `OpenSSH 9.6p1`) to identify:
- Known CVEs with severity (high/medium/low/informational)
- Available updates with release dates
- Critical vulnerabilities needing immediate attention

Analysis uses Claude's training knowledge — no external API calls.

---

## Design Decisions

**Local HTML Generation** — Report generation (HTML + PDF) moved from Claude to Python (`generate_report.py`). Previously, Claude generated HTML+CSS from scratch on every run, consuming significant tokens. Local generation via Python template approach is faster and cheaper, letting Claude focus on high-value vulnerability analysis.

## Known Limitations & Notes

- **OS Detection & Hostname Resolution** — Require `--root true` flag (run with sudo). OS detection uses nmap's TCP/IP fingerprinting (`-O` flag), hostname resolution uses reverse DNS (`-R` flag). Some devices (embedded systems, network appliances) may not fingerprint reliably or may lack reverse DNS records.
- **MAC Addresses** — Available in discovery results only with `--root true` flag. Regular scans without root won't include MAC addresses.
- **Vulnerability Data** — Currently uses Claude's training knowledge only. Future: external CVE/update APIs (NVD, etc.) could be integrated for real-time accuracy.

---

## Status

Functional core pipeline: discovery → ports → vulns → PDF report. Early alpha, expect changes.

---

## Contributing

Issues and PRs welcome. See CLAUDE.md for internal orchestration logic.

---

## License

None, idk use it as much as you want.
