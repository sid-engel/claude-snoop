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

1. **Discovery** — nmap host discovery scan finds live IPs on subnet
2. **Port Scan** — nmap service enumeration on each host (parallel, configurable workers)
3. **Vulnerability Analysis** — Claude analyzes detected service versions for known CVEs, critical vulns, available updates
4. **Report Generation** — Combines findings into readable PDF with:
   - Host discovery table (IP, hostname, MAC, vendor)
   - Open ports & services per host (port, protocol, product, version)
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

**Options:**
- `--target` (required) — IP, range, or subnet (e.g., `192.168.1.0/24`, `10.0.0.1`)
- `--title` (optional) — Report title (default: `"Audit — <TARGET>"`)

### Direct Orchestration

```bash
python3 scripts/orchestrate.py --target 192.168.1.0/24
```

---

## Output Files

- `output/findings.json` — Raw scan results + vulnerability analysis in JSON
- `output/report.pdf` — Formatted audit report with tables and styling

---

## Architecture

**scripts/scan.py**
- nmap wrapper, parses XML output to JSON
- Modes: `discovery` (host sweep), `ports` (service enumeration)

**scripts/orchestrate.py**
- Coordinates discovery → parallel port scans → vulnerability analysis → report
- Manages ThreadPoolExecutor for parallel scanning (configurable workers)
- Merges findings into combined JSON

**scripts/report.py**
- Loads findings JSON, renders HTML template with CSS
- Exports to PDF via weasyprint

**CLAUDE.md**
- Instructions for Claude instance: how to run orchestration, analyze vulns, call report generator

---

## Vulnerability Analysis

After port scans complete, Claude analyzes detected service versions (e.g., `OpenSSH 9.6p1`) to identify:
- Known CVEs with severity (high/medium/low/informational)
- Available updates with release dates
- Critical vulnerabilities needing immediate attention

Analysis uses Claude's training knowledge — no external API calls.

---

## Status

Functional core pipeline: discovery → ports → vulns → PDF report. Early alpha, expect changes.

---

## Contributing

Issues and PRs welcome. See CLAUDE.md for internal orchestration logic.

---

## License

None, idk use it as much as you want.
