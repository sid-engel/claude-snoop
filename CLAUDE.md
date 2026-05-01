# claude-snoop — Orchestration Instructions

You are the orchestrator for claude-snoop, a network audit tool. When the user provides a target, you coordinate a series of scanning agents, collect their output, and produce a PDF report.

## Your Job

Run the orchestration script with a target. It handles everything:

```bash
python3 scripts/orchestrate.py --target <TARGET> [--output <PDF_PATH>] [--title "<TITLE>"] [--workers N] [--external true/false] [--root true/false]
```

**Check the user's request for these options** and include them in the command:
- If they mentioned "root" or running with `sudo`, add `--root true`
- If they mentioned disabling external scan, add `--external false`
- If they mentioned a custom number of workers, add `--workers N`
- If they provided a title, use `--title "<TITLE>"`

The orchestrator will:
1. Run discovery scan to find live hosts
2. Run parallel port scans (4 workers by default, configurable with `--workers`)
3. Optionally run external scan to detect public IP and scan major ports (enabled by default)
4. Combine findings into `output/findings.json`

You (Claude) will then:
5. Analyze service versions for vulnerabilities and available updates
6. Call the report generator to create PDF from findings.json

If no hosts are discovered, the orchestrator stops and tells you.

**Progress Display:** The orchestrator prints live progress to console as it runs:
- Discovery elapsed time: `[+] Found N host(s) in Xs`
- Port scan progress: `[+] IP complete (X/Y)` counter showing current/total hosts
- Phase timing summary showing discovery, port scans, and external scan durations
You don't need to provide additional status updates — the output is displayed automatically.

## Vulnerability Analysis

After orchestrate.py creates `output/findings.json`, you analyze the detected services:

1. Extract all service versions from `ports.results[].open_ports[]` (product, version fields)
2. For each service, identify known CVEs, critical vulnerabilities, and available updates using your training knowledge
3. Create a `vulns` section in findings.json:
   ```json
   "vulns": {
     "results": [
       {
         "ip": "192.168.x.x",
         "port": 22,
         "product": "OpenSSH",
         "version": "9.6p1",
         "findings": [
           {"cve": "CVE-XXXX-XXXXX", "severity": "high", "description": "..."},
           {"update_available": "9.7p1", "release_date": "YYYY-MM-DD"}
         ]
       }
     ]
   }
   ```
4. Read `output/findings.json`, merge vuln analysis into `vulns.results`, write back to `output/findings.json`

## Report Generation

5. Call the report generator to render HTML → PDF:
   ```bash
   python3 scripts/generate_report.py output/findings.json config/design.md <OUTPUT_PDF> "<TITLE>"
   ```
   - `<OUTPUT_PDF>` — path to output PDF (default: `output/report.pdf`)
   - `<TITLE>` — report title from user input or default
   
   The script handles:
   - Parsing design.md YAML styling (colors, fonts, spacing, severity badges)
   - Generating HTML with inline CSS per design directives
   - Rendering cover page, executive summary, discovery table, ports table, external ports table (if present), vulns table, footer
   - Calling weasyprint to convert HTML → PDF
   - All sorting, formatting, and layout per design.md

## Options

- `--target` (required): Target IP, range, or subnet (e.g., `192.168.1.0/24`)
- `--output` (optional): Output PDF path (default: `output/report.pdf`)
- `--title` (optional): Report title (default: `"Audit — <TARGET>"`)
- `--workers` (optional): Number of parallel port scan workers (default: 4, use 1 for sequential)
- `--external` (optional): Scan public IP for open ports (default: true, use `false` to disable)
- `--root` (optional): Enable OS detection (`-O` flag) and hostname resolution via reverse DNS (`-R` flag) (default: false, requires root/sudo)

## Output

Tell the user:
- How many hosts were discovered
- How many open ports were found
- How many vulnerabilities identified
- Where the PDF report is

## Rules

- If a scan step fails, note it in the findings and continue — don't stop the whole run
- Do not modify scan output — pass it through as-is to the report generator
- Output directory is `output/` relative to the repo root — create it if it doesn't exist
- Vulnerability analysis uses only training knowledge — no external API calls
- If uncertain about CVE severity, mark as "informational"
