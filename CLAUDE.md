# claude-snoop — Orchestration Instructions

You are the orchestrator for claude-snoop, a network audit tool. When the user provides a target, you coordinate a series of scanning agents, collect their output, and produce a PDF report.

## Your Job

Run the orchestration script with a target. It handles everything:

```bash
python3 scripts/orchestrate.py --target <TARGET> [--output <PDF_PATH>] [--title "<TITLE>"] [--workers N]
```

The orchestrator will:
1. Run discovery scan to find live hosts
2. Run parallel port scans (4 workers by default, configurable with `--workers`)
3. Combine findings into `output/findings.json`

You (Claude) will then:
4. Analyze service versions for vulnerabilities and available updates
5. Generate the PDF report from design.md

If no hosts are discovered, the orchestrator stops and tells you.

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

5. Read `config/design.md` to understand the report design directives (colors, fonts, spacing, layout, severity badges)
6. Generate HTML from findings.json using design.md styling:
   - Build HTML with inline CSS per design directives
   - Render cover page, executive summary, discovery table, ports table, vulns table, footer
   - Use severity badges with colors/labels from design.md
   - Follow spacing, fonts, colors exactly as specified
   - **Handle findings properly:** Each finding in vulns.results[].findings[] is either:
     - CVE finding: has 'cve', 'severity', 'description' keys
     - Update finding: has 'update_available', 'release_date' keys
     - Check `if 'cve' in finding` vs `elif 'update_available' in finding` before accessing keys
     - Don't assume all findings have all keys
7. Call weasyprint via subprocess to convert HTML to PDF:
   ```bash
   echo "<html>...</html>" | weasyprint - <PDF_PATH>
   ```
   Or write HTML to temp file, then:
   ```bash
   weasyprint <HTML_FILE> <PDF_PATH>
   ```
   Use same output path and title from orchestrate.py run.
   - **CSS note:** Avoid `min-height: 100vh` (weasyprint PDF limitation). Use fixed heights, padding, or page-break rules instead.

## Options

- `--target` (required): Target IP, range, or subnet (e.g., `192.168.1.0/24`)
- `--output` (optional): Output PDF path (default: `output/report.pdf`)
- `--title` (optional): Report title (default: `"Audit — <TARGET>"`)
- `--workers` (optional): Number of parallel port scan workers (default: 4, use 1 for sequential)

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
