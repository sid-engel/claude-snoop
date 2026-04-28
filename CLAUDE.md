# claude-snoop — Orchestration Instructions

You are the orchestrator for claude-snoop, a network audit tool. When the user provides a target, you coordinate a series of scanning agents, collect their output, and produce a PDF report.

## Your Job

1. Run each scan agent in order using `scripts/scan.py`
2. Collect and combine the JSON output from each agent
3. Write the combined findings to `output/findings.json`
4. Run `scripts/report.py` to generate the PDF
5. Tell the user where the report is

## Scan Order

Always run in this order — each step builds on the last:

### Step 1 — Discovery
Find live hosts on the subnet.

```bash
python3 scripts/scan.py --target <TARGET> --mode discovery
```

Parse the JSON output. If no hosts are found, stop and tell the user.

### Step 2 — Ports & Services
Enumerate open ports on discovered hosts. **Run one host at a time** to ensure nmap processes each properly.

For each discovered host IP from Step 1:

```bash
python3 scripts/scan.py --target <HOST_IP> --mode ports
```

Print progress before each scan: `Scanning <HOST_IP> for open ports...`
Collect JSON output from each scan into an array.

## Combining Findings

After all scans complete, write a single JSON file structured like this:

```json
{
  "meta": {
    "target": "<TARGET>",
    "timestamp": "<ISO8601>",
    "tool": "claude-snoop"
  },
  "discovery": { ...output from step 1... },
  "ports":     { ...output from step 2... }
}
```

Write this to `output/findings.json`.

## Generating the Report

```bash
python3 scripts/report.py --input output/findings.json --output output/report.pdf --title "<TITLE>"
```

Use the target as the title if none is provided (e.g. "Audit — 192.168.1.0/24").

## Output

Tell the user:
- How many hosts were discovered
- How many open ports were found
- Where the PDF report is

## Rules

- Always run as root/sudo if possible — some nmap scans require elevated privileges
- If a scan step fails, note it in the findings and continue — don't stop the whole run
- Do not modify scan output — pass it through as-is to the report generator
- Output directory is `output/` relative to the repo root — create it if it doesn't exist
