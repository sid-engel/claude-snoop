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
4. Generate PDF report
5. Print summary (host count, port count, report path)

If no hosts are discovered, the orchestrator stops and tells you.

## Options

- `--target` (required): Target IP, range, or subnet (e.g., `192.168.1.0/24`)
- `--output` (optional): Output PDF path (default: `output/report.pdf`)
- `--title` (optional): Report title (default: `"Audit — <TARGET>"`)
- `--workers` (optional): Number of parallel port scan workers (default: 4, use 1 for sequential)

## Output

Tell the user:
- How many hosts were discovered
- How many open ports were found
- Where the PDF report is

## Rules

- If a scan step fails, note it in the findings and continue — don't stop the whole run
- Do not modify scan output — pass it through as-is to the report generator
- Output directory is `output/` relative to the repo root — create it if it doesn't exist
