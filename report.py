#!/usr/bin/env python3
"""
report.py — claude-snoop report generator
Takes combined JSON findings from all agents, renders HTML, exports PDF.

Usage:
    python3 report.py --input findings.json --output report.pdf
    python3 report.py --input findings.json --output report.pdf --title "Acme Corp Audit"
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


# Severity ordering for sorting
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#2980b9",
    "informational": "#7f8c8d",
}


def load_findings(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.lower(), "#7f8c8d")
    return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'


def render_discovery(hosts: list) -> str:
    if not hosts:
        return "<p>No hosts discovered.</p>"

    rows = ""
    for h in hosts:
        rows += f"""
        <tr>
            <td>{h.get('ip', '—')}</td>
            <td>{h.get('hostname') or '—'}</td>
            <td>{h.get('mac') or '—'}</td>
            <td>{h.get('vendor') or '—'}</td>
        </tr>"""

    return f"""
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC Address</th>
                <th>Vendor</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>"""


def render_ports(hosts: list) -> str:
    if not hosts:
        return "<p>No open ports found.</p>"

    html = ""
    for host in hosts:
        ip = host.get("ip", "Unknown")
        ports = host.get("open_ports", [])
        if not ports:
            continue

        rows = ""
        for p in sorted(ports, key=lambda x: x["port"]):
            service = p.get("service") or "—"
            product = p.get("product") or ""
            version = p.get("version") or ""
            detail = f"{product} {version}".strip() or "—"
            rows += f"""
            <tr>
                <td>{p['port']}/{p['protocol']}</td>
                <td>{service}</td>
                <td>{detail}</td>
            </tr>"""

        html += f"""
        <h4>{ip}</h4>
        <table>
            <thead>
                <tr><th>Port</th><th>Service</th><th>Version</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    return html or "<p>No open ports found.</p>"


def render_vulns(hosts: list) -> str:
    if not hosts:
        return "<p>No vulnerability findings.</p>"

    html = ""
    for host in hosts:
        ip = host.get("ip", "Unknown")
        findings = sorted(
            host.get("findings", []),
            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "informational"), 99),
        )
        if not findings:
            continue

        rows = ""
        for f in findings:
            rows += f"""
            <tr>
                <td>{f.get('port', '—')}</td>
                <td>{f.get('script', '—')}</td>
                <td>{severity_badge(f.get('severity', 'informational'))}</td>
                <td><pre>{f.get('output', '—')}</pre></td>
            </tr>"""

        html += f"""
        <h4>{ip}</h4>
        <table>
            <thead>
                <tr><th>Port</th><th>Script</th><th>Severity</th><th>Output</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    return html or "<p>No vulnerability findings.</p>"


def count_findings_by_severity(findings_data: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for host in findings_data:
        for f in host.get("findings", []):
            sev = f.get("severity", "informational").lower()
            if sev in counts:
                counts[sev] += 1
    return counts


def render_html(data: dict, title: str) -> str:
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    target = data.get("meta", {}).get("target", "Unknown")

    discovery_results = data.get("discovery", {}).get("results", [])
    ports_results = data.get("ports", {}).get("results", [])
    vulns_results = data.get("vulns", {}).get("results", [])

    host_count = len(discovery_results)
    sev_counts = count_findings_by_severity(vulns_results)

    # Summary bar
    summary_items = ""
    for sev, count in sev_counts.items():
        if count > 0:
            color = SEVERITY_COLORS[sev]
            summary_items += f"""
            <div class="summary-item">
                <span class="summary-count" style="color:{color}">{count}</span>
                <span class="summary-label">{sev.capitalize()}</span>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 11px;
    color: #2c3e50;
    line-height: 1.5;
  }}

  /* Cover */
  .cover {{
    height: 100vh;
    background: #1a1a2e;
    color: white;
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 60px;
    page-break-after: always;
  }}

  .cover h1 {{
    font-size: 36px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 12px;
  }}

  .cover .subtitle {{
    font-size: 16px;
    color: #a0aec0;
    margin-bottom: 48px;
  }}

  .cover .meta-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    max-width: 500px;
  }}

  .cover .meta-item label {{
    display: block;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #718096;
    margin-bottom: 4px;
  }}

  .cover .meta-item span {{
    font-size: 14px;
    color: #e2e8f0;
  }}

  .cover .paw {{
    font-size: 48px;
    margin-bottom: 24px;
  }}

  /* Page layout */
  .page {{
    padding: 40px 48px;
    max-width: 100%;
  }}

  h2 {{
    font-size: 20px;
    font-weight: 700;
    color: #1a1a2e;
    border-bottom: 2px solid #1a1a2e;
    padding-bottom: 8px;
    margin: 32px 0 16px;
  }}

  h3 {{
    font-size: 14px;
    font-weight: 600;
    margin: 24px 0 10px;
    color: #2d3748;
  }}

  h4 {{
    font-size: 12px;
    font-weight: 600;
    margin: 16px 0 6px;
    color: #4a5568;
    font-family: monospace;
  }}

  /* Summary strip */
  .summary-strip {{
    display: flex;
    gap: 24px;
    background: #f7f8fa;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 20px 24px;
    margin-bottom: 32px;
  }}

  .summary-item {{
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 60px;
  }}

  .summary-count {{
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
  }}

  .summary-label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #718096;
    margin-top: 4px;
  }}

  .summary-divider {{
    width: 1px;
    background: #e2e8f0;
    margin: 0 8px;
  }}

  .host-count {{
    margin-left: auto;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }}

  /* Tables */
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 16px;
    font-size: 10.5px;
  }}

  th {{
    background: #1a1a2e;
    color: white;
    text-align: left;
    padding: 7px 10px;
    font-weight: 600;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}

  td {{
    padding: 6px 10px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
  }}

  tr:nth-child(even) td {{ background: #f7f8fa; }}

  pre {{
    font-size: 9px;
    white-space: pre-wrap;
    word-break: break-word;
    max-width: 400px;
    color: #4a5568;
  }}

  /* Badges */
  .badge {{
    color: white;
    padding: 2px 7px;
    border-radius: 10px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.3px;
    white-space: nowrap;
  }}

  /* Footer */
  .footer {{
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid #e2e8f0;
    font-size: 9px;
    color: #a0aec0;
    text-align: center;
  }}
</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover">
  <div class="paw">🐾</div>
  <h1>{title}</h1>
  <p class="subtitle">Network Security Audit Report</p>
  <div class="meta-grid">
    <div class="meta-item">
      <label>Target</label>
      <span>{target}</span>
    </div>
    <div class="meta-item">
      <label>Generated</label>
      <span>{generated}</span>
    </div>
    <div class="meta-item">
      <label>Hosts Discovered</label>
      <span>{host_count}</span>
    </div>
    <div class="meta-item">
      <label>Tool</label>
      <span>claude-snoop</span>
    </div>
  </div>
</div>

<!-- Report Body -->
<div class="page">

  <h2>Summary</h2>
  <div class="summary-strip">
    {summary_items if summary_items else '<span style="color:#718096">No findings to display.</span>'}
    <div class="summary-divider"></div>
    <div class="host-count">
      <span class="summary-count" style="color:#1a1a2e">{host_count}</span>
      <span class="summary-label">Hosts Found</span>
    </div>
  </div>

  <h2>Host Discovery</h2>
  {render_discovery(discovery_results)}

  <h2>Open Ports &amp; Services</h2>
  {render_ports(ports_results)}

  <h2>Vulnerability Findings</h2>
  {render_vulns(vulns_results)}

  <div class="footer">
    Generated by claude-snoop &nbsp;·&nbsp; {generated} &nbsp;·&nbsp; github.com/sid-engel/claude-snoop
  </div>

</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="claude-snoop report generator")
    parser.add_argument("--input", required=True, help="Path to combined findings JSON")
    parser.add_argument("--output", required=True, help="Output PDF path")
    parser.add_argument("--title", default="Network Audit Report", help="Report title")
    parser.add_argument("--html-only", action="store_true", help="Output HTML instead of PDF (for debugging)")
    args = parser.parse_args()

    data = load_findings(args.input)
    html = render_html(data, args.title)

    if args.html_only:
        html_path = args.output.replace(".pdf", ".html")
        Path(html_path).write_text(html)
        print(f"[ok] HTML written to {html_path}")
        return

    try:
        from weasyprint import HTML
    except ImportError:
        print("[error] weasyprint not installed. Run: pip install weasyprint", file=sys.stderr)
        sys.exit(1)

    HTML(string=html).write_pdf(args.output)
    print(f"[ok] Report written to {args.output}")


if __name__ == "__main__":
    main()
