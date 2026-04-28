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
from datetime import datetime, timezone
from pathlib import Path
import os


def load_findings(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_design() -> dict:
    """Load design config from config/design.json."""
    config_path = Path(__file__).parent.parent / "config" / "design.json"

    if not config_path.exists():
        print(f"[error] Design config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(config_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[error] Failed to load design config: {e}", file=sys.stderr)
        sys.exit(1)


def render_discovery(hosts: list) -> str:
    if not hosts:
        return "<p>No hosts discovered.</p>"

    rows = ""
    for h in hosts:
        rows += f"""
        <tr>
            <td>{h.get('ip', '—')}</td>
            <td>{h.get('hostname') or '—'}</td>
        </tr>"""

    return f"""
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
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


def render_vulns(vulns: list, design: dict) -> str:
    if not vulns:
        return "<p>No vulnerabilities found.</p>"

    severity_config = design.get("severity", {})
    mono_font = design.get("fonts", {}).get("mono", "monospace")
    badge_padding = design.get("opacity", {}).get("badge_padding", "2px 6px")
    badge_radius = design.get("opacity", {}).get("badge_radius", "3px")

    html = ""
    for host in vulns:
        ip = host.get("ip", "Unknown")
        findings = host.get("findings", [])
        if not findings:
            continue

        rows = ""
        for finding in findings:
            if "cve" in finding:
                cve = finding.get("cve", "—")
                severity = finding.get("severity", "informational").lower()
                description = finding.get("description", "—")
                sev_config = severity_config.get(severity, severity_config.get("informational", {}))
                color = sev_config.get("color", "#1976d2")
                label = sev_config.get("label", severity.upper())
                rows += f"""
            <tr>
                <td style="font-family: {mono_font}; font-size: 9px;">{cve}</td>
                <td><span style="background: {color}; color: white; padding: {badge_padding}; border-radius: {badge_radius}; font-size: 9px; font-weight: 600;">{label}</span></td>
                <td>{description}</td>
            </tr>"""
            elif "update_available" in finding:
                update_ver = finding.get("update_available", "—")
                release_date = finding.get("release_date", "—")
                upd_config = severity_config.get("update_available", {})
                color = upd_config.get("color", "#388e3c")
                label = upd_config.get("label", "AVAILABLE")
                rows += f"""
            <tr>
                <td style="font-family: {mono_font}; font-size: 9px;">UPDATE</td>
                <td><span style="background: {color}; color: white; padding: {badge_padding}; border-radius: {badge_radius}; font-size: 9px; font-weight: 600;">{label}</span></td>
                <td>Version {update_ver} ({release_date})</td>
            </tr>"""

        product = host.get("product", "Unknown")
        version = host.get("version", "—")
        port = host.get("port", "—")

        html += f"""
        <h4>{ip}:{port} — {product} {version}</h4>
        <table>
            <thead>
                <tr><th>Finding</th><th>Severity</th><th>Details</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    return html or "<p>No vulnerabilities found.</p>"




def render_html(data: dict, title: str, design: dict) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target = data.get("meta", {}).get("target", "Unknown")

    discovery_results = data.get("discovery", {}).get("results", [])
    ports_results = data.get("ports", {}).get("results", [])
    vulns_results = data.get("vulns", {}).get("results", [])

    host_count = len(discovery_results)

    # Extract design config
    colors = design.get("colors", {})
    fonts = design.get("fonts", {})
    spacing = design.get("spacing", {})
    branding = design.get("branding", {})
    severity_config = design.get("severity", {})

    # Extract font sizes
    font_body = fonts.get("sizes", {}).get("body", "11px")
    font_h1 = fonts.get("sizes", {}).get("h1", "36px")
    font_h2 = fonts.get("sizes", {}).get("h2", "20px")
    font_h3 = fonts.get("sizes", {}).get("h3", "14px")
    font_h4 = fonts.get("sizes", {}).get("h4", "12px")
    font_table_header = fonts.get("sizes", {}).get("table_header", "10px")
    font_table_cell = fonts.get("sizes", {}).get("table_cell", "10.5px")
    font_small = fonts.get("sizes", {}).get("small", "9px")
    font_label = fonts.get("sizes", {}).get("label", "10px")
    font_family = fonts.get("family", "'Helvetica Neue', Helvetica, Arial, sans-serif")
    font_mono = fonts.get("mono", "Courier New, monospace")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: {font_family};
    font-size: {font_body};
    color: {colors.get('text_dark', '#2c3e50')};
    line-height: 1.5;
  }}

  /* Cover */
  .cover {{
    height: 100vh;
    background: {colors.get('cover_bg', '#1a1a2e')};
    color: {colors.get('cover_text', '#ffffff')};
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: {spacing.get('cover_padding', '60px')};
    page-break-after: always;
  }}

  .cover h1 {{
    font-size: {font_h1};
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 12px;
  }}

  .cover .subtitle {{
    font-size: 16px;
    color: {colors.get('text_light', '#a0aec0')};
    margin-bottom: 48px;
  }}

  .cover .meta-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: {spacing.get('meta_grid_gap', '24px')};
    max-width: 500px;
  }}

  .cover .meta-item label {{
    display: block;
    font-size: {font_label};
    text-transform: uppercase;
    letter-spacing: 1px;
    color: {colors.get('text_muted', '#718096')};
    margin-bottom: 4px;
  }}

  .cover .meta-item span {{
    font-size: 14px;
    color: {colors.get('bg_lighter', '#e2e8f0')};
  }}

  .cover .paw {{
    font-size: 48px;
    margin-bottom: 24px;
  }}

  /* Page layout */
  .page {{
    padding: {spacing.get('page_padding', '40px 48px')};
    max-width: 100%;
  }}

  h2 {{
    font-size: {font_h2};
    font-weight: 700;
    color: {colors.get('primary', '#1a1a2e')};
    border-bottom: 2px solid {colors.get('primary', '#1a1a2e')};
    padding-bottom: 8px;
    margin: {spacing.get('section_margin_top', '32px')} 0 {spacing.get('section_margin_bottom', '16px')};
  }}

  h3 {{
    font-size: {font_h3};
    font-weight: 600;
    margin: {spacing.get('subsection_margin_top', '24px')} 0 10px;
    color: {colors.get('text_dark', '#2d3748')};
  }}

  h4 {{
    font-size: {font_h4};
    font-weight: 600;
    margin: 16px 0 6px;
    color: {colors.get('text_muted', '#4a5568')};
    font-family: {font_mono};
  }}

  /* Summary strip */
  .summary-strip {{
    display: flex;
    gap: {spacing.get('summary_gap', '24px')};
    background: {colors.get('bg_light', '#f7f8fa')};
    border: 1px solid {colors.get('border', '#e2e8f0')};
    border-radius: 6px;
    padding: {spacing.get('summary_padding', '20px 24px')};
    margin-bottom: {spacing.get('section_margin_top', '32px')};
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
    font-size: {font_label};
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: {colors.get('text_muted', '#718096')};
    margin-top: 4px;
  }}

  .summary-divider {{
    width: 1px;
    background: {colors.get('border', '#e2e8f0')};
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
    margin-bottom: {spacing.get('table_margin_bottom', '16px')};
    font-size: {font_table_cell};
  }}

  th {{
    background: {colors.get('primary', '#1a1a2e')};
    color: white;
    text-align: left;
    padding: {spacing.get('table_header_padding', '7px 10px')};
    font-weight: 600;
    font-size: {font_table_header};
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}

  td {{
    padding: {spacing.get('table_padding', '6px 10px')};
    border-bottom: 1px solid {colors.get('border', '#e2e8f0')};
    vertical-align: top;
  }}

  tr:nth-child(even) td {{ background: {colors.get('bg_light', '#f7f8fa')}; }}

  pre {{
    font-size: {font_small};
    white-space: pre-wrap;
    word-break: break-word;
    max-width: 400px;
    color: {colors.get('text_muted', '#4a5568')};
  }}

  /* Footer */
  .footer {{
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid {colors.get('border', '#e2e8f0')};
    font-size: {font_small};
    color: {colors.get('text_light', '#a0aec0')};
    text-align: center;
  }}
</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover">
  <div class="paw">{branding.get('logo_emoji', '🐾')}</div>
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
      <span>{branding.get('tool_name', 'claude-snoop')}</span>
    </div>
  </div>
</div>

<!-- Report Body -->
<div class="page">

  <h2>Summary</h2>
  <div class="summary-strip">
    <div class="host-count">
      <span class="summary-count" style="color:{colors.get('primary', '#1a1a2e')}">{host_count}</span>
      <span class="summary-label">Hosts Found</span>
    </div>
  </div>

  <h2>Host Discovery</h2>
  {render_discovery(discovery_results)}

  <h2>Open Ports &amp; Services</h2>
  {render_ports(ports_results)}

  <h2>Vulnerabilities &amp; Updates</h2>
  {render_vulns(vulns_results, design)}

  <div class="footer">
    Generated by {branding.get('tool_name', 'claude-snoop')} &nbsp;·&nbsp; {generated} &nbsp;·&nbsp; {branding.get('github_url', 'github.com/sid-engel/claude-snoop')}
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
    design = load_design()
    html = render_html(data, args.title, design)

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
