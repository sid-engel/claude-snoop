#!/usr/bin/env python3
import json
import sys
import subprocess
import re
from datetime import datetime
from pathlib import Path

def parse_design_md(design_path):
    """Parse YAML frontmatter from design.md"""
    with open(design_path, 'r') as f:
        content = f.read()

    # Extract YAML frontmatter
    match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
    if not match:
        return {}

    yaml_str = match.group(1)
    config = {
        'colors': {},
        'fonts': {'sizes': {}, 'weights': {}},
        'spacing': {},
        'branding': {},
        'severity': {}
    }

    current_section = None
    current_subsection = None

    # Parse YAML with proper indentation tracking
    for line in yaml_str.split('\n'):
        if not line.strip() or line.strip().startswith('#'):
            continue

        if ':' not in line:
            continue

        # Detect indentation level
        indent = len(line) - len(line.lstrip())
        key, val = line.split(':', 1)
        key = key.strip()
        val = val.strip()

        # Handle quoted values properly (don't strip comments inside quotes)
        if val.startswith('"'):
            end_quote = val.find('"', 1)
            if end_quote != -1:
                val = val[1:end_quote]
        elif val.startswith("'"):
            end_quote = val.find("'", 1)
            if end_quote != -1:
                val = val[1:end_quote]
        else:
            # Unquoted value, strip trailing comments
            if '#' in val:
                val = val.split('#')[0].strip()

        # Top-level section (no indent)
        if indent == 0:
            if key in ['colors', 'fonts', 'spacing', 'branding', 'severity']:
                current_section = key
                current_subsection = None
            continue

        # First-level nested (2 spaces)
        if indent == 2:
            if current_section == 'colors':
                config['colors'][key] = val
            elif current_section == 'branding':
                config['branding'][key] = val
            elif current_section == 'spacing':
                config['spacing'][key] = val
            elif current_section == 'fonts':
                if key in ['sizes', 'weights']:
                    current_subsection = key
                else:
                    config['fonts'][key] = val
            elif current_section == 'severity':
                # Severity subsection (high, medium, low, etc.)
                if key in ['high', 'medium', 'low', 'informational', 'update_available']:
                    current_subsection = key
                    config['severity'][key] = {}
            continue

        # Second-level nested (4 spaces)
        if indent == 4:
            if current_section == 'fonts':
                if current_subsection == 'sizes':
                    config['fonts']['sizes'][key] = val
                elif current_subsection == 'weights':
                    config['fonts']['weights'][key] = val
            elif current_section == 'severity' and current_subsection:
                config['severity'][current_subsection][key] = val

    return config

def get_color(config, key, default='#000000'):
    """Get color from config with fallback"""
    return config.get('colors', {}).get(key, default)

def get_severity_config(config, severity):
    """Get severity config with fallback defaults"""
    defaults = {
        'high': {'color': '#DC2626', 'bg': '#FEE2E2', 'label': 'CRITICAL'},
        'medium': {'color': '#EA580C', 'bg': '#FFEDD5', 'label': 'WARNING'},
        'low': {'color': '#2563EB', 'bg': '#DBEAFE', 'label': 'NOTICE'},
        'informational': {'color': '#7C3AED', 'bg': '#EDE9FE', 'label': 'INFO'},
        'update_available': {'color': '#16A34A', 'bg': '#DCFCE7', 'label': 'UPDATE'}
    }

    severity_config = config.get('severity', {}).get(severity, {})
    default = defaults.get(severity, defaults['informational'])

    return {
        'color': severity_config.get('color', default['color']),
        'bg': severity_config.get('bg', default['bg']),
        'label': severity_config.get('label', default['label'])
    }

def generate_html(findings, config, title):
    """Generate HTML report"""

    colors = config.get('colors', {})
    fonts = config.get('fonts', {})
    spacing = config.get('spacing', {})
    branding = config.get('branding', {})

    primary = colors.get('primary', '#1E293B')
    secondary = colors.get('secondary', '#64748B')
    accent = colors.get('accent', '#0EA5E9')
    text_dark = colors.get('text_dark', '#0F172A')
    text_light = colors.get('text_light', '#94A3B8')
    background = colors.get('background', '#F8FAFC')
    border = colors.get('border', '#E2E8F0')
    cover_bg = colors.get('cover_bg', '#0F172A')
    cover_text = colors.get('cover_text', '#FFFFFF')

    font_family = fonts.get('family', 'Segoe UI, system-ui, sans-serif')
    font_mono = fonts.get('mono', 'Fira Code, Monaco, monospace')

    h1_size = fonts.get('sizes', {}).get('h1', '36px')
    h2_size = fonts.get('sizes', {}).get('h2', '24px')
    h3_size = fonts.get('sizes', {}).get('h3', '18px')
    body_size = fonts.get('sizes', {}).get('body', '12px')
    table_size = fonts.get('sizes', {}).get('table', '11px')

    page_margin = spacing.get('page_margin', '40px')
    section_gap = spacing.get('section_gap', '30px')
    table_padding = spacing.get('table_padding', '12px')
    line_height = spacing.get('line_height', '1.6')

    logo = branding.get('logo', '🐾')

    # Build severity badge CSS from config
    badge_css = ""
    for severity in ['high', 'medium', 'low', 'informational', 'update_available']:
        sev_config = get_severity_config(config, severity)
        badge_name = 'update' if severity == 'update_available' else severity
        badge_css += f"""
        .badge-{badge_name} {{
            color: {sev_config['color']};
            background: {sev_config['bg']};
        }}"""

    # Extract data
    meta = findings.get('meta', {})
    discovery = findings.get('discovery', {}).get('results', [])
    ports = findings.get('ports', {}).get('results', [])
    external = findings.get('external', {})
    vulns = findings.get('vulns', {}).get('results', [])

    target = meta.get('target', 'Unknown')
    timestamp = meta.get('timestamp', '')

    # Parse timestamp for footer
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        footer_time = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        footer_time = timestamp

    # Count stats
    host_count = len(discovery)
    port_count = sum(len(h.get('open_ports', [])) for h in ports)
    external_count = len(external.get('open_ports', []))
    vuln_count = len(vulns)
    critical_count = len([v for v in vulns if any(f.get('severity') == 'high' for f in v.get('findings', []))])

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        @page {{
            size: A4;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: {font_family};
            font-size: {body_size};
            color: {text_dark};
            background: {background};
            line-height: {line_height};
            margin: 0;
            padding: 0;
        }}

        .page {{
            page-break-after: always;
            padding: {page_margin};
        }}

        .cover-page {{
            background: {cover_bg};
            color: {cover_text};
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: {page_margin};
            text-align: center;
        }}

        .cover-logo {{
            font-size: 72px;
            margin-bottom: 40px;
        }}

        .cover-title {{
            font-size: {h1_size};
            font-weight: 700;
            margin: 20px 0;
        }}

        .cover-subtitle {{
            font-size: {h2_size};
            color: {cover_text};
            opacity: 0.8;
            margin: 20px 0;
        }}

        .cover-meta {{
            font-size: {body_size};
            color: {cover_text};
            opacity: 0.6;
            margin-top: 60px;
        }}

        h1 {{
            font-size: {h1_size};
            color: {primary};
            margin: {section_gap} 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid {accent};
        }}

        h2 {{
            font-size: {h2_size};
            color: {primary};
            margin: 25px 0 15px 0;
        }}

        h3 {{
            font-size: {h3_size};
            color: {primary};
            margin: 15px 0 10px 0;
        }}

        .executive-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: {section_gap} 0;
        }}

        .summary-card {{
            background: {accent};
            color: white;
            padding: {table_padding};
            border-radius: 8px;
            text-align: center;
        }}

        .summary-card-value {{
            font-size: 32px;
            font-weight: 700;
            margin: 10px 0;
        }}

        .summary-card-label {{
            font-size: {body_size};
            opacity: 0.9;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: {table_size};
        }}

        thead {{
            background: {secondary};
            color: white;
        }}

        th {{
            padding: {table_padding};
            text-align: left;
            font-weight: 700;
            border: 1px solid {border};
        }}

        td {{
            padding: {table_padding};
            border: 1px solid {border};
            word-break: break-word;
        }}

        tbody tr:nth-child(even) {{
            background: {background};
        }}

        tbody tr:nth-child(odd) {{
            background: white;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            white-space: nowrap;
        }}

        .no-findings {{
            color: {text_light};
            font-style: italic;
            padding: 20px;
            text-align: center;
        }}

        .footer {{
            margin-top: {section_gap};
            padding-top: {table_padding};
            border-top: 1px solid {border};
            font-size: 10px;
            color: {text_light};
            text-align: center;
        }}

        .page-break {{
            page-break-after: always;
        }}{badge_css}
    </style>
</head>
<body>
"""

    # Cover page
    html += f"""    <div class="cover-page">
        <div class="cover-logo">{logo}</div>
        <div class="cover-title">{title}</div>
        <div class="cover-subtitle">{target}</div>
        <div class="cover-meta">
            <p>Scan Date: {timestamp.split('T')[0]}</p>
        </div>
    </div>
    <div class="page-break"></div>

    <div class="page">
        <h1>Executive Summary</h1>
        <div class="executive-summary">
            <div class="summary-card">
                <div class="summary-card-label">Hosts Discovered</div>
                <div class="summary-card-value">{host_count}</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">Open Ports</div>
                <div class="summary-card-value">{port_count}</div>
            </div>
"""

    if external_count > 0:
        html += f"""            <div class="summary-card">
                <div class="summary-card-label">External Ports</div>
                <div class="summary-card-value">{external_count}</div>
            </div>
"""

    html += f"""            <div class="summary-card">
                <div class="summary-card-label">Vulnerabilities</div>
                <div class="summary-card-value">{vuln_count}</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">Critical Issues</div>
                <div class="summary-card-value">{critical_count}</div>
            </div>
        </div>

        <h1>Host Discovery</h1>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"""

    # Sort discovery by IP
    discovery_sorted = sorted(discovery, key=lambda x: tuple(map(int, x['ip'].split('.'))))
    for host in discovery_sorted:
        hostname = host.get('hostname') or '—'
        html += f"""                <tr>
                    <td>{host['ip']}</td>
                    <td>{hostname}</td>
                    <td>Online</td>
                </tr>
"""

    html += """            </tbody>
        </table>

        <h1>Port & Service Inventory</h1>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
"""

    # Flatten and sort ports
    all_ports = []
    for host_data in ports:
        ip = host_data['ip']
        for port in host_data.get('open_ports', []):
            all_ports.append((ip, port))

    all_ports.sort(key=lambda x: (tuple(map(int, x[0].split('.'))), x[1]['port']))

    for ip, port in all_ports:
        product = port.get('product') or '—'
        version = port.get('version') or '—'
        html += f"""                <tr>
                    <td>{ip}</td>
                    <td>{port['port']}</td>
                    <td>{port['protocol']}</td>
                    <td>{port['service']}</td>
                    <td>{product}</td>
                    <td>{version}</td>
                </tr>
"""

    html += """            </tbody>
        </table>
"""

    # External ports section
    if external.get('open_ports'):
        html += f"""        <h1>External Ports Scan</h1>
        <p><strong>Public IP:</strong> {external.get('public_ip')}</p>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
"""
        ext_ports = sorted(external.get('open_ports', []), key=lambda x: x['port'])
        for port in ext_ports:
            product = port.get('product') or '—'
            version = port.get('version') or '—'
            html += f"""                <tr>
                    <td>{port['port']}</td>
                    <td>{port['protocol']}</td>
                    <td>{port['service']}</td>
                    <td>{product}</td>
                    <td>{version}</td>
                </tr>
"""
        html += """            </tbody>
        </table>
"""
    elif external:
        html += f"""        <h1>External Ports Scan</h1>
        <p><strong>Public IP:</strong> {external.get('public_ip')}</p>
        <p class="no-findings">No open ports detected on public IP</p>
"""

    # Vulnerabilities section
    html += """        <h1>Vulnerabilities & Findings</h1>
"""

    if vulns:
        # Sort by severity then IP
        severity_order = {'high': 0, 'medium': 1, 'low': 2, 'informational': 3}
        vulns_sorted = sorted(vulns, key=lambda x: (
            min((severity_order.get(f.get('severity', 'informational'), 99) for f in x.get('findings', [])), default=99),
            tuple(map(int, x['ip'].split('.')))
        ))

        html += """        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Port</th>
                    <th>Product</th>
                    <th>Version</th>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
"""

        for vuln in vulns_sorted:
            ip = vuln['ip']
            port = vuln['port']
            product = vuln.get('product', '—')
            version = vuln.get('version', '—')

            for finding in vuln.get('findings', []):
                if 'cve' in finding or 'issue' in finding:
                    # Handle both CVE format and issue format
                    identifier = finding.get('cve') or finding.get('issue', '')
                    severity = finding.get('severity', 'informational')
                    desc = finding.get('description', '')
                    sev_config = get_severity_config(config, severity)
                    badge_class = f"badge-{severity}"
                    severity_label = sev_config['label']
                    html += f"""                <tr>
                    <td>{ip}</td>
                    <td>{port}</td>
                    <td>{product}</td>
                    <td>{version}</td>
                    <td>{identifier}</td>
                    <td><span class="badge {badge_class}">{severity_label}</span></td>
                    <td>{desc}</td>
                </tr>
"""
                elif 'update_available' in finding:
                    update = finding['update_available']
                    desc = f"Update available: {update}"
                    sev_config = get_severity_config(config, 'update_available')
                    update_label = sev_config['label']
                    html += f"""                <tr>
                    <td>{ip}</td>
                    <td>{port}</td>
                    <td>{product}</td>
                    <td>{version}</td>
                    <td>Update Available</td>
                    <td><span class="badge badge-update">{update_label}</span></td>
                    <td>{desc}</td>
                </tr>
"""

        html += """            </tbody>
        </table>
"""
    else:
        html += """        <p class="no-findings">No vulnerabilities detected</p>
"""

    # Footer
    html += f"""        <div class="footer">
            <p>Generated by claude-snoop | {footer_time} | Target: {target}</p>
        </div>
    </div>
</body>
</html>"""

    return html

def main():
    if len(sys.argv) < 4:
        print("Usage: generate_report.py <findings.json> <design.md> <output.pdf> <title>")
        sys.exit(1)

    findings_path = sys.argv[1]
    design_path = sys.argv[2]
    output_pdf = sys.argv[3]
    title = sys.argv[4] if len(sys.argv) > 4 else "Audit Report"

    # Read findings
    with open(findings_path, 'r') as f:
        findings = json.load(f)

    # Parse design
    config = parse_design_md(design_path)

    # Generate HTML
    html = generate_html(findings, config, title)

    # Convert to PDF using weasyprint
    try:
        result = subprocess.run(
            ['weasyprint', '-', output_pdf],
            input=html.encode('utf-8'),
            capture_output=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"Error generating PDF: {result.stderr.decode()}")
            sys.exit(1)

        print(f"[✓] PDF report generated: {output_pdf}")
    except FileNotFoundError:
        print("Error: weasyprint not found. Install with: pip install weasyprint")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
