# claude-snoop Report Design Configuration

Customize PDF report appearance via `config/design.json`. All settings are optional — defaults provide a clean, professional audit report.

---

## Quick Customization Examples

### Change color scheme (dark → light)
```json
{
  "colors": {
    "primary": "#ffffff",
    "cover_bg": "#f5f5f5",
    "cover_text": "#1a1a2e",
    "text_dark": "#333333"
  }
}
```

### Change branding
```json
{
  "branding": {
    "logo_emoji": "🔐",
    "tool_name": "SecurityAudit Pro",
    "github_url": "your-org/your-tool"
  }
}
```

### Adjust severity colors (red → orange palette)
```json
{
  "severity": {
    "high": {
      "color": "#ff6b35",
      "label": "CRITICAL"
    },
    "medium": {
      "color": "#ff8c42",
      "label": "WARNING"
    },
    "low": {
      "color": "#ffa500",
      "label": "NOTICE"
    }
  }
}
```

---

## Configuration Reference

### `branding` — Report identity
- `logo_emoji` — Cover page emoji (default: 🐾)
- `tool_name` — Footer text (default: claude-snoop)
- `github_url` — Footer link (default: github.com/sid-engel/claude-snoop)

### `colors` — Palette
- `primary` — Main headers, table headers (default: #1a1a2e dark navy)
- `secondary` — Alternate headers (default: #16213e darker navy)
- `accent` — Highlights, accents (default: #0f3460 deep blue)
- `text_dark` — Body text (default: #2c3e50)
- `text_light` — Subtitle, metadata (default: #a0aec0 light gray)
- `text_muted` — Labels, hints (default: #718096 muted gray)
- `bg_light` — Table alternating rows (default: #f7f8fa light)
- `bg_lighter` — Borders, dividers (default: #e2e8f0)
- `border` — Table/section borders (default: #e2e8f0)
- `cover_bg` — Cover page background (default: #1a1a2e)
- `cover_text` — Cover page text (default: #ffffff white)

### `severity` — Vulnerability severity badges
Each severity level has:
- `color` — Badge background color (hex)
- `label` — Badge text (uppercase)

Levels: `high`, `medium`, `low`, `informational`, `update_available`

```json
{
  "severity": {
    "high": {
      "color": "#d32f2f",
      "label": "HIGH"
    }
  }
}
```

### `fonts` — Typography
- `family` — Body font stack (default: Helvetica/Arial)
- `mono` — Code/monospace font (default: Courier New)
- `sizes` — Font sizes in px:
  - `body`, `h1`, `h2`, `h3`, `h4`, `table_header`, `table_cell`, `small`, `label`
- `weights` — Font weights:
  - `normal` (400), `semibold` (600), `bold` (700)

```json
{
  "fonts": {
    "family": "'Segoe UI', Tahoma, sans-serif",
    "sizes": {
      "body": "12px",
      "h1": "40px"
    }
  }
}
```

### `spacing` — Margins, padding, gaps
- `cover_padding` — Cover page padding (default: 60px)
- `page_padding` — Report page padding (default: 40px 48px)
- `section_margin_top` — Section top margin (default: 32px)
- `section_margin_bottom` — Section bottom margin (default: 16px)
- `subsection_margin_top` — Subsection top margin (default: 24px)
- `table_margin_bottom` — Table bottom margin (default: 16px)
- `table_padding` — Cell padding (default: 6px 10px)
- `table_header_padding` — Header cell padding (default: 7px 10px)
- `summary_padding` — Summary strip padding (default: 20px 24px)
- `summary_gap` — Gap between summary items (default: 24px)
- `meta_grid_gap` — Cover metadata grid gap (default: 24px)

### `layout` — Structural settings
- `cover_height` — Cover page height (default: 100vh full viewport)
- `cover_display` — Cover layout (default: flex)
- `cover_direction` — Flex direction (default: column)
- `cover_justify` — Flex justify (default: center)
- `cover_page_break` — Page break after cover (default: always)
- `max_width` — Page max width (default: 100%)
- `table_width` — Table width (default: 100%)

### `borders` — Border styles
- `radius` — Border radius (default: 6px)
- `table_collapse` — Table cell collapse (default: collapse)
- `section_border_width` — Section border width (default: 2px)

### `opacity` — Badge styling
- `badge_padding` — Badge padding (default: 2px 6px)
- `badge_radius` — Badge radius (default: 3px)

---

## Full Default Config

See `config/design.json` for complete defaults. Edit any values to customize.

To reset to defaults, delete `config/design.json` (or restore from git).

---

## Examples

### Professional (Dark, Blue)
Current default. Conservative, corporate-friendly.

### Tech (High Contrast, Dark)
```json
{
  "colors": {
    "primary": "#0d47a1",
    "accent": "#00bcd4",
    "cover_bg": "#0a0e27"
  },
  "severity": {
    "high": {"color": "#ff1744"}
  }
}
```

### Minimal (Light, Simple)
```json
{
  "colors": {
    "primary": "#333333",
    "cover_bg": "#f0f0f0",
    "cover_text": "#333333",
    "text_dark": "#444444"
  }
}
```

### Custom Brand (Your Colors)
```json
{
  "branding": {
    "logo_emoji": "🛡️",
    "tool_name": "Acme Security Audit"
  },
  "colors": {
    "primary": "#c41e3a",
    "accent": "#ffd700"
  },
  "severity": {
    "high": {"color": "#c41e3a"},
    "medium": {"color": "#ff9800"}
  }
}
```

---

## Tips

- Colors must be valid hex (`#RRGGBB`) or CSS color names
- Font sizes must include units (px, em, pt)
- Spacing values can be single (`10px`) or multiple (`10px 20px`)
- Severity colors should have sufficient contrast with white text
- Test PDF after changes to verify rendering
- Not all CSS properties are supported in weasyprint (see weasyprint docs for limitations)

---

## Usage

Report generation automatically loads `config/design.json`. No need to change code — just edit the config.

```bash
# Generate report with custom design
python3 scripts/report.py --input findings.json --output report.pdf --title "Audit"
```

Design settings are applied automatically.
