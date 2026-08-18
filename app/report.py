"""Generate a self-contained downloadable HTML report from scan data."""

from datetime import datetime
from typing import Any

from jinja2 import Environment, BaseLoader

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS Report — {{ domain }}</title>
<style>
  :root {
    --canvas: #0C0D0E;
    --surface: #141619;
    --raised: #1B1E22;
    --hairline: #2A2E34;
    --text-primary: #F2F0EA;
    --text-secondary: #B5B8BC;
    --text-muted: #7E858E;
    --accent: #65B9E8;
    --success: #63B995;
    --warning: #E0A458;
    --danger: #E36D6D;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--canvas);
    color: var(--text-secondary);
    font-family: 'Geist', 'Inter', system-ui, sans-serif;
    font-size: 15px;
    line-height: 1.65;
    padding: 48px 24px;
  }
  .container { max-width: 780px; margin: 0 auto; }
  h1 { color: var(--text-primary); font-size: 28px; font-weight: 600; letter-spacing: -0.02em; margin-bottom: 6px; }
  .meta { color: var(--text-muted); font-family: 'Geist Mono', monospace; font-size: 12px; margin-bottom: 40px; }
  h2 { color: var(--text-primary); font-size: 16px; font-weight: 600; margin: 40px 0 16px; border-bottom: 1px solid var(--hairline); padding-bottom: 8px; }
  .summary-row { display: flex; gap: 16px; margin-bottom: 40px; flex-wrap: wrap; }
  .badge {
    display: flex; flex-direction: column; align-items: center;
    padding: 16px 28px; border-radius: 8px; background: var(--surface);
    border: 1px solid var(--hairline); min-width: 100px;
  }
  .badge .count { font-size: 28px; font-weight: 700; font-family: 'Geist Mono', monospace; line-height: 1; }
  .badge .label { font-size: 11px; color: var(--text-muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.08em; }
  .badge.errors .count { color: var(--danger); }
  .badge.warnings .count { color: var(--warning); }
  .badge.info .count { color: var(--accent); }
  .finding {
    display: flex; gap: 12px; padding: 12px 16px;
    border-radius: 6px; margin-bottom: 8px;
    border-left: 3px solid;
    background: var(--surface);
  }
  .finding.error { border-color: var(--danger); }
  .finding.warning { border-color: var(--warning); }
  .finding.info { border-color: var(--accent); }
  .severity-tag {
    font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; padding: 2px 6px; border-radius: 3px;
    white-space: nowrap; align-self: flex-start; margin-top: 2px;
  }
  .error .severity-tag { background: rgba(227,109,109,0.15); color: var(--danger); }
  .warning .severity-tag { background: rgba(224,164,88,0.15); color: var(--warning); }
  .info .severity-tag { background: rgba(101,185,232,0.15); color: var(--accent); }
  .finding-rtype { font-family: 'Geist Mono', monospace; font-size: 11px; color: var(--text-muted); margin-top: 2px; }
  .finding-msg { color: var(--text-primary); font-size: 14px; line-height: 1.5; }
  .finding-msg code { font-family: 'Geist Mono', monospace; font-size: 12px; background: var(--raised); padding: 1px 4px; border-radius: 3px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 8px; }
  th { text-align: left; padding: 8px 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); border-bottom: 1px solid var(--hairline); }
  td { padding: 10px 12px; font-family: 'Geist Mono', monospace; font-size: 12.5px; color: var(--text-primary); border-bottom: 1px solid var(--hairline); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 100px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; }
  .pill-ok { background: rgba(99,185,149,0.15); color: var(--success); }
  .pill-fail { background: rgba(227,109,109,0.15); color: var(--danger); }
  .pill-info { background: rgba(101,185,232,0.12); color: var(--accent); }
  .status-not_found, .status-timeout, .status-error { color: var(--text-muted); font-style: italic; font-size: 12px; }
  .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--hairline); color: var(--text-muted); font-size: 12px; font-family: 'Geist Mono', monospace; }
</style>
</head>
<body>
<div class="container">
  <h1>DNS Report — {{ domain }}</h1>
  <p class="meta">Scanned {{ scan_timestamp }} &nbsp;·&nbsp; dns-analyzer v1</p>

  <div class="summary-row">
    <div class="badge errors"><span class="count">{{ summary.errors }}</span><span class="label">Errors</span></div>
    <div class="badge warnings"><span class="count">{{ summary.warnings }}</span><span class="label">Warnings</span></div>
    <div class="badge info"><span class="count">{{ summary.info }}</span><span class="label">Info</span></div>
  </div>

  <h2>Findings</h2>
  {% if findings %}
    {% for f in findings %}
    <div class="finding {{ f.severity }}">
      <div>
        <span class="severity-tag">{{ f.severity }}</span>
        <div class="finding-rtype">{{ f.record_type }}</div>
      </div>
      <div class="finding-msg">{{ f.message | replace('`', '<code>') | replace('`', '</code>') }}</div>
    </div>
    {% endfor %}
  {% else %}
    <p style="color: var(--success); padding: 12px 0;">✓ No issues found.</p>
  {% endif %}

  {% for rtype, entry in records.items() %}
  <h2>{{ rtype }} Records</h2>
  {% if entry.status != 'ok' %}
    <p class="status-{{ entry.status }}">Status: {{ entry.status }}</p>
  {% else %}
    {% if rtype == 'SOA' %}
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        {% for k, v in entry.records.items() %}
        <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
        {% endfor %}
        <tr><td>TTL</td><td>{{ entry.ttl }}s</td></tr>
      </table>
    {% elif rtype == 'MX' %}
      <table>
        <tr><th>Priority</th><th>Host</th><th>Resolves</th></tr>
        {% for r in entry.records %}
        <tr>
          <td>{{ r.priority }}</td>
          <td>{{ r.host }}</td>
          <td><span class="pill {% if r.resolves %}pill-ok{% else %}pill-fail{% endif %}">{% if r.resolves %}yes{% else %}no{% endif %}</span></td>
        </tr>
        {% endfor %}
      </table>
    {% elif rtype == 'NS' %}
      <table>
        <tr><th>Host</th><th>Resolves</th></tr>
        {% for r in entry.records %}
        <tr>
          <td>{{ r.host }}</td>
          <td><span class="pill {% if r.resolves %}pill-ok{% else %}pill-fail{% endif %}">{% if r.resolves %}yes{% else %}no{% endif %}</span></td>
        </tr>
        {% endfor %}
      </table>
    {% else %}
      <table>
        <tr><th>Value</th></tr>
        {% for r in entry.records %}
        <tr><td>{{ r }}</td></tr>
        {% endfor %}
      </table>
    {% endif %}
    <p style="color: var(--text-muted); font-size: 12px; margin-top: 4px; font-family: 'Geist Mono', monospace;">TTL: {{ entry.ttl }}s</p>
  {% endif %}
  {% endfor %}

  <div class="footer">Generated by dns-analyzer · {{ domain }} · {{ scan_timestamp }}</div>
</div>
</body>
</html>"""

_env = Environment(loader=BaseLoader(), autoescape=False)
_tmpl = _env.from_string(_TEMPLATE)


def build_report(domain: str, scan_timestamp: str, records: dict, findings: list, summary: dict) -> str:
    """Render a self-contained HTML report string."""
    return _tmpl.render(
        domain=domain,
        scan_timestamp=scan_timestamp,
        records=records,
        findings=findings,
        summary=summary,
    )
