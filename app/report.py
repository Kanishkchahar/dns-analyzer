"""Generate a self-contained downloadable HTML report from scan data."""

import html
import re
from datetime import datetime
from typing import Any

from jinja2 import Environment, BaseLoader
from markupsafe import Markup

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
  .pill-warn { background: rgba(224,164,88,0.15); color: var(--warning); }
  .status-not_found, .status-timeout, .status-error { color: var(--text-muted); font-style: italic; font-size: 12px; }
  .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--hairline); color: var(--text-muted); font-size: 12px; font-family: 'Geist Mono', monospace; }

  /* ── Email Score ── */
  .score-section {
    display: flex; align-items: center; gap: 28px;
    background: var(--surface); border: 1px solid var(--hairline);
    border-radius: 12px; padding: 28px 32px; margin-bottom: 40px;
  }
  .score-ring {
    position: relative; width: 100px; height: 100px; flex-shrink: 0;
  }
  .score-ring svg { transform: rotate(-90deg); }
  .score-ring-bg { fill: none; stroke: var(--hairline); stroke-width: 8; }
  .score-ring-fg { fill: none; stroke-width: 8; stroke-linecap: round; transition: stroke-dashoffset 0.6s ease; }
  .score-grade {
    position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }
  .score-grade-letter { font-size: 28px; font-weight: 700; color: var(--text-primary); font-family: 'Geist Mono', monospace; line-height: 1; }
  .score-grade-num { font-size: 12px; color: var(--text-muted); font-family: 'Geist Mono', monospace; }
  .score-details h3 { color: var(--text-primary); font-size: 18px; font-weight: 600; margin-bottom: 4px; }
  .score-details p { color: var(--text-muted); font-size: 13px; }

  /* ── Copy block ── */
  .copy-block {
    background: var(--raised); border: 1px solid var(--hairline);
    border-radius: 6px; padding: 14px 16px;
    font-family: 'Geist Mono', monospace; font-size: 12px;
    color: var(--accent); word-break: break-all;
    margin: 8px 0;
  }
  .auth-card {
    background: var(--surface); border: 1px solid var(--hairline);
    border-radius: 8px; padding: 18px 20px; margin-bottom: 12px;
  }
  .auth-card-title {
    font-size: 13px; font-weight: 700; color: var(--text-primary);
    text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 10px;
    display: flex; align-items: center; gap: 8px;
  }
  .auth-card-row { display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; }
  .auth-card-key { color: var(--text-muted); }
  .auth-card-val { color: var(--text-primary); font-family: 'Geist Mono', monospace; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
  <h1>DNS Report — {{ domain }}</h1>
  <p class="meta">Scanned {{ scan_timestamp }} &nbsp;·&nbsp; dns-analyzer v2 — InboxShield Edition</p>

  {# ── Email Health Score ── #}
  {% if email_auth and email_auth.score %}
  {% set sc = email_auth.score %}
  {% set circ = 283 %}
  {% set offset = circ - (circ * sc.score / 100) %}
  {% if sc.score >= 85 %}{% set ring_color = "var(--success)" %}
  {% elif sc.score >= 55 %}{% set ring_color = "var(--warning)" %}
  {% else %}{% set ring_color = "var(--danger)" %}{% endif %}
  <div class="score-section">
    <div class="score-ring">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle class="score-ring-bg" cx="50" cy="50" r="45"/>
        <circle class="score-ring-fg" cx="50" cy="50" r="45"
                stroke="{{ ring_color }}"
                stroke-dasharray="{{ circ }}"
                stroke-dashoffset="{{ offset }}"/>
      </svg>
      <div class="score-grade">
        <span class="score-grade-letter">{{ sc.grade }}</span>
        <span class="score-grade-num">{{ sc.score }}/100</span>
      </div>
    </div>
    <div class="score-details">
      <h3>Email Health: {{ sc.label }}</h3>
      <p>Based on SPF, DMARC, and DKIM analysis for {{ domain }}</p>
    </div>
  </div>
  {% endif %}

  <div class="summary-row">
    <div class="badge errors"><span class="count">{{ summary.errors }}</span><span class="label">Errors</span></div>
    <div class="badge warnings"><span class="count">{{ summary.warnings }}</span><span class="label">Warnings</span></div>
    <div class="badge info"><span class="count">{{ summary.info }}</span><span class="label">Info</span></div>
  </div>

  {# ── Email Authentication Details ── #}
  {% if email_auth %}
  <h2>📧 Email Authentication</h2>

  {# SPF #}
  <div class="auth-card">
    <div class="auth-card-title">
      {% if email_auth.spf %}<span class="pill pill-ok">Found</span>{% else %}<span class="pill pill-fail">Missing</span>{% endif %}
      SPF (Sender Policy Framework)
    </div>
    {% if email_auth.spf %}
    <div class="copy-block">{{ email_auth.spf.raw }}</div>
    {% if email_auth.spf_lookups %}
    <div class="auth-card-row">
      <span class="auth-card-key">DNS Lookups</span>
      <span class="auth-card-val">
        {{ email_auth.spf_lookups.total_lookups }} / {{ email_auth.spf_lookups.limit }}
        {% if email_auth.spf_lookups.over_limit %}<span class="pill pill-fail">Over Limit</span>{% else %}<span class="pill pill-ok">OK</span>{% endif %}
      </span>
    </div>
    {% endif %}
    {% if email_auth.spf.all_mechanism %}
    <div class="auth-card-row">
      <span class="auth-card-key">Policy</span>
      <span class="auth-card-val">{{ email_auth.spf.all_mechanism }}</span>
    </div>
    {% endif %}
    {% if email_auth.spf_flattened and email_auth.spf_lookups and email_auth.spf_lookups.over_limit %}
    <h2 style="font-size:13px; margin-top:16px;">✅ Suggested Flattened SPF Record</h2>
    <div class="copy-block">{{ email_auth.spf_flattened.flattened_record }}</div>
    <p style="font-size:12px; color: var(--text-muted); margin-top:4px;">This flattened record uses 0 DNS lookups (all IPs resolved to ip4/ip6 entries).</p>
    {% endif %}
    {% else %}
    <p style="color: var(--text-muted); font-size: 13px;">No SPF record found in TXT records.</p>
    {% endif %}
  </div>

  {# DMARC #}
  <div class="auth-card">
    <div class="auth-card-title">
      {% if email_auth.dmarc %}<span class="pill pill-ok">Found</span>{% else %}<span class="pill pill-fail">Missing</span>{% endif %}
      DMARC (Domain-based Message Authentication)
    </div>
    {% if email_auth.dmarc %}
    <div class="copy-block">{{ email_auth.dmarc.raw }}</div>
    <div class="auth-card-row">
      <span class="auth-card-key">Policy</span>
      <span class="auth-card-val">
        {{ email_auth.dmarc.policy }}
        {% if email_auth.dmarc.policy == 'reject' %}<span class="pill pill-ok">Strong</span>
        {% elif email_auth.dmarc.policy == 'quarantine' %}<span class="pill pill-warn">Moderate</span>
        {% else %}<span class="pill pill-fail">Weak</span>{% endif %}
      </span>
    </div>
    <div class="auth-card-row">
      <span class="auth-card-key">Enforcement</span>
      <span class="auth-card-val">{{ email_auth.dmarc.pct }}% of emails</span>
    </div>
    {% if email_auth.dmarc.rua %}
    <div class="auth-card-row">
      <span class="auth-card-key">Reports To</span>
      <span class="auth-card-val">{{ email_auth.dmarc.rua }}</span>
    </div>
    {% endif %}
    {% else %}
    <p style="color: var(--text-muted); font-size: 13px;">No DMARC record found at _dmarc.{{ domain }}</p>
    {% endif %}
  </div>

  {# DKIM #}
  <div class="auth-card">
    <div class="auth-card-title">
      {% if email_auth.dkim and email_auth.dkim.has_dkim %}<span class="pill pill-ok">Found</span>{% else %}<span class="pill pill-warn">Not Found</span>{% endif %}
      DKIM (DomainKeys Identified Mail)
    </div>
    {% if email_auth.dkim and email_auth.dkim.has_dkim %}
      {% for sel in email_auth.dkim.selectors_found %}
      <div class="auth-card-row">
        <span class="auth-card-key">{{ sel.selector }}</span>
        <span class="auth-card-val">
          {% if sel.has_key %}<span class="pill pill-ok">Valid Key</span>{% else %}<span class="pill pill-fail">Empty Key</span>{% endif %}
          {{ sel.key_type }} · {{ sel.public_key }}
        </span>
      </div>
      {% endfor %}
    {% else %}
    <p style="color: var(--text-muted); font-size: 13px;">No DKIM records found for common selectors. Custom selectors may exist.</p>
    {% endif %}
  </div>
  {% endif %}

  {# ── Security Suite ── #}
  {% if security %}
  <h2>🛡️ Advanced Security &amp; Threat Defense</h2>
  <div class="auth-card">
    <div class="auth-card-title">
      {% if security.dnssec and security.dnssec.enabled %}<span class="pill pill-ok">Secured</span>{% else %}<span class="pill pill-warn">Unsigned</span>{% endif %}
      DNSSEC Validation
    </div>
    <div class="auth-card-row">
      <span class="auth-card-key">Status</span>
      <span class="auth-card-val">{{ security.dnssec.status }}</span>
    </div>
    <div class="auth-card-row">
      <span class="auth-card-key">DNSKEY / DS Records</span>
      <span class="auth-card-val">{{ security.dnssec.dnskey_count }} keys / {{ security.dnssec.ds_count }} DS</span>
    </div>
  </div>

  <div class="auth-card">
    <div class="auth-card-title">
      {% if security.takeover and security.takeover.vulnerable %}<span class="pill pill-fail">Critical Alert</span>{% else %}<span class="pill pill-ok">Protected</span>{% endif %}
      Subdomain Takeover Defense
    </div>
    <div class="auth-card-row">
      <span class="auth-card-key">Status</span>
      <span class="auth-card-val">{{ security.takeover.status }}</span>
    </div>
    <div class="auth-card-row">
      <span class="auth-card-key">Provider</span>
      <span class="auth-card-val">{{ security.takeover.provider }}</span>
    </div>
  </div>

  <div class="auth-card">
    <div class="auth-card-title">
      {% if security.bimi and security.bimi.has_bimi %}<span class="pill pill-ok">Active</span>{% elif security.bimi and security.bimi.dmarc_eligible %}<span class="pill pill-info">Eligible</span>{% else %}<span class="pill pill-warn">Not Configured</span>{% endif %}
      BIMI Email Brand Inboxes
    </div>
    <div class="auth-card-row">
      <span class="auth-card-key">Status</span>
      <span class="auth-card-val">{{ security.bimi.status }}</span>
    </div>
  </div>
  {% endif %}

  <h2>Findings</h2>
  {% if findings %}
    {% for f in findings %}
    <div class="finding {{ f.severity }}">
      <div>
        <span class="severity-tag">{{ f.severity }}</span>
        <div class="finding-rtype">{{ f.record_type }}</div>
      </div>
      <div class="finding-msg">{{ f.message | format_msg }}</div>
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

  <div class="footer">Generated by dns-analyzer v2 · InboxShield Edition · {{ domain }} · {{ scan_timestamp }}</div>
</div>
</body>
</html>"""


def format_finding_msg(msg: str) -> Markup:
    """Safely format backtick code spans without allowing untrusted HTML injection."""
    escaped = html.escape(str(msg))
    formatted = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return Markup(formatted)


_env = Environment(loader=BaseLoader(), autoescape=True)
_env.filters["format_msg"] = format_finding_msg
_tmpl = _env.from_string(_TEMPLATE)


def build_report(
    domain: str,
    scan_timestamp: str,
    records: dict,
    findings: list,
    summary: dict,
    email_auth: Any = None,
    security: Any = None,
    remediation: Any = None,
) -> str:
    """Render a self-contained HTML report string."""
    return _tmpl.render(
        domain=domain,
        scan_timestamp=scan_timestamp,
        records=records,
        findings=findings,
        summary=summary,
        email_auth=email_auth,
        security=security,
        remediation=remediation,
    )
