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
  .badge.inconclusive .count { color: var(--warning); }
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
  .finding-code { color: var(--accent); font: 10px 'Geist Mono', monospace; margin-left: 8px; }
  .finding-guidance { color: var(--text-secondary); font-size: 12px; margin-top: 9px; }
  .finding-guidance summary { color: var(--accent); cursor: pointer; }
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
  <p class="meta">Scanned {{ scan_timestamp }} &nbsp;·&nbsp; dns-analyzer 2.2.0 — InboxShield Edition</p>

  {% if domain_score %}
  <section class="score-section" aria-label="Overall domain score">
    <div class="score-details">
      <h3>Overall Domain Grade: {{ domain_score.grade }}</h3>
      <p>{{ domain_score.score }}/100 · {{ domain_score.label }}</p>
    </div>
  </section>
  {% endif %}

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
    <div class="badge inconclusive"><span class="count">{{ summary.inconclusive|default(0) }}</span><span class="label">Inconclusive</span></div>
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
    {% if email_auth.spf_flattened and email_auth.spf_flattened.get('can_flatten', true) and email_auth.spf_flattened.flattened_record and email_auth.spf_lookups and email_auth.spf_lookups.over_limit %}
    <h2 style="font-size:13px; margin-top:16px;">✅ Suggested Flattened SPF Record</h2>
    <div class="copy-block">{{ email_auth.spf_flattened.flattened_record }}</div>
    <p style="font-size:12px; color: var(--text-muted); margin-top:4px;">This flattened record uses 0 DNS lookups (all IPs resolved to ip4/ip6 entries).</p>
    {% elif email_auth.spf_flattened and email_auth.spf_flattened.get('can_flatten') is false and email_auth.spf_lookups and email_auth.spf_lookups.over_limit %}
    <h2 style="font-size:13px; margin-top:16px;">⚠️ SPF Flattening Notice</h2>
    <p style="font-size:12px; color: var(--warning); margin-top:4px;">Automated flattening is not safe for this record: {{ email_auth.spf_flattened.reason }}. Manual optimization advised.</p>
    {% endif %}
    {% else %}
    <p style="color: var(--text-muted); font-size: 13px;">No SPF record found in TXT records.</p>
    {% endif %}
  </div>

  {# DMARC #}
  <div class="auth-card">
    <div class="auth-card-title">
      {% if email_auth.dmarc and email_auth.dmarc.status == 'inconclusive' %}<span class="pill pill-warn">Could Not Verify</span>
      {% elif email_auth.dmarc %}<span class="pill pill-ok">Found</span>{% else %}<span class="pill pill-fail">Missing</span>{% endif %}
      DMARC (Domain-based Message Authentication)
    </div>
    {% if email_auth.dmarc and email_auth.dmarc.status == 'inconclusive' %}
    <p style="color:var(--text-muted);font-size:13px;">{{ email_auth.dmarc.reason or 'DMARC lookup was inconclusive.' }}</p>
    {% elif email_auth.dmarc %}
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
      {% if email_auth.dkim and email_auth.dkim.status == 'inconclusive' %}<span class="pill pill-warn">Could Not Verify</span>
      {% elif email_auth.dkim and email_auth.dkim.has_dkim %}<span class="pill pill-ok">Found</span>{% else %}<span class="pill pill-warn">Not Found</span>{% endif %}
      DKIM (DomainKeys Identified Mail)
    </div>
    {% if email_auth.dkim and email_auth.dkim.status == 'inconclusive' %}
    <p style="color:var(--text-muted);font-size:13px;">{{ email_auth.dkim.reason or 'DKIM selector lookups were inconclusive.' }}</p>
    {% elif email_auth.dkim and email_auth.dkim.has_dkim %}
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

  {% if email_auth and (email_auth.mta_sts or email_auth.tls_rpt) %}
  <h2>✉️ Mail Transport Security</h2>
  <div class="auth-card">
    <div class="auth-card-title"><span class="pill {% if email_auth.mta_sts.status == 'configured' %}pill-ok{% elif email_auth.mta_sts.status == 'inconclusive' %}pill-warn{% else %}pill-info{% endif %}">{{ email_auth.mta_sts.status|default('unavailable') }}</span>MTA-STS</div>
    {% if email_auth.mta_sts.reason or email_auth.mta_sts.policy_reason %}<p style="color:var(--text-muted);font-size:13px;">{{ email_auth.mta_sts.reason or email_auth.mta_sts.policy_reason }}</p>{% endif %}
    {% if email_auth.mta_sts.policy %}<div class="auth-card-row"><span class="auth-card-key">Policy mode</span><span class="auth-card-val">{{ email_auth.mta_sts.policy.mode }} · max_age {{ email_auth.mta_sts.policy.max_age }}</span></div>{% endif %}
    <div class="auth-card-row"><span class="auth-card-key">Policy file</span><span class="auth-card-val">{{ email_auth.mta_sts.policy_status|default('not fetched') }}</span></div>
  </div>
  <div class="auth-card">
    <div class="auth-card-title"><span class="pill {% if email_auth.tls_rpt.status == 'configured' %}pill-ok{% elif email_auth.tls_rpt.status == 'inconclusive' %}pill-warn{% else %}pill-info{% endif %}">{{ email_auth.tls_rpt.status|default('unavailable') }}</span>TLS-RPT</div>
    {% if email_auth.tls_rpt.reason %}<p style="color:var(--text-muted);font-size:13px;">{{ email_auth.tls_rpt.reason }}</p>{% endif %}
    {% if email_auth.tls_rpt.reporting_uris %}<div class="auth-card-row"><span class="auth-card-key">Reporting destinations</span><span class="auth-card-val">{{ email_auth.tls_rpt.reporting_uris|join(', ') }}</span></div>{% endif %}
  </div>
  {% endif %}

  {# ── Security Suite ── #}
  {% if security %}
  <h2>🛡️ Advanced Security &amp; Threat Defense</h2>
  <div class="auth-card">
    <div class="auth-card-title">
      {% if security.dnssec and security.dnssec.status == 'delegation_match_verified' %}<span class="pill pill-ok">Delegation Verified</span>
      {% elif security.dnssec and security.dnssec.status == 'incomplete_chain' %}<span class="pill pill-warn">Incomplete Chain</span>
      {% elif security.dnssec and security.dnssec.status == 'bogus' %}<span class="pill pill-fail">Bogus</span>
      {% elif security.dnssec and security.dnssec.status == 'inconclusive' %}<span class="pill pill-warn">Could Not Verify</span>
      {% else %}<span class="pill pill-warn">Unsigned</span>{% endif %}
      DNSSEC Validation
    </div>
    <div class="auth-card-row">
      <span class="auth-card-key">Status</span>
      <span class="auth-card-val">{{ security.dnssec.status }}</span>
    </div>
    {% if security.dnssec and security.dnssec.status == 'delegation_match_verified' %}
    <div class="auth-card-row">
      <span class="auth-card-key">Validation Scope</span>
      <span class="auth-card-val">DS-to-DNSKEY match verified; RRSIG and root trust-anchor chain not validated</span>
    </div>
    {% endif %}
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

  {% if tls %}
  <h2>🔒 TLS &amp; HTTPS Posture</h2>
  <div class="auth-card">
    <div class="auth-card-title">
      {% if tls.status == 'complete' %}<span class="pill pill-ok">Checked</span>
      {% elif tls.status == 'blocked' %}<span class="pill pill-fail">Blocked</span>
      {% else %}<span class="pill pill-warn">{{ tls.status|default('Unavailable') }}</span>{% endif %}
      TLS Certificate and HTTPS
    </div>
    {% if tls.reason %}<p style="color:var(--text-muted);font-size:13px;margin-bottom:8px;">{{ tls.reason }}</p>{% endif %}
    <div class="auth-card-row"><span class="auth-card-key">Protocol / Cipher</span><span class="auth-card-val">{{ tls.tls_version or 'Unavailable' }}{% if tls.cipher %} · {{ tls.cipher }}{% endif %}</span></div>
    {% if tls.certificate %}
    <div class="auth-card-row"><span class="auth-card-key">Certificate Issuer</span><span class="auth-card-val">{{ tls.certificate.issuer or 'Unknown' }}</span></div>
    <div class="auth-card-row"><span class="auth-card-key">Valid Until</span><span class="auth-card-val">{{ tls.certificate.valid_until or 'Unavailable' }} · {{ tls.certificate.days_remaining }} days remaining</span></div>
    <div class="auth-card-row"><span class="auth-card-key">Hostname Match</span><span class="auth-card-val">{{ 'Yes' if tls.certificate.san_matched else 'No' }}</span></div>
    {% endif %}
    {% if tls.https_redirect %}
    <div class="auth-card-row"><span class="auth-card-key">HTTP → HTTPS</span><span class="auth-card-val">{{ 'Enforced' if tls.https_redirect.enforced else 'Not detected' }}{% if tls.https_redirect.status_code %} · HTTP {{ tls.https_redirect.status_code }}{% endif %}{% if tls.https_redirect.location %} · {{ tls.https_redirect.location }}{% endif %}</span></div>
    {% endif %}
    {% if tls.security_headers %}
    <div class="auth-card-row"><span class="auth-card-key">Security Headers</span><span class="auth-card-val">HSTS {{ 'present' if tls.security_headers.hsts else 'missing' }} · CSP {{ 'present' if tls.security_headers.csp else 'missing' }} · X-Frame-Options {{ tls.security_headers.x_frame_options or 'missing' }} · X-Content-Type-Options {{ tls.security_headers.x_content_type_options or 'missing' }}</span></div>
    <div class="auth-card-row"><span class="auth-card-key">Isolation Headers</span><span class="auth-card-val">Permissions-Policy {{ tls.security_headers.permissions_policy or 'missing' }} · COOP {{ tls.security_headers.cross_origin_opener_policy or 'missing' }} · CORP {{ tls.security_headers.cross_origin_resource_policy or 'missing' }}</span></div>
    {% if tls.security_headers.csp_risks %}<div class="auth-card-row"><span class="auth-card-key">CSP Review</span><span class="auth-card-val">{{ tls.security_headers.csp_risks|join('; ') }}</span></div>{% endif %}
    {% if tls.security_headers.cookies %}<div class="auth-card-row"><span class="auth-card-key">Cookie flags</span><span class="auth-card-val">{{ tls.security_headers.cookies|length }} cookie(s); values not stored{% for cookie in tls.security_headers.cookies if cookie.missing %}<br>{{ cookie.name }} missing {{ cookie.missing|join(', ') }}{% endfor %}</span></div>{% endif %}
    {% endif %}
    {% if tls.http_methods %}<div class="auth-card-row"><span class="auth-card-key">OPTIONS methods</span><span class="auth-card-val">{{ tls.http_methods.advertised|join(', ') if tls.http_methods.advertised else 'Allow header unavailable' }}{% if tls.http_methods.review_methods %} · Review: {{ tls.http_methods.review_methods|join(', ') }}{% endif %} · no write probe sent</span></div>{% endif %}
  </div>
  {% endif %}

  {% if subdomains %}
  <h2>🌐 Passive Subdomain Inventory</h2>
  <div class="auth-card">
    <div class="auth-card-title"><span class="pill {% if subdomains.state == 'DISCOVERY_COMPLETED' %}pill-ok{% elif subdomains.state == 'NO_RESULTS' %}pill-info{% else %}pill-warn{% endif %}">{{ (subdomains.state or subdomains.status or 'unknown')|replace('_', ' ')|lower }}</span>Certificate Transparency Results</div>
    <p style="color:var(--text-muted);font-size:12px;margin-bottom:8px;">Source: {{ subdomains.source|default('not reported') }} · Checked: {{ subdomains.timestamp|default('time not reported') }}{% if subdomains.attempts is defined %} · Requests: {{ subdomains.attempts }}{% endif %}</p>
    {% if subdomains.reason %}<p style="color:var(--text-muted);font-size:13px;margin-bottom:8px;">{{ subdomains.reason }}</p>{% endif %}
    <div class="auth-card-row"><span class="auth-card-key">Discovered</span><span class="auth-card-val">{{ subdomains.discovered_count|default(0) }}{% if subdomains.discovered_total and subdomains.discovered_total != subdomains.discovered_count %} of {{ subdomains.discovered_total }}{% endif %}</span></div>
    {% if subdomains.subdomains %}
    <table><thead><tr><th>Hostname</th><th>State</th><th>Addresses / CNAME</th><th>Risk tags</th><th>First seen</th></tr></thead><tbody>
      {% for host in subdomains.subdomains %}<tr><td>{{ host.subdomain }}</td><td>{{ host.status }}{% if host.takeover and host.takeover.vulnerable %} · takeover risk{% endif %}</td><td>{{ (host.ips or [])|join(', ') }}{% if host.cname %} · {{ host.cname }}{% endif %}</td><td>{{ (host.risk_tags or [])|join(', ') }}</td><td>{{ host.first_seen or 'Not reported' }}</td></tr>{% endfor %}
    </tbody></table>
    {% endif %}
  </div>
  {% endif %}

  {% if path_scan and path_scan.targets %}
  <h2>🧭 Common Web Paths</h2>
  {% for target in path_scan.targets %}
  <div class="auth-card">
    <div class="auth-card-title"><span class="pill {% if target.status == 'complete' %}pill-ok{% else %}pill-warn{% endif %}">{{ target.status }}</span>{{ target.target }}</div>
    {% if target.reason %}<p style="color:var(--text-muted);font-size:13px;margin-bottom:8px;">{{ target.reason }}</p>{% endif %}
    {% if target.paths %}
    <table><thead><tr><th>Path</th><th>Result</th><th>HTTP</th><th>Redirect / Details</th></tr></thead><tbody>
      {% for item in target.paths %}<tr><td>{{ item.path }}</td><td>{{ item.state }}</td><td>{{ item.status_code or '—' }}{% if item.redirect_status_code %} → {{ item.redirect_status_code }}{% endif %}</td><td>{{ item.location or item.error or '—' }}</td></tr>{% endfor %}
    </tbody></table>
    {% endif %}
    {% if target.advertised_paths %}<h3 style="font-size:13px;color:var(--text-primary);margin:16px 0 8px;">Paths advertised by robots.txt or sitemap</h3>
    <table><thead><tr><th>Path</th><th>Source</th><th>Review</th></tr></thead><tbody>{% for item in target.advertised_paths %}<tr><td>{{ item.path }}</td><td>{{ item.source }}</td><td>{% if item.review == 'review' %}Manual review suggested; path was not requested{% else %}No name-based flag{% endif %}</td></tr>{% endfor %}</tbody></table>{% endif %}
  </div>
  {% endfor %}
  {% endif %}

  {% if coverage %}
  <h2>✓ Scan Coverage</h2>
  <div class="auth-card"><table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>
    {% for check in coverage %}<tr><td>{{ check.name }}</td><td>{{ check.status }}</td><td>{{ check.detail }}</td></tr>{% endfor %}
  </tbody></table></div>
  {% endif %}

  {% if dns_posture %}
  <h2>🧭 Authoritative DNS Checks</h2>
  {% set axfr = dns_posture.axfr or {} %}
  <div class="auth-card">
    <div class="auth-card-title">AXFR Exposure · {{ axfr.status|default('unavailable') }}</div>
    <p style="color:var(--text-muted);font-size:13px;">Only server names and transfer record counts are retained; transferred record contents are not included.</p>
    {% for server in axfr.servers or [] %}<div class="auth-card-row"><span class="auth-card-key">{{ server.nameserver }}</span><span class="auth-card-val">{{ server.status }} · {{ server.records_exposed }} record(s)</span></div>{% endfor %}
    {% set consistency = dns_posture.nameserver_consistency or {} %}
    <div class="auth-card-row"><span class="auth-card-key">Nameserver consistency</span><span class="auth-card-val">SOA serials {{ 'match' if consistency.serials_match else 'differ' }} · NS sets {{ 'match' if consistency.ns_sets_match else 'differ' }}</span></div>
    {% for observation in consistency.observations or [] %}<div class="auth-card-row"><span class="auth-card-key">{{ observation.nameserver }} ({{ observation.address }})</span><span class="auth-card-val">SOA {{ observation.soa_serial or 'unavailable' }} · {{ (observation.ns_records or [])|join(', ') }}{% if observation.errors %} · {{ observation.errors }}{% endif %}</span></div>{% endfor %}
    {% set wildcard = dns_posture.wildcard or {} %}
    <div class="auth-card-row"><span class="auth-card-key">Wildcard DNS</span><span class="auth-card-val">{{ wildcard.status|default('unavailable') }}{% if wildcard.addresses %} · {{ wildcard.addresses|join(', ') }}{% endif %}</span></div>
  </div>
  {% endif %}

  <h2>Findings</h2>
  {% if findings %}
    {% for f in findings %}
    <div class="finding {{ f.severity }}">
      <div>
        <span class="severity-tag">{{ f.severity }}</span>
        <div class="finding-rtype">{{ f.record_type }}</div>
        <code class="finding-code">{{ f.code }}</code>
      </div>
      <div class="finding-msg">{{ f.message | format_msg }}
        {% if f.explanation %}<details class="finding-guidance"><summary>{{ f.explanation.title }}</summary><p>{{ f.explanation.why }}</p><p><strong>How it could be abused:</strong> {{ f.explanation.attacker }}</p><p><strong>Suggested fix:</strong> {{ f.explanation.fix }}</p><small>{{ f.explanation.technical }} · {{ f.explanation.reference }}</small></details>{% endif %}
      </div>
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
    {% elif rtype == 'CAA' %}
      <table><tr><th>Flags</th><th>Tag</th><th>Value</th></tr>
        {% for r in entry.records %}<tr><td>{{ r.flags }}</td><td>{{ r.tag }}</td><td>{{ r.value }}</td></tr>{% endfor %}
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

  <div class="footer">Generated by dns-analyzer 2.2.0 · InboxShield Edition · {{ domain }} · {{ scan_timestamp }}</div>
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
    tls: Any = None,
    subdomains: Any = None,
    path_scan: Any = None,
    coverage: Any = None,
    dns_posture: Any = None,
    domain_score: Any = None,
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
        tls=tls,
        subdomains=subdomains,
        path_scan=path_scan,
        coverage=coverage,
        dns_posture=dns_posture,
        domain_score=domain_score,
    )
