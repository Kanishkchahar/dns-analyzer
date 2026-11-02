/* ============================================================
   DNS Analyzer — Frontend Logic
   ============================================================ */

"use strict";

// ── DOM refs ──────────────────────────────────────────────────
const domainInput  = document.getElementById("domain-input");
const analyzeBtn   = document.getElementById("analyze-btn");
const errorBanner  = document.getElementById("error-banner");
const errorMsg     = document.getElementById("error-msg");
const results      = document.getElementById("results");
const resultDomain = document.getElementById("result-domain");
const downloadBtn  = document.getElementById("download-btn");
const findingsList = document.getElementById("findings-list");
const recordsGrid  = document.getElementById("records-grid");
const countErrors  = document.getElementById("count-errors");
const countWarnings= document.getElementById("count-warnings");
const countInfo    = document.getElementById("count-info");
const badgeErrors  = document.getElementById("badge-errors");
const badgeWarnings= document.getElementById("badge-warnings");

// Email auth DOM refs
const emailScoreSection = document.getElementById("email-score-section");
const scoreRingFg       = document.getElementById("score-ring-fg");
const scoreGrade        = document.getElementById("score-grade");
const scoreNum          = document.getElementById("score-num");
const scoreLabel        = document.getElementById("score-label");
const scoreDesc         = document.getElementById("score-desc");
const emailAuthSection  = document.getElementById("email-auth-section");
const emailAuthCards    = document.getElementById("email-auth-cards");

// ── State ─────────────────────────────────────────────────────
let currentDomain = "";
let currentFindings = [];
let currentFilter = "all";

// ── Toast & Clipboard Helpers ─────────────────────────────────
function showToast(message) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="7" cy="7" r="6" stroke="#63B995" stroke-width="1.5"/>
      <path d="M4.5 7l2 2 3-3" stroke="#63B995" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span>${escapeHtml(message)}</span>
  `;
  toast.classList.add("visible");
  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => {
    toast.classList.remove("visible");
  }, 2200);
}

function copyToClipboard(text, btnElement) {
  navigator.clipboard.writeText(text).then(() => {
    if (btnElement) {
      const originalHtml = btnElement.innerHTML;
      btnElement.classList.add("copied");
      btnElement.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M2.5 6l2.5 2.5 4.5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg> Copied!`;
      setTimeout(() => {
        btnElement.classList.remove("copied");
        btnElement.innerHTML = originalHtml;
      }, 1800);
    }
    showToast("Copied to clipboard!");
  }).catch((err) => {
    console.error("Clipboard write error:", err);
    showToast("Failed to copy");
  });
}

function makeCopyBlock(text) {
  const wrapper = document.createElement("div");
  wrapper.className = "copy-block-wrapper";
  wrapper.innerHTML = `
    <div class="copy-block">${escapeHtml(text)}</div>
    <button class="copy-btn" type="button" aria-label="Copy to clipboard">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <rect x="3.5" y="3.5" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.2"/>
        <path d="M2.5 8.5H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5a1 1 0 0 1 1 1v.5" stroke="currentColor" stroke-width="1.2"/>
      </svg>
      <span>Copy</span>
    </button>
  `;
  const btn = wrapper.querySelector(".copy-btn");
  btn.addEventListener("click", () => copyToClipboard(text, btn));
  return wrapper;
}

// ── URL -> domain extraction ───────────────────────────────────
function extractDomain(raw) {
  raw = raw.trim();
  // If it looks like a URL (has ://) use URL parser
  if (/^https?:\/\//i.test(raw)) {
    try {
      return new URL(raw).hostname;
    } catch (_) { /* fall through */ }
  }
  // Strip everything after the first / or ?  (handles "boot.dev/path")
  return raw.split(/[/?#]/)[0].toLowerCase();
}

// ── Event listeners ───────────────────────────────────────────
analyzeBtn.addEventListener("click", runAnalysis);
domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") runAnalysis();
});

// Quick-pick sample chips
document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    domainInput.value = chip.dataset.domain;
    runAnalysis();
  });
});

// Keyboard shortcut '/' to focus domain search
window.addEventListener("keydown", (e) => {
  if (e.key === "/" && document.activeElement !== domainInput) {
    e.preventDefault();
    domainInput.focus();
    domainInput.select();
  }
});

// Findings filter tabs
document.querySelectorAll(".filter-chip").forEach((btn) => {
  btn.addEventListener("click", () => {
    applyFindingsFilter(btn.dataset.filter);
  });
});

// Summary badges click toggles severity filters
badgeErrors.addEventListener("click", () => {
  applyFindingsFilter(currentFilter === "error" ? "all" : "error");
});
badgeWarnings.addEventListener("click", () => {
  applyFindingsFilter(currentFilter === "warning" ? "all" : "warning");
});
badgeInfo.addEventListener("click", () => {
  applyFindingsFilter(currentFilter === "info" ? "all" : "info");
});

downloadBtn.addEventListener("click", () => {
  if (!currentDomain) return;
  const url = `/api/report/${encodeURIComponent(currentDomain)}`;
  const a = document.createElement("a");
  a.href = url;
  a.download = `dns-report-${currentDomain}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
});

// ── Core: run analysis ────────────────────────────────────────
async function runAnalysis() {
  const raw = domainInput.value.trim();
  if (!raw) {
    showError("Please enter a domain or URL.");
    domainInput.classList.add("input-error");
    domainInput.focus();
    return;
  }

  // Auto-extract the hostname from any URL
  const domain = extractDomain(raw);
  // Update the input so the user sees what was parsed
  domainInput.value = domain;

  setLoading(true);
  hideError();
  hideResults();

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });

    const data = await res.json();

    if (!res.ok) {
      // Backend validation error (400) or server error (500)
      const detail = data?.detail ?? "An unexpected error occurred.";
      showError(typeof detail === "string" ? detail : JSON.stringify(detail));
      return;
    }

    renderResults(data);
  } catch (err) {
    showError("Network error — could not reach the server. Is the backend running?");
    console.error(err);
  } finally {
    setLoading(false);
  }
}

// ── UI state helpers ──────────────────────────────────────────
function setLoading(on) {
  analyzeBtn.disabled = on;
  analyzeBtn.classList.toggle("loading", on);
  domainInput.classList.remove("input-error");
}

function showError(msg) {
  errorMsg.textContent = msg;
  errorBanner.classList.add("visible");
  errorBanner.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideError() {
  errorBanner.classList.remove("visible");
  errorMsg.textContent = "";
}

function hideResults() {
  results.classList.remove("visible");
  emailScoreSection.style.display = "none";
  emailAuthSection.style.display = "none";
}

// ── Render ────────────────────────────────────────────────────
function renderResults(data) {
  currentDomain = data.domain;
  resultDomain.textContent = data.domain;
  currentFindings = data.findings || [];

  // Summary badges
  countErrors.textContent  = data.summary.errors;
  countWarnings.textContent= data.summary.warnings;
  countInfo.textContent    = data.summary.info;
  badgeErrors.classList.toggle("zero", data.summary.errors === 0);
  badgeWarnings.classList.toggle("zero", data.summary.warnings === 0);

  // Render findings with default filter "all"
  applyFindingsFilter("all");

  // Records
  recordsGrid.innerHTML = "";
  const ORDER = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
  for (const rtype of ORDER) {
    const entry = data.records[rtype];
    if (entry) recordsGrid.appendChild(renderRecordCard(rtype, entry));
  }

  // Email Authentication
  renderEmailAuth(data.email_auth, data.domain);

  results.classList.add("visible");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Findings Filter & List ────────────────────────────────────
function applyFindingsFilter(filter) {
  currentFilter = filter;

  // Update filter buttons UI
  document.querySelectorAll(".filter-chip").forEach((btn) => {
    const isActive = btn.dataset.filter === filter;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", isActive);
  });

  // Highlight badge if filtered
  badgeErrors.classList.toggle("active-filter", filter === "error");
  badgeWarnings.classList.toggle("active-filter", filter === "warning");
  badgeInfo.classList.toggle("active-filter", filter === "info");

  renderFindingsList();
}

function renderFindingsList() {
  findingsList.innerHTML = "";
  const filtered = currentFilter === "all"
    ? currentFindings
    : currentFindings.filter((f) => f.severity === currentFilter);

  if (filtered.length === 0) {
    const emptyMsg = currentFilter === "all"
      ? "No issues found — DNS configuration looks healthy."
      : `No ${currentFilter} findings detected.`;
    findingsList.innerHTML = `
      <div class="no-issues" role="status">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <circle cx="8" cy="8" r="7" stroke="#63B995" stroke-width="1.5"/>
          <path d="M5 8l2 2 4-4" stroke="#63B995" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        ${escapeHtml(emptyMsg)}
      </div>`;
  } else {
    for (const f of filtered) {
      findingsList.appendChild(renderFinding(f));
    }
  }
}

// ── Finding card ──────────────────────────────────────────────
function renderFinding(f) {
  const div = document.createElement("div");
  div.className = `finding-item ${f.severity}`;
  div.setAttribute("role", "listitem");

  // Format backtick-wrapped text as <code>
  const msgHtml = escapeHtml(f.message).replace(/`([^`]+)`/g, "<code>$1</code>");

  div.innerHTML = `
    <div class="finding-meta">
      <span class="severity-tag">${escapeHtml(f.severity)}</span>
      <span class="finding-rtype">${escapeHtml(f.record_type)}</span>
    </div>
    <div class="finding-msg">${msgHtml}</div>
  `;
  return div;
}

// ── Record card ───────────────────────────────────────────────
function renderRecordCard(rtype, entry) {
  const card = document.createElement("div");
  card.className = "record-card";

  const isOk = entry.status === "ok";
  const statusLabel = isOk ? "OK" : entry.status.replace("_", " ");
  const statusClass = isOk ? "status-ok" : "status-fail";
  const ttlStr = isOk && entry.ttl != null ? `TTL ${entry.ttl}s` : "";

  card.innerHTML = `
    <div class="record-card-header">
      <span class="record-type-label">${escapeHtml(rtype)}</span>
      <div style="display:flex;align-items:center;gap:10px;">
        ${ttlStr ? `<span class="record-ttl">${escapeHtml(ttlStr)}</span>` : ""}
        <span class="record-status ${statusClass}">${escapeHtml(statusLabel)}</span>
      </div>
    </div>
    <div class="record-card-body" id="rcard-${rtype}"></div>
  `;

  const body = card.querySelector(`#rcard-${rtype}`);

  if (!isOk) {
    body.innerHTML = `<div class="record-empty">No data — ${escapeHtml(entry.status)}</div>`;
    return card;
  }

  if (rtype === "SOA") {
    const rec = entry.records;
    const fields = [
      ["Primary NS", rec.mname],
      ["Responsible", rec.rname],
      ["Serial", rec.serial],
      ["Refresh", `${rec.refresh}s`],
      ["Retry", `${rec.retry}s`],
      ["Expire", `${rec.expire}s`],
      ["Minimum TTL", `${rec.minimum}s`],
    ];
    for (const [label, val] of fields) {
      const row = document.createElement("div");
      row.className = "record-row";
      row.innerHTML = `<span class="record-label">${escapeHtml(label)}</span><span class="record-value">${escapeHtml(String(val))}</span>`;
      body.appendChild(row);
    }
  } else if (rtype === "MX") {
    for (const r of entry.records) {
      const row = document.createElement("div");
      row.className = "record-row";
      const resolvePill = `<span class="resolve-pill ${r.resolves ? "resolve-yes" : "resolve-no"}">${r.resolves ? "resolves" : "unresolved"}</span>`;
      row.innerHTML = `
        <span class="record-label">P${escapeHtml(String(r.priority))}</span>
        <span class="record-value">${escapeHtml(r.host)}</span>
        ${resolvePill}
      `;
      body.appendChild(row);
    }
  } else if (rtype === "NS") {
    for (const r of entry.records) {
      const row = document.createElement("div");
      row.className = "record-row";
      const resolvePill = `<span class="resolve-pill ${r.resolves ? "resolve-yes" : "resolve-no"}">${r.resolves ? "resolves" : "unresolved"}</span>`;
      row.innerHTML = `
        <span class="record-value">${escapeHtml(r.host)}</span>
        ${resolvePill}
      `;
      body.appendChild(row);
    }
  } else {
    const records = Array.isArray(entry.records) ? entry.records : [entry.records];
    if (records.length === 0) {
      body.innerHTML = `<div class="record-empty">No records returned.</div>`;
    } else {
      for (const r of records) {
        const row = document.createElement("div");
        row.className = "record-row";
        row.innerHTML = `<span class="record-value">${escapeHtml(String(r))}</span>`;
        body.appendChild(row);
      }
    }
  }

  return card;
}

// ── Email Auth Rendering ──────────────────────────────────────
function renderEmailAuth(emailAuth, domain) {
  // Hide sections by default
  emailScoreSection.style.display = "none";
  emailAuthSection.style.display = "none";
  emailAuthCards.innerHTML = "";

  if (!emailAuth) return;

  // ── Score ring ──
  if (emailAuth.score) {
    const sc = emailAuth.score;
    const circumference = 2 * Math.PI * 48; // r=48
    const offset = circumference - (circumference * sc.score / 100);

    let ringColor = "var(--danger)";
    if (sc.score >= 85) ringColor = "var(--success)";
    else if (sc.score >= 55) ringColor = "var(--warning)";

    scoreRingFg.style.stroke = ringColor;
    // Animate: start from full offset, then transition to target
    scoreRingFg.style.strokeDashoffset = circumference;
    scoreGrade.textContent = sc.grade;
    scoreNum.textContent = `${sc.score}/100`;
    scoreLabel.textContent = `Email Health: ${sc.label}`;
    scoreDesc.textContent = `Based on SPF, DMARC, and DKIM analysis for ${domain}`;

    emailScoreSection.style.display = "flex";

    // Trigger the animation after a frame
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        scoreRingFg.style.strokeDashoffset = offset;
      });
    });
  }

  // ── SPF Card ──
  emailAuthCards.appendChild(renderSpfCard(emailAuth));

  // ── DMARC Card ──
  emailAuthCards.appendChild(renderDmarcCard(emailAuth, domain));

  // ── DKIM Card ──
  emailAuthCards.appendChild(renderDkimCard(emailAuth));

  emailAuthSection.style.display = "block";
}

function renderSpfCard(emailAuth) {
  const card = document.createElement("div");
  card.className = "auth-card";

  const spf = emailAuth.spf;
  const hasSpf = !!spf;
  const pill = hasSpf
    ? `<span class="pill pill-ok">Found</span>`
    : `<span class="pill pill-fail">Missing</span>`;

  card.innerHTML = `<div class="auth-card-title">${pill} SPF (Sender Policy Framework)</div>`;

  if (!hasSpf) {
    card.innerHTML += `<p class="auth-empty">No SPF record found in TXT records.</p>`;
    return card;
  }

  // Raw SPF with 1-click copy button
  card.appendChild(makeCopyBlock(spf.raw));

  // SPF Lookup progress meter
  if (emailAuth.spf_lookups) {
    const lk = emailAuth.spf_lookups;
    const pct = Math.min(100, Math.round((lk.total_lookups / lk.limit) * 100));
    let meterClass = "meter-ok";
    let statusText = "OK";
    if (lk.over_limit) {
      meterClass = "meter-danger";
      statusText = "Over Limit";
    } else if (lk.total_lookups >= 8) {
      meterClass = "meter-warn";
      statusText = "Approaching Limit";
    }

    const meterContainer = document.createElement("div");
    meterContainer.className = "lookup-meter";
    meterContainer.innerHTML = `
      <div class="lookup-meter-labels">
        <span>DNS Lookups: <strong>${lk.total_lookups}</strong> / ${lk.limit} RFC 7208 limit (${statusText})</span>
        <span>${pct}%</span>
      </div>
      <div class="lookup-meter-track">
        <div class="lookup-meter-fill ${meterClass}" style="width: ${pct}%"></div>
      </div>
    `;
    card.appendChild(meterContainer);
  }

  // Policy
  if (spf.all_mechanism) {
    const row = document.createElement("div");
    row.className = "auth-card-row";
    row.innerHTML = `
      <span class="auth-card-key">Policy</span>
      <span class="auth-card-val">${escapeHtml(spf.all_mechanism)}</span>
    `;
    card.appendChild(row);
  }

  // Includes
  if (spf.includes && spf.includes.length > 0) {
    const row = document.createElement("div");
    row.className = "auth-card-row";
    row.innerHTML = `
      <span class="auth-card-key">Includes</span>
      <span class="auth-card-val">${spf.includes.map((i) => escapeHtml(i)).join(", ")}</span>
    `;
    card.appendChild(row);
  }

  // Flattened SPF suggestion
  if (emailAuth.spf_flattened && emailAuth.spf_lookups && emailAuth.spf_lookups.over_limit) {
    const flatHeading = document.createElement("h4");
    flatHeading.style.cssText = "font-size:13px; margin-top:16px; margin-bottom:6px; color: var(--text-primary);";
    flatHeading.textContent = "✅ Suggested Flattened SPF Record (0 Lookups)";
    card.appendChild(flatHeading);

    card.appendChild(makeCopyBlock(emailAuth.spf_flattened.flattened_record));

    const flatHint = document.createElement("p");
    flatHint.className = "flattened-hint";
    flatHint.textContent = "This flattened record resolves all includes directly to ip4/ip6 ranges, eliminating RFC 7208 lookup errors.";
    card.appendChild(flatHint);
  }

  return card;
}

function renderDmarcCard(emailAuth, domain) {
  const card = document.createElement("div");
  card.className = "auth-card";

  const dmarc = emailAuth.dmarc;
  const hasDmarc = !!dmarc;
  const pill = hasDmarc
    ? `<span class="pill pill-ok">Found</span>`
    : `<span class="pill pill-fail">Missing</span>`;

  card.innerHTML = `<div class="auth-card-title">${pill} DMARC (Domain-based Message Authentication)</div>`;

  if (!hasDmarc) {
    card.innerHTML += `<p class="auth-empty">No DMARC record found at _dmarc.${escapeHtml(domain)}</p>`;
    return card;
  }

  // Raw DMARC with 1-click copy button
  card.appendChild(makeCopyBlock(dmarc.raw));

  // Policy strength
  let policyPill = `<span class="pill pill-fail">Weak</span>`;
  if (dmarc.policy === "reject") policyPill = `<span class="pill pill-ok">Strong</span>`;
  else if (dmarc.policy === "quarantine") policyPill = `<span class="pill pill-warn">Moderate</span>`;

  const rows = [
    ["Policy", `${escapeHtml(dmarc.policy || "none")} ${policyPill}`],
    ["Enforcement", `${dmarc.pct}% of emails`],
    ...(dmarc.rua ? [["Reports To", escapeHtml(dmarc.rua)]] : []),
    ["DKIM Alignment", dmarc.adkim === "s" ? "strict" : "relaxed"],
    ["SPF Alignment", dmarc.aspf === "s" ? "strict" : "relaxed"],
  ];

  for (const [key, val] of rows) {
    const row = document.createElement("div");
    row.className = "auth-card-row";
    row.innerHTML = `
      <span class="auth-card-key">${key}</span>
      <span class="auth-card-val">${val}</span>
    `;
    card.appendChild(row);
  }

  return card;
}

function renderDkimCard(emailAuth) {
  const card = document.createElement("div");
  card.className = "auth-card";

  const dkim = emailAuth.dkim;
  const hasDkim = dkim && dkim.has_dkim;
  const pill = hasDkim
    ? `<span class="pill pill-ok">Found</span>`
    : `<span class="pill pill-warn">Not Found</span>`;

  let body = "";

  if (hasDkim) {
    for (const sel of dkim.selectors_found) {
      const keyPill = sel.has_key
        ? `<span class="pill pill-ok">Valid Key</span>`
        : `<span class="pill pill-fail">Empty Key</span>`;
      body += `
        <div class="auth-card-row">
          <span class="auth-card-key">${escapeHtml(sel.selector)}</span>
          <span class="auth-card-val">${keyPill} ${escapeHtml(sel.key_type)} · ${escapeHtml(sel.public_key)}</span>
        </div>`;
    }
  } else {
    body = `<p class="auth-empty">No DKIM records found for common selectors. Custom selectors may exist.</p>`;
  }

  card.innerHTML = `
    <div class="auth-card-title">${pill} DKIM (DomainKeys Identified Mail)</div>
    ${body}`;
  return card;
}

// ── Utility ───────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
