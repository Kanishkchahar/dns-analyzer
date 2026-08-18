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

// ── State ─────────────────────────────────────────────────────
let currentDomain = "";

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
}

// ── Render ────────────────────────────────────────────────────
function renderResults(data) {
  currentDomain = data.domain;
  resultDomain.textContent = data.domain;

  // Summary badges
  countErrors.textContent  = data.summary.errors;
  countWarnings.textContent= data.summary.warnings;
  countInfo.textContent    = data.summary.info;
  badgeErrors.classList.toggle("zero", data.summary.errors === 0);
  badgeWarnings.classList.toggle("zero", data.summary.warnings === 0);

  // Findings
  findingsList.innerHTML = "";
  if (data.findings.length === 0) {
    findingsList.innerHTML = `
      <div class="no-issues" role="status">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <circle cx="8" cy="8" r="7" stroke="#63B995" stroke-width="1.5"/>
          <path d="M5 8l2 2 4-4" stroke="#63B995" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        No issues found — DNS configuration looks healthy.
      </div>`;
  } else {
    for (const f of data.findings) {
      findingsList.appendChild(renderFinding(f));
    }
  }

  // Records
  recordsGrid.innerHTML = "";
  const ORDER = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
  for (const rtype of ORDER) {
    const entry = data.records[rtype];
    if (entry) recordsGrid.appendChild(renderRecordCard(rtype, entry));
  }

  results.classList.add("visible");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
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

// ── Utility ───────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
