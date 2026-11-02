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
const badgeInfo    = document.getElementById("badge-info");
const findingsSearch = document.getElementById("findings-search");
let findingsSearchQuery = "";

// Accessibility & Help modal DOM refs
const shortcutsBtn     = document.getElementById("shortcuts-btn");
const shortcutsModal   = document.getElementById("shortcuts-modal");
const closeModalBtn    = document.getElementById("close-modal-btn");
const recentChipsContainer = document.getElementById("recent-chips-container");
const recentChipsList  = document.getElementById("recent-chips-list");
const clearRecentBtn   = document.getElementById("clear-recent-btn");
const loadingBar       = document.getElementById("loading-bar");
const loadingStatusText= document.getElementById("loading-status-text");

// Email auth DOM refs
const emailScoreSection = document.getElementById("email-score-section");
const scoreRingFg       = document.getElementById("score-ring-fg");
const scoreGrade        = document.getElementById("score-grade");
const scoreNum          = document.getElementById("score-num");
const scoreLabel        = document.getElementById("score-label");
const scoreDesc         = document.getElementById("score-desc");
const emailAuthSection  = document.getElementById("email-auth-section");
const emailAuthCards    = document.getElementById("email-auth-cards");

// Security & Remediation DOM refs
const securitySuiteSection = document.getElementById("security-suite-section");
const securityCards        = document.getElementById("security-cards");
const remediationSection   = document.getElementById("remediation-section");
const remediationList      = document.getElementById("remediation-list");
const downloadZoneBtn      = document.getElementById("download-zone-btn");

// ── State ─────────────────────────────────────────────────────
let currentDomain = "";
let currentFindings = [];
let currentFilter = "all";
let currentZoneSnippet = "";
let loadingInterval = null;

// ── Recent Searches (localStorage) ───────────────────────────
const STORAGE_KEY_RECENT = "dns_analyzer_recent";

function getRecentSearches() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY_RECENT) || "[]");
  } catch (_) {
    return [];
  }
}

function saveRecentSearch(domain) {
  if (!domain) return;
  domain = domain.toLowerCase();
  let list = getRecentSearches().filter((d) => d !== domain);
  list.unshift(domain);
  if (list.length > 5) list = list.slice(0, 5);
  try {
    localStorage.setItem(STORAGE_KEY_RECENT, JSON.stringify(list));
  } catch (_) {}
  renderRecentChips();
}

function clearRecentSearches() {
  try {
    localStorage.removeItem(STORAGE_KEY_RECENT);
  } catch (_) {}
  renderRecentChips();
  showToast("Recent search history cleared");
}

function renderRecentChips() {
  if (!recentChipsContainer || !recentChipsList) return;
  const list = getRecentSearches();
  if (list.length === 0) {
    recentChipsContainer.style.display = "none";
    recentChipsList.innerHTML = "";
    return;
  }
  recentChipsList.innerHTML = "";
  for (const d of list) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip-recent";
    chip.textContent = d;
    chip.setAttribute("aria-label", `Analyze recent domain ${d}`);
    chip.addEventListener("click", () => {
      domainInput.value = d;
      runAnalysis();
    });
    recentChipsList.appendChild(chip);
  }
  recentChipsContainer.style.display = "flex";
}

// ── Shortcuts Modal Helpers ───────────────────────────────────
function openShortcutsModal() {
  if (!shortcutsModal) return;
  if (typeof shortcutsModal.showModal === "function") {
    shortcutsModal.showModal();
  } else {
    shortcutsModal.setAttribute("open", "");
  }
}

function closeShortcutsModal() {
  if (!shortcutsModal) return;
  if (typeof shortcutsModal.close === "function") {
    shortcutsModal.close();
  } else {
    shortcutsModal.removeAttribute("open");
  }
}

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
  const onCopied = () => {
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
  };

  const fallbackCopy = () => {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      onCopied();
    } catch (err) {
      console.error("Clipboard copy error:", err);
      showToast("Failed to copy");
    }
  };

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(onCopied).catch(fallbackCopy);
  } else {
    fallbackCopy();
  }
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

// Shortcuts modal open/close
if (shortcutsBtn) {
  shortcutsBtn.addEventListener("click", openShortcutsModal);
}
if (closeModalBtn) {
  closeModalBtn.addEventListener("click", closeShortcutsModal);
}
if (shortcutsModal) {
  shortcutsModal.addEventListener("click", (e) => {
    if (e.target === shortcutsModal) closeShortcutsModal();
  });
}
if (clearRecentBtn) {
  clearRecentBtn.addEventListener("click", clearRecentSearches);
}

// Global keyboard accessibility shortcuts
window.addEventListener("keydown", (e) => {
  const isInputFocused = document.activeElement === domainInput;

  // Shortcuts modal toggle with ?
  if (e.key === "?" && !isInputFocused) {
    e.preventDefault();
    if (shortcutsModal && shortcutsModal.hasAttribute("open")) {
      closeShortcutsModal();
    } else {
      openShortcutsModal();
    }
    return;
  }

  // Escape closes modal or error banner, or clears findings search
  if (e.key === "Escape") {
    if (shortcutsModal && shortcutsModal.hasAttribute("open")) {
      closeShortcutsModal();
    } else if (findingsSearch && document.activeElement === findingsSearch && findingsSearchQuery) {
      findingsSearch.value = "";
      findingsSearchQuery = "";
      renderFindingsList();
    } else if (errorBanner && errorBanner.classList.contains("visible")) {
      hideError();
    }
    return;
  }

  // '/' to focus domain search
  if (e.key === "/" && !isInputFocused) {
    e.preventDefault();
    domainInput.focus();
    domainInput.select();
    return;
  }

  // Number keys 1-4 for quick-sample domains when not in search input
  if (!isInputFocused && ["1", "2", "3", "4"].includes(e.key)) {
    const sampleChips = document.querySelectorAll(".quick-chips .chip");
    const idx = parseInt(e.key, 10) - 1;
    if (sampleChips[idx]) {
      e.preventDefault();
      sampleChips[idx].click();
    }
    return;
  }

  // 'f' to cycle findings filters: all -> error -> warning -> info -> all
  if (!isInputFocused && (e.key === "f" || e.key === "F")) {
    e.preventDefault();
    const filters = ["all", "error", "warning", "info"];
    const nextIdx = (filters.indexOf(currentFilter) + 1) % filters.length;
    applyFindingsFilter(filters[nextIdx]);
    showToast(`Filter: ${filters[nextIdx].toUpperCase()}`);
    return;
  }

  // 'd' to download offline HTML report
  if (!isInputFocused && (e.key === "d" || e.key === "D") && currentDomain) {
    e.preventDefault();
    downloadBtn.click();
    return;
  }

  // 'z' to download BIND zone file
  if (!isInputFocused && (e.key === "z" || e.key === "Z") && currentZoneSnippet) {
    if (downloadZoneBtn) {
      e.preventDefault();
      downloadZoneBtn.click();
    }
    return;
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

if (findingsSearch) {
  findingsSearch.addEventListener("input", (e) => {
    findingsSearchQuery = e.target.value.toLowerCase().trim();
    renderFindingsList();
  });
}

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

if (downloadZoneBtn) {
  downloadZoneBtn.addEventListener("click", () => {
    if (!currentZoneSnippet || !currentDomain) {
      showToast("No zone snippet available for this domain.");
      return;
    }
    const blob = new Blob([currentZoneSnippet], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `dns-fixes-${currentDomain}.zone`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast("BIND zone file downloaded!");
  });
}

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

  let data;
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });

    data = await res.json();

    if (!res.ok) {
      // Backend validation error (400) or server error (500)
      const detail = data?.detail ?? "An unexpected error occurred.";
      showError(typeof detail === "string" ? detail : JSON.stringify(detail));
      return;
    }
  } catch (err) {
    showError("Network error — could not reach the server. Is the backend running?");
    console.error("Fetch error:", err);
    return;
  } finally {
    setLoading(false);
  }

  try {
    renderResults(data);
    saveRecentSearch(domain);
  } catch (renderErr) {
    showError(`Error displaying results: ${renderErr.message}`);
    console.error("Render error:", renderErr);
  }
}

// ── UI state helpers ──────────────────────────────────────────
function setLoading(on) {
  analyzeBtn.disabled = on;
  analyzeBtn.classList.toggle("loading", on);
  domainInput.classList.remove("input-error");

  if (!loadingBar || !loadingStatusText) return;

  if (on) {
    loadingBar.style.display = "flex";
    loadingStatusText.textContent = "Querying 7 DNS record types concurrently...";
    const messages = [
      "Auditing SPF syntax & recursion lookup limits...",
      "Evaluating DMARC enforcement & DKIM selectors...",
      "Inspecting DNSSEC cryptographic keys & takeover risks...",
      "Compiling diagnostic health score & remediation...",
    ];
    let step = 0;
    clearInterval(loadingInterval);
    loadingInterval = setInterval(() => {
      step = (step + 1) % messages.length;
      loadingStatusText.textContent = messages[step];
    }, 450);
  } else {
    clearInterval(loadingInterval);
    loadingBar.style.display = "none";
  }
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
  if (securitySuiteSection) securitySuiteSection.style.display = "none";
  if (remediationSection) remediationSection.style.display = "none";
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
  badgeInfo.classList.toggle("zero", data.summary.info === 0);

  // Executive Posture Matrix
  renderPostureMatrix(data);

  // Reset findings search on new scan
  if (findingsSearch) {
    findingsSearch.value = "";
    findingsSearchQuery = "";
  }

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

  // Security Suite (DNSSEC, Subdomain Takeover, BIMI)
  renderSecuritySuite(data.security);

  // 1-Click Remediation Fixes
  renderRemediation(data.remediation, data.bind_zone_snippet);

  results.classList.add("visible");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Executive Posture Matrix ──────────────────────────────────
function renderPostureMatrix(data) {
  const routingEl = document.getElementById("posture-routing");
  const redundancyEl = document.getElementById("posture-redundancy");
  const emailEl = document.getElementById("posture-email");
  const dnssecEl = document.getElementById("posture-dnssec");

  if (!routingEl || !redundancyEl || !emailEl || !dnssecEl) return;

  // 1. DNS Routing (A / AAAA)
  const aRecs = data.records?.A?.records || [];
  const aaaaRecs = data.records?.AAAA?.records || [];
  if (aRecs.length > 0 && aaaaRecs.length > 0) {
    routingEl.textContent = `Dual-Stack (${aRecs.length} IPv4, ${aaaaRecs.length} IPv6)`;
    routingEl.className = "posture-val ok";
  } else if (aRecs.length > 0) {
    routingEl.textContent = `IPv4 Reachable (${aRecs.length} host${aRecs.length === 1 ? "" : "s"})`;
    routingEl.className = "posture-val ok";
  } else if (aaaaRecs.length > 0) {
    routingEl.textContent = `IPv6 Only (${aaaaRecs.length} host${aaaaRecs.length === 1 ? "" : "s"})`;
    routingEl.className = "posture-val ok";
  } else {
    routingEl.textContent = "Unresolvable (No A/AAAA)";
    routingEl.className = "posture-val danger";
  }

  // 2. Nameserver Redundancy
  const nsRecs = data.records?.NS?.records || [];
  if (nsRecs.length >= 2) {
    redundancyEl.textContent = `Fault-Tolerant (${nsRecs.length} NS hosts)`;
    redundancyEl.className = "posture-val ok";
  } else if (nsRecs.length === 1) {
    redundancyEl.textContent = "Single NS (SPOF Risk)";
    redundancyEl.className = "posture-val warn";
  } else {
    redundancyEl.textContent = "Missing Authoritative NS";
    redundancyEl.className = "posture-val danger";
  }

  // 3. Email Authentication
  const dmarc = data.email_auth?.dmarc;
  const spf = data.email_auth?.spf;
  if (dmarc && (dmarc.policy === "reject" || dmarc.policy === "quarantine")) {
    emailEl.textContent = `Enforced (${dmarc.policy})`;
    emailEl.className = "posture-val ok";
  } else if (dmarc && dmarc.policy === "none") {
    emailEl.textContent = "Audit Mode (p=none)";
    emailEl.className = "posture-val warn";
  } else if (spf) {
    emailEl.textContent = "SPF Only (No DMARC)";
    emailEl.className = "posture-val warn";
  } else {
    emailEl.textContent = "Unprotected (Spoof Risk)";
    emailEl.className = "posture-val danger";
  }

  // 4. DNSSEC
  const dnssec = data.security?.dnssec;
  if (dnssec && dnssec.status === "secured") {
    dnssecEl.textContent = "Cryptographically Signed";
    dnssecEl.className = "posture-val ok";
  } else if (dnssec && dnssec.status === "incomplete_chain") {
    dnssecEl.textContent = "Incomplete DS Chain";
    dnssecEl.className = "posture-val warn";
  } else {
    dnssecEl.textContent = "Unsigned Zone";
    dnssecEl.className = "posture-val warn";
  }
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
  let filtered = currentFilter === "all"
    ? currentFindings
    : currentFindings.filter((f) => f.severity === currentFilter);

  if (findingsSearchQuery) {
    filtered = filtered.filter((f) =>
      (f.message && f.message.toLowerCase().includes(findingsSearchQuery)) ||
      (f.record_type && f.record_type.toLowerCase().includes(findingsSearchQuery)) ||
      (f.severity && f.severity.toLowerCase().includes(findingsSearchQuery))
    );
  }

  if (filtered.length === 0) {
    let emptyMsg = currentFilter === "all"
      ? "No issues found — DNS configuration looks healthy."
      : `No ${currentFilter} findings detected.`;
    if (findingsSearchQuery) {
      emptyMsg = `No findings match "${findingsSearchQuery}".`;
    }
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

// ── Smart Data Helpers ────────────────────────────────────────
function detectMxProvider(host) {
  if (!host) return null;
  const h = host.toLowerCase();
  if (h.includes("google") || h.includes("aspmx")) return "Google Workspace";
  if (h.includes("outlook") || h.includes("microsoft") || h.includes("office365")) return "Microsoft 365";
  if (h.includes("pphosted") || h.includes("proofpoint")) return "Proofpoint";
  if (h.includes("mimecast")) return "Mimecast";
  if (h.includes("zoho")) return "Zoho Mail";
  if (h.includes("cloudflare") || h.includes("cf-emailsecurity")) return "Cloudflare Mail";
  if (h.includes("mailgun")) return "Mailgun";
  if (h.includes("sendgrid")) return "SendGrid";
  if (h.includes("amazonses") || h.includes("aws")) return "Amazon SES";
  if (h.includes("secureserver") || h.includes("godaddy")) return "GoDaddy Mail";
  if (h.includes("protonmail") || h.includes("proton")) return "Proton Mail";
  if (h.includes("yahoodns") || h.includes("yahoo")) return "Yahoo Mail";
  if (h.includes("icloud.com") || h.includes("apple.com")) return "iCloud Mail";
  if (h.includes("fastmail")) return "Fastmail";
  if (h.includes("yandex")) return "Yandex Mail";
  return null;
}

function detectNsProvider(host) {
  if (!host) return null;
  const h = host.toLowerCase();
  if (h.includes("cloudflare")) return "Cloudflare DNS";
  if (h.includes("awsdns") || h.includes("route53")) return "AWS Route 53";
  if (h.includes("googledomains") || h.includes("google")) return "Google Cloud DNS";
  if (h.includes("azure-dns")) return "Azure DNS";
  if (h.includes("registrar-servers") || h.includes("namecheap")) return "Namecheap";
  if (h.includes("domaincontrol") || h.includes("godaddy")) return "GoDaddy DNS";
  if (h.includes("digitalocean")) return "DigitalOcean";
  if (h.includes("linode") || h.includes("akamai")) return "Akamai/Linode";
  if (h.includes("he.net") || h.includes("hurricane")) return "Hurricane Electric";
  return null;
}

function classifyTxt(val) {
  if (!val) return "TXT";
  const s = String(val).toLowerCase();
  if (s.startsWith("v=spf1")) return "SPF Policy";
  if (s.includes("google-site-verification")) return "Google Verify";
  if (s.includes("ms=ms") || s.includes("microsoft")) return "Microsoft Verify";
  if (s.includes("apple-domain-verification")) return "Apple Verify";
  if (s.includes("facebook-domain-verification")) return "Meta Verify";
  if (s.includes("stripe-verification")) return "Stripe";
  if (s.includes("github-verification")) return "GitHub";
  if (s.includes("docusign")) return "DocuSign";
  if (s.includes("atlassian")) return "Atlassian";
  if (s.includes("adobe")) return "Adobe";
  return "General TXT";
}

function formatSeconds(secs) {
  const n = parseInt(secs, 10);
  if (isNaN(n)) return `${secs}s`;
  if (n < 60) return `${n}s`;
  if (n < 3600) return `${n}s (${Math.round(n / 60)} mins)`;
  if (n < 86400) return `${n}s (${+(n / 3600).toFixed(1)} hrs)`;
  return `${n}s (${+(n / 86400).toFixed(1)} days)`;
}

function formatSoaEmail(rname) {
  if (!rname) return "";
  const parts = String(rname).split(".");
  if (parts.length > 1) {
    const user = parts[0].replace(/\\/g, "");
    const domain = parts.slice(1).join(".").replace(/\.$/, "");
    return `${user}@${domain}`;
  }
  return rname;
}

function makeInlineCopyBtn(text) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "record-copy-btn";
  btn.setAttribute("aria-label", "Copy value to clipboard");
  btn.setAttribute("title", "Copy value");
  btn.innerHTML = `
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <rect x="3.5" y="3.5" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.2"/>
      <path d="M2.5 8.5H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5a1 1 0 0 1 1 1v.5" stroke="currentColor" stroke-width="1.2"/>
    </svg>`;
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    copyToClipboard(text, btn);
  });
  return btn;
}

// ── Smart Record Card Rendering ───────────────────────────────
function renderRecordCard(rtype, entry) {
  const card = document.createElement("div");
  card.className = "record-card";

  const isOk = entry.status === "ok";
  const statusLabel = isOk ? "OK" : entry.status.replace("_", " ");
  const statusClass = isOk ? "status-ok" : "status-fail";
  const ttlStr = isOk && entry.ttl != null ? `TTL ${entry.ttl}s` : "";

  let countLabel = "";
  if (isOk && entry.records) {
    if (Array.isArray(entry.records)) {
      countLabel = `${entry.records.length} record${entry.records.length === 1 ? "" : "s"}`;
    }
  }

  card.innerHTML = `
    <div class="record-card-header">
      <div style="display:flex;align-items:center;gap:8px;">
        <span class="record-type-label">${escapeHtml(rtype)}</span>
        ${countLabel ? `<span class="records-meta-tag">${countLabel}</span>` : ""}
      </div>
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
      ["Admin Contact", formatSoaEmail(rec.rname)],
      ["Serial", rec.serial],
      ["Refresh Interval", formatSeconds(rec.refresh)],
      ["Retry Interval", formatSeconds(rec.retry)],
      ["Expire Limit", formatSeconds(rec.expire)],
      ["Minimum TTL", formatSeconds(rec.minimum)],
    ];
    for (const [label, val] of fields) {
      const row = document.createElement("div");
      row.className = "record-row";
      row.innerHTML = `<span class="record-label">${escapeHtml(label)}</span><span class="record-value">${escapeHtml(String(val))}</span>`;
      row.appendChild(makeInlineCopyBtn(String(val)));
      body.appendChild(row);
    }
  } else if (rtype === "MX") {
    for (const r of entry.records) {
      const row = document.createElement("div");
      row.className = "record-row";
      const resolvePill = `<span class="resolve-pill ${r.resolves ? "resolve-yes" : "resolve-no"}">${r.resolves ? "✓ resolves" : "✗ unresolvable"}</span>`;
      const provider = detectMxProvider(r.host);
      row.innerHTML = `
        <span class="record-label">Priority ${escapeHtml(String(r.priority))}</span>
        <span class="record-value">${escapeHtml(r.host)}</span>
        ${provider ? `<span class="record-provider-pill">${escapeHtml(provider)}</span>` : ""}
        ${resolvePill}
      `;
      row.appendChild(makeInlineCopyBtn(r.host));
      body.appendChild(row);
    }
  } else if (rtype === "NS") {
    for (const r of entry.records) {
      const row = document.createElement("div");
      row.className = "record-row";
      const resolvePill = `<span class="resolve-pill ${r.resolves ? "resolve-yes" : "resolve-no"}">${r.resolves ? "✓ resolves" : "✗ unresolvable"}</span>`;
      const provider = detectNsProvider(r.host);
      row.innerHTML = `
        <span class="record-value">${escapeHtml(r.host)}</span>
        ${provider ? `<span class="record-provider-pill">${escapeHtml(provider)}</span>` : ""}
        ${resolvePill}
      `;
      row.appendChild(makeInlineCopyBtn(r.host));
      body.appendChild(row);
    }
  } else if (rtype === "TXT") {
    const records = Array.isArray(entry.records) ? entry.records : [entry.records];
    if (records.length === 0) {
      body.innerHTML = `<div class="record-empty">No records returned.</div>`;
    } else {
      for (const r of records) {
        const row = document.createElement("div");
        row.className = "record-row";
        const category = classifyTxt(r);
        row.innerHTML = `
          <span class="record-category-pill">${escapeHtml(category)}</span>
          <span class="record-value">${escapeHtml(String(r))}</span>
        `;
        row.appendChild(makeInlineCopyBtn(String(r)));
        body.appendChild(row);
      }
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
        row.appendChild(makeInlineCopyBtn(String(r)));
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
    emailScoreSection.classList.remove("score-pass", "score-warn", "score-fail");
    if (sc.score >= 85) {
      ringColor = "var(--success)";
      emailScoreSection.classList.add("score-pass");
    } else if (sc.score >= 55) {
      ringColor = "var(--warning)";
      emailScoreSection.classList.add("score-warn");
    } else {
      emailScoreSection.classList.add("score-fail");
    }

    scoreRingFg.style.stroke = ringColor;
    scoreGrade.style.color = ringColor;
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

  card.innerHTML = `<div class="auth-card-title">${pill} SPF (Sender Policy Framework) <span class="info-badge" title="Specifies authorized mail servers allowed to send email for this domain.">?</span></div>`;

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

  card.innerHTML = `<div class="auth-card-title">${pill} DMARC (Message Authentication) <span class="info-badge" title="Enforces policies for email senders and provides abuse reports to prevent phishing.">?</span></div>`;

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
    <div class="auth-card-title">${pill} DKIM (DomainKeys Identified Mail) <span class="info-badge" title="Cryptographic digital signature verifying emails were not tampered with in transit.">?</span></div>
    ${body}`;
  return card;
}

// ── Security Suite Rendering ──────────────────────────────────
function renderSecuritySuite(security) {
  if (!securitySuiteSection || !securityCards) return;
  securitySuiteSection.style.display = "none";
  securityCards.innerHTML = "";

  if (!security) return;

  // 1. DNSSEC Card
  if (security.dnssec) {
    const sec = security.dnssec;
    const isOk = sec.status === "secured";
    const pill = isOk
      ? `<span class="pill pill-ok">Secured</span>`
      : (sec.status === "bogus" ? `<span class="pill pill-fail">Bogus</span>` : `<span class="pill pill-warn">Unsigned</span>`);

    let desc = "Protects against DNS cache poisoning (Kaminsky attacks) and spoofing.";
    if (isOk) {
      const algo = sec.keys && sec.keys[0] ? sec.keys[0].algorithm : "Standard";
      desc = `Cryptographically signed zone using ${algo}. DS record validated at parent registry.`;
    } else if (sec.status === "incomplete_chain") {
      desc = "DNSKEY exists in zone, but missing DS delegation in parent registrar.";
    }

    const card = document.createElement("div");
    card.className = "security-card";
    card.innerHTML = `
      <div>
        <div class="sec-card-header">
          <span class="sec-card-title">🔐 DNSSEC Validation <span class="info-badge" title="Cryptographically signs DNS records to prevent spoofing and cache poisoning.">?</span></span>
          ${pill}
        </div>
        <div class="sec-card-status">${isOk ? "Cryptographically Authenticated" : "Not Authenticated"}</div>
        <div class="sec-card-desc">${escapeHtml(desc)}</div>
      </div>
      <div style="margin-top:12px; font-size:11px; color:var(--text-muted); font-family:'Geist Mono', monospace;">
        Keys: ${sec.dnskey_count || 0} · DS: ${sec.ds_count || 0}
      </div>
    `;
    securityCards.appendChild(card);
  }

  // 2. Subdomain Takeover Card
  if (security.takeover) {
    const to = security.takeover;
    const isVuln = to.vulnerable;
    const pill = isVuln
      ? `<span class="pill pill-fail">Vulnerable</span>`
      : `<span class="pill pill-ok">Protected</span>`;

    const card = document.createElement("div");
    card.className = "security-card";
    card.innerHTML = `
      <div>
        <div class="sec-card-header">
          <span class="sec-card-title">🛡️ Subdomain Takeover <span class="info-badge" title="Detects dangling CNAME records pointing to abandoned cloud services before attackers hijack them.">?</span></span>
          ${pill}
        </div>
        <div class="sec-card-status">${isVuln ? "CRITICAL: Dangling CNAME" : "No Dangling Pointers"}</div>
        <div class="sec-card-desc">${escapeHtml(to.details || "Analyzed CNAME targets against cloud service fingerprints.")}</div>
      </div>
      <div style="margin-top:12px; font-size:11px; color:var(--text-muted); font-family:'Geist Mono', monospace;">
        Provider: ${escapeHtml(to.provider || "None")}
      </div>
    `;
    securityCards.appendChild(card);
  }

  // 3. BIMI Email Brand Card
  if (security.bimi) {
    const bi = security.bimi;
    const isBimi = bi.has_bimi && bi.status === "active";
    let pill = `<span class="pill pill-warn">Not Configured</span>`;
    let statusText = "No Brand Logo";
    let desc = "BIMI displays your official verified brand logo next to emails in Gmail, Apple Mail, and Yahoo Mail.";

    if (isBimi) {
      pill = `<span class="pill pill-ok">Active</span>`;
      statusText = "Verified Logo Published";
      desc = `Active logo URL: ${bi.logo_url}`;
    } else if (bi.dmarc_eligible) {
      pill = `<span class="pill pill-info">Eligible</span>`;
      statusText = "Ready for BIMI";
      desc = "Your domain's strong DMARC policy qualifies it to publish a BIMI logo!";
    }

    const card = document.createElement("div");
    card.className = "security-card";
    card.innerHTML = `
      <div>
        <div class="sec-card-header">
          <span class="sec-card-title">✨ BIMI Brand Inboxes <span class="info-badge" title="Displays your official brand logo in Gmail and Apple Mail recipient inboxes.">?</span></span>
          ${pill}
        </div>
        <div class="sec-card-status">${statusText}</div>
        <div class="sec-card-desc">${escapeHtml(desc)}</div>
      </div>
      <div style="margin-top:12px; font-size:11px; color:var(--text-muted); font-family:'Geist Mono', monospace;">
        DMARC Eligible: ${bi.dmarc_eligible ? "Yes" : "Requires p=quarantine/reject"}
      </div>
    `;
    securityCards.appendChild(card);
  }

  securitySuiteSection.style.display = "block";
}

// ── 1-Click Remediation Fix Generator ─────────────────────────
function renderRemediation(fixes, snippet) {
  if (!remediationSection || !remediationList) return;
  remediationSection.style.display = "none";
  remediationList.innerHTML = "";
  currentZoneSnippet = snippet || "";

  if (!fixes || fixes.length === 0) {
    remediationList.innerHTML = `
      <div class="no-issues" role="status">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="8" cy="8" r="7" stroke="#63B995" stroke-width="1.5"/>
          <path d="M5 8l2 2 4-4" stroke="#63B995" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Optimal posture! All DNS, SPF, DMARC, and security records are properly configured.
      </div>
    `;
    remediationSection.style.display = "block";
    return;
  }

  for (const fix of fixes) {
    const card = document.createElement("div");
    card.className = "fix-card";

    const header = document.createElement("div");
    header.className = "fix-card-header";
    header.innerHTML = `
      <span class="fix-card-title">
        <span class="pill pill-info">${escapeHtml(fix.record_type)}</span>
        ${escapeHtml(fix.title)}
      </span>
      <span style="font-family:'Geist Mono', monospace; font-size:11px; color:var(--text-muted);">TTL ${fix.ttl}s</span>
    `;
    card.appendChild(header);

    // Copy block with host and value
    const copyContent = `${fix.value}`;
    const copyBlock = makeCopyBlock(copyContent);
    card.appendChild(copyBlock);

    // Provider guides
    if (fix.provider_guides && Object.keys(fix.provider_guides).length > 0) {
      const guidesContainer = document.createElement("div");
      guidesContainer.className = "fix-provider-guides";
      guidesContainer.innerHTML = `<div class="fix-provider-title">Platform Quick Guide</div>`;
      for (const [provider, guide] of Object.entries(fix.provider_guides)) {
        const item = document.createElement("div");
        item.className = "fix-provider-item";
        item.innerHTML = `<strong style="color:var(--text-primary);">${escapeHtml(provider)}:</strong> ${escapeHtml(guide)}`;
        guidesContainer.appendChild(item);
      }
      card.appendChild(guidesContainer);
    }

    remediationList.appendChild(card);
  }

  remediationSection.style.display = "block";
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

// ── Jump Nav Scroll-Spy (IntersectionObserver) ────────────────
function initJumpNav() {
  const nav = document.getElementById("jump-nav");
  if (!nav) return;

  const pills = nav.querySelectorAll(".jump-pill");
  if (!pills.length) return;

  // Build a map from section id → pill element
  const pillMap = new Map();
  pills.forEach((pill) => {
    const href = pill.getAttribute("href");
    if (href && href.startsWith("#")) {
      pillMap.set(href.slice(1), pill);
    }
  });

  // Track which sections are currently intersecting
  const visibleSections = new Set();

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          visibleSections.add(entry.target.id);
        } else {
          visibleSections.delete(entry.target.id);
        }
      }

      // Activate the first visible section (in DOM order)
      for (const [id, pill] of pillMap) {
        if (visibleSections.has(id)) {
          pills.forEach((p) => p.classList.remove("active"));
          pill.classList.add("active");
          break;
        }
      }
    },
    {
      rootMargin: "-80px 0px -40% 0px",
      threshold: 0.1,
    }
  );

  // Observe each target section
  for (const id of pillMap.keys()) {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  }

  // Smooth scroll + active state on click
  pills.forEach((pill) => {
    pill.addEventListener("click", (e) => {
      e.preventDefault();
      const targetId = pill.getAttribute("href")?.slice(1);
      const target = targetId && document.getElementById(targetId);
      if (target) {
        pills.forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });
}

// ── Initialize ─────────────────────────────────────────────────
renderRecentChips();
initJumpNav();
