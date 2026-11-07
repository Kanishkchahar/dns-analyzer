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
const recordsCount = document.getElementById("records-count");
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

// Multi-format & View Mode DOM refs
const clearInputBtn    = document.getElementById("clear-input-btn");
const inputKbdHint     = document.getElementById("input-kbd-hint");
const shareLinkBtn     = document.getElementById("share-link-btn");
const copyMdBtn        = document.getElementById("copy-md-btn");
const exportJsonBtn    = document.getElementById("export-json-btn");
const viewCardsBtn     = document.getElementById("view-cards-btn");
const viewDigBtn       = document.getElementById("view-dig-btn");
const recordsDigContainer = document.getElementById("records-dig-container");
const digDomainLabel   = document.getElementById("dig-domain-label");
const digTerminalBody  = document.getElementById("dig-terminal-body");
const copyDigBtn       = document.getElementById("copy-dig-btn");

// ── State ─────────────────────────────────────────────────────
let currentDomain = "";
let currentFindings = [];
let currentFilter = "all";
let currentZoneSnippet = "";
let currentScanData = null;
let currentViewMode = "cards"; // "cards" | "dig"
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
  const activeEl = document.activeElement;
  const activeTag = activeEl ? activeEl.tagName.toLowerCase() : "";
  const isInputFocused = activeTag === "input" || activeTag === "textarea" || activeTag === "select" || (activeEl && activeEl.isContentEditable);

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

  // 'c' to copy shareable scan URL
  if (!isInputFocused && (e.key === "c" || e.key === "C") && currentDomain && shareLinkBtn) {
    e.preventDefault();
    shareLinkBtn.click();
    return;
  }

  // 'm' to copy Markdown summary
  if (!isInputFocused && (e.key === "m" || e.key === "M") && currentScanData && copyMdBtn) {
    e.preventDefault();
    copyMdBtn.click();
    return;
  }

  // 'j' to export JSON
  if (!isInputFocused && (e.key === "j" || e.key === "J") && currentScanData && exportJsonBtn) {
    e.preventDefault();
    exportJsonBtn.click();
    return;
  }

  // 'v' to toggle DNS records view (cards vs dig)
  if (!isInputFocused && (e.key === "v" || e.key === "V") && currentDomain) {
    e.preventDefault();
    if (currentViewMode === "cards" && viewDigBtn) {
      viewDigBtn.click();
    } else if (viewCardsBtn) {
      viewCardsBtn.click();
    }
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

// Summary badges click switches to findings tab and applies filter
badgeErrors.addEventListener("click", () => {
  switchSegmentTab("tab-findings");
  applyFindingsFilter("error");
});
badgeWarnings.addEventListener("click", () => {
  switchSegmentTab("tab-findings");
  applyFindingsFilter("warning");
});
badgeInfo.addEventListener("click", () => {
  switchSegmentTab("tab-findings");
  applyFindingsFilter("info");
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
    const announcer = document.getElementById("scan-status-announcer");
    if (announcer) {
      announcer.textContent = `Analysis complete for ${domain}. Score: ${data.domain_score?.score || 0} out of 100, Grade: ${data.domain_score?.grade || "N/A"}.`;
    }
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
  const announcer = document.getElementById("scan-status-announcer");
  if (announcer) {
    announcer.textContent = `Error: ${msg}`;
  }
}

function hideError() {
  errorBanner.classList.remove("visible");
  errorMsg.textContent = "";
}

function hideResults() {
  results.classList.remove("visible");
  const panels = document.querySelectorAll(".results-tab-panel");
  panels.forEach((p) => {
    p.classList.remove("active");
    p.style.display = "none";
  });
}

// ── Render ────────────────────────────────────────────────────
function renderResults(data) {
  currentDomain = data.domain;
  currentScanData = data;
  resultDomain.textContent = data.domain;
  currentFindings = data.findings || [];

  // Update URL search param for shareability
  try {
    const url = new URL(window.location);
    url.searchParams.set("domain", data.domain);
    window.history.replaceState({ domain: data.domain }, "", url);
  } catch (_) {}

  // Update dig domain label
  if (digDomainLabel) {
    digDomainLabel.textContent = data.domain;
  }

  // Summary badges
  countErrors.textContent  = data.summary.errors;
  countWarnings.textContent= data.summary.warnings;
  countInfo.textContent    = data.summary.info;
  badgeErrors.classList.toggle("zero", data.summary.errors === 0);
  badgeWarnings.classList.toggle("zero", data.summary.warnings === 0);
  badgeInfo.classList.toggle("zero", data.summary.info === 0);

  // Bento Grid Security Posture Cockpit
  renderBentoCockpit(data);

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
  let renderedRecordTypes = 0;
  for (const rtype of ORDER) {
    const entry = data.records[rtype];
    if (entry) {
      recordsGrid.appendChild(renderRecordCard(rtype, entry));
      renderedRecordTypes++;
    }
  }
  if (recordsCount) {
    recordsCount.textContent = `${renderedRecordTypes} record type${renderedRecordTypes === 1 ? "" : "s"}`;
  }

  // Render dig view terminal simulation if active
  renderDigView();

  // Email Authentication
  renderEmailAuth(data.email_auth, data.domain);

  // Security Suite (DNSSEC, Subdomain Takeover, BIMI)
  renderSecuritySuite(data.security);

  // TLS & HTTPS Web Security
  renderTLS(data.tls);

  // Passive Subdomain Footprint
  renderSubdomains(data.subdomains);

  // Default network scope input
  const scopeInput = document.getElementById("list-scan-input");
  if (scopeInput && !scopeInput.value.trim()) {
    scopeInput.value = data.domain;
  }

  // 1-Click Remediation Fixes
  renderRemediation(data.remediation, data.bind_zone_snippet);

  // Update Segmented Tab Badges and Overview Snapshots
  updateTabBadges(data);

  // Activate default or chosen tab
  switchSegmentTab(activeSegmentTabId || "tab-overview");

  results.classList.add("visible");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Tab Badges & Overview Snapshots ───────────────────────────
function updateTabBadges(data) {
  // 1. Email badge & snapshot
  const emailBadge = document.getElementById("tab-badge-email");
  const emailPill = document.getElementById("overview-email-pill");
  const emailDesc = document.getElementById("overview-email-desc");
  const grade = data.email_auth?.score?.grade || "--";
  const score = data.email_auth?.score?.score ?? 0;

  if (emailBadge) {
    emailBadge.textContent = grade;
    emailBadge.className = "tab-badge";
    if (grade.startsWith("A")) emailBadge.classList.add("badge-green");
    else if (grade === "B" || grade === "C") emailBadge.classList.add("badge-amber");
    else emailBadge.classList.add("badge-red");
  }
  if (emailPill) {
    emailPill.textContent = `Grade ${grade} (${score}/100)`;
    emailPill.className = "snapshot-pill " + (grade.startsWith("A") ? "good" : grade === "B" ? "warn" : "danger");
  }
  if (emailDesc) {
    const dmarcPol = data.email_auth?.dmarc?.policy;
    emailDesc.textContent = `Email sender score is ${score}/100 (${grade}). ${dmarcPol ? "DMARC policy: " + dmarcPol : "DMARC policy missing"}.`;
  }

  // 2. Threats badge & snapshot
  const threatsBadge = document.getElementById("tab-badge-threats");
  const threatsPill = document.getElementById("overview-threats-pill");
  const threatsDesc = document.getElementById("overview-threats-desc");
  const isTakeoverVuln = Boolean(data.security?.takeover?.vulnerable);
  const isDnssecSecured = data.security?.dnssec?.status === "secured";

  if (threatsBadge) {
    threatsBadge.className = "tab-badge";
    if (isTakeoverVuln) {
      threatsBadge.textContent = "Alert";
      threatsBadge.classList.add("badge-red");
    } else if (isDnssecSecured) {
      threatsBadge.textContent = "Secured";
      threatsBadge.classList.add("badge-green");
    } else {
      threatsBadge.textContent = "Audit";
    }
  }
  if (threatsPill) {
    threatsPill.textContent = isTakeoverVuln ? "Critical Alert" : (isDnssecSecured ? "Cryptographically Secured" : "Unsigned");
    threatsPill.className = "snapshot-pill " + (isTakeoverVuln ? "danger" : isDnssecSecured ? "good" : "warn");
  }
  if (threatsDesc) {
    threatsDesc.textContent = isTakeoverVuln
      ? "CRITICAL: Dangling CNAME detected pointing to unclaimed cloud endpoint!"
      : (isDnssecSecured ? "DNSSEC validation active with parent DS delegation. Subdomain takeover safe." : "DNSSEC is not enabled for this zone. No dangling takeover vulnerabilities.");
  }

  // 3. Fixes badge & snapshot
  const fixesBadge = document.getElementById("tab-badge-fixes");
  const fixPill = document.getElementById("overview-fix-pill");
  const fixDesc = document.getElementById("overview-fix-desc");
  const fixCount = (data.remediation || []).length;

  if (fixesBadge) {
    fixesBadge.textContent = `${fixCount} Fix${fixCount === 1 ? "" : "es"}`;
  }
  if (fixPill) {
    fixPill.textContent = fixCount === 0 ? "Posture Optimal" : `${fixCount} Fix${fixCount === 1 ? "" : "es"} Ready`;
    fixPill.className = "snapshot-pill " + (fixCount === 0 ? "good" : "warn");
  }
  if (fixDesc) {
    fixDesc.textContent = fixCount === 0
      ? "Zero configuration changes needed. Your DNS zone is fully hardened!"
      : `${fixCount} actionable DNS change${fixCount === 1 ? "" : "s"} generated for Cloudflare, Route 53, and GoDaddy.`;
  }

  // 4. Findings badge
  const findingsBadge = document.getElementById("tab-badge-findings");
  const errCount = data.summary?.errors || 0;
  if (findingsBadge) {
    findingsBadge.textContent = String((data.findings || []).length);
    findingsBadge.className = "tab-badge " + (errCount > 0 ? "badge-red" : "badge-green");
  }
}

// ── Bento Grid Security Posture Cockpit ───────────────────────
function renderBentoCockpit(data) {
  const hero = document.getElementById("bento-hero");
  const bentoRingFg = document.getElementById("bento-ring-fg");
  const bentoGrade = document.getElementById("bento-grade");
  const bentoScoreNum = document.getElementById("bento-score-num");
  const heroSubtitle = document.getElementById("bento-hero-subtitle");

  if (!hero) return;

  // ── Score Ring in Hero ──
  const sc = data.domain_score || data.email_auth?.score;
  if (sc && bentoRingFg && bentoGrade && bentoScoreNum) {
    const circumference = 2 * Math.PI * 60; // r=60
    const offset = circumference - (circumference * sc.score / 100);

    let ringColor = "var(--danger)";
    hero.classList.remove("score-pass", "score-warn", "score-fail");
    if (sc.score >= 85) {
      ringColor = "var(--success)";
      hero.classList.add("score-pass");
    } else if (sc.score >= 55) {
      ringColor = "var(--warning)";
      hero.classList.add("score-warn");
    } else {
      hero.classList.add("score-fail");
    }

    bentoRingFg.style.stroke = ringColor;
    bentoGrade.style.color = ringColor;
    bentoRingFg.style.strokeDashoffset = circumference;
    bentoGrade.textContent = sc.grade;
    bentoScoreNum.textContent = `${sc.score}/100`;

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        bentoRingFg.style.strokeDashoffset = offset;
      });
    });
  } else {
    if (bentoGrade) bentoGrade.textContent = "--";
    if (bentoScoreNum) bentoScoreNum.textContent = "--/100";
  }

  // ── Hero Subtitle ──
  if (heroSubtitle) {
    const errs = data.summary?.errors || 0;
    const warns = data.summary?.warnings || 0;
    const inconcl = typeof data.domain_score?.inconclusive_count === "number"
      ? data.domain_score.inconclusive_count
      : (data.summary?.inconclusive || 0);
    const checkNames = (data.domain_score?.inconclusive_checks && data.domain_score.inconclusive_checks.length > 0)
      ? `: ${data.domain_score.inconclusive_checks.join(", ")}`
      : "";
    const labelPrefix = data.domain_score?.label ? `${data.domain_score.label} · ` : "";
    if (errs > 0) {
      heroSubtitle.textContent = `${labelPrefix}${errs} Critical Issue${errs === 1 ? "" : "s"} Detected`;
      heroSubtitle.style.color = "var(--danger)";
    } else if (warns > 0) {
      heroSubtitle.textContent = `${labelPrefix}${warns} Warning${warns === 1 ? "" : "s"} — Review Advised`;
      heroSubtitle.style.color = "var(--warning)";
    } else if (inconcl > 0) {
      heroSubtitle.textContent = `${labelPrefix}Base Checks Passed (${inconcl} Check${inconcl === 1 ? "" : "s"} Inconclusive${checkNames})`;
      heroSubtitle.style.color = "var(--accent)";
    } else {
      heroSubtitle.textContent = `${labelPrefix}All Audited Systems Authenticated & Safe`;
      heroSubtitle.style.color = "var(--success)";
    }
  }

  // ── DNS Infrastructure Card ──
  const dnsHeadline = document.getElementById("bento-dns-headline");
  const dnsBullets = document.getElementById("bento-dns-bullets");
  const dnsStatusEl = document.getElementById("bento-dns-status");
  const dnsCard = document.getElementById("bento-dns");

  if (dnsHeadline && dnsBullets) {
    const aRecs = data.records?.A?.records || [];
    const aaaaRecs = data.records?.AAAA?.records || [];
    const nsRecs = data.records?.NS?.records || [];
    const soaOk = data.records?.SOA?.status === "ok";

    let headline, statusClass = "ok", statusText = "Healthy";
    if (aRecs.length > 0 && aaaaRecs.length > 0) {
      headline = "Dual-Stack Reachable";
    } else if (aRecs.length > 0) {
      headline = "IPv4 Reachable";
    } else if (aaaaRecs.length > 0) {
      headline = "IPv6 Only";
    } else {
      headline = "Unresolvable";
      statusClass = "danger";
      statusText = "Critical";
    }
    if (nsRecs.length < 2 && nsRecs.length > 0 && statusClass !== "danger") {
      statusClass = "warn";
      statusText = "Warning";
    }

    dnsHeadline.textContent = headline;
    dnsBullets.innerHTML = `
      <li><span class="bullet-label">IPv4:</span> <span class="bullet-val ${aRecs.length > 0 ? 'ok' : 'warn'}">${aRecs.length} Address${aRecs.length === 1 ? "" : "es"} Resolved</span></li>
      <li><span class="bullet-label">IPv6:</span> <span class="bullet-val ${aaaaRecs.length > 0 ? 'ok' : 'warn'}">${aaaaRecs.length} Address${aaaaRecs.length === 1 ? "" : "es"} Resolved</span></li>
      <li><span class="bullet-label">NS:</span> <span class="bullet-val ${nsRecs.length >= 2 ? 'ok' : 'warn'}">${nsRecs.length} Redundant Server${nsRecs.length === 1 ? "" : "s"}</span></li>
      <li><span class="bullet-label">SOA:</span> <span class="bullet-val ${soaOk ? 'ok' : 'warn'}">${soaOk ? "Valid Zone Authority" : "Missing"}</span></li>
    `;
    if (dnsStatusEl) dnsStatusEl.textContent = `Status: ${statusText}`;
    const dnsDot = dnsCard?.querySelector(".bento-status-dot");
    if (dnsDot) dnsDot.className = `bento-status-dot ${statusClass}`;
  }

  // ── Email Authentication Card ──
  const emailHeadline = document.getElementById("bento-email-headline");
  const emailBullets = document.getElementById("bento-email-bullets");
  const emailStatusEl = document.getElementById("bento-email-status");
  const emailCard = document.getElementById("bento-email");

  if (emailHeadline && emailBullets) {
    const dmarc = data.email_auth?.dmarc;
    const spf = data.email_auth?.spf;
    const dkim = data.email_auth?.dkim;

    let spfText = "Missing", spfClass = "danger";
    if (spf) {
      if (spf.all_mechanism === "-all") { spfText = "Valid (-all policy)"; spfClass = "ok"; }
      else if (spf.all_mechanism === "~all") { spfText = "Soft Fail (~all)"; spfClass = "warn"; }
      else { spfText = `Found (${spf.all_mechanism || "no qualifier"})`; spfClass = "warn"; }
    }

    let dmarcText = "Missing", dmarcClass = "danger";
    if (dmarc) {
      if (dmarc.policy === "reject") { dmarcText = "Strict (p=reject)"; dmarcClass = "ok"; }
      else if (dmarc.policy === "quarantine") { dmarcText = "Moderate (p=quarantine)"; dmarcClass = "ok"; }
      else { dmarcText = "Audit Only (p=none)"; dmarcClass = "warn"; }
    }

    let dkimText = "Not Found", dkimClass = "warn";
    if (dkim?.has_dkim) {
      const selCount = dkim.selectors_found?.length || 0;
      dkimText = `${selCount} Verified Selector${selCount === 1 ? "" : "s"}`;
      dkimClass = "ok";
    }

    let headline, statusClass = "ok", statusText = "Enforced";
    if (dmarc && (dmarc.policy === "reject" || dmarc.policy === "quarantine") && spf) {
      headline = "Phishing Immune";
    } else if (dmarc?.policy === "none") {
      headline = "Audit Mode"; statusClass = "warn"; statusText = "Monitor Only";
    } else if (spf && !dmarc) {
      headline = "SPF Only — No DMARC"; statusClass = "warn"; statusText = "Partial";
    } else {
      headline = "Unprotected"; statusClass = "danger"; statusText = "Vulnerable";
    }

    emailHeadline.textContent = headline;
    emailBullets.innerHTML = `
      <li><span class="bullet-label">SPF:</span> <span class="bullet-val ${spfClass}">${escapeHtml(spfText)}</span></li>
      <li><span class="bullet-label">DMARC:</span> <span class="bullet-val ${dmarcClass}">${escapeHtml(dmarcText)}</span></li>
      <li><span class="bullet-label">DKIM:</span> <span class="bullet-val ${dkimClass}">${escapeHtml(dkimText)}</span></li>
    `;
    if (emailStatusEl) emailStatusEl.textContent = `Status: ${statusText}`;
    const emailDot = emailCard?.querySelector(".bento-status-dot");
    if (emailDot) emailDot.className = `bento-status-dot ${statusClass}`;
  }

  // ── Cryptography & Takeover Card ──
  const cryptoHeadline = document.getElementById("bento-crypto-headline");
  const cryptoBullets = document.getElementById("bento-crypto-bullets");
  const cryptoStatusEl = document.getElementById("bento-crypto-status");
  const cryptoCard = document.getElementById("bento-crypto");

  if (cryptoHeadline && cryptoBullets) {
    const dnssec = data.security?.dnssec;
    const takeover = data.security?.takeover;

    let dnssecText = "Unsigned Zone", dnssecClass = "warn";
    if (dnssec?.status === "secured") {
      const algo = dnssec.keys?.[0]?.algorithm || "Standard";
      dnssecText = `Signed (${algo})`; dnssecClass = "ok";
    } else if (dnssec?.status === "incomplete_chain") {
      dnssecText = "Incomplete DS Chain"; dnssecClass = "warn";
    } else if (dnssec?.status === "bogus") {
      dnssecText = "Bogus — Failed"; dnssecClass = "danger";
    }

    let dsText = "No DS Records", dsClass = "warn";
    if (dnssec?.ds_count > 0) {
      dsText = `Valid (${dnssec.ds_count} DS)`; dsClass = "ok";
    }

    let takeoverText = "Zero Dangling CNAMEs", takeoverClass = "ok";
    if (takeover?.vulnerable) {
      takeoverText = `CRITICAL: → ${takeover.provider || "Unknown"}`; takeoverClass = "danger";
    }

    let headline, statusClass = "ok", statusText = "Secured";
    if (takeover?.vulnerable) {
      headline = "Takeover Risk Detected"; statusClass = "danger"; statusText = "Vulnerable";
    } else if (dnssec?.status === "secured") {
      headline = "Hardened Against Hijacking";
    } else {
      headline = "Partially Protected"; statusClass = "warn"; statusText = "Unsigned";
    }

    cryptoHeadline.textContent = headline;
    cryptoBullets.innerHTML = `
      <li><span class="bullet-label">DNSSEC:</span> <span class="bullet-val ${dnssecClass}">${escapeHtml(dnssecText)}</span></li>
      <li><span class="bullet-label">DS Chain:</span> <span class="bullet-val ${dsClass}">${escapeHtml(dsText)}</span></li>
      <li><span class="bullet-label">Takeover:</span> <span class="bullet-val ${takeoverClass}">${escapeHtml(takeoverText)}</span></li>
    `;
    if (cryptoStatusEl) cryptoStatusEl.textContent = `Status: ${statusText}`;
    const cryptoDot = cryptoCard?.querySelector(".bento-status-dot");
    if (cryptoDot) cryptoDot.className = `bento-status-dot ${statusClass}`;
  }

  // ── Remediation Card ──
  const fixesHeadline = document.getElementById("bento-fixes-headline");
  const fixesBullets = document.getElementById("bento-fixes-bullets");
  const fixesStatusEl = document.getElementById("bento-fixes-status");
  const fixesDot = document.getElementById("bento-fixes-dot");

  if (fixesHeadline && fixesBullets) {
    const fixCount = (data.remediation || []).length;
    if (fixCount === 0) {
      fixesHeadline.textContent = "Fully Hardened";
      fixesBullets.innerHTML = `
        <li><span class="bullet-label">Critical Fixes:</span> <span class="bullet-val ok">0 Needed</span></li>
        <li><span class="bullet-label">Posture:</span> <span class="bullet-val ok">Optimal A+ Configuration</span></li>
      `;
      if (fixesStatusEl) fixesStatusEl.textContent = "Status: Optimal";
      if (fixesDot) fixesDot.className = "bento-status-dot ok";
    } else {
      fixesHeadline.textContent = "Actionable Fixes Available";
      fixesBullets.innerHTML = `
        <li><span class="bullet-label">Fixes Ready:</span> <span class="bullet-val warn">${fixCount} Copy-Paste Record${fixCount === 1 ? "" : "s"}</span></li>
        <li><span class="bullet-label">Posture:</span> <span class="bullet-val warn">Hardening Required</span></li>
      `;
      if (fixesStatusEl) fixesStatusEl.textContent = `Status: ${fixCount} Action${fixCount === 1 ? "" : "s"}`;
      if (fixesDot) fixesDot.className = "bento-status-dot warn";
    }
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
  card.className = `record-card record-card-${rtype.toLowerCase()}`;

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
    if (emailAuth.spf_flattened.can_flatten !== false && emailAuth.spf_flattened.flattened_record) {
      const flatHeading = document.createElement("h4");
      flatHeading.style.cssText = "font-size:13px; margin-top:16px; margin-bottom:6px; color: var(--text-primary);";
      flatHeading.textContent = "✅ Suggested Flattened SPF Record (0 Lookups)";
      card.appendChild(flatHeading);

      card.appendChild(makeCopyBlock(emailAuth.spf_flattened.flattened_record));

      const flatHint = document.createElement("p");
      flatHint.className = "flattened-hint";
      flatHint.textContent = "This flattened record resolves all includes directly to ip4/ip6 ranges, eliminating RFC 7208 lookup errors.";
      card.appendChild(flatHint);
    } else if (emailAuth.spf_flattened.can_flatten === false) {
      const notice = document.createElement("p");
      notice.className = "flattened-hint";
      notice.style.color = "var(--warning)";
      notice.textContent = `⚠️ SPF Flattening Notice: ${emailAuth.spf_flattened.reason || "Automated flattening is not safe for this record."}`;
      card.appendChild(notice);
    }
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

// ── TLS & HTTPS Diagnostics Rendering ─────────────────────────
function renderTLS(tls) {
  const tlsSec = document.getElementById("tls-section");
  const tlsCards = document.getElementById("tls-cards");
  const tlsBadge = document.getElementById("tab-badge-tls");
  if (!tlsSec || !tlsCards) return;

  tlsSec.style.display = "none";
  tlsCards.innerHTML = "";

  if (!tls || !tls.scanned) {
    if (tlsBadge) {
      tlsBadge.textContent = "N/A";
      tlsBadge.className = "tab-badge";
    }
    return;
  }

  const cert = tls.certificate;
  let statusClass = "badge-green";
  let statusText = tls.tls_version ? `${tls.tls_version} Active` : "Active";
  if (!cert || cert.is_expired) {
    statusClass = "badge-red";
    statusText = "Expired";
  } else if (cert.days_remaining <= 14) {
    statusClass = "badge-amber";
    statusText = "Expiring Soon";
  }

  if (tlsBadge) {
    tlsBadge.textContent = statusText;
    tlsBadge.className = "tab-badge " + statusClass;
  }

  // 1. Certificate Validity Card
  if (cert) {
    const cardCert = document.createElement("div");
    cardCert.className = "security-card";
    const pill = cert.is_expired
      ? `<span class="pill pill-fail">Expired</span>`
      : (cert.days_remaining <= 14 ? `<span class="pill pill-warn">${cert.days_remaining}d Left</span>` : `<span class="pill pill-ok">Valid (${cert.days_remaining}d)</span>`);

    cardCert.innerHTML = `
      <div>
        <div class="sec-card-header">
          <span class="sec-card-title">📜 X.509 Certificate</span>
          ${pill}
        </div>
        <div class="sec-card-status">${escapeHtml(cert.issuer || "Public CA")}</div>
        <div class="sec-card-desc">Valid until: <strong>${escapeHtml(cert.valid_until || "N/A")}</strong>. Covers domain: <strong>${cert.san_matched ? "Yes (SAN Aligned)" : "No (SAN Mismatch)"}</strong>.</div>
      </div>
      <div style="margin-top:12px; font-size:11px; color:var(--text-muted); font-family:'Geist Mono', monospace;">
        SANs: ${(cert.san || []).slice(0, 4).join(", ")}${(cert.san || []).length > 4 ? "..." : ""}
      </div>
    `;
    tlsCards.appendChild(cardCert);
  }

  // 2. Encryption Protocol & Cipher Card
  const cardProto = document.createElement("div");
  cardProto.className = "security-card";
  const protoPill = (tls.tls_version === "TLSv1.3" || tls.tls_version === "TLSv1.2")
    ? `<span class="pill pill-ok">${escapeHtml(tls.tls_version || "Active")}</span>`
    : `<span class="pill pill-warn">Legacy</span>`;

  cardProto.innerHTML = `
    <div>
      <div class="sec-card-header">
        <span class="sec-card-title">🔐 Negotiated Protocol</span>
        ${protoPill}
      </div>
      <div class="sec-card-status">${escapeHtml(tls.tls_version || "None")}</div>
      <div class="sec-card-desc">Cipher Suite: <code>${escapeHtml(tls.cipher || "Standard AES/GCM")}</code></div>
    </div>
  `;
  tlsCards.appendChild(cardProto);

  // 3. HTTPS Redirection & Security Headers Card
  const cardHdrs = document.createElement("div");
  cardHdrs.className = "security-card";
  const redir = tls.https_redirect?.enforced;
  const hsts = tls.security_headers?.hsts;
  const csp = tls.security_headers?.csp;

  cardHdrs.innerHTML = `
    <div>
      <div class="sec-card-header">
        <span class="sec-card-title">🛡️ Web Security Headers</span>
        <span class="pill ${hsts ? "pill-ok" : "pill-warn"}">${hsts ? "HSTS Enforced" : "HSTS Missing"}</span>
      </div>
      <div class="sec-card-status">${redir ? "HTTP → HTTPS 301 Enforced" : "No Automatic HTTPS Redirect"}</div>
      <div class="sec-card-desc">
        HSTS: <strong>${hsts ? "Active" : "None"}</strong> · CSP: <strong>${csp ? "Active" : "None"}</strong> · X-Frame-Options: <strong>${escapeHtml(tls.security_headers?.x_frame_options || "None")}</strong>
      </div>
    </div>
  `;
  tlsCards.appendChild(cardHdrs);

  tlsSec.style.display = "block";
}

// ── Passive Subdomain Footprint Rendering ─────────────────────
function renderSubdomains(subData) {
  const subSec = document.getElementById("subdomains-section");
  const subList = document.getElementById("subdomains-list");
  const subCountPill = document.getElementById("subdomain-count-pill");
  const subBadge = document.getElementById("tab-badge-subdomains");
  if (!subSec || !subList) return;

  subSec.style.display = "none";
  subList.innerHTML = "";

  const subs = subData?.subdomains || [];
  if (subBadge) {
    subBadge.textContent = String(subs.length);
    subBadge.className = "tab-badge " + (subs.length > 0 ? "badge-green" : "");
  }
  if (subCountPill) {
    subCountPill.textContent = `${subs.length} Discovered Host${subs.length === 1 ? "" : "s"}`;
  }

  if (subs.length === 0) {
    subList.innerHTML = `
      <div class="no-issues" role="status" style="margin-top:12px;">
        No publicly logged subdomains detected via Certificate Transparency for this domain apex.
      </div>
    `;
    subSec.style.display = "block";
    return;
  }

  let tableHtml = `
    <div class="records-table-container" style="margin-top:14px;">
      <table class="records-table">
        <thead>
          <tr>
            <th>Subdomain</th>
            <th>Resolved IPv4 / IPv6</th>
            <th>CNAME Pointer</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
  `;

  for (const s of subs) {
    const isDangling = s.status === "dangling";
    const statusPill = isDangling
      ? `<span class="pill pill-fail"><span class="status-indicator-dot dot-yellow"></span> Dangling CNAME</span>`
      : (s.status === "resolving"
          ? `<span class="pill pill-ok"><span class="status-indicator-dot dot-green"></span> Active</span>`
          : `<span class="pill pill-warn"><span class="status-indicator-dot dot-yellow"></span> Inactive</span>`);

    const escapedIps = (s.ips || []).map(ip => escapeHtml(ip)).join(", ");

    tableHtml += `
      <tr>
        <td style="font-family:'Geist Mono', monospace; font-weight:600; color:var(--text-primary);">${escapeHtml(s.subdomain)}</td>
        <td style="font-family:'Geist Mono', monospace; font-size:12px;">${escapedIps || '<span style="color:var(--text-muted)">None</span>'}</td>
        <td style="font-family:'Geist Mono', monospace; font-size:12px; color:var(--text-muted);">${escapeHtml(s.cname || "—")}</td>
        <td>${statusPill}</td>
        <td>
          <button class="btn btn-secondary btn-add-scope" data-host="${escapeHtml(s.subdomain)}" style="padding:4px 10px; font-size:11px;" type="button">
            + Add to Scope
          </button>
        </td>
      </tr>
    `;
  }

  tableHtml += `</tbody></table></div>`;
  subList.innerHTML = tableHtml;

  // Add click handlers for "+ Add to Scope"
  subList.querySelectorAll(".btn-add-scope").forEach(btn => {
    btn.addEventListener("click", () => {
      const host = btn.getAttribute("data-host");
      const scopeInput = document.getElementById("list-scan-input");
      if (scopeInput && host) {
        const cur = scopeInput.value.trim();
        scopeInput.value = cur ? `${cur}\n${host}` : host;
        switchSegmentTab("tab-network");
      }
    });
  });

  subSec.style.display = "block";
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
        ${fix.is_draft ? '<span class="pill pill-warning" style="font-size:10px; margin-left:6px; letter-spacing:0.04em;">DRAFT</span>' : ""}
      </span>
      <span style="font-family:'Geist Mono', monospace; font-size:11px; color:var(--text-muted);">TTL ${fix.ttl}s</span>
    `;
    card.appendChild(header);

    // Copy block with host and value
    const copyContent = `${fix.value}`;
    const copyBlock = makeCopyBlock(copyContent);
    card.appendChild(copyBlock);

    // Impact Notice Warning
    if (fix.impact_warning) {
      const impactEl = document.createElement("div");
      impactEl.className = "fix-impact-warning";
      impactEl.style.cssText = "margin-top:8px; padding:8px 12px; background:rgba(235,87,87,0.08); border-left:3px solid var(--danger); border-radius:4px; font-size:12px; color:var(--text-secondary);";
      impactEl.innerHTML = `<strong style="color:var(--danger); font-weight:600;">⚠️ Operational Notice:</strong> ${escapeHtml(fix.impact_warning)}`;
      card.appendChild(impactEl);
    }

    // Prerequisites Checklist
    if (fix.prerequisites && fix.prerequisites.length > 0) {
      const prereqEl = document.createElement("div");
      prereqEl.className = "fix-prerequisites";
      prereqEl.style.cssText = "margin-top:8px; font-size:12px; color:var(--text-muted);";
      prereqEl.innerHTML = `
        <div style="font-weight:600; color:var(--text-secondary); margin-bottom:4px;">Prerequisites & Verification:</div>
        <ul style="margin:0; padding-left:18px; line-height:1.45;">
          ${fix.prerequisites.map(p => `<li>${escapeHtml(p)}</li>`).join("")}
        </ul>
      `;
      card.appendChild(prereqEl);
    }

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

// ── Segmented Tab Controller ──────────────────────────────────
let activeSegmentTabId = "tab-overview";

function switchSegmentTab(targetTabId, shouldFocus = false) {
  const tabs = Array.from(document.querySelectorAll(".segment-tab"));
  const panels = document.querySelectorAll(".results-tab-panel");
  const resultsEl = document.getElementById("results");
  if (!tabs.length || !panels.length) return;

  const targetTab = document.getElementById(targetTabId);
  if (!targetTab) return;

  const targetPanelId = targetTab.getAttribute("data-target"); // e.g. "panel-overview" or "all"
  activeSegmentTabId = targetTabId;

  tabs.forEach((t) => {
    t.classList.remove("active");
    t.setAttribute("aria-selected", "false");
    t.setAttribute("tabindex", "-1");
  });
  targetTab.classList.add("active");
  targetTab.setAttribute("aria-selected", "true");
  targetTab.setAttribute("tabindex", "0");
  if (shouldFocus) {
    targetTab.focus();
  }

  if (targetPanelId === "all") {
    resultsEl?.classList.add("all-mode");
    panels.forEach((p) => {
      p.classList.add("active");
      p.style.display = "block";
      p.removeAttribute("hidden");
    });
  } else {
    resultsEl?.classList.remove("all-mode");
    panels.forEach((p) => {
      if (p.id === targetPanelId) {
        p.classList.add("active");
        p.style.display = "block";
        p.removeAttribute("hidden");
      } else {
        p.classList.remove("active");
        p.style.display = "none";
        p.setAttribute("hidden", "");
      }
    });
  }

  // Smoothly align with the segment nav if page has scrolled far below
  const nav = document.getElementById("segment-nav");
  if (nav) {
    const navRect = nav.getBoundingClientRect();
    if (navRect.top < 50) {
      nav.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }
}

function initSegmentedTabs() {
  const nav = document.getElementById("segment-nav");
  if (!nav) return;

  const tabs = Array.from(nav.querySelectorAll(".segment-tab"));
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      switchSegmentTab(tab.id);
    });
  });

  // WAI-ARIA tablist arrow-key navigation
  nav.addEventListener("keydown", (e) => {
    const currentTab = document.activeElement;
    if (!currentTab || !currentTab.classList.contains("segment-tab")) return;

    const currentIndex = tabs.indexOf(currentTab);
    if (currentIndex === -1) return;

    let targetIndex = -1;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") {
      e.preventDefault();
      targetIndex = (currentIndex + 1) % tabs.length;
    } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
      e.preventDefault();
      targetIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else if (e.key === "Home") {
      e.preventDefault();
      targetIndex = 0;
    } else if (e.key === "End") {
      e.preventDefault();
      targetIndex = tabs.length - 1;
    }

    if (targetIndex !== -1 && tabs[targetIndex]) {
      switchSegmentTab(tabs[targetIndex].id, true);
    }
  });

  // Snapshot card links (data-switch="tab-email", etc.)
  document.querySelectorAll("[data-switch]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTabId = btn.getAttribute("data-switch");
      if (targetTabId) {
        switchSegmentTab(targetTabId);
      }
    });
  });
}

// ── CLI / dig & Markdown Generation Helpers ───────────────────
function generateDigOutput(domain, records) {
  const ts = new Date().toUTCString();
  let lines = [
    `; <<>> DiG 9.18.28-1ubuntu0.24.04.1-Ubuntu <<>> ${domain} ANY`,
    `;; global options: +cmd +noall +answer`,
    `;; Got answer:`,
    `;; ->>HEADER<<- opcode: QUERY, status: NOERROR`,
    "",
  ];
  if (!records) return lines.join("\n");

  const rtypes = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"];
  let hasAny = false;
  for (const rtype of rtypes) {
    const entry = records[rtype];
    if (!entry || entry.status !== "ok" || !entry.records) continue;
    const ttl = entry.ttl || 3600;

    if (rtype === "A" || rtype === "AAAA") {
      entry.records.forEach((ip) => {
        hasAny = true;
        lines.push(`${domain}.\t\t${ttl}\tIN\t${rtype}\t${ip}`);
      });
    } else if (rtype === "MX") {
      entry.records.forEach((mx) => {
        hasAny = true;
        const host = typeof mx === "object" ? mx.host : mx;
        const prio = typeof mx === "object" ? mx.priority : 10;
        lines.push(`${domain}.\t\t${ttl}\tIN\tMX\t${prio} ${host}.`);
      });
    } else if (rtype === "NS") {
      entry.records.forEach((ns) => {
        hasAny = true;
        const host = typeof ns === "object" ? ns.host : ns;
        lines.push(`${domain}.\t\t${ttl}\tIN\tNS\t${host}.`);
      });
    } else if (rtype === "CNAME") {
      entry.records.forEach((c) => {
        hasAny = true;
        lines.push(`${domain}.\t\t${ttl}\tIN\tCNAME\t${c}.`);
      });
    } else if (rtype === "TXT") {
      entry.records.forEach((t) => {
        hasAny = true;
        lines.push(`${domain}.\t\t${ttl}\tIN\tTXT\t"${t}"`);
      });
    } else if (rtype === "SOA") {
      const s = entry.records;
      if (typeof s === "object") {
        hasAny = true;
        lines.push(`${domain}.\t\t${ttl}\tIN\tSOA\t${s.mname}. ${s.rname}. ${s.serial} ${s.refresh} ${s.retry} ${s.expire} ${s.minimum}`);
      }
    }
  }

  if (!hasAny) {
    lines.push(`;; No authoritative answer records found for ${domain}`);
  }

  lines.push("");
  lines.push(`;; Query time: ~120 msec`);
  lines.push(`;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)`);
  lines.push(`;; WHEN: ${ts}`);
  lines.push(`;; MSG SIZE rcvd: 480`);
  return lines.join("\n");
}

function renderDigView() {
  if (!digTerminalBody || !currentScanData) return;
  digTerminalBody.textContent = generateDigOutput(
    currentScanData.domain,
    currentScanData.records
  );
}

function generateMarkdownSummary(data) {
  const d = data.domain;
  const grade = data.email_auth?.score?.grade || "N/A";
  const score = data.email_auth?.score?.score ?? "N/A";
  const errs = data.summary?.errors ?? 0;
  const warns = data.summary?.warnings ?? 0;
  const info = data.summary?.info ?? 0;
  const dnssec = data.security?.dnssec?.status || "unknown";
  const takeover = data.security?.takeover?.status || "safe";

  let md = [
    `# 🛡️ DNS Security Audit: ${d}`,
    `**Scan Timestamp:** ${data.scan_timestamp || new Date().toISOString()}`,
    `**Email Health Grade:** ${grade} (${score}/100) | **DNSSEC:** ${dnssec} | **Takeover:** ${takeover}`,
    "",
    `### Diagnostic Summary`,
    `| Severity | Count |`,
    `|---|---|`,
    `| 🔴 Errors | ${errs} |`,
    `| 🟡 Warnings | ${warns} |`,
    `| 🔵 Info | ${info} |`,
    "",
    `### Key Findings`,
  ];

  if (data.findings && data.findings.length > 0) {
    data.findings.slice(0, 10).forEach((f) => {
      const emoji = f.severity === "error" ? "🔴" : f.severity === "warning" ? "🟡" : "ℹ️";
      md.push(`- ${emoji} **[${f.record_type}]** ${f.message}`);
    });
    if (data.findings.length > 10) {
      md.push(`- *...and ${data.findings.length - 10} additional findings.*`);
    }
  } else {
    md.push(`*No misconfigurations detected.*`);
  }

  md.push("");
  md.push(`*Analyzed by [DNS Analyzer](http://127.0.0.1:8000/?domain=${encodeURIComponent(d)})*`);
  return md.join("\n");
}

// ── Multi-Format Action Handlers ──────────────────────────────
if (shareLinkBtn) {
  shareLinkBtn.addEventListener("click", () => {
    if (!currentDomain) return;
    const url = new URL(window.location);
    url.searchParams.set("domain", currentDomain);
    copyToClipboard(url.toString(), "Shareable scan link copied to clipboard!");
  });
}

if (copyMdBtn) {
  copyMdBtn.addEventListener("click", () => {
    if (!currentScanData) return;
    const md = generateMarkdownSummary(currentScanData);
    copyToClipboard(md, "Markdown summary copied to clipboard!");
  });
}

if (exportJsonBtn) {
  exportJsonBtn.addEventListener("click", () => {
    if (!currentScanData) return;
    const blob = new Blob([JSON.stringify(currentScanData, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `dns-scan-${currentDomain}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast("Scan JSON exported successfully!");
  });
}

// View toggle handlers (Cards vs CLI dig)
if (viewCardsBtn && viewDigBtn && recordsGrid && recordsDigContainer) {
  viewCardsBtn.addEventListener("click", () => {
    currentViewMode = "cards";
    viewCardsBtn.classList.add("active");
    viewCardsBtn.setAttribute("aria-pressed", "true");
    viewDigBtn.classList.remove("active");
    viewDigBtn.setAttribute("aria-pressed", "false");
    recordsGrid.style.display = "grid";
    recordsDigContainer.style.display = "none";
  });

  viewDigBtn.addEventListener("click", () => {
    currentViewMode = "dig";
    viewDigBtn.classList.add("active");
    viewDigBtn.setAttribute("aria-pressed", "true");
    viewCardsBtn.classList.remove("active");
    viewCardsBtn.setAttribute("aria-pressed", "false");
    recordsGrid.style.display = "none";
    recordsDigContainer.style.display = "block";
    renderDigView();
  });
}

if (copyDigBtn && digTerminalBody) {
  copyDigBtn.addEventListener("click", () => {
    copyToClipboard(digTerminalBody.textContent, "CLI dig output copied to clipboard!");
  });
}

// Clear input button handler
if (domainInput) {
  domainInput.addEventListener("input", () => {
    const hasText = domainInput.value.trim().length > 0;
    if (clearInputBtn) clearInputBtn.style.display = hasText ? "flex" : "none";
    if (inputKbdHint) inputKbdHint.style.display = hasText ? "none" : "inline-block";
  });
}
if (clearInputBtn) {
  clearInputBtn.addEventListener("click", () => {
    domainInput.value = "";
    clearInputBtn.style.display = "none";
    if (inputKbdHint) inputKbdHint.style.display = "inline-block";
    domainInput.focus();
  });
}

// ── URL Search Param Auto-Scan ────────────────────────────────
function checkUrlParams() {
  try {
    const params = new URLSearchParams(window.location.search);
    const domain = params.get("domain");
    if (domain) {
      domainInput.value = domain;
      if (clearInputBtn) clearInputBtn.style.display = "flex";
      if (inputKbdHint) inputKbdHint.style.display = "none";
      runAnalysis();
    }
  } catch (_) {}
}

// ── Network Connectivity Listeners ────────────────────────────
window.addEventListener("offline", () => {
  showToast("Network disconnected — offline mode active.");
});
window.addEventListener("online", () => {
  showToast("Internet connection restored.");
});

// ── Network Scope & Port Scan Handlers ────────────────────────
const listScanInput = document.getElementById("list-scan-input");
const btnRunListScan = document.getElementById("btn-run-list-scan");
const portScanConfirm = document.getElementById("port-scan-confirm");
const btnRunPortScan = document.getElementById("btn-run-port-scan");
const networkResults = document.getElementById("network-results");

if (portScanConfirm && btnRunPortScan) {
  portScanConfirm.addEventListener("change", () => {
    btnRunPortScan.disabled = !portScanConfirm.checked;
  });
}

if (btnRunListScan && listScanInput && networkResults) {
  btnRunListScan.addEventListener("click", async () => {
    const raw = listScanInput.value.trim();
    if (!raw) {
      showToast("Please enter at least one target hostname or IP.");
      return;
    }
    const targets = raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    btnRunListScan.disabled = true;
    btnRunListScan.textContent = "Resolving Scope...";

    try {
      const resp = await fetch("/api/network/list-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "List scan failed.");

      networkResults.style.display = "block";
      networkResults.innerHTML = `
        <div class="audit-card">
          <div class="audit-card-header">
            <span class="audit-card-title">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                <circle cx="8" cy="8" r="6"/>
                <path d="M2 8h12M8 2a10 10 0 0 1 0 12M8 2a10 10 0 0 0 0 12"/>
              </svg>
              Scope Resolution &amp; SSRF Filter Inventory
            </span>
            <span class="pill ${data.in_scope_count === data.total_targets ? 'pill-ok' : (data.in_scope_count > 0 ? 'pill-warn' : 'pill-fail')}">
              ${data.in_scope_count} / ${data.total_targets} Safe In-Scope
            </span>
          </div>

          <div class="audit-stats-bar">
            <div class="audit-stat-chip">
              <span>Total Targets:</span>
              <strong>${data.total_targets}</strong>
            </div>
            <span class="audit-stat-sep">/</span>
            <div class="audit-stat-chip">
              <span>Public Scope:</span>
              <strong class="color-good">${data.in_scope_count} Safe</strong>
            </div>
            <span class="audit-stat-sep">/</span>
            <div class="audit-stat-chip">
              <span>Blocked:</span>
              <strong class="${(data.total_targets - data.in_scope_count) > 0 ? 'color-danger' : ''}">
                ${data.total_targets - data.in_scope_count} Filtered
              </strong>
            </div>
          </div>

          <div class="records-table-container">
            <table class="records-table">
              <thead>
                <tr>
                  <th>Target Scope</th>
                  <th>Resolved IP Address &amp; Routing</th>
                  <th>Classification</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                ${data.targets.map(t => `
                  <tr>
                    <td>
                      <span style="font-family:'Geist Mono', monospace; font-weight:600; color:var(--text-primary);">
                        ${escapeHtml(t.target)}
                      </span>
                    </td>
                    <td>
                      ${(t.resolved_ips && t.resolved_ips.length > 0)
                        ? t.resolved_ips.map(ip => `
                            <div style="font-family:'Geist Mono', monospace; font-size:12px; margin-bottom:2px;">
                              <span style="color:${ip.safe ? 'var(--text-primary)' : 'var(--danger)'}; font-weight:500;">
                                ${escapeHtml(ip.ip)}
                              </span>
                              <span style="font-size:11px; color:var(--text-muted); margin-left:6px;">(${escapeHtml(ip.reason)})</span>
                            </div>
                          `).join("")
                        : '<span style="color:var(--text-muted); font-size:12px;">Unresolvable</span>'
                      }
                    </td>
                    <td>
                      ${t.in_scope_safe
                        ? '<span class="pill pill-ok"><span class="status-indicator-dot dot-green"></span> Approved Public</span>'
                        : '<span class="pill pill-fail"><span class="status-indicator-dot dot-yellow"></span> Blocked RFC 1918 / Loopback</span>'}
                    </td>
                    <td>
                      ${t.in_scope_safe
                        ? `<button class="btn btn-secondary btn-quick-probe" data-target="${escapeHtml(t.target)}" style="padding:4px 10px; font-size:11px;" type="button">
                            Probe Ports
                           </button>`
                        : '<span style="font-size:11px; color:var(--text-muted);">Blocked</span>'}
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      `;

      // Wire up quick probe buttons
      networkResults.querySelectorAll(".btn-quick-probe").forEach(btn => {
        btn.addEventListener("click", () => {
          const tgt = btn.getAttribute("data-target");
          if (tgt) {
            listScanInput.value = tgt;
            if (portScanConfirm) portScanConfirm.checked = true;
            if (btnRunPortScan) {
              btnRunPortScan.disabled = false;
              btnRunPortScan.click();
            }
          }
        });
      });
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btnRunListScan.disabled = false;
      btnRunListScan.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
          <path d="M2 4h12M2 8h12M2 12h8" stroke-linecap="round"/>
        </svg>
        <span>Run List Scan (Resolve Scope Only)</span>
      `;
    }
  });
}

if (btnRunPortScan && listScanInput && networkResults) {
  btnRunPortScan.addEventListener("click", async () => {
    const raw = listScanInput.value.trim();
    const firstTarget = raw.split(/[\n,]+/)[0]?.trim();
    if (!firstTarget) {
      showToast("Please provide a target to verify standard ports.");
      return;
    }
    btnRunPortScan.disabled = true;
    btnRunPortScan.textContent = "Probing Standard Ports...";

    try {
      const resp = await fetch("/api/network/port-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: firstTarget, confirmed: true }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Port scan failed.");

      networkResults.style.display = "block";
      networkResults.innerHTML = `
        <div class="audit-card">
          <div class="audit-card-header">
            <span class="audit-card-title">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                <circle cx="7" cy="7" r="5"/>
                <path d="M11 11l3.5 3.5" stroke-linecap="round"/>
              </svg>
              Port &amp; Service Assessment: <span class="audit-card-target">${escapeHtml(data.target)}</span>
            </span>
            <span class="pill ${data.open_ports_count > 0 ? 'pill-ok' : 'pill-info'}">
              ${data.open_ports_count || 0} Open Services Detected
            </span>
          </div>

          <div class="audit-stats-bar">
            <div class="audit-stat-chip">
              <span>Target IP:</span>
              <strong>${escapeHtml(data.target_ip || "Resolved")}</strong>
            </div>
            <span class="audit-stat-sep">/</span>
            <div class="audit-stat-chip">
              <span>Ports Probed:</span>
              <strong>${(data.ports || []).length} Ports</strong>
            </div>
            <span class="audit-stat-sep">/</span>
            <div class="audit-stat-chip">
              <span>Open Services:</span>
              <strong class="${data.open_ports_count > 0 ? 'color-good' : ''}">${data.open_ports_count || 0} Active</strong>
            </div>
            <span class="audit-stat-sep">/</span>
            <div class="audit-stat-chip">
              <span>Safety Filter:</span>
              <strong class="color-good">SSRF Passed</strong>
            </div>
          </div>

          <div class="records-table-container">
            <table class="records-table">
              <thead>
                <tr>
                  <th>Port &amp; Protocol</th>
                  <th>Standard Service</th>
                  <th>Port State</th>
                  <th>Service Banner &amp; Evidence</th>
                </tr>
              </thead>
              <tbody>
                ${(data.ports || []).map(p => {
                  const isOpen = p.state === "open";
                  const isClosed = p.state === "closed";
                  const statePill = isOpen
                    ? '<span class="pill pill-ok"><span class="status-indicator-dot dot-green"></span> OPEN</span>'
                    : (isClosed
                        ? '<span class="pill pill-info"><span class="status-indicator-dot dot-muted"></span> CLOSED</span>'
                        : '<span class="pill pill-warn"><span class="status-indicator-dot dot-yellow"></span> FILTERED</span>');
                  return `
                    <tr>
                      <td>
                        <div class="port-badge">
                          <span>${p.port}</span>
                          <span class="port-proto">TCP</span>
                        </div>
                      </td>
                      <td>
                        <span style="font-weight:600; color:var(--text-primary);">${escapeHtml(p.service)}</span>
                      </td>
                      <td>${statePill}</td>
                      <td>
                        <div class="banner-evidence-cell" title="${escapeHtml(p.banner || (isOpen ? 'TCP SYN/ACK Handshake Confirmed' : 'Connection Refused / Filtered'))}">
                          ${escapeHtml(p.banner || (isOpen ? 'TCP SYN/ACK Handshake Confirmed' : 'Connection Refused / Filtered'))}
                        </div>
                      </td>
                    </tr>
                  `;
                }).join("")}
              </tbody>
            </table>
          </div>
        </div>
      `;
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btnRunPortScan.disabled = !portScanConfirm?.checked;
      btnRunPortScan.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
          <circle cx="7" cy="7" r="5"/>
          <path d="M11 11l3.5 3.5" stroke-linecap="round"/>
        </svg>
        <span>Verify Standard Ports</span>
      `;
    }
  });
}

// ── Initialize ─────────────────────────────────────────────────
renderRecentChips();
initSegmentedTabs();
checkUrlParams();
