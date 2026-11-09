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
const multiDomainDashboard = document.getElementById("multi-domain-dashboard");
const multiDomainResults = document.getElementById("multi-domain-results");
const resultDomain = document.getElementById("result-domain");
const downloadBtn  = document.getElementById("download-btn");
const findingsList = document.getElementById("findings-list");
const recordsGrid  = document.getElementById("records-grid");
const recordsCount = document.getElementById("records-count");
const countErrors  = document.getElementById("count-errors");
const countWarnings= document.getElementById("count-warnings");
const countInfo    = document.getElementById("count-info");
const countInconclusive = document.getElementById("count-inconclusive");
const badgeErrors  = document.getElementById("badge-errors");
const badgeWarnings= document.getElementById("badge-warnings");
const badgeInfo    = document.getElementById("badge-info");
const badgeInconclusive = document.getElementById("badge-inconclusive");
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
const loadingElapsedText = document.getElementById("loading-elapsed");
const stopScanButton = document.getElementById("stop-scan-btn");

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
let loadingStartedAt = 0;
let analysisInFlight = false;
let activeAnalysisController = null;
const SCAN_HISTORY_KEY = "dns_analyzer_scan_history_v1";
const API_KEY_STORAGE_KEY = "dns_analyzer_api_key_session";
const THEME_STORAGE_KEY = "dns_analyzer_theme";
const themeToggle = document.getElementById("theme-toggle");

function setTheme(theme, persist = false) {
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
  if (persist) {
    try {
      if (theme === "system") localStorage.removeItem(THEME_STORAGE_KEY);
      else localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch (_) {}
  }
  if (themeToggle) {
    const next = theme === "system" ? "light" : theme === "light" ? "dark" : "system";
    themeToggle.title = `Theme: ${theme}. Click for ${next}.`;
    themeToggle.setAttribute("aria-label", `Switch to ${next} theme`);
    themeToggle.querySelector("span").textContent = theme === "system" ? "System" : theme[0].toUpperCase() + theme.slice(1);
  }
}

let selectedTheme = "system";
try {
  const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
  if (["light", "dark"].includes(storedTheme)) selectedTheme = storedTheme;
} catch (_) {}
setTheme(selectedTheme);
themeToggle?.addEventListener("click", () => {
  selectedTheme = selectedTheme === "system" ? "light" : selectedTheme === "light" ? "dark" : "system";
  setTheme(selectedTheme, true);
});

function getDashboardApiKey() {
  try { return sessionStorage.getItem(API_KEY_STORAGE_KEY) || ""; }
  catch (_) { return ""; }
}

function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  const apiKey = getDashboardApiKey();
  if (apiKey && !headers.has("Authorization")) headers.set("Authorization", `Bearer ${apiKey}`);
  return fetch(url, { ...options, headers });
}

function apiErrorMessage(response, payload, fallback) {
  if (response.status === 401) {
    return "This server requires a valid API key. Open “API access” above the domain field and enter the key.";
  }
  return payload?.detail || fallback;
}

const dashboardApiKeyInput = document.getElementById("dashboard-api-key");
const saveDashboardApiKeyButton = document.getElementById("save-dashboard-api-key");
const clearDashboardApiKeyButton = document.getElementById("clear-dashboard-api-key");
const dashboardApiKeyStatus = document.getElementById("dashboard-api-key-status");

if (dashboardApiKeyInput) dashboardApiKeyInput.value = getDashboardApiKey();
if (saveDashboardApiKeyButton && dashboardApiKeyInput) {
  saveDashboardApiKeyButton.addEventListener("click", () => {
    const value = dashboardApiKeyInput.value.trim();
    try {
      if (value) sessionStorage.setItem(API_KEY_STORAGE_KEY, value);
      else sessionStorage.removeItem(API_KEY_STORAGE_KEY);
      dashboardApiKeyStatus.textContent = value ? "Key saved for this tab." : "No key entered.";
    } catch (_) {
      dashboardApiKeyStatus.textContent = "This browser cannot store the key for this tab.";
    }
  });
}
if (clearDashboardApiKeyButton && dashboardApiKeyInput) {
  clearDashboardApiKeyButton.addEventListener("click", () => {
    try { sessionStorage.removeItem(API_KEY_STORAGE_KEY); } catch (_) {}
    dashboardApiKeyInput.value = "";
    if (dashboardApiKeyStatus) dashboardApiKeyStatus.textContent = "Key cleared.";
  });
}

// ── Recent Searches (localStorage) ───────────────────────────
const STORAGE_KEY_RECENT = "dns_analyzer_recent";

function getRecentSearches() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY_RECENT) || "[]");
    return Array.isArray(value)
      ? value.filter((domain) => typeof domain === "string" && domain.length > 0 && domain.length <= 253).slice(0, 5)
      : [];
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

  // 'f' cycles all findings filters, including checks that could not be verified.
  if (!isInputFocused && (e.key === "f" || e.key === "F")) {
    e.preventDefault();
    const filters = ["all", "error", "warning", "inconclusive", "info"];
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
badgeInconclusive.addEventListener("click", () => {
  switchSegmentTab("tab-findings");
  applyFindingsFilter("inconclusive");
});

if (findingsSearch) {
  findingsSearch.addEventListener("input", (e) => {
    findingsSearchQuery = e.target.value.toLowerCase().trim();
    renderFindingsList();
  });
}

downloadBtn.addEventListener("click", async () => {
  if (!currentDomain) return;
  const url = `/api/report/${encodeURIComponent(currentDomain)}`;
  downloadBtn.disabled = true;
  try {
    const response = await apiFetch(url);
    if (!response.ok) {
      let detail = "The report could not be downloaded.";
      try { detail = apiErrorMessage(response, await response.json(), detail); } catch (_) {}
      throw new Error(detail);
    }
    const blobUrl = URL.createObjectURL(await response.blob());
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = `dns-report-${currentDomain}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  } catch (err) {
    showToast(err.message || "The report could not be downloaded.", "danger");
  } finally {
    downloadBtn.disabled = false;
  }
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
  if (analysisInFlight) return;
  const raw = domainInput.value.trim();
  if (!raw) {
    showError("Please enter a domain or URL.");
    domainInput.classList.add("input-error");
    domainInput.focus();
    return;
  }

  const domains = raw.split(/[\n,;]+/).map(value => extractDomain(value)).filter(Boolean);
  if (domains.length > 8) {
    showError("Compare up to 8 domains at a time.");
    return;
  }
  if (!domains.length) {
    showError("Please enter one domain or a comma/newline separated list of domains.");
    return;
  }
  if (domains.length > 1) {
    domainInput.value = domains.join(", ");
    return runBatchAnalysis(domains);
  }

  // Auto-extract the hostname from any URL
  const domain = domains[0];
  // Update the input so the user sees what was parsed
  domainInput.value = domain;

  analysisInFlight = true;
  const scanController = new AbortController();
  activeAnalysisController = scanController;
  setLoading(true);
  hideError();
  hideResults();

  let data;
  try {
    const res = await apiFetch("/api/analyze", {
      method: "POST",
      signal: scanController.signal,
      headers: { "Content-Type": "application/json" },
      // Always bypass the short server cache so each user-triggered scan
      // re-runs DNS, TLS, and passive security checks against current data.
      body: JSON.stringify({ domain, force_refresh: true }),
    });

    const responseText = await res.text();
    try {
      data = JSON.parse(responseText);
    } catch (_) {
      throw new Error(`The server returned an unreadable response (HTTP ${res.status}). Please try again.`);
    }

    if (!res.ok) {
      // Backend validation error (400) or server error (500)
      const detail = apiErrorMessage(res, data, "An unexpected error occurred.");
      showError(typeof detail === "string" ? detail : JSON.stringify(detail));
      return;
    }
  } catch (err) {
    if (err.name === "AbortError") {
      showToast("Scan stopped. The server is cancelling the disconnected request.");
    } else showError(err instanceof TypeError
      ? "Network error — could not reach the server. Check your connection and try again."
      : (err.message || "The scan could not be completed. Please try again."));
    if (err.name !== "AbortError") console.error("Fetch error:", err);
    return;
  } finally {
    if (activeAnalysisController === scanController) activeAnalysisController = null;
    setLoading(false);
    analysisInFlight = false;
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

async function runBatchAnalysis(domains) {
  if (analysisInFlight) return;
  analysisInFlight = true;
  const scanController = new AbortController();
  activeAnalysisController = scanController;
  setLoading(true);
  hideError();
  hideResults();
  try {
    const response = await apiFetch("/api/analyze/batch", {
      method: "POST",
      signal: scanController.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains, force_refresh: true }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(apiErrorMessage(response, payload, "Multi-domain analysis failed."));
    const rows = payload.results || [];
    for (const row of rows) if (row.status === "complete") saveRecentSearch(row.domain);
    renderBatchDashboard(rows);
  } catch (err) {
    if (err.name === "AbortError") showToast("Comparison scan stopped.");
    else showError(err instanceof TypeError
      ? "Network error — could not reach the server. Check your connection and try again."
      : (err.message || "The comparison could not be completed."));
  } finally {
    if (activeAnalysisController === scanController) activeAnalysisController = null;
    setLoading(false);
    analysisInFlight = false;
  }
}

function renderBatchDashboard(rows) {
  if (!multiDomainDashboard || !multiDomainResults) return;
  multiDomainResults.replaceChildren();
  for (const row of rows) {
    const card = document.createElement("article");
    card.className = "multi-domain-card";
    const head = document.createElement("div");
    head.className = "multi-domain-card-head";
    const name = document.createElement("strong");
    name.className = "multi-domain-card-domain";
    name.textContent = row.domain;
    const grade = document.createElement("span");
    grade.className = "multi-domain-grade";
    const data = row.status === "complete" ? row.data : null;
    grade.textContent = data?.domain_score?.grade || (row.status === "complete" ? "—" : "!");
    head.append(name, grade);
    card.appendChild(head);

    const metrics = document.createElement("div");
    metrics.className = "multi-domain-metrics";
    if (data) {
      metrics.textContent = `Score ${data.domain_score?.score ?? "—"}/100 · ${data.summary?.errors || 0} errors · ${data.summary?.warnings || 0} warnings`;
    } else {
      metrics.textContent = row.error || "Scan did not complete.";
    }
    card.appendChild(metrics);

    const priority = document.createElement("p");
    priority.className = "multi-domain-priority";
    if (data) {
      const first = (data.findings || []).find(item => item.severity === "error")
        || (data.findings || []).find(item => item.severity === "warning");
      priority.textContent = first ? `Fix first: ${first.message}` : "No error or warning findings.";
    } else {
      priority.textContent = "Open this domain separately to retry the scan.";
    }
    card.appendChild(priority);

    const open = document.createElement("button");
    open.className = "btn btn-secondary";
    open.type = "button";
    open.textContent = data ? "Open report" : "Retry this domain";
    open.addEventListener("click", () => {
      if (data) {
        renderResults(data);
        results.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      else {
        domainInput.value = row.domain;
        runAnalysis();
      }
    });
    card.appendChild(open);
    multiDomainResults.appendChild(card);
  }
  multiDomainDashboard.classList.add("visible");
  document.body.classList.add("results-active");
  multiDomainDashboard.scrollIntoView({ behavior: "smooth", block: "start" });
}

document.getElementById("clear-multi-domain")?.addEventListener("click", () => {
  multiDomainDashboard?.classList.remove("visible");
  document.body.classList.remove("results-active");
  domainInput.value = "";
  domainInput.focus();
});

// ── UI state helpers ──────────────────────────────────────────
function setLoading(on) {
  analyzeBtn.disabled = on;
  analyzeBtn.classList.toggle("loading", on);
  domainInput.classList.remove("input-error");
  document.querySelector(".hero")?.setAttribute("aria-busy", String(on));
  document.body.classList.toggle("results-scanning", on);
  if (stopScanButton) {
    stopScanButton.hidden = !on;
    stopScanButton.disabled = false;
    stopScanButton.querySelector("span").textContent = "Stop scan";
  }

  if (!loadingBar || !loadingStatusText) return;

  if (on) {
    loadingBar.style.display = "flex";
    loadingStatusText.textContent = "Analyzing DNS records and security posture…";
    loadingStartedAt = performance.now();
    if (loadingElapsedText) loadingElapsedText.textContent = "0:00 elapsed";
    clearInterval(loadingInterval);
    loadingInterval = setInterval(() => {
      const elapsedSeconds = Math.floor((performance.now() - loadingStartedAt) / 1000);
      const minutes = Math.floor(elapsedSeconds / 60);
      const seconds = String(elapsedSeconds % 60).padStart(2, "0");
      if (loadingElapsedText) loadingElapsedText.textContent = `${minutes}:${seconds} elapsed`;
      if (elapsedSeconds >= 12) {
        loadingStatusText.textContent = "Still working — waiting for DNS and HTTPS responses…";
      }
    }, 1000);
  } else {
    clearInterval(loadingInterval);
    loadingInterval = null;
    loadingBar.style.display = "none";
  }
}

stopScanButton?.addEventListener("click", () => {
  if (!activeAnalysisController) return;
  stopScanButton.disabled = true;
  stopScanButton.querySelector("span").textContent = "Stopping…";
  activeAnalysisController.abort();
});

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
  multiDomainDashboard?.classList.remove("visible");
  results.classList.remove("visible");
  document.body.classList.remove("results-active");
  const panels = document.querySelectorAll(".results-tab-panel");
  panels.forEach((p) => {
    p.classList.remove("active");
    p.style.display = "none";
  });
}

// ── Render ────────────────────────────────────────────────────
function renderResults(data, recheckContext = null) {
  multiDomainDashboard?.classList.remove("visible");
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
  const inconclusiveCount = Number.isInteger(data.summary.inconclusive) ? data.summary.inconclusive : 0;
  countInconclusive.textContent = inconclusiveCount;
  badgeErrors.classList.toggle("zero", data.summary.errors === 0);
  badgeWarnings.classList.toggle("zero", data.summary.warnings === 0);
  badgeInfo.classList.toggle("zero", data.summary.info === 0);
  badgeInconclusive.classList.toggle("zero", inconclusiveCount === 0);

  // Bento Grid Security Posture Cockpit
  renderBentoCockpit(data, recheckContext?.previousScore ?? null);
  renderScanCoverage(data.coverage || []);
  renderScanHistory(data);

  // Reset findings search on new scan
  if (findingsSearch) {
    findingsSearch.value = "";
    findingsSearchQuery = "";
  }

  // Render findings with default filter "all"
  applyFindingsFilter("all");

  // Records
  recordsGrid.innerHTML = "";
  const ORDER = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"];
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
  renderDnsAuthorityAudit(data.dns_posture || {});

  // Render dig view terminal simulation if active
  renderDigView();

  // Email Authentication
  renderEmailAuth(data.email_auth, data.domain);

  // Security Suite (DNSSEC, Subdomain Takeover, BIMI)
  renderSecuritySuite(data.security);
  renderExtensionChecks(data.extensions || {});

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
  document.body.classList.add("results-active");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderDnsAuthorityAudit(posture) {
  const root = document.getElementById("dns-authority-audit");
  if (!root) return;
  const axfr = posture.axfr || {};
  const consistency = posture.nameserver_consistency || {};
  const asnDiversity = posture.nameserver_asn_diversity || {};
  const delegation = posture.parent_child_delegation || {};
  const wildcard = posture.wildcard || {};
  const servers = axfr.servers || [];
  const observations = consistency.observations || [];
  const asnNameservers = asnDiversity.nameservers || [];
  const tone = status => status === "detected" || status === "transfer_allowed" ? "pill-warn" : status === "inconclusive" || status === "partial" ? "pill-warn" : "pill-info";
  root.innerHTML = `
    <h3>Authoritative DNS Checks</h3>
    <div class="dns-authority-grid">
      <article class="auth-card"><div class="auth-card-title"><span class="pill ${servers.some(item => item.records_exposed > 0) ? "pill-fail" : tone(axfr.status)}">${escapeHtml(axfr.status || "unavailable")}</span>Zone transfer (AXFR)</div>
        <p class="auth-helper-copy">Only nameserver names and record counts are retained. Zone contents are never displayed.</p>
        ${servers.map(item => `<div class="auth-card-row"><span class="auth-card-key">${escapeHtml(item.nameserver)}</span><span class="auth-card-val">${escapeHtml(item.status)} · ${Number(item.records_exposed || 0)} record(s)</span></div>`).join("") || `<p class="auth-empty">No authoritative nameservers were available to check.</p>`}
      </article>
      <article class="auth-card"><div class="auth-card-title"><span class="pill ${consistency.status === "complete" ? "pill-ok" : "pill-warn"}">${escapeHtml(consistency.status || "unavailable")}</span>Nameserver consistency</div>
        <div class="auth-card-row"><span class="auth-card-key">SOA serials</span><span class="auth-card-val">${consistency.serials_match === true ? "Match" : consistency.serials_match === false ? "Differ" : "Not compared"}</span></div>
        <div class="auth-card-row"><span class="auth-card-key">NS sets</span><span class="auth-card-val">${consistency.ns_sets_match === true ? "Match" : consistency.ns_sets_match === false ? "Differ" : "Not compared"}</span></div>
        ${observations.map(item => `<div class="auth-card-row"><span class="auth-card-key">${escapeHtml(item.nameserver)} · ${escapeHtml(item.address || "")}</span><span class="auth-card-val">SOA ${escapeHtml(String(item.soa_serial ?? "unavailable"))}${item.errors ? ` · ${escapeHtml(JSON.stringify(item.errors))}` : ""}</span></div>`).join("")}
      </article>
      <article class="auth-card"><div class="auth-card-title"><span class="pill ${asnDiversity.status === "complete" ? (asnDiversity.single_asn ? "pill-warn" : "pill-ok") : "pill-warn"}">${escapeHtml(asnDiversity.status || "unavailable")}</span>Nameserver network diversity</div>
        <p class="auth-helper-copy">${asnDiversity.single_asn === true ? `All checked addresses map to origin AS${escapeHtml(asnDiversity.asns?.[0] || "")}.` : asnDiversity.single_asn === false ? "Multiple origin ASNs were observed." : "Network origin could not be determined for every nameserver address."} One ASN does not establish a shared physical site.</p>
        ${asnNameservers.flatMap(server => (server.addresses || []).map(address => `<div class="auth-card-row"><span class="auth-card-key">${escapeHtml(server.nameserver)} · ${escapeHtml(address.ip)}</span><span class="auth-card-val">${address.asns?.length ? `${address.asns.map(asn => `AS${escapeHtml(asn)}`).join(", ")} · ${escapeHtml((address.prefixes || []).join(", "))}` : escapeHtml(address.status || "unavailable")}</span></div>`)).join("") || `<p class="auth-empty">No complete ASN observations are available.</p>`}
        <p class="auth-helper-copy">Source: Team Cymru BGP origin mapping. This check is informational and does not affect the grade.</p>
      </article>
      <article class="auth-card"><div class="auth-card-title"><span class="pill ${delegation.status === "complete" ? (delegation.delegation_matches === false || (delegation.glue || []).some(item => ["missing", "inconsistent"].includes(item.status)) || (delegation.lame_nameservers || []).length ? "pill-warn" : "pill-ok") : "pill-warn"}">${escapeHtml(delegation.status || "unavailable")}</span>Parent-child delegation &amp; glue</div>
        <div class="auth-card-row"><span class="auth-card-key">Parent zone</span><span class="auth-card-val">${escapeHtml(delegation.parent_zone || "Not determined")}</span></div>
        <div class="auth-card-row"><span class="auth-card-key">Delegation comparison</span><span class="auth-card-val">${delegation.delegation_matches === true ? "Parent and child NS sets match" : delegation.delegation_matches === false ? "Parent and child NS sets differ" : "Not compared"}</span></div>
        ${(delegation.lame_nameservers || []).map(host => `<div class="auth-card-row"><span class="auth-card-key">Lame authority</span><span class="auth-card-val">${escapeHtml(host)}</span></div>`).join("")}
        ${(delegation.glue || []).map(item => `<div class="auth-card-row"><span class="auth-card-key">${escapeHtml(item.nameserver)} glue</span><span class="auth-card-val">${escapeHtml(item.status)}${item.addresses?.length ? ` · ${escapeHtml(item.addresses.join(", "))}` : ""}</span></div>`).join("") || `<p class="auth-empty">Parent referral data is incomplete.</p>`}
        <p class="auth-helper-copy">Glue is required only for in-bailiwick nameservers. Parent lookups that disagree or fail are inconclusive.</p>
      </article>
      <article class="auth-card"><div class="auth-card-title"><span class="pill ${tone(wildcard.status)}">${escapeHtml(wildcard.status || "unavailable")}</span>Wildcard DNS</div>
        <p class="auth-card-val">${escapeHtml((wildcard.addresses || []).join(", ") || wildcard.reason || "No wildcard address detected.")}</p>
        <p class="auth-helper-copy">CT hostnames marked wildcard only resolve to these probe addresses and have no explicit CNAME.</p>
      </article>
    </div>`;
}

function renderScanCoverage(coverage) {
  const list = document.getElementById("scan-coverage-list");
  const count = document.getElementById("coverage-count");
  if (!list || !count) return;
  const entries = Array.isArray(coverage) ? coverage : [];
  const complete = entries.filter(item => item.status === "complete").length;
  count.textContent = `${complete}/${entries.length} complete`;
  list.innerHTML = entries.map(item => {
    const label = item.status === "not_run" ? "Optional" : item.status === "partial" ? "Partial" : item.status === "blocked" ? "Blocked" : "Complete";
    const tone = item.status === "complete" ? "coverage-complete" : item.status === "blocked" ? "coverage-blocked" : item.status === "not_run" ? "coverage-optional" : "coverage-partial";
    return `<div class="scan-coverage-item ${tone}">
      <span class="coverage-indicator" aria-hidden="true"></span>
      <div><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.detail || "")}</small></div>
      <span class="coverage-status">${label}</span>
    </div>`;
  }).join("") || `<p class="auth-empty">Coverage details are unavailable for this scan.</p>`;
}

function readScanHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(SCAN_HISTORY_KEY) || "[]");
    if (!Array.isArray(value)) return [];
    return value.filter((item) => item && typeof item === "object"
      && typeof item.domain === "string" && item.domain.length <= 253
      && typeof item.timestamp === "string"
      && item.records && typeof item.records === "object" && !Array.isArray(item.records)).slice(0, 60);
  } catch (_) { return []; }
}

function renderScanHistory(data) {
  const output = document.getElementById("scan-history-content");
  if (!output || !data?.domain) return;
  const previousHistory = readScanHistory();
  const timestamp = data.scan_timestamp || new Date().toISOString();
  const previous = previousHistory.find(item => item.domain === data.domain && item.timestamp !== timestamp) || null;
  const records = Object.fromEntries(Object.entries(data.records || {}).map(([type, record]) => [type, JSON.stringify(record?.records ?? null)]));
  const ctStatus = data.subdomains?.status || "unavailable";
  const snapshot = {
    domain: data.domain,
    timestamp,
    records,
    ctStatus,
    ctHosts: (data.subdomains?.subdomains || []).map(item => item.subdomain).sort(),
    certificate: data.tls?.certificate ? {
      issuer: data.tls.certificate.issuer,
      valid_until: data.tls.certificate.valid_until,
      san: [...(data.tls.certificate.san || [])].sort(),
      tls_version: data.tls.tls_version,
    } : null,
    pathScan: (data.path_scan?.targets || []).filter(target => target.target?.toLowerCase().replace(/\.$/, "") === data.domain.toLowerCase()).map(target => ({
      paths: (target.paths || []).map(item => [item.path, item.status_code, item.state, item.location, item.redirect_status_code]),
      advertised: (target.advertised_paths || []).map(item => [item.path, item.source, item.review]).sort((a, b) => a[0].localeCompare(b[0])),
    })),
  };
  const changed = [];
  if (previous) {
    const recordTypes = [...new Set([...Object.keys(previous.records || {}), ...Object.keys(records)])];
    const changedRecords = recordTypes.filter(type => previous.records?.[type] !== records[type]);
    if (changedRecords.length) changed.push(`DNS record changes: ${changedRecords.join(", ")}`);
    if (previous.ctStatus === "complete" && ctStatus === "complete") {
      const oldHosts = new Set(previous.ctHosts || []);
      const newHosts = new Set(snapshot.ctHosts);
      const added = [...newHosts].filter(host => !oldHosts.has(host));
      const removed = [...oldHosts].filter(host => !newHosts.has(host));
      if (added.length) changed.push(`New CT names: ${added.join(", ")}`);
      if (removed.length) changed.push(`CT names no longer listed: ${removed.join(", ")}`);
    } else {
      changed.push("CT inventory change not compared because at least one scan was incomplete.");
    }
    if (previous.certificate && snapshot.certificate && JSON.stringify(previous.certificate) !== JSON.stringify(snapshot.certificate)) {
      changed.push("TLS certificate or negotiated protocol changed.");
    }
    if (previous.pathScan?.length && snapshot.pathScan.length && JSON.stringify(previous.pathScan) !== JSON.stringify(snapshot.pathScan)) {
      changed.push("Common web path or advertised-path results changed.");
    } else if (!previous.pathScan?.length && snapshot.pathScan.length) {
      changed.push("A web-path baseline was saved for future comparisons.");
    }
  }

  try {
    const remaining = previousHistory.filter(item => item.domain !== data.domain);
    const olderScans = previousHistory.filter(item => item.domain === data.domain && item.timestamp !== timestamp);
    const perDomain = [snapshot, ...olderScans].slice(0, 5);
    localStorage.setItem(SCAN_HISTORY_KEY, JSON.stringify([...perDomain, ...remaining].slice(0, 60)));
  } catch (_) { /* Storage can be unavailable in private browsing or under quota pressure. */ }

  output.innerHTML = previous
    ? `<div class="history-previous">Compared with <strong>${escapeHtml(previous.timestamp)}</strong> · ${changed.length ? changed.map(escapeHtml).join("<br>") : "No monitored DNS, CT, or certificate changes detected."}</div>`
    : `<div class="history-previous">This is the first saved scan for <strong>${escapeHtml(data.domain)}</strong>. Changes will appear after another scan in this browser.</div>`;
}

const clearScanHistoryButton = document.getElementById("clear-scan-history");
if (clearScanHistoryButton) {
  clearScanHistoryButton.addEventListener("click", () => {
    try { localStorage.removeItem(SCAN_HISTORY_KEY); } catch (_) { /* Browser storage may be disabled. */ }
    const content = document.getElementById("scan-history-content");
    if (content) content.innerHTML = `<div class="history-previous">Local scan history cleared. The next scan will create a new baseline.</div>`;
    showToast("Local scan history cleared.");
  });
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

  const recordsBadge = document.getElementById("tab-badge-records");
  if (recordsBadge) recordsBadge.textContent = String(Object.keys(data.records || {}).filter(key => key !== "zone_metadata").length);

  // 2. Threats badge & snapshot
  const threatsBadge = document.getElementById("tab-badge-threats");
  const takeoverAssessment = getTakeoverPresentation(data.security?.takeover);
  const isDnssecDelegationVerified = data.security?.dnssec?.status === "delegation_match_verified";

  if (threatsBadge) {
    threatsBadge.className = "tab-badge";
    if (takeoverAssessment.critical) {
      threatsBadge.textContent = "Alert";
      threatsBadge.classList.add("badge-red");
    } else if (takeoverAssessment.needsReview) {
      threatsBadge.textContent = "Review";
      threatsBadge.classList.add("badge-amber");
    } else if (isDnssecDelegationVerified) {
      threatsBadge.textContent = "DS Match";
      threatsBadge.classList.add("badge-amber");
    } else {
      threatsBadge.textContent = "Audit";
    }
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
function renderBentoCockpit(data, previousScore = null) {
  const hero = document.getElementById("bento-hero");
  const bentoRingFg = document.getElementById("bento-ring-fg");
  const bentoGrade = document.getElementById("bento-grade");
  const bentoScoreNum = document.getElementById("bento-score-num");
  const heroSubtitle = document.getElementById("bento-hero-subtitle");
  const breakdownContent = document.getElementById("score-breakdown-content");

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
    const startOffset = previousScore === null
      ? circumference
      : circumference - (circumference * Math.max(0, Math.min(100, previousScore)) / 100);
    bentoRingFg.style.strokeDashoffset = startOffset;
    bentoGrade.textContent = sc.grade.replace(/ \(incomplete\)$/, "");
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

  if (breakdownContent) {
    breakdownContent.replaceChildren();
    const breakdown = data.score_breakdown;
    if (!breakdown?.factors) {
      breakdownContent.textContent = "Score details are unavailable for this result.";
    } else {
      const table = document.createElement("table");
      table.className = "score-breakdown-table";
      const header = document.createElement("tr");
      ["Factor", "Points", "Status", "Checks"].forEach(label => {
        const th = document.createElement("th");
        th.scope = "col";
        th.textContent = label;
        header.appendChild(th);
      });
      const thead = document.createElement("thead");
      thead.appendChild(header);
      table.appendChild(thead);
      const tbody = document.createElement("tbody");
      Object.values(breakdown.factors).forEach(factor => {
        const row = document.createElement("tr");
        const pointsEarned = factor.points_earned ?? factor.score;
        const pointsMaximum = factor.maximum ?? factor.max_score;
        const statusText = String(factor.status ?? "unknown").replace(/_/g, " ");
        const cells = [
          factor.category,
          pointsEarned == null ? "N/A" : `${pointsEarned}/${pointsMaximum ?? "?"}`,
          statusText,
          `${factor.checks_completed ?? 0}/${factor.checks_total ?? 0}`,
        ];
        cells.forEach((value, index) => {
          const cell = document.createElement("td");
          cell.dataset.label = ["Factor", "Points", "Status", "Checks"][index];
          cell.textContent = String(value ?? "—");
          row.appendChild(cell);
        });
        tbody.appendChild(row);
      });
      table.appendChild(tbody);
      breakdownContent.appendChild(table);

      Object.values(breakdown.factors).forEach(factor => {
        const checks = (factor.checks || []).filter(check => check.status === "inconclusive");
        if (!checks.length) return;
        const note = document.createElement("p");
        note.textContent = `${factor.category}: ${checks.map(check => check.check).join(", ")} could not be scored.`;
        breakdownContent.appendChild(note);
      });

      (breakdown.caps_applied || []).forEach(cap => {
        const note = document.createElement("p");
        note.className = "score-cap-note";
        note.textContent = `Score cap ${cap.maximum}: ${cap.reason}`;
        breakdownContent.appendChild(note);
      });
      const normalization = document.createElement("p");
      normalization.className = "score-normalization-note";
      normalization.textContent = `${breakdown.inconclusive_policy ? `${breakdown.inconclusive_policy} ` : ""}${breakdown.normalization} Based on ${breakdown.included_factor_count} of ${breakdown.total_factor_count} factors.`;
      breakdownContent.appendChild(normalization);
      (breakdown.excluded_factors || []).forEach(factor => {
        const note = document.createElement("p");
        note.textContent = `${factor.category} (${factor.weight} points): excluded from normalization (${factor.status}).`;
        breakdownContent.appendChild(note);
      });
    }
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
    const provisionalNote = data.domain_score?.grade?.endsWith("(incomplete)")
      ? " Grade is provisional (incomplete) because over 30% of factor weight was excluded."
      : "";
    if (errs > 0) {
      heroSubtitle.textContent = `${labelPrefix}${errs} Critical Issue${errs === 1 ? "" : "s"} Detected.${provisionalNote}`;
      heroSubtitle.style.color = "var(--danger)";
    } else if (warns > 0) {
      heroSubtitle.textContent = `${labelPrefix}${warns} Warning${warns === 1 ? "" : "s"} — Review Advised.${provisionalNote}`;
      heroSubtitle.style.color = "var(--warning)";
    } else if (inconcl > 0) {
      heroSubtitle.textContent = `${labelPrefix}Base Checks Passed (${inconcl} Check${inconcl === 1 ? "" : "s"} Inconclusive${checkNames}).${provisionalNote}`;
      heroSubtitle.style.color = "var(--accent)";
    } else {
      heroSubtitle.textContent = `${labelPrefix}All Audited Systems Authenticated & Safe.${provisionalNote}`;
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
    if (dmarc && (dmarc.policy === "reject" || dmarc.policy === "quarantine")) {
      headline = "DMARC Policy Active";
      statusText = "Policy Enforced";
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
    if (dnssec?.status === "delegation_match_verified") {
      const algo = dnssec.keys?.[0]?.algorithm || "Standard";
      dnssecText = `DS Match (${algo})`; dnssecClass = "warn";
    } else if (dnssec?.status === "incomplete_chain") {
      dnssecText = "Incomplete DS Chain"; dnssecClass = "warn";
    } else if (dnssec?.status === "bogus") {
      dnssecText = "Bogus — Failed"; dnssecClass = "danger";
    }

    let dsText = "No DS Records", dsClass = "warn";
    if (dnssec?.ds_count > 0 && dnssec.status === "delegation_match_verified") {
      dsText = `Matched (${dnssec.ds_count} DS)`; dsClass = "ok";
    } else if (dnssec?.ds_count > 0 && dnssec.status === "bogus") {
      dsText = `Mismatch (${dnssec.ds_count} DS)`; dsClass = "danger";
    } else if (dnssec?.ds_count > 0) {
      dsText = `Found (${dnssec.ds_count} DS)`;
    }

    const takeoverAssessment = getTakeoverPresentation(takeover);
    const takeoverText = takeoverAssessment.bentoText;
    const takeoverClass = takeoverAssessment.tone;

    let headline, statusClass = "warn", statusText = "Review";
    if (takeoverAssessment.critical) {
      headline = "Takeover Risk Detected"; statusClass = "danger"; statusText = "Vulnerable";
    } else if (takeoverAssessment.needsReview) {
      headline = "Takeover Check Needs Review";
    } else if (dnssec?.status === "delegation_match_verified") {
      headline = "DS Delegation Match"; statusText = "Partial Validation";
    } else {
      headline = "Security Checks Need Review";
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
    btn.setAttribute("aria-pressed", String(isActive));
  });

  // Highlight badge if filtered
  badgeErrors.classList.toggle("active-filter", filter === "error");
  badgeWarnings.classList.toggle("active-filter", filter === "warning");
  badgeInfo.classList.toggle("active-filter", filter === "info");
  badgeInconclusive.classList.toggle("active-filter", filter === "inconclusive");

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
      : currentFilter === "inconclusive" ? "No checks were inconclusive." : `No ${currentFilter} findings detected.`;
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
      <code class="finding-code">${escapeHtml(f.code || "GEN-001")}</code>
    </div>
    <div class="finding-msg">${msgHtml}</div>
    ${f.explanation ? `<details class="finding-guidance"><summary>${escapeHtml(f.explanation.title || "What this means and what to do")}</summary><p>${escapeHtml(f.explanation.why || "")}</p><p><strong>How it could be abused:</strong> ${escapeHtml(f.explanation.attacker || "")}</p><p><strong>Suggested fix:</strong> ${escapeHtml(f.explanation.fix || "")}</p><small>${escapeHtml(f.explanation.technical || "")}${f.explanation.reference ? ` · ${escapeHtml(f.explanation.reference)}` : ""}</small></details>` : ""}
  `;
  const fixes = (currentScanData?.remediation || []).filter((fix) => {
    const type = String(fix.record_type || "").toUpperCase();
    const findingType = String(f.record_type || "").toUpperCase();
    return type && (type === findingType || (type === "TXT" && /SPF|DMARC|DKIM|BIMI|TLS-RPT/i.test(findingType)));
  });
  if (fixes.length) {
    const drawer = document.createElement("details");
    drawer.className = "finding-fix-drawer";
    const summary = document.createElement("summary");
    summary.textContent = `View recommended record${fixes.length > 1 ? "s" : ""} (${fixes.length})`;
    drawer.appendChild(summary);
    fixes.forEach((fix) => {
      const item = document.createElement("div");
      item.className = "finding-fix-item";
      const title = document.createElement("strong");
      title.textContent = fix.title || `${fix.record_type} record`;
      item.appendChild(title);
      const content = document.createElement("p");
      content.textContent = fix.guidance_only ? (fix.guidance || "Review before changing DNS.") : `${fix.name || currentDomain || "@"} ${fix.record_type} ${fix.value || ""}`;
      item.appendChild(content);
      if (!fix.guidance_only && fix.value) item.appendChild(makeCopyBlock(fix.value));
      drawer.appendChild(item);
    });
    div.appendChild(drawer);
  }
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
        <button class="record-dig-btn" type="button" aria-label="Copy dig command for ${escapeHtml(rtype)}" title="Copy dig command"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><path d="m5 4-3 4 3 4m6-8 3 4-3 4M9.5 3l-3 10"/></svg></button>
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
  card.querySelector(".record-dig-btn")?.addEventListener("click", (event) => {
    const command = `dig +noall +answer ${currentDomain || "example.com"} ${rtype}`;
    copyToClipboard(command, event.currentTarget);
  });

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
      const state = r.resolution_status === "inconclusive" ? "unknown" : r.resolves ? "yes" : "no";
      const label = state === "unknown" ? "? could not verify" : state === "yes" ? `✓ resolves${r.address_families?.length ? ` · ${r.address_families.join("/")}` : ""}` : "✗ unresolvable";
      const resolvePill = `<span class="resolve-pill resolve-${state}">${label}</span>`;
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
      const state = r.resolution_status === "inconclusive" ? "unknown" : r.resolves ? "yes" : "no";
      const label = state === "unknown" ? "? could not verify" : state === "yes" ? `✓ resolves${r.address_families?.length ? ` · ${r.address_families.join("/")}` : ""}` : "✗ unresolvable";
      const resolvePill = `<span class="resolve-pill resolve-${state}">${label}</span>`;
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
  } else if (rtype === "CAA") {
    for (const record of entry.records || []) {
      const value = `${record.flags} ${record.tag} "${record.value}"`;
      const row = document.createElement("div");
      row.className = "record-row";
      row.innerHTML = `<span class="record-category-pill">${escapeHtml(record.tag)}</span><span class="record-value">${escapeHtml(value)}</span>`;
      row.appendChild(makeInlineCopyBtn(value));
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
    scoreGrade.textContent = sc.grade.replace(/ \(incomplete\)$/, "");
    scoreNum.textContent = `${sc.score}/100`;
    scoreLabel.textContent = `Email Health: ${sc.label}`;
    scoreDesc.textContent = sc.inconclusive_count
      ? `DNS and email posture score for ${domain}. ${sc.inconclusive_count} check(s) could not be verified; TLS, mail transport, and BIMI are reported separately.`
      : `DNS and email posture score for ${domain}. TLS, mail transport, and BIMI are reported separately.`;

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
  emailAuthCards.appendChild(renderMailTransportCards(emailAuth));

  emailAuthSection.style.display = "block";
}

function renderMailTransportCards(emailAuth) {
  const wrapper = document.createElement("div");
  wrapper.className = "mail-transport-grid";
  const sts = emailAuth.mta_sts || {};
  const statusPill = (status) => status === "configured" ? "pill-ok" : status === "inconclusive" ? "pill-warn" : "pill-info";
  const stsPolicy = sts.policy || {};
  const mxRows = Array.isArray(stsPolicy.mx) ? stsPolicy.mx : [];
  const stsCard = document.createElement("article");
  stsCard.className = "auth-card";
  stsCard.innerHTML = `
    <div class="auth-card-title"><span class="pill ${statusPill(sts.status)}">${escapeHtml(sts.status || "unavailable")}</span>MTA-STS</div>
    ${sts.reason || sts.policy_reason ? `<p class="auth-empty">${escapeHtml(sts.reason || sts.policy_reason)}</p>` : ""}
    ${sts.record ? `<div class="auth-card-row"><span class="auth-card-key">DNS policy ID</span><span class="auth-card-val">${escapeHtml(sts.id || "Published")}</span></div>` : ""}
    ${sts.policy_status ? `<div class="auth-card-row"><span class="auth-card-key">Policy file</span><span class="auth-card-val">${escapeHtml(sts.policy_status)}${sts.policy_http_status ? ` · HTTP ${sts.policy_http_status}` : ""}</span></div>` : ""}
    ${stsPolicy.mode ? `<div class="auth-card-row"><span class="auth-card-key">Mode / max age</span><span class="auth-card-val">${escapeHtml(stsPolicy.mode)} · ${escapeHtml(String(stsPolicy.max_age ?? "unknown"))} seconds</span></div>` : ""}
    ${mxRows.length ? `<div class="auth-card-row"><span class="auth-card-key">MX patterns</span><span class="auth-card-val">${mxRows.map(escapeHtml).join(", ")}</span></div>` : ""}
    <p class="auth-helper-copy">Checks the DNS policy and the HTTPS policy file. No email is sent.</p>`;

  const rpt = emailAuth.tls_rpt || {};
  const rptCard = document.createElement("article");
  rptCard.className = "auth-card";
  rptCard.innerHTML = `
    <div class="auth-card-title"><span class="pill ${statusPill(rpt.status)}">${escapeHtml(rpt.status || "unavailable")}</span>TLS-RPT</div>
    ${rpt.reason ? `<p class="auth-empty">${escapeHtml(rpt.reason)}</p>` : ""}
    ${rpt.record ? `<div class="auth-card-row"><span class="auth-card-key">Record</span><span class="auth-card-val">${escapeHtml(rpt.record)}</span></div>` : ""}
    ${rpt.reporting_uris?.length ? `<div class="auth-card-row"><span class="auth-card-key">Reports sent to</span><span class="auth-card-val">${rpt.reporting_uris.map(escapeHtml).join(", ")}</span></div>` : ""}
    <p class="auth-helper-copy">TLS-RPT lets mail systems send reports about failed encrypted delivery attempts.</p>`;
  wrapper.append(stsCard, rptCard);
  return wrapper;
}

function renderSpfCard(emailAuth) {
  const card = document.createElement("div");
  card.className = "auth-card";

  const spf = emailAuth.spf;
  const isInconclusive = spf?.status === "inconclusive";
  const hasSpf = !!spf && !isInconclusive;
  const pill = isInconclusive
    ? `<span class="pill pill-warn">Could Not Verify</span>`
    : hasSpf ? `<span class="pill pill-ok">Found</span>` : `<span class="pill pill-fail">Missing</span>`;

  card.innerHTML = `<div class="auth-card-title">${pill} SPF (Sender Policy Framework) <span class="info-badge" title="Specifies authorized mail servers allowed to send email for this domain.">?</span></div>`;

  if (!hasSpf) {
    card.innerHTML += `<p class="auth-empty">${escapeHtml(isInconclusive ? spf.reason || "The TXT lookup did not complete." : "No SPF record found in TXT records.")}</p>`;
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
  const dmarcUnavailable = dmarc?.status === "inconclusive";
  const hasDmarc = !!dmarc && !dmarcUnavailable;
  const pill = dmarcUnavailable
    ? `<span class="pill pill-warn">Could Not Verify</span>`
    : hasDmarc
    ? `<span class="pill pill-ok">Found</span>`
    : `<span class="pill pill-fail">Missing</span>`;

  card.innerHTML = `<div class="auth-card-title">${pill} DMARC (Message Authentication) <span class="info-badge" title="Enforces policies for email senders and provides abuse reports to prevent phishing.">?</span></div>`;

  if (!hasDmarc) {
    card.innerHTML += `<p class="auth-empty">${dmarcUnavailable
      ? `DMARC could not be verified: ${escapeHtml(dmarc.reason || "DNS lookup was inconclusive.")}`
      : `No DMARC record found at _dmarc.${escapeHtml(domain)}`}</p>`;
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
    ["Enforcement", `${escapeHtml(String(Number(dmarc.pct) || 0))}% of emails`],
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
  const dkimUnavailable = dkim?.status === "inconclusive";
  const hasDkim = dkim && dkim.has_dkim;
  const pill = dkimUnavailable
    ? `<span class="pill pill-warn">Could Not Verify</span>`
    : hasDkim
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
    body = `<p class="auth-empty">${dkimUnavailable
      ? `DKIM checks were inconclusive: ${escapeHtml(dkim.reason || "DNS lookup failed.")}`
      : "No DKIM records found for common selectors. Custom selectors may exist."}</p>`;
  }

  card.innerHTML = `
    <div class="auth-card-title">${pill} DKIM (DomainKeys Identified Mail) <span class="info-badge" title="Cryptographic digital signature verifying emails were not tampered with in transit.">?</span></div>
    ${body}`;
  return card;
}

const customDkimInput = document.getElementById("custom-dkim-selectors");
const customDkimButton = document.getElementById("btn-check-custom-dkim");
if (customDkimInput && customDkimButton) {
  customDkimButton.addEventListener("click", async () => {
    if (!currentDomain || !currentScanData?.email_auth) {
      showToast("Run a domain analysis before checking custom selectors.");
      return;
    }
    const selectors = [...new Set(customDkimInput.value.split(/[\s,;]+/).map(value => value.trim()).filter(Boolean))];
    if (!selectors.length || selectors.length > 20) {
      showToast("Enter between 1 and 20 DKIM selectors.");
      customDkimInput.focus();
      return;
    }
    customDkimButton.disabled = true;
    const originalText = customDkimButton.textContent;
    customDkimButton.textContent = "Checking…";
    try {
      const response = await apiFetch("/api/email/dkim-selectors", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: currentDomain, selectors }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(apiErrorMessage(response, data, "Custom DKIM selector check failed."));
      const previous = currentScanData.email_auth.dkim || {};
      const found = new Map([...(previous.selectors_found || []), ...(data.selectors_found || [])].map(item => [item.selector, item]));
      const combinedChecked = [...new Set([...(previous.selectors_checked || []), ...(data.selectors_checked || [])])];
      const combined = {
        ...previous,
        ...data,
        selectors_found: [...found.values()],
        selectors_checked: combinedChecked,
        custom_selectors: [...new Set([...(previous.custom_selectors || []), ...selectors])],
        has_dkim: found.size > 0,
        status: data.status === "inconclusive" && found.size === 0 ? "inconclusive" : data.status === "partial" ? "partial" : "complete",
      };
      currentScanData.email_auth.dkim = combined;
      renderEmailAuth(currentScanData.email_auth, currentDomain);
      showToast(`Checked ${selectors.length} custom DKIM selector(s).`);
    } catch (error) {
      showToast(error.message || "Custom DKIM selector check failed.", "danger");
    } finally {
      customDkimButton.disabled = false;
      customDkimButton.textContent = originalText;
    }
  });
}

// ── Security Suite Rendering ──────────────────────────────────
function getTakeoverPresentation(takeover) {
  if (!takeover || takeover.scanned === false) {
    return {
      label: "Not Checked", pillClass: "pill-warn", statusText: "Takeover check was not completed.",
      description: "No takeover assessment is available for this scan.", bentoText: "Not Checked",
      tone: "warn", needsReview: true, critical: false,
    };
  }
  if (takeover.vulnerable || takeover.status === "critical_vulnerability") {
    return {
      label: "Vulnerable", pillClass: "pill-fail", statusText: "Critical dangling CNAME detected.",
      description: "A known provider target appears claimable.", bentoText: `CRITICAL: ${takeover.provider || "Takeover risk"}`,
      tone: "danger", needsReview: false, critical: true,
    };
  }
  if (takeover.status === "could_not_verify") {
    return {
      label: "Unverified", pillClass: "pill-warn", statusText: "Could not verify the CNAME target.",
      description: "The target could not be checked conclusively.", bentoText: "Could Not Verify",
      tone: "warn", needsReview: true, critical: false,
    };
  }
  if (takeover.status === "dangling_alias") {
    return {
      label: "Review Alias", pillClass: "pill-warn", statusText: "Unresolvable CNAME target needs review.",
      description: "The target appears dangling, but no supported provider signature confirmed takeover risk.", bentoText: "Dangling Alias",
      tone: "warn", needsReview: true, critical: false,
    };
  }
  if (takeover.status === "cloud_hosted") {
    return {
      label: "Active CNAME", pillClass: "pill-info", statusText: "Target resolves; confirm the cloud resource is still yours.",
      description: "An active cloud endpoint can still become dangling if its resource is removed.", bentoText: "Active Cloud Target",
      tone: "warn", needsReview: true, critical: false,
    };
  }
  if (takeover.status === "safe") {
    return {
      label: "No Known Issue", pillClass: "pill-ok", statusText: "No dangling target was identified.",
      description: "No known dangling CNAME was identified by the supported checks.", bentoText: "No Known Issue",
      tone: "ok", needsReview: false, critical: false,
    };
  }
  return {
    label: "Review Needed", pillClass: "pill-warn", statusText: "Takeover status is unavailable or unrecognized.",
    description: "This result does not confirm that the domain is protected.", bentoText: "Review Needed",
    tone: "warn", needsReview: true, critical: false,
  };
}

function renderSecuritySuite(security) {
  if (!securitySuiteSection || !securityCards) return;
  securitySuiteSection.style.display = "none";
  securityCards.innerHTML = "";

  if (!security) return;

  // 1. DNSSEC Card
  if (security.dnssec) {
    const sec = security.dnssec;
    const isDelegationVerified = sec.status === "delegation_match_verified";
    const isInconclusive = sec.status === "inconclusive";
    const pill = isDelegationVerified
          ? `<span class="pill pill-ok">Delegation Verified</span>`
          : (sec.status === "bogus" ? `<span class="pill pill-fail">Bogus</span>` : (isInconclusive
            ? `<span class="pill pill-warn">Could Not Verify</span>`
            : `<span class="pill pill-warn">Unsigned</span>`));

    let desc = "DNSSEC signatures let validating resolvers detect altered DNS data; DNSSEC does not prevent attacks by itself.";
    if (isDelegationVerified) {
      const algo = sec.keys && sec.keys[0] ? sec.keys[0].algorithm : "Standard";
      desc = `Parent DS record matches published DNSKEY digest (${algo}). Parent-child delegation link verified; full RRSIG root anchor chain unvalidated.`;
    } else if (isInconclusive) {
      desc = "DNS queries failed, so DNSSEC could not be verified. This is not evidence that the zone is unsigned.";
    } else if (sec.status === "incomplete_chain") {
      desc = "DNSKEY exists in zone, but missing DS delegation in parent registrar.";
    }

    const card = document.createElement("div");
    card.className = "security-card";
    card.innerHTML = `
      <div>
        <div class="sec-card-header">
          <span class="sec-card-title">${iconSvg("shield")} DNSSEC Validation <span class="info-badge" title="Cryptographically signs DNS records to prevent spoofing and cache poisoning.">?</span></span>
          ${pill}
        </div>
        <div class="sec-card-status">${isDelegationVerified ? "Delegation Link Verified" : (isInconclusive ? "Could Not Verify" : "Not Authenticated")}</div>
        <div class="sec-card-desc">${escapeHtml(desc)}</div>
      </div>
      <div style="margin-top:12px; font-size:11px; color:var(--text-muted); font-family:'Geist Mono', monospace;">
        Keys: ${sec.dnskey_count || 0} · DS: ${sec.ds_count || 0}
      </div>
    `;
    securityCards.appendChild(card);
    const zoneNodes = (sec.chain_graph?.nodes || []).filter(node => node.type === "zone");
    if (zoneNodes.length) {
      const namespace = "http://www.w3.org/2000/svg";
      const viewport = document.createElement("div");
      viewport.className = "dnssec-chain-viewport";
      const svg = document.createElementNS(namespace, "svg");
      const width = Math.max(220, zoneNodes.length * 180);
      svg.setAttribute("viewBox", `0 0 ${width} 112`);
      svg.setAttribute("role", "img");
      svg.setAttribute("aria-label", "DNSSEC root to zone chain status");
      (sec.chain_graph.edges || []).filter(edge => edge.type === "delegation").forEach((edge, index) => {
        const line = document.createElementNS(namespace, "line");
        line.setAttribute("x1", String(85 + index * 180));
        line.setAttribute("x2", String(180 + index * 180));
        line.setAttribute("y1", "48");
        line.setAttribute("y2", "48");
        line.setAttribute("class", "dnssec-chain-edge");
        svg.appendChild(line);
      });
      zoneNodes.forEach((node, index) => {
        const x = 8 + index * 180;
        const rect = document.createElementNS(namespace, "rect");
        rect.setAttribute("x", String(x));
        rect.setAttribute("y", "20");
        rect.setAttribute("width", "154");
        rect.setAttribute("height", "56");
        rect.setAttribute("rx", "8");
        rect.setAttribute("class", `dnssec-chain-node ${node.status === "secure" ? "is-secure" : node.status === "bogus" ? "is-bogus" : "is-unknown"}`);
        const label = document.createElementNS(namespace, "text");
        label.setAttribute("x", String(x + 77));
        label.setAttribute("y", "42");
        label.setAttribute("text-anchor", "middle");
        label.setAttribute("class", "dnssec-chain-label");
        label.textContent = node.label;
        const state = document.createElementNS(namespace, "text");
        state.setAttribute("x", String(x + 77));
        state.setAttribute("y", "62");
        state.setAttribute("text-anchor", "middle");
        state.setAttribute("class", "dnssec-chain-state");
        state.textContent = node.status;
        svg.append(rect, label, state);
      });
      viewport.appendChild(svg);
      card.appendChild(viewport);
    }
  }

  // 2. Subdomain Takeover Card
  if (security.takeover) {
    const to = security.takeover;
    const assessment = getTakeoverPresentation(to);
    const pill = `<span class="pill ${assessment.pillClass}">${assessment.label}</span>`;

    const card = document.createElement("div");
    card.className = "security-card";
    card.innerHTML = `
      <div>
        <div class="sec-card-header">
          <span class="sec-card-title">${iconSvg("shield")} Subdomain Takeover <span class="info-badge" title="Detects dangling CNAME records pointing to abandoned cloud services before attackers hijack them.">?</span></span>
          ${pill}
        </div>
        <div class="sec-card-status">${assessment.statusText}</div>
        <div class="sec-card-desc">${escapeHtml(to.details || assessment.description)}</div>
      </div>
      <div style="margin-top:12px; font-size:11px; color:var(--text-muted); font-family:'Geist Mono', monospace;">
        Provider: ${escapeHtml(to.provider || "None")}
        ${to.disclaimer ? `<div style="margin-top:6px;">${escapeHtml(to.disclaimer)}</div>` : ""}
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

function renderExtensionChecks(extensions) {
  const section = document.getElementById("extension-checks-section");
  const container = document.getElementById("extension-checks-cards");
  if (!section || !container) return;
  container.replaceChildren();

  const checks = [];
  const lifecycle = extensions.domain_lifecycle;
  if (lifecycle) checks.push(["Domain registration expiry (RDAP)", lifecycle]);
  const extended = extensions.extended_security || {};
  if (extended.rpki) checks.push(["RPKI route origin", extended.rpki]);
  if (extended.dane_tlsa) checks.push(["DANE / TLSA", extended.dane_tlsa]);
  if (extended.smtp_starttls) checks.push(["SMTP STARTTLS", extended.smtp_starttls]);
  if (extended.dnsbl) checks.push(["MX reputation (DNSBL)", extended.dnsbl]);

  for (const [title, check] of checks) {
    const card = document.createElement("article");
    card.className = "security-card";
    const heading = document.createElement("h3");
    heading.className = "sec-card-title";
    heading.textContent = title;
    const state = document.createElement("div");
    state.className = "sec-card-status";
    state.textContent = String(check.status || "unavailable").replaceAll("_", " ");
    card.append(heading, state);

    const details = document.createElement("div");
    details.className = "sec-card-desc";
    const lines = [];
    if (title.startsWith("Domain registration") && check.expires) {
      lines.push(`Expires ${check.expires} (${check.days_remaining} days)`);
    }
    for (const item of check.observations || []) {
      if (item.address) lines.push(`${item.address} · ${item.prefix || "no routed prefix"} · AS${item.asn ?? "?"} · ${item.status}`);
      else if (item.name) lines.push(`${item.name} · ${item.status} · ${item.records?.length || 0} TLSA record(s)`);
      for (const endpoint of item.addresses || []) {
        lines.push(`${endpoint.address} · certificate ${endpoint.certificate_sha256 || endpoint.status}`);
        for (const match of endpoint.matches || []) {
          const matchText = match.matched === true ? "matched" : match.matched === false ? "mismatch" : "not evaluated";
          lines.push(`  DANE usage ${match.usage}, selector ${match.selector}, matching ${match.matching_type}: ${matchText}`);
        }
      }
      if (item.lists) {
        lines.push(`${item.host || "MX"}${item.address ? ` · ${item.address}` : ""}`);
        for (const list of item.lists) lines.push(`  ${list.provider} · ${list.status}${list.return_codes?.length ? ` · ${list.return_codes.map(code => `127.0.0.${code}`).join(", ")}` : ""}`);
      }
    }
    for (const host of check.hosts || []) {
      lines.push(`${host.host} · ${host.status}${host.tls_version ? ` · ${host.tls_version} ${host.cipher || ""}` : ""}`);
    }
    if (check.reason) lines.push(check.reason);
    if (check.dnssec_validation === "not_performed") lines.push("Certificate associations may be compared, but DNSSEC authenticity and complete DANE validation are not established.");
    details.textContent = lines.join("\n") || "No additional evidence was returned.";
    card.appendChild(details);
    container.appendChild(card);
  }
  section.style.display = checks.length ? "block" : "none";
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
    const status = tls?.status || "unavailable";
    const badgeText = status === "blocked" ? "Blocked" : status === "unreachable" ? "No Response" : "N/A";
    if (tlsBadge) {
      tlsBadge.textContent = badgeText;
      tlsBadge.className = "tab-badge" + (status === "blocked" ? " badge-amber" : "");
    }
    tlsCards.innerHTML = `
      <div class="tls-unavailable" role="status">
        TLS and HTTPS checks could not complete. ${escapeHtml(tls?.reason || "No scan details were returned.")} Certificate, redirect, and security-header results are unavailable.
      </div>
    `;
    tlsSec.style.display = "block";
    return;
  }

  const cert = tls.certificate;
  let statusClass = tls.status === "certificate_error" ? "badge-red" : "badge-green";
  let statusText = tls.status === "certificate_error"
    ? "Cert Error"
    : (tls.tls_version ? `${tls.tls_version} Active` : "TLS Checked");
  if (tls.status !== "certificate_error" && cert?.is_expired) {
    statusClass = "badge-red";
    statusText = "Expired";
  } else if (cert && !cert.is_expired && cert.days_remaining <= 30) {
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
      : (cert.days_remaining <= 30 ? `<span class="pill pill-warn">${cert.days_remaining}d Left</span>` : `<span class="pill pill-ok">Valid (${cert.days_remaining}d)</span>`);

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
        SANs: ${(cert.san || []).slice(0, 4).map(escapeHtml).join(", ")}${(cert.san || []).length > 4 ? "..." : ""}
      </div>
    `;
    tlsCards.appendChild(cardCert);
  } else if (tls.status === "certificate_error") {
    const cardCert = document.createElement("div");
    cardCert.className = "security-card";
    cardCert.innerHTML = `
      <div class="sec-card-header">
        <span class="sec-card-title">📜 X.509 Certificate</span>
        <span class="pill pill-fail">Verification Failed</span>
      </div>
      <div class="sec-card-status">Certificate could not be trusted</div>
      <div class="sec-card-desc">${escapeHtml(tls.reason || "The certificate could not be verified by the server trust store.")}</div>
    `;
    tlsCards.appendChild(cardCert);
  }

  // 2. Encryption Protocol & Cipher Card
  const cardProto = document.createElement("div");
  cardProto.className = "security-card";
  const protoPill = !tls.tls_version
    ? `<span class="pill pill-warn">Unavailable</span>`
    : ((tls.tls_version === "TLSv1.3" || tls.tls_version === "TLSv1.2")
      ? `<span class="pill pill-ok">${escapeHtml(tls.tls_version)}</span>`
      : `<span class="pill pill-warn">Legacy</span>`);

  cardProto.innerHTML = `
    <div>
      <div class="sec-card-header">
        <span class="sec-card-title">${iconSvg("shield")} Negotiated Protocol</span>
        ${protoPill}
      </div>
      <div class="sec-card-status">${escapeHtml(tls.tls_version || "Not negotiated")}</div>
      <div class="sec-card-desc">Cipher Suite: <code>${escapeHtml(tls.cipher || "Unavailable")}</code></div>
    </div>
  `;
  tlsCards.appendChild(cardProto);

  if (Array.isArray(tls.protocol_sweep)) {
    const sweepCard = document.createElement("article");
    sweepCard.className = "security-card";
    const sweepTitle = document.createElement("h3");
    sweepTitle.className = "sec-card-title";
    sweepTitle.textContent = "TLS Protocol Support Sweep";
    sweepCard.appendChild(sweepTitle);
    for (const item of tls.protocol_sweep) {
      const row = document.createElement("div");
      row.className = "auth-card-row";
      const version = document.createElement("span");
      version.className = "auth-card-key";
      version.textContent = item.protocol;
      const result = document.createElement("span");
      result.className = "auth-card-val";
      const state = item.status === "supported" ? "Supported" : item.status === "probe_unavailable" ? "Probe unavailable" : "Not observed";
      result.textContent = `${state}${item.cipher ? ` · ${item.cipher}` : ""}${item.weak_cipher_observed ? " · weak cipher" : ""}`;
      row.append(version, result);
      sweepCard.appendChild(row);
    }
    const note = document.createElement("p");
    note.className = "sec-card-desc";
    note.textContent = "One bounded handshake is attempted for each protocol. Not observed can also mean filtered or unavailable from this scanner; this is not an exhaustive cipher or vulnerability sweep.";
    sweepCard.appendChild(note);
    tlsCards.appendChild(sweepCard);
  }

  // 3. HTTPS Redirection & Security Headers Card
  const cardHdrs = document.createElement("div");
  cardHdrs.className = "security-card";
  const redir = tls.https_redirect?.enforced;
  const hsts = tls.security_headers?.hsts;
  const csp = tls.security_headers?.csp;
  const headers = tls.security_headers || {};
  const cspRisks = headers.csp_risks || [];
  const cookies = headers.cookies || [];

  cardHdrs.innerHTML = `
    <div>
      <div class="sec-card-header">
        <span class="sec-card-title">${iconSvg("shield")} Web Security Headers</span>
        <span class="pill ${hsts ? "pill-ok" : "pill-warn"}">${hsts ? "HSTS Enforced" : "HSTS Missing"}</span>
      </div>
      <div class="sec-card-status">${redir ? "HTTP → HTTPS 301 Enforced" : "No Automatic HTTPS Redirect"}</div>
      <div class="sec-card-desc">
        HSTS: <strong>${hsts ? "Active" : "None"}</strong> · CSP: <strong>${csp ? "Present" : "Missing"}</strong> · X-Frame-Options: <strong>${escapeHtml(headers.x_frame_options || "Missing")}</strong> · X-Content-Type-Options: <strong>${escapeHtml(headers.x_content_type_options || "Missing")}</strong>
      </div>
      <div class="security-header-details">
        <div><span>Referrer-Policy</span><strong>${escapeHtml(headers.referrer_policy || "Missing")}</strong></div>
        <div><span>Permissions-Policy</span><strong>${escapeHtml(headers.permissions_policy || "Missing")}</strong></div>
        <div><span>COOP</span><strong>${escapeHtml(headers.cross_origin_opener_policy || "Missing")}</strong></div>
        <div><span>CORP</span><strong>${escapeHtml(headers.cross_origin_resource_policy || "Missing")}</strong></div>
      </div>
      ${cspRisks.length ? `<p class="security-risk-note"><strong>CSP review:</strong> ${cspRisks.map(escapeHtml).join(" · ")}</p>` : (csp ? `<p class="security-ok-note">CSP passed the common directive checks. This is a focused review, not a complete policy proof.</p>` : "")}
      <div class="cookie-audit-summary"><strong>Cookie flags</strong><span>${cookies.length ? `${cookies.length} cookie(s) observed; values were not stored.` : "No Set-Cookie headers observed."}</span>
      ${cookies.map(cookie => `<div><code>${escapeHtml(cookie.name || "unnamed")}</code><span>Secure ${cookie.secure ? "✓" : "✗"} · HttpOnly ${cookie.http_only ? "✓" : "✗"} · SameSite ${escapeHtml(cookie.same_site || "missing")}</span></div>`).join("")}</div>
    </div>
  `;
  tlsCards.appendChild(cardHdrs);

  const methods = tls.http_methods;
  if (methods) {
    const methodsCard = document.createElement("div");
    methodsCard.className = "security-card";
    const flagged = methods.review_methods || [];
    methodsCard.innerHTML = `
      <div>
        <div class="sec-card-header"><span class="sec-card-title">↔️ HTTP Method Advertisement</span><span class="pill ${flagged.length ? "pill-warn" : methods.status === "inconclusive" ? "pill-warn" : "pill-info"}">${methods.status === "inconclusive" ? "Could Not Verify" : flagged.length ? "Review" : "Checked"}</span></div>
        <div class="sec-card-status">${escapeHtml((methods.advertised || []).join(", ") || `No Allow header (HTTP ${methods.http_status ?? "N/A"})`)}</div>
        <div class="sec-card-desc">Uses an OPTIONS response only. Advertised methods may not be enabled; no PUT, DELETE, or TRACE request was sent.</div>
        ${methods.reason ? `<div class="sec-card-desc">${escapeHtml(methods.reason)}</div>` : ""}
      </div>`;
    tlsCards.appendChild(methodsCard);
  }

  tlsSec.style.display = "block";
}

// ── Passive Subdomain Footprint Rendering ─────────────────────
function renderSubdomains(subData) {
  const subSec = document.getElementById("subdomains-section");
  const subList = document.getElementById("subdomains-list");
  const subCountPill = document.getElementById("subdomain-count-pill");
  const subdomainsMeta = document.getElementById("subdomains-meta");
  const subBadge = document.getElementById("tab-badge-subdomains");
  const exportCsvButton = document.getElementById("export-subdomains-csv-btn");
  if (!subSec || !subList) return;

  subSec.style.display = "none";
  subList.innerHTML = "";

  const inventoryStatus = subData?.status || "unavailable";
  if (subdomainsMeta) {
    const state = String(subData?.state || inventoryStatus).replaceAll("_", " ").toLowerCase();
    const source = subData?.source || "Certificate Transparency provider";
    const timestamp = subData?.timestamp || "time unavailable";
    const attempts = Number.isFinite(subData?.attempts) ? ` · ${subData.attempts} request${subData.attempts === 1 ? "" : "s"}` : "";
    subdomainsMeta.textContent = `Result: ${state} · Source: ${source} · Checked: ${timestamp}${attempts}`;
  }
  const subs = subData?.subdomains || [];
  if (exportCsvButton) {
    exportCsvButton.disabled = subs.length === 0;
    exportCsvButton.onclick = () => {
      const cell = value => {
        const text = String(value ?? "");
        const safe = /^[=+@\-\t\r]/.test(text) ? `'${text}` : text;
        return `"${safe.replaceAll('"', '""')}"`;
      };
      const rows = [["hostname", "status", "addresses", "cname", "first_seen", "risk_tags", "takeover_status"], ...subs.map(item => [item.subdomain, item.status, (item.ips || []).join("; "), item.cname || "", item.first_seen || "", (item.risk_tags || []).join("; "), item.takeover?.status || "not_checked"])];
      const csv = rows.map(row => row.map(cell).join(",")).join("\r\n");
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `subdomains-${currentDomain}.csv`;
      anchor.click();
      URL.revokeObjectURL(url);
      showToast("Subdomain inventory exported as CSV.");
    };
  }
  if (subBadge) {
    subBadge.textContent = inventoryStatus === "unavailable"
      ? "N/A"
      : `${subs.length}${inventoryStatus === "partial" ? "+" : ""}`;
    subBadge.className = "tab-badge " + (inventoryStatus === "unavailable" ? "badge-amber" : (subs.length > 0 ? "badge-green" : ""));
  }
  if (subCountPill) {
    subCountPill.textContent = inventoryStatus === "unavailable"
      ? "Inventory Unavailable"
      : `${subs.length}${inventoryStatus === "partial" ? "+" : ""} Discovered Host${subs.length === 1 ? "" : "s"}`;
  }

  if (inventoryStatus === "unavailable") {
    subList.innerHTML = `
      <div class="tls-unavailable" role="status">
        Certificate Transparency inventory could not be retrieved. ${escapeHtml(subData?.reason || "No scan details were returned.")}
      </div>
    `;
    subSec.style.display = "block";
    return;
  }

  if (subs.length === 0) {
    subList.innerHTML = `
      <div class="${inventoryStatus === "partial" ? "tls-unavailable" : "no-issues"}" role="status" style="margin-top:12px;">
        ${inventoryStatus === "partial"
          ? "Certificate Transparency returned only a partial inventory; no names were recovered from the available response."
          : "No publicly logged subdomains detected via Certificate Transparency for this domain apex."}
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
            <th>Risk tags</th>
            <th>First seen</th>
            <th>Takeover</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
  `;

  for (const s of subs) {
    const isDangling = s.status === "dangling" || s.takeover?.vulnerable;
    const takeoverStatus = s.takeover?.status || "not_checked";
    const statusPill = isDangling
      ? `<span class="pill pill-fail"><span class="status-indicator-dot dot-yellow"></span>${s.takeover?.vulnerable ? "Takeover risk" : "Dangling CNAME"}</span>`
      : (s.status === "wildcard_only"
          ? `<span class="pill pill-info">Wildcard only</span>`
          : s.status === "resolving"
          ? `<span class="pill pill-ok"><span class="status-indicator-dot dot-green"></span> Active</span>`
          : `<span class="pill pill-warn"><span class="status-indicator-dot dot-yellow"></span> Inactive</span>`);

    const escapedIps = (s.ips || []).map(ip => escapeHtml(ip)).join(", ");

    tableHtml += `
      <tr>
        <td style="font-family:'Geist Mono', monospace; font-weight:600; color:var(--text-primary);">${escapeHtml(s.subdomain)}</td>
        <td style="font-family:'Geist Mono', monospace; font-size:12px;">${escapedIps || '<span style="color:var(--text-muted)">None</span>'}</td>
        <td style="font-family:'Geist Mono', monospace; font-size:12px; color:var(--text-muted);">${escapeHtml(s.cname || "—")}</td>
        <td>${(s.risk_tags || []).map(tag => `<span class="pill pill-warn">${escapeHtml(tag)}</span>`).join(" ") || "—"}</td>
        <td>${escapeHtml(s.first_seen || "Not reported")}</td>
        <td>${escapeHtml(takeoverStatus)}</td>
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
      <span style="font-family:'Geist Mono', monospace; font-size:11px; color:var(--text-muted);">${fix.guidance_only ? "No record generated" : `TTL ${fix.ttl}s`}</span>
    `;
    card.appendChild(header);

    if (fix.guidance_only) {
      const guidance = document.createElement("p");
      guidance.className = "remediation-guidance";
      guidance.textContent = fix.guidance || "Review the prerequisites before changing DNS.";
      card.appendChild(guidance);
    } else {
      const recheckButton = document.createElement("button");
      recheckButton.type = "button";
      recheckButton.className = "btn btn-secondary remediation-recheck-btn";
      recheckButton.textContent = "Re-check after fix";
      recheckButton.addEventListener("click", () => recheckAfterFix(fix, recheckButton));
      card.appendChild(recheckButton);

      // Copy block with host and value
      const copyContent = `${fix.value}`;
      const copyBlock = makeCopyBlock(copyContent);
      card.appendChild(copyBlock);
    }

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
      for (const [provider, command] of Object.entries(fix.provider_commands || {})) {
        const item = document.createElement("div");
        item.className = "fix-provider-item provider-command";
        item.innerHTML = `<strong style="color:var(--text-primary);">${escapeHtml(provider)} CLI:</strong> <code>${escapeHtml(command)}</code>`;
        guidesContainer.appendChild(item);
      }
      card.appendChild(guidesContainer);
    }

    remediationList.appendChild(card);
  }

  remediationSection.style.display = "block";
}

async function recheckAfterFix(fix, button) {
  if (!currentDomain || !currentScanData) return;
  const previous = currentScanData;
  const oldScore = previous.domain_score?.score ?? 0;
  const observedTtl = previous.records?.[fix.record_type]?.ttl;
  button.disabled = true;
  button.textContent = "Re-checking…";
  setLoading(true);
  try {
    const response = await apiFetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: currentDomain, force_refresh: true }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(apiErrorMessage(response, data, "Fresh scan failed."));
    const oldFindings = previous.findings || [];
    const newFindings = data.findings || [];
    const remaining = [...newFindings];
    const fixed = [];
    for (const oldFinding of oldFindings) {
      const aliases = new Set([oldFinding.code, ...(oldFinding.legacy_codes || [])]);
      const index = remaining.findIndex(item => aliases.has(item.code) || (item.legacy_codes || []).includes(oldFinding.code));
      if (index >= 0) remaining.splice(index, 1);
      else fixed.push(oldFinding);
    }
    renderResults(data, { previousScore: oldScore });
    const note = document.createElement("section");
    note.className = "recheck-result-card";
    const describe = items => items.length
      ? items.map(item => `<li><code>${escapeHtml(item.code || "GEN-001")}</code> ${escapeHtml(item.record_type)}: ${escapeHtml(item.explanation?.title || item.message)}</li>`).join("")
      : "<li>None</li>";
    note.innerHTML = `<h3>Re-check results</h3>
      <p>Overall score: <strong>${oldScore} → ${data.domain_score?.score ?? 0}</strong></p>
      <p><strong>Resolved since previous scan (${fixed.length})</strong></p><ul>${describe(fixed)}</ul>
      <p><strong>New findings (${remaining.length})</strong></p><ul>${describe(remaining)}</ul>
      <p class="dns-cache-note">DNS cache note: ${observedTtl ? `the previous ${escapeHtml(fix.record_type)} TTL was ${Number(observedTtl)} seconds. Recursive resolvers may continue serving cached answers for up to that TTL after a change.` : `the previous ${escapeHtml(fix.record_type)} TTL was unavailable, so the remaining DNS cache delay cannot be estimated.`}</p>`;
    remediationList.prepend(note);
    showToast("Fresh scan complete. Compare resolved and new findings above the fix list.");
  } catch (error) {
    showToast(error.message || "Fresh scan failed.", "danger");
    button.disabled = false;
    button.textContent = "Re-check after fix";
  } finally {
    setLoading(false);
  }
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

function iconSvg(kind) {
  const paths = {
    shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9Z"/>',
  };
  return `<svg class="heading-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">${paths[kind] || paths.shield}</svg>`;
}

// ── Segmented Tab Controller ──────────────────────────────────
let activeSegmentTabId = "tab-overview";

function switchSegmentTab(targetTabId, shouldFocus = false) {
  const tabs = Array.from(document.querySelectorAll(".segment-tab"));
  const panels = document.querySelectorAll(".results-tab-panel");
  const resultsEl = document.getElementById("results");
  if (!tabs.length || !panels.length) return;

  const aliases = {
    "tab-findings": "tab-overview", "tab-remediation": "tab-overview",
    "tab-threats": "tab-records", "tab-network": "tab-subdomains",
  };
  targetTabId = aliases[targetTabId] || targetTabId;
  const targetTab = document.getElementById(targetTabId);
  if (!targetTab) return;

  const targetSegment = targetTab.getAttribute("data-target");
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

  resultsEl?.classList.remove("all-mode");
  panels.forEach((p) => {
    const active = p.dataset.segment === targetSegment;
    p.classList.toggle("active", active);
    p.style.display = active ? "block" : "none";
    if (active) p.removeAttribute("hidden");
    else p.setAttribute("hidden", "");
  });

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

  // Apply roving tabindex and the initial panel visibility before keyboard
  // users reach the report navigation.
  switchSegmentTab(activeSegmentTabId);
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

  const rtypes = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"];
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
    } else if (rtype === "CAA") {
      entry.records.forEach((record) => {
        hasAny = true;
        lines.push(`${domain}.\t\t${ttl}\tIN\tCAA\t${record.flags} ${record.tag} "${record.value}"`);
      });
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
      md.push(`- ${emoji} **[${f.code || "GEN-001"} · ${f.record_type}]** ${f.message}`);
      if (f.explanation?.fix) md.push(`  - **Fix:** ${f.explanation.fix}`);
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
const btnRunPathScan = document.getElementById("btn-run-path-scan");
const widePathConfirm = document.getElementById("wide-path-confirm");
const widePathTokenInput = document.getElementById("wide-path-auth-token");
const portScanConfirm = document.getElementById("port-scan-confirm");
const btnRunPortScan = document.getElementById("btn-run-port-scan");
const networkResults = document.getElementById("network-results");
const networkPathResults = document.getElementById("network-path-results");
const stopScopeScanButton = document.getElementById("stop-scope-scan");
const scopeScanStatus = document.getElementById("scope-scan-status");
let activeScopeScanController = null;

function beginScopeScan(label) {
  if (activeScopeScanController) return null;
  const controller = new AbortController();
  activeScopeScanController = controller;
  document.body.classList.add("scope-scanning");
  if (scopeScanStatus) scopeScanStatus.textContent = `Running ${label}…`;
  if (stopScopeScanButton) {
    stopScopeScanButton.hidden = false;
    stopScopeScanButton.disabled = false;
    stopScopeScanButton.querySelector("span").textContent = "Stop scan";
  }
  [btnRunListScan, btnRunPathScan, btnRunPortScan].forEach(button => { if (button) button.disabled = true; });
  return controller;
}

function finishScopeScan(controller, status) {
  if (activeScopeScanController !== controller) return;
  activeScopeScanController = null;
  document.body.classList.remove("scope-scanning");
  if (scopeScanStatus) scopeScanStatus.textContent = status;
  if (stopScopeScanButton) {
    stopScopeScanButton.hidden = true;
    stopScopeScanButton.disabled = false;
    stopScopeScanButton.querySelector("span").textContent = "Stop scan";
  }
  if (btnRunListScan) btnRunListScan.disabled = false;
  if (btnRunPathScan) btnRunPathScan.disabled = false;
  if (btnRunPortScan) btnRunPortScan.disabled = !portScanConfirm?.checked;
}

stopScopeScanButton?.addEventListener("click", () => {
  if (!activeScopeScanController) return;
  stopScopeScanButton.disabled = true;
  stopScopeScanButton.querySelector("span").textContent = "Stopping…";
  if (scopeScanStatus) scopeScanStatus.textContent = "Stopping the active scope check…";
  activeScopeScanController.abort();
});

if (btnRunPathScan && listScanInput && networkPathResults) {
  btnRunPathScan.addEventListener("click", async () => {
    const targets = listScanInput.value.split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
    if (!targets.length) {
      showToast("Enter at least one approved hostname or public IP.");
      listScanInput.focus();
      return;
    }
    if (targets.length > 5) {
      showToast("Common path checks support up to 5 targets per run.");
      return;
    }
    const wide = Boolean(widePathConfirm?.checked);
    if (wide && targets.length > 2) {
      showToast("Wide directory checks support up to 2 targets per run.");
      return;
    }
    const scanController = beginScopeScan("website path check");
    if (!scanController) return;

    btnRunPathScan.disabled = true;
    btnRunPathScan.setAttribute("aria-busy", "true");
    btnRunPathScan.innerHTML = `<span class="mini-spinner" aria-hidden="true"></span><span>Checking Common Paths…</span>`;
    networkPathResults.style.display = "block";
    networkPathResults.innerHTML = `
      <div class="audit-card path-scan-loading" role="status" aria-live="polite">
        <span class="mini-spinner" aria-hidden="true"></span>
        <span>${wide ? "Checking a bounded 64-path directory list and same-host redirects." : "Checking common HTTPS paths and same-host redirects."} No recursive crawling.</span>
      </div>`;

    let finalStatus = "Website path check complete";
    try {
      const resp = await apiFetch("/api/network/path-scan", {
        method: "POST",
        signal: scanController.signal,
        headers: {
          "Content-Type": "application/json",
          ...(wide && document.getElementById("wide-path-auth-token")?.value?.trim()
            ? { "X-Wide-Path-Token": document.getElementById("wide-path-auth-token").value.trim() }
            : {}),
        },
        body: JSON.stringify({ targets, wide, confirmed: wide }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(apiErrorMessage(resp, data, "Common path check failed."));

      if (currentScanData) {
        currentScanData.path_scan = data;
        renderScanHistory(currentScanData);
      }

      networkPathResults.innerHTML = data.targets.map(target => {
        const counts = (target.paths || []).reduce((acc, item) => {
          acc[item.state] = (acc[item.state] || 0) + 1;
          return acc;
        }, {});
        const pillClass = target.status === "complete" ? "pill-ok" : (target.status === "blocked" ? "pill-fail" : "pill-warn");
        const rows = (target.paths || []).map(item => {
          const label = {
            found: "Available", redirect: "Redirect", restricted: "Restricted", not_found: "Not Found",
            unavailable: "No Response", response: "HTTP Response",
          }[item.state] || item.state;
          const rowClass = item.state === "found" ? "path-state-found" : (item.state === "unavailable" ? "path-state-unavailable" : "");
          return `<tr>
            <td><code class="path-name">${escapeHtml(item.path)}</code></td>
            <td><span class="path-state ${rowClass}">${escapeHtml(label)}</span></td>
            <td>${item.status_code ? `<code>${item.status_code}</code>` : `<span class="text-muted">—</span>`}</td>
            <td class="path-evidence">${item.location
              ? `Redirect location: <code>${escapeHtml(item.location)}</code>${item.redirect_status_code ? ` · same-host check: HTTP ${item.redirect_status_code}` : ""}${item.error ? ` · ${escapeHtml(item.error)}` : ""}`
              : escapeHtml(item.error || "No additional response details")}</td>
          </tr>`;
        }).join("");

        if (currentScanData && target.target.toLowerCase().replace(/\.$/, "") === currentDomain.toLowerCase()) {
          const coverageEntry = (currentScanData.coverage || []).find(item => item.name === "Common web paths");
          if (coverageEntry) {
            coverageEntry.status = target.status === "complete" ? "complete" : "partial";
            coverageEntry.detail = "Standalone common path and publication-file scan completed";
            renderScanCoverage(currentScanData.coverage);
          }
        }

        return `<section class="audit-card path-scan-card" aria-label="Common web paths for ${escapeHtml(target.target)}">
          <div class="audit-card-header">
            <div>
              <span class="audit-card-title">Website Paths <span class="audit-card-target">${escapeHtml(target.target)}</span></span>
              <div class="path-scan-summary">Checks completed · ${counts.found || 0} available · ${counts.redirect || 0} redirects · ${counts.restricted || 0} restricted</div>
            </div>
            <span class="pill ${pillClass}">${target.status === "complete" ? "Complete" : target.status === "blocked" ? "Blocked" : "Partial"}</span>
          </div>
          ${target.reason ? `<p class="path-scan-reason">${escapeHtml(target.reason)}</p>` : ""}
          ${target.advertised_paths?.length ? `<div class="path-advertised-section">
            <h3>Paths advertised by robots.txt or sitemap <span>${target.advertised_paths.length}</span></h3>
            <div class="path-advertised-list">${target.advertised_paths.map(item => `<div><code>${escapeHtml(item.path)}</code><span>${escapeHtml(item.source)}${item.review === "review" ? ` · <strong title="${escapeHtml(item.review_reason || "Name merits manual review; no access was attempted.")}">Review</strong>` : ""}</span></div>`).join("")}</div>
          </div>` : ""}
          ${rows ? `<div class="records-table-container path-table-container"><table class="records-table path-results-table">
            <thead><tr><th>Path</th><th>Result</th><th>HTTP</th><th>Details</th></tr></thead><tbody>${rows}</tbody>
          </table></div>` : `<p class="path-scan-reason">No path requests were sent because this target did not pass the public-scope check.</p>`}
        </section>`;
      }).join("");
    } catch (err) {
      if (err.name === "AbortError") {
        finalStatus = "Website path check stopped";
        networkPathResults.innerHTML = `<div class="audit-card" role="status">Scan stopped. The server has been asked to cancel the request.</div>`;
      } else {
        finalStatus = "Website path check failed";
        networkPathResults.innerHTML = `<div class="audit-card path-scan-error" role="alert">${escapeHtml(err.message || "Common path check failed.")}</div>`;
        showToast(err.message || "Common path check failed.", "danger");
      }
    } finally {
      finishScopeScan(scanController, finalStatus);
      btnRunPathScan.disabled = false;
      btnRunPathScan.removeAttribute("aria-busy");
      btnRunPathScan.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
          <path d="M2 3h12v10H2zM2 6h12M5 3v3" stroke-linejoin="round"/>
          <path d="M5 9h2m2 0h2m-6 2h2" stroke-linecap="round"/>
        </svg>
        <span>Check website paths</span>`;
    }
  });
}

if (portScanConfirm && btnRunPortScan) {
  portScanConfirm.addEventListener("change", () => {
    btnRunPortScan.disabled = Boolean(activeScopeScanController) || !portScanConfirm.checked;
  });
}

if (widePathConfirm && widePathTokenInput) {
  const updateWideTokenVisibility = () => { widePathTokenInput.hidden = !widePathConfirm.checked; };
  widePathConfirm.addEventListener("change", updateWideTokenVisibility);
  updateWideTokenVisibility();
}

if (btnRunListScan && listScanInput && networkResults) {
  btnRunListScan.addEventListener("click", async () => {
    const raw = listScanInput.value.trim();
    if (!raw) {
      showToast("Please enter at least one target hostname or IP.");
      return;
    }
    const targets = raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    if (targets.length > 50) {
      showToast("Target resolution supports up to 50 targets per run.");
      listScanInput.focus();
      return;
    }
    const scanController = beginScopeScan("public target resolution");
    if (!scanController) return;
    btnRunListScan.disabled = true;
    btnRunListScan.textContent = "Resolving Scope...";
    networkResults.style.display = "block";
    networkResults.innerHTML = `<div class="audit-card path-scan-loading" role="status" aria-live="polite"><span class="mini-spinner" aria-hidden="true"></span> Resolving targets and filtering non-public addresses…</div>`;

    let finalStatus = "Target resolution complete";
    try {
      const resp = await apiFetch("/api/network/list-scan", {
        method: "POST",
        signal: scanController.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(apiErrorMessage(resp, data, "List scan failed."));

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
            if (!portScanConfirm?.checked) {
              showToast("Confirm authorization before probing ports.");
              portScanConfirm?.focus();
              return;
            }
            btnRunPortScan?.click();
          }
        });
      });
    } catch (err) {
      if (err.name === "AbortError") {
        finalStatus = "Target resolution stopped";
        networkResults.style.display = "block";
        networkResults.innerHTML = `<div class="audit-card" role="status">Scan stopped. The server has been asked to cancel the request.</div>`;
      } else {
        finalStatus = "Target resolution failed";
        showToast(err.message, "danger");
      }
    } finally {
      finishScopeScan(scanController, finalStatus);
      btnRunListScan.disabled = false;
      btnRunListScan.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
          <path d="M2 4h12M2 8h12M2 12h8" stroke-linecap="round"/>
        </svg>
        <span>Resolve targets</span>
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
    const scanController = beginScopeScan("authorized port check");
    if (!scanController) return;
    btnRunPortScan.disabled = true;
    btnRunPortScan.textContent = "Running Service Scan…";
    networkResults.style.display = "block";
    networkResults.innerHTML = `<div class="audit-card path-scan-loading" role="status" aria-live="polite"><span class="mini-spinner" aria-hidden="true"></span> Checking the first target with the selected TCP method…</div>`;

    const authToken = document.getElementById("port-scan-auth-token")?.value?.trim() || null;

    let finalStatus = "Port check complete";
    try {
      const resp = await apiFetch("/api/network/port-scan", {
        method: "POST",
        signal: scanController.signal,
        headers: {
          "Content-Type": "application/json",
          ...(authToken ? { "X-Port-Scan-Token": authToken } : {}),
        },
        body: JSON.stringify({
          target: firstTarget,
          confirmed: true,
          scanner: document.getElementById("port-scan-mode")?.value || "nmap",
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(apiErrorMessage(resp, data, "Port scan failed."));

      if (data.status !== "completed") {
        finalStatus = `Port check ${data.status || "unavailable"}`;
        networkResults.style.display = "block";
        let pillClass = "pill-warn", titleText = "Active Scan Refused";
        if (data.status === "disabled") {
          pillClass = "pill-info";
          titleText = "Active Probes Disabled";
        } else if (data.status === "unauthorized") {
          pillClass = "pill-warn";
          titleText = "Authorization Required";
        } else if (data.status === "blocked") {
          pillClass = "pill-fail";
          titleText = "Blocked by SSRF Guard";
        } else if (data.status === "confirmation_required") {
          pillClass = "pill-warn";
          titleText = "Confirmation Required";
        } else if (data.status === "nmap_unavailable") {
          pillClass = "pill-info";
          titleText = "Nmap Unavailable";
        }

        networkResults.innerHTML = `
          <div class="audit-card">
            <div class="audit-card-header">
              <span class="audit-card-title">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                  <circle cx="7" cy="7" r="5"/>
                  <path d="M11 11l3.5 3.5" stroke-linecap="round"/>
                </svg>
                ${escapeHtml(titleText)}: <span class="audit-card-target">${escapeHtml(data.target || firstTarget)}</span>
              </span>
              <span class="pill ${pillClass}">
                Status: ${escapeHtml(data.status)}
              </span>
            </div>
            <div style="padding: 16px 20px; font-size: 13px; color: var(--text-secondary); line-height: 1.5;">
              ${escapeHtml(data.message || "Active port scanning could not be executed for this target.")}
            </div>
          </div>
        `;
        return;
      }

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
              <strong>${data.probed_ports_count ?? (data.ports || []).length} Ports Probed</strong>
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

          <p class="port-scan-result-note">An open port means a TCP connection was accepted; it does not by itself prove a vulnerability. Filtered ports may not reveal whether a service is running.</p>

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
      if (err.name === "AbortError") {
        finalStatus = "Port check stopped";
        networkResults.style.display = "block";
        networkResults.innerHTML = `<div class="audit-card" role="status">Scan stopped. The server has been asked to cancel the request.</div>`;
      } else {
        finalStatus = "Port check failed";
        showToast(err.message, "danger");
      }
    } finally {
      finishScopeScan(scanController, finalStatus);
      btnRunPortScan.disabled = !portScanConfirm?.checked;
      btnRunPortScan.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
          <circle cx="7" cy="7" r="5"/>
          <path d="M11 11l3.5 3.5" stroke-linecap="round"/>
        </svg>
        <span>Verify ports</span>
      `;
    }
  });
}

// ── Initialize ─────────────────────────────────────────────────
renderRecentChips();
initSegmentedTabs();
checkUrlParams();
