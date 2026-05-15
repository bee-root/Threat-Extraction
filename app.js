"use strict";
// Global error capture for debugging startup failures
try {
  window.addEventListener('error', (e) => {
    try {
      const el = document.getElementById('keysFileNote');
      if (el) el.textContent = `ERROR: ${e.message}`;
    } catch (er) {}
    console.error('Captured error', e.message, e.error);
  });
  window.addEventListener('unhandledrejection', (e) => {
    try {
      const el = document.getElementById('keysFileNote');
      if (el) el.textContent = `UNHANDLED REJECTION: ${e.reason}`;
    } catch (er) {}
    console.error('Unhandled rejection', e.reason);
  });
} catch (e) {}
/* ═══════════════════════════════════════════════════════════════
   THREAT EXTRACTION DASHBOARD — app.js
   Real API calls via Cloudflare Worker · Keys in localStorage
   No UI changes · Beautiful console logging
═══════════════════════════════════════════════════════════════ */

// ── Cloudflare Worker URL ──────────────────────────────────────
// Replace with your Worker URL — must include https://
// Example: 'https://wild-union-9040.yourname.workers.dev'
const WORKER = "https://threat-extraction.vodislavimad.workers.dev";

// ── localStorage key names ─────────────────────────────────────
const LS = {
  VT: "soc_vt_key",
  ABUSE: "soc_abuse_key",
  KAS: "soc_kas_key",
  CF: "soc_cf_token",
};

// ── Console logger ─────────────────────────────────────────────
const LOG = {
  _sep() {
    console.log("%c" + "─".repeat(60), "color:#2a3f55");
  },

  section(title) {
    console.log("\n%c" + "━".repeat(60), "color:#1e2d40");
    console.log(
      `%c  ${title}`,
      "color:#00c8f0;font-weight:bold;font-size:13px;font-family:monospace",
    );
    console.log("%c" + "━".repeat(60), "color:#1e2d40");
  },

  ip(ip, vtData, abuseData) {
    this._sep();
    console.log(
      `%c[IP] %c${ip}`,
      "color:#00c8f0;font-weight:bold;font-family:monospace",
      "color:#d4e2f0;font-weight:bold;font-family:monospace",
    );
    if (vtData && vtData.data && vtData.data.attributes) {
      const a = vtData.data.attributes;
      const stats = a.last_analysis_stats || {};
      const flagged = (stats.malicious || 0) + (stats.suspicious || 0);
      const total = Object.values(stats).reduce((s, v) => s + v, 0);
      const verdict =
        flagged >= 5
          ? "🔴 MALICIOUS"
          : flagged >= 1
            ? "🟡 SUSPICIOUS"
            : "🟢 CLEAN";
      console.log(
        "%c  VirusTotal",
        "color:#f0c040;font-weight:bold;font-family:monospace",
      );
      console.log(
        `%c    Verdict:       %c${verdict}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Flagged:       %c${flagged} / ${total} vendors`,
        "color:#8fa8c0;font-family:monospace",
        flagged > 0
          ? "color:#f04f5a;font-family:monospace"
          : "color:#30d080;font-family:monospace",
      );
      console.log(
        `%c    Malicious:     %c${stats.malicious || 0}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Suspicious:    %c${stats.suspicious || 0}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Harmless:      %c${stats.harmless || 0}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Undetected:    %c${stats.undetected || 0}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      if (a.country)
        console.log(
          `%c    Country:       %c${a.country}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.as_owner)
        console.log(
          `%c    AS Owner:      %c${a.as_owner}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.asn)
        console.log(
          `%c    ASN:           %c${a.asn}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.network)
        console.log(
          `%c    Network:       %c${a.network}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      console.log(
        "%c    Full VT data:",
        "color:#8fa8c0;font-family:monospace",
        a,
      );
    } else {
      console.log(
        "%c  VirusTotal: no data",
        "color:#4d6880;font-family:monospace",
      );
    }
    if (abuseData && abuseData.data) {
      const d = abuseData.data;
      const sc = d.abuseConfidenceScore || 0;
      const scColor =
        sc >= 75
          ? "color:#f04f5a"
          : sc >= 25
            ? "color:#f0c040"
            : "color:#30d080";
      console.log(
        "%c  AbuseIPDB",
        "color:#f07832;font-weight:bold;font-family:monospace",
      );
      console.log(
        `%c    Confidence:    %c${sc}%`,
        "color:#8fa8c0;font-family:monospace",
        `${scColor};font-weight:bold;font-family:monospace`,
      );
      console.log(
        `%c    Total Reports: %c${d.totalReports || 0}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    ISP:           %c${d.isp || "—"}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Country:       %c${d.countryCode || "—"}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Domain:        %c${d.domain || "—"}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Usage Type:    %c${d.usageType || "—"}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      if (d.reports && d.reports.length) {
        console.log(
          `%c    Last Report:   %c${d.reports[0].reportedAt || "—"} — ${d.reports[0].comment || ""}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      }
      console.log(
        "%c    Full Abuse data:",
        "color:#8fa8c0;font-family:monospace",
        d,
      );
    } else {
      console.log(
        "%c  AbuseIPDB: no data",
        "color:#4d6880;font-family:monospace",
      );
    }
  },

  domain(domain, vtData) {
    this._sep();
    console.log(
      `%c[DOMAIN] %c${domain}`,
      "color:#f0c040;font-weight:bold;font-family:monospace",
      "color:#d4e2f0;font-weight:bold;font-family:monospace",
    );
    if (vtData && vtData.data && vtData.data.attributes) {
      const a = vtData.data.attributes;
      const stats = a.last_analysis_stats || {};
      const flagged = (stats.malicious || 0) + (stats.suspicious || 0);
      const total = Object.values(stats).reduce((s, v) => s + v, 0);
      const verdict =
        flagged >= 5
          ? "🔴 MALICIOUS"
          : flagged >= 1
            ? "🟡 SUSPICIOUS"
            : "🟢 CLEAN";
      console.log(
        "%c  VirusTotal",
        "color:#f0c040;font-weight:bold;font-family:monospace",
      );
      console.log(
        `%c    Verdict:       %c${verdict}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Flagged:       %c${flagged} / ${total} vendors`,
        "color:#8fa8c0;font-family:monospace",
        flagged > 0
          ? "color:#f04f5a;font-family:monospace"
          : "color:#30d080;font-family:monospace",
      );
      if (a.registrar)
        console.log(
          `%c    Registrar:     %c${a.registrar}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.creation_date)
        console.log(
          `%c    Created:       %c${new Date(a.creation_date * 1000).toISOString().split("T")[0]}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.categories)
        console.log(
          `%c    Categories:    %c${Object.values(a.categories).join(", ")}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.popularity_ranks)
        console.log(
          "%c    Popularity:",
          "color:#8fa8c0;font-family:monospace",
          a.popularity_ranks,
        );
      console.log(
        "%c    Full VT data:",
        "color:#8fa8c0;font-family:monospace",
        a,
      );
    } else {
      console.log(
        "%c  VirusTotal: no data",
        "color:#4d6880;font-family:monospace",
      );
    }
  },

  hash(hash, vtData) {
    this._sep();
    const type =
      { 32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512" }[hash.length] ||
      "Unknown";
    console.log(
      `%c[HASH/${type}] %c${hash}`,
      "color:#a060f0;font-weight:bold;font-family:monospace",
      "color:#d4e2f0;font-weight:bold;font-family:monospace",
    );
    if (vtData && vtData.data && vtData.data.attributes) {
      const a = vtData.data.attributes;
      const stats = a.last_analysis_stats || {};
      const flagged = (stats.malicious || 0) + (stats.suspicious || 0);
      const total = Object.values(stats).reduce((s, v) => s + v, 0);
      const verdict =
        flagged >= 5
          ? "🔴 MALWARE"
          : flagged >= 1
            ? "🟡 SUSPICIOUS"
            : "🟢 CLEAN";
      console.log(
        `%c    Verdict:       %c${verdict}`,
        "color:#8fa8c0;font-family:monospace",
        "color:#d4e2f0;font-family:monospace",
      );
      console.log(
        `%c    Flagged:       %c${flagged} / ${total} vendors`,
        "color:#8fa8c0;font-family:monospace",
        flagged > 0
          ? "color:#f04f5a;font-family:monospace"
          : "color:#30d080;font-family:monospace",
      );
      if (a.meaningful_name)
        console.log(
          `%c    File Name:     %c${a.meaningful_name}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.size)
        console.log(
          `%c    Size:          %c${(a.size / 1024).toFixed(1)} KB`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.type_description)
        console.log(
          `%c    Type:          %c${a.type_description}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.md5)
        console.log(
          `%c    MD5:           %c${a.md5}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      if (a.sha256)
        console.log(
          `%c    SHA256:        %c${a.sha256}`,
          "color:#8fa8c0;font-family:monospace",
          "color:#d4e2f0;font-family:monospace",
        );
      console.log(
        "%c    Full VT data:",
        "color:#8fa8c0;font-family:monospace",
        a,
      );
    } else {
      console.log(
        "%c  VirusTotal: no data / not found",
        "color:#4d6880;font-family:monospace",
      );
    }
  },

  error(ioc, type, err) {
    this._sep();
    console.log(
      `%c[ERROR] %c${type.toUpperCase()} — ${ioc}`,
      "color:#f04f5a;font-weight:bold;font-family:monospace",
      "color:#d4e2f0;font-family:monospace",
    );
    console.log(`%c  ${err}`, "color:#f04f5a;font-family:monospace");
  },

  summary(r) {
    console.log("\n%c" + "█".repeat(60), "color:#00c8f0");
    console.log(
      "%c  ANALYSIS COMPLETE",
      "color:#00c8f0;font-weight:bold;font-size:14px;font-family:monospace",
    );
    console.log("%c" + "█".repeat(60), "color:#00c8f0");
    console.log(
      `%c  Total analyzed:  %c${r.total}`,
      "color:#8fa8c0;font-family:monospace",
      "color:#d4e2f0;font-weight:bold;font-family:monospace",
    );
    console.log(
      `%c  🔴 Malicious:    %c${r.malicious}`,
      "color:#8fa8c0;font-family:monospace",
      "color:#f04f5a;font-weight:bold;font-family:monospace",
    );
    console.log(
      `%c  🟡 Suspicious:   %c${r.suspicious}`,
      "color:#8fa8c0;font-family:monospace",
      "color:#f0c040;font-weight:bold;font-family:monospace",
    );
    console.log(
      `%c  🟢 Clean:        %c${r.clean}`,
      "color:#8fa8c0;font-family:monospace",
      "color:#30d080;font-weight:bold;font-family:monospace",
    );
    console.log(
      `%c  ❌ Errors:       %c${r.errors}`,
      "color:#8fa8c0;font-family:monospace",
      "color:#f04f5a;font-family:monospace",
    );
    // Also emit a readable English analysis report summary for analysts.
    console.log("%c" + "█".repeat(60) + "\n", "color:#00c8f0");
    const total = r.total || 0;
    const mal = r.malicious || 0;
    const sus = r.suspicious || 0;
    const clean = r.clean || 0;
    const err = r.errors || 0;
    const pct = (n) => (total ? Math.round((n / total) * 100) : 0);
    const reportLines = [];
    reportLines.push(`Analysis Report — Summary of findings`);
    reportLines.push(`We analyzed ${total} indicator${total === 1 ? "" : "s"} in this run.`);
    reportLines.push(`Detected ${mal} malicious (${pct(mal)}%), ${sus} suspicious (${pct(sus)}%) and ${clean} clean (${pct(clean)}%).`);
    if (err) reportLines.push(`There were ${err} errors during analysis; please re-run those items later.`);
    reportLines.push("");
    reportLines.push("Recommendations:");
    reportLines.push(" - Immediately investigate the malicious IOCs, prioritize containment and traffic blocking.");
    reportLines.push(" - For suspicious items, perform deeper dynamic analysis and retrospective telemetry searches.");
    reportLines.push(" - Add high-confidence malicious IOCs to blocklists and create detection rules.");
    reportLines.push(" - Where possible, enrich findings with external OSINT (WHOIS, passive DNS, telemetry).");
    reportLines.push("");
    reportLines.push("Note: This summary is a rapid triage output — use the full report for complete analysis details.");
    console.log(reportLines.join("\n"));
  },

  keySaved(name) {
    console.log(
      `%c[KEYS] %c${name} saved to localStorage`,
      "color:#30d080;font-weight:bold;font-family:monospace",
      "color:#d4e2f0;font-family:monospace",
    );
  },
  keyLoaded(name) {
    console.log(
      `%c[KEYS] %c${name} loaded from localStorage`,
      "color:#00c8f0;font-family:monospace",
      "color:#d4e2f0;font-family:monospace",
    );
  },
};

// ── DOM refs ───────────────────────────────────────────────────
const fileInput = document.getElementById("fileInput");
const fileList = document.getElementById("fileList");
const clearBtn = document.getElementById("clearBtn");
const countIps = document.getElementById("countIps");
const countUrls = document.getElementById("countUrls");
const countDomains = document.getElementById("countDomains");
const countHashes = document.getElementById("countHashes");
const ipContainer = document.getElementById("ipContainer");
const urlContainer = document.getElementById("urlContainer");
const domainContainer = document.getElementById("domainContainer");
const hashContainer = document.getElementById("hashContainer");
const manualType = document.getElementById("manualType");
const manualInput = document.getElementById("manualInput");
const manualSearchBtn = document.getElementById("manualSearchBtn");
const manualNote = document.getElementById("manualNote");
const vtKeyInput = document.getElementById("vtKey");
const abuseKeyInput = document.getElementById("abuseKey");
const saveKeysBtn = document.getElementById("saveKeysBtn");
const authNote = document.getElementById("authNote");
const keysFileInput = document.getElementById("keysFileInput");
const keysFileNote = document.getElementById("keysFileNote");
const startAnalysisBtn = document.getElementById("startAnalysisBtn");
const stopAnalysisBtn = document.getElementById("stopAnalysisBtn");
const analysisNote = document.getElementById("analysisNote");
const reportMaliciousBtn = document.getElementById("reportMaliciousBtn");
const reportFullBtn = document.getElementById("reportFullBtn");
const reportNote = document.getElementById("reportNote");

// ── Analysis state ─────────────────────────────────────────────
let analysisAborted = false;
let analysisRunning = false;
let currentIps = [];
let currentUrls = [];
let currentDomains = [];
let currentHashes = [];
const apiCache = {};

// ── Load keys from localStorage on startup ─────────────────────
function loadKeys() {
  const vt = localStorage.getItem(LS.VT) || "";
  const abuse = localStorage.getItem(LS.ABUSE) || "";
  const kas = localStorage.getItem(LS.KAS) || "";
  const cf = localStorage.getItem(LS.CF) || "";
  if (vt) {
    vtKeyInput.value = vt;
    LOG.keyLoaded("VirusTotal");
  }
  if (abuse) {
    abuseKeyInput.value = abuse;
    LOG.keyLoaded("AbuseIPDB");
  }
  if (kas) LOG.keyLoaded("Kaspersky");
  if (cf) LOG.keyLoaded("Cloudflare");
  if (vt || abuse)
    authNote.textContent = "Keys have been loaded from the browser.";

  // Debug: show whether keys were read (masked) so we can trace issues.
  try {
    const mask = (s) => (s ? `${s.slice(0,4)}…${s.slice(-4)}` : "(none)");
    if (typeof keysFileNote !== 'undefined' && keysFileNote) {
      keysFileNote.textContent = `VT:${mask(vt)} ABUSE:${mask(abuse)}`;
    }
    console.log('loadKeys debug:', { vtStored: !!vt, abuseStored: !!abuse, vtRaw: vt ? vt.slice(0,6) + '...' : null });
  } catch (e) {
    /* ignore */
  }

  // Restore manual search inputs if available
  try {
    const savedManual = localStorage.getItem('manual_input') || '';
    const savedType = localStorage.getItem('manual_type') || '';
    if (savedManual) manualInput.value = savedManual;
    if (savedType) manualType.value = savedType;
  } catch (e) {
    // ignore
  }
}

// ── Save keys ──────────────────────────────────────────────────
function setupKeysEventListener() {
  if (!saveKeysBtn) return;
  saveKeysBtn.addEventListener('click', () => {
    const vt = vtKeyInput.value.trim();
    const abuse = abuseKeyInput.value.trim();
    if (vt) {
      localStorage.setItem(LS.VT, vt);
      LOG.keySaved('VirusTotal');
    } else localStorage.removeItem(LS.VT);
    if (abuse) {
      localStorage.setItem(LS.ABUSE, abuse);
      LOG.keySaved('AbuseIPDB');
    } else localStorage.removeItem(LS.ABUSE);
    authNote.textContent = 'Keys have been saved to the browser.';
    updateAnalysisBtnState();
  });
}

function getKeys() {
  return {
    vt: vtKeyInput.value.trim() || localStorage.getItem(LS.VT) || "",
    abuse: abuseKeyInput.value.trim() || localStorage.getItem(LS.ABUSE) || "",
  };
}

// ── Load API keys from .txt file ───────────────────────────────
// Accepts lines like:
//   VT=abcdef               vt: abcdef
//   VIRUSTOTAL = abcdef     # comments allowed
//   ABUSE abcdef            ABUSEIPDB=...
const KEY_ALIASES = {
  vt: ["vt", "virustotal", "vt_key", "vtkey"],
  abuse: ["abuse", "abuseipdb", "abuse_key", "abusekey"],
};

function parseKeysFile(text) {
  const found = { vt: null, abuse: null };
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    // Strip inline comments (# or //) and trim.
    const line = rawLine.replace(/(\s)(#|\/\/).*$/, "$1").trim();
    if (!line) continue;
    // Match KEY=value | KEY:value | KEY value
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*[:=\s]\s*(.+)$/);
    if (!m) continue;
    const rawKey = m[1].toLowerCase();
    const rawVal = m[2].trim().replace(/^["']|["']$/g, "");
    if (!rawVal) continue;
    for (const [target, aliases] of Object.entries(KEY_ALIASES)) {
      if (aliases.includes(rawKey)) {
        found[target] = rawVal;
        break;
      }
    }
  }
  return found;
}

if (keysFileInput) {
  keysFileInput.addEventListener("change", async () => {
    const file = keysFileInput.files && keysFileInput.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = parseKeysFile(text);
      const filled = [];
      if (parsed.vt) {
        vtKeyInput.value = parsed.vt;
        localStorage.setItem(LS.VT, parsed.vt);
        LOG.keySaved("VirusTotal");
        filled.push("VirusTotal");
      }
      if (parsed.abuse) {
        abuseKeyInput.value = parsed.abuse;
        localStorage.setItem(LS.ABUSE, parsed.abuse);
        LOG.keySaved("AbuseIPDB");
        filled.push("AbuseIPDB");
      }

      if (filled.length) {
        keysFileNote.textContent = `✓ Loaded ${filled.length} key(s): ${filled.join(", ")}.`;
        authNote.textContent = "Keys loaded from file and saved.";
      } else {
        keysFileNote.textContent =
          "No recognized keys found. Expected lines like 'VT=...' or 'ABUSE=...'.";
      }
      updateAnalysisBtnState();
    } catch (e) {
      keysFileNote.textContent = `Error reading file: ${e.message}`;
        } finally {
          keysFileInput.value = "";
        }
      });
    }

// ── Helpers ────────────────────────────────────────────────────
// Trusted-domain / suspicious-TLD / hardcoded-ISP lists were removed.
// Verdicts now come from the real API responses (VirusTotal, AbuseIPDB,
// Talos) so the dashboard reflects live OSINT data instead of static maps.
function formatVtDate(unix) {
  if (!unix) return null;
  const d = new Date(unix * 1000);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().split("T")[0];
}

// Pull a 2-letter country code out of a VT domain response.
// VT usually doesn't surface country directly for domains, but the raw whois
// string often contains a 'Registrant Country' or 'Country' line.
function extractDomainCountry(a) {
  if (!a) return null;
  if (a.country && typeof a.country === "string") return a.country.toUpperCase();
  const whois = a.whois || "";
  if (!whois) return null;
  const patterns = [
    /Registrant Country:\s*([A-Za-z]{2,40})/i,
    /Admin Country:\s*([A-Za-z]{2,40})/i,
    /Country:\s*([A-Za-z]{2,40})/i,
  ];
  for (const re of patterns) {
    const m = whois.match(re);
    if (m && m[1]) return m[1].trim().toUpperCase();
  }
  return null;
}

// Stitch together the multi-line Analysis block from a default template,
// filling only the rows we actually have data for; otherwise show '—'.
function buildAnalysisBlock(verdict, sections) {
  const lines = [`THREAT LEVEL: ${verdict}`];
  for (const { title, rows } of sections) {
    lines.push("");
    lines.push(`[ ${title} ]`);
    for (const [label, value] of rows) {
      const v = value === undefined || value === null || value === "" ? "—" : value;
      lines.push(`  • ${label.padEnd(20)}${v}`);
    }
  }
  return lines.join("\n");
}

// ── OSINT sources ──────────────────────────────────────────────
// Each category lists only providers that genuinely support that IOC type.
// IP-only services (e.g. AbuseIPDB, Shodan, GreyNoise, ThreatSummary/guardpot)
// don't appear under domain/url/hash. Hash-specific sandboxes
// (MalwareBazaar, Hybrid Analysis, Triage, etc.) only appear under hash.
const urlHost = (v) => {
  try {
    return new URL(v).hostname;
  } catch {
    return v;
  }
};

const osintSources = {
  ip: [
    {
      label: "VirusTotal",
      url: (v) => `https://www.virustotal.com/gui/ip-address/${v}/details`,
    },
    { label: "AbuseIPDB", url: (v) => `https://www.abuseipdb.com/check/${v}` },
    {
      label: "IPQualityScore",
      url: (v) =>
        `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${v}`,
    },
    {
      label: "Talos",
      url: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${v}`,
    },
    {
      label: "Cloudflare Radar",
      url: (v) => `https://radar.cloudflare.com/ip/${v}`,
    },
    {
      label: "Kaspersky OpenTip",
      url: (v) => `https://opentip.kaspersky.com/${v}`,
    },
    
    { label: "GreyNoise", url: (v) => `https://viz.greynoise.io/ip/${v}` },
    {
      label: "AlienVault OTX",
      url: (v) => `https://otx.alienvault.com/indicator/ip/${v}`,
    },
    {
      label: "ThreatSummary",
      url: (v) => `https://threatsummary.guardpot.com/search?query=${v}`,
    },
  ],
  url: [
    {
      label: "VirusTotal",
      url: (v) =>
        `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}`,
    },
    {
      label: "URLScan",
      url: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}`,
    },
    {
      label: "URLVoid",
      url: (v) => `https://www.urlvoid.com/scan/${urlHost(v)}/`,
    },
    {
      label: "Sucuri SiteCheck",
      url: (v) => `https://sitecheck.sucuri.net/results/${encodeURIComponent(v)}`,
    },
    {
      label: "Symantec SiteReview",
      url: (v) =>
        `https://sitereview.bluecoat.com/#/lookup-result/${encodeURIComponent(v)}`,
    },
    {
      label: "Talos",
      url: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}`,
    },
    {
      label: "Kaspersky OpenTip",
      url: (v) => `https://opentip.kaspersky.com/${encodeURIComponent(v)}`,
    },
    {
      label: "AlienVault OTX",
      url: (v) => `https://otx.alienvault.com/indicator/url/${encodeURIComponent(v)}`,
    },
  ],
  domain: [
    {
      label: "VirusTotal",
      url: (v) => `https://www.virustotal.com/gui/domain/${v}/details`,
    },
    {
      label: "URLScan",
      url: (v) => `https://urlscan.io/domain/${v}`,
    },
    {
      label: "URLVoid",
      url: (v) => `https://www.urlvoid.com/scan/${v}/`,
    },
    {
      label: "Symantec SiteReview",
      url: (v) =>
        `https://sitereview.bluecoat.com/#/lookup-result/${encodeURIComponent(v)}`,
    },
    {
      label: "Talos",
      url: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${v}`,
    },
    {
      label: "Cloudflare Radar",
      url: (v) => `https://radar.cloudflare.com/domains/domain/${v}`,
    },
    { label: "Shodan", url: (v) => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
    {
      label: "Kaspersky OpenTip",
      url: (v) => `https://opentip.kaspersky.com/${encodeURIComponent(v)}`,
    },
    {
      label: "SecurityTrails",
      url: (v) => `https://securitytrails.com/domain/${v}/dns`,
    },
    {
      label: "AlienVault OTX",
      url: (v) => `https://otx.alienvault.com/indicator/domain/${v}`,
    },
    { label: "WHOIS", url: (v) => `https://who.is/whois/${v}` },
  ],
  hash: [
    {
      label: "VirusTotal",
      url: (v) => `https://www.virustotal.com/gui/file/${v}/detection`,
    },
    {
      label: "MalwareBazaar",
      url: (v) => `https://bazaar.abuse.ch/sample/${v}/`,
    },
    {
      label: "Hybrid Analysis",
      url: (v) => `https://www.hybrid-analysis.com/search?query=${v}`,
    },
    { label: "Triage", url: (v) => `https://tria.ge/s?q=${v}` },
    {
      label: "Joe Sandbox",
      url: (v) => `https://www.joesandbox.com/search?q=${v}`,
    },
    {
      label: "Kaspersky OpenTip",
      url: (v) => `https://opentip.kaspersky.com/${v}`,
    },
    {
      label: "AlienVault OTX",
      url: (v) => `https://otx.alienvault.com/indicator/file/${v}`,
    },
    {
      label: "ThreatFox",
      url: (v) => `https://threatfox.abuse.ch/browse.php?search=hash%3A${v}`,
    },
  ],
};

// ── Event listeners ────────────────────────────────────────────
function init() {
  fileInput.addEventListener("change", handleFiles);
  manualSearchBtn.addEventListener("click", handleManualSearch);
  clearBtn.addEventListener("click", resetDashboard);
  startAnalysisBtn.addEventListener("click", startAnalysis);
  stopAnalysisBtn.addEventListener("click", stopAnalysis);
  reportMaliciousBtn.addEventListener("click", () => downloadReport("malicious"));
  reportFullBtn.addEventListener("click", () => downloadReport("full"));
  setupKeysEventListener();
  // Ensure inputs are populated from localStorage (robust startup path)
  try {
    const vt = localStorage.getItem(LS.VT) || "";
    const abuse = localStorage.getItem(LS.ABUSE) || "";
    if (vt && vtKeyInput) vtKeyInput.value = vt;
    if (abuse && abuseKeyInput) abuseKeyInput.value = abuse;
    if (vt || abuse) authNote.textContent = 'Keys have been loaded from the browser.';
    // Update visible debug note
    if (typeof keysFileNote !== 'undefined' && keysFileNote) {
      const mask = (s) => (s ? `${s.slice(0,4)}…${s.slice(-4)}` : "(none)");
      keysFileNote.textContent = `VT:${mask(vt)} ABUSE:${mask(abuse)}`;
    }
  } catch (e) {
    console.warn('init key population failed', e.message);
  }
  // Also call loadKeys() for backward compatibility
  if (typeof loadKeys === 'function') loadKeys();
  try { window.__appInitialized = true; } catch (e) {}
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

// ── File handling ──────────────────────────────────────────────
function handleFiles() {
  const files = Array.from(fileInput.files);
  if (!files.length) return;
  fileList.textContent = files.map((f) => f.name).join(" | ");
  Promise.all(files.map(readFileAsText)).then((contents) =>
    processText(contents.join("\n")),
  );
}

function readFileAsText(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result);
    r.onerror = () => rej(r.error);
    r.readAsText(file);
  });
}

// ── Manual search ──────────────────────────────────────────────
function handleManualSearch() {
  const raw = manualInput.value.trim();
  if (!raw) {
    manualNote.textContent =
      "Enter at least one value for manual processing.";
    return;
  }
  manualNote.textContent = `Manual processing for: ${manualType.value.toUpperCase()}`;
  processManualInput(raw, manualType.value);
  // Persist manual search so it survives refresh
  try {
    localStorage.setItem('manual_input', raw);
    localStorage.setItem('manual_type', manualType.value);
  } catch (e) {
    console.warn('Could not persist manual search:', e.message);
  }
}

function processManualInput(text, type) {
  let urls = [],
    ips = [],
    domains = [],
    hashes = [];
  if (type === "all") {
    urls = extractUrls(text);
    ips = extractIps(text);
    domains = extractDomains(text, urls);
    hashes = extractHashes(text);
  } else if (type === "ip") {
    ips = parseManualValues(text, "ip");
  } else if (type === "url") {
    urls = parseManualValues(text, "url");
    domains = extractDomains(urls.join(" "), urls);
  } else if (type === "domain") {
    domains = parseManualValues(text, "domain");
  } else if (type === "hash") {
    hashes = parseManualValues(text, "hash");
  }
  renderAll(ips, urls, domains, hashes);
}

function parseManualValues(text, type) {
  const items = text
    .split(/[,\n\r;\t]+/)
    .map((i) => i.trim())
    .filter(Boolean);
  if (type === "ip") return [...new Set(items.filter(isValidIp))];
  if (type === "url")
    return [
      ...new Set(
        items.filter(
          (i) => i.startsWith("http://") || i.startsWith("https://"),
        ),
      ),
    ];
  if (type === "domain")
    return [
      ...new Set(
        items.filter((i) =>
          /^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(i),
        ),
      ),
    ];
  if (type === "hash")
    return [
      ...new Set(
        items.filter((i) =>
          /^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$|^[A-Fa-f0-9]{128}$/.test(
            i,
          ),
        ),
      ),
    ];
  return [];
}

function processText(text) {
  const urls = extractUrls(text);
  const ips = extractIps(text);
  const domains = extractDomains(text, urls);
  const hashes = extractHashes(text);
  renderAll(ips, urls, domains, hashes);
}

function renderAll(ips, urls, domains, hashes) {
  currentIps = ips;
  currentUrls = urls;
  currentDomains = domains;
  currentHashes = hashes;
  const ipD = ips
    .map((ip) => ({ ip, ...getIpDetails(ip) }))
    .sort((a, b) => b.score - a.score);
  const urlD = urls
    .map((url) => ({ url, ...getUrlDetails(url) }))
    .sort((a, b) => b.score - a.score);
  const domD = domains
    .map((domain) => ({ domain, ...getDomainDetails(domain) }))
    .sort((a, b) => b.score - a.score);
  const hashD = hashes
    .map((hash) => ({ hash, ...getHashDetails(hash) }))
    .sort((a, b) => b.score - a.score);
  countIps.textContent = ipD.length;
  countUrls.textContent = urlD.length;
  countDomains.textContent = domD.length;
  countHashes.textContent = hashD.length;
  ipContainer.innerHTML = ipD.length
    ? createIpTable(ipD)
    : "<p>No IPs found.</p>";
  urlContainer.innerHTML = urlD.length
    ? createUrlTable(urlD)
    : "<p>No URLs found.</p>";
  domainContainer.innerHTML = domD.length
    ? createDomainTable(domD)
    : "<p>No domains found.</p>";
  hashContainer.innerHTML = hashD.length
    ? createHashTable(hashD)
    : "<p>No hashes found.</p>";
  updateAnalysisBtnState();
}

// ── Extractors ─────────────────────────────────────────────────
function extractUrls(text) {
  return [
    ...new Set(
      (text.match(/https?:\/\/[^\s"'<>]+/gi) || []).map((u) => u.trim()),
    ),
  ];
}
function extractIps(text) {
  return [
    ...new Set(
      (text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(isValidIp),
    ),
  ];
}
function isValidIp(v) {
  return v.split(".").every((s) => {
    const n = +s;
    return n >= 0 && n <= 255;
  });
}
function extractDomains(text, urls) {
  const urlDomains = urls
    .map((u) => {
      try {
        return new URL(u).hostname.toLowerCase();
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  const plain = (
    text.match(/\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) || []
  )
    .map((d) => d.toLowerCase())
    .filter((d) => !urlDomains.includes(d) && !isValidIp(d));
  return [...new Set([...urlDomains, ...plain])];
}
function extractHashes(text) {
  const r = new Set();
  [
    /\b[A-Fa-f0-9]{32}\b/g,
    /\b[A-Fa-f0-9]{40}\b/g,
    /\b[A-Fa-f0-9]{64}\b/g,
    /\b[A-Fa-f0-9]{128}\b/g,
  ].forEach((p) => (text.match(p) || []).forEach((h) => r.add(h)));
  return [...r];
}

// ── Details (use real data if available) ───────────────────────
function getIpDetails(ip) {
  const isPrivate = isPrivateIp(ip),
    reserved = isReservedIp(ip);
  const ipType = reserved ? "Reserved" : isPrivate ? "Private" : "Public";
  const cached = apiCache[ip];

  if (cached && !cached.err) {
    const vtAttr =
      (cached.vt && cached.vt.data && cached.vt.data.attributes) || null;
    const stats = (vtAttr && vtAttr.last_analysis_stats) || null;
    const aData = (cached.abuse && cached.abuse.data) || null;

    const mal = stats ? (stats.malicious || 0) + (stats.suspicious || 0) : 0;
    const total = stats ? Object.values(stats).reduce((a, b) => a + b, 0) : 0;
    const abScore = aData ? aData.abuseConfidenceScore || 0 : 0;
    const reportCount = (aData && aData.totalReports) || 0;
    const score = Math.min(100, Math.max(mal * 8, abScore));

    // ISP comes from AbuseIPDB; fall back to VT's as_owner if missing.
    const isp =
      (aData && aData.isp) || (vtAttr && vtAttr.as_owner) || null;
    const country =
      (aData && (aData.countryCode || aData.countryName)) ||
      (vtAttr && vtAttr.country) ||
      null;
    const usageType = (aData && aData.usageType) || null;
    const resolvedDomain = (aData && aData.domain) || null;
    const asn = vtAttr && vtAttr.asn ? `AS${vtAttr.asn}` : null;

    const verdict =
      mal >= 5 || abScore >= 75
        ? "⚠ MALICIOUS"
        : mal >= 1 || abScore >= 25
          ? "⚡ SUSPICIOUS"
          : "✓ CLEAN";
    // Human-readable prose summary for analysts (based on verdict and reputation)
    const classification = verdict.startsWith("⚠")
      ? "malicious"
      : verdict.startsWith("⚡")
        ? "suspicious"
        : "clean";
    const reputationWord = abScore >= 75 ? "poor" : abScore >= 25 ? "questionable" : "neutral/clean";
    const abusePhrase = reportCount ? ` and recent abuse/phishing/malware-related reports (${reportCount})` : "";
    const prose = `This IP address is classified as ${classification} based on multiple OSINT sources, with a ${reputationWord} network reputation${abusePhrase}.`;

    // Normalize attack evidence into concise categories (no raw log/comment dumps).
    const attackTypes = new Set();
    const addAttackTypeFromText = (text) => {
      const t = String(text || "").toLowerCase();
      if (!t) return;
      if (/ssh|\b22\b/.test(t)) attackTypes.add("SSH");
      if (/rdp|\b3389\b/.test(t)) attackTypes.add("RDP");
      if (/brute[\s-]?force|credential stuffing|password spray/.test(t)) attackTypes.add("Brute-force");
      if (/phish|spoof/.test(t)) attackTypes.add("Phishing");
      if (/spam|smtp|mail|dnsbl|blacklist|spamhaus|spamcop/.test(t)) attackTypes.add("Email spam/abuse");
      if (/scan|port scan|recon|enumeration/.test(t)) attackTypes.add("Port scanning/recon");
      if (/ddos|dos|flood/.test(t)) attackTypes.add("DDoS/DoS");
      if (/exploit|sql injection|web attack|xss|rce/.test(t)) attackTypes.add("Exploitation/Web attack");
      if (/malware|trojan|ransom|botnet|c2|command.?and.?control/.test(t)) attackTypes.add("Malware/Botnet activity");
      if (/proxy|vpn|tor/.test(t)) attackTypes.add("Proxy/VPN/Tor abuse");
    };

    const abuseCategoryMap = {
      4: "DDoS/DoS",
      5: "Brute-force",
      7: "Phishing",
      9: "Proxy/VPN/Tor abuse",
      10: "Email spam/abuse",
      11: "Email spam/abuse",
      12: "Email spam/abuse",
      13: "Proxy/VPN/Tor abuse",
      14: "Port scanning/recon",
      15: "Exploitation/Web attack",
      16: "Exploitation/Web attack",
      18: "Brute-force",
      20: "Malware/Botnet activity",
      21: "Exploitation/Web attack",
      22: "SSH",
      23: "IoT-targeted attack",
    };

    try {
      // Attack types are derived only from AbuseIPDB report details.
      if (aData && aData.reports && Array.isArray(aData.reports)) {
        for (const rep of aData.reports) {
          if (!rep) continue;
          addAttackTypeFromText(rep.comment || "");
          if (Array.isArray(rep.categories)) {
            for (const c of rep.categories) {
              const mapped = abuseCategoryMap[c];
              if (mapped) attackTypes.add(mapped);
            }
          }
        }
      }
    } catch (e) {
      /* ignore */
    }

    let attacksNote = "—";
    if (attackTypes.size) {
      attacksNote = Array.from(attackTypes).slice(0, 6).join(", ");
    } else if (abScore >= 25 || reportCount > 0) {
      attacksNote = "Abuse reported (attack type not specified)";
    }

    const note = prose + "\n\n" + buildAnalysisBlock(verdict, [
      {
        title: "DETECTION METRICS",
        rows: [
          ["VirusTotal", `${mal}/${total}`],
          ["AbuseIPDB", `${abScore}%`],
        ],
      },
      {
        title: "NETWORK INFO",
        rows: [
          ["ISP", isp || "—"],
          ["Country", country || "—"],
          ["ASN", asn || "—"],
          ["Usage Type", usageType || "—"],
          ["Resolved Domain", resolvedDomain || "—"],
        ],
      },
      {
        title: "ATTACKS",
        rows: [["Observed Attack Types", attacksNote]],
      },
      {
        title: "CATEGORY",
        rows: [["IP Type", ipType]],
      },
    ]);

    return {
      category: ipType,
      isp: isp || "—",
      vtVendors: `${mal}/${total}`,
      abuseConfidence: `${abScore}%`,
      country: country || "—",
      note,
      score,
      isDetected: mal > 0 || abScore > 25,
    };
  }

  const baseNote = buildAnalysisBlock(
    reserved
      ? "— RESERVED"
      : isPrivate
        ? "— PRIVATE"
        : "— NOT YET ANALYZED",
    [
      {
        title: "DETECTION METRICS",
        rows: [
          ["VirusTotal", null],
          ["AbuseIPDB", null],
        ],
      },
      {
        title: "NETWORK INFO",
        rows: [
          ["ISP", null],
          ["Country", null],
          ["ASN", null],
          ["Usage Type", null],
          ["Resolved Domain", null],
        ],
      },
      {
        title: "CATEGORY",
        rows: [["IP Type", ipType]],
      },
    ],
  );

  return {
    category: ipType,
    isp: "—",
    vtVendors: "—",
    abuseConfidence: "—",
    country: "—",
    note: baseNote,
    score: reserved ? 5 : isPrivate ? 10 : 25,
    isDetected: false,
  };
}

function getDomainDetails(domain) {
  const cached = apiCache[domain];
  if (cached && cached.vt && cached.vt.data && cached.vt.data.attributes) {
    const a = cached.vt.data.attributes;
    const stats = a.last_analysis_stats || {};
    const mal = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((a2, b) => a2 + b, 0);
    const creationDate = formatVtDate(a.creation_date);
    const lastModified =
      formatVtDate(a.last_update_date) || formatVtDate(a.last_modification_date);
    const registrar = a.registrar || null;
    const country = extractDomainCountry(a);
    const categories =
      a.categories && typeof a.categories === "object"
        ? [...new Set(Object.values(a.categories))].join(", ")
        : null;
    const reputation =
      typeof a.reputation === "number" ? String(a.reputation) : null;

    const verdict =
      mal >= 5 ? "⚠ MALICIOUS" : mal >= 1 ? "⚡ SUSPICIOUS" : "✓ CLEAN";
    const classification = mal >= 5 ? "malicious" : mal >= 1 ? "suspicious" : "clean";
    const reputationWord =
      reputation && Number(reputation) >= 50
        ? "low"
        : reputation && Number(reputation) > 0
        ? "medium"
        : "neutral/clean";
    const prose = `This domain is classified as ${classification} based on multiple OSINT sources, with a ${reputationWord} web reputation and ${mal} vendor(s) flagging it.`;

    // Place structured analysis block above the prose summary (consistent with IP entries)
    const note = buildAnalysisBlock(verdict, [
      {
        title: "DETECTION METRICS",
        rows: [
          ["VirusTotal", `${mal}/${total} vendors flagged this domain`],
          ["VT Reputation", reputation],
        ],
      },
      {
        title: "REGISTRATION",
        rows: [
          ["Creation Date", creationDate],
          ["Last Updated", lastModified],
          ["Registrar", registrar],
          ["Country", country],
        ],
      },
      {
        title: "CATEGORIZATION",
        rows: [["Categories", categories]],
      },
    ]) + "\n\n" + prose;

    return {
      vtVendors: `${mal}/${total}`,
      creationDate: creationDate || "—",
      registrar: registrar || "—",
      country: country || "—",
      note,
      score: Math.min(100, 30 + mal * 10),
      isDetected: mal > 0,
    };
  }

  const baseNote = buildAnalysisBlock(
    "— NOT YET ANALYZED",
    [
      {
        title: "DETECTION METRICS",
        rows: [
          ["VirusTotal", null],
          ["VT Reputation", null],
        ],
      },
      {
        title: "REGISTRATION",
        rows: [
          ["Creation Date", null],
          ["Last Updated", null],
          ["Registrar", null],
          ["Country", null],
        ],
      },
      {
        title: "CATEGORIZATION",
        rows: [["Categories", null]],
      },
    ],
  ) + "\n\nNo information found for this domain.";

  return {
    vtVendors: "—",
    creationDate: "—",
    registrar: "—",
    country: "—",
    note: baseNote,
    score: 30,
    isDetected: false,
  };
}

function getUrlDetails(rawUrl) {
  const parsed = parseUrl(rawUrl);
  const host = (parsed && parsed.hostname) || "N/A";
  const path = (parsed && parsed.pathname) || "/";
  const query = (parsed && parsed.search) || "";

  const cached = apiCache[rawUrl];
  if (cached && cached.vt && cached.vt.data && cached.vt.data.attributes) {
    const a = cached.vt.data.attributes;
    const stats = a.last_analysis_stats || {};
    const mal = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((a2, b) => a2 + b, 0);
    const verdict =
      mal >= 5 ? "⚠ MALICIOUS" : mal >= 1 ? "⚡ SUSPICIOUS" : "✓ CLEAN";
    const classification = verdict.startsWith("⚠") ? "malicious" : verdict.startsWith("⚡") ? "suspicious" : "clean";
    const reputationWord = mal >= 5 ? "low" : mal >= 1 ? "questionable" : "neutral/clean";
    const prose = `This URL is classified as ${classification} based on multiple OSINT sources, with a ${reputationWord} web reputation${mal ? ", possibly associated with phishing, scams, malware distribution, or abusive activity" : ""}.`;

    // Structured block above prose for consistency
    const note = buildAnalysisBlock(verdict, [
      {
        title: "DETECTION METRICS",
        rows: [["VirusTotal", `${mal}/${total} vendors flagged this URL`]],
      },
      {
        title: "URL STRUCTURE",
        rows: [
          ["Host", host],
          ["Path", path || "/"],
          ["Query", query || null],
        ],
      },
    ]) + "\n\n" + prose;
    return {
      domain: host,
      path,
      query: query || "—",
      vtVendors: `${mal}/${total}`,
      note,
      score: Math.min(100, 30 + mal * 10),
      isDetected: mal > 0,
    };
  }

  const baseNote = buildAnalysisBlock(
    "— NOT YET ANALYZED",
    [
      {
        title: "DETECTION METRICS",
        rows: [["VirusTotal", null]],
      },
      {
        title: "URL STRUCTURE",
        rows: [
          ["Host", host],
          ["Path", path || "/"],
          ["Query", query || null],
        ],
      },
    ],
  ) + "\n\nNo information found for this URL.";

  return {
    domain: host,
    path,
    query: query || "—",
    vtVendors: "—",
    note: baseNote,
    score: 30,
    isDetected: false,
  };
}

function getHashDetails(hash) {
  const types = { 32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512" };
  const hashType = types[hash.length] || "Unknown";
  const cached = apiCache[hash];

  if (cached && cached.vt && cached.vt.data && cached.vt.data.attributes) {
    const a = cached.vt.data.attributes;
    const stats = a.last_analysis_stats || {};
    const mal = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((acc, b) => acc + b, 0);
    const verdict =
      mal >= 5 ? "⚠ MALWARE" : mal >= 1 ? "⚡ SUSPICIOUS" : "✓ CLEAN";
    const classification = verdict.startsWith("⚠") ? "malicious" : verdict.startsWith("⚡") ? "suspicious" : "clean";
    const prose = `This file hash is classified as ${classification} based on detections from multiple OSINT and malware analysis platforms, potentially associated with malware families, trojans, ransomware, or suspicious executable behavior.`;

    // Structured block above prose for consistency
    const note = buildAnalysisBlock(verdict, [
      {
        title: "DETECTION METRICS",
        rows: [["VirusTotal", `${mal}/${total} vendors flagged this file`]],
      },
      {
        title: "FILE INFO",
        rows: [
          ["Hash Type", hashType],
          ["File Type", a.type_description || null],
          ["File Size", a.size ? `${(a.size / 1024).toFixed(1)} KB` : null],
          ["File Name", a.meaningful_name || null],
          ["First Seen", formatVtDate(a.first_submission_date)],
          ["Last Seen", formatVtDate(a.last_submission_date)],
        ],
      },
    ]) + "\n\n" + prose;
    return {
      type: hashType,
      note,
      score: Math.min(100, mal * 10),
      isDetected: mal > 0,
    };
  }

  const baseNote = buildAnalysisBlock(
    "— NOT YET ANALYZED",
    [
      {
        title: "DETECTION METRICS",
        rows: [["VirusTotal", null]],
      },
      {
        title: "FILE INFO",
        rows: [
          ["Hash Type", hashType],
          ["File Type", null],
          ["File Size", null],
          ["File Name", null],
          ["First Seen", null],
          ["Last Seen", null],
        ],
      },
    ],
  ) + "\n\nNo information found for this file hash.";

  return {
    type: hashType,
    note: baseNote,
    score: hashType === "Unknown" ? 35 : 50,
    isDetected: false,
  };
}

function parseUrl(rawUrl) {
  try {
    return new URL(rawUrl);
  } catch {
    return null;
  }
}

function isPrivateIp(ip) {
  const o = ip.split(".").map(Number);
  return (
    o[0] === 10 ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) ||
    o[0] === 127 ||
    (o[0] === 169 && o[1] === 254) ||
    o[0] >= 224
  );
}
function isReservedIp(ip) {
  const o = ip.split(".").map(Number);
  return (
    o[0] === 0 || o[0] === 127 || (o[0] === 169 && o[1] === 254) || o[0] >= 224
  );
}

// ── Worker fetch ───────────────────────────────────────────────
async function workerFetch(path, headers = {}) {
  return fetch(`${WORKER}${path}`, {
    headers,
    signal: AbortSignal.timeout(12000),
  });
}

async function vtFetch(path) {
  const { vt } = getKeys();
  if (!vt) return null;
  const res = await workerFetch(path, { "X-VT-Key": vt });
  if (res.status === 404) return null;
  if (res.status === 429)
    throw new Error("VT rate limit — wait and retry");
  if (res.status === 401) throw new Error("VT API key invalid");
  if (!res.ok) throw new Error(`VT HTTP ${res.status}`);
  return res.json();
}

async function abuseFetch(ip) {
  const { abuse } = getKeys();
  if (!abuse) return null;
  const res = await workerFetch(`/abuse/${ip}`, { "X-Abuse-Key": abuse });
  if (res.status === 429) throw new Error("AbuseIPDB rate limit");
  if (res.status === 401) throw new Error("AbuseIPDB key invalid");
  if (!res.ok) throw new Error(`AbuseIPDB HTTP ${res.status}`);
  return res.json();
}


// ── Rate-limited queue ─────────────────────────────────────────
const apiQueue = [];
let queueRunning = false;
function enqueue(fn) {
  return new Promise((res, rej) => {
    apiQueue.push({ fn, res, rej });
    drainQueue();
  });
}
async function drainQueue() {
  if (queueRunning) return;
  queueRunning = true;
  while (apiQueue.length && !analysisAborted) {
    const { fn, res, rej } = apiQueue.shift();
    try {
      res(await fn());
    } catch (e) {
      rej(e);
    }
    if (apiQueue.length && !analysisAborted) await sleep(15000);
  }
  queueRunning = false;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Analysis button state ──────────────────────────────────────
function updateAnalysisBtnState() {
  const hasIOCs =
    currentIps.length + currentDomains.length + currentHashes.length > 0;
  const { vt, abuse } = getKeys();
  const hasKeys = !!(vt || abuse);
  startAnalysisBtn.disabled = !(hasIOCs && hasKeys) || analysisRunning;
  stopAnalysisBtn.disabled = !analysisRunning;
  if (!hasKeys)
    analysisNote.textContent =
      'Add API keys and press "Save keys" to enable analysis.';
  else if (!hasIOCs)
    analysisNote.textContent = "Upload files to enable analysis.";
  else
    analysisNote.textContent = 'Press "Start Analysis" to query APIs.';
  updateReportBtnState();
}

// ── Start analysis ─────────────────────────────────────────────
async function startAnalysis() {
  if (analysisRunning) return;
  const { vt, abuse } = getKeys();
  if (!vt && !abuse) {
    analysisNote.textContent = "Add at least one API key.";
    return;
  }
  analysisAborted = false;
  analysisRunning = true;
  startAnalysisBtn.disabled = true;
  stopAnalysisBtn.disabled = false;

  const iocs = [
    ...currentIps
      .filter((v) => !apiCache[v])
      .map((v) => ({ value: v, type: "ip" })),
    ...currentDomains
      .filter((v) => !apiCache[v])
      .map((v) => ({ value: v, type: "domain" })),
    ...currentHashes
      .filter((v) => !apiCache[v])
      .map((v) => ({ value: v, type: "hash" })),
  ];

  if (!iocs.length) {
    analysisNote.textContent = "All IOCs are already analyzed.";
    finishAnalysis();
    return;
  }

  LOG.section(`STARTING ANALYSIS — ${iocs.length} IOCs`);
  const summary = {
    total: iocs.length,
    malicious: 0,
    suspicious: 0,
    clean: 0,
    errors: 0,
  };
  let done = 0;

  for (const ioc of iocs) {
    if (analysisAborted) break;
    await enqueue(async () => {
      if (analysisAborted) return;
      try {
        if (ioc.type === "ip") {
          const [vtRes, abuseRes] = await Promise.allSettled([
            vtFetch(`/vt/ip/${ioc.value}`),
            abuseFetch(ioc.value),
          ]);
          const vtData = vtRes.status === "fulfilled" ? vtRes.value : null;
          const abuseData =
            abuseRes.status === "fulfilled" ? abuseRes.value : null;
          apiCache[ioc.value] = { vt: vtData, abuse: abuseData };
          LOG.ip(ioc.value, vtData, abuseData);
          const mal =
            (vtData &&
              vtData.data &&
              vtData.data.attributes &&
              vtData.data.attributes.last_analysis_stats &&
              vtData.data.attributes.last_analysis_stats.malicious) ||
            0;
          const sc =
            (abuseData &&
              abuseData.data &&
              abuseData.data.abuseConfidenceScore) ||
            0;
          if (mal >= 5 || sc >= 75) summary.malicious++;
          else if (mal >= 1 || sc >= 25) summary.suspicious++;
          else summary.clean++;
        } else if (ioc.type === "domain") {
          const vtData = await vtFetch(`/vt/domain/${ioc.value}`);
          apiCache[ioc.value] = { vt: vtData };
          LOG.domain(ioc.value, vtData);
          const mal =
            (vtData &&
              vtData.data &&
              vtData.data.attributes &&
              vtData.data.attributes.last_analysis_stats &&
              vtData.data.attributes.last_analysis_stats.malicious) ||
            0;
          if (mal >= 5) summary.malicious++;
          else if (mal >= 1) summary.suspicious++;
          else summary.clean++;
        } else if (ioc.type === "hash") {
          const vtData = await vtFetch(`/vt/hash/${ioc.value}`);
          apiCache[ioc.value] = { vt: vtData };
          LOG.hash(ioc.value, vtData);
          const mal =
            (vtData &&
              vtData.data &&
              vtData.data.attributes &&
              vtData.data.attributes.last_analysis_stats &&
              vtData.data.attributes.last_analysis_stats.malicious) ||
            0;
          if (mal >= 5) summary.malicious++;
          else if (mal >= 1) summary.suspicious++;
          else summary.clean++;
        }
      } catch (e) {
        apiCache[ioc.value] = { err: e.message };
        LOG.error(ioc.value, ioc.type, e.message);
        summary.errors++;
      }
      done++;
      analysisNote.textContent = `Analyzing ${done} / ${iocs.length} IOCs…`;
      renderAll(currentIps, currentUrls, currentDomains, currentHashes);
    });
  }
  LOG.summary(summary);
  finishAnalysis(!analysisAborted);
}

function stopAnalysis() {
  analysisAborted = true;
  apiQueue.length = 0;
  analysisNote.textContent = "Analysis stopped by user.";
  finishAnalysis(false);
}

function finishAnalysis(completed = true) {
  analysisRunning = false;
  startAnalysisBtn.disabled = false;
  stopAnalysisBtn.disabled = true;
  if (completed) analysisNote.textContent = "✓ Analysis complete.";
}

// ── Card builders (UI identical to original) ───────────────────
function createIpTable(items) {
  return items
    .map(
      (item) => `
    <div class="result-item ${item.isDetected ? "detected" : ""}">
        <div class="result-item-left">
            <div><div class="result-label">IP Address</div><div class="result-value">${item.ip}</div></div>
            <div><div class="result-label">ISP</div><div class="result-value">${item.isp}</div></div>
            <div><div class="result-label">Country</div><div class="result-value">${item.country}</div></div>
            <div><div class="result-label">Category</div><div class="result-value">${item.category}</div></div>
            <div><div class="result-label">VirusTotal Vendors</div><div class="result-value">${item.vtVendors}${item.vtVendors !== "—" ? " vendors flagged" : ""}</div></div>
            <div><div class="result-label">AbuseIPDB Confidence</div><div class="result-value">${item.abuseConfidence}</div></div>
            <div><div class="result-label">Analysis</div><div class="analysis-block">${item.note}</div></div>
            <div><div class="result-label">Score</div><div>${createTag(item.score, !!apiCache[item.ip])}</div></div>
        </div>
        <div class="result-item-right">
            <div class="result-label">OSINT Sources</div>
            <div class="osint-button-group">${createOsintButtons(item.ip, "ip")}</div>
        </div>
    </div>`,
    )
    .join("");
}

function createUrlTable(items) {
  return items
    .map(
      (item) => `
    <div class="result-item ${item.isDetected ? "detected" : ""}">
        <div class="result-item-left">
            <div><div class="result-label">URL</div><div class="result-value">${sanitizeDisplayUrl(item.url)}</div></div>
            <div><div class="result-label">Domain</div><div class="result-value">${item.domain}</div></div>
            <div><div class="result-label">Path</div><div class="result-value">${item.path || "/"}</div></div>
            <div><div class="result-label">Query</div><div class="result-value">${item.query || "—"}</div></div>
            <div><div class="result-label">VirusTotal Vendors</div><div class="result-value">${item.vtVendors}${item.vtVendors !== "—" ? " vendors flagged" : ""}</div></div>
            <div><div class="result-label">Analysis</div><div class="analysis-block">${item.note}</div></div>
            <div><div class="result-label">Score</div><div>${createTag(item.score, !!apiCache[item.url])}</div></div>
        </div>
        <div class="result-item-right">
            <div class="result-label">OSINT Sources</div>
            <div class="osint-button-group">${createOsintButtons(item.url, "url")}</div>
        </div>
    </div>`,
    )
    .join("");
}

function createDomainTable(items) {
  return items
    .map(
      (item) => `
    <div class="result-item ${item.isDetected ? "detected" : ""}">
        <div class="result-item-left">
            <div><div class="result-label">Domain</div><div class="result-value">${item.domain}</div></div>
            <div><div class="result-label">VirusTotal Vendors</div><div class="result-value">${item.vtVendors}${item.vtVendors !== "—" ? " vendors flagged" : ""}</div></div>
            <div><div class="result-label">Creation Date</div><div class="result-value">${item.creationDate || "—"}</div></div>
            <div><div class="result-label">Country</div><div class="result-value">${item.country || "—"}</div></div>
            <div><div class="result-label">Analysis</div><div class="analysis-block">${item.note}</div></div>
            <div><div class="result-label">Score</div><div>${createTag(item.score, !!apiCache[item.domain])}</div></div>
        </div>
        <div class="result-item-right">
            <div class="result-label">OSINT Sources</div>
            <div class="osint-button-group">${createOsintButtons(item.domain, "domain")}</div>
        </div>
    </div>`,
    )
    .join("");
}

function createHashTable(items) {
  return items
    .map(
      (item) => `
    <div class="result-item ${item.isDetected ? "detected" : ""}">
        <div class="result-item-left">
            <div><div class="result-label">Hash</div><div class="result-value">${item.hash}</div></div>
            <div><div class="result-label">Type</div><div class="result-value">${item.type}</div></div>
            <div><div class="result-label">Analysis</div><div class="analysis-block">${item.note}</div></div>
            <div><div class="result-label">Score</div><div>${createTag(item.score, !!apiCache[item.hash])}</div></div>
        </div>
        <div class="result-item-right">
            <div class="result-label">OSINT Sources</div>
            <div class="osint-button-group">${createOsintButtons(item.hash, "hash")}</div>
        </div>
    </div>`,
    )
    .join("");
}

function createTag(score, analyzed = false) {
  if (!analyzed) return `<span class="tag tag-pending">UNANALYZED</span>`;
  const label = score >= 70 ? "High" : score >= 45 ? "Medium" : "Low";
  const cls =
    score >= 70
      ? "tag tag-high"
      : score >= 45
        ? "tag tag-medium"
        : "tag tag-low";
  return `<span class="${cls}">${label} (${score})</span>`;
}

function createOsintButtons(value, category) {
  return (osintSources[category] || [])
    .map(
      (src) =>
        `<a class="osint-link osint-direct" href="${src.url(value)}" target="_blank" rel="noreferrer">${src.label}</a>`,
    )
    .join("");
}

function sanitizeDisplayUrl(u) {
  if (!u) return "—";
  try {
    const parsed = new URL(u);
    const hostPath = `${parsed.hostname}${parsed.pathname}${parsed.search}`;
    let prefix = "hxxp[:]//";
    if (parsed.protocol === "https:") prefix = "hxxps[:]//";
    else if (parsed.protocol === "http:") prefix = "hxxp[:]//";
    else prefix = parsed.protocol.replace(":", "[:]//");
    return prefix + hostPath.replace(/\./g, "[.]");
  } catch (e) {
    return String(u).replace(/\./g, "[.]").replace(/^https?:\/\//, "hxxp://");
  }
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".osint-open-all");
  if (!btn) return;
  const cat = btn.dataset.category,
    val = decodeURIComponent(btn.dataset.value);
  (osintSources[cat] || []).forEach((src) =>
    window.open(src.url(val), "_blank"),
  );
});

// ── Reports ────────────────────────────────────────────────────
function updateReportBtnState() {
  const total =
    currentIps.length +
    currentUrls.length +
    currentDomains.length +
    currentHashes.length;
  const hasIOCs = total > 0;
  reportMaliciousBtn.disabled = !hasIOCs;
  reportFullBtn.disabled = !hasIOCs;
  if (!hasIOCs) {
    reportNote.textContent = "Load IOCs to enable the report buttons.";
  } else {
    reportNote.textContent = `${total} IOC(s) ready for export.`;
  }
}

function isMalicious(item) {
  return item && (item.score >= 70 || item.isDetected === true);
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

// Pull just the first line ("THREAT LEVEL: ...") out of a multi-line note
// for use in the compact malicious-only report rows.
function shortVerdict(note) {
  if (!note) return "";
  return String(note).split("\n")[0];
}

// Indent every line of the structured analysis block under "Note:".
function indentNote(note, indent = "    ") {
  if (!note) return "";
  return String(note)
    .split("\n")
    .map((l) => (l ? indent + l : l))
    .join("\n");
}

function buildReport(type) {
  const now = new Date();
  const iso = now.toISOString();
  const ips = currentIps
    .map((ip) => ({ ip, ...getIpDetails(ip) }))
    .sort((a, b) => b.score - a.score);
  const urls = currentUrls
    .map((url) => ({ url, ...getUrlDetails(url) }))
    .sort((a, b) => b.score - a.score);
  const domains = currentDomains
    .map((domain) => ({ domain, ...getDomainDetails(domain) }))
    .sort((a, b) => b.score - a.score);
  const hashes = currentHashes
    .map((hash) => ({ hash, ...getHashDetails(hash) }))
    .sort((a, b) => b.score - a.score);

  const filterFn = type === "malicious" ? isMalicious : () => true;
  const ipsList = ips.filter(filterFn);
  const urlsList = urls.filter(filterFn);
  const domainsList = domains.filter(filterFn);
  const hashesList = hashes.filter(filterFn);

  const lines = [];
  lines.push("=".repeat(70));
  lines.push(
    `  THREAT EXTRACTION REPORT — ${
      type === "malicious" ? "MALICIOUS ONLY" : "FULL DETAILS"
    }`,
  );
  lines.push(`  Generated: ${iso}`);
  lines.push("=".repeat(70));
  lines.push("");
  lines.push(
    `Summary: ${ipsList.length} IP(s) · ${urlsList.length} URL(s) · ${domainsList.length} domain(s) · ${hashesList.length} hash(es)`,
  );
  lines.push("");

  if (
    type === "malicious" &&
    !ipsList.length &&
    !urlsList.length &&
    !domainsList.length &&
    !hashesList.length
  ) {
    lines.push("No malicious items found.");
    return lines.join("\n");
  }

  // ── IPs ──
  if (ipsList.length) {
    lines.push("─".repeat(70));
    lines.push("  IP ADDRESSES");
    lines.push("─".repeat(70));
    if (type === "malicious") {
      ipsList.forEach((it) => {
        lines.push(
          `${pad(it.ip, 18)}  score=${pad(it.score, 4)}  VT=${pad(it.vtVendors, 8)}  Abuse=${pad(it.abuseConfidence, 6)}  ${shortVerdict(it.note)}`,
        );
      });
    } else {
      ipsList.forEach((it) => {
        lines.push("");
        lines.push(`IP: ${it.ip}`);
        lines.push(`  Category:           ${it.category}`);
        lines.push(`  ISP:                ${it.isp}`);
        lines.push(`  Country:            ${it.country}`);
        lines.push(`  VirusTotal Vendors: ${it.vtVendors}`);
        lines.push(`  AbuseIPDB:          ${it.abuseConfidence}`);
        lines.push(`  Score:              ${it.score}`);
        lines.push(`  Detected:           ${it.isDetected ? "yes" : "no"}`);
        lines.push(`  Analysis:`);
        lines.push(indentNote(it.note));
      });
    }
    lines.push("");
  }

  // ── URLs ──
  if (urlsList.length) {
    lines.push("─".repeat(70));
    lines.push("  URLS");
    lines.push("─".repeat(70));
    if (type === "malicious") {
      urlsList.forEach((it) => {
        lines.push(`${it.url}  score=${it.score}  ${shortVerdict(it.note)}`);
      });
    } else {
      urlsList.forEach((it) => {
        lines.push("");
        lines.push(`URL: ${it.url}`);
        lines.push(`  Domain:             ${it.domain}`);
        lines.push(`  Path:               ${it.path || "/"}`);
        lines.push(`  Query:              ${it.query || "—"}`);
        lines.push(`  VirusTotal Vendors: ${it.vtVendors}`);
        lines.push(`  Score:              ${it.score}`);
        lines.push(`  Detected:           ${it.isDetected ? "yes" : "no"}`);
        lines.push(`  Analysis:`);
        lines.push(indentNote(it.note));
      });
    }
    lines.push("");
  }

  // ── Domains ──
  if (domainsList.length) {
    lines.push("─".repeat(70));
    lines.push("  DOMAINS");
    lines.push("─".repeat(70));
    if (type === "malicious") {
      domainsList.forEach((it) => {
        lines.push(
          `${pad(it.domain, 32)}  score=${pad(it.score, 4)}  VT=${pad(it.vtVendors, 6)}  ${shortVerdict(it.note)}`,
        );
      });
    } else {
      domainsList.forEach((it) => {
        lines.push("");
        lines.push(`Domain: ${it.domain}`);
        lines.push(`  VirusTotal Vendors: ${it.vtVendors}`);
        lines.push(`  Creation Date:      ${it.creationDate || "—"}`);
        lines.push(`  Registrar:          ${it.registrar || "—"}`);
        lines.push(`  Country:            ${it.country || "—"}`);
        lines.push(`  Score:              ${it.score}`);
        lines.push(`  Detected:           ${it.isDetected ? "yes" : "no"}`);
        lines.push(`  Analysis:`);
        lines.push(indentNote(it.note));
      });
    }
    lines.push("");
  }

  // ── Hashes ──
  if (hashesList.length) {
    lines.push("─".repeat(70));
    lines.push("  FILE HASHES");
    lines.push("─".repeat(70));
    if (type === "malicious") {
      hashesList.forEach((it) => {
        lines.push(
          `${pad(it.type, 8)}  ${it.hash}  score=${it.score}  ${shortVerdict(it.note)}`,
        );
      });
    } else {
      hashesList.forEach((it) => {
        lines.push("");
        lines.push(`Hash: ${it.hash}`);
        lines.push(`  Type:               ${it.type}`);
        lines.push(`  Score:              ${it.score}`);
        lines.push(`  Detected:           ${it.isDetected ? "yes" : "no"}`);
        lines.push(`  Analysis:`);
        lines.push(indentNote(it.note));
      });
    }
    lines.push("");
  }

  return lines.join("\n");
}

function downloadReport(type) {
  const total =
    currentIps.length +
    currentUrls.length +
    currentDomains.length +
    currentHashes.length;
  if (!total) {
    reportNote.textContent = "No IOCs to export.";
    return;
  }
  const text = buildReport(type);
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  a.href = blobUrl;
  a.download = `threat-report-${type}-${stamp}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  reportNote.textContent = `✓ Downloaded ${type} report.`;
}

// ── Reset ──────────────────────────────────────────────────────
function resetDashboard() {
  if (analysisRunning) {
    analysisAborted = true;
    apiQueue.length = 0;
    finishAnalysis(false);
  }
  fileInput.value = "";
  fileList.textContent = "";
  countIps.textContent =
    countUrls.textContent =
    countDomains.textContent =
    countHashes.textContent =
      "0";
  ipContainer.innerHTML =
    urlContainer.innerHTML =
    domainContainer.innerHTML =
    hashContainer.innerHTML =
      "<p>No files loaded.</p>";
  currentIps = [];
  currentUrls = [];
  currentDomains = [];
  currentHashes = [];
  updateAnalysisBtnState();
}

// ── Init ───────────────────────────────────────────────────────
loadKeys();
resetDashboard();
updateAnalysisBtnState();
