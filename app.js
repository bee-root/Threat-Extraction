"use strict";
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
  CF: "soc_cf_key",
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
    console.log("%c" + "█".repeat(60) + "\n", "color:#00c8f0");
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
const kasKeyInput = document.getElementById("kasKey");
const abuseKeyInput = document.getElementById("abuseKey");
const cfKeyInput = document.getElementById("cfKey");
const saveKeysBtn = document.getElementById("saveKeysBtn");
const authNote = document.getElementById("authNote");
const startAnalysisBtn = document.getElementById("startAnalysisBtn");
const stopAnalysisBtn = document.getElementById("stopAnalysisBtn");
const analysisNote = document.getElementById("analysisNote");

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
  const kas = localStorage.getItem(LS.KAS) || "";
  const abuse = localStorage.getItem(LS.ABUSE) || "";
  const cf = localStorage.getItem(LS.CF) || "";
  if (vt) {
    vtKeyInput.value = vt;
    LOG.keyLoaded("VirusTotal");
  }
  if (kas) {
    kasKeyInput.value = kas;
    LOG.keyLoaded("Kaspersky");
  }
  if (abuse) {
    abuseKeyInput.value = abuse;
    LOG.keyLoaded("AbuseIPDB");
  }
  if (cf) {
    cfKeyInput.value = cf;
    LOG.keyLoaded("Cloudflare");
  }
  if (vt || kas || abuse || cf)
    authNote.textContent = "Cheile au fost încărcate din browser.";
}

// ── Save keys ──────────────────────────────────────────────────
saveKeysBtn.addEventListener("click", () => {
  const vt = vtKeyInput.value.trim();
  const kas = kasKeyInput.value.trim();
  const abuse = abuseKeyInput.value.trim();
  const cf = cfKeyInput.value.trim();
  if (vt) {
    localStorage.setItem(LS.VT, vt);
    LOG.keySaved("VirusTotal");
  } else localStorage.removeItem(LS.VT);
  if (kas) {
    localStorage.setItem(LS.KAS, kas);
    LOG.keySaved("Kaspersky");
  } else localStorage.removeItem(LS.KAS);
  if (abuse) {
    localStorage.setItem(LS.ABUSE, abuse);
    LOG.keySaved("AbuseIPDB");
  } else localStorage.removeItem(LS.ABUSE);
  if (cf) {
    localStorage.setItem(LS.CF, cf);
    LOG.keySaved("Cloudflare");
  } else localStorage.removeItem(LS.CF);
  authNote.textContent = "Cheile au fost salvate în browser.";
  updateAnalysisBtnState();
});

function getKeys() {
  return {
    vt: vtKeyInput.value.trim() || localStorage.getItem(LS.VT) || "",
    abuse: abuseKeyInput.value.trim() || localStorage.getItem(LS.ABUSE) || "",
  };
}

// ── Trusted domains ────────────────────────────────────────────
const suspiciousTlds = ["ru", "cn", "tk", "ml", "cf", "ga", "gq"];
const suspiciousKeywords = [
  "malware",
  "phishing",
  "exploit",
  "ransom",
  "crypto",
  "bitcoin",
  "attack",
  "login",
  "update",
  "secure",
  "account",
  "admin",
];
const trustedDomains = [
  "microsoft.com",
  "outlook.com",
  "protection.outlook.com",
  "google.com",
  "apple.com",
  "amazon.com",
  "github.com",
  "facebook.com",
  "twitter.com",
  "linkedin.com",
  "reddit.com",
  "dropbox.com",
  "adobe.com",
  "slack.com",
  "zoom.com",
  "cisco.com",
  "ibm.com",
  "oracle.com",
  "salesforce.com",
  "stripe.com",
  "paypal.com",
  "github.io",
  "cloudflare.com",
  "cloudfront.net",
  "akamai.net",
  "amazonaws.com",
  "azure.com",
  "gstatic.com",
  "googleapis.com",
];
function isDomainTrusted(domain) {
  if (!domain || domain === "N/A") return false;
  const d = domain.toLowerCase();
  return trustedDomains.some((t) => d === t || d.endsWith("." + t));
}

// ── ISP map ────────────────────────────────────────────────────
const ispMap = {
  "1.": "APNIC",
  "3.": "GE",
  "4.": "Level3",
  "5.": "RIPE NCC",
  "8.": "Level3",
  "13.": "Microsoft",
  "15.": "Verizon",
  "18.": "Amazon",
  "35.": "Google",
  "40.": "Cogent",
  "44.": "Comcast",
  "50.": "Comcast",
  "52.": "Amazon",
  "54.": "Amazon",
  "66.": "Level3",
  "69.": "Cox",
  "72.": "Comcast",
  "74.": "Comcast",
  "75.": "Comcast",
  "76.": "Comcast",
  "77.": "Rostelecom",
  "78.": "Rostelecom",
  "79.": "Nitel",
  "80.": "Rostelecom",
  "81.": "Nitel",
  "82.": "Nitel",
  "83.": "Nitel",
  "84.": "Nitel",
  "85.": "Nitel",
  "86.": "Nitel",
  "87.": "Yandex",
  "88.": "Nitel",
  "89.": "Telecom Italia",
  "90.": "Telecom Italia",
  "91.": "Nitel",
  "92.": "Nitel",
  "93.": "Nitel",
  "94.": "Nitel",
  "95.": "Nitel",
  "96.": "Nitel",
  "97.": "Comcast",
  "98.": "Comcast",
  "99.": "Level3",
  "100.": "Comcast",
  "103.": "APNIC",
  "104.": "Level3",
  "113.": "APNIC",
  "127.": "Loopback",
  "128.": "Research",
  "130.": "Research",
  "149.": "Level3",
  "150.": "RIPE NCC",
  "159.": "RIPE NCC",
  "173.": "Level3",
  "174.": "Cogent",
  "175.": "APNIC",
  "176.": "RIPE NCC",
  "181.": "LACNIC",
  "183.": "APNIC",
  "184.": "Level3",
  "185.": "RIPE NCC",
  "192.": "RIPE NCC",
  "193.": "RIPE NCC",
  "194.": "RIPE NCC",
  "195.": "RIPE NCC",
  "197.": "AFRINIC",
  "198.": "Level3",
  "199.": "Level3",
  "200.": "LACNIC",
  "202.": "APNIC",
  "203.": "APNIC",
  "204.": "Level3",
  "208.": "Cogent",
  "209.": "Cogent",
  "210.": "APNIC",
  "212.": "RIPE NCC",
  "213.": "RIPE NCC",
  "216.": "Level3",
  "217.": "RIPE NCC",
  "218.": "APNIC",
};

// ── OSINT sources ──────────────────────────────────────────────
const osintSources = {
  ip: [
    {
      label: "VirusTotal",
      url: (v) => `https://www.virustotal.com/gui/ip-address/${v}/details`,
    },
    { label: "AbuseIPDB", url: (v) => `https://www.abuseipdb.com/check/${v}` },
    {
      label: "IPQualityScore",
      url: (v) => `https://www.ipqualityscore.com/free-ip-lookup/${v}`,
    },
    {
      label: "CrowdSec",
      url: (v) => `https://app.crowdsec.net/analysis/ip/${v}`,
    },
    {
      label: "Cloudflare Radar",
      url: (v) => `https://radar.cloudflare.com/${v}`,
    },
    {
      label: "Talos",
      url: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${v}`,
    },
    {
      label: "Kaspersky OpenTip",
      url: (v) => `https://opentip.kaspersky.com/${v}`,
    },
  ],
  url: [
    {
      label: "VirusTotal",
      url: (v) =>
        `https://www.virustotal.com/gui/url/${encodeURIComponent(v)}/detection`,
    },
    {
      label: "URLScan",
      url: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}`,
    },
    {
      label: "Blue Coat",
      url: (v) =>
        `https://sitereview.bluecoat.com/sitereview.jsp#/?url=${encodeURIComponent(v)}`,
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
      label: "ThreatSummary",
      url: (v) =>
        `https://threatsummary.guardpot.com/search?query=${encodeURIComponent(v)}`,
    },
    {
      label: "CrowdSec",
      url: (v) =>
        `https://app.crowdsec.net/analysis/url/${encodeURIComponent(v)}`,
    },
  ],
  domain: [
    {
      label: "VirusTotal",
      url: (v) => `https://www.virustotal.com/gui/domain/${v}/details`,
    },
    {
      label: "URLScan",
      url: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}`,
    },
    {
      label: "Blue Coat",
      url: (v) =>
        `https://sitereview.bluecoat.com/sitereview.jsp#/?url=${encodeURIComponent(v)}`,
    },
    {
      label: "Talos",
      url: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}`,
    },
    {
      label: "Cloudflare Radar",
      url: (v) => `https://radar.cloudflare.com/${v}`,
    },
    {
      label: "Kaspersky OpenTip",
      url: (v) => `https://opentip.kaspersky.com/${encodeURIComponent(v)}`,
    },
    {
      label: "ThreatSummary",
      url: (v) =>
        `https://threatsummary.guardpot.com/search?query=${encodeURIComponent(v)}`,
    },
  ],
  hash: [
    {
      label: "VirusTotal",
      url: (v) => `https://www.virustotal.com/gui/file/${v}/detection`,
    },
    {
      label: "Kaspersky OpenTip",
      url: (v) => `https://opentip.kaspersky.com/${v}`,
    },
    {
      label: "ThreatSummary",
      url: (v) => `https://threatsummary.guardpot.com/search?query=${v}`,
    },
  ],
};

// ── Event listeners ────────────────────────────────────────────
fileInput.addEventListener("change", handleFiles);
manualSearchBtn.addEventListener("click", handleManualSearch);
clearBtn.addEventListener("click", resetDashboard);
startAnalysisBtn.addEventListener("click", startAnalysis);
stopAnalysisBtn.addEventListener("click", stopAnalysis);

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
      "Introduce cel puțin o valoare pentru procesare manuală.";
    return;
  }
  manualNote.textContent = `Procesare manuală pentru: ${manualType.value.toUpperCase()}`;
  processManualInput(raw, manualType.value);
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
    : "<p>Nu s-au găsit IP-uri.</p>";
  urlContainer.innerHTML = urlD.length
    ? createUrlTable(urlD)
    : "<p>Nu s-au găsit URL-uri.</p>";
  domainContainer.innerHTML = domD.length
    ? createDomainTable(domD)
    : "<p>Nu s-au găsit domenii.</p>";
  hashContainer.innerHTML = hashD.length
    ? createHashTable(hashD)
    : "<p>Nu s-au găsit hash-uri.</p>";
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
  const isp = ispMap[ip.split(".")[0] + "."] || "Unknown";
  const cached = apiCache[ip];
  if (cached && !cached.err) {
    const stats =
      (cached.vt &&
        cached.vt.data &&
        cached.vt.data.attributes &&
        cached.vt.data.attributes.last_analysis_stats) ||
      null;
    const aData = (cached.abuse && cached.abuse.data) || null;
    const mal = stats ? (stats.malicious || 0) + (stats.suspicious || 0) : 0;
    const total = stats ? Object.values(stats).reduce((a, b) => a + b, 0) : 0;
    const abScore = aData ? aData.abuseConfidenceScore : 0;
    const score = Math.min(100, Math.max(mal * 8, abScore));
    const note =
      mal >= 5 || abScore >= 75
        ? `⚠ Malitios: ${mal}/${total} VT vendors · ${abScore}% AbuseIPDB`
        : mal >= 1 || abScore >= 25
          ? `⚡ Suspect: ${mal}/${total} VT vendors · ${abScore}% AbuseIPDB`
          : `✓ Curat: ${mal}/${total} VT vendors · ${abScore}% AbuseIPDB`;
    return {
      category: reserved ? "Reserved" : isPrivate ? "Private" : "Public",
      isp,
      vtVendors: `${mal}/${total}`,
      abuseConfidence: `${abScore}%`,
      talosReputation:
        abScore >= 75 || mal >= 10
          ? "Negative"
          : abScore >= 50 || mal >= 5
            ? "Poor"
            : abScore >= 20 || mal >= 2
              ? "Neutral"
              : "Good",
      note,
      score,
      isDetected: mal > 0 || abScore > 25,
    };
  }
  return {
    category: reserved ? "Reserved" : isPrivate ? "Private" : "Public",
    isp,
    vtVendors: "—",
    abuseConfidence: "—",
    talosReputation: "—",
    note: reserved
      ? "IP rezervat - nu prezintă risc direct"
      : isPrivate
        ? "IP privat/intern - nu accesibil public"
        : "Nu a fost analizat încă",
    score: reserved ? 5 : isPrivate ? 10 : 25,
    isDetected: false,
  };
}

function getDomainDetails(domain) {
  if (isDomainTrusted(domain))
    return {
      vtVendors: 0,
      talosReputation: "Good",
      note: "Domeniu de încredere - reputație bună pe toate sursele OSINT",
      score: 5,
      isDetected: false,
    };
  const cached = apiCache[domain];
  if (cached && cached.vt && cached.vt.data && cached.vt.data.attributes) {
    const stats = cached.vt.data.attributes.last_analysis_stats || {};
    const mal = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    return {
      vtVendors: mal,
      talosReputation:
        mal >= 10
          ? "Negative"
          : mal >= 5
            ? "Poor"
            : mal >= 2
              ? "Neutral"
              : "Good",
      note:
        mal > 0
          ? `${mal}/${total} VT vendors semnalează`
          : "✓ Curat pe VirusTotal",
      score: Math.min(100, 30 + mal * 10),
      isDetected: mal > 0,
    };
  }
  let score = 30;
  const tld = domain.split(".").pop();
  if (suspiciousTlds.includes(tld)) score += 25;
  if (suspiciousKeywords.some((w) => domain.includes(w))) score += 20;
  return {
    vtVendors: "—",
    talosReputation: "—",
    note: "Nu a fost analizat încă",
    score,
    isDetected: false,
  };
}

function getUrlDetails(rawUrl) {
  const parsed = parseUrl(rawUrl);
  const host = (parsed && parsed.hostname) || "N/A";
  const path = (parsed && parsed.pathname) || "/";
  const query = (parsed && parsed.search) || "";
  const isTrusted = isDomainTrusted(host);
  const score = isTrusted
    ? 15
    : getUrlSuspicionScore(rawUrl, host, path, query);
  return {
    domain: host,
    path,
    query: query || "—",
    vtVendors: "—",
    talosReputation: "—",
    note: isTrusted
      ? "Domeniu de încredere"
      : score >= 60
        ? "URL potențial malitios - verifică sursele OSINT"
        : "No verdict - URL-ul nu a fost raportat pe sursele OSINT",
    score,
    isDetected: !isTrusted && score >= 60,
  };
}

function getHashDetails(hash) {
  const types = { 32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512" };
  const notes = {
    32: "MD5 hash - verifică reputația pe VirusTotal",
    40: "SHA1 hash - deprecated dar încă folosit pe VT",
    64: "SHA256 hash - standard actual pentru file integrity",
    128: "SHA512 hash - hash puternic pentru fișiere mari",
  };
  const cached = apiCache[hash];
  if (cached && cached.vt && cached.vt.data && cached.vt.data.attributes) {
    const stats = cached.vt.data.attributes.last_analysis_stats || {};
    const mal = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    return {
      type: types[hash.length] || "Unknown",
      note:
        mal > 0
          ? `⚠ ${mal}/${total} VT vendors semnalează malware`
          : "✓ Curat pe VirusTotal",
      score: Math.min(100, mal * 10),
      isDetected: mal > 0,
    };
  }
  return {
    type: types[hash.length] || "Unknown",
    note:
      notes[hash.length] ||
      "Format necunoscut - ar putea fi SSDEEP, CTH, etc. No verdict.",
    score: types[hash.length] ? 50 : 35,
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
function getUrlSuspicionScore(rawUrl, host, path, query) {
  let score = 40;
  if (host) {
    const tld = host.split(".").pop();
    if (suspiciousTlds.includes(tld)) score += 20;
    if (suspiciousKeywords.some((w) => host.includes(w))) score += 15;
  }
  if (
    suspiciousKeywords.some((w) =>
      `${host}${path}${query}`.toLowerCase().includes(w),
    )
  )
    score += 20;
  if (path.length > 40) score += 10;
  return Math.min(score, 100);
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
    throw new Error("VT rate limit — așteaptă și reîncearcă");
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
      'Adaugă cheile API și apasă "Salvează cheile" pentru a activa analiza.';
  else if (!hasIOCs)
    analysisNote.textContent = "Încarcă fișiere pentru a activa analiza.";
  else
    analysisNote.textContent = 'Apasă "Start Analysis" pentru a interoga APIs.';
}

// ── Start analysis ─────────────────────────────────────────────
async function startAnalysis() {
  if (analysisRunning) return;
  const { vt, abuse } = getKeys();
  if (!vt && !abuse) {
    analysisNote.textContent = "Adaugă cel puțin o cheie API.";
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
      .filter((v) => !isDomainTrusted(v) && !apiCache[v])
      .map((v) => ({ value: v, type: "domain" })),
    ...currentHashes
      .filter((v) => !apiCache[v])
      .map((v) => ({ value: v, type: "hash" })),
  ];

  if (!iocs.length) {
    analysisNote.textContent = "Toate IOC-urile sunt deja analizate.";
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
      analysisNote.textContent = `Se analizează ${done} / ${iocs.length} IOC-uri…`;
      renderAll(currentIps, currentUrls, currentDomains, currentHashes);
    });
  }
  LOG.summary(summary);
  finishAnalysis(!analysisAborted);
}

function stopAnalysis() {
  analysisAborted = true;
  apiQueue.length = 0;
  analysisNote.textContent = "Analiză oprită de utilizator.";
  finishAnalysis(false);
}

function finishAnalysis(completed = true) {
  analysisRunning = false;
  startAnalysisBtn.disabled = false;
  stopAnalysisBtn.disabled = true;
  if (completed) analysisNote.textContent = "✓ Analiză completă.";
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
            <div><div class="result-label">Category</div><div class="result-value">${item.category}</div></div>
            <div><div class="result-label">VirusTotal Vendors</div><div class="result-value">${item.vtVendors}${item.vtVendors !== "—" ? " vendors semnalează" : ""}</div></div>
            <div><div class="result-label">AbuseIPDB Confidence</div><div class="result-value">${item.abuseConfidence}</div></div>
            <div><div class="result-label">Talos Reputation</div><div class="result-value">${item.talosReputation}</div></div>
            <div><div class="result-label">Analysis</div><div class="result-value">${item.note}</div></div>
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
            <div><div class="result-label">URL</div><div class="result-value"><a href="${item.url}" target="_blank" rel="noreferrer">${item.url}</a></div></div>
            <div><div class="result-label">Domain</div><div class="result-value">${item.domain}</div></div>
            <div><div class="result-label">Path</div><div class="result-value">${item.path || "/"}</div></div>
            <div><div class="result-label">Query</div><div class="result-value">${item.query || "—"}</div></div>
            <div><div class="result-label">VirusTotal Vendors</div><div class="result-value">—</div></div>
            <div><div class="result-label">Talos Reputation</div><div class="result-value">—</div></div>
            <div><div class="result-label">Analysis</div><div class="result-value">${item.note}</div></div>
            <div><div class="result-label">Score</div><div>${createTag(item.score, false)}</div></div>
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
            <div><div class="result-label">VirusTotal Vendors</div><div class="result-value">${item.vtVendors}${item.vtVendors !== "—" ? " vendors semnalează" : ""}</div></div>
            <div><div class="result-label">Talos Reputation</div><div class="result-value">${item.talosReputation}</div></div>
            <div><div class="result-label">Analysis</div><div class="result-value">${item.note}</div></div>
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
            <div><div class="result-label">Analysis</div><div class="result-value">${item.note}</div></div>
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
  if (!analyzed) return `<span class="tag tag-pending">NEANALIZ</span>`;
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

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".osint-open-all");
  if (!btn) return;
  const cat = btn.dataset.category,
    val = decodeURIComponent(btn.dataset.value);
  (osintSources[cat] || []).forEach((src) =>
    window.open(src.url(val), "_blank"),
  );
});

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
      "<p>Nu s-au încărcat fișiere.</p>";
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
