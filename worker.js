/* ═══════════════════════════════════════════════════════════════
   THREAT EXTRACTION — Cloudflare Worker proxy
   Routes API calls from the browser dashboard to OSINT providers.
   Each provider's API key is sent by the browser in a dedicated header
   (X-Vt-Key, X-Abuse-Key, ...). The worker forwards it to the upstream.
   Deploy with: wrangler deploy
═══════════════════════════════════════════════════════════════ */

const ALLOWED_HEADERS = [
  "Content-Type",
  "X-Vt-Key",
  "X-Abuse-Key",
  "X-Kas-Key",
  "X-Otx-Key",
  "X-Urlscan-Key",
  "X-Ipqs-Key",
  "X-Shodan-Key",
  "X-Gn-Key",
  "X-Mb-Key",
  "X-Tf-Key",
  "X-Uh-Key",
  "X-Ha-Key",
  "X-St-Key",
  "X-Tri-Key",
  "X-Cf-Key",
].join(", ");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": ALLOWED_HEADERS,
  "Access-Control-Max-Age": "86400",
};

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json", ...extra },
  });
}

function passthrough(res) {
  // Proxy upstream JSON response with CORS headers attached.
  return new Response(res.body, {
    status: res.status,
    headers: {
      ...CORS,
      "Content-Type":
        res.headers.get("Content-Type") || "application/json; charset=utf-8",
    },
  });
}

async function proxy(url, init = {}) {
  const upstream = await fetch(url, init);
  return passthrough(upstream);
}

export default {
  async fetch(request) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");
    const h = (name) => request.headers.get(name) || "";

    try {
      // ─── VirusTotal ──────────────────────────────────────────
      // /vt/ip/<ip>   /vt/domain/<domain>   /vt/url/<url>   /vt/hash/<hash>
      let m = path.match(/^\/vt\/(ip|domain|url|hash)\/(.+)$/);
      if (m) {
        const [, type, value] = m;
        const key = h("X-Vt-Key");
        if (!key) return json({ error: "Missing X-Vt-Key" }, 400);
        const route =
          type === "ip"
            ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`
            : type === "domain"
              ? `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`
              : type === "hash"
                ? `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`
                : `https://www.virustotal.com/api/v3/urls/${vtUrlId(value)}`;
        return proxy(route, { headers: { "x-apikey": key } });
      }

      // ─── AbuseIPDB ───────────────────────────────────────────
      // /abuse/<ip>
      m = path.match(/^\/abuse\/(.+)$/);
      if (m) {
        const ip = m[1];
        const key = h("X-Abuse-Key");
        if (!key) return json({ error: "Missing X-Abuse-Key" }, 400);
        const u = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
        return proxy(u, { headers: { Key: key, Accept: "application/json" } });
      }

      // ─── Kaspersky OpenTip ───────────────────────────────────
      // /kas/<ip|domain|url|hash>/<value>
      m = path.match(/^\/kas\/(ip|domain|url|hash)\/(.+)$/);
      if (m) {
        const [, type, value] = m;
        const key = h("X-Kas-Key");
        if (!key) return json({ error: "Missing X-Kas-Key" }, 400);
        const ep = { ip: "ip", domain: "domain", url: "url", hash: "file" }[type];
        const u = `https://opentip.kaspersky.com/api/v1/search/${ep}?request=${encodeURIComponent(value)}`;
        return proxy(u, { headers: { "x-api-key": key } });
      }

      // ─── AlienVault OTX ──────────────────────────────────────
      // /otx/<ip|domain|url|hash>/<value>
      m = path.match(/^\/otx\/(ip|domain|url|hash)\/(.+)$/);
      if (m) {
        const [, type, value] = m;
        const key = h("X-Otx-Key");
        if (!key) return json({ error: "Missing X-Otx-Key" }, 400);
        const seg = {
          ip: `IPv4/${encodeURIComponent(value)}/general`,
          domain: `domain/${encodeURIComponent(value)}/general`,
          url: `url/${encodeURIComponent(value)}/general`,
          hash: `file/${encodeURIComponent(value)}/general`,
        }[type];
        return proxy(`https://otx.alienvault.com/api/v1/indicators/${seg}`, {
          headers: { "X-OTX-API-KEY": key },
        });
      }

      // ─── URLScan.io ──────────────────────────────────────────
      // /urlscan/search?q=...   (key optional; higher quota with key)
      if (path === "/urlscan/search") {
        const q = url.searchParams.get("q") || "";
        if (!q) return json({ error: "Missing q" }, 400);
        const key = h("X-Urlscan-Key");
        const headers = key ? { "API-Key": key } : {};
        return proxy(
          `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}`,
          { headers },
        );
      }

      // ─── IPQualityScore ──────────────────────────────────────
      // /ipqs/<ip>
      m = path.match(/^\/ipqs\/(.+)$/);
      if (m) {
        const ip = m[1];
        const key = h("X-Ipqs-Key");
        if (!key) return json({ error: "Missing X-Ipqs-Key" }, 400);
        return proxy(
          `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(key)}/${encodeURIComponent(ip)}`,
        );
      }

      // ─── GreyNoise Community (no key required) ───────────────
      // /greynoise/<ip>
      m = path.match(/^\/greynoise\/(.+)$/);
      if (m) {
        const ip = m[1];
        const key = h("X-Gn-Key");
        const headers = { Accept: "application/json" };
        if (key) headers["key"] = key;
        return proxy(
          `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
          { headers },
        );
      }

      // ─── Shodan InternetDB (free, no key) + host (with key) ──
      // /shodan/<ip>
      m = path.match(/^\/shodan\/(.+)$/);
      if (m) {
        const ip = m[1];
        const key = h("X-Shodan-Key");
        if (key) {
          return proxy(
            `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`,
          );
        }
        return proxy(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
      }

      // ─── MalwareBazaar (abuse.ch) ────────────────────────────
      // /mb/<hash>
      m = path.match(/^\/mb\/(.+)$/);
      if (m) {
        const hash = m[1];
        const key = h("X-Mb-Key");
        const form = new FormData();
        form.append("query", "get_info");
        form.append("hash", hash);
        const headers = {};
        if (key) headers["Auth-Key"] = key;
        return proxy("https://mb-api.abuse.ch/api/v1/", {
          method: "POST",
          body: form,
          headers,
        });
      }

      // ─── ThreatFox (abuse.ch) ────────────────────────────────
      // /tf/<value>   — search by IOC value
      m = path.match(/^\/tf\/(.+)$/);
      if (m) {
        const value = decodeURIComponent(m[1]);
        const key = h("X-Tf-Key");
        const headers = { "Content-Type": "application/json" };
        if (key) headers["Auth-Key"] = key;
        return proxy("https://threatfox-api.abuse.ch/api/v1/", {
          method: "POST",
          body: JSON.stringify({ query: "search_ioc", search_term: value }),
          headers,
        });
      }

      // ─── URLhaus (abuse.ch) ──────────────────────────────────
      // /uh   (POST body)
      if (path === "/uh") {
        const body = await request.text();
        const key = h("X-Uh-Key");
        const headers = { "Content-Type": "application/x-www-form-urlencoded" };
        if (key) headers["Auth-Key"] = key;
        return proxy("https://urlhaus-api.abuse.ch/v1/url/", {
          method: "POST",
          body,
          headers,
        });
      }

      // ─── Hybrid Analysis ─────────────────────────────────────
      // /ha/hash/<hash>
      m = path.match(/^\/ha\/hash\/(.+)$/);
      if (m) {
        const hash = m[1];
        const key = h("X-Ha-Key");
        if (!key) return json({ error: "Missing X-Ha-Key" }, 400);
        const form = new URLSearchParams({ hash });
        return proxy("https://www.hybrid-analysis.com/api/v2/search/hash", {
          method: "POST",
          body: form,
          headers: {
            "api-key": key,
            "User-Agent": "Falcon Sandbox",
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
          },
        });
      }

      // ─── SecurityTrails ──────────────────────────────────────
      // /st/domain/<domain>
      m = path.match(/^\/st\/domain\/(.+)$/);
      if (m) {
        const domain = m[1];
        const key = h("X-St-Key");
        if (!key) return json({ error: "Missing X-St-Key" }, 400);
        return proxy(
          `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}`,
          { headers: { APIKEY: key, Accept: "application/json" } },
        );
      }

      // ─── Triage (tria.ge) ────────────────────────────────────
      // /tri/hash/<hash>
      m = path.match(/^\/tri\/hash\/(.+)$/);
      if (m) {
        const hash = m[1];
        const key = h("X-Tri-Key");
        if (!key) return json({ error: "Missing X-Tri-Key" }, 400);
        return proxy(
          `https://tria.ge/api/v0/search?query=${encodeURIComponent(hash)}`,
          { headers: { Authorization: `Bearer ${key}` } },
        );
      }

      // ─── Cloudflare Radar ────────────────────────────────────
      // /cf/ip/<ip>     /cf/domain/<domain>
      m = path.match(/^\/cf\/(ip|domain)\/(.+)$/);
      if (m) {
        const [, type, value] = m;
        const key = h("X-Cf-Key");
        if (!key) return json({ error: "Missing X-Cf-Key" }, 400);
        const u =
          type === "ip"
            ? `https://api.cloudflare.com/client/v4/radar/entities/asns/ip?ip=${encodeURIComponent(value)}`
            : `https://api.cloudflare.com/client/v4/radar/ranking/domain/${encodeURIComponent(value)}`;
        return proxy(u, { headers: { Authorization: `Bearer ${key}` } });
      }

      return json({ error: "Unknown route", path }, 404);
    } catch (err) {
      return json({ error: err.message || String(err) }, 500);
    }
  },
};

// ── Helpers ──────────────────────────────────────────────────────
function vtUrlId(rawUrl) {
  // VirusTotal URL ID = base64url-without-padding of the URL.
  const bytes = new TextEncoder().encode(rawUrl);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
