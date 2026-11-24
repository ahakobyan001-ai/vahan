/**
 * ՎԱՀԱՆ — կենտրոնացված connector backend (Cloudflare Worker)
 * ---------------------------------------------------------------
 * Մեկ կետից միացնում է բոլոր անվճար օնլայն անվտանգային աղբյուրները։
 * Deploy՝ ամբողջությամբ բրաուզերից (Cloudflare dashboard), առանց install։
 *
 * Endpoint-ներ (բոլորը JSON, CORS-ով բաց frontend-ի համար).
 *   GET  /health                 — կենդանության ստուգում
 *   GET  /geo?ip=1.2.3.4          — geo + ASN (ipwho.is)
 *   GET  /ip?ip=1.2.3.4           — geo + attack-surface + ռիսկ (ipwho.is + Shodan InternetDB)
 *   GET  /cve?id=CVE-2024-3400    — CVE + CVSS + EPSS + KEV (Shodan CVEDB → NVD fallback)
 *   GET  /epss?cve=CVE-...        — EPSS score (FIRST)
 *   GET  /kev                     — CISA KEV ամփոփում (cached)
 *   GET  /iocs?days=1             — վերջին IoC-ները (abuse.ch ThreatFox — պահանջում է ABUSECH_AUTH_KEY)
 *
 * Պաշտպանական շերտ (edit-level).
 *   - Եթե դրված է VAHAN_API_KEY env, ամեն հարցում պահանջում է `X-API-Key` վերնագիր։
 *   - Դերերը (roles) կարող են կապվել բանալիների հետ VAHAN_ROLES env-ով (JSON)։
 *   - Լրացուցիչ՝ դրեք Cloudflare Access հարթակի դիմաց SSO/MFA-ի համար։
 *
 * Env (Settings → Variables).
 *   VAHAN_API_KEY      (ընտրովի) — gateway բանալի frontend↔backend
 *   ABUSECH_AUTH_KEY   (ընտրովի) — anvчар abuse.ch Auth-Key (IoC feed-ի համար)
 *   NVD_API_KEY        (ընտրովի) — անվճ. NVD բանալի (rate limit 5→50 / 30վրկ)
 *   ALLOW_ORIGIN       (ընտրովի) — CORS origin, default "*" (prod-ում դրեք ձեր Pages դոմենը)
 */

const UA = "VAHAN-SOC/0.3 (+https://vahan.local)";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = env.ALLOW_ORIGIN || "*";
    const cors = {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,X-API-Key",
      "Access-Control-Max-Age": "86400",
    };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const json = (obj, status = 200, extra = {}) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8", ...cors, ...extra },
      });

    // --- Gateway defense: optional API key ---
    if (env.VAHAN_API_KEY) {
      const supplied = request.headers.get("X-API-Key") || url.searchParams.get("key");
      if (supplied !== env.VAHAN_API_KEY) {
        return json({ error: "unauthorized", hint: "X-API-Key վերնագիրը սխալ է կամ բացակայում է" }, 401);
      }
    }

    const path = url.pathname.replace(/\/+$/, "") || "/";
    try {
      if (path === "/" || path === "/health")
        return json({ ok: true, service: "VAHAN connector", ts: Date.now(),
          connectors: ["geo", "ip", "cve", "epss", "kev", "iocs", "asn", "domain", "breach", "country", "username"],
          iocs_enabled: !!env.ABUSECH_AUTH_KEY, breach_enabled: !!env.HIBP_API_KEY });

      if (path === "/geo") return json(await geo(url.searchParams.get("ip")));
      if (path === "/ip")  return json(await ipIntel(url.searchParams.get("ip")));
      if (path === "/cve") return json(await cve(url.searchParams.get("id"), env));
      if (path === "/epss") return json(await epss(url.searchParams.get("cve")));
      if (path === "/kev") return json(await kev(ctx));
      if (path === "/iocs") return json(await iocs(url.searchParams.get("days") || "1", env));
      if (path === "/asn") return json(await asn(url.searchParams.get("q")));
      if (path === "/domain") return json(await domain(url.searchParams.get("name")));
      if (path === "/breach") return json(await breach(url.searchParams.get("email"), env));
      if (path === "/country") return json(await country(url.searchParams.get("cc")));
      if (path === "/username") return json(await username(url.searchParams.get("u")));

      return json({ error: "not_found", path }, 404);
    } catch (e) {
      return json({ error: "connector_error", message: String(e && e.message || e) }, 502);
    }
  },
};

/* ------------------------- helpers ------------------------- */
function isIP(ip) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip || ""); }
async function getJSON(u, opts = {}) {
  const r = await fetch(u, { ...opts, headers: { "User-Agent": UA, "Accept": "application/json", ...(opts.headers || {}) }, cf: { cacheTtl: 300, cacheEverything: true } });
  if (!r.ok) throw new Error(`upstream ${r.status} @ ${new URL(u).host}`);
  return r.json();
}

/* ------------------------- GEO (ipwho.is) ------------------------- */
async function geo(ip) {
  if (!isIP(ip)) throw new Error("ip param required");
  const d = await getJSON(`https://ipwho.is/${ip}`);
  if (d.success === false) throw new Error(d.message || "geo lookup failed");
  return {
    ip, country: d.country, country_code: d.country_code, flag: d.flag && d.flag.emoji,
    city: d.city, region: d.region, lat: d.latitude, lon: d.longitude,
    asn: d.connection && d.connection.asn ? "AS" + d.connection.asn : null,
    isp: d.connection && (d.connection.isp || d.connection.org),
    source: "ipwho.is",
  };
}

/* ------------------------- IP INTEL (geo + Shodan InternetDB) ------------------------- */
async function ipIntel(ip) {
  if (!isIP(ip)) throw new Error("ip param required");
  const [g, surface] = await Promise.allSettled([
    geo(ip),
    getJSON(`https://internetdb.shodan.io/${ip}`),
  ]);
  const geoD = g.status === "fulfilled" ? g.value : { ip };
  const sd = surface.status === "fulfilled" ? surface.value : { ports: [], vulns: [], tags: [], hostnames: [], cpes: [] };
  // simple risk heuristic from attack surface
  let risk = 0;
  risk += Math.min((sd.vulns || []).length * 18, 60);
  risk += Math.min((sd.ports || []).length * 3, 20);
  const badTags = (sd.tags || []).filter(t => /scanner|malware|compromised|honeypot|tor|proxy|vpn/i.test(t));
  risk += Math.min(badTags.length * 12, 30);
  risk = Math.min(risk, 100);
  return {
    ...geoD,
    ports: sd.ports || [], vulns: sd.vulns || [], tags: sd.tags || [],
    hostnames: sd.hostnames || [], cpes: sd.cpes || [],
    risk, classification: risk >= 70 ? "malicious" : risk >= 35 ? "suspicious" : "benign",
    sources: ["ipwho.is", "Shodan InternetDB"],
  };
}

/* ------------------------- CVE (Shodan CVEDB → NVD fallback) ------------------------- */
async function cve(id, env) {
  if (!/^CVE-\d{4}-\d{4,}$/i.test(id || "")) throw new Error("valid CVE id required");
  id = id.toUpperCase();
  try {
    const d = await getJSON(`https://cvedb.shodan.io/cve/${id}`);
    return {
      id: d.cve_id || id, summary: d.summary,
      cvss: d.cvss_v3 || d.cvss, epss: d.epss, epss_percentile: d.ranking_epss,
      kev: !!d.kev, published: d.published_time, references: (d.references || []).slice(0, 5),
      source: "Shodan CVEDB",
    };
  } catch (e) {
    // fallback: NVD + EPSS + KEV
    const headers = env.NVD_API_KEY ? { apiKey: env.NVD_API_KEY } : {};
    const nvd = await getJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { headers });
    const v = nvd.vulnerabilities && nvd.vulnerabilities[0] && nvd.vulnerabilities[0].cve;
    const metric = v && v.metrics && (v.metrics.cvssMetricV31 || v.metrics.cvssMetricV30 || []);
    const cvss = metric && metric[0] && metric[0].cvssData && metric[0].cvssData.baseScore;
    const [ep, kv] = await Promise.allSettled([epss(id), kev()]);
    return {
      id, summary: v && v.descriptions && v.descriptions.find(d => d.lang === "en")?.value,
      cvss, epss: ep.status === "fulfilled" ? ep.value.epss : null,
      kev: kv.status === "fulfilled" ? kv.value.ids.includes(id) : null,
      source: "NVD + FIRST EPSS + CISA KEV",
    };
  }
}

/* ------------------------- EPSS (FIRST) ------------------------- */
async function epss(cveId) {
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId || "")) throw new Error("valid CVE id required");
  const d = await getJSON(`https://api.first.org/data/v1/epss?cve=${cveId.toUpperCase()}`);
  const row = d.data && d.data[0];
  return { cve: cveId.toUpperCase(), epss: row ? +row.epss : null, percentile: row ? +row.percentile : null, date: row && row.date, source: "FIRST EPSS" };
}

/* ------------------------- CISA KEV (cached) ------------------------- */
let _kevCache = null, _kevAt = 0;
async function kev(ctx) {
  const now = Date.now();
  if (_kevCache && now - _kevAt < 6 * 3600 * 1000) return _kevCache;
  const d = await getJSON("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
  const ids = (d.vulnerabilities || []).map(v => v.cveID);
  const recent = (d.vulnerabilities || []).slice(-25).reverse().map(v => ({
    id: v.cveID, vendor: v.vendorProject, product: v.product, added: v.dateAdded,
    ransomware: v.knownRansomwareCampaignUse, due: v.dueDate,
  }));
  _kevCache = { count: d.count || ids.length, catalog_version: d.catalogVersion, ids, recent, source: "CISA KEV" };
  _kevAt = now;
  return _kevCache;
}

/* ------------------------- IoC (abuse.ch ThreatFox — optional key) ------------------------- */
async function iocs(days, env) {
  if (!env.ABUSECH_AUTH_KEY)
    return { enabled: false, data: [], note: "Ավելացրեք ABUSECH_AUTH_KEY env-ը (անվճ. auth.abuse.ch) IoC feed-ը միացնելու համար" };
  const r = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Auth-Key": env.ABUSECH_AUTH_KEY, "Content-Type": "application/json", "User-Agent": UA },
    body: JSON.stringify({ query: "get_iocs", days: +days || 1 }),
  });
  const d = await r.json();
  const data = (d.data || []).slice(0, 50).map(x => ({
    k: x.ioc_type, v: x.ioc, malware: x.malware_printable, conf: x.confidence_level,
    first_seen: x.first_seen, src: "abuse.ch ThreatFox", tags: x.tags || [],
  }));
  return { enabled: true, status: d.query_status, count: data.length, data, source: "abuse.ch ThreatFox" };
}

/* ------------------------- ASN / operators (RIPEstat) ------------------------- */
async function asn(q) {
  if (!q) throw new Error("q (ASN or IP) required");
  let num;
  if (/^as\d+$/i.test(q)) num = q.replace(/^as/i, "");
  else if (isIP(q)) {
    const ni = await getJSON(`https://stat.ripe.net/data/network-info/data.json?resource=${q}`);
    num = ni.data && ni.data.asns && ni.data.asns[0];
    if (!num) throw new Error("no ASN for IP");
  } else throw new Error("q must be ASN or IP");
  const [ov, pfx] = await Promise.allSettled([
    getJSON(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${num}`),
    getJSON(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${num}`),
  ]);
  const o = ov.status === "fulfilled" ? ov.value.data : {};
  const p = pfx.status === "fulfilled" ? pfx.value.data : {};
  return { asn: "AS" + num, holder: o.holder, announced: o.announced,
    prefixes: (p.prefixes || []).length || null, country: (o.holder || "").split(",").pop().trim(), source: "RIPEstat" };
}

/* ------------------------- Domain footprint (crt.sh + DoH + RDAP) ------------------------- */
async function domain(name) {
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(name || "")) throw new Error("valid domain required");
  const [crt, a, rdap] = await Promise.allSettled([
    getJSON(`https://crt.sh/?q=%25.${name}&output=json`),
    getJSON(`https://dns.google/resolve?name=${name}&type=A`),
    getJSON(`https://rdap.org/domain/${name}`),
  ]);
  let subs = [];
  if (crt.status === "fulfilled") {
    const set = new Set();
    (crt.value || []).forEach(r => String(r.name_value || "").split("\n").forEach(s => { s = s.trim(); if (s && !s.startsWith("*") && s.endsWith(name)) set.add(s); }));
    subs = [...set].slice(0, 40);
  }
  const aRec = a.status === "fulfilled" && a.value.Answer ? a.value.Answer.filter(x => x.type === 1).map(x => x.data) : [];
  let registrar = null;
  if (rdap.status === "fulfilled") {
    const ents = rdap.value.entities || [];
    for (const e of ents) { const fn = e.vcardArray && e.vcardArray[1] && e.vcardArray[1].find(f => f[0] === "fn"); if (fn) { registrar = fn[3]; break; } }
  }
  return { domain: name, subdomains: subs, dns: { A: aRec.join(", ") || "—" }, registrar: registrar || "—", sources: ["crt.sh", "dns.google", "rdap.org"] };
}

/* ------------------------- Breach exposure (HIBP — optional key) ------------------------- */
async function breach(email, env) {
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email || "")) throw new Error("valid email required");
  if (!env.HIBP_API_KEY) return { enabled: false, note: "Ավելացրեք HIBP_API_KEY env (haveibeenpwned.com) breach-ստուգման համար" };
  const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
    { headers: { "hibp-api-key": env.HIBP_API_KEY, "User-Agent": UA } });
  if (r.status === 404) return { email, count: 0, breaches: [], source: "HIBP" };
  if (!r.ok) throw new Error("HIBP " + r.status);
  const d = await r.json();
  return { email, count: d.length, breaches: d.map(b => ({ n: b.Name, y: (b.BreachDate || "").slice(0, 4), c: b.PwnCount, d: b.DataClasses })), source: "HIBP" };
}

/* ------------------------- Country dossier (RIPEstat) ------------------------- */
async function country(cc) {
  if (!/^[a-z]{2}$/i.test(cc || "")) throw new Error("2-letter country code required");
  cc = cc.toLowerCase();
  const [st, as] = await Promise.allSettled([
    getJSON(`https://stat.ripe.net/data/country-resource-stats/data.json?resource=${cc}&resolution=1y`),
    getJSON(`https://stat.ripe.net/data/country-asns/data.json?resource=${cc}&lod=1`),
  ]);
  let prefixes = null;
  if (st.status === "fulfilled") { const s = st.value.data && st.value.data.stats; const last = s && s[s.length - 1]; if (last) prefixes = last.v4_prefixes; }
  let asnCount = null, topAsns = [];
  if (as.status === "fulfilled") {
    const co = as.value.data && as.value.data.countries && as.value.data.countries[0];
    if (co) { const routed = String(co.routed || "").replace(/[\[\]\s]/g, "").split(",").filter(Boolean); asnCount = routed.length; topAsns = routed.slice(0, 6).map(a => "AS" + a); }
  }
  return { cc: cc.toUpperCase(), prefixes, asns: asnCount, topAsns, source: "RIPEstat" };
}

/* ------------------------- Username presence (GitHub reliable) ------------------------- */
async function username(u) {
  if (!/^[a-z0-9_.-]{1,40}$/i.test(u || "")) throw new Error("valid username required");
  const platforms = {};
  try {
    const gh = await fetch(`https://api.github.com/users/${u}`, { headers: { "User-Agent": UA, "Accept": "application/vnd.github+json" } });
    platforms["GitHub"] = gh.status === 200;
  } catch (e) { platforms["GitHub"] = null; }
  return { username: u, platforms,
    note: "Հուսալի՝ GitHub API (200/404)։ Մնացած հարթակները client-side best-effort են CORS-ի պատճառով", source: "VAHAN" };
}
