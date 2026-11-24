# ՎԱՀԱՆ — connector backend

Կենտրոնացված, օնլայն, **առանց install** շերտ, որ հարթակի բոլոր մոդուլները կապում է իրական անվճար անվտանգային աղբյուրների հետ։ Աշխատում է Cloudflare Worker-ի վրա (անվճ. tier, ամբողջը բրաուզերից)։

```
            ┌────────────────────────────────────────────┐
  Բրաուզեր  │   ՎԱՀԱՆ UI  (Cloudflare Pages — static)      │
  (դու)  ─► │   կանչում է միայն քո backend-ին (1 origin)    │
            └───────────────┬────────────────────────────┘
                            │  HTTPS + X-API-Key
                            ▼
            ┌────────────────────────────────────────────┐
            │   VAHAN connector  (Cloudflare Worker)       │
            │   CORS · gateway key · cache · role gate     │
            └───┬───────┬────────┬────────┬────────┬───────┘
                ▼       ▼        ▼        ▼        ▼
            ipwho.is  Shodan   Shodan   CISA     FIRST    abuse.ch
                      InternetDB CVEDB   KEV      EPSS     ThreatFox
                                 /NVD
```

Ինչու՞ backend. claude.ai-ի նախատիպ-էջն ու ցանկացած «մաքուր» frontend sandbox արգելափակում են ուղիղ արտաքին կանչերը (CORS/CSP)։ Backend-ը դրանք կենտրոնացնում է մեկ կետում, թաքցնում բանալիները, քեշավորում ու կիրառում պաշտպանական շերտ։

## Աղբյուրները (բոլորը անվճար)

| Աղբյուր | Ինչի համար | Endpoint | Բանալի |
|---|---|---|---|
| ipwho.is | IP → երկիր, ASN, ISP | `ipwho.is/{ip}` | Ոչ |
| Shodan InternetDB | բաց պորտեր, vulns, tags | `internetdb.shodan.io/{ip}` | Ոչ |
| Shodan CVEDB | CVE + CVSS + EPSS + KEV մեկ կանչով | `cvedb.shodan.io/cve/{id}` | Ոչ |
| NVD CVE API 2.0 | կանոնական CVE/CVSS (fallback) | `services.nvd.nist.gov/rest/json/cves/2.0` | Ընտր. (free) |
| CISA KEV | ակտիվ շահագործվող խոցելիություններ | `cisa.gov/.../known_exploited_vulnerabilities.json` | Ոչ |
| FIRST EPSS | շահագործման հավանականություն (30 օր) | `api.first.org/data/v1/epss` | Ոչ |
| abuse.ch ThreatFox | IP/domain/hash IoC | `threatfox-api.abuse.ch/api/v1/` | Պահանջ. (free) |
| abuse.ch URLhaus | վնասաբեր URL-ներ | `urlhaus-api.abuse.ch/v1/` | Պահանջ. (free) |

> abuse.ch-ը 2025-ից պահանջում է անվճ. Auth-Key։ Առանց դրա մնացած բոլոր աղբյուրները աշխատում են out-of-the-box։

### Հետախուզական connector-ներ (v0.5)

| Endpoint | Աղբյուր | Ինչի համար | Բանալի |
|---|---|---|---|
| `GET /asn?q=AS13335` կամ `?q=1.1.1.1` | RIPEstat | օպերատոր, holder, prefixes, announced | Ոչ |
| `GET /domain?name=example.com` | crt.sh + dns.google + rdap.org | ենթադոմեններ, DNS(A), registrar | Ոչ |
| `GET /breach?email=a@b.com` | HaveIBeenPwned | breach exposure | Պահանջ. `HIBP_API_KEY` |

> **Traceroute**-ը բրաուզերից/Worker-ից ICMP չի կարող անել։ UI-ի երթուղին նմանակված է backbone-օպերատորներով, իսկ deploy-ում ամեն hop-ի geo-ն քաշվում է `/ip`-ից։ Իրական ցանցային trace-ի համար պետք է հանգույց-ագենտ կամ looking-glass / RIPE Atlas։
>
> **Շրջանակ.** OSINT-ը պաշտպանական է՝ քո սեփական/լիազորված ակտիվների exposure-ի համար (breach, cert-transparency, DNS/RDAP), ոչ՝ մասնավոր անձանց հետևման։

## Ամենաարագը՝ գործարկել ԼՈԿԱԼ, առանց backend-ի (ուղիղ ռեժիմ)

`index.html`-ը **ունի ուղիղ ռեժիմ**. երբ բացում ես քո համակարգում (ոչ claude.ai-ի sandbox-ում), բրաուզերն ինքն ուղիղ կանչում է CORS-բաց անվճար աղբյուրները ու անցնում **LIVE**՝ առանց որևէ backend/account.

Քայլեր.
1. Ներբեռնիր `index.html`-ը։
2. Բաց արա այն բրաուզերով (double-click, կամ ավելի կայուն՝ քո պանակում գործարկիր `python3 -m http.server 8000` → բացիր `http://localhost:8000`)։
3. Մտիր (PIN → TOTP → դեմք — հիմա տեսախցիկն աշխատում է, քանի որ sandbox չէ)։
4. Վերևում կհայտնվի «Ուղիղ ռեժիմ · LIVE»։ Աշխատում են իրական տվյալներով՝ **IP հետախուզ., Օպերատորներ/ASN, Երկրի դոսյե, OSINT (domain/username), AI որոնում, Խոցելիության EPSS/CVE**։

Ուղիղ ռեժիմում աշխատող աղբյուրներ (CORS-բաց). ipwho.is, Shodan InternetDB, Shodan CVEDB, FIRST EPSS, RIPEstat, GitHub, dns.google, RDAP։
Backend է պետք միայն սրանց համար (CORS փակ / բանալի). abuse.ch IoC, HIBP breach, CISA KEV, NVD։ Դրանց համար՝ ստորև deploy-ը։

## Deploy — ամբողջը բրաուզերից (առանց install)

1. Մտիր **dash.cloudflare.com** → Workers & Pages → **Create → Worker**։
2. Անուն տուր (օր. `vahan-connector`) → **Deploy**, հետո **Edit code**։
3. Ջնջիր կաղապարը, փակցրու `worker.js`-ի ամբողջ պարունակությունը → **Deploy**։
4. **Settings → Variables and Secrets**, ավելացրու (բոլորը ընտրովի).
   - `VAHAN_API_KEY` — ցանկացած երկար պատահական տող (frontend↔backend պաշտպանություն)
   - `ABUSECH_AUTH_KEY` — վերցրու անվճ. **auth.abuse.ch**-ից (IoC feed-ի համար)
   - `NVD_API_KEY` — անվճ. **nvd.nist.gov/developers/request-an-api-key**
   - `ALLOW_ORIGIN` — prod-ում դրա քո UI դոմենը (օր. `https://vahan.pages.dev`)
5. Քո backend-ը հիմա այստեղ է՝ `https://vahan-connector.<քո-ենթատիրույթ>.workers.dev`
6. ՎԱՀԱՆ UI-ում՝ **Աղբյուրներ** բաժին → փակցրու այդ URL-ը «Backend URL» դաշտում → **Ստուգել**։

Ստուգիր կապը արագ (բրաուզերում բացիր).
```
https://vahan-connector.<ենթ>.workers.dev/health
https://vahan-connector.<ենթ>.workers.dev/ip?ip=185.220.101.1
https://vahan-connector.<ենթ>.workers.dev/cve?id=CVE-2024-3400
https://vahan-connector.<ենթ>.workers.dev/kev
```

### UI-ն hosting անելու (նույն պատ՝ օնլայն, առանց install)
Cloudflare Pages → Create → Upload `index.html`-ը → ստանում ես `https://vahan.pages.dev`։ Քանի որ UI-ն ու Worker-ը նույն հարթակում են, կարող ես նաև backend-ը կապել Pages-ին որպես `/api/*` route՝ մեկ origin, զրո CORS։

## Պաշտպանական մակարդակներ

1. **Gateway բանալի** — `VAHAN_API_KEY` env. ամեն հարցում պահանջում է `X-API-Key`։
2. **Դերեր (RBAC)** — UI-ում՝ Դիտող / Վերլուծաբան / Ադմին / SOC-ղեկավար. գործողությունները փակվում են ըստ դերի, ամեն քայլ՝ audit log-ում։
3. **Պաշտպանության աստիճան (L1–L5)** — ավտոմատ սրվում է ըստ ակտիվ սպառնալիքների ծավալի (ձեռքով override-ով)։
4. **SSO / MFA** — prod-ում Worker-ի դիմաց դրեք **Cloudflare Access** (Zero Trust) կամ **Keycloak**՝ ձեր ինքնության պրովայդերով։
5. **Rate limiting + cache** — Worker-ը քեշավորում է upstream-ները, իջեցնում ծանրաբեռնվածությունը։

## Ճանապարհային քարտեզ (հաջորդ շերտ)
- Պատմության պահում՝ Cloudflare **D1/KV** (անվճ.)՝ տրենդերի ու հաշվետվությունների համար
- Ավտոմատ sync՝ Cron Trigger-ով (KEV/EPSS/IoC օրական)
- Webhook-ներ ու SOAR playbook-ներ (Shuffle) ալերտի պահին
- IP→երկիր ամբողջական offline շտեմարան՝ MaxMind GeoLite2 + RIR delegated stats
