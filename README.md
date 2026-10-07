<p align="center">
  <img src="assets/sentinelforge-logo.svg" alt="SentinelForge Logo" width="900"/>
</p>

<p align="center">
  <strong>Forge Your Defense • Stay Vigilant</strong>
</p>

<p align="center">
  <img src="https://github.com/lloredia/SentinelForge/actions/workflows/ci.yml/badge.svg?style=plastic" alt="CI" />
  <img src="https://img.shields.io/github/last-commit/lloredia/SentinelForge?style=plastic" alt="last commit" />
  <img src="https://img.shields.io/github/languages/top/lloredia/SentinelForge?style=plastic" alt="top language" />
  <img src="https://img.shields.io/github/languages/count/lloredia/SentinelForge?style=plastic" alt="language count" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=plastic" alt="MIT license" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-black?logo=rust&logoColor=white&style=plastic" alt="Rust" />
  <img src="https://img.shields.io/badge/Axum-black?logo=rust&logoColor=white&style=plastic" alt="Axum" />
  <img src="https://img.shields.io/badge/React-20232A?logo=react&logoColor=61DAFB&style=plastic" alt="React" />
  <img src="https://img.shields.io/badge/PostgreSQL-316192?logo=postgresql&logoColor=white&style=plastic" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white&style=plastic" alt="Docker" />
</p>

---

Threat intelligence service for collecting, enriching, and searching indicators of compromise. The API is Rust (Axum, sqlx, PostgreSQL). The dashboard is React (Vite). Collectors cover AlienVault OTX, Emerging Threats, and HoneyTrap. Enrichment covers VirusTotal, AbuseIPDB, GeoIP, DNS, and WHOIS.

![SentinelForge Dashboard](assets/screenshot.png)

## Features

| Feature | What it does |
|---------|----------------|
| IOC types | IP, CIDR, domain, URL, MD5/SHA1/SHA256, email, CVE |
| Search | Paginated `ILIKE` filters (type, severity, confidence, score, tags, source). Wildcards in the query are escaped. |
| Enrichment | GeoIP, DNS, WHOIS, VirusTotal, AbuseIPDB. Missing GeoIP files and missing vendor keys are skipped. |
| Dashboard | Cyberpunk React UI: stats, filters, IOC table, detail panel, submit form |
| API auth | Write routes require an API key. Read auth is optional. |
| Controls | CORS allowlist, body size limit, per-IP rate limit, request timeout |

Redis is started by Compose for later use. The API does not talk to it. Feed collectors are implemented as libraries. `POST /api/v1/feeds/refresh` is authenticated and currently returns a stub; nothing schedules collection at startup.

## Architecture

```mermaid
flowchart TB
    subgraph Clients
        UI[React Dashboard<br/>127.0.0.1:3000]
        API_CLIENT[API Clients<br/>curl/scripts]
        HONEYPOT[HoneyTrap<br/>collector]
    end

    subgraph SentinelForge Backend
        API[Axum REST API<br/>127.0.0.1:8080]

        subgraph Enrichment Engine
            GEOIP[GeoIP<br/>MaxMind]
            DNS[DNS<br/>Resolver]
            WHOIS[WHOIS<br/>fixed TLD servers]
            VT[VirusTotal<br/>API]
            ABUSE[AbuseIPDB<br/>API]
        end

        subgraph Storage Layer
            REPO[ThreatIntel<br/>Repository]
            PG[(PostgreSQL<br/>Database)]
        end
    end

    UI -->|HTTP + X-API-Key| API
    API_CLIENT -->|HTTP + X-API-Key| API
    HONEYPOT -.->|not scheduled| API

    API --> REPO
    REPO --> PG

    API --> GEOIP
    API --> DNS
    API --> WHOIS
    API --> VT
    API --> ABUSE

    style UI fill:#00ffaa,stroke:#000,color:#000
    style API fill:#ff6b00,stroke:#000,color:#fff
    style PG fill:#316192,stroke:#000,color:#fff
    style GEOIP fill:#ffd000,stroke:#000,color:#000
    style DNS fill:#ffd000,stroke:#000,color:#000
    style WHOIS fill:#ffd000,stroke:#000,color:#000
    style VT fill:#ffd000,stroke:#000,color:#000
    style ABUSE fill:#ffd000,stroke:#000,color:#000
```

## Data flow

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant D as Detector
    participant E as Enrichment
    participant DB as PostgreSQL

    C->>A: POST /api/v1/indicators<br/>X-API-Key + {"value": "8.8.8.8"}
    A->>D: Detect and validate IOC
    D-->>A: Type: IP
    A->>DB: Upsert indicator
    DB-->>A: Indicator created
    A->>E: Enrich (GeoIP, DNS, optional vendors)
    E-->>DB: Store enrichment rows
    A-->>C: 201 Created
```

Enrichment runs in the request that asks for it (`POST /api/v1/indicators/:id/enrich`), not as a background job after create.

## Quick start

Requirements: Docker with Compose, or Rust 1.99 (see `rust-toolchain.toml`), PostgreSQL 16, and Node.js 22 for a local UI build.

```bash
cp .env.example .env
```

Edit `.env`:

- Set `POSTGRES_PASSWORD` to a URL-safe value (letters, digits, `.`, `_`, `-`). Compose embeds it in `DATABASE_URL`.
- Set `API_KEYS` to at least one random key, 16 characters or longer.
- Set `VITE_API_KEY` to that same key if the dashboard should submit IOCs. The key is compiled into the browser bundle.

GeoIP databases are optional. Enrichment continues without them.

```bash
export MAXMIND_LICENSE_KEY=your-maxmind-key
./scripts/download-geoip.sh
```

Start the stack. Postgres, Redis, the API, and the UI come up. Adminer stays off unless you pass `--profile debug`. Published ports bind to `127.0.0.1` only.

```bash
docker compose up --build
```

- API: `http://127.0.0.1:8080/health`
- UI: `http://127.0.0.1:3000`
- Adminer (debug only): `docker compose --profile debug up adminer` then `http://127.0.0.1:8081`

### Without Docker

```bash
# Postgres already running, .env filled in
set -a && source .env && set +a
cargo run -- --migrate
```

The process listens on `127.0.0.1:8080` unless `HOST` is set. The container image sets `HOST=0.0.0.0` so Compose can publish it.

```bash
cd sentinelforge-ui
npm ci
npm start
```

Vite serves the dashboard on port 3000.

## API examples

Replace the key with the value from `API_KEYS`. Reads work without a key when `REQUIRE_READ_AUTH=false` (the default). Writes always require a key, sent as `X-API-Key` or `Authorization: Bearer`.

```bash
curl -s http://127.0.0.1:8080/health
```

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/indicators \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"value": "8.8.8.8", "severity": "low", "tags": ["dns"]}'
```

```bash
curl -s "http://127.0.0.1:8080/api/v1/indicators?search=8.8.8.8&page=1&per_page=20"
```

```bash
curl -s "http://127.0.0.1:8080/api/v1/lookup?value=8.8.8.8"
```

```bash
curl -s http://127.0.0.1:8080/api/v1/stats
```

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/indicators/bulk \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "source": "threat-feed",
    "indicators": [
      {"value": "1.2.3.4", "severity": "high"},
      {"value": "evil.example", "severity": "critical"}
    ]
  }'
```

`page` must be at least 1. `per_page` must be from 1 to 100. Bulk import accepts at most 500 indicators. Invalid IOC values return 400.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | no | Health check |
| `GET` | `/api/v1/indicators` | read | Paginated search |
| `POST` | `/api/v1/indicators` | write | Create an indicator |
| `GET` | `/api/v1/indicators/:id` | read | Indicator, enrichments, sighting count |
| `DELETE` | `/api/v1/indicators/:id` | write | Delete an indicator |
| `POST` | `/api/v1/indicators/:id/enrich` | write | Run enrichment providers |
| `POST` | `/api/v1/indicators/:id/sightings` | write | Record a sighting |
| `GET` | `/api/v1/lookup` | read | Lookup by `value` query parameter |
| `GET` | `/api/v1/stats` | read | Dashboard counters |
| `POST` | `/api/v1/indicators/bulk` | write | Bulk import |
| `GET` | `/api/v1/sources` | read | Feed sources |
| `POST` | `/api/v1/feeds/refresh` | write | Stub. Collectors are not scheduled |

| Type | Example |
|------|---------|
| IP / CIDR | `8.8.8.8`, `2001:4860:4860::8888`, `10.0.0.0/8` |
| Domain | `malicious-domain.com` |
| URL | `https://evil.example/malware.exe` (http or https, no userinfo) |
| Hash | 32, 40, or 64 hex characters |
| Email | `attacker@evil.example` |
| CVE | `CVE-2024-1234` |

| Provider | Needs a key | If it is missing |
|----------|:-----------:|------------------|
| MaxMind GeoIP | license key only to download | Lookup returns no geo fields |
| DNS | no | Disabled if system resolv.conf cannot be read |
| WHOIS | no | Queries a fixed public TLD server list. No referral chase |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Provider is not registered |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Provider is not registered |

## Security

- API keys come from `API_KEYS`. The server stores SHA-256 digests and compares them in constant time. Keys are not written to logs. Outbound errors are redacted before they are logged.
- Browser origins come from `CORS_ALLOWED_ORIGINS`. The API does not send `Access-Control-Allow-Origin: *`.
- Local default bind address is `127.0.0.1`. The container sets `HOST=0.0.0.0` and Compose publishes `127.0.0.1:8080` on the host.
- Request bodies are capped (`BODY_LIMIT_BYTES`, default 2 MiB). Each client IP is rate limited (`RATE_LIMIT_PER_SECOND`, `RATE_LIMIT_BURST`). Handlers time out at 30 seconds.
- IOC values are checked for type, length, and unsafe characters before insert.
- Outbound HTTP uses a 10 second timeout, a 5 second connect timeout, and no redirects. VirusTotal path segments are restricted to expected tokens.
- HoneyTrap's base URL is validated before use: http or https only, no credentials, and link-local or metadata addresses are always rejected. Loopback and private addresses require `HONEYTRAP_ALLOW_PRIVATE=true`. Public feed URLs must be HTTPS and on a host allowlist.
- WHOIS connects only to a built-in map of public TLD servers, with a short timeout and a response cap.
- GeoLite2 databases are not in git. MaxMind's GeoLite2 EULA forbids redistributing the files. Use `scripts/download-geoip.sh` with your own `MAXMIND_LICENSE_KEY`.
- Postgres, Redis, and Adminer are not published on `0.0.0.0`. Adminer is behind the Compose `debug` profile. The database password is read from `.env`.

The UI key (`VITE_API_KEY`) is visible to the browser. Treat the dashboard as an operator console on localhost, or put a reverse proxy in front of it before exposing it.

## Project layout

```
sentinelforge/
├── src/                  # API, auth, storage, enrichment, collectors
├── migrations/
├── tests/                # Postgres integration tests
├── docker/Dockerfile     # multi-stage, distroless, non-root
├── scripts/download-geoip.sh
├── sentinelforge-ui/     # Vite + React dashboard
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## Development checks

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
DATABASE_URL=postgres://sentinelforge:sentinelforge_test@127.0.0.1:5432/sentinelforge cargo test
cargo audit
cargo deny check
cd sentinelforge-ui && npm ci && npm run lint && npm test && npm run build
```

CI runs those checks, builds the API and UI images, scans them with Trivy (high and critical, ignoring unfixed OS findings), and runs gitleaks.

## Roadmap

- [x] API key authentication for writes, optional for reads
- [x] Per-IP rate limiting and request body limits
- [ ] Scheduled threat-feed ingestion (OTX, Emerging Threats, HoneyTrap)
- [ ] STIX/TAXII import and export
- [ ] Alerting (email, Slack, webhooks)
- [ ] MITRE ATT&CK mapping

## License

MIT. See [LICENSE](LICENSE).

GeoLite2 data, if you download it, stays under the [MaxMind GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) and is not part of this MIT license.

<p align="center">
  <img src="assets/sentinelforge-logo-small.png" alt="SentinelForge" width="100"/>
  <br/>
  <strong>SentinelForge</strong> - Forge Your Defense
</p>
