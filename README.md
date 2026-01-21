<p align="center">
  <img src="assets/sentinelforge-logo.png" alt="SentinelForge Logo" width="550"/>
</p>

<p align="center">
  <strong>Forge Your Defense • Stay Vigilant</strong>
</p>


<!-- Repo Stats -->
<p align="center">
  <img src="https://img.shields.io/github/last-commit/lloredia/SentinelForge?style=plastic" />
  <img src="https://img.shields.io/github/languages/top/lloredia/SentinelForge?style=plastic" />
  <img src="https://img.shields.io/github/languages/count/lloredia/SentinelForge?style=plastic" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=plastic" />
</p>
<!-- Tech Stack -->
<p align="center">
  <img src="https://img.shields.io/badge/Rust-black?logo=rust&logoColor=white&style=plastic" />
  <img src="https://img.shields.io/badge/Axum-black?logo=rust&logoColor=white&style=plastic" />
  <img src="https://img.shields.io/badge/React-20232A?logo=react&logoColor=61DAFB&style=plastic" />
  <img src="https://img.shields.io/badge/PostgreSQL-316192?logo=postgresql&logoColor=white&style=plastic" />
  <img src="https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white&style=plastic" />
  <img src="https://img.shields.io/badge/JSON-000000?logo=json&logoColor=white&style=plastic" />
  <img src="https://img.shields.io/badge/SQL-003B57?logo=databricks&logoColor=white&style=plastic" />
</p>

<!-- Language Breakdown -->
<p align="center">
  <img src="https://img.shields.io/badge/Rust-64.8-black?style=plastic&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/JavaScript-28.5-F7DF1E?style=plastic&logo=javascript&logoColor=black" />
  <img src="https://img.shields.io/badge/PL%2FpgSQL-3.7-336791?style=plastic&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/HTML-1.4-E34F26?style=plastic&logo=html5&logoColor=white" />
  <img src="https://img.shields.io/badge/Dockerfile-1.3-2496ED?style=plastic&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/CSS-0.3-1572B6?style=plastic&logo=css3&logoColor=white" />
</p>



---

A modern, high-performance **Threat Intelligence Platform** built with Rust and React. Collect, enrich, and analyze Indicators of Compromise (IOCs) with automatic type detection and real-time enrichment.

![SentinelForge Dashboard](assets/screenshot.png)

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🎯 **Multi-type IOC Support** | IPs, domains, URLs, hashes, emails, and CVEs |
| 🔍 **Auto-detection** | Automatically identifies IOC type from input |
| 🌍 **Real-time Enrichment** | GeoIP, DNS, VirusTotal, AbuseIPDB integration |
| 🖥️ **Cyberpunk Dashboard** | Beautiful React UI with terminal aesthetics |
| 🔌 **RESTful API** | Full-featured API for automation and integration |
| 🗄️ **PostgreSQL Backend** | Reliable storage with full-text search |
| 🏷️ **Tagging & Severity** | Organize and prioritize threats |
| 🚦 **TLP Support** | Traffic Light Protocol for sharing classification |

## 🏗️ Architecture

```mermaid
flowchart TB
    subgraph Clients
        UI[React Dashboard<br/>:3000]
        API_CLIENT[API Clients<br/>curl/scripts]
        HONEYPOT[HoneyTrap<br/>Honeypot]
    end

    subgraph SentinelForge Backend
        API[Axum REST API<br/>:8080]
        
        subgraph Enrichment Engine
            GEOIP[GeoIP<br/>MaxMind]
            DNS[DNS<br/>Resolver]
            VT[VirusTotal<br/>API]
            ABUSE[AbuseIPDB<br/>API]
        end
        
        subgraph Storage Layer
            REPO[ThreatIntel<br/>Repository]
            PG[(PostgreSQL<br/>Database)]
        end
    end

    subgraph External Services
        MAXMIND[MaxMind<br/>GeoLite2]
        VT_API[VirusTotal<br/>API]
        ABUSE_API[AbuseIPDB<br/>API]
    end

    UI -->|HTTP| API
    API_CLIENT -->|HTTP| API
    HONEYPOT -->|HTTP| API
    
    API --> REPO
    REPO --> PG
    
    API --> GEOIP
    API --> DNS
    API --> VT
    API --> ABUSE
    
    GEOIP -.->|mmdb| MAXMIND
    VT -.->|REST| VT_API
    ABUSE -.->|REST| ABUSE_API

    style UI fill:#00ffaa,stroke:#000,color:#000
    style API fill:#ff6b00,stroke:#000,color:#fff
    style PG fill:#316192,stroke:#000,color:#fff
    style GEOIP fill:#ffd000,stroke:#000,color:#000
    style DNS fill:#ffd000,stroke:#000,color:#000
    style VT fill:#ffd000,stroke:#000,color:#000
    style ABUSE fill:#ffd000,stroke:#000,color:#000
```

## 🔄 Data Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant D as Detector
    participant E as Enrichment
    participant DB as PostgreSQL

    C->>A: POST /api/v1/indicators<br/>{"value": "8.8.8.8"}
    A->>D: Detect IOC Type
    D-->>A: Type: IP
    A->>DB: Upsert Indicator
    DB-->>A: Indicator Created
    
    par Async Enrichment
        A->>E: Enrich (GeoIP)
        E-->>DB: Save: Country, ASN
        A->>E: Enrich (DNS)
        E-->>DB: Save: PTR Record
        A->>E: Enrich (VirusTotal)
        E-->>DB: Save: Reputation
    end
    
    A-->>C: 201 Created<br/>{indicator + id}
```

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+
- PostgreSQL 14+
- Node.js 18+ (for frontend)

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/lloredia/SentinelForge.git
cd SentinelForge

# Set up database
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/sentinelforge"
createdb sentinelforge

# Run migrations
cargo install sqlx-cli --no-default-features --features postgres
sqlx migrate run

# Build and run
cargo build --release
./target/release/sentinelforge
```

### Frontend Setup

```bash
cd sentinelforge-ui
npm install
npm start
```

The dashboard will be available at `http://localhost:3000`

### GeoIP Setup (Optional)

1. Sign up for a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2-City and GeoLite2-ASN databases
3. Place `.mmdb` files in the `data/` directory

## 📡 API Reference

### Health Check
```bash
curl http://localhost:8080/health
```

### Create Indicator
```bash
curl -X POST http://localhost:8080/api/v1/indicators \
  -H "Content-Type: application/json" \
  -d '{"value": "8.8.8.8", "severity": "low", "tags": ["dns", "google"]}'
```

### List Indicators
```bash
curl http://localhost:8080/api/v1/indicators
```

### Lookup by Value
```bash
curl "http://localhost:8080/api/v1/lookup?value=8.8.8.8"
```

### Get Statistics
```bash
curl http://localhost:8080/api/v1/stats
```

### Bulk Import
```bash
curl -X POST http://localhost:8080/api/v1/indicators/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "source": "threat-feed",
    "indicators": [
      {"value": "1.2.3.4", "severity": "high"},
      {"value": "evil.com", "severity": "critical"}
    ]
  }'
```

## 📋 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/indicators` | List indicators (paginated) |
| `POST` | `/api/v1/indicators` | Create indicator |
| `GET` | `/api/v1/indicators/:id` | Get indicator by ID |
| `DELETE` | `/api/v1/indicators/:id` | Delete indicator |
| `POST` | `/api/v1/indicators/:id/enrich` | Trigger enrichment |
| `POST` | `/api/v1/indicators/:id/sightings` | Add sighting |
| `GET` | `/api/v1/lookup` | Lookup by value |
| `GET` | `/api/v1/stats` | Dashboard statistics |
| `POST` | `/api/v1/indicators/bulk` | Bulk import |
| `GET` | `/api/v1/sources` | List feed sources |

## 🎯 IOC Types

| Type | Example | Auto-detected |
|------|---------|:-------------:|
| IP | `8.8.8.8`, `2001:4860:4860::8888` | ✅ |
| Domain | `malicious-domain.com` | ✅ |
| URL | `https://evil.com/malware.exe` | ✅ |
| Hash | MD5, SHA1, SHA256 | ✅ |
| Email | `attacker@evil.com` | ✅ |
| CVE | `CVE-2024-1234` | ✅ |

## 🔌 Enrichment Providers

| Provider | Data | API Key Required |
|----------|------|:----------------:|
| MaxMind GeoIP | Country, City, ASN, Org | Free account |
| DNS | PTR, A, MX records | ❌ |
| VirusTotal | Reputation, detections | ✅ |
| AbuseIPDB | Abuse reports, confidence | ✅ |

### Configure API Keys

```bash
export VIRUSTOTAL_API_KEY="your-api-key"
export ABUSEIPDB_API_KEY="your-api-key"
```

## 📁 Project Structure

```
sentinelforge/
├── src/
│   ├── main.rs              # Application entry point
│   ├── api/                  # REST API handlers
│   ├── models/               # Data models & IOC utils
│   ├── storage/              # Database operations
│   ├── enrichment/           # Enrichment providers
│   │   ├── geoip.rs          # MaxMind GeoIP
│   │   ├── dns.rs            # DNS lookups
│   │   ├── virustotal.rs     # VirusTotal API
│   │   ├── abuseipdb.rs      # AbuseIPDB API
│   │   └── whois.rs          # WHOIS lookups
│   └── collectors/           # Threat feed collectors
├── migrations/               # Database migrations
├── data/                     # GeoIP databases
├── sentinelforge-ui/         # React dashboard
└── Cargo.toml
```

## 🐳 Docker Deployment

```bash
# Build
docker build -t sentinelforge .

# Run with PostgreSQL
docker-compose up -d
```

## 🗺️ Roadmap

- [ ] STIX/TAXII integration
- [ ] Automated threat feed ingestion
- [ ] Alert notifications (email, Slack, webhooks)
- [ ] MITRE ATT&CK mapping
- [ ] API rate limiting
- [ ] User authentication
- [ ] HoneyTrap honeypot integration

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [MaxMind](https://www.maxmind.com/) for GeoIP databases
- [Axum](https://github.com/tokio-rs/axum) for the web framework
- [SQLx](https://github.com/launchbadge/sqlx) for async database operations

---

<p align="center">
  <img src="sentinelforge-logo-small.png" alt="SentinelForge" width="100"/>
  <br/>
  <strong>SentinelForge</strong> - Forge Your Defense
</p>
