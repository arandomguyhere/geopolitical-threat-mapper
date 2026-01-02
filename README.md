# Geopolitical Threat Mapper

Multi-layer situational awareness platform integrating cyber threats, news intelligence, maritime tracking, and aviation data for geopolitical risk assessment.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GEOPOLITICAL THREAT MAPPER                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────┐  ┌─────────────────────┐                  │
│  │   AIS_Tracker       │  │ Google-News-Scraper │                  │
│  │   (Integration)     │  │    (Integration)    │                  │
│  └──────────┬──────────┘  └──────────┬──────────┘                  │
│             │                        │                              │
│             └────────────┬───────────┘                              │
│                          ▼                                          │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    CYBER LAYER                                │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐  │  │
│  │  │Infrastructure│ │    IOCs    │ │  Telemetry  │ │  Vulns  │  │  │
│  │  │  (Shodan)   │ │   (OTX)    │ │ (DShield)   │ │  (NVD)  │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘  │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                          │                                          │
│         ┌────────────────┼────────────────┐                         │
│         ▼                ▼                ▼                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  Aviation   │  │ GPS/GNSS    │  │   News      │                 │
│  │  (OpenSky)  │  │ Interference│  │  (GDELT)    │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Sources (All Free)

### Cyber Layer

| Layer | Sources | Auth Required |
|-------|---------|---------------|
| **Infrastructure** | Shodan, Criminal IP, LeakIX, ZoomEye, Netlas | API Keys |
| **IOCs** | AlienVault OTX, ThreatFox, URLhaus, Feodo, GreyNoise | Some optional |
| **Telemetry** | DShield, Shadowserver, FireHOL, DataPlane, CINS | Mostly free |
| **Vulnerabilities** | NVD, CISA KEV, Shodan CVEDB | Optional key |

### Other Layers

| Layer | Sources | Auth Required |
|-------|---------|---------------|
| **Maritime** | AIS_Tracker integration, Global Fishing Watch | GFW key optional |
| **Aviation** | OpenSky Network, ADS-B Exchange | Account optional |
| **GPS Interference** | GPSJAM.org, SkAI Spoofing Tracker | No |
| **News** | Google-News-Scraper integration, GDELT | No |
| **Sanctions** | OFAC, OpenSanctions | Optional |

## Setup

1. Clone the repository:
```bash
git clone https://github.com/arandomguyhere/geopolitical-threat-mapper
cd geopolitical-threat-mapper
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure API keys:
```bash
cp .env.example .env
# Edit .env with your API keys
```

5. Run collectors:
```bash
python -m scripts.collectors.cyber
```

## API Key Registration

All sources are free tier. Get your keys:

| Source | Registration URL |
|--------|------------------|
| Shodan | https://account.shodan.io/register |
| AlienVault OTX | https://otx.alienvault.com/accounts/signup/ |
| GreyNoise | https://viz.greynoise.io/signup |
| OpenSky | https://opensky-network.org/index.php?option=com_users&view=registration |
| NVD | https://nvd.nist.gov/developers/request-an-api-key |
| Global Fishing Watch | https://globalfishingwatch.org/our-apis/ |

## Related Projects

- [AIS_Tracker](https://github.com/arandomguyhere/AIS_Tracker) - Maritime intelligence system
- [Google-News-Scraper](https://github.com/arandomguyhere/Google-News-Scraper) - Cyber threat news aggregation

## Directory Structure

```
geopolitical-threat-mapper/
├── .env.example           # Environment variable template
├── requirements.txt       # Python dependencies
├── scripts/
│   ├── config/           # Configuration management
│   │   └── settings.py   # API keys and settings loader
│   ├── collectors/       # Data collectors
│   │   ├── cyber/        # Cyber threat intelligence
│   │   │   ├── infrastructure.py  # Shodan-style exposure mapping
│   │   │   ├── ioc_feeds.py       # IOC/threat actor tracking
│   │   │   ├── attack_telemetry.py # Honeypot/attack data
│   │   │   └── vulnerability.py    # CVE/exploit tracking
│   │   ├── aviation/     # ADS-B flight tracking
│   │   ├── maritime/     # AIS vessel tracking
│   │   └── news/         # News/GDELT integration
│   ├── processors/       # Data correlation & analysis
│   └── outputs/          # Map generation & API
├── data/                 # SQLite databases
└── logs/                 # Application logs
```

## License

MIT
