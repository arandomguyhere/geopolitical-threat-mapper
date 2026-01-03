# Geopolitical Threat Mapper

A multi-layer situational awareness platform that correlates cyber threats, maritime activity, aviation data, GPS interference, and news events to provide real-time geopolitical intelligence.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GEOPOLITICAL THREAT MAPPER                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  YOUR EXISTING REPOS (FOUNDATION)                                   │
│  ┌─────────────────────┐  ┌─────────────────────┐                  │
│  │   AIS_Tracker       │  │ Google-News-Scraper │                  │
│  │   (Maritime Intel)  │  │   (Threat News)     │                  │
│  └──────────┬──────────┘  └──────────┬──────────┘                  │
│             │                        │                              │
│  NEW DATA SOURCES                    │                              │
│  ┌──────────┴────────────────────────┴──────────┐                  │
│  │  Shodan │ Censys │ OTX │ OpenSky │ GPSJAM   │                   │
│  └──────────────────────────────────────────────┘                  │
│                              │                                      │
│            ┌─────────────────┴──────────────────┐                  │
│            │      CORRELATION ENGINE            │                  │
│            └─────────────────┬──────────────────┘                  │
│                              │                                      │
│            ┌─────────────────┴──────────────────┐                  │
│            │  Threat Feed │ Heatmap │ Alerts    │                  │
│            └────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

- **Multi-Layer Correlation**: Connects cyber threats with maritime, aviation, and news data
- **Real-Time Monitoring**: Track 6 strategic chokepoints globally
- **Cyber Threat Heatmap**: Regional exposure scoring from Shodan, OTX, and abuse.ch
- **APT Tracking**: Integration with your Google-News-Scraper's 60+ APT groups
- **Maritime Intelligence**: Leverages your AIS_Tracker for dark ships and sanctions
- **Aviation Overlay**: Military aircraft detection via OpenSky Network
- **GPS Interference**: Spoofing/jamming detection from GPSJAM

## Monitored Regions

| Region | Priority | Key Threats |
|--------|----------|-------------|
| Baltic Sea | Critical | Cable sabotage, shadow fleet, GPS jamming |
| Black Sea | Critical | GPS spoofing, dark tankers, STS transfers |
| Red Sea | Critical | Houthi attacks, vessel rerouting, UAV incursions |
| Taiwan Strait | Critical | Naval surge, ADIZ violations, APT activity |
| Strait of Hormuz | High | Tanker seizures, Iran navy, surveillance drones |
| Malacca Strait | High | Port attacks, trade disruption |

## Quick Start

### Prerequisites

- Python 3.10+
- Your existing repos:
  - [AIS_Tracker](https://github.com/arandomguyhere/AIS_Tracker) running locally
  - [Google-News-Scraper](https://github.com/arandomguyhere/Google-News-Scraper) output available

### Installation

```bash
git clone https://github.com/arandomguyhere/geopolitical-threat-mapper.git
cd geopolitical-threat-mapper
pip install -r requirements.txt
```

### Configuration

1. Copy and configure environment variables:
```bash
cp .env.example .env
```

2. Add your API keys:
```bash
# Required for full functionality
SHODAN_API_KEY=your_key_here
OTX_API_KEY=your_key_here

# Optional but recommended
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
GREYNOISE_API_KEY=your_key_here
OPENSKY_USERNAME=your_username
OPENSKY_PASSWORD=your_password
```

### Run

```bash
# Step 1: Collect data from all sources
python main.py

# Step 2: Start the web dashboard
python server.py

# Step 3: Open http://localhost:8081 in your browser
```

**Options:**
```bash
# Specific regions only
python main.py --regions baltic_sea taiwan_strait

# Web dashboard on different port
python server.py --port 9000
```

## Data Sources

### Cyber Intelligence (Unlimited Free)

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| AlienVault OTX | APT pulses, IOCs | Unlimited |
| abuse.ch ThreatFox | Malware C2 servers | Unlimited |
| abuse.ch URLhaus | Malware URLs | Unlimited |
| DShield/SANS ISC | Attack trends | Unlimited |
| FireHOL | IP blocklists | Unlimited |
| CISA KEV | Exploited CVEs | Unlimited |

### Cyber Intelligence (Rate Limited)

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| Shodan | Infrastructure exposure | 100/month |
| Censys | Certificates, hosts | 250/month |
| GreyNoise | Mass scanning detection | 50/day |
| Criminal IP | IP intelligence | 50/day |

### Aviation

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| OpenSky Network | Aircraft tracking | Generous (registered) |
| ADS-B Exchange | Military unfiltered | $10/month |

### GPS Interference

| Source | Use Case | Update Frequency |
|--------|----------|------------------|
| GPSJAM.org | Interference map | Daily |

### Events

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| GDELT Project | Global events | Unlimited |

## Output Files

After running, find these in the `output/` directory:

- **feed.json** - Complete threat feed with all events and correlations
- **cyber_heatmap.json** - Regional cyber threat scores
- **daily_brief.md** - Human-readable situation report

## Web Dashboard

The web dashboard (`server.py`) provides an interactive map at **http://localhost:8081**:

**Features:**
- Dark-themed Leaflet map with multiple layers
- GPS interference zones with intensity indicators
- Military and civilian aircraft tracking
- Strategic chokepoint overlays
- Cyber threat markers by country
- AIS vessel integration (when Arsenal Tracker running on port 8080)
- Auto-refresh every 60 seconds

**Layer Controls:**
- GPS Interference
- Aviation
- Chokepoints
- AIS Vessels
- Cyber Threats

## Correlation Rules

The system watches for these patterns:

| Rule | Priority | Triggers |
|------|----------|----------|
| Shadow Fleet Cable Threat | Critical | Vessel near cable + AIS gap + news mentions |
| Sanctions Evasion STS | Critical | STS transfer + sanctions match |
| Pre-Conflict Cyber | High | Exposure spike + APT activity + tension news |
| GPS Warfare | High | Interference + aviation anomalies + AIS anomalies |
| Chokepoint Disruption | High | Traffic anomaly + attack news + airspace restriction |

See `config/correlation_rules.yaml` for full definitions.

## Project Structure

```
geopolitical-threat-mapper/
├── main.py                    # Data collection orchestrator
├── server.py                  # Web dashboard (port 8081)
├── requirements.txt
├── .env.example               # Environment template
├── scripts/
│   ├── config/
│   │   ├── sources.yaml           # Data source configuration
│   │   ├── correlation_rules.yaml # Correlation rule definitions
│   │   └── chokepoints.geojson    # Strategic chokepoint polygons
│   ├── collectors/
│   │   ├── cyber/                 # Shodan, OTX, abuse.ch, NVD
│   │   ├── maritime/              # AIS_Tracker integration
│   │   ├── aviation/              # OpenSky/Airplanes.Live
│   │   ├── gps/                   # GPSJAM interference
│   │   └── news/                  # News scraper integration
│   └── processors/
│       └── correlation_engine.py  # Multi-source correlation
├── tests/                     # 40 unit tests
└── output/                    # Generated files
```

## API Keys

Register for free tiers:

| Service | Sign Up |
|---------|---------|
| Shodan | https://account.shodan.io/register |
| AlienVault OTX | https://otx.alienvault.com/accounts/signup |
| Censys | https://censys.io/register |
| GreyNoise | https://viz.greynoise.io/signup |
| OpenSky | https://opensky-network.org/index.php |
| NVD | https://nvd.nist.gov/developers/request-an-api-key |

## Integration with Your Repos

### AIS_Tracker Integration

```python
# Pull from AIS_Tracker API
AIS_TRACKER_URL = "http://localhost:8080"

# Endpoints used:
# GET /api/vessels - Active vessels
# GET /api/alerts - Current alerts
# GET /api/dark-ships - Dark vessel detections
# GET /api/sanctions/check - Sanctions matches
```

### Google-News-Scraper Integration

```python
# Read from feed.json
NEWS_SCRAPER_FEED = "/path/to/Google-News-Scraper/docs/feed.json"

# Expected fields:
# - title, source, url
# - categories (APT groups, sectors)
# - sentiment
# - confidence_score
```

## Roadmap

- [x] Core correlation engine design
- [x] Cyber collectors (Shodan, OTX, abuse.ch, DShield, NVD)
- [x] Configuration system (sources.yaml, correlation_rules.yaml)
- [x] Chokepoints definition (12 strategic locations)
- [x] AIS_Tracker API connector
- [x] News-Scraper feed ingester (60+ APT groups)
- [x] Aviation collector (Airplanes.Live + OpenSky fallback)
- [x] GPSJAM interference collector
- [x] Correlation engine implementation
- [x] Interactive Leaflet map (web dashboard)
- [x] Unit test suite (40 tests)
- [ ] GDELT integration
- [ ] GitHub Actions automation
- [ ] Alert notifications (Slack, Discord)

## Contributing

1. Fork the repo
2. Create a feature branch
3. Submit a PR

## License

MIT

## Acknowledgments

- Built on top of [AIS_Tracker](https://github.com/arandomguyhere/AIS_Tracker)
- News data from [Google-News-Scraper](https://github.com/arandomguyhere/Google-News-Scraper)
- Threat intel from AlienVault OTX, abuse.ch, and the OSINT community
