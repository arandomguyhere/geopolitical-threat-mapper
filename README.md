# Geopolitical Threat Mapper

A multi-layer situational awareness platform that correlates cyber threats, maritime activity, aviation data, GPS interference, financial markets, and news events to provide real-time geopolitical intelligence.

[![CI](https://github.com/arandomguyhere/geopolitical-threat-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/arandomguyhere/geopolitical-threat-mapper/actions/workflows/ci.yml)
[![Deploy to GitHub Pages](https://github.com/arandomguyhere/geopolitical-threat-mapper/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/arandomguyhere/geopolitical-threat-mapper/actions/workflows/deploy-pages.yml)

**[Live Demo](https://arandomguyhere.github.io/geopolitical-threat-mapper/)** - Interactive map with live crypto & market data

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GEOPOLITICAL THREAT MAPPER                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  DATA SOURCES                                                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │ AIS_Tracker │ │ News/RSS    │ │ Financial   │ │ Cyber Intel │  │
│  │ (Maritime)  │ │ (50+ feeds) │ │ (Markets)   │ │ (APT/IOCs)  │  │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘  │
│         │               │               │               │          │
│  ┌──────┴───────────────┴───────────────┴───────────────┴──────┐  │
│  │  OpenSky │ GPSJAM │ Shodan │ OTX │ VesselFinder │ FRED     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│            ┌─────────────────┴──────────────────┐                  │
│            │      CORRELATION ENGINE            │                  │
│            │  (6 domains: cyber, maritime,      │                  │
│            │   aviation, GPS, news, financial)  │                  │
│            └─────────────────┬──────────────────┘                  │
│                              │                                      │
│            ┌─────────────────┴──────────────────┐                  │
│            │  Threat Feed │ Dashboard │ Alerts  │                  │
│            └────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

- **Multi-Layer Correlation**: Connects 6 intelligence domains (cyber, maritime, aviation, GPS, news, financial)
- **Real-Time Monitoring**: Track 6 strategic chokepoints globally
- **Financial Market Signals**: VIX, oil prices, defense ETFs, crypto for geopolitical correlation
- **Narrative Tracking**: Disinformation detection with fringe → mainstream migration analysis
- **50+ RSS Feeds**: Curated news from mainstream, defense, think tanks, and regional sources
- **Cyber Threat Heatmap**: Regional exposure scoring from Shodan, OTX, and abuse.ch
- **APT Tracking**: Integration with your Google-News-Scraper's 60+ APT groups
- **Maritime Intelligence**: Leverages your AIS_Tracker + bulk vessel scraper fallback
- **Aviation Overlay**: Military aircraft detection via OpenSky Network
- **GPS Interference**: Spoofing/jamming detection from GPSJAM
- **GitHub Pages Demo**: Static site deployment for live demos

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

**Option 1: Settings UI (Recommended)**
1. Start the web dashboard: `python server.py`
2. Open http://localhost:8081
3. Click **Settings** button
4. Enter your API keys and click **Save**
5. Restart `main.py` to apply

**Option 2: Manual .env file**
```bash
cp .env.example .env
# Edit .env with your keys
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
| abuse.ch Feodo | Botnet C2 IPs (with country) | Unlimited |
| DShield/SANS ISC | Attack trends | Unlimited |
| FireHOL | IP blocklists | Unlimited |
| CISA KEV | Exploited CVEs | Unlimited |
| Shodan CVEDB | CVE lookups | Unlimited |

### Cyber Intelligence (Rate Limited)

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| Shodan | Infrastructure exposure | 100/month |
| ZoomEye | Chinese cyberspace scanner | Free tier |
| Netlas | Attack surface discovery | 50/day |
| LeakIX | Exposed data/misconfigs | Free for researchers |
| GreyNoise | Mass scanning detection | 50/day |
| Criminal IP | IP intelligence | 50/day |

### Aviation

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| Airplanes.Live | Aircraft tracking (primary) | Unlimited |
| OpenSky Network | Aircraft tracking (fallback) | Generous (registered) |
| ADS-B Exchange | Military unfiltered | $10/month |

**Note:** Aircraft display with rotational icons based on heading. Military aircraft (red) are identified by callsign patterns (USAF, RCH, NATO, etc.).

### GPS Interference

| Source | Use Case | Update Frequency |
|--------|----------|------------------|
| GPSJAM.org | Interference map | Daily |

### Events & News

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| GDELT Project | Global events | Unlimited |
| 50+ RSS Feeds | Curated news sources | Unlimited |

### Financial Markets

| Source | Use Case | Rate Limit |
|--------|----------|------------|
| CoinGecko | Crypto prices (BTC, ETH, stablecoins) | Unlimited |
| Yahoo Finance | VIX, commodities, sector ETFs | Unlimited |
| FRED | Federal Reserve data | Unlimited |

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
- Aircraft tracking with rotation based on heading (military=red, civilian=blue)
- Strategic chokepoint overlays with polygon boundaries
- Cyber threat markers by country (IOCs from Feodo, ThreatFox, OTX)
- AIS vessel integration with advanced visualization
- Settings UI for API key configuration
- Auto-refresh every 60 seconds

**Vessel Tracking (Best-in-class):**
- Ship icons with heading-based rotation (vessels point in direction of travel)
- Risk-based coloring: Red (dark/critical), Orange (high), Blue (medium), Green (normal), Purple (sanctioned)
- Click any vessel for detailed side panel with:
  - Flag, name, type, MMSI, IMO
  - Position, speed, course, heading, destination
  - Risk indicators (AIS gaps, sanctions, STS transfers, flag of convenience)
  - Dark fleet score (0-100)
- Vessel search by MMSI, name, or IMO number
- Dark fleet alert banner for high-risk vessels

**Layer Controls:**
- GPS Interference - Jamming/spoofing zones
- Aviation - Individual aircraft with directional icons
- Chokepoints - Strategic maritime choke points
- AIS Vessels - Ship tracking with risk visualization
- Cyber Threats - IOC markers aggregated by country
- Financial Signals - Market indicator markers

**Market Signals Panel:**
- VIX fear index with color-coded levels
- Crude oil price and daily change
- Defense sector ETF performance
- Bitcoin price as sanctions/capital flight indicator
- Market momentum indicator (surging/rising/stable/declining)

**Settings UI:**
- Configure all API keys from the web interface
- Keys are stored in `.env` file (created automatically)
- Masked display for security (shows last 4 characters)

**Cyber Threat Display:**
- C2 servers, botnets, and malware IOCs from abuse.ch feeds
- Country-level aggregation with threat scoring
- Popup details: Total IOCs, C2 count, botnet indicators, malware families

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
├── build_static.py            # Static site generator for GitHub Pages
├── requirements.txt
├── .env.example               # Environment template
├── .github/
│   └── workflows/
│       ├── ci.yml             # Lint, test, build
│       └── deploy-pages.yml   # GitHub Pages deployment
├── scripts/
│   ├── config/
│   │   ├── sources.yaml           # Data source + RSS feeds
│   │   ├── correlation_rules.yaml # Correlation rule definitions
│   │   ├── locations.yaml         # Conflict zones, bases, cables
│   │   └── chokepoints.geojson    # Strategic chokepoint polygons
│   ├── collectors/
│   │   ├── cyber/                 # Shodan, OTX, abuse.ch, NVD
│   │   ├── maritime/              # AIS_Tracker + VesselScraper
│   │   ├── aviation/              # OpenSky/Airplanes.Live
│   │   ├── financial/             # Markets, commodities, crypto
│   │   ├── gps/                   # GPSJAM interference
│   │   └── news/                  # News scraper integration
│   └── processors/
│       ├── correlation_engine.py  # Multi-source correlation
│       └── narrative_tracker.py   # Disinformation detection
├── tests/                     # Unit tests
└── output/                    # Generated files
```

## API Keys

Register for free tiers:

| Service | Sign Up |
|---------|---------|
| Shodan | https://account.shodan.io/register |
| ZoomEye | https://www.zoomeye.org/login |
| Netlas | https://app.netlas.io/registration/ |
| LeakIX | https://leakix.net/auth/register |
| AlienVault OTX | https://otx.alienvault.com/accounts/signup |
| AISStream | https://aisstream.io/ |
| Marinesia | https://marinesia.com/ |
| GreyNoise | https://viz.greynoise.io/signup |
| OpenSky | https://opensky-network.org/index.php |
| NVD | https://nvd.nist.gov/developers/request-an-api-key |

## Integration with Your Repos

### AIS_Tracker Integration

The mapper uses **direct integration** with AIS_Tracker modules - no separate API server required!

**Direct Integration (Recommended):**
```bash
# Clone AIS_Tracker next to this repo
git clone https://github.com/arandomguyhere/AIS_Tracker.git ../AIS_Tracker

# Set API keys for AIS data sources
AISSTREAM_API_KEY=your_key_here    # Real-time vessel streaming
MARINESIA_API_KEY=your_key_here    # Vessel info, port data (optional)
```

**Features from direct integration:**
- Real-time vessel positions via AISStream WebSocket
- Behavioral analysis (AIS gaps, spoofing, loitering)
- Sanctions checking (FleetLeaks, OFAC)
- Dark fleet detection and risk scoring
- Flag of convenience detection

**Fallback API mode:**
```python
# If direct integration unavailable, falls back to API
AIS_TRACKER_URL = "http://localhost:8080"
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
- [x] Direct AIS_Tracker integration (no API server needed)
- [x] News-Scraper feed ingester (60+ APT groups)
- [x] Aviation collector (Airplanes.Live + OpenSky fallback)
- [x] GPSJAM interference collector
- [x] Correlation engine implementation
- [x] Interactive Leaflet map (web dashboard)
- [x] Settings UI for API key configuration
- [x] Best-in-class vessel tracking (ship icons, details panel, search, risk scoring)
- [x] Unit test suite
- [x] Financial market integration (VIX, commodities, crypto, defense ETFs)
- [x] Narrative/disinformation tracking
- [x] 50+ RSS feed aggregation
- [x] Bulk vessel scraper fallback
- [x] GitHub Actions CI/CD
- [x] GitHub Pages static deployment
- [ ] GDELT integration
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
