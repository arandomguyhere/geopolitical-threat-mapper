#!/usr/bin/env python3
"""
Static Site Builder for GitHub Pages

Generates a static version of the Geopolitical Threat Mapper dashboard
that can run entirely in the browser without a Python backend.

Data is embedded directly into the HTML or loaded from static JSON files.
"""

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).parent
DIST_DIR = ROOT_DIR / "dist"
DATA_DIR = ROOT_DIR / "data"
FEED_DIR = DATA_DIR / "feed"
SCRIPTS_DIR = ROOT_DIR / "scripts"
CONFIG_DIR = SCRIPTS_DIR / "config"


def load_yaml_as_json(yaml_path: Path) -> dict:
    """Load YAML file and convert to dict"""
    try:
        import yaml
        with open(yaml_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Could not load {yaml_path}: {e}")
        return {}


def generate_sample_data() -> dict:
    """Generate sample data for static site"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "gps": {
            "interference_zones": [
                {"lat": 55.0, "lon": 15.0, "radius_km": 50, "severity": "high", "type": "jamming", "region": "baltic_sea"},
                {"lat": 44.0, "lon": 34.0, "radius_km": 80, "severity": "critical", "type": "spoofing", "region": "black_sea"},
                {"lat": 33.5, "lon": 36.0, "radius_km": 40, "severity": "medium", "type": "jamming", "region": "syria"},
            ]
        },
        "aviation": {
            "aircraft": [
                {"hex": "ABC123", "lat": 35.0, "lon": 33.0, "alt_ft": 35000, "type": "military", "category": "reconnaissance"},
                {"hex": "DEF456", "lat": 50.0, "lon": 30.0, "alt_ft": 28000, "type": "military", "category": "tanker"},
            ]
        },
        "cyber": {
            "threats": [
                {"actor": "APT28", "target_country": "UA", "severity": "high", "type": "espionage"},
                {"actor": "Volt Typhoon", "target_country": "US", "severity": "critical", "type": "infrastructure"},
            ],
            "statistics": {
                "active_campaigns": 12,
                "critical_threats": 3,
            }
        },
        "financial": {
            "vix": {"value": 18.5, "change_pct": 2.3, "level": "normal"},
            "commodities": [
                {"symbol": "CL=F", "name": "Crude Oil (WTI)", "price": 75.50, "change_pct": 1.2},
                {"symbol": "GC=F", "name": "Gold", "price": 2050.00, "change_pct": 0.5},
            ],
            "sectors": [
                {"symbol": "ITA", "name": "iShares Aerospace & Defense", "change_pct": 0.8, "sector_type": "defense"},
                {"symbol": "XLE", "name": "Energy Select", "change_pct": 1.5, "sector_type": "energy"},
            ],
            "crypto": [
                {"symbol": "BTC", "name": "Bitcoin", "price": 42000, "change_24h": 2.5},
                {"symbol": "ETH", "name": "Ethereum", "price": 2200, "change_24h": 1.8},
            ],
            "momentum": "stable",
        },
    }


def generate_chokepoints() -> list:
    """Generate chokepoint data"""
    return [
        {
            "id": "baltic_sea",
            "name": "Baltic Sea",
            "lat": 55.0,
            "lon": 15.0,
            "threat_level": "high",
            "description": "Critical shipping lanes, subsea cable routes",
            "recent_events": ["Cable damage incidents", "Shadow fleet activity"],
        },
        {
            "id": "black_sea",
            "name": "Black Sea",
            "lat": 44.0,
            "lon": 34.0,
            "threat_level": "critical",
            "description": "Active conflict zone, grain corridor",
            "recent_events": ["Naval drone attacks", "Mine threats"],
        },
        {
            "id": "red_sea",
            "name": "Red Sea / Bab el-Mandeb",
            "lat": 12.5,
            "lon": 43.5,
            "threat_level": "critical",
            "description": "Houthi attacks on shipping",
            "recent_events": ["Missile attacks", "Drone strikes"],
        },
        {
            "id": "taiwan_strait",
            "name": "Taiwan Strait",
            "lat": 24.0,
            "lon": 119.5,
            "threat_level": "elevated",
            "description": "Strategic waterway, military tensions",
            "recent_events": ["PLA exercises", "ADIZ incursions"],
        },
        {
            "id": "hormuz",
            "name": "Strait of Hormuz",
            "lat": 26.5,
            "lon": 56.5,
            "threat_level": "high",
            "description": "Critical oil transit point",
            "recent_events": ["IRGC naval activity", "Tanker seizures"],
        },
        {
            "id": "malacca",
            "name": "Strait of Malacca",
            "lat": 2.5,
            "lon": 101.5,
            "threat_level": "moderate",
            "description": "Major shipping lane",
            "recent_events": ["Piracy concerns"],
        },
    ]


def load_feed_data() -> dict:
    """Load existing feed data if available"""
    feed_file = FEED_DIR / "combined_feed.json"
    if feed_file.exists():
        try:
            with open(feed_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load feed data: {e}")
    return generate_sample_data()


def extract_dashboard_html() -> str:
    """Extract and modify the dashboard HTML from server.py"""
    server_py = ROOT_DIR / "server.py"

    with open(server_py, "r", encoding="utf-8") as f:
        content = f.read()

    # Find DASHBOARD_HTML variable assignment
    # Pattern: DASHBOARD_HTML = """...."""
    start_marker = 'DASHBOARD_HTML = """'
    end_marker = '"""'

    start = content.find(start_marker)
    if start == -1:
        # Try single quotes
        start_marker = "DASHBOARD_HTML = '''"
        end_marker = "'''"
        start = content.find(start_marker)

    if start == -1:
        raise ValueError("Could not find DASHBOARD_HTML in server.py")

    # Move past the opening quotes
    start += len(start_marker)

    # Find the closing quotes (must be on its own or end of variable)
    # Search for """ that ends the string (not part of content)
    search_from = start
    end = -1

    while True:
        pos = content.find(end_marker, search_from)
        if pos == -1:
            break
        # Check if this is likely the end of the template
        # It should be followed by newline or end of file or a new statement
        after = content[pos + len(end_marker):pos + len(end_marker) + 20]
        if after.strip().startswith(('\n', '@', 'def ', '#', '')):
            end = pos
            break
        search_from = pos + 1

    if end == -1:
        # Fallback: find </html> and then the next """
        html_end = content.find("</html>", start)
        if html_end != -1:
            end = content.find(end_marker, html_end)

    if end == -1:
        raise ValueError("Could not find end of DASHBOARD_HTML in server.py")

    html = content[start:end]
    return html.strip()


def modify_html_for_static(html: str, feed_data: dict, chokepoints: list) -> str:
    """Modify HTML to work as static site"""

    # Embed data directly in the page
    data_script = f"""
    <script>
        // Embedded data for static site (no backend required)
        window.STATIC_MODE = true;
        window.FEED_DATA = {json.dumps(feed_data, indent=2)};
        window.CHOKEPOINTS = {json.dumps(chokepoints, indent=2)};
    </script>
    """

    # Replace fetch calls with live data fetchers
    static_loader = """
    <script>
        // Live data fetchers for static site
        window.LIVE_DATA_CACHE = {};
        window.LIVE_DATA_CACHE_TIME = {};
        const CACHE_TTL = 60000; // 1 minute cache

        // Store original fetch before overriding
        const _originalFetch = window.fetch.bind(window);

        async function fetchLiveFinancial() {
            const now = Date.now();
            if (window.LIVE_DATA_CACHE.financial && (now - window.LIVE_DATA_CACHE_TIME.financial) < CACHE_TTL) {
                return window.LIVE_DATA_CACHE.financial;
            }

            const data = {
                vix: { value: 0, level: 'normal' },
                commodities: [],
                crypto: [],
                sectors: [{ sector_type: 'defense', change_pct: 0 }],
                momentum: 'stable'
            };

            try {
                // Fetch crypto from CoinGecko (public API)
                const cryptoResp = await _originalFetch('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,tether&vs_currencies=usd&include_24hr_change=true');
                if (cryptoResp.ok) {
                    const crypto = await cryptoResp.json();
                    data.crypto = [
                        { symbol: 'BTC', name: 'Bitcoin', price: crypto.bitcoin?.usd || 0, change_24h: crypto.bitcoin?.usd_24h_change || 0 },
                        { symbol: 'ETH', name: 'Ethereum', price: crypto.ethereum?.usd || 0, change_24h: crypto.ethereum?.usd_24h_change || 0 },
                        { symbol: 'USDT', name: 'Tether', price: crypto.tether?.usd || 1, change_24h: crypto.tether?.usd_24h_change || 0 }
                    ];
                    console.log('Crypto data loaded:', data.crypto);
                }

                // Fetch fear & greed as VIX proxy
                const fgiResp = await _originalFetch('https://api.alternative.me/fng/?limit=1');
                if (fgiResp.ok) {
                    const fgi = await fgiResp.json();
                    const value = parseInt(fgi.data?.[0]?.value || 50);
                    // Invert: fear (low) = high VIX, greed (high) = low VIX
                    const vixProxy = Math.round((100 - value) * 0.4 + 10);
                    data.vix = {
                        value: vixProxy,
                        level: vixProxy > 30 ? 'elevated' : vixProxy > 20 ? 'normal' : 'low',
                        fear_greed: fgi.data?.[0]?.value_classification || 'Neutral',
                        fear_greed_value: value
                    };
                    console.log('Fear/Greed data loaded:', data.vix);
                }

                // Calculate momentum from BTC change
                const btcChange = data.crypto[0]?.change_24h || 0;
                if (btcChange > 5) data.momentum = 'surging';
                else if (btcChange > 2) data.momentum = 'rising';
                else if (btcChange < -5) data.momentum = 'declining';
                else data.momentum = 'stable';

            } catch (e) {
                console.warn('Live financial fetch error:', e);
            }

            window.LIVE_DATA_CACHE.financial = data;
            window.LIVE_DATA_CACHE_TIME.financial = now;
            return data;
        }

        // Override fetch for static mode with live data
        if (window.STATIC_MODE) {
            window.fetch = async function(url, options) {
                if (typeof url === 'string') {
                    if (url === '/api/feed') {
                        const financial = await fetchLiveFinancial();
                        const feed = { ...window.FEED_DATA, financial, timestamp: new Date().toISOString() };
                        return { ok: true, json: async () => feed };
                    }
                    if (url === '/api/chokepoints') {
                        return { ok: true, json: async () => window.CHOKEPOINTS };
                    }
                    if (url === '/api/financial') {
                        const financial = await fetchLiveFinancial();
                        return { ok: true, json: async () => financial };
                    }
                    if (url === '/api/ais') {
                        return { ok: true, json: async () => ({ vessels: [], statistics: {} }) };
                    }
                    if (url.startsWith('/api/')) {
                        return { ok: true, json: async () => ({}) };
                    }
                }
                return _originalFetch(url, options);
            };

            // Wait for processFinancialData to be defined, then load live data
            async function initLiveData() {
                // Wait up to 5 seconds for the function to be available
                for (let i = 0; i < 50; i++) {
                    if (typeof processFinancialData === 'function') {
                        console.log('Loading live financial data...');
                        const financial = await fetchLiveFinancial();
                        processFinancialData(financial);
                        return true;
                    }
                    await new Promise(r => setTimeout(r, 100));
                }
                console.warn('processFinancialData not found');
                return false;
            }

            // Start loading after a short delay to ensure page scripts have loaded
            setTimeout(initLiveData, 500);

            // Auto-refresh live data every 60 seconds
            setInterval(async () => {
                console.log('Refreshing live data...');
                window.LIVE_DATA_CACHE = {};
                const financial = await fetchLiveFinancial();
                if (typeof processFinancialData === 'function') {
                    processFinancialData(financial);
                }
            }, 60000);
        }
    </script>
    """

    # Add live data banner
    static_banner = """
    <div id="static-mode-banner" style="position:fixed;top:0;left:50%;transform:translateX(-50%);background:#2ecc71;color:#000;padding:5px 15px;border-radius:0 0 5px 5px;font-size:0.75rem;z-index:9999;">
        <span id="live-indicator" style="display:inline-block;width:8px;height:8px;background:#fff;border-radius:50%;margin-right:6px;animation:pulse 2s infinite;"></span>
        Live Data - Crypto &amp; Fear/Greed Index
    </div>
    <style>
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
    </style>
    """

    # Insert scripts after <head>
    html = html.replace("<head>", f"<head>\n{data_script}")

    # Insert static loader before closing body
    html = html.replace("</body>", f"{static_loader}\n{static_banner}\n</body>")

    # Update title
    html = html.replace("<title>", "<title>Geopolitical Threat Mapper - ")

    return html


def copy_static_assets():
    """Copy any static assets (CSS, JS, images)"""
    assets_dir = ROOT_DIR / "static"
    if assets_dir.exists():
        shutil.copytree(assets_dir, DIST_DIR / "static", dirs_exist_ok=True)


def generate_data_files(feed_data: dict, chokepoints: list):
    """Generate static JSON data files"""
    data_out = DIST_DIR / "data"
    data_out.mkdir(parents=True, exist_ok=True)

    # Write feed data
    with open(data_out / "feed.json", "w", encoding="utf-8") as f:
        json.dump(feed_data, f, indent=2)

    # Write chokepoints
    with open(data_out / "chokepoints.json", "w", encoding="utf-8") as f:
        json.dump(chokepoints, f, indent=2)

    # Write locations config if available
    locations_yaml = CONFIG_DIR / "locations.yaml"
    if locations_yaml.exists():
        locations = load_yaml_as_json(locations_yaml)
        with open(data_out / "locations.json", "w", encoding="utf-8") as f:
            json.dump(locations, f, indent=2)


def build():
    """Main build function"""
    print("Building static site...")

    # Clean dist directory
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True)

    # Load data
    print("Loading feed data...")
    feed_data = load_feed_data()
    chokepoints = generate_chokepoints()

    # Extract and modify HTML
    print("Extracting dashboard HTML...")
    try:
        html = extract_dashboard_html()
    except ValueError as e:
        print(f"Error: {e}")
        print("Generating minimal static page...")
        html = generate_minimal_html()

    print("Modifying for static deployment...")
    html = modify_html_for_static(html, feed_data, chokepoints)

    # Write index.html
    with open(DIST_DIR / "index.html", "w", encoding="utf-8") as f:
        f.write(html)

    # Copy static assets
    print("Copying static assets...")
    copy_static_assets()

    # Generate data files
    print("Generating data files...")
    generate_data_files(feed_data, chokepoints)

    # Create 404.html (same as index for SPA routing)
    shutil.copy(DIST_DIR / "index.html", DIST_DIR / "404.html")

    print(f"\nBuild complete! Output in: {DIST_DIR}")
    print(f"Files generated:")
    for f in DIST_DIR.rglob("*"):
        if f.is_file():
            print(f"  - {f.relative_to(DIST_DIR)}")


def generate_minimal_html() -> str:
    """Generate a minimal HTML page if extraction fails"""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Geopolitical Threat Mapper</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; }
        #map { width: 100%; height: 100vh; }
        .header { position: absolute; top: 0; left: 0; right: 0; z-index: 1000; background: rgba(26,26,46,0.95); padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e94560; }
        .header h1 { color: #e94560; font-size: 1.2rem; }
        .stats { display: flex; gap: 20px; }
        .stat { text-align: center; }
        .stat-value { font-size: 1.5rem; font-weight: bold; }
        .stat-label { font-size: 0.7rem; color: #888; }
        .critical { color: #e94560; }
        .high { color: #f39c12; }
        .medium { color: #3498db; }
        .low { color: #2ecc71; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Geopolitical Threat Mapper</h1>
        <div class="stats">
            <div class="stat">
                <div class="stat-value critical" id="threat-score">--</div>
                <div class="stat-label">Threat Level</div>
            </div>
            <div class="stat">
                <div class="stat-value high" id="gps-zones">0</div>
                <div class="stat-label">GPS Zones</div>
            </div>
            <div class="stat">
                <div class="stat-value medium" id="chokepoints">0</div>
                <div class="stat-label">Chokepoints</div>
            </div>
        </div>
    </div>
    <div id="map"></div>
    <script>
        // Initialize map
        const map = L.map('map').setView([30, 40], 3);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '© OpenStreetMap © CARTO',
            maxZoom: 19
        }).addTo(map);

        // Load data
        async function loadData() {
            try {
                const feedResp = await fetch('/api/feed');
                const feed = await feedResp.json();

                const cpResp = await fetch('/api/chokepoints');
                const chokepoints = await cpResp.json();

                // Add chokepoints to map
                chokepoints.forEach(cp => {
                    const color = cp.threat_level === 'critical' ? '#e94560' :
                                  cp.threat_level === 'high' ? '#f39c12' : '#3498db';
                    L.circleMarker([cp.lat, cp.lon], {
                        radius: 12,
                        color: color,
                        fillColor: color,
                        fillOpacity: 0.5
                    }).addTo(map).bindPopup(`<b>${cp.name}</b><br>${cp.description}`);
                });

                document.getElementById('chokepoints').textContent = chokepoints.length;

                // Add GPS zones
                const gpsZones = feed.gps?.interference_zones || [];
                gpsZones.forEach(zone => {
                    const color = zone.severity === 'critical' ? '#e94560' :
                                  zone.severity === 'high' ? '#f39c12' : '#3498db';
                    L.circle([zone.lat, zone.lon], {
                        radius: (zone.radius_km || 50) * 1000,
                        color: color,
                        fillColor: color,
                        fillOpacity: 0.2
                    }).addTo(map);
                });

                document.getElementById('gps-zones').textContent = gpsZones.length;
                document.getElementById('threat-score').textContent = 'ELEVATED';

            } catch (error) {
                console.error('Error loading data:', error);
            }
        }

        loadData();
    </script>
</body>
</html>"""


if __name__ == "__main__":
    build()
