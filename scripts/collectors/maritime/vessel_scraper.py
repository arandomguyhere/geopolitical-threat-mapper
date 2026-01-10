"""
Bulk Vessel Scraper - Fallback AIS Data Source

Scrapes vessel data from free sources around points of interest (chokepoints).
Use as fallback when AISStream.io or AIS_Tracker unavailable.

Sources:
- MarineTraffic.com (limited, requires careful rate limiting)
- VesselFinder.com (backup)
- ShipXplorer.com (backup)

Note: These sources have anti-scraping measures. Use responsibly.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


# Chokepoint coordinates for regional vessel search
CHOKEPOINTS = {
    "red_sea": {
        "name": "Red Sea / Bab el-Mandeb",
        "lat": 12.5,
        "lon": 43.5,
        "radius_nm": 100,
    },
    "hormuz": {
        "name": "Strait of Hormuz",
        "lat": 26.5,
        "lon": 56.5,
        "radius_nm": 50,
    },
    "taiwan_strait": {
        "name": "Taiwan Strait",
        "lat": 24.0,
        "lon": 119.5,
        "radius_nm": 100,
    },
    "malacca": {
        "name": "Strait of Malacca",
        "lat": 2.5,
        "lon": 101.5,
        "radius_nm": 100,
    },
    "baltic_sea": {
        "name": "Baltic Sea",
        "lat": 55.0,
        "lon": 15.0,
        "radius_nm": 150,
    },
    "black_sea": {
        "name": "Black Sea",
        "lat": 43.5,
        "lon": 34.0,
        "radius_nm": 200,
    },
}

# Shadow fleet flags (high risk for sanctions evasion)
SHADOW_FLEET_FLAGS = {
    "CM", "GA", "GN", "PW", "TG", "TZ",  # Common flags of convenience
    "PA", "LR", "MH", "BS", "CY", "MT",  # Major open registries
}

# Sanctioned country flags
SANCTIONED_FLAGS = {"RU", "IR", "KP", "SY", "VE"}


@dataclass
class ScrapedVessel:
    """Vessel data from scraping"""
    mmsi: str
    name: str
    lat: float
    lon: float
    flag: Optional[str] = None
    vessel_type: Optional[str] = None
    speed: Optional[float] = None
    course: Optional[float] = None
    heading: Optional[float] = None
    destination: Optional[str] = None
    last_update: Optional[datetime] = None
    imo: Optional[str] = None
    # Risk indicators
    is_shadow_fleet_flag: bool = False
    is_sanctioned_flag: bool = False
    region: Optional[str] = None
    source: str = "scraper"


class VesselScraper:
    """
    Bulk vessel scraper for chokepoint monitoring

    Provides fallback vessel data when primary AIS sources unavailable.
    """

    def __init__(
        self,
        rate_limit_seconds: float = 5.0,  # Be nice to servers
        cache_ttl_seconds: int = 300,  # 5 min cache
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        self.rate_limit = rate_limit_seconds
        self.cache_ttl = cache_ttl_seconds
        self.user_agent = user_agent
        self.session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_request: float = 0

    async def init_session(self):
        """Initialize HTTP session with browser-like headers"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            },
        )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def _rate_limit(self):
        """Enforce rate limiting between requests"""
        import time
        now = time.time()
        elapsed = now - self._last_request
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request = time.time()

    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if key not in self._cache:
            return False
        cached = self._cache[key]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        return age < self.cache_ttl

    async def scrape_vesselfinder_area(
        self,
        lat: float,
        lon: float,
        radius_nm: int = 50,
    ) -> List[ScrapedVessel]:
        """
        Scrape vessels from VesselFinder around a point

        Uses their map API endpoint to get vessels in view.
        """
        cache_key = f"vf_{lat}_{lon}_{radius_nm}"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]["data"]

        if not self.session:
            await self.init_session()

        await self._rate_limit()

        vessels = []

        try:
            # Calculate bounding box (rough approximation)
            # 1 degree latitude ≈ 60 nautical miles
            lat_delta = radius_nm / 60
            lon_delta = radius_nm / (60 * abs(lat) if lat != 0 else 60)

            min_lat = lat - lat_delta
            max_lat = lat + lat_delta
            min_lon = lon - lon_delta
            max_lon = lon + lon_delta

            # VesselFinder map API
            url = f"https://www.vesselfinder.com/api/pub/vesselsonmap?bbox={min_lon},{min_lat},{max_lon},{max_lat}&zoom=8&mmsi=0&show_names=1"

            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    for v in data.get("vessels", []):
                        try:
                            vessel = ScrapedVessel(
                                mmsi=str(v.get("mmsi", "")),
                                name=v.get("name", "Unknown"),
                                lat=float(v.get("lat", 0)),
                                lon=float(v.get("lon", 0)),
                                flag=v.get("flag"),
                                vessel_type=v.get("type"),
                                speed=float(v.get("speed", 0)) if v.get("speed") else None,
                                course=float(v.get("course", 0)) if v.get("course") else None,
                                source="vesselfinder",
                            )

                            # Check risk flags
                            if vessel.flag:
                                vessel.is_shadow_fleet_flag = vessel.flag in SHADOW_FLEET_FLAGS
                                vessel.is_sanctioned_flag = vessel.flag in SANCTIONED_FLAGS

                            vessels.append(vessel)
                        except (ValueError, TypeError) as e:
                            logger.debug(f"Error parsing vessel: {e}")
                            continue

                    logger.info(f"VesselFinder: {len(vessels)} vessels near {lat},{lon}")

                elif resp.status == 429:
                    logger.warning("VesselFinder rate limited")
                else:
                    logger.warning(f"VesselFinder returned {resp.status}")

        except Exception as e:
            logger.error(f"VesselFinder scrape error: {e}")

        self._cache[cache_key] = {
            "data": vessels,
            "timestamp": datetime.utcnow(),
        }

        return vessels

    async def scrape_marinetraffic_area(
        self,
        lat: float,
        lon: float,
        zoom: int = 8,
    ) -> List[ScrapedVessel]:
        """
        Scrape vessels from MarineTraffic map view

        Note: MarineTraffic has aggressive anti-scraping.
        Use VesselFinder as primary, this as backup.
        """
        cache_key = f"mt_{lat}_{lon}_{zoom}"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]["data"]

        if not self.session:
            await self.init_session()

        await self._rate_limit()

        vessels = []

        try:
            # MarineTraffic uses tiles - we need to calculate tile coordinates
            # This is a simplified approach using their /getData endpoint
            url = f"https://www.marinetraffic.com/getData/get_data_json_4/z:{zoom}/X:{int(lon)}/Y:{int(lat)}/station:0"

            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()

                    # Parse the response (it's often JSONP or special format)
                    # MarineTraffic format varies, this is best effort
                    try:
                        import json
                        # Try to extract JSON from response
                        json_match = re.search(r'\[.*\]', text)
                        if json_match:
                            data = json.loads(json_match.group())

                            for v in data:
                                if isinstance(v, list) and len(v) >= 4:
                                    try:
                                        vessel = ScrapedVessel(
                                            mmsi=str(v[0]) if v[0] else "",
                                            name=str(v[6]) if len(v) > 6 and v[6] else "Unknown",
                                            lat=float(v[1]) if v[1] else 0,
                                            lon=float(v[2]) if v[2] else 0,
                                            course=float(v[3]) if len(v) > 3 and v[3] else None,
                                            speed=float(v[4]) if len(v) > 4 and v[4] else None,
                                            flag=str(v[5]) if len(v) > 5 and v[5] else None,
                                            source="marinetraffic",
                                        )

                                        if vessel.flag:
                                            vessel.is_shadow_fleet_flag = vessel.flag in SHADOW_FLEET_FLAGS
                                            vessel.is_sanctioned_flag = vessel.flag in SANCTIONED_FLAGS

                                        vessels.append(vessel)
                                    except (ValueError, TypeError, IndexError):
                                        continue
                    except json.JSONDecodeError:
                        logger.debug("MarineTraffic response not valid JSON")

                    logger.info(f"MarineTraffic: {len(vessels)} vessels near {lat},{lon}")

                elif resp.status == 403:
                    logger.warning("MarineTraffic blocked request")
                else:
                    logger.warning(f"MarineTraffic returned {resp.status}")

        except Exception as e:
            logger.error(f"MarineTraffic scrape error: {e}")

        self._cache[cache_key] = {
            "data": vessels,
            "timestamp": datetime.utcnow(),
        }

        return vessels

    async def get_vessels_at_chokepoint(
        self,
        chokepoint_id: str,
    ) -> List[ScrapedVessel]:
        """
        Get vessels at a specific chokepoint

        Uses VesselFinder as primary, MarineTraffic as backup.
        """
        if chokepoint_id not in CHOKEPOINTS:
            logger.warning(f"Unknown chokepoint: {chokepoint_id}")
            return []

        cp = CHOKEPOINTS[chokepoint_id]

        # Try VesselFinder first
        vessels = await self.scrape_vesselfinder_area(
            cp["lat"],
            cp["lon"],
            cp["radius_nm"],
        )

        # If VesselFinder failed, try MarineTraffic
        if not vessels:
            vessels = await self.scrape_marinetraffic_area(
                cp["lat"],
                cp["lon"],
            )

        # Add region to all vessels
        for v in vessels:
            v.region = chokepoint_id

        return vessels

    async def get_all_chokepoint_vessels(self) -> Dict[str, List[ScrapedVessel]]:
        """
        Get vessels at all chokepoints

        Returns dict keyed by chokepoint_id.
        """
        results = {}

        for cp_id in CHOKEPOINTS:
            logger.info(f"Fetching vessels at {cp_id}...")
            vessels = await self.get_vessels_at_chokepoint(cp_id)
            results[cp_id] = vessels
            # Rate limit between chokepoints
            await asyncio.sleep(self.rate_limit)

        return results

    async def collect_all(self) -> Dict[str, Any]:
        """
        Collect all vessel data for correlation engine

        Returns format compatible with AIS collector output.
        """
        chokepoint_vessels = await self.get_all_chokepoint_vessels()

        # Flatten and deduplicate vessels
        all_vessels = []
        seen_mmsi = set()

        for cp_id, vessels in chokepoint_vessels.items():
            for v in vessels:
                if v.mmsi and v.mmsi not in seen_mmsi:
                    seen_mmsi.add(v.mmsi)
                    all_vessels.append(v)

        # Convert to dict format for correlation engine
        vessel_dicts = []
        for v in all_vessels:
            vessel_dicts.append({
                "mmsi": v.mmsi,
                "name": v.name,
                "lat": v.lat,
                "lon": v.lon,
                "flag": v.flag,
                "vessel_type": v.vessel_type,
                "speed": v.speed,
                "course": v.course,
                "heading": v.heading,
                "destination": v.destination,
                "region": v.region,
                "chokepoint": v.region,
                # Risk indicators
                "is_shadow_fleet": v.is_shadow_fleet_flag,
                "is_flag_of_convenience": v.is_shadow_fleet_flag,
                "sanctions_match": v.is_sanctioned_flag,
                "is_dark": False,  # Can't determine from scrape
                "risk_level": self._calculate_risk_level(v),
                "dark_fleet_score": self._calculate_dark_fleet_score(v),
                "source": v.source,
            })

        # Statistics by region
        stats_by_region = {}
        for cp_id, vessels in chokepoint_vessels.items():
            shadow_count = sum(1 for v in vessels if v.is_shadow_fleet_flag)
            sanctioned_count = sum(1 for v in vessels if v.is_sanctioned_flag)

            stats_by_region[cp_id] = {
                "vessel_count": len(vessels),
                "shadow_fleet_flags": shadow_count,
                "sanctioned_flags": sanctioned_count,
            }

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "vessel_scraper",
            "vessels": vessel_dicts,
            "statistics": {
                "total_vessels": len(vessel_dicts),
                "shadow_fleet_flags": sum(1 for v in all_vessels if v.is_shadow_fleet_flag),
                "sanctioned_flags": sum(1 for v in all_vessels if v.is_sanctioned_flag),
                "by_region": stats_by_region,
            },
        }

    def _calculate_risk_level(self, vessel: ScrapedVessel) -> str:
        """Calculate risk level from available data"""
        if vessel.is_sanctioned_flag:
            return "critical"
        if vessel.is_shadow_fleet_flag:
            return "high"
        return "low"

    def _calculate_dark_fleet_score(self, vessel: ScrapedVessel) -> float:
        """
        Calculate dark fleet score (0-100)

        Limited scoring since we don't have:
        - AIS gap history
        - Ownership data
        - STS transfer detection
        """
        score = 0

        # Sanctioned flag = high score
        if vessel.is_sanctioned_flag:
            score += 50

        # Shadow fleet flag = moderate score
        if vessel.is_shadow_fleet_flag:
            score += 30

        # Unknown or missing name
        if not vessel.name or vessel.name == "Unknown":
            score += 10

        # Very slow speed (potential loitering/STS)
        if vessel.speed is not None and vessel.speed < 1:
            score += 10

        return min(100, score)


async def main():
    """Test the vessel scraper"""
    scraper = VesselScraper()

    try:
        # Test single chokepoint
        print("Testing Red Sea scrape...")
        vessels = await scraper.get_vessels_at_chokepoint("red_sea")
        print(f"Found {len(vessels)} vessels at Red Sea")

        for v in vessels[:5]:
            print(f"  {v.mmsi}: {v.name} ({v.flag}) at {v.lat}, {v.lon}")

        # Test full collection
        print("\nCollecting all chokepoints...")
        data = await scraper.collect_all()
        print(f"Total vessels: {data['statistics']['total_vessels']}")
        print(f"Shadow fleet flags: {data['statistics']['shadow_fleet_flags']}")
        print(f"Sanctioned flags: {data['statistics']['sanctioned_flags']}")

    finally:
        await scraper.close()


if __name__ == "__main__":
    asyncio.run(main())
