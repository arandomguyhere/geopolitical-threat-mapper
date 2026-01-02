"""
Aviation Collector - Multi-Source Aircraft Tracking

Real-time aircraft tracking for situational awareness:
- Military aircraft detection
- ADIZ violations
- Unusual traffic patterns
- Chokepoint monitoring

Sources (in priority order):
1. Airplanes.Live - Free, unfiltered ADS-B data
2. ADS-B Exchange - Free tier available
3. OpenSky Network - Fallback (auth required since 2025)
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

import aiohttp

from ..base import BaseCollector

logger = logging.getLogger(__name__)


class AircraftCategory(Enum):
    """Aircraft category classification"""
    MILITARY = "military"
    GOVERNMENT = "government"
    CARGO = "cargo"
    PASSENGER = "passenger"
    PRIVATE = "private"
    HELICOPTER = "helicopter"
    UNKNOWN = "unknown"


# Military aircraft ICAO24 prefixes by country
# These are approximate and not exhaustive
MILITARY_PREFIXES = {
    "US": ["ae", "af", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad"],
    "RU": ["15", "16"],
    "CN": ["78", "79", "7a", "7b", "7c"],
    "GB": ["43"],
    "FR": ["39"],
    "DE": ["3f"],
    "IL": ["73"],
    "TW": ["89"],
    "JP": ["84"],
    "KR": ["71"],
}

# Known military callsign patterns
MILITARY_CALLSIGNS = [
    "FORTE", "DUKE", "JAKE", "EVIL", "REAPER", "DOOM", "DARK",
    "RCH", "REACH", "IRON", "STEEL", "KNIFE", "VALOR", "HAVOC",
    "VIPER", "COBRA", "HAWK", "EAGLE", "ATLAS", "BOXER", "CARGO",
    "NATO", "USAF", "NAVY", "ARMY", "COAST", "RAF", "GAF", "FAF",
]

# Special mission aircraft (reconnaissance, tankers, AWACS)
SPECIAL_MISSION_TYPES = [
    "RC-135", "EP-3", "P-8", "E-3", "E-8", "KC-135", "KC-10", "KC-46",
    "RQ-4", "MQ-9", "MQ-4", "U-2", "E-2", "P-3", "Boeing E-7",
    "Beech MC-12", "RC-12", "DHC-8", "Bombardier", "Gulfstream",
]


@dataclass
class Aircraft:
    """Aircraft data from aviation sources"""
    icao24: str
    callsign: Optional[str] = None
    origin_country: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    altitude: Optional[float] = None  # meters
    velocity: Optional[float] = None  # m/s
    heading: Optional[float] = None  # degrees
    vertical_rate: Optional[float] = None  # m/s
    on_ground: bool = False
    last_contact: Optional[datetime] = None

    # Classification
    category: AircraftCategory = AircraftCategory.UNKNOWN
    is_military: bool = False
    is_special_mission: bool = False

    # Context
    region: Optional[str] = None
    squawk: Optional[str] = None  # transponder code
    source: str = "unknown"  # Which API provided this data


@dataclass
class AviationAnomaly:
    """Aviation anomaly detection"""
    anomaly_type: str  # military_surge, unusual_pattern, gnss_anomaly, etc.
    region: str
    description: str
    aircraft_count: int = 0
    aircraft_ids: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    severity: str = "medium"


class OpenSkyCollector(BaseCollector):
    """
    Multi-source aviation collector with fallback support

    Primary: Airplanes.Live (free, unfiltered)
    Secondary: ADS-B Exchange API
    Tertiary: OpenSky Network (requires OAuth2 since March 2025)

    API docs:
    - https://airplanes.live/api-guide/
    - https://www.adsbexchange.com/data/
    - https://openskynetwork.github.io/opensky-api/
    """

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        adsbx_api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        self.username = username
        self.password = password
        self.adsbx_api_key = adsbx_api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session: Optional[aiohttp.ClientSession] = None

        # API endpoints
        self.sources = {
            "airplanes_live": "https://api.airplanes.live/v2",
            "adsbx": "https://adsbexchange.com/api/aircraft/v2",
            "opensky": "https://opensky-network.org/api",
        }

        # Track which source is working
        self.active_source: Optional[str] = None

        # For backwards compatibility
        self.base_url = self.sources["airplanes_live"]

        # Chokepoint bounding boxes
        self.chokepoints = {
            "baltic_sea": (53.0, 66.0, 9.0, 30.0),  # lamin, lamax, lomin, lomax
            "black_sea": (40.0, 47.0, 27.0, 42.0),
            "red_sea": (12.0, 30.0, 32.0, 44.0),
            "taiwan_strait": (21.0, 26.0, 116.0, 122.0),
            "hormuz": (24.0, 28.0, 54.0, 58.0),
            "malacca": (0.0, 8.0, 98.0, 105.0),
            "south_china_sea": (5.0, 25.0, 105.0, 120.0),
            "kaliningrad": (54.0, 56.0, 19.0, 23.0),  # GPS jamming hotspot
        }

        # Cache for tracking
        self._last_states: Dict[str, Aircraft] = {}
        self._military_cache: Dict[str, List[str]] = {}  # region -> icao24 list

    async def init_session(self):
        """Initialize HTTP session"""
        headers = {
            "User-Agent": "ThreatMapper/1.0 (research)",
            "Accept": "application/json",
        }

        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            headers=headers,
        )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    def _classify_aircraft(self, icao24: str, callsign: Optional[str]) -> Tuple[AircraftCategory, bool, bool]:
        """Classify aircraft as military, special mission, etc."""
        is_military = False
        is_special = False
        category = AircraftCategory.UNKNOWN

        icao_prefix = icao24[:2].lower() if icao24 else ""
        callsign_upper = (callsign or "").upper().strip()

        # Check military prefixes
        for country, prefixes in MILITARY_PREFIXES.items():
            if icao_prefix in prefixes:
                is_military = True
                category = AircraftCategory.MILITARY
                break

        # Check military callsigns
        if callsign_upper:
            for pattern in MILITARY_CALLSIGNS:
                if pattern in callsign_upper:
                    is_military = True
                    category = AircraftCategory.MILITARY
                    break

            # Check special mission patterns
            for pattern in SPECIAL_MISSION_TYPES:
                if pattern.upper() in callsign_upper:
                    is_special = True
                    break

        return category, is_military, is_special

    def _get_region(self, lat: float, lon: float) -> Optional[str]:
        """Determine which region the aircraft is in"""
        for region, bbox in self.chokepoints.items():
            lamin, lamax, lomin, lomax = bbox
            if lamin <= lat <= lamax and lomin <= lon <= lomax:
                return region
        return None

    async def _fetch_airplanes_live(
        self,
        lamin: Optional[float] = None,
        lamax: Optional[float] = None,
        lomin: Optional[float] = None,
        lomax: Optional[float] = None,
    ) -> List[Aircraft]:
        """Fetch from Airplanes.Live API (free, unfiltered)"""
        if not self.session:
            await self.init_session()

        # Airplanes.Live uses point + radius or bounds
        if all(v is not None for v in [lamin, lamax, lomin, lomax]):
            # Calculate center point and radius
            center_lat = (lamin + lamax) / 2
            center_lon = (lomin + lomax) / 2
            # Approximate radius in nautical miles
            lat_diff = (lamax - lamin) * 60  # degrees to nm
            lon_diff = (lomax - lomin) * 60 * 0.7  # rough cos adjustment
            radius = max(lat_diff, lon_diff) / 2

            url = f"{self.sources['airplanes_live']}/point/{center_lat}/{center_lon}/{int(radius)}"
        else:
            # Get all military aircraft
            url = f"{self.sources['airplanes_live']}/mil"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    self.active_source = "airplanes_live"
                    return self._parse_airplanes_live(data, lamin, lamax, lomin, lomax)
                else:
                    logger.warning(f"Airplanes.Live returned {response.status}")
                    return []
        except Exception as e:
            logger.warning(f"Airplanes.Live error: {e}")
            return []

    def _parse_airplanes_live(
        self,
        data: Dict[str, Any],
        lamin: Optional[float] = None,
        lamax: Optional[float] = None,
        lomin: Optional[float] = None,
        lomax: Optional[float] = None,
    ) -> List[Aircraft]:
        """Parse Airplanes.Live response format"""
        aircraft_list = []

        for ac in data.get("ac", []):
            lat = ac.get("lat")
            lon = ac.get("lon")

            if lat is None or lon is None:
                continue

            # Filter by bounds if specified
            if all(v is not None for v in [lamin, lamax, lomin, lomax]):
                if not (lamin <= lat <= lamax and lomin <= lon <= lomax):
                    continue

            icao24 = ac.get("hex", "").lower()
            callsign = ac.get("flight", "").strip() if ac.get("flight") else None

            category, is_military, is_special = self._classify_aircraft(icao24, callsign)
            region = self._get_region(lat, lon)

            aircraft = Aircraft(
                icao24=icao24,
                callsign=callsign,
                origin_country=ac.get("r", ""),  # registration country
                lat=lat,
                lon=lon,
                altitude=ac.get("alt_baro") or ac.get("alt_geom"),
                velocity=ac.get("gs"),  # ground speed in knots
                heading=ac.get("track"),
                vertical_rate=ac.get("baro_rate"),
                on_ground=ac.get("alt_baro") == "ground",
                category=category,
                is_military=is_military or ac.get("dbFlags", 0) & 1,  # dbFlags bit 0 = military
                is_special_mission=is_special,
                region=region,
                squawk=ac.get("squawk"),
                source="airplanes_live",
            )

            # Parse last contact time
            seen = ac.get("seen")
            if seen is not None:
                try:
                    aircraft.last_contact = datetime.utcnow() - timedelta(seconds=float(seen))
                except (ValueError, TypeError):
                    pass

            aircraft_list.append(aircraft)
            self._last_states[aircraft.icao24] = aircraft

        return aircraft_list

    async def _fetch_opensky(
        self,
        lamin: Optional[float] = None,
        lamax: Optional[float] = None,
        lomin: Optional[float] = None,
        lomax: Optional[float] = None,
    ) -> List[Aircraft]:
        """Fetch from OpenSky Network API (fallback)"""
        if not self.session:
            await self.init_session()

        url = f"{self.sources['opensky']}/states/all"
        params = {}

        if all(v is not None for v in [lamin, lamax, lomin, lomax]):
            params = {
                "lamin": lamin,
                "lamax": lamax,
                "lomin": lomin,
                "lomax": lomax,
            }

        try:
            # OpenSky now requires OAuth2 for new accounts
            auth = None
            if self.username and self.password:
                auth = aiohttp.BasicAuth(self.username, self.password)

            async with self.session.get(url, params=params, auth=auth) as response:
                if response.status == 200:
                    data = await response.json()
                    self.active_source = "opensky"
                    return self._parse_opensky(data)
                elif response.status == 401:
                    logger.warning("OpenSky requires authentication (OAuth2 since March 2025)")
                    return []
                else:
                    logger.warning(f"OpenSky returned {response.status}")
                    return []
        except aiohttp.ClientConnectorError:
            logger.warning("OpenSky Network unreachable")
            return []
        except Exception as e:
            logger.warning(f"OpenSky error: {e}")
            return []

    def _parse_opensky(self, data: Dict[str, Any]) -> List[Aircraft]:
        """Parse OpenSky state vector format"""
        aircraft_list = []

        for state in data.get("states", []):
            if len(state) < 17:
                continue

            icao24 = state[0]
            callsign = state[1].strip() if state[1] else None
            lat = state[6]
            lon = state[5]

            if lat is None or lon is None:
                continue

            category, is_military, is_special = self._classify_aircraft(icao24, callsign)
            region = self._get_region(lat, lon)

            aircraft = Aircraft(
                icao24=icao24,
                callsign=callsign,
                origin_country=state[2],
                lat=lat,
                lon=lon,
                altitude=state[7] or state[13],
                velocity=state[9],
                heading=state[10],
                vertical_rate=state[11],
                on_ground=state[8] or False,
                category=category,
                is_military=is_military,
                is_special_mission=is_special,
                region=region,
                squawk=state[14],
                source="opensky",
            )

            if state[4]:
                try:
                    aircraft.last_contact = datetime.utcfromtimestamp(state[4])
                except (ValueError, TypeError):
                    pass

            aircraft_list.append(aircraft)
            self._last_states[aircraft.icao24] = aircraft

        return aircraft_list

    async def _get_states(
        self,
        lamin: Optional[float] = None,
        lamax: Optional[float] = None,
        lomin: Optional[float] = None,
        lomax: Optional[float] = None,
    ) -> List[Aircraft]:
        """Get current aircraft states with source fallback"""
        # Try sources in order
        sources_to_try = [
            ("airplanes_live", self._fetch_airplanes_live),
            ("opensky", self._fetch_opensky),
        ]

        for source_name, fetch_func in sources_to_try:
            try:
                aircraft = await fetch_func(lamin, lamax, lomin, lomax)
                if aircraft:
                    logger.debug(f"Using {source_name}: {len(aircraft)} aircraft")
                    return aircraft
            except Exception as e:
                logger.warning(f"{source_name} failed: {e}")
                continue

        logger.warning("All aviation sources failed")
        return []

    async def get_chokepoint_aircraft(self, region: str) -> List[Aircraft]:
        """Get aircraft in a specific chokepoint region"""
        if region not in self.chokepoints:
            logger.warning(f"Unknown region: {region}")
            return []

        lamin, lamax, lomin, lomax = self.chokepoints[region]
        aircraft = await self._get_states(lamin, lamax, lomin, lomax)

        # Tag with region
        for ac in aircraft:
            ac.region = region

        return aircraft

    async def get_military_aircraft(
        self,
        region: Optional[str] = None
    ) -> List[Aircraft]:
        """Get military aircraft, optionally filtered by region"""
        if region:
            aircraft = await self.get_chokepoint_aircraft(region)
        else:
            # Try to get military-specific feed from Airplanes.Live
            try:
                url = f"{self.sources['airplanes_live']}/mil"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        aircraft = self._parse_airplanes_live(data)
                    else:
                        aircraft = await self._get_states()
            except Exception:
                aircraft = await self._get_states()

        military = [ac for ac in aircraft if ac.is_military]

        # Update cache
        if region:
            self._military_cache[region] = [ac.icao24 for ac in military]

        return military

    async def get_special_mission_aircraft(self) -> List[Aircraft]:
        """Get reconnaissance, tankers, AWACS, and other special mission aircraft"""
        aircraft = await self._get_states()
        return [ac for ac in aircraft if ac.is_special_mission]

    async def detect_anomalies(self, region: str) -> List[AviationAnomaly]:
        """Detect aviation anomalies in a region"""
        anomalies = []
        aircraft = await self.get_chokepoint_aircraft(region)
        military = [ac for ac in aircraft if ac.is_military]
        special = [ac for ac in aircraft if ac.is_special_mission]

        # Military surge detection
        prev_count = len(self._military_cache.get(region, []))
        curr_count = len(military)

        if curr_count >= 20:  # Significant military presence
            anomalies.append(AviationAnomaly(
                anomaly_type="military_presence",
                region=region,
                description=f"High military aircraft activity: {curr_count} aircraft detected",
                aircraft_count=curr_count,
                aircraft_ids=[ac.icao24 for ac in military],
                severity="high" if curr_count >= 50 else "medium",
            ))

        if prev_count > 0 and curr_count > prev_count * 1.5:  # 50% surge
            anomalies.append(AviationAnomaly(
                anomaly_type="military_surge",
                region=region,
                description=f"Military surge detected: {prev_count} → {curr_count} aircraft",
                aircraft_count=curr_count,
                aircraft_ids=[ac.icao24 for ac in military],
                severity="high",
            ))

        # Special mission detection
        if special:
            anomalies.append(AviationAnomaly(
                anomaly_type="special_mission",
                region=region,
                description=f"Special mission aircraft detected: {', '.join(ac.callsign or ac.icao24 for ac in special)}",
                aircraft_count=len(special),
                aircraft_ids=[ac.icao24 for ac in special],
                severity="medium",
            ))

        # GNSS anomaly detection (squawk codes)
        gnss_issues = [ac for ac in aircraft if ac.squawk in ["7500", "7600", "7700"]]
        if gnss_issues:
            anomalies.append(AviationAnomaly(
                anomaly_type="emergency_squawk",
                region=region,
                description=f"Emergency squawk codes detected: {len(gnss_issues)} aircraft",
                aircraft_count=len(gnss_issues),
                aircraft_ids=[ac.icao24 for ac in gnss_issues],
                severity="critical",
            ))

        # Update cache
        self._military_cache[region] = [ac.icao24 for ac in military]

        return anomalies

    async def get_region_summary(self, region: str) -> Dict[str, Any]:
        """Get aviation summary for a chokepoint region"""
        aircraft = await self.get_chokepoint_aircraft(region)
        anomalies = await self.detect_anomalies(region)

        # Count by category
        category_counts = {}
        for ac in aircraft:
            cat = ac.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Count by origin country
        country_counts = {}
        for ac in aircraft:
            country = ac.origin_country or "Unknown"
            country_counts[country] = country_counts.get(country, 0) + 1

        military_count = sum(1 for ac in aircraft if ac.is_military)
        special_count = sum(1 for ac in aircraft if ac.is_special_mission)

        return {
            "region": region,
            "timestamp": datetime.utcnow().isoformat(),
            "source": self.active_source or "unknown",
            "total_aircraft": len(aircraft),
            "military_count": military_count,
            "special_mission_count": special_count,
            "category_breakdown": category_counts,
            "country_breakdown": dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "anomalies": [self._anomaly_to_dict(a) for a in anomalies],
            "anomaly_count": len(anomalies),
        }

    async def collect_all(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Collect aviation data for all or specified regions"""
        if regions is None:
            regions = list(self.chokepoints.keys())

        all_aircraft = []
        all_anomalies = []
        region_summaries = {}

        for region in regions:
            try:
                aircraft = await self.get_chokepoint_aircraft(region)
                all_aircraft.extend(aircraft)

                anomalies = await self.detect_anomalies(region)
                all_anomalies.extend(anomalies)

                summary = await self.get_region_summary(region)
                region_summaries[region] = summary

                # Rate limit protection
                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Error collecting aviation data for {region}: {e}")

        # Global military tracking
        all_military = [ac for ac in all_aircraft if ac.is_military]
        all_special = [ac for ac in all_aircraft if ac.is_special_mission]

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": self.active_source or "unknown",
            "aircraft": [self._aircraft_to_dict(ac) for ac in all_aircraft],
            "military_aircraft": [self._aircraft_to_dict(ac) for ac in all_military],
            "special_mission": [self._aircraft_to_dict(ac) for ac in all_special],
            "anomalies": [self._anomaly_to_dict(a) for a in all_anomalies],
            "region_summaries": region_summaries,
            "statistics": {
                "total_aircraft": len(all_aircraft),
                "military_count": len(all_military),
                "special_mission_count": len(all_special),
                "anomaly_count": len(all_anomalies),
                "regions_monitored": len(regions),
            }
        }

    def _aircraft_to_dict(self, aircraft: Aircraft) -> Dict[str, Any]:
        """Convert Aircraft to dictionary"""
        return {
            "icao24": aircraft.icao24,
            "callsign": aircraft.callsign,
            "origin_country": aircraft.origin_country,
            "lat": aircraft.lat,
            "lon": aircraft.lon,
            "altitude": aircraft.altitude,
            "velocity": aircraft.velocity,
            "heading": aircraft.heading,
            "vertical_rate": aircraft.vertical_rate,
            "on_ground": aircraft.on_ground,
            "last_contact": aircraft.last_contact.isoformat() if aircraft.last_contact else None,
            "category": aircraft.category.value,
            "is_military": aircraft.is_military,
            "is_special_mission": aircraft.is_special_mission,
            "region": aircraft.region,
            "squawk": aircraft.squawk,
            "source": aircraft.source,
        }

    def _anomaly_to_dict(self, anomaly: AviationAnomaly) -> Dict[str, Any]:
        """Convert AviationAnomaly to dictionary"""
        return {
            "anomaly_type": anomaly.anomaly_type,
            "region": anomaly.region,
            "description": anomaly.description,
            "aircraft_count": anomaly.aircraft_count,
            "aircraft_ids": anomaly.aircraft_ids,
            "detected_at": anomaly.detected_at.isoformat(),
            "severity": anomaly.severity,
        }
