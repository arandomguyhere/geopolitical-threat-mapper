"""
Infrastructure Exposure Collector (Shodan-style)
Maps vulnerable systems, exposed services, and attack surface by country/region

Sources:
- Shodan (api.shodan.io) - Free: 100 results/search
- Criminal IP (criminalip.io) - Free: Limited credits
- LeakIX (leakix.net) - Free tier
- ZoomEye (zoomeye.org) - Free: 20/month
- Netlas (netlas.io) - Free: 50/month
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json

from ..base import BaseCollector
from ...config import get_config

logger = logging.getLogger(__name__)


@dataclass
class ExposedService:
    """Represents an exposed service/device"""
    ip: str
    port: int
    protocol: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[int] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CountryExposure:
    """Aggregated exposure data for a country"""
    country_code: str
    country_name: str
    total_exposed: int = 0
    critical_vulns: int = 0
    exposed_ics_scada: int = 0
    exposed_databases: int = 0
    exposed_webcams: int = 0
    exposed_rdp: int = 0
    exposed_ssh: int = 0
    top_services: Dict[str, int] = field(default_factory=dict)
    top_vulns: Dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization (UI-compatible field names)"""
        return {
            "country_code": self.country_code,
            "country_name": self.country_name,
            "total_exposed": self.total_exposed,
            "critical_vulns": self.critical_vulns,
            "exposed_ics_scada": self.exposed_ics_scada,
            "ics_count": self.exposed_ics_scada,  # UI alias
            "exposed_databases": self.exposed_databases,
            "exposed_webcams": self.exposed_webcams,
            "exposed_rdp": self.exposed_rdp,
            "exposed_ssh": self.exposed_ssh,
            "top_services": self.top_services,
            "top_vulns": self.top_vulns,
            "risk_score": self.risk_score,
            "threat_score": self.risk_score,  # UI alias
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }


class InfrastructureCollector(BaseCollector):
    """
    Collects infrastructure exposure data from multiple sources.
    Aggregates by country for geopolitical threat mapping.
    """

    # Strategic queries for geopolitical relevance
    STRATEGIC_QUERIES = {
        "ics_scada": [
            "port:502 modbus",
            "port:102 s7",
            "scada",
            "ics",
            '"Schneider Electric"',
            '"Siemens" port:102',
        ],
        "critical_infra": [
            "port:1911 niagara",
            "port:47808 bacnet",
            "port:20000 dnp3",
            '"power grid"',
            '"water treatment"',
        ],
        "exposed_databases": [
            "port:27017 mongodb",
            "port:9200 elasticsearch",
            "port:6379 redis",
            "port:5432 postgresql",
            "port:3306 mysql",
        ],
        "remote_access": [
            "port:3389 rdp",
            "port:5900 vnc",
            "port:22 ssh",
            "port:23 telnet",
        ],
        "webcams": [
            "webcam",
            "netcam",
            "ip camera",
            "hikvision",
            "dahua",
        ],
        "military_gov": [
            "org:military",
            "org:government",
            "org:defense",
            ".mil",
            ".gov",
        ],
    }

    # Countries of geopolitical interest
    PRIORITY_COUNTRIES = [
        "CN", "RU", "US", "IR", "KP", "UA", "TW", "IL", "SA", "AE",
        "PK", "IN", "BY", "SY", "VE", "CU", "MM", "AF", "IQ", "YE"
    ]

    def __init__(self):
        self.config = get_config()
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[ExposedService] = []
        self.country_stats: Dict[str, CountryExposure] = {}
        self._shodan_invalid = False  # Track if Shodan key already failed

    async def init_session(self):
        """Initialize aiohttp session"""
        if self.session is None:
            headers = {
                "User-Agent": "GeopoliticalThreatMapper/1.0 (Security Research)",
                "Accept": "application/json",
            }
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers=headers
            )

    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    # =========================================================================
    # SHODAN
    # =========================================================================

    async def query_shodan(
        self,
        query: str,
        country: Optional[str] = None,
        limit: int = 100
    ) -> List[ExposedService]:
        """
        Query Shodan API

        Free tier limits:
        - 100 results per search
        - 1 query credit per search with filters
        - No streaming/bulk access
        """
        api_key = self.config.cyber_infrastructure.shodan_api_key
        if not api_key:
            logger.warning("Shodan API key not configured")
            return []

        # Skip if we already know the key is invalid
        if self._shodan_invalid:
            return []

        await self.init_session()

        # Add country filter if specified
        if country:
            query = f"{query} country:{country}"

        url = f"{self.config.cyber_infrastructure.shodan_base_url}/shodan/host/search"
        params = {
            "key": api_key,
            "query": query,
        }

        try:
            async with self.session.get(url, params=params) as resp:
                if resp.status == 401:
                    logger.error("Shodan: Invalid API key - skipping further queries")
                    self._shodan_invalid = True
                    return []
                if resp.status == 402:
                    logger.warning("Shodan: Query credits exhausted")
                    return []
                if resp.status != 200:
                    logger.error(f"Shodan error: {resp.status}")
                    return []

                data = await resp.json()
                results = []

                for match in data.get("matches", [])[:limit]:
                    service = ExposedService(
                        ip=match.get("ip_str", ""),
                        port=match.get("port", 0),
                        protocol=match.get("transport", "tcp"),
                        service=match.get("_shodan", {}).get("module", "unknown"),
                        product=match.get("product"),
                        version=match.get("version"),
                        country=match.get("location", {}).get("country_name"),
                        country_code=match.get("location", {}).get("country_code"),
                        city=match.get("location", {}).get("city"),
                        asn=match.get("asn"),
                        org=match.get("org"),
                        isp=match.get("isp"),
                        vulnerabilities=list(match.get("vulns", {}).keys()),
                        tags=match.get("tags", []),
                        source="shodan",
                        raw_data=match,
                    )
                    results.append(service)

                logger.info(f"Shodan: Found {len(results)} results for '{query}'")
                return results

        except Exception as e:
            logger.error(f"Shodan query error: {e}")
            return []

    async def get_shodan_host(self, ip: str) -> Optional[Dict]:
        """Get detailed info for a specific IP from Shodan"""
        api_key = self.config.cyber_infrastructure.shodan_api_key
        if not api_key:
            return None

        await self.init_session()
        url = f"{self.config.cyber_infrastructure.shodan_base_url}/shodan/host/{ip}"
        params = {"key": api_key}

        try:
            async with self.session.get(url, params=params) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error(f"Shodan host lookup error: {e}")
        return None

    # =========================================================================
    # CRIMINAL IP
    # =========================================================================

    async def query_criminal_ip(
        self,
        query: str,
        limit: int = 100
    ) -> List[ExposedService]:
        """
        Query Criminal IP API

        Free tier: Limited credits, 2 searches/day unauthenticated
        Combines Shodan + GreyNoise + VirusTotal functionality
        """
        api_key = self.config.cyber_infrastructure.criminal_ip_api_key
        if not api_key:
            logger.warning("Criminal IP API key not configured")
            return []

        await self.init_session()
        url = f"{self.config.cyber_infrastructure.criminal_ip_base_url}/v1/asset/search"

        headers = {"x-api-key": api_key}
        params = {"query": query, "offset": 0}

        try:
            async with self.session.get(url, headers=headers, params=params) as resp:
                if resp.status != 200:
                    logger.error(f"Criminal IP error: {resp.status}")
                    return []

                data = await resp.json()
                results = []

                for item in data.get("data", {}).get("result", [])[:limit]:
                    service = ExposedService(
                        ip=item.get("ip", ""),
                        port=item.get("open_port_no", 0),
                        protocol="tcp",
                        service=item.get("product", "unknown"),
                        product=item.get("product"),
                        version=item.get("version"),
                        country=item.get("country"),
                        country_code=item.get("country_code"),
                        city=item.get("city"),
                        asn=item.get("as_no"),
                        org=item.get("as_name"),
                        tags=item.get("tags", []),
                        source="criminal_ip",
                        raw_data=item,
                    )
                    results.append(service)

                logger.info(f"Criminal IP: Found {len(results)} results")
                return results

        except Exception as e:
            logger.error(f"Criminal IP query error: {e}")
            return []

    # =========================================================================
    # LEAKIX
    # =========================================================================

    async def query_leakix(
        self,
        query: str,
        limit: int = 100
    ) -> List[ExposedService]:
        """
        Query LeakIX API

        Free tier available - focuses on exposed data and misconfigurations
        """
        api_key = self.config.cyber_infrastructure.leakix_api_key
        if not api_key:
            logger.warning("LeakIX API key not configured")
            return []

        await self.init_session()
        url = f"{self.config.cyber_infrastructure.leakix_base_url}/search"

        headers = {
            "api-key": api_key,
            "Accept": "application/json",
        }
        params = {"scope": "leak", "q": query}

        try:
            async with self.session.get(url, headers=headers, params=params) as resp:
                if resp.status != 200:
                    logger.error(f"LeakIX error: {resp.status}")
                    return []

                data = await resp.json()
                results = []

                for item in data[:limit]:
                    service = ExposedService(
                        ip=item.get("ip", ""),
                        port=item.get("port", 0),
                        protocol=item.get("protocol", "tcp"),
                        service=item.get("service", "unknown"),
                        country_code=item.get("geoip", {}).get("country_iso_code"),
                        country=item.get("geoip", {}).get("country_name"),
                        city=item.get("geoip", {}).get("city_name"),
                        asn=item.get("network", {}).get("asn"),
                        org=item.get("network", {}).get("organization_name"),
                        tags=item.get("tags", []),
                        source="leakix",
                        raw_data=item,
                    )
                    results.append(service)

                logger.info(f"LeakIX: Found {len(results)} results")
                return results

        except Exception as e:
            logger.error(f"LeakIX query error: {e}")
            return []

    # =========================================================================
    # AGGREGATION
    # =========================================================================

    async def collect_country_exposure(
        self,
        country_code: str,
        categories: Optional[List[str]] = None
    ) -> CountryExposure:
        """
        Collect exposure data for a specific country across all categories
        """
        if categories is None:
            categories = list(self.STRATEGIC_QUERIES.keys())

        exposure = CountryExposure(
            country_code=country_code,
            country_name=country_code,  # Will be enriched
        )

        all_results: List[ExposedService] = []

        for category in categories:
            queries = self.STRATEGIC_QUERIES.get(category, [])
            for query in queries[:2]:  # Limit queries to conserve credits
                # Try Shodan first (most comprehensive)
                results = await self.query_shodan(query, country=country_code, limit=50)
                all_results.extend(results)

                # Rate limit between queries
                await asyncio.sleep(1)

        # Aggregate statistics
        exposure.total_exposed = len(all_results)

        for result in all_results:
            # Count vulnerabilities
            exposure.critical_vulns += len(result.vulnerabilities)

            # Count by category
            service_lower = (result.service or "").lower()
            if any(x in service_lower for x in ["modbus", "s7", "scada", "ics"]):
                exposure.exposed_ics_scada += 1
            elif any(x in service_lower for x in ["mongo", "elastic", "redis", "mysql", "postgres"]):
                exposure.exposed_databases += 1
            elif any(x in service_lower for x in ["webcam", "camera", "hikvision", "dahua"]):
                exposure.exposed_webcams += 1
            elif result.port == 3389:
                exposure.exposed_rdp += 1
            elif result.port == 22:
                exposure.exposed_ssh += 1

            # Track top services
            if result.service:
                exposure.top_services[result.service] = exposure.top_services.get(result.service, 0) + 1

            # Track top vulns
            for vuln in result.vulnerabilities:
                exposure.top_vulns[vuln] = exposure.top_vulns.get(vuln, 0) + 1

        # Calculate risk score (0-100)
        exposure.risk_score = self._calculate_risk_score(exposure)
        exposure.last_updated = datetime.now(timezone.utc)

        return exposure

    def _calculate_risk_score(self, exposure: CountryExposure) -> float:
        """Calculate a risk score based on exposure metrics"""
        score = 0.0

        # Weight ICS/SCADA heavily (critical infrastructure)
        score += min(exposure.exposed_ics_scada * 10, 30)

        # Exposed databases
        score += min(exposure.exposed_databases * 2, 15)

        # Critical vulnerabilities
        score += min(exposure.critical_vulns * 0.5, 25)

        # Remote access
        score += min(exposure.exposed_rdp * 0.5, 10)
        score += min(exposure.exposed_ssh * 0.1, 5)

        # Webcams (surveillance concern)
        score += min(exposure.exposed_webcams * 0.2, 5)

        # Total exposure
        score += min(exposure.total_exposed * 0.01, 10)

        return min(score, 100.0)

    async def collect_all_priority_countries(self) -> Dict[str, CountryExposure]:
        """Collect exposure data for all priority countries"""
        results = {}

        for country in self.PRIORITY_COUNTRIES:
            logger.info(f"Collecting exposure data for {country}...")
            exposure = await self.collect_country_exposure(country)
            results[country] = exposure

            # Rate limit between countries
            await asyncio.sleep(2)

        self.country_stats = results
        return results

    def to_geojson(self) -> Dict:
        """Export country exposure data as GeoJSON for mapping"""
        features = []

        for code, exposure in self.country_stats.items():
            feature = {
                "type": "Feature",
                "properties": {
                    "country_code": code,
                    "country_name": exposure.country_name,
                    "total_exposed": exposure.total_exposed,
                    "critical_vulns": exposure.critical_vulns,
                    "exposed_ics_scada": exposure.exposed_ics_scada,
                    "exposed_databases": exposure.exposed_databases,
                    "risk_score": exposure.risk_score,
                    "last_updated": exposure.last_updated.isoformat(),
                },
                "geometry": None,  # Will be filled by map layer
            }
            features.append(feature)

        return {
            "type": "FeatureCollection",
            "features": features,
        }


# Convenience function
async def collect_infrastructure(countries: Optional[List[str]] = None) -> Dict[str, CountryExposure]:
    """Collect infrastructure exposure data"""
    collector = InfrastructureCollector()
    try:
        if countries:
            results = {}
            for country in countries:
                results[country] = await collector.collect_country_exposure(country)
            return results
        else:
            return await collector.collect_all_priority_countries()
    finally:
        await collector.close()
