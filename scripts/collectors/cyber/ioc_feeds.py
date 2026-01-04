"""
IOC/Threat Actor Intelligence Collector (OTX-style)
Correlates with news for APT tracking and campaign attribution

Sources (all FREE):
- AlienVault OTX (otx.alienvault.com) - UNLIMITED with key
- abuse.ch ThreatFox - No key required
- abuse.ch URLhaus - No key required
- abuse.ch MalwareBazaar - No key required
- abuse.ch Feodo Tracker - No key required
- Pulsedive - Free tier
- GreyNoise - 10/day unauth, unlimited with key
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import json
import hashlib

from ..base import BaseCollector
from ...config import get_config

logger = logging.getLogger(__name__)


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    YARA = "yara"


class ThreatType(Enum):
    MALWARE = "malware"
    BOTNET = "botnet"
    C2 = "c2"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    APT = "apt"
    SPAM = "spam"
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    """Indicator of Compromise"""
    value: str
    ioc_type: IOCType
    threat_type: ThreatType = ThreatType.UNKNOWN
    confidence: int = 50  # 0-100
    severity: str = "medium"  # low, medium, high, critical
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    country: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source: str = "unknown"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "threat_type": self.threat_type.value,
            "confidence": self.confidence,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "malware_family": self.malware_family,
            "threat_actor": self.threat_actor,
            "campaign": self.campaign,
            "country": self.country,
            "tags": self.tags,
            "references": self.references,
            "source": self.source,
        }


@dataclass
class ThreatActorProfile:
    """Aggregated threat actor information"""
    name: str
    aliases: List[str] = field(default_factory=list)
    country: Optional[str] = None
    motivation: Optional[str] = None  # espionage, financial, hacktivism, destruction
    targets: List[str] = field(default_factory=list)  # sectors/countries targeted
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK
    malware: List[str] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    last_activity: Optional[datetime] = None
    sources: List[str] = field(default_factory=list)


class IOCCollector(BaseCollector):
    """
    Collects IOCs from multiple threat intelligence feeds.
    Aggregates by threat actor/campaign for news correlation.
    """

    # Known APT groups and their country attribution (for correlation)
    APT_ATTRIBUTION = {
        # China
        "APT1": "CN", "APT10": "CN", "APT15": "CN", "APT17": "CN",
        "APT27": "CN", "APT30": "CN", "APT31": "CN", "APT40": "CN",
        "APT41": "CN", "Winnti": "CN", "Mustang Panda": "CN",
        "Volt Typhoon": "CN", "Salt Typhoon": "CN",
        # Russia
        "APT28": "RU", "APT29": "RU", "Sandworm": "RU", "Turla": "RU",
        "Gamaredon": "RU", "Fancy Bear": "RU", "Cozy Bear": "RU",
        "Evil Corp": "RU", "Midnight Blizzard": "RU",
        # North Korea
        "APT37": "KP", "APT38": "KP", "Lazarus": "KP", "Kimsuky": "KP",
        "BlueNoroff": "KP", "Andariel": "KP",
        # Iran
        "APT33": "IR", "APT34": "IR", "APT35": "IR", "APT39": "IR",
        "MuddyWater": "IR", "Charming Kitten": "IR", "OilRig": "IR",
        # Other
        "DarkSide": "RU", "REvil": "RU", "Conti": "RU", "LockBit": "RU",
        "BlackCat": "RU", "Cl0p": "RU",
    }

    def __init__(self):
        self.config = get_config()
        self.session: Optional[aiohttp.ClientSession] = None
        self.iocs: List[IOC] = []
        self.threat_actors: Dict[str, ThreatActorProfile] = {}
        self.seen_hashes: Set[str] = set()  # Deduplication

    async def init_session(self):
        """Initialize aiohttp session"""
        if self.session is None:
            # Use standard browser User-Agent - some APIs block custom agents
            # NOTE: Don't set Content-Type in session headers - let aiohttp set it
            # based on the request type (json= vs data=)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json",
            }
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60),
                headers=headers
            )

    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    def _dedupe_key(self, ioc: IOC) -> str:
        """Generate deduplication key for IOC"""
        return hashlib.md5(f"{ioc.ioc_type.value}:{ioc.value}".encode()).hexdigest()

    # =========================================================================
    # ALIENVAULT OTX (Primary - Unlimited with key)
    # =========================================================================

    async def fetch_otx_pulses(
        self,
        modified_since: Optional[datetime] = None,
        limit: int = 50
    ) -> List[IOC]:
        """
        Fetch recent pulses from AlienVault OTX

        Free tier: UNLIMITED with API key
        Contains: IOCs, malware, threat actors, campaigns
        """
        api_key = self.config.cyber_ioc.otx_api_key
        if not api_key:
            logger.warning("OTX API key not configured")
            return []

        await self.init_session()

        # Get subscribed pulses
        url = f"{self.config.cyber_ioc.otx_base_url}/pulses/subscribed"
        headers = {"X-OTX-API-KEY": api_key}
        params = {"limit": limit}

        if modified_since:
            params["modified_since"] = modified_since.isoformat()

        results = []

        try:
            async with self.session.get(url, headers=headers, params=params) as resp:
                if resp.status != 200:
                    logger.error(f"OTX error: {resp.status}")
                    return []

                data = await resp.json()

                for pulse in data.get("results", []):
                    # Extract threat actor/campaign info
                    threat_actor = None
                    campaign = pulse.get("name", "")

                    for tag in pulse.get("tags", []):
                        tag_upper = tag.upper()
                        if tag_upper in self.APT_ATTRIBUTION:
                            threat_actor = tag_upper
                            break

                    # Process indicators
                    for indicator in pulse.get("indicators", []):
                        ioc_type = self._map_otx_type(indicator.get("type", ""))
                        if not ioc_type:
                            continue

                        ioc = IOC(
                            value=indicator.get("indicator", ""),
                            ioc_type=ioc_type,
                            threat_type=self._infer_threat_type(pulse, indicator),
                            confidence=70,
                            first_seen=self._parse_datetime(indicator.get("created")),
                            malware_family=pulse.get("malware_family"),
                            threat_actor=threat_actor,
                            campaign=campaign,
                            country=self.APT_ATTRIBUTION.get(threat_actor) if threat_actor else None,
                            tags=pulse.get("tags", []),
                            references=pulse.get("references", []),
                            source="otx",
                            raw_data={"pulse_id": pulse.get("id")},
                        )

                        key = self._dedupe_key(ioc)
                        if key not in self.seen_hashes:
                            self.seen_hashes.add(key)
                            results.append(ioc)

                logger.info(f"OTX: Fetched {len(results)} IOCs from {len(data.get('results', []))} pulses")

        except Exception as e:
            logger.error(f"OTX fetch error: {e}")

        return results

    def _map_otx_type(self, otx_type: str) -> Optional[IOCType]:
        """Map OTX indicator type to IOCType"""
        mapping = {
            "IPv4": IOCType.IP,
            "IPv6": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.DOMAIN,
            "URL": IOCType.URL,
            "FileHash-MD5": IOCType.HASH_MD5,
            "FileHash-SHA1": IOCType.HASH_SHA1,
            "FileHash-SHA256": IOCType.HASH_SHA256,
            "email": IOCType.EMAIL,
            "CVE": IOCType.CVE,
            "YARA": IOCType.YARA,
        }
        return mapping.get(otx_type)

    def _infer_threat_type(self, pulse: Dict, indicator: Dict) -> ThreatType:
        """Infer threat type from pulse/indicator metadata"""
        tags = [t.lower() for t in pulse.get("tags", [])]
        name = pulse.get("name", "").lower()

        if any(x in tags or x in name for x in ["ransomware", "ransom"]):
            return ThreatType.RANSOMWARE
        if any(x in tags or x in name for x in ["apt", "espionage", "nation-state"]):
            return ThreatType.APT
        if any(x in tags or x in name for x in ["botnet", "bot"]):
            return ThreatType.BOTNET
        if any(x in tags or x in name for x in ["c2", "c&c", "command and control"]):
            return ThreatType.C2
        if any(x in tags or x in name for x in ["phishing", "phish"]):
            return ThreatType.PHISHING
        if any(x in tags or x in name for x in ["malware", "trojan", "rat"]):
            return ThreatType.MALWARE

        return ThreatType.UNKNOWN

    # =========================================================================
    # ABUSE.CH THREATFOX (No auth required)
    # =========================================================================

    async def fetch_threatfox(self, days: int = 7) -> List[IOC]:
        """
        Fetch recent IOCs from ThreatFox

        Free: No API key required
        Contains: Malware IOCs (IPs, domains, URLs, hashes)
        """
        await self.init_session()
        url = self.config.cyber_ioc.threatfox_url

        payload = {
            "query": "get_iocs",
            "days": days,
        }

        results = []

        try:
            async with self.session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.error(f"ThreatFox error: {resp.status}")
                    return []

                data = await resp.json()

                if data.get("query_status") != "ok":
                    logger.error(f"ThreatFox query failed: {data.get('query_status')}")
                    return []

                for item in data.get("data", []):
                    ioc_type = self._map_threatfox_type(item.get("ioc_type", ""))
                    if not ioc_type:
                        continue

                    # Map threat type
                    threat_type_str = item.get("threat_type", "").lower()
                    if "botnet" in threat_type_str:
                        threat_type = ThreatType.BOTNET
                    elif "c2" in threat_type_str or "payload" in threat_type_str:
                        threat_type = ThreatType.C2
                    else:
                        threat_type = ThreatType.MALWARE

                    ioc = IOC(
                        value=item.get("ioc", ""),
                        ioc_type=ioc_type,
                        threat_type=threat_type,
                        confidence=int(item.get("confidence_level", 50)),
                        first_seen=self._parse_datetime(item.get("first_seen")),
                        last_seen=self._parse_datetime(item.get("last_seen")),
                        malware_family=item.get("malware"),
                        tags=item.get("tags", []),
                        references=[item.get("reference")] if item.get("reference") else [],
                        source="threatfox",
                        raw_data=item,
                    )

                    key = self._dedupe_key(ioc)
                    if key not in self.seen_hashes:
                        self.seen_hashes.add(key)
                        results.append(ioc)

                logger.info(f"ThreatFox: Fetched {len(results)} IOCs")

        except Exception as e:
            logger.error(f"ThreatFox fetch error: {e}")

        return results

    def _map_threatfox_type(self, tf_type: str) -> Optional[IOCType]:
        """Map ThreatFox type to IOCType"""
        mapping = {
            "ip:port": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "md5_hash": IOCType.HASH_MD5,
            "sha1_hash": IOCType.HASH_SHA1,
            "sha256_hash": IOCType.HASH_SHA256,
        }
        return mapping.get(tf_type)

    # =========================================================================
    # ABUSE.CH URLHAUS (No auth required)
    # =========================================================================

    async def fetch_urlhaus(self, limit: int = 1000) -> List[IOC]:
        """
        Fetch malware URLs from URLhaus

        Free: No API key required
        Contains: Malware distribution URLs
        """
        await self.init_session()
        url = f"{self.config.cyber_ioc.urlhaus_url}/urls/recent/"

        results = []

        try:
            # URLhaus API requires POST with limit in body
            payload = {"limit": str(limit)}
            async with self.session.post(url, data=payload) as resp:
                if resp.status != 200:
                    logger.error(f"URLhaus error: {resp.status}")
                    return []

                data = await resp.json()

                for item in data.get("urls", []):
                    ioc = IOC(
                        value=item.get("url", ""),
                        ioc_type=IOCType.URL,
                        threat_type=ThreatType.MALWARE,
                        confidence=80,
                        first_seen=self._parse_datetime(item.get("date_added")),
                        malware_family=item.get("threat"),
                        tags=item.get("tags", []),
                        source="urlhaus",
                        raw_data=item,
                    )

                    key = self._dedupe_key(ioc)
                    if key not in self.seen_hashes:
                        self.seen_hashes.add(key)
                        results.append(ioc)

                logger.info(f"URLhaus: Fetched {len(results)} URLs")

        except Exception as e:
            logger.error(f"URLhaus fetch error: {e}")

        return results

    # =========================================================================
    # ABUSE.CH FEODO TRACKER (No auth required)
    # =========================================================================

    async def fetch_feodo(self) -> List[IOC]:
        """
        Fetch botnet C2 servers from Feodo Tracker

        Free: No API key required
        Contains: Botnet C2 IPs (Emotet, Dridex, TrickBot, QakBot, etc.)
        """
        await self.init_session()
        url = f"{self.config.cyber_ioc.feodo_url}/ipblocklist_recommended.json"

        results = []

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Feodo error: {resp.status}")
                    return []

                data = await resp.json()

                for item in data:
                    ioc = IOC(
                        value=item.get("ip_address", ""),
                        ioc_type=IOCType.IP,
                        threat_type=ThreatType.BOTNET,
                        confidence=90,
                        severity="high",
                        first_seen=self._parse_datetime(item.get("first_seen")),
                        last_seen=self._parse_datetime(item.get("last_online")),
                        malware_family=item.get("malware"),
                        country=item.get("country"),
                        source="feodo",
                        raw_data=item,
                    )

                    key = self._dedupe_key(ioc)
                    if key not in self.seen_hashes:
                        self.seen_hashes.add(key)
                        results.append(ioc)

                logger.info(f"Feodo: Fetched {len(results)} C2 IPs")

        except Exception as e:
            logger.error(f"Feodo fetch error: {e}")

        return results

    # =========================================================================
    # GREYNOISE (Scanner identification)
    # =========================================================================

    async def check_greynoise(self, ip: str) -> Optional[Dict]:
        """
        Check if IP is a known scanner via GreyNoise

        Free: 10/day unauth, unlimited with key
        Returns: Whether IP is mass-scanner (benign) or targeted (malicious)
        """
        api_key = self.config.cyber_ioc.greynoise_api_key
        await self.init_session()

        if api_key:
            url = f"{self.config.cyber_ioc.greynoise_base_url}/community/{ip}"
            headers = {"key": api_key}
        else:
            # Community endpoint (limited)
            url = f"https://api.greynoise.io/v3/community/{ip}"
            headers = {}

        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return {"noise": False, "riot": False}  # Not in database

        except Exception as e:
            logger.error(f"GreyNoise check error: {e}")

        return None

    # =========================================================================
    # AGGREGATION
    # =========================================================================

    async def collect_all(self, days: int = 7) -> List[IOC]:
        """Collect IOCs from all configured sources"""
        all_iocs = []

        # Run collectors concurrently
        tasks = [
            self.fetch_threatfox(days=days),
            self.fetch_urlhaus(limit=500),
            self.fetch_feodo(),
        ]

        # Add OTX if configured
        if self.config.cyber_ioc.otx_api_key:
            since = datetime.now(timezone.utc) - timedelta(days=days)
            tasks.append(self.fetch_otx_pulses(modified_since=since))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Collector error: {result}")
            elif isinstance(result, list):
                all_iocs.extend(result)

        self.iocs = all_iocs
        logger.info(f"Total IOCs collected: {len(all_iocs)}")

        return all_iocs

    def get_by_threat_actor(self, actor: str) -> List[IOC]:
        """Get IOCs associated with a threat actor"""
        return [ioc for ioc in self.iocs if ioc.threat_actor and actor.lower() in ioc.threat_actor.lower()]

    def get_by_country(self, country_code: str) -> List[IOC]:
        """Get IOCs attributed to a country"""
        return [ioc for ioc in self.iocs if ioc.country == country_code]

    def get_by_malware(self, malware: str) -> List[IOC]:
        """Get IOCs for a malware family"""
        return [ioc for ioc in self.iocs if ioc.malware_family and malware.lower() in ioc.malware_family.lower()]

    def get_stats(self) -> Dict:
        """Get statistics on collected IOCs"""
        stats = {
            "total": len(self.iocs),
            "by_type": {},
            "by_threat_type": {},
            "by_source": {},
            "by_country": {},
            "malware_families": {},
            "threat_actors": set(),
        }

        for ioc in self.iocs:
            # By IOC type
            type_key = ioc.ioc_type.value
            stats["by_type"][type_key] = stats["by_type"].get(type_key, 0) + 1

            # By threat type
            threat_key = ioc.threat_type.value
            stats["by_threat_type"][threat_key] = stats["by_threat_type"].get(threat_key, 0) + 1

            # By source
            stats["by_source"][ioc.source] = stats["by_source"].get(ioc.source, 0) + 1

            # By country
            if ioc.country:
                stats["by_country"][ioc.country] = stats["by_country"].get(ioc.country, 0) + 1

            # Malware families
            if ioc.malware_family:
                stats["malware_families"][ioc.malware_family] = stats["malware_families"].get(ioc.malware_family, 0) + 1

            # Threat actors
            if ioc.threat_actor:
                stats["threat_actors"].add(ioc.threat_actor)

        stats["threat_actors"] = list(stats["threat_actors"])
        return stats

    def _parse_datetime(self, value: Optional[str]) -> Optional[datetime]:
        """Parse datetime string"""
        if not value:
            return None
        try:
            # Try common formats
            for fmt in [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d",
            ]:
                try:
                    return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        except Exception:
            pass
        return None


# Convenience function
async def collect_iocs(days: int = 7) -> List[IOC]:
    """Collect IOCs from all sources"""
    collector = IOCCollector()
    try:
        return await collector.collect_all(days=days)
    finally:
        await collector.close()
