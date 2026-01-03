"""
Attack Telemetry Collector (Shadowserver/DShield-style)
Real-time attack activity, honeypot data, and scan intelligence

Sources (all FREE):
- DShield/SANS ISC (isc.sans.edu) - API available
- Shadowserver (shadowserver.org) - Dashboard data
- FireHOL IP Lists (github.com/firehol) - No auth required
- DataPlane.org - No auth required
- CINS Army - No auth required
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import json

from ..base import BaseCollector
from ...config import get_config

logger = logging.getLogger(__name__)


class AttackType(Enum):
    SSH_BRUTE = "ssh_brute_force"
    RDP_BRUTE = "rdp_brute_force"
    TELNET_BRUTE = "telnet_brute_force"
    FTP_BRUTE = "ftp_brute_force"
    WEB_ATTACK = "web_attack"
    SQL_INJECTION = "sql_injection"
    DDOS = "ddos"
    SCAN = "port_scan"
    EXPLOIT = "exploit"
    MALWARE = "malware"
    SPAM = "spam"
    UNKNOWN = "unknown"


@dataclass
class AttackEvent:
    """Represents an attack event/observation"""
    source_ip: str
    target_port: int
    attack_type: AttackType
    protocol: str = "tcp"
    target_ip: Optional[str] = None
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_country: Optional[str] = None
    source_asn: Optional[int] = None
    source_org: Optional[str] = None
    payload: Optional[str] = None
    cve: Optional[str] = None
    signature: Optional[str] = None
    source: str = "unknown"
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackStats:
    """Aggregated attack statistics for a country/region"""
    country_code: str
    country_name: str = ""
    total_attacks: int = 0
    unique_sources: int = 0
    attacks_by_type: Dict[str, int] = field(default_factory=dict)
    attacks_by_port: Dict[int, int] = field(default_factory=dict)
    top_source_ips: List[str] = field(default_factory=list)
    top_asns: Dict[int, int] = field(default_factory=dict)
    trend: str = "stable"  # increasing, decreasing, stable
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BadIP:
    """Known malicious IP from blocklists"""
    ip: str
    lists: List[str] = field(default_factory=list)
    category: str = "unknown"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    country: Optional[str] = None
    asn: Optional[int] = None


class TelemetryCollector(BaseCollector):
    """
    Collects real-time attack telemetry from honeypot networks and blocklists.
    Aggregates by source country for geopolitical threat mapping.
    """

    # FireHOL blocklist URLs (no auth required)
    FIREHOL_LISTS = {
        "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "firehol_level3": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
        "firehol_abusers_30d": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_30d.netset",
        "spamhaus_drop": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
        "spamhaus_edrop": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset",
        "dshield": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
        "blocklist_de": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset",
    }

    # DataPlane feeds
    DATAPLANE_FEEDS = {
        "sshpwauth": "https://dataplane.org/sshpwauth.txt",
        "sipquery": "https://dataplane.org/sipquery.txt",
        "sipinvitation": "https://dataplane.org/sipinvitation.txt",
        "dnsrd": "https://dataplane.org/dnsrd.txt",
        "vncrfb": "https://dataplane.org/vncrfb.txt",
    }

    def __init__(self):
        self.config = get_config()
        self.session: Optional[aiohttp.ClientSession] = None
        self.events: List[AttackEvent] = []
        self.bad_ips: Dict[str, BadIP] = {}
        self.country_stats: Dict[str, AttackStats] = {}

    async def init_session(self):
        """Initialize aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60)
            )

    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    # =========================================================================
    # DSHIELD/SANS ISC
    # =========================================================================

    async def fetch_dshield_top_ips(self, limit: int = 100) -> List[AttackEvent]:
        """
        Fetch top attacking IPs from DShield

        Free: API available
        Contains: Top attacking IPs, ports, sources
        """
        await self.init_session()
        url = f"{self.config.cyber_telemetry.dshield_base_url}/topips/count/{limit}"

        results = []

        try:
            async with self.session.get(url, params={"json": ""}) as resp:
                if resp.status != 200:
                    logger.error(f"DShield error: {resp.status}")
                    return []

                data = await resp.json(content_type=None)

                for item in data:
                    event = AttackEvent(
                        source_ip=item.get("ip", ""),
                        target_port=0,  # Not specified in top IPs
                        attack_type=AttackType.SCAN,
                        count=item.get("count", 1),
                        source_country=item.get("geo"),
                        source_asn=item.get("asn"),
                        source="dshield",
                        raw_data=item,
                    )
                    results.append(event)

                logger.info(f"DShield: Fetched {len(results)} top IPs")

        except Exception as e:
            logger.error(f"DShield fetch error: {e}")

        return results

    async def fetch_dshield_top_ports(self) -> Dict[int, int]:
        """Fetch top targeted ports from DShield"""
        await self.init_session()
        url = f"{self.config.cyber_telemetry.dshield_base_url}/topports/records/50"

        try:
            async with self.session.get(url, params={"json": ""}) as resp:
                if resp.status != 200:
                    return {}

                data = await resp.json(content_type=None)
                return {int(item["port"]): int(item["count"]) for item in data}

        except Exception as e:
            logger.error(f"DShield ports error: {e}")
            return {}

    async def fetch_dshield_ip_info(self, ip: str) -> Optional[Dict]:
        """Get detailed info for a specific IP from DShield"""
        await self.init_session()
        url = f"{self.config.cyber_telemetry.dshield_base_url}/ip/{ip}"

        try:
            async with self.session.get(url, params={"json": ""}) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error(f"DShield IP lookup error: {e}")

        return None

    async def fetch_dshield_port_history(self, port: int, days: int = 30) -> List[Dict]:
        """Get attack history for a specific port"""
        await self.init_session()
        url = f"{self.config.cyber_telemetry.dshield_base_url}/port/{port}"

        try:
            async with self.session.get(url, params={"json": ""}) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error(f"DShield port history error: {e}")

        return []

    # =========================================================================
    # FIREHOL IP BLOCKLISTS
    # =========================================================================

    async def fetch_firehol_list(self, list_name: str) -> Set[str]:
        """
        Fetch IPs from a FireHOL blocklist

        Free: No auth required
        Contains: Curated malicious IP lists
        """
        if list_name not in self.FIREHOL_LISTS:
            logger.error(f"Unknown FireHOL list: {list_name}")
            return set()

        await self.init_session()
        url = self.FIREHOL_LISTS[list_name]
        ips = set()

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"FireHOL {list_name} error: {resp.status}")
                    return set()

                text = await resp.text()

                for line in text.strip().split("\n"):
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    # Handle CIDR notation
                    ip = line.split("/")[0]
                    if ip:
                        ips.add(ip)

                        # Update bad_ips index
                        if ip in self.bad_ips:
                            self.bad_ips[ip].lists.append(list_name)
                        else:
                            self.bad_ips[ip] = BadIP(
                                ip=ip,
                                lists=[list_name],
                                category=self._categorize_firehol_list(list_name),
                            )

                logger.info(f"FireHOL {list_name}: Loaded {len(ips)} IPs")

        except Exception as e:
            logger.error(f"FireHOL {list_name} fetch error: {e}")

        return ips

    def _categorize_firehol_list(self, list_name: str) -> str:
        """Categorize FireHOL list by threat type"""
        if "spam" in list_name.lower():
            return "spam"
        if "abuse" in list_name.lower():
            return "abuse"
        if "level1" in list_name:
            return "critical"
        if "level2" in list_name:
            return "high"
        if "level3" in list_name:
            return "medium"
        return "unknown"

    async def fetch_all_firehol(self) -> Dict[str, Set[str]]:
        """Fetch all FireHOL blocklists"""
        results = {}

        for list_name in self.FIREHOL_LISTS:
            results[list_name] = await self.fetch_firehol_list(list_name)
            await asyncio.sleep(0.5)  # Rate limiting

        return results

    # =========================================================================
    # DATAPLANE.ORG
    # =========================================================================

    async def fetch_dataplane_feed(self, feed_name: str) -> List[AttackEvent]:
        """
        Fetch attack data from DataPlane.org

        Free: No auth required
        Contains: SSH auth attempts, VNC, SIP attacks, DNS
        """
        if feed_name not in self.DATAPLANE_FEEDS:
            logger.error(f"Unknown DataPlane feed: {feed_name}")
            return []

        await self.init_session()
        url = self.DATAPLANE_FEEDS[feed_name]
        results = []

        # Map feed to attack type
        attack_type_map = {
            "sshpwauth": AttackType.SSH_BRUTE,
            "sipquery": AttackType.SCAN,
            "sipinvitation": AttackType.SCAN,
            "dnsrd": AttackType.SCAN,
            "vncrfb": AttackType.RDP_BRUTE,
        }

        port_map = {
            "sshpwauth": 22,
            "sipquery": 5060,
            "sipinvitation": 5060,
            "dnsrd": 53,
            "vncrfb": 5900,
        }

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"DataPlane {feed_name} error: {resp.status}")
                    return []

                text = await resp.text()

                for line in text.strip().split("\n"):
                    line = line.strip()
                    # Skip comments
                    if not line or line.startswith("#"):
                        continue

                    # Format: ASN|IP|date|count (varies by feed)
                    parts = line.split("|")
                    if len(parts) >= 2:
                        ip = parts[1].strip() if len(parts) > 1 else parts[0].strip()

                        event = AttackEvent(
                            source_ip=ip,
                            target_port=port_map.get(feed_name, 0),
                            attack_type=attack_type_map.get(feed_name, AttackType.UNKNOWN),
                            source_asn=int(parts[0]) if parts[0].isdigit() else None,
                            source=f"dataplane_{feed_name}",
                            raw_data={"line": line},
                        )
                        results.append(event)

                logger.info(f"DataPlane {feed_name}: Loaded {len(results)} events")

        except Exception as e:
            logger.error(f"DataPlane {feed_name} fetch error: {e}")

        return results

    async def fetch_all_dataplane(self) -> List[AttackEvent]:
        """Fetch all DataPlane feeds"""
        all_events = []

        for feed_name in self.DATAPLANE_FEEDS:
            events = await self.fetch_dataplane_feed(feed_name)
            all_events.extend(events)
            await asyncio.sleep(0.5)

        return all_events

    # =========================================================================
    # CINS ARMY
    # =========================================================================

    async def fetch_cins_army(self) -> Set[str]:
        """
        Fetch bad actor IPs from CINS Army

        Free: No auth required
        Contains: Known bad actors from honeypot network
        """
        await self.init_session()
        url = self.config.cyber_telemetry.cins_url
        ips = set()

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"CINS Army error: {resp.status}")
                    return set()

                text = await resp.text()

                for line in text.strip().split("\n"):
                    ip = line.strip()
                    if ip and not ip.startswith("#"):
                        ips.add(ip)

                        if ip in self.bad_ips:
                            self.bad_ips[ip].lists.append("cins_army")
                        else:
                            self.bad_ips[ip] = BadIP(
                                ip=ip,
                                lists=["cins_army"],
                                category="honeypot",
                            )

                logger.info(f"CINS Army: Loaded {len(ips)} IPs")

        except Exception as e:
            logger.error(f"CINS Army fetch error: {e}")

        return ips

    # =========================================================================
    # AGGREGATION
    # =========================================================================

    async def collect_all(self) -> Dict[str, Any]:
        """Collect telemetry from all sources"""
        results = {
            "events": [],
            "bad_ips": {},
            "top_ports": {},
            "blocklists": {},
        }

        # Collect attack events
        tasks = [
            self.fetch_dshield_top_ips(limit=100),
            self.fetch_all_dataplane(),
        ]

        event_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in event_results:
            if isinstance(result, Exception):
                logger.error(f"Collector error: {result}")
            elif isinstance(result, list):
                results["events"].extend(result)

        # Collect blocklists
        results["blocklists"] = await self.fetch_all_firehol()
        await self.fetch_cins_army()

        # Get top ports
        results["top_ports"] = await self.fetch_dshield_top_ports()

        # Store results
        self.events = results["events"]
        results["bad_ips"] = self.bad_ips

        logger.info(f"Telemetry collected: {len(self.events)} events, {len(self.bad_ips)} bad IPs")

        return results

    def check_ip(self, ip: str) -> Optional[BadIP]:
        """Check if an IP is in any blocklist"""
        return self.bad_ips.get(ip)

    def get_attack_stats_by_country(self) -> Dict[str, AttackStats]:
        """Aggregate attack statistics by source country"""
        stats: Dict[str, AttackStats] = {}

        for event in self.events:
            country = event.source_country or "UNKNOWN"

            if country not in stats:
                stats[country] = AttackStats(country_code=country)

            s = stats[country]
            s.total_attacks += event.count
            s.attacks_by_type[event.attack_type.value] = (
                s.attacks_by_type.get(event.attack_type.value, 0) + event.count
            )
            s.attacks_by_port[event.target_port] = (
                s.attacks_by_port.get(event.target_port, 0) + event.count
            )

            if len(s.top_source_ips) < 10 and event.source_ip not in s.top_source_ips:
                s.top_source_ips.append(event.source_ip)

            if event.source_asn:
                s.top_asns[event.source_asn] = s.top_asns.get(event.source_asn, 0) + 1

        self.country_stats = stats
        return stats

    def get_summary(self) -> Dict:
        """Get summary of telemetry data"""
        if not self.country_stats:
            self.get_attack_stats_by_country()

        return {
            "total_events": len(self.events),
            "total_bad_ips": len(self.bad_ips),
            "countries_attacking": len(self.country_stats),
            "top_attacking_countries": sorted(
                [(k, v.total_attacks) for k, v in self.country_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "blocklists_loaded": list(self.FIREHOL_LISTS.keys()) + ["cins_army"],
        }


# Convenience function
async def collect_telemetry() -> Dict[str, Any]:
    """Collect attack telemetry from all sources"""
    collector = TelemetryCollector()
    try:
        return await collector.collect_all()
    finally:
        await collector.close()
