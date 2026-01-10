"""
Multi-Layer Correlation Engine

Correlates events across:
- Cyber (infrastructure, IOCs, vulnerabilities)
- Maritime (AIS_Tracker)
- Aviation (OpenSky)
- GPS interference (GPSJAM)
- News (Google-News-Scraper)

Implements rules from correlation_rules.yaml
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
import yaml

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventSource(Enum):
    """Event source types"""
    CYBER = "cyber"
    MARITIME = "maritime"
    AVIATION = "aviation"
    GPS = "gps"
    NEWS = "news"
    FINANCIAL = "financial"  # Market data, commodities, prediction markets


@dataclass
class Event:
    """Normalized event from any source"""
    id: str
    source: EventSource
    event_type: str
    timestamp: datetime
    lat: Optional[float] = None
    lon: Optional[float] = None
    region: Optional[str] = None

    # Identifiers for matching
    entities: Dict[str, Any] = field(default_factory=dict)  # mmsi, imo, ip, domain, etc.

    # Event data
    severity: str = "medium"
    confidence: float = 0.5
    description: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Correlation:
    """A correlation between multiple events"""
    id: str
    rule_id: str
    rule_name: str
    events: List[Event]
    severity: AlertSeverity
    confidence: float
    description: str
    region: Optional[str] = None
    detected_at: datetime = field(default_factory=datetime.utcnow)
    actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatScore:
    """Composite threat score for a region"""
    region: str
    timestamp: datetime
    overall_score: float  # 0-100
    cyber_score: float
    maritime_score: float
    aviation_score: float
    gps_score: float
    news_score: float
    financial_score: float  # Market volatility, commodity spikes
    active_correlations: int
    trend: str  # increasing, stable, decreasing
    momentum: str = "stable"  # surging, rising, stable, declining


class CorrelationEngine:
    """
    Multi-source threat correlation engine

    Implements the correlation rules from config/correlation_rules.yaml
    to detect cross-domain threats.
    """

    def __init__(
        self,
        rules_path: Optional[str] = None,
        chokepoints_path: Optional[str] = None,
    ):
        self.rules: List[Dict[str, Any]] = []
        self.chokepoints: Dict[str, Dict[str, Any]] = {}
        self.scoring_config: Dict[str, Any] = {}
        self.thresholds: Dict[str, Any] = {}

        # Event buffer for correlation
        self.event_buffer: Dict[str, List[Event]] = {
            "cyber": [],
            "maritime": [],
            "aviation": [],
            "gps": [],
            "news": [],
            "financial": [],
        }

        # Active correlations
        self.active_correlations: List[Correlation] = []
        self.correlation_history: List[Correlation] = []

        # Threat scores by region
        self.region_scores: Dict[str, ThreatScore] = {}

        # Load configuration
        if rules_path:
            self._load_rules(rules_path)
        if chokepoints_path:
            self._load_chokepoints(chokepoints_path)

    def _load_rules(self, path: str):
        """Load correlation rules from YAML"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            self.rules = config.get("rules", [])
            self.scoring_config = config.get("scoring", {})
            self.thresholds = config.get("thresholds", {})

            logger.info(f"Loaded {len(self.rules)} correlation rules")

        except Exception as e:
            logger.error(f"Error loading rules: {e}")

    def _load_chokepoints(self, path: str):
        """Load chokepoint definitions from GeoJSON"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                geojson = json.load(f)

            for feature in geojson.get("features", []):
                props = feature.get("properties", {})
                chokepoint_id = props.get("id")
                if chokepoint_id:
                    self.chokepoints[chokepoint_id] = {
                        "name": props.get("name"),
                        "priority": props.get("priority"),
                        "threats": props.get("threats", []),
                        "actors": props.get("actors", []),
                        "geometry": feature.get("geometry"),
                    }

            logger.info(f"Loaded {len(self.chokepoints)} chokepoints")

        except Exception as e:
            logger.error(f"Error loading chokepoints: {e}")

    def ingest_cyber_data(self, data: Dict[str, Any]):
        """Ingest cyber intelligence data"""
        events = []

        # Infrastructure exposure
        for service in data.get("exposed_services", []):
            event = Event(
                id=f"cyber_infra_{service.get('ip')}_{service.get('port')}",
                source=EventSource.CYBER,
                event_type="exposed_service",
                timestamp=datetime.utcnow(),
                lat=service.get("lat"),
                lon=service.get("lon"),
                region=service.get("region"),
                entities={"ip": service.get("ip"), "port": service.get("port")},
                severity="medium",
                description=f"Exposed {service.get('service')} on port {service.get('port')}",
                raw_data=service,
            )
            events.append(event)

        # IOCs
        for ioc in data.get("iocs", []):
            event = Event(
                id=f"cyber_ioc_{ioc.get('value', '')}",
                source=EventSource.CYBER,
                event_type="ioc",
                timestamp=datetime.utcnow(),
                entities={
                    "ip": ioc.get("ip"),
                    "domain": ioc.get("domain"),
                    "hash": ioc.get("hash"),
                    "apt_group": ioc.get("apt_group"),
                },
                severity=ioc.get("severity", "medium"),
                description=ioc.get("description", "IOC detected"),
                raw_data=ioc,
            )
            events.append(event)

        # Vulnerabilities
        for vuln in data.get("vulnerabilities", []):
            event = Event(
                id=f"cyber_vuln_{vuln.get('cve_id', '')}",
                source=EventSource.CYBER,
                event_type="vulnerability",
                timestamp=datetime.utcnow(),
                entities={"cve": vuln.get("cve_id")},
                severity="high" if vuln.get("is_kev") else "medium",
                description=f"CVE {vuln.get('cve_id')} detected",
                raw_data=vuln,
            )
            events.append(event)

        self.event_buffer["cyber"].extend(events)
        self._prune_buffer("cyber")

        return len(events)

    def ingest_maritime_data(self, data: Dict[str, Any]):
        """Ingest maritime intelligence data"""
        events = []

        # Vessels
        for vessel in data.get("vessels", []):
            if vessel.get("is_dark") or vessel.get("sanctions_match") or vessel.get("near_cable"):
                event = Event(
                    id=f"maritime_vessel_{vessel.get('mmsi')}",
                    source=EventSource.MARITIME,
                    event_type="vessel_of_interest",
                    timestamp=datetime.utcnow(),
                    lat=vessel.get("lat"),
                    lon=vessel.get("lon"),
                    region=vessel.get("region"),
                    entities={
                        "mmsi": vessel.get("mmsi"),
                        "imo": vessel.get("imo"),
                        "vessel_name": vessel.get("name"),
                    },
                    severity=vessel.get("risk_level", "medium"),
                    description=self._describe_vessel(vessel),
                    raw_data=vessel,
                )
                events.append(event)

        # Dark ships
        for dark in data.get("dark_ships", []):
            event = Event(
                id=f"maritime_dark_{dark.get('mmsi')}",
                source=EventSource.MARITIME,
                event_type="dark_vessel",
                timestamp=datetime.utcnow(),
                lat=dark.get("lat"),
                lon=dark.get("lon"),
                region=dark.get("region"),
                entities={"mmsi": dark.get("mmsi")},
                severity="high",
                description=f"Dark vessel detected: {dark.get('mmsi')} ({dark.get('ais_gap_hours', 0):.1f}h gap)",
                raw_data=dark,
            )
            events.append(event)

        # STS transfers
        for sts in data.get("sts_transfers", []):
            event = Event(
                id=f"maritime_sts_{sts.get('vessel_1_mmsi')}_{sts.get('vessel_2_mmsi')}",
                source=EventSource.MARITIME,
                event_type="sts_transfer",
                timestamp=datetime.utcnow(),
                lat=sts.get("lat"),
                lon=sts.get("lon"),
                region=sts.get("region"),
                entities={
                    "mmsi_1": sts.get("vessel_1_mmsi"),
                    "mmsi_2": sts.get("vessel_2_mmsi"),
                },
                severity="critical" if sts.get("sanctions_involved") else "high",
                description=f"STS transfer: {sts.get('vessel_1_name')} <-> {sts.get('vessel_2_name')}",
                raw_data=sts,
            )
            events.append(event)

        # Cable proximity
        for cable in data.get("cable_proximity", []):
            if cable.get("risk_score", 0) > 30:
                event = Event(
                    id=f"maritime_cable_{cable.get('vessel_mmsi')}_{cable.get('cable_name')}",
                    source=EventSource.MARITIME,
                    event_type="cable_proximity",
                    timestamp=datetime.utcnow(),
                    lat=cable.get("lat"),
                    lon=cable.get("lon"),
                    entities={
                        "mmsi": cable.get("vessel_mmsi"),
                        "cable_name": cable.get("cable_name"),
                    },
                    severity="critical" if cable.get("risk_score", 0) > 70 else "high",
                    description=f"Vessel {cable.get('vessel_name')} near cable {cable.get('cable_name')}",
                    raw_data=cable,
                )
                events.append(event)

        self.event_buffer["maritime"].extend(events)
        self._prune_buffer("maritime")

        return len(events)

    def ingest_aviation_data(self, data: Dict[str, Any]):
        """Ingest aviation intelligence data"""
        events = []

        # Military aircraft
        for aircraft in data.get("military_aircraft", []):
            event = Event(
                id=f"aviation_mil_{aircraft.get('icao24')}",
                source=EventSource.AVIATION,
                event_type="military_aircraft",
                timestamp=datetime.utcnow(),
                lat=aircraft.get("lat"),
                lon=aircraft.get("lon"),
                region=aircraft.get("region"),
                entities={
                    "icao24": aircraft.get("icao24"),
                    "callsign": aircraft.get("callsign"),
                    "country": aircraft.get("origin_country"),
                },
                severity="medium",
                description=f"Military aircraft: {aircraft.get('callsign') or aircraft.get('icao24')} ({aircraft.get('origin_country')})",
                raw_data=aircraft,
            )
            events.append(event)

        # Anomalies
        for anomaly in data.get("anomalies", []):
            event = Event(
                id=f"aviation_anomaly_{anomaly.get('anomaly_type')}_{anomaly.get('region')}",
                source=EventSource.AVIATION,
                event_type=f"aviation_{anomaly.get('anomaly_type')}",
                timestamp=datetime.utcnow(),
                region=anomaly.get("region"),
                severity=anomaly.get("severity", "medium"),
                description=anomaly.get("description", "Aviation anomaly"),
                raw_data=anomaly,
            )
            events.append(event)

        self.event_buffer["aviation"].extend(events)
        self._prune_buffer("aviation")

        return len(events)

    def ingest_gps_data(self, data: Dict[str, Any]):
        """Ingest GPS interference data"""
        events = []

        for zone in data.get("zones", []):
            if zone.get("intensity") not in ["none", "low"]:
                event = Event(
                    id=f"gps_{zone.get('id')}",
                    source=EventSource.GPS,
                    event_type="gps_interference",
                    timestamp=datetime.utcnow(),
                    lat=zone.get("center_lat"),
                    lon=zone.get("center_lon"),
                    region=zone.get("region"),
                    entities={
                        "attributed_to": zone.get("attributed_to"),
                        "interference_type": zone.get("interference_type"),
                    },
                    severity="high" if zone.get("intensity") in ["high", "severe"] else "medium",
                    description=f"GPS {zone.get('interference_type')} detected ({zone.get('intensity')} intensity)",
                    raw_data=zone,
                )
                events.append(event)

        self.event_buffer["gps"].extend(events)
        self._prune_buffer("gps")

        return len(events)

    def ingest_news_data(self, data: Dict[str, Any]):
        """Ingest news intelligence data"""
        events = []

        for article in data.get("high_priority", []):
            event = Event(
                id=f"news_{article.get('id')}",
                source=EventSource.NEWS,
                event_type="threat_news",
                timestamp=datetime.fromisoformat(article.get("published_at")) if article.get("published_at") else datetime.utcnow(),
                entities={
                    "apt_groups": article.get("apt_groups", []),
                    "countries": article.get("attributed_countries", []),
                    "categories": article.get("categories", []),
                },
                severity="high" if article.get("threat_level", 0) >= 7 else "medium",
                confidence=article.get("confidence_score", 0.5),
                description=article.get("title", ""),
                raw_data=article,
            )

            # Set region from article
            regions = article.get("regions", [])
            if regions:
                event.region = regions[0]

            events.append(event)

        self.event_buffer["news"].extend(events)
        self._prune_buffer("news")

        return len(events)

    def ingest_financial_data(self, data: Dict[str, Any]):
        """
        Ingest financial/market intelligence data

        Supports data from:
        - Commodities (oil, gold, etc.)
        - Crypto markets (Bitcoin, Ethereum)
        - Sector ETFs (defense, energy)
        - Prediction markets (Polymarket)
        - Fed data (balance sheet)
        """
        events = []

        # Commodity price movements
        for commodity in data.get("commodities", []):
            change_pct = commodity.get("change_pct", 0)
            if abs(change_pct) >= 2:  # Significant movement
                severity = "critical" if abs(change_pct) >= 5 else "high" if abs(change_pct) >= 3 else "medium"
                event = Event(
                    id=f"financial_commodity_{commodity.get('symbol')}",
                    source=EventSource.FINANCIAL,
                    event_type="commodity_movement",
                    timestamp=datetime.utcnow(),
                    entities={
                        "symbol": commodity.get("symbol"),
                        "name": commodity.get("name"),
                        "change_pct": change_pct,
                        "price": commodity.get("price"),
                    },
                    severity=severity,
                    confidence=0.9,
                    description=f"{commodity.get('name', commodity.get('symbol'))}: {change_pct:+.1f}%",
                    raw_data=commodity,
                )
                events.append(event)

        # Sector movements (defense, energy, etc.)
        for sector in data.get("sectors", []):
            change_pct = sector.get("change_pct", 0)
            if abs(change_pct) >= 1.5:  # Significant sector movement
                severity = "high" if abs(change_pct) >= 3 else "medium"
                event = Event(
                    id=f"financial_sector_{sector.get('symbol')}",
                    source=EventSource.FINANCIAL,
                    event_type="sector_movement",
                    timestamp=datetime.utcnow(),
                    entities={
                        "symbol": sector.get("symbol"),
                        "name": sector.get("name"),
                        "sector_type": sector.get("sector_type"),
                        "change_pct": change_pct,
                    },
                    severity=severity,
                    description=f"Sector {sector.get('name')}: {change_pct:+.1f}%",
                    raw_data=sector,
                )
                events.append(event)

        # Crypto volatility (relevant for sanctions evasion signals)
        for crypto in data.get("crypto", []):
            change_pct = crypto.get("change_24h", 0)
            if abs(change_pct) >= 5:  # High crypto volatility
                event = Event(
                    id=f"financial_crypto_{crypto.get('symbol')}",
                    source=EventSource.FINANCIAL,
                    event_type="crypto_volatility",
                    timestamp=datetime.utcnow(),
                    entities={
                        "symbol": crypto.get("symbol"),
                        "change_24h": change_pct,
                        "price": crypto.get("price"),
                    },
                    severity="medium",
                    description=f"{crypto.get('symbol')}: {change_pct:+.1f}% (24h)",
                    raw_data=crypto,
                )
                events.append(event)

        # Prediction market signals (geopolitical events)
        for prediction in data.get("predictions", []):
            # Track significant probability changes
            prob_change = prediction.get("probability_change", 0)
            if abs(prob_change) >= 10:  # 10% swing in prediction
                event = Event(
                    id=f"financial_prediction_{prediction.get('id')}",
                    source=EventSource.FINANCIAL,
                    event_type="prediction_market",
                    timestamp=datetime.utcnow(),
                    entities={
                        "question": prediction.get("question"),
                        "probability": prediction.get("probability"),
                        "probability_change": prob_change,
                        "category": prediction.get("category"),
                    },
                    severity="high" if abs(prob_change) >= 20 else "medium",
                    description=f"Prediction shift: {prediction.get('question', '')[:50]}... ({prob_change:+.0f}%)",
                    raw_data=prediction,
                )
                events.append(event)

        # VIX / volatility index
        vix = data.get("vix", {})
        if vix.get("value", 0) >= 25:  # Elevated fear
            event = Event(
                id=f"financial_vix_{datetime.utcnow().strftime('%Y%m%d')}",
                source=EventSource.FINANCIAL,
                event_type="volatility_spike",
                timestamp=datetime.utcnow(),
                entities={
                    "vix_value": vix.get("value"),
                    "vix_change": vix.get("change_pct", 0),
                },
                severity="critical" if vix.get("value", 0) >= 35 else "high",
                description=f"VIX elevated: {vix.get('value'):.1f}",
                raw_data=vix,
            )
            events.append(event)

        self.event_buffer["financial"].extend(events)
        self._prune_buffer("financial")

        return len(events)

    def _prune_buffer(self, source: str, max_age_hours: int = 24, max_size: int = 1000):
        """Remove old events from buffer"""
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        self.event_buffer[source] = [
            e for e in self.event_buffer[source]
            if e.timestamp > cutoff
        ][-max_size:]

    def _describe_vessel(self, vessel: Dict[str, Any]) -> str:
        """Generate description for vessel event"""
        parts = []
        if vessel.get("is_dark"):
            parts.append("dark vessel")
        if vessel.get("sanctions_match"):
            parts.append("sanctions match")
        if vessel.get("near_cable"):
            parts.append(f"near cable {vessel.get('cable_name', '')}")
        if vessel.get("in_sts_transfer"):
            parts.append("in STS transfer")
        return f"Vessel {vessel.get('name', vessel.get('mmsi'))}: {', '.join(parts)}"

    def _check_rule_conditions(
        self,
        rule: Dict[str, Any],
        events_by_source: Dict[str, List[Event]]
    ) -> Tuple[bool, List[Event], float]:
        """Check if a rule's conditions are met"""
        triggers = rule.get("triggers", [])
        correlation = rule.get("correlation", {})

        matched_events: List[Event] = []
        sources_matched: Set[str] = set()

        for trigger in triggers:
            source = trigger.get("source")
            conditions = trigger.get("conditions", [])

            source_map = {
                "ais_tracker": "maritime",
                "news_scraper": "news",
                "cyber": "cyber",
                "aviation": "aviation",
                "gps": "gps",
                "financial": "financial",
                "markets": "financial",
            }
            source_key = source_map.get(source, source)

            for event in events_by_source.get(source_key, []):
                if self._event_matches_conditions(event, conditions):
                    matched_events.append(event)
                    sources_matched.add(source_key)
                    break  # One match per trigger

        # Check if we have enough sources
        require_sources = correlation.get("require_sources", 2)
        if len(sources_matched) < require_sources:
            return False, [], 0.0

        # Calculate confidence
        confidence = self._calculate_confidence(
            matched_events,
            sources_matched,
            correlation,
        )

        return True, matched_events, confidence

    def _event_matches_conditions(
        self,
        event: Event,
        conditions: List[Dict[str, Any]]
    ) -> bool:
        """Check if an event matches rule conditions"""
        for condition in conditions:
            field = condition.get("field")
            operator = condition.get("operator", "==")
            value = condition.get("value")
            contains_any = condition.get("contains_any", [])

            # Get field value from event
            event_value = None
            if hasattr(event, field):
                event_value = getattr(event, field)
            elif field in event.entities:
                event_value = event.entities[field]
            elif field in event.raw_data:
                event_value = event.raw_data[field]

            # Check condition
            if contains_any:
                # Check if any keyword matches
                search_text = str(event_value).lower() if event_value else ""
                if event.description:
                    search_text += " " + event.description.lower()
                if not any(kw.lower() in search_text for kw in contains_any):
                    return False

            elif operator == "==":
                if event_value != value:
                    return False
            elif operator == ">=":
                if not (event_value and event_value >= value):
                    return False
            elif operator == ">":
                if not (event_value and event_value > value):
                    return False
            elif operator == "in":
                if event_value not in value:
                    return False
            elif condition.get("exists"):
                if not event_value:
                    return False

        return True

    def _calculate_confidence(
        self,
        events: List[Event],
        sources: Set[str],
        correlation_config: Dict[str, Any]
    ) -> float:
        """Calculate correlation confidence score"""
        scoring = self.scoring_config.get("confidence", {})

        # Base confidence from source count
        if len(sources) == 1:
            confidence = scoring.get("base_single_source", 0.5)
        elif len(sources) == 2:
            confidence = scoring.get("base_two_sources", 0.7)
        else:
            confidence = scoring.get("base_three_sources", 0.9)

        # Multi-source bonus
        confidence += (len(sources) - 1) * scoring.get("multi_source_bonus", 0.1)

        # Temporal proximity bonus
        if len(events) > 1:
            timestamps = [e.timestamp for e in events if e.timestamp]
            if timestamps:
                time_span = (max(timestamps) - min(timestamps)).total_seconds() / 3600
                if time_span < 1:
                    confidence += scoring.get("temporal_proximity_bonus", 0.1)

        # Geographic proximity bonus
        coords = [(e.lat, e.lon) for e in events if e.lat and e.lon]
        if len(coords) > 1:
            # Simple distance check
            lat_span = max(c[0] for c in coords) - min(c[0] for c in coords)
            lon_span = max(c[1] for c in coords) - min(c[1] for c in coords)
            if lat_span < 2 and lon_span < 2:  # ~100km
                confidence += scoring.get("geo_proximity_bonus", 0.1)

        return min(confidence, scoring.get("max_confidence", 1.0))

    def run_correlation(self) -> List[Correlation]:
        """Run all correlation rules against buffered events"""
        new_correlations = []

        for rule in self.rules:
            try:
                matched, events, confidence = self._check_rule_conditions(
                    rule,
                    self.event_buffer,
                )

                if matched:
                    # Check minimum confidence
                    min_confidence = self.thresholds.get(
                        "correlation_confidence", {}
                    ).get("alert_minimum", 0.7)

                    if confidence < min_confidence:
                        continue

                    # Create correlation
                    correlation = Correlation(
                        id=f"corr_{rule.get('id')}_{datetime.utcnow().timestamp()}",
                        rule_id=rule.get("id"),
                        rule_name=rule.get("name"),
                        events=events,
                        severity=AlertSeverity(rule.get("priority", "medium")),
                        confidence=confidence,
                        description=self._format_correlation_description(rule, events),
                        region=self._determine_correlation_region(events),
                        actions=[a.get("type") for a in rule.get("actions", [])],
                    )

                    new_correlations.append(correlation)
                    self.active_correlations.append(correlation)

                    logger.info(
                        f"Correlation detected: {correlation.rule_name} "
                        f"(confidence: {correlation.confidence:.2f})"
                    )

            except Exception as e:
                logger.error(f"Error running rule {rule.get('id')}: {e}")

        return new_correlations

    def _format_correlation_description(
        self,
        rule: Dict[str, Any],
        events: List[Event]
    ) -> str:
        """Format correlation description from rule template"""
        template = rule.get("description", "Correlation detected")

        # Extract variables from events
        variables = {
            "region": self._determine_correlation_region(events) or "Unknown",
            "event_count": len(events),
            "sources": ", ".join(set(e.source.value for e in events)),
        }

        # Add entity-specific variables
        for event in events:
            for key, value in event.entities.items():
                if value and key not in variables:
                    variables[key] = value

        # Format template
        try:
            for key, value in variables.items():
                template = template.replace(f"{{{key}}}", str(value))
        except Exception:
            pass

        return template

    def _determine_correlation_region(self, events: List[Event]) -> Optional[str]:
        """Determine the region for a correlation"""
        regions = [e.region for e in events if e.region]
        if regions:
            # Return most common region
            return max(set(regions), key=regions.count)
        return None

    def calculate_threat_score(self, region: str) -> ThreatScore:
        """Calculate composite threat score for a region"""
        scoring = self.scoring_config.get("regional", {})

        # Count events by source for this region
        counts = {source: 0 for source in self.event_buffer.keys()}
        for source, events in self.event_buffer.items():
            counts[source] = sum(1 for e in events if e.region == region)

        # Calculate component scores (normalized to 0-100)
        def normalize(count, max_expected):
            return min(100, (count / max_expected) * 100) if max_expected > 0 else 0

        cyber_score = normalize(counts["cyber"], 50)
        maritime_score = normalize(counts["maritime"], 20)
        aviation_score = normalize(counts["aviation"], 30)
        gps_score = normalize(counts["gps"], 5)
        news_score = normalize(counts["news"], 10)
        financial_score = normalize(counts["financial"], 10)

        # Apply weights (financial adds economic signal layer)
        overall = (
            cyber_score * scoring.get("cyber_score", 0.25) +
            maritime_score * scoring.get("maritime_activity", 0.20) +
            news_score * scoring.get("news_sentiment", 0.15) +
            gps_score * scoring.get("gps_interference", 0.15) +
            aviation_score * scoring.get("aviation_anomaly", 0.10) +
            financial_score * scoring.get("financial_signal", 0.15)
        )

        # Add correlation boost
        active_corr = sum(
            1 for c in self.active_correlations
            if c.region == region
        )
        overall += active_corr * 5  # 5 points per active correlation
        overall = min(100, overall)

        # Determine trend
        prev_score = self.region_scores.get(region)
        if prev_score:
            if overall > prev_score.overall_score + 5:
                trend = "increasing"
            elif overall < prev_score.overall_score - 5:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "new"

        # Calculate momentum (ported from situation-monitor)
        momentum = self._calculate_momentum(region, overall, prev_score)

        score = ThreatScore(
            region=region,
            timestamp=datetime.utcnow(),
            overall_score=overall,
            cyber_score=cyber_score,
            maritime_score=maritime_score,
            aviation_score=aviation_score,
            gps_score=gps_score,
            news_score=news_score,
            financial_score=financial_score,
            active_correlations=active_corr,
            trend=trend,
            momentum=momentum,
        )

        self.region_scores[region] = score
        return score

    def _calculate_momentum(
        self,
        region: str,
        current_score: float,
        prev_score: Optional[ThreatScore]
    ) -> str:
        """
        Calculate momentum indicator (ported from situation-monitor intelligence.js)

        Momentum tracks rate of change, not just direction:
        - surging: rapid increase (>10 points in short time)
        - rising: moderate increase (5-10 points)
        - stable: little change (<5 points)
        - declining: decrease (>5 points down)
        """
        if not prev_score:
            return "stable"

        delta = current_score - prev_score.overall_score

        # Check time since last score
        time_delta = (datetime.utcnow() - prev_score.timestamp).total_seconds() / 60

        # Normalize delta by time (per 10 minutes, like situation-monitor)
        if time_delta > 0:
            rate = (delta / time_delta) * 10
        else:
            rate = delta

        if rate >= 10:
            return "surging"
        elif rate >= 5:
            return "rising"
        elif rate <= -5:
            return "declining"
        else:
            return "stable"

    def get_threat_heatmap(self) -> Dict[str, Any]:
        """Generate threat heatmap for all regions"""
        heatmap = {}

        for region in self.chokepoints.keys():
            score = self.calculate_threat_score(region)
            heatmap[region] = {
                "overall_score": score.overall_score,
                "cyber_score": score.cyber_score,
                "maritime_score": score.maritime_score,
                "aviation_score": score.aviation_score,
                "gps_score": score.gps_score,
                "news_score": score.news_score,
                "financial_score": score.financial_score,
                "trend": score.trend,
                "momentum": score.momentum,
                "active_correlations": score.active_correlations,
                "threat_level": self._score_to_level(score.overall_score),
            }

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "regions": heatmap,
            "summary": {
                "critical_regions": [r for r, d in heatmap.items() if d["threat_level"] == "critical"],
                "high_regions": [r for r, d in heatmap.items() if d["threat_level"] == "high"],
                "increasing_regions": [r for r, d in heatmap.items() if d["trend"] == "increasing"],
                "surging_regions": [r for r, d in heatmap.items() if d["momentum"] == "surging"],
            }
        }

    def _score_to_level(self, score: float) -> str:
        """Convert score to threat level"""
        thresholds = self.thresholds.get("cyber_threat_score", {})
        if score >= thresholds.get("critical", 85):
            return "critical"
        elif score >= thresholds.get("high", 70):
            return "high"
        elif score >= thresholds.get("medium", 50):
            return "medium"
        elif score >= thresholds.get("low", 30):
            return "low"
        return "minimal"

    def generate_daily_brief(self) -> str:
        """Generate daily situation report"""
        heatmap = self.get_threat_heatmap()
        correlations = self.active_correlations[-20:]  # Last 20

        lines = [
            "# Daily Geopolitical Threat Brief",
            f"Generated: {datetime.utcnow().isoformat()}Z",
            "",
            "## Executive Summary",
            "",
        ]

        # Critical/High regions
        critical = heatmap["summary"]["critical_regions"]
        high = heatmap["summary"]["high_regions"]

        if critical:
            lines.append(f"**CRITICAL THREAT**: {', '.join(critical)}")
        if high:
            lines.append(f"**HIGH THREAT**: {', '.join(high)}")
        if not critical and not high:
            lines.append("No critical or high threat regions currently detected.")

        lines.extend(["", "## Regional Threat Scores", ""])

        # Table of scores
        lines.append("| Region | Score | Trend | Top Concern |")
        lines.append("|--------|-------|-------|-------------|")

        for region, data in sorted(
            heatmap["regions"].items(),
            key=lambda x: x[1]["overall_score"],
            reverse=True
        ):
            # Determine top concern
            scores = {
                "Cyber": data["cyber_score"],
                "Maritime": data["maritime_score"],
                "Aviation": data["aviation_score"],
                "GPS": data["gps_score"],
                "News": data["news_score"],
            }
            top_concern = max(scores, key=scores.get) if any(scores.values()) else "None"

            trend_icon = "↑" if data["trend"] == "increasing" else "↓" if data["trend"] == "decreasing" else "→"

            lines.append(
                f"| {region} | {data['overall_score']:.0f} | {trend_icon} | {top_concern} |"
            )

        # Active correlations
        if correlations:
            lines.extend(["", "## Active Correlations", ""])
            for corr in correlations:
                lines.append(
                    f"- **{corr.rule_name}** ({corr.severity.value}): "
                    f"{corr.description} [Confidence: {corr.confidence:.0%}]"
                )

        # Event statistics
        lines.extend(["", "## Event Statistics (24h)", ""])
        for source, events in self.event_buffer.items():
            lines.append(f"- {source.title()}: {len(events)} events")

        return "\n".join(lines)

    def export_feed(self) -> Dict[str, Any]:
        """Export complete threat feed"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_heatmap": self.get_threat_heatmap(),
            "active_correlations": [
                self._correlation_to_dict(c)
                for c in self.active_correlations
            ],
            "event_counts": {
                source: len(events)
                for source, events in self.event_buffer.items()
            },
            "chokepoints": self.chokepoints,
        }

    def _correlation_to_dict(self, correlation: Correlation) -> Dict[str, Any]:
        """Convert Correlation to dictionary"""
        return {
            "id": correlation.id,
            "rule_id": correlation.rule_id,
            "rule_name": correlation.rule_name,
            "severity": correlation.severity.value,
            "confidence": correlation.confidence,
            "description": correlation.description,
            "region": correlation.region,
            "detected_at": correlation.detected_at.isoformat(),
            "event_count": len(correlation.events),
            "event_sources": list(set(e.source.value for e in correlation.events)),
            "actions": correlation.actions,
        }
