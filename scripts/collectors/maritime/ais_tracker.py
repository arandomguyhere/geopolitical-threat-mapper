"""
AIS_Tracker Integration Collector

Connects to the user's AIS_Tracker API for maritime intelligence:
- Real-time vessel positions
- Dark ship detections (AIS gaps)
- Sanctions matches
- STS transfers
- Cable proximity alerts
- SAR detections
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

import aiohttp

from ..base import BaseCollector

logger = logging.getLogger(__name__)


class VesselRisk(Enum):
    """Vessel risk classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class Vessel:
    """Vessel data from AIS_Tracker"""
    mmsi: str
    imo: Optional[str] = None
    name: Optional[str] = None
    flag: Optional[str] = None
    vessel_type: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    speed: Optional[float] = None
    course: Optional[float] = None
    destination: Optional[str] = None
    last_seen: Optional[datetime] = None

    # Risk indicators from AIS_Tracker
    is_dark: bool = False
    ais_gap_hours: Optional[float] = None
    flag_changes: int = 0
    age_years: Optional[int] = None
    sanctions_match: bool = False
    near_cable: bool = False
    cable_name: Optional[str] = None
    in_sts_transfer: bool = False
    risk_score: float = 0.0
    risk_level: VesselRisk = VesselRisk.UNKNOWN

    # Additional context
    region: Optional[str] = None
    chokepoint: Optional[str] = None


@dataclass
class MaritimeAlert:
    """Maritime alert from AIS_Tracker"""
    id: str
    alert_type: str
    severity: str
    vessel_mmsi: Optional[str] = None
    vessel_name: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    description: str = ""
    timestamp: Optional[datetime] = None
    region: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class STSTransfer:
    """Ship-to-ship transfer detection"""
    vessel_1_mmsi: str
    vessel_2_mmsi: str
    vessel_1_name: Optional[str] = None
    vessel_2_name: Optional[str] = None
    lat: float = 0.0
    lon: float = 0.0
    detected_at: Optional[datetime] = None
    duration_hours: Optional[float] = None
    sanctions_involved: bool = False
    region: Optional[str] = None


@dataclass
class CableProximity:
    """Vessel near subsea cable"""
    vessel_mmsi: str
    vessel_name: Optional[str] = None
    cable_name: str
    cable_type: str  # power, telecom, mixed
    distance_nm: float
    lat: float
    lon: float
    is_anchored: bool = False
    is_drifting: bool = False
    ais_gap_before: bool = False
    risk_score: float = 0.0


class AISTrackerCollector(BaseCollector):
    """
    Collector for AIS_Tracker maritime intelligence API

    Endpoints used:
    - GET /api/vessels - Active vessels
    - GET /api/alerts - Current alerts
    - GET /api/dark-ships - Dark vessel detections
    - GET /api/sanctions/check - Sanctions matches
    - GET /api/infrastructure/cables - Cable proximity
    - GET /api/sar/detections - SAR satellite detections
    - GET /api/sts/transfers - STS transfer events
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session: Optional[aiohttp.ClientSession] = None

        # Chokepoint bounding boxes for region classification
        self.chokepoints = {
            "baltic_sea": {"min_lat": 53.0, "max_lat": 66.0, "min_lon": 9.0, "max_lon": 30.0},
            "black_sea": {"min_lat": 40.0, "max_lat": 47.0, "min_lon": 27.0, "max_lon": 42.0},
            "red_sea": {"min_lat": 12.0, "max_lat": 30.0, "min_lon": 32.0, "max_lon": 44.0},
            "taiwan_strait": {"min_lat": 21.0, "max_lat": 26.0, "min_lon": 116.0, "max_lon": 122.0},
            "hormuz": {"min_lat": 24.0, "max_lat": 28.0, "min_lon": 54.0, "max_lon": 58.0},
            "malacca": {"min_lat": 0.0, "max_lat": 8.0, "min_lon": 98.0, "max_lon": 105.0},
        }

    async def init_session(self):
        """Initialize HTTP session"""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            headers=headers
        )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    def _classify_region(self, lat: float, lon: float) -> Optional[str]:
        """Classify coordinates into chokepoint region"""
        for region, bbox in self.chokepoints.items():
            if (bbox["min_lat"] <= lat <= bbox["max_lat"] and
                bbox["min_lon"] <= lon <= bbox["max_lon"]):
                return region
        return None

    def _calculate_risk_level(self, vessel: Dict[str, Any]) -> VesselRisk:
        """Calculate vessel risk level from indicators"""
        score = 0

        # Dark vessel (AIS gap)
        if vessel.get("is_dark") or vessel.get("ais_gap_hours", 0) >= 4:
            score += 30

        # Sanctions match
        if vessel.get("sanctions_match"):
            score += 40

        # Near cable
        if vessel.get("near_cable"):
            score += 20

        # Flag changes (shadow fleet indicator)
        flag_changes = vessel.get("flag_changes", 0)
        if flag_changes >= 3:
            score += 20
        elif flag_changes >= 1:
            score += 10

        # Old vessel (shadow fleet indicator)
        age = vessel.get("age_years", 0)
        if age >= 20:
            score += 15
        elif age >= 15:
            score += 10

        # STS transfer
        if vessel.get("in_sts_transfer"):
            score += 25

        if score >= 70:
            return VesselRisk.CRITICAL
        elif score >= 50:
            return VesselRisk.HIGH
        elif score >= 30:
            return VesselRisk.MEDIUM
        elif score > 0:
            return VesselRisk.LOW
        return VesselRisk.UNKNOWN

    async def _get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make GET request to AIS_Tracker API"""
        if not self.session:
            await self.init_session()

        url = f"{self.base_url}{endpoint}"
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.warning(f"AIS_Tracker API error: {response.status} for {endpoint}")
                    return None
        except aiohttp.ClientError as e:
            logger.error(f"AIS_Tracker connection error: {e}")
            return None
        except Exception as e:
            logger.error(f"AIS_Tracker unexpected error: {e}")
            return None

    async def get_vessels(
        self,
        region: Optional[str] = None,
        vessel_type: Optional[str] = None,
        min_risk: Optional[str] = None
    ) -> List[Vessel]:
        """Get active vessels from AIS_Tracker"""
        params = {}
        if region:
            params["region"] = region
        if vessel_type:
            params["type"] = vessel_type
        if min_risk:
            params["min_risk"] = min_risk

        data = await self._get("/api/vessels", params)
        if not data:
            return []

        vessels = []
        for v in data.get("vessels", data if isinstance(data, list) else []):
            lat = v.get("lat") or v.get("latitude")
            lon = v.get("lon") or v.get("longitude")

            vessel = Vessel(
                mmsi=str(v.get("mmsi", "")),
                imo=v.get("imo"),
                name=v.get("name") or v.get("vessel_name"),
                flag=v.get("flag") or v.get("flag_country"),
                vessel_type=v.get("vessel_type") or v.get("type"),
                lat=lat,
                lon=lon,
                speed=v.get("speed") or v.get("sog"),
                course=v.get("course") or v.get("cog"),
                destination=v.get("destination"),
                is_dark=v.get("is_dark", False),
                ais_gap_hours=v.get("ais_gap_hours"),
                flag_changes=v.get("flag_changes", 0),
                age_years=v.get("age_years") or v.get("vessel_age"),
                sanctions_match=v.get("sanctions_match", False),
                near_cable=v.get("near_cable", False),
                cable_name=v.get("cable_name"),
                in_sts_transfer=v.get("in_sts_transfer", False),
            )

            # Classify region if coordinates available
            if lat and lon:
                vessel.region = self._classify_region(lat, lon)
                vessel.chokepoint = vessel.region

            # Calculate risk
            vessel.risk_level = self._calculate_risk_level(v)
            vessel.risk_score = v.get("risk_score", 0.0)

            vessels.append(vessel)

        return vessels

    async def get_dark_ships(self, region: Optional[str] = None) -> List[Vessel]:
        """Get dark ship detections (vessels with AIS gaps)"""
        params = {"region": region} if region else {}
        data = await self._get("/api/dark-ships", params)
        if not data:
            return []

        dark_ships = []
        for v in data.get("dark_ships", data if isinstance(data, list) else []):
            vessel = Vessel(
                mmsi=str(v.get("mmsi", "")),
                name=v.get("name") or v.get("vessel_name"),
                flag=v.get("flag"),
                is_dark=True,
                ais_gap_hours=v.get("gap_hours") or v.get("ais_gap_hours"),
                lat=v.get("last_lat") or v.get("lat"),
                lon=v.get("last_lon") or v.get("lon"),
            )
            vessel.risk_level = VesselRisk.HIGH
            dark_ships.append(vessel)

        return dark_ships

    async def get_alerts(self, severity: Optional[str] = None) -> List[MaritimeAlert]:
        """Get current maritime alerts"""
        params = {"severity": severity} if severity else {}
        data = await self._get("/api/alerts", params)
        if not data:
            return []

        alerts = []
        for a in data.get("alerts", data if isinstance(data, list) else []):
            alert = MaritimeAlert(
                id=str(a.get("id", "")),
                alert_type=a.get("type") or a.get("alert_type", "unknown"),
                severity=a.get("severity", "medium"),
                vessel_mmsi=a.get("mmsi") or a.get("vessel_mmsi"),
                vessel_name=a.get("vessel_name"),
                lat=a.get("lat") or a.get("latitude"),
                lon=a.get("lon") or a.get("longitude"),
                description=a.get("description") or a.get("message", ""),
                region=a.get("region"),
                metadata=a.get("metadata", {}),
            )

            # Parse timestamp
            ts = a.get("timestamp") or a.get("created_at")
            if ts:
                try:
                    if isinstance(ts, str):
                        alert.timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        alert.timestamp = datetime.fromtimestamp(ts)
                except (ValueError, TypeError):
                    pass

            alerts.append(alert)

        return alerts

    async def get_sanctions_matches(self) -> List[Vessel]:
        """Get vessels matching sanctions lists"""
        data = await self._get("/api/sanctions/check")
        if not data:
            return []

        matches = []
        for v in data.get("matches", data if isinstance(data, list) else []):
            vessel = Vessel(
                mmsi=str(v.get("mmsi", "")),
                name=v.get("name") or v.get("vessel_name"),
                imo=v.get("imo"),
                flag=v.get("flag"),
                sanctions_match=True,
                lat=v.get("lat"),
                lon=v.get("lon"),
            )
            vessel.risk_level = VesselRisk.CRITICAL
            matches.append(vessel)

        return matches

    async def get_sts_transfers(self, region: Optional[str] = None) -> List[STSTransfer]:
        """Get ship-to-ship transfer detections"""
        params = {"region": region} if region else {}
        data = await self._get("/api/sts/transfers", params)
        if not data:
            # Try alternate endpoint
            data = await self._get("/api/events/sts", params)
        if not data:
            return []

        transfers = []
        for t in data.get("transfers", data if isinstance(data, list) else []):
            transfer = STSTransfer(
                vessel_1_mmsi=str(t.get("vessel_1_mmsi") or t.get("mmsi_1", "")),
                vessel_2_mmsi=str(t.get("vessel_2_mmsi") or t.get("mmsi_2", "")),
                vessel_1_name=t.get("vessel_1_name") or t.get("name_1"),
                vessel_2_name=t.get("vessel_2_name") or t.get("name_2"),
                lat=t.get("lat", 0.0),
                lon=t.get("lon", 0.0),
                duration_hours=t.get("duration_hours"),
                sanctions_involved=t.get("sanctions_involved", False),
            )

            # Classify region
            if transfer.lat and transfer.lon:
                transfer.region = self._classify_region(transfer.lat, transfer.lon)

            transfers.append(transfer)

        return transfers

    async def get_cable_proximity(self) -> List[CableProximity]:
        """Get vessels near subsea cables"""
        data = await self._get("/api/infrastructure/cables")
        if not data:
            return []

        proximities = []
        for c in data.get("proximities", data if isinstance(data, list) else []):
            proximity = CableProximity(
                vessel_mmsi=str(c.get("mmsi", "")),
                vessel_name=c.get("vessel_name"),
                cable_name=c.get("cable_name", "Unknown"),
                cable_type=c.get("cable_type", "unknown"),
                distance_nm=c.get("distance_nm", 0.0),
                lat=c.get("lat", 0.0),
                lon=c.get("lon", 0.0),
                is_anchored=c.get("is_anchored", False),
                is_drifting=c.get("is_drifting", False),
                ais_gap_before=c.get("ais_gap_before", False),
            )

            # Calculate risk score
            risk = 0
            if proximity.distance_nm < 1.0:
                risk += 40
            elif proximity.distance_nm < 5.0:
                risk += 20
            if proximity.is_anchored:
                risk += 30
            if proximity.is_drifting:
                risk += 25
            if proximity.ais_gap_before:
                risk += 35
            proximity.risk_score = min(risk, 100)

            proximities.append(proximity)

        return proximities

    async def get_sar_detections(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get SAR satellite detections (dark vessels detected by radar)"""
        params = {"region": region} if region else {}
        data = await self._get("/api/sar/detections", params)
        if not data:
            return []

        return data.get("detections", data if isinstance(data, list) else [])

    async def get_chokepoint_summary(self, chokepoint_id: str) -> Dict[str, Any]:
        """Get summary statistics for a chokepoint"""
        vessels = await self.get_vessels(region=chokepoint_id)
        dark_ships = await self.get_dark_ships(region=chokepoint_id)
        sts = await self.get_sts_transfers(region=chokepoint_id)

        # Count by risk level
        risk_counts = {level.value: 0 for level in VesselRisk}
        for v in vessels:
            risk_counts[v.risk_level.value] += 1

        return {
            "chokepoint_id": chokepoint_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_vessels": len(vessels),
            "dark_ships": len(dark_ships),
            "sts_transfers": len(sts),
            "risk_breakdown": risk_counts,
            "sanctions_vessels": sum(1 for v in vessels if v.sanctions_match),
            "cable_proximity": sum(1 for v in vessels if v.near_cable),
        }

    async def collect_all(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Collect all maritime intelligence data"""
        if regions is None:
            regions = list(self.chokepoints.keys())

        all_vessels = []
        all_dark_ships = []
        all_alerts = []
        all_sts = []
        all_cable = []
        chokepoint_summaries = {}

        # Collect data for each region
        for region in regions:
            try:
                vessels = await self.get_vessels(region=region)
                all_vessels.extend(vessels)

                dark = await self.get_dark_ships(region=region)
                all_dark_ships.extend(dark)

                sts = await self.get_sts_transfers(region=region)
                all_sts.extend(sts)

                summary = await self.get_chokepoint_summary(region)
                chokepoint_summaries[region] = summary

            except Exception as e:
                logger.error(f"Error collecting data for region {region}: {e}")

        # Get global alerts and cable proximity
        try:
            all_alerts = await self.get_alerts()
            all_cable = await self.get_cable_proximity()
        except Exception as e:
            logger.error(f"Error collecting alerts/cables: {e}")

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "ais_tracker",
            "vessels": [self._vessel_to_dict(v) for v in all_vessels],
            "dark_ships": [self._vessel_to_dict(v) for v in all_dark_ships],
            "alerts": [self._alert_to_dict(a) for a in all_alerts],
            "sts_transfers": [self._sts_to_dict(s) for s in all_sts],
            "cable_proximity": [self._cable_to_dict(c) for c in all_cable],
            "chokepoint_summaries": chokepoint_summaries,
            "statistics": {
                "total_vessels": len(all_vessels),
                "dark_ships": len(all_dark_ships),
                "sts_transfers": len(all_sts),
                "active_alerts": len(all_alerts),
                "cable_risks": len(all_cable),
            }
        }

    def _vessel_to_dict(self, vessel: Vessel) -> Dict[str, Any]:
        """Convert Vessel to dictionary"""
        return {
            "mmsi": vessel.mmsi,
            "imo": vessel.imo,
            "name": vessel.name,
            "flag": vessel.flag,
            "vessel_type": vessel.vessel_type,
            "lat": vessel.lat,
            "lon": vessel.lon,
            "speed": vessel.speed,
            "course": vessel.course,
            "destination": vessel.destination,
            "is_dark": vessel.is_dark,
            "ais_gap_hours": vessel.ais_gap_hours,
            "flag_changes": vessel.flag_changes,
            "age_years": vessel.age_years,
            "sanctions_match": vessel.sanctions_match,
            "near_cable": vessel.near_cable,
            "cable_name": vessel.cable_name,
            "in_sts_transfer": vessel.in_sts_transfer,
            "risk_score": vessel.risk_score,
            "risk_level": vessel.risk_level.value,
            "region": vessel.region,
            "chokepoint": vessel.chokepoint,
        }

    def _alert_to_dict(self, alert: MaritimeAlert) -> Dict[str, Any]:
        """Convert MaritimeAlert to dictionary"""
        return {
            "id": alert.id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "vessel_mmsi": alert.vessel_mmsi,
            "vessel_name": alert.vessel_name,
            "lat": alert.lat,
            "lon": alert.lon,
            "description": alert.description,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "region": alert.region,
            "metadata": alert.metadata,
        }

    def _sts_to_dict(self, sts: STSTransfer) -> Dict[str, Any]:
        """Convert STSTransfer to dictionary"""
        return {
            "vessel_1_mmsi": sts.vessel_1_mmsi,
            "vessel_2_mmsi": sts.vessel_2_mmsi,
            "vessel_1_name": sts.vessel_1_name,
            "vessel_2_name": sts.vessel_2_name,
            "lat": sts.lat,
            "lon": sts.lon,
            "detected_at": sts.detected_at.isoformat() if sts.detected_at else None,
            "duration_hours": sts.duration_hours,
            "sanctions_involved": sts.sanctions_involved,
            "region": sts.region,
        }

    def _cable_to_dict(self, cable: CableProximity) -> Dict[str, Any]:
        """Convert CableProximity to dictionary"""
        return {
            "vessel_mmsi": cable.vessel_mmsi,
            "vessel_name": cable.vessel_name,
            "cable_name": cable.cable_name,
            "cable_type": cable.cable_type,
            "distance_nm": cable.distance_nm,
            "lat": cable.lat,
            "lon": cable.lon,
            "is_anchored": cable.is_anchored,
            "is_drifting": cable.is_drifting,
            "ais_gap_before": cable.ais_gap_before,
            "risk_score": cable.risk_score,
        }
