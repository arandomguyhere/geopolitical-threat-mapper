"""
Direct AIS_Tracker Integration

Uses AIS_Tracker modules directly instead of requiring API server.
Imports functions from the cloned AIS_Tracker repository.
"""

from __future__ import annotations  # Defer type annotation evaluation (PEP 563)

import sys
import os
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from pathlib import Path

# Add AIS_Tracker to path
AIS_TRACKER_PATH = Path(__file__).parent.parent.parent.parent.parent / "AIS_Tracker"
if AIS_TRACKER_PATH.exists():
    sys.path.insert(0, str(AIS_TRACKER_PATH))

logger = logging.getLogger(__name__)

# Try to import AIS_Tracker modules
try:
    from ais_sources.manager import AISSourceManager, create_manager
    from ais_sources.base import AISPosition, AISVesselInfo
    HAS_AIS_SOURCES = True
except ImportError as e:
    logger.warning(f"AIS sources not available: {e}")
    HAS_AIS_SOURCES = False

try:
    from behavior import (
        detect_ais_gaps,
        detect_spoofing,
        detect_encounters,
        detect_loitering,
        detect_sts_transfers,
        calculate_dark_fleet_score,
        is_flag_of_convenience,
        is_shadow_fleet_flag,
        validate_mmsi,
        get_flag_country,
    )
    HAS_BEHAVIOR = True
except ImportError as e:
    logger.warning(f"Behavior module not available: {e}")
    HAS_BEHAVIOR = False

try:
    from sanctions import SanctionsDatabase
    HAS_SANCTIONS = True
except ImportError as e:
    logger.warning(f"Sanctions module not available: {e}")
    HAS_SANCTIONS = False

try:
    from venezuela import (
        calculate_venezuela_risk_score,
        is_in_venezuela_zone,
        detect_circle_spoofing,
    )
    HAS_VENEZUELA = True
except ImportError as e:
    logger.warning(f"Venezuela module not available: {e}")
    HAS_VENEZUELA = False


@dataclass
class DirectVessel:
    """Vessel data from direct AIS integration"""
    mmsi: str
    imo: Optional[str] = None
    name: Optional[str] = None
    flag: Optional[str] = None
    vessel_type: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    speed: Optional[float] = None
    course: Optional[float] = None
    heading: Optional[float] = None
    destination: Optional[str] = None
    last_seen: Optional[datetime] = None

    # Risk indicators
    is_dark: bool = False
    ais_gap_hours: Optional[float] = None
    flag_changes: int = 0
    age_years: Optional[int] = None
    sanctions_match: bool = False
    sanctions_info: Optional[Dict[str, Any]] = None
    near_cable: bool = False
    in_sts_transfer: bool = False

    # Computed scores
    dark_fleet_score: float = 0.0
    risk_level: str = "unknown"
    is_flag_of_convenience: bool = False
    is_shadow_fleet: bool = False

    # Regional classification
    region: Optional[str] = None
    chokepoint: Optional[str] = None


class DirectAISCollector:
    """
    Direct AIS data collector using AIS_Tracker modules.

    No API server required - imports and uses modules directly.
    Provides vessel positions, behavioral analysis, and sanctions checking.
    """

    # Chokepoint bounding boxes
    CHOKEPOINTS = {
        "baltic_sea": {"min_lat": 53.0, "max_lat": 66.0, "min_lon": 9.0, "max_lon": 30.0},
        "black_sea": {"min_lat": 40.0, "max_lat": 47.0, "min_lon": 27.0, "max_lon": 42.0},
        "red_sea": {"min_lat": 12.0, "max_lat": 30.0, "min_lon": 32.0, "max_lon": 44.0},
        "taiwan_strait": {"min_lat": 21.0, "max_lat": 26.0, "min_lon": 116.0, "max_lon": 122.0},
        "hormuz": {"min_lat": 24.0, "max_lat": 28.0, "min_lon": 54.0, "max_lon": 58.0},
        "malacca": {"min_lat": 0.0, "max_lat": 8.0, "min_lon": 98.0, "max_lon": 105.0},
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize direct AIS collector.

        Args:
            config_path: Path to ais_config.json (optional)
        """
        self.manager: Optional[AISSourceManager] = None
        self.sanctions_db: Optional[SanctionsDatabase] = None
        self._initialized = False

        # Default config path
        if config_path is None:
            config_path = str(AIS_TRACKER_PATH / "ais_config.json")
        self.config_path = config_path

    def is_available(self) -> bool:
        """Check if AIS_Tracker modules are available"""
        return HAS_AIS_SOURCES

    def initialize(self) -> bool:
        """
        Initialize AIS sources and sanctions database.

        Returns:
            True if initialization successful
        """
        if self._initialized:
            return True

        if not HAS_AIS_SOURCES:
            logger.warning("AIS sources not available - cannot initialize")
            return False

        try:
            # Create manager from config or programmatically
            if os.path.exists(self.config_path):
                self.manager = AISSourceManager.from_config(self.config_path)
            else:
                # Create with environment variables
                aisstream_key = os.getenv("AISSTREAM_API_KEY")
                marinesia_key = os.getenv("MARINESIA_API_KEY")

                self.manager = create_manager(
                    aisstream_key=aisstream_key,
                    marinesia_key=marinesia_key,
                    enable_marinesia=True
                )

            # Start the manager
            if self.manager.start():
                logger.info("AIS source manager started successfully")
            else:
                logger.warning("AIS sources started but may have limited connectivity")

            # Initialize sanctions database
            if HAS_SANCTIONS:
                self.sanctions_db = SanctionsDatabase()
                logger.info("Sanctions database initialized")

            self._initialized = True
            return True

        except Exception as e:
            logger.error(f"Failed to initialize AIS collector: {e}")
            return False

    def close(self):
        """Stop AIS sources"""
        if self.manager:
            self.manager.stop()
            self._initialized = False

    def _classify_region(self, lat: float, lon: float) -> Optional[str]:
        """Classify coordinates into chokepoint region"""
        for region, bbox in self.CHOKEPOINTS.items():
            if (bbox["min_lat"] <= lat <= bbox["max_lat"] and
                bbox["min_lon"] <= lon <= bbox["max_lon"]):
                return region
        return None

    def _calculate_risk_level(self, score: float) -> str:
        """Convert risk score to level"""
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        elif score > 0:
            return "low"
        return "unknown"

    def get_vessels_in_region(self, region: str) -> List[DirectVessel]:
        """
        Get vessels in a specific chokepoint region.

        Args:
            region: Chokepoint ID (e.g., 'baltic_sea', 'taiwan_strait')

        Returns:
            List of vessels in the region
        """
        if not self._initialized:
            if not self.initialize():
                return []

        if region not in self.CHOKEPOINTS:
            logger.warning(f"Unknown region: {region}")
            return []

        bbox = self.CHOKEPOINTS[region]
        return self.get_vessels_in_area(
            bbox["min_lat"], bbox["min_lon"],
            bbox["max_lat"], bbox["max_lon"],
            region=region
        )

    def get_vessels_in_area(
        self,
        min_lat: float,
        min_lon: float,
        max_lat: float,
        max_lon: float,
        region: Optional[str] = None
    ) -> List[DirectVessel]:
        """
        Get vessels in a bounding box area.

        Uses Marinesia's area query feature if available.
        """
        if not self._initialized:
            if not self.initialize():
                return []

        vessels = []

        try:
            positions = self.manager.get_vessels_in_area(
                min_lat, min_lon, max_lat, max_lon
            )

            for pos in positions:
                vessel = self._position_to_vessel(pos, region=region)
                vessels.append(vessel)

            logger.info(f"Found {len(vessels)} vessels in area")

        except Exception as e:
            logger.error(f"Error getting vessels in area: {e}")

        return vessels

    def get_vessel_info(self, mmsi: str) -> Optional[DirectVessel]:
        """
        Get detailed vessel information with analysis.

        Combines data from multiple sources and runs behavioral analysis.
        """
        if not self._initialized:
            if not self.initialize():
                return None

        try:
            # Get combined info from all sources
            info = self.manager.get_combined_vessel_info(mmsi)

            vessel = DirectVessel(mmsi=mmsi)

            # Position data
            if info.get("position"):
                pos = info["position"]
                vessel.lat = pos.get("lat")
                vessel.lon = pos.get("lon")
                vessel.speed = pos.get("speed")
                vessel.course = pos.get("course")
                vessel.heading = pos.get("heading")

            # Profile data
            if info.get("profile"):
                profile = info["profile"]
                vessel.name = profile.get("name")
                vessel.imo = profile.get("imo")
                vessel.flag = profile.get("flag")
                vessel.vessel_type = profile.get("ship_type")
                vessel.destination = profile.get("destination")

            # Run sanctions check
            if self.sanctions_db:
                sanctions = self.sanctions_db.check_vessel(
                    mmsi=mmsi,
                    imo=vessel.imo,
                    name=vessel.name
                )
                if sanctions and sanctions.get("is_sanctioned"):
                    vessel.sanctions_match = True
                    vessel.sanctions_info = sanctions

            # Run behavioral analysis
            self._analyze_vessel(vessel)

            # Classify region
            if vessel.lat and vessel.lon:
                vessel.region = self._classify_region(vessel.lat, vessel.lon)
                vessel.chokepoint = vessel.region

            return vessel

        except Exception as e:
            logger.error(f"Error getting vessel info for {mmsi}: {e}")
            return None

    def check_sanctions(self, mmsi: str = None, imo: str = None, name: str = None) -> Dict[str, Any]:
        """
        Check if a vessel is on sanctions lists.

        Args:
            mmsi: Vessel MMSI
            imo: Vessel IMO number
            name: Vessel name

        Returns:
            Sanctions check result
        """
        if not HAS_SANCTIONS:
            return {"error": "Sanctions module not available"}

        if not self.sanctions_db:
            self.sanctions_db = SanctionsDatabase()

        try:
            return self.sanctions_db.check_vessel(mmsi=mmsi, imo=imo, name=name)
        except Exception as e:
            logger.error(f"Sanctions check error: {e}")
            return {"error": str(e)}

    def _position_to_vessel(self, pos: AISPosition, region: Optional[str] = None) -> DirectVessel:
        """Convert AISPosition to DirectVessel"""
        vessel = DirectVessel(
            mmsi=pos.mmsi,
            lat=pos.latitude,
            lon=pos.longitude,
            speed=pos.speed,
            course=pos.course,
            heading=pos.heading,
            last_seen=pos.timestamp
        )

        if region:
            vessel.region = region
            vessel.chokepoint = region
        elif vessel.lat and vessel.lon:
            vessel.region = self._classify_region(vessel.lat, vessel.lon)
            vessel.chokepoint = vessel.region

        # Try to get additional vessel info
        try:
            info = self.manager.get_vessel_info(pos.mmsi)
            if info:
                vessel.name = info.name
                vessel.imo = info.imo
                vessel.flag = info.flag
                vessel.vessel_type = info.ship_type
                vessel.destination = info.destination
        except Exception:
            pass

        return vessel

    def _analyze_vessel(self, vessel: DirectVessel):
        """Run behavioral analysis on vessel"""
        if not HAS_BEHAVIOR:
            return

        try:
            # Check flag of convenience
            if vessel.flag:
                vessel.is_flag_of_convenience = is_flag_of_convenience(vessel.flag)
                vessel.is_shadow_fleet = is_shadow_fleet_flag(vessel.flag)

            # Calculate risk score based on indicators
            risk_score = 0

            if vessel.sanctions_match:
                risk_score += 40

            if vessel.is_dark or (vessel.ais_gap_hours and vessel.ais_gap_hours >= 4):
                risk_score += 30

            if vessel.is_flag_of_convenience:
                risk_score += 10

            if vessel.is_shadow_fleet:
                risk_score += 20

            if vessel.age_years and vessel.age_years >= 20:
                risk_score += 15

            if vessel.in_sts_transfer:
                risk_score += 25

            vessel.dark_fleet_score = min(risk_score, 100)
            vessel.risk_level = self._calculate_risk_level(risk_score)

        except Exception as e:
            logger.warning(f"Behavioral analysis error: {e}")

    def collect_all(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect all maritime data for specified regions.

        Args:
            regions: List of chokepoint IDs to collect. If None, collects all.

        Returns:
            Complete maritime intelligence data
        """
        if not self.is_available():
            logger.warning("AIS_Tracker not available - returning empty result")
            return self._empty_result()

        if not self._initialized:
            if not self.initialize():
                return self._empty_result()

        if regions is None:
            regions = list(self.CHOKEPOINTS.keys())

        all_vessels = []
        dark_ships = []
        chokepoint_summaries = {}

        for region in regions:
            try:
                vessels = self.get_vessels_in_region(region)
                all_vessels.extend(vessels)

                # Identify dark ships (high risk)
                for v in vessels:
                    if v.is_dark or v.risk_level in ("critical", "high"):
                        dark_ships.append(v)

                # Create summary
                risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
                for v in vessels:
                    risk_counts[v.risk_level] = risk_counts.get(v.risk_level, 0) + 1

                chokepoint_summaries[region] = {
                    "chokepoint_id": region,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "total_vessels": len(vessels),
                    "dark_ships": len([v for v in vessels if v.is_dark]),
                    "risk_breakdown": risk_counts,
                    "sanctions_vessels": len([v for v in vessels if v.sanctions_match]),
                }

            except Exception as e:
                logger.error(f"Error collecting region {region}: {e}")

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ais_tracker_direct",
            "vessels": [self._vessel_to_dict(v) for v in all_vessels],
            "dark_ships": [self._vessel_to_dict(v) for v in dark_ships],
            "alerts": [],
            "sts_transfers": [],
            "cable_proximity": [],
            "chokepoint_summaries": chokepoint_summaries,
            "statistics": {
                "total_vessels": len(all_vessels),
                "dark_ships": len(dark_ships),
                "sts_transfers": 0,
                "active_alerts": 0,
                "cable_risks": 0,
            }
        }

    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result"""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ais_tracker_direct",
            "vessels": [],
            "dark_ships": [],
            "alerts": [],
            "sts_transfers": [],
            "cable_proximity": [],
            "chokepoint_summaries": {},
            "statistics": {
                "total_vessels": 0,
                "dark_ships": 0,
                "sts_transfers": 0,
                "active_alerts": 0,
                "cable_risks": 0,
            }
        }

    def _vessel_to_dict(self, vessel: DirectVessel) -> Dict[str, Any]:
        """Convert vessel to dictionary"""
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
            "heading": vessel.heading,
            "destination": vessel.destination,
            "is_dark": vessel.is_dark,
            "ais_gap_hours": vessel.ais_gap_hours,
            "flag_changes": vessel.flag_changes,
            "age_years": vessel.age_years,
            "sanctions_match": vessel.sanctions_match,
            "near_cable": vessel.near_cable,
            "in_sts_transfer": vessel.in_sts_transfer,
            "dark_fleet_score": vessel.dark_fleet_score,
            "risk_level": vessel.risk_level,
            "is_flag_of_convenience": vessel.is_flag_of_convenience,
            "is_shadow_fleet": vessel.is_shadow_fleet,
            "region": vessel.region,
            "chokepoint": vessel.chokepoint,
        }

    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        status = {
            "available": self.is_available(),
            "initialized": self._initialized,
            "modules": {
                "ais_sources": HAS_AIS_SOURCES,
                "behavior": HAS_BEHAVIOR,
                "sanctions": HAS_SANCTIONS,
                "venezuela": HAS_VENEZUELA,
            }
        }

        if self.manager:
            status["manager"] = self.manager.get_status()

        return status


# Convenience functions
def collect_maritime_direct(regions: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Collect maritime data using direct AIS_Tracker integration.

    Args:
        regions: List of chokepoint regions to collect

    Returns:
        Maritime intelligence data
    """
    collector = DirectAISCollector()
    try:
        return collector.collect_all(regions=regions)
    finally:
        collector.close()


def check_vessel_sanctions(mmsi: str = None, imo: str = None, name: str = None) -> Dict[str, Any]:
    """
    Check vessel against sanctions lists.

    Args:
        mmsi: Vessel MMSI
        imo: Vessel IMO number
        name: Vessel name

    Returns:
        Sanctions check result
    """
    collector = DirectAISCollector()
    return collector.check_sanctions(mmsi=mmsi, imo=imo, name=name)
