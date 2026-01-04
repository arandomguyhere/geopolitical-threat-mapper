"""Data collectors for Geopolitical Threat Mapper"""

from .cyber import (
    InfrastructureCollector,
    IOCCollector,
    TelemetryCollector,
    VulnerabilityCollector,
)
from .maritime import AISTrackerCollector, DirectAISCollector
from .news import NewsScraperCollector
from .aviation import OpenSkyCollector
from .gps import GPSJamCollector

__all__ = [
    # Cyber
    "InfrastructureCollector",
    "IOCCollector",
    "TelemetryCollector",
    "VulnerabilityCollector",
    # Maritime
    "AISTrackerCollector",
    "DirectAISCollector",
    # News
    "NewsScraperCollector",
    # Aviation
    "OpenSkyCollector",
    # GPS
    "GPSJamCollector",
]
