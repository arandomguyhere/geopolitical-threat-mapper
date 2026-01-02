"""Tests for data collectors"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

import sys
sys.path.insert(0, '.')

from scripts.collectors import (
    AISTrackerCollector,
    NewsScraperCollector,
    OpenSkyCollector,
    GPSJamCollector,
)
from scripts.collectors.maritime.ais_tracker import Vessel, VesselRisk, MaritimeAlert


class TestAISTrackerCollector:
    """Tests for AIS_Tracker integration"""

    def test_init(self):
        """Test collector initialization"""
        collector = AISTrackerCollector(base_url="http://localhost:8080")
        assert collector.base_url == "http://localhost:8080"
        assert len(collector.chokepoints) == 6

    def test_classify_region_baltic(self):
        """Test region classification for Baltic Sea"""
        collector = AISTrackerCollector()
        # Coordinates in Baltic Sea
        assert collector._classify_region(55.0, 15.0) == "baltic_sea"
        # Coordinates outside any region
        assert collector._classify_region(0.0, 0.0) is None

    def test_classify_region_taiwan(self):
        """Test region classification for Taiwan Strait"""
        collector = AISTrackerCollector()
        assert collector._classify_region(23.0, 119.0) == "taiwan_strait"

    def test_calculate_risk_level_critical(self):
        """Test critical risk calculation"""
        collector = AISTrackerCollector()
        vessel = {
            "is_dark": True,
            "sanctions_match": True,
            "near_cable": True,
        }
        assert collector._calculate_risk_level(vessel) == VesselRisk.CRITICAL

    def test_calculate_risk_level_high(self):
        """Test high risk calculation"""
        collector = AISTrackerCollector()
        vessel = {
            "is_dark": True,
            "flag_changes": 3,
        }
        assert collector._calculate_risk_level(vessel) == VesselRisk.HIGH

    def test_calculate_risk_level_unknown(self):
        """Test unknown risk calculation"""
        collector = AISTrackerCollector()
        vessel = {}
        assert collector._calculate_risk_level(vessel) == VesselRisk.UNKNOWN


class TestNewsScraperCollector:
    """Tests for News Scraper integration"""

    def test_init(self):
        """Test collector initialization"""
        collector = NewsScraperCollector(feed_path="/path/to/feed.json")
        assert collector.max_age_hours == 168  # 1 week default

    def test_classify_categories_apt(self):
        """Test APT category classification"""
        collector = NewsScraperCollector()
        article = {
            "title": "APT28 targets critical infrastructure",
            "summary": "Nation-state threat actor",
        }
        categories = collector._classify_categories(article)
        assert any(c.value == "apt" for c in categories)

    def test_classify_categories_ransomware(self):
        """Test ransomware category classification"""
        collector = NewsScraperCollector()
        article = {
            "title": "LockBit ransomware hits hospital",
            "summary": "",
        }
        categories = collector._classify_categories(article)
        assert any(c.value == "ransomware" for c in categories)

    def test_extract_apt_groups(self):
        """Test APT group extraction"""
        collector = NewsScraperCollector()
        article = {
            "title": "APT28 and APT29 conduct joint operation",
            "categories": ["APT28"],
            "summary": "Russia-linked groups",
        }
        groups = collector._extract_apt_groups(article)
        assert "APT28" in groups

    def test_detect_regions(self):
        """Test region detection from article"""
        collector = NewsScraperCollector()
        article = {
            "title": "Baltic Sea cable cut in sabotage",
            "summary": "Finland investigating",
        }
        regions = collector._detect_regions(article)
        assert "baltic_sea" in regions


class TestOpenSkyCollector:
    """Tests for OpenSky aviation collector"""

    def test_init(self):
        """Test collector initialization"""
        collector = OpenSkyCollector()
        # Primary source is now Airplanes.Live (OpenSky requires OAuth2 since 2025)
        assert collector.base_url == "https://api.airplanes.live/v2"
        assert "opensky" in collector.sources  # OpenSky is fallback
        assert len(collector.chokepoints) == 8

    def test_classify_military_us(self):
        """Test US military aircraft classification"""
        collector = OpenSkyCollector()
        category, is_mil, is_special = collector._classify_aircraft("ae1234", "REACH01")
        assert is_mil is True

    def test_classify_military_callsign(self):
        """Test military classification by callsign"""
        collector = OpenSkyCollector()
        category, is_mil, is_special = collector._classify_aircraft("123456", "FORTE11")
        assert is_mil is True

    def test_classify_civilian(self):
        """Test civilian aircraft classification"""
        collector = OpenSkyCollector()
        # Use icao24 prefix not in military list (4b = Switzerland)
        category, is_mil, is_special = collector._classify_aircraft("4b1234", "UAL123")
        assert is_mil is False

    def test_get_region_baltic(self):
        """Test region detection Baltic"""
        collector = OpenSkyCollector()
        assert collector._get_region(55.0, 20.0) == "baltic_sea"

    def test_get_region_none(self):
        """Test region detection outside monitored areas"""
        collector = OpenSkyCollector()
        assert collector._get_region(-20.0, -60.0) is None


class TestGPSJamCollector:
    """Tests for GPSJAM GPS interference collector"""

    def test_init(self):
        """Test collector initialization"""
        collector = GPSJamCollector()
        assert collector.base_url == "https://gpsjam.org"
        assert len(collector.chokepoints) == 6

    def test_classify_region(self):
        """Test region classification"""
        collector = GPSJamCollector()
        # 55.0, 21.0 is within both baltic_sea and kaliningrad, but baltic_sea comes first
        assert collector._classify_region(55.0, 21.0) == "baltic_sea"
        # Test eastern_med region
        assert collector._classify_region(35.0, 30.0) == "eastern_med"

    def test_get_attribution_kaliningrad(self):
        """Test attribution for Kaliningrad"""
        collector = GPSJamCollector()
        # Near Kaliningrad
        assert collector._get_attribution(54.7, 20.5) == "Russia"

    def test_get_attribution_unknown(self):
        """Test attribution for unknown location"""
        collector = GPSJamCollector()
        assert collector._get_attribution(0.0, 0.0) is None

    def test_parse_intensity(self):
        """Test intensity parsing"""
        collector = GPSJamCollector()
        from scripts.collectors.gps.gpsjam import IntensityLevel
        assert collector._parse_intensity(0) == IntensityLevel.NONE
        assert collector._parse_intensity(0.2) == IntensityLevel.LOW
        assert collector._parse_intensity(0.5) == IntensityLevel.MODERATE
        assert collector._parse_intensity(0.7) == IntensityLevel.HIGH
        assert collector._parse_intensity(0.9) == IntensityLevel.SEVERE
