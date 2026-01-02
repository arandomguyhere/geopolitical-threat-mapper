"""Tests for correlation engine"""

import pytest
from datetime import datetime, timedelta

import sys
sys.path.insert(0, '.')

from scripts.processors.correlation_engine import (
    CorrelationEngine,
    Event,
    EventSource,
    AlertSeverity,
)


class TestCorrelationEngine:
    """Tests for the correlation engine"""

    @pytest.fixture
    def engine(self):
        """Create engine with config files"""
        return CorrelationEngine(
            rules_path='scripts/config/correlation_rules.yaml',
            chokepoints_path='scripts/config/chokepoints.geojson',
        )

    @pytest.fixture
    def engine_no_config(self):
        """Create engine without config files"""
        return CorrelationEngine()

    def test_init_with_config(self, engine):
        """Test initialization with config files"""
        assert len(engine.rules) == 10
        assert len(engine.chokepoints) == 12
        assert "baltic_sea" in engine.chokepoints

    def test_init_without_config(self, engine_no_config):
        """Test initialization without config files"""
        assert engine_no_config.rules == []
        assert engine_no_config.chokepoints == {}

    def test_ingest_cyber_data(self, engine):
        """Test cyber data ingestion"""
        data = {
            "exposed_services": [
                {"ip": "1.2.3.4", "port": 22, "service": "ssh", "region": "baltic_sea"},
            ],
            "iocs": [
                {"value": "malware.com", "domain": "malware.com", "severity": "high"},
            ],
            "vulnerabilities": [
                {"cve_id": "CVE-2024-1234", "is_kev": True},
            ],
        }
        count = engine.ingest_cyber_data(data)
        assert count == 3
        assert len(engine.event_buffer["cyber"]) == 3

    def test_ingest_maritime_data(self, engine):
        """Test maritime data ingestion"""
        data = {
            "vessels": [
                {"mmsi": "123456789", "is_dark": True, "lat": 55.0, "lon": 15.0, "region": "baltic_sea"},
            ],
            "dark_ships": [
                {"mmsi": "987654321", "gap_hours": 10, "lat": 55.0, "lon": 15.0},
            ],
            "sts_transfers": [],
            "cable_proximity": [],
        }
        count = engine.ingest_maritime_data(data)
        assert count >= 1
        assert len(engine.event_buffer["maritime"]) >= 1

    def test_ingest_news_data(self, engine):
        """Test news data ingestion"""
        data = {
            "high_priority": [
                {
                    "id": "article1",
                    "title": "APT28 targets Baltic infrastructure",
                    "threat_level": 8,
                    "apt_groups": ["APT28"],
                    "regions": ["baltic_sea"],
                },
            ],
        }
        count = engine.ingest_news_data(data)
        assert count == 1
        assert len(engine.event_buffer["news"]) == 1

    def test_calculate_threat_score(self, engine):
        """Test threat score calculation"""
        # Add some events
        engine.ingest_cyber_data({
            "exposed_services": [{"ip": "1.2.3.4", "port": 22, "service": "ssh", "region": "baltic_sea"}] * 10,
            "iocs": [],
            "vulnerabilities": [],
        })

        score = engine.calculate_threat_score("baltic_sea")
        assert score.region == "baltic_sea"
        assert 0 <= score.overall_score <= 100
        assert score.cyber_score >= 0

    def test_score_to_level(self, engine):
        """Test score to level conversion"""
        assert engine._score_to_level(90) == "critical"
        assert engine._score_to_level(75) == "high"
        assert engine._score_to_level(60) == "medium"
        assert engine._score_to_level(35) == "low"
        assert engine._score_to_level(10) == "minimal"

    def test_get_threat_heatmap(self, engine):
        """Test threat heatmap generation"""
        heatmap = engine.get_threat_heatmap()
        assert "timestamp" in heatmap
        assert "regions" in heatmap
        assert "summary" in heatmap
        assert "baltic_sea" in heatmap["regions"]

    def test_generate_daily_brief(self, engine):
        """Test daily brief generation"""
        brief = engine.generate_daily_brief()
        assert "# Daily Geopolitical Threat Brief" in brief
        assert "Executive Summary" in brief
        assert "Regional Threat Scores" in brief

    def test_export_feed(self, engine):
        """Test feed export"""
        feed = engine.export_feed()
        assert "timestamp" in feed
        assert "threat_heatmap" in feed
        assert "active_correlations" in feed
        assert "event_counts" in feed

    def test_event_buffer_pruning(self, engine):
        """Test that old events are pruned"""
        # Add old event
        old_event = Event(
            id="old_event",
            source=EventSource.CYBER,
            event_type="test",
            timestamp=datetime.utcnow() - timedelta(hours=48),
        )
        engine.event_buffer["cyber"].append(old_event)

        # Add new event
        new_event = Event(
            id="new_event",
            source=EventSource.CYBER,
            event_type="test",
            timestamp=datetime.utcnow(),
        )
        engine.event_buffer["cyber"].append(new_event)

        # Prune
        engine._prune_buffer("cyber", max_age_hours=24)

        # Old event should be gone
        ids = [e.id for e in engine.event_buffer["cyber"]]
        assert "old_event" not in ids
        assert "new_event" in ids


class TestEventMatching:
    """Tests for event matching logic"""

    @pytest.fixture
    def engine(self):
        return CorrelationEngine(
            rules_path='scripts/config/correlation_rules.yaml',
            chokepoints_path='scripts/config/chokepoints.geojson',
        )

    def test_event_matches_conditions_equals(self, engine):
        """Test equals operator"""
        event = Event(
            id="test",
            source=EventSource.MARITIME,
            event_type="sts_transfer",
            timestamp=datetime.utcnow(),
        )
        event.raw_data = {"event_type": "sts_transfer"}

        conditions = [{"field": "event_type", "operator": "==", "value": "sts_transfer"}]
        assert engine._event_matches_conditions(event, conditions)

    def test_event_matches_conditions_gte(self, engine):
        """Test >= operator"""
        event = Event(
            id="test",
            source=EventSource.AVIATION,
            event_type="military",
            timestamp=datetime.utcnow(),
        )
        event.raw_data = {"aircraft_count": 25}

        conditions = [{"field": "aircraft_count", "operator": ">=", "value": 20}]
        assert engine._event_matches_conditions(event, conditions)

    def test_event_matches_conditions_contains_any(self, engine):
        """Test contains_any matching"""
        event = Event(
            id="test",
            source=EventSource.NEWS,
            event_type="news",
            timestamp=datetime.utcnow(),
            description="Shadow fleet vessel detected near cable",
        )

        conditions = [{"field": "description", "contains_any": ["shadow fleet", "cable"]}]
        assert engine._event_matches_conditions(event, conditions)


class TestConfidenceCalculation:
    """Tests for confidence score calculation"""

    @pytest.fixture
    def engine(self):
        engine = CorrelationEngine()
        engine.scoring_config = {
            "confidence": {
                "base_single_source": 0.5,
                "base_two_sources": 0.7,
                "base_three_sources": 0.9,
                "multi_source_bonus": 0.1,
                "temporal_proximity_bonus": 0.1,
                "geo_proximity_bonus": 0.1,
                "max_confidence": 1.0,
            }
        }
        return engine

    def test_single_source_confidence(self, engine):
        """Test single source base confidence"""
        events = [
            Event(id="1", source=EventSource.CYBER, event_type="test", timestamp=datetime.utcnow()),
        ]
        confidence = engine._calculate_confidence(events, {"cyber"}, {})
        assert confidence == 0.5

    def test_two_source_confidence(self, engine):
        """Test two source base confidence"""
        events = [
            Event(id="1", source=EventSource.CYBER, event_type="test", timestamp=datetime.utcnow()),
            Event(id="2", source=EventSource.MARITIME, event_type="test", timestamp=datetime.utcnow()),
        ]
        confidence = engine._calculate_confidence(events, {"cyber", "maritime"}, {})
        assert confidence >= 0.7

    def test_temporal_proximity_bonus(self, engine):
        """Test temporal proximity adds bonus"""
        now = datetime.utcnow()
        events = [
            Event(id="1", source=EventSource.CYBER, event_type="test", timestamp=now),
            Event(id="2", source=EventSource.NEWS, event_type="test", timestamp=now),
        ]
        confidence = engine._calculate_confidence(events, {"cyber", "news"}, {})
        # Should get base (0.7) + multi-source bonus (0.1) + temporal bonus (0.1)
        assert confidence >= 0.8

    def test_geo_proximity_bonus(self, engine):
        """Test geographic proximity adds bonus"""
        now = datetime.utcnow()
        events = [
            Event(id="1", source=EventSource.CYBER, event_type="test", timestamp=now, lat=55.0, lon=15.0),
            Event(id="2", source=EventSource.MARITIME, event_type="test", timestamp=now, lat=55.1, lon=15.1),
        ]
        confidence = engine._calculate_confidence(events, {"cyber", "maritime"}, {})
        # Should get various bonuses including geo
        assert confidence >= 0.9
