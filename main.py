#!/usr/bin/env python3
"""
Geopolitical Threat Mapper - Main Orchestrator

Multi-layer situational awareness platform that correlates:
- Cyber threats (Shodan, OTX, abuse.ch)
- Maritime activity (AIS_Tracker)
- Aviation data (OpenSky Network)
- GPS interference (GPSJAM)
- News events (Google-News-Scraper)
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

from scripts.collectors import (
    InfrastructureCollector,
    IOCCollector,
    TelemetryCollector,
    VulnerabilityCollector,
    AISTrackerCollector,
    NewsScraperCollector,
    OpenSkyCollector,
    GPSJamCollector,
)
from scripts.processors import CorrelationEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ThreatMapper")

# Default regions to monitor
DEFAULT_REGIONS = [
    "baltic_sea",
    "black_sea",
    "red_sea",
    "taiwan_strait",
    "hormuz",
    "malacca",
]


class ThreatMapper:
    """Main orchestrator for the Geopolitical Threat Mapper"""

    def __init__(
        self,
        regions: Optional[List[str]] = None,
        config_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
    ):
        self.regions = regions or DEFAULT_REGIONS
        self.config_dir = config_dir or Path(__file__).parent / "scripts" / "config"
        self.output_dir = output_dir or Path(__file__).parent / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize correlation engine
        self.engine = CorrelationEngine(
            rules_path=str(self.config_dir / "correlation_rules.yaml"),
            chokepoints_path=str(self.config_dir / "chokepoints.geojson"),
        )

        # Collector instances (initialized on demand)
        self._collectors = {}

        # Store collected data for output generation
        self.collected_data = {}

    def _get_env(self, key: str, default: str = "") -> str:
        """Get environment variable"""
        return os.getenv(key, default)

    async def collect_cyber(self) -> dict:
        """Collect cyber threat intelligence"""
        logger.info("Collecting cyber intelligence...")
        results = {
            "exposed_services": [],
            "iocs": [],
            "attack_data": [],
            "vulnerabilities": [],
        }

        # Infrastructure (Shodan, etc.)
        shodan_key = self._get_env("SHODAN_API_KEY")
        if shodan_key:
            try:
                async with InfrastructureCollector() as collector:
                    data = await collector.collect_all_priority_countries()
                    results["exposed_services"] = list(data.values()) if data else []
                    logger.info(f"Collected exposure data for {len(results['exposed_services'])} countries")
            except Exception as e:
                logger.error(f"Infrastructure collection error: {e}")

        # IOCs (OTX, ThreatFox, etc.)
        otx_key = self._get_env("OTX_API_KEY")
        try:
            async with IOCCollector() as collector:
                iocs = await collector.collect_all()
                results["iocs"] = [ioc.to_dict() if hasattr(ioc, 'to_dict') else ioc for ioc in iocs]
                logger.info(f"Collected {len(results['iocs'])} IOCs")
        except Exception as e:
            logger.error(f"IOC collection error: {e}")

        # Attack telemetry (DShield, FireHOL)
        try:
            async with TelemetryCollector() as collector:
                data = await collector.collect_all()
                results["attack_data"] = data.get("events", [])
                logger.info(f"Collected {len(results['attack_data'])} attack records")
        except Exception as e:
            logger.error(f"Telemetry collection error: {e}")

        # Vulnerabilities (CISA KEV, NVD)
        try:
            async with VulnerabilityCollector() as collector:
                data = await collector.collect_all()
                all_vulns = data.get("kev", []) + data.get("recent", []) + data.get("strategic", [])
                results["vulnerabilities"] = all_vulns
                logger.info(f"Collected {len(results['vulnerabilities'])} vulnerabilities")
        except Exception as e:
            logger.error(f"Vulnerability collection error: {e}")

        # Ingest into correlation engine
        self.engine.ingest_cyber_data(results)

        return results

    async def collect_maritime(self) -> dict:
        """Collect maritime intelligence from AIS_Tracker"""
        logger.info("Collecting maritime intelligence...")

        ais_url = self._get_env("AIS_TRACKER_URL", "http://localhost:8080")

        try:
            async with AISTrackerCollector(base_url=ais_url) as collector:
                data = await collector.collect_all(regions=self.regions)

                logger.info(
                    f"Collected {data.get('statistics', {}).get('total_vessels', 0)} vessels, "
                    f"{data.get('statistics', {}).get('dark_ships', 0)} dark ships"
                )

                # Ingest into correlation engine
                self.engine.ingest_maritime_data(data)

                return data
        except Exception as e:
            logger.error(f"Maritime collection error: {e}")
            return {}

    async def collect_news(self) -> dict:
        """Collect news intelligence from Google-News-Scraper"""
        logger.info("Collecting news intelligence...")

        feed_path = self._get_env(
            "NEWS_SCRAPER_FEED",
            str(Path(__file__).parent.parent / "Google-News-Scraper" / "docs" / "feed.json")
        )
        api_url = self._get_env("NEWS_SCRAPER_API_URL")

        try:
            async with NewsScraperCollector(
                feed_path=feed_path if Path(feed_path).exists() else None,
                api_url=api_url if api_url else None,
            ) as collector:
                data = await collector.collect_all()

                logger.info(
                    f"Collected {data.get('statistics', {}).get('total_articles', 0)} articles, "
                    f"{data.get('statistics', {}).get('unique_apt_groups', 0)} APT groups mentioned"
                )

                # Ingest into correlation engine
                self.engine.ingest_news_data(data)

                return data
        except Exception as e:
            logger.error(f"News collection error: {e}")
            return {}

    async def collect_aviation(self) -> dict:
        """Collect aviation intelligence from OpenSky"""
        logger.info("Collecting aviation intelligence...")

        username = self._get_env("OPENSKY_USERNAME")
        password = self._get_env("OPENSKY_PASSWORD")

        try:
            async with OpenSkyCollector(
                username=username if username else None,
                password=password if password else None,
            ) as collector:
                data = await collector.collect_all(regions=self.regions)

                logger.info(
                    f"Collected {data.get('statistics', {}).get('total_aircraft', 0)} aircraft, "
                    f"{data.get('statistics', {}).get('military_count', 0)} military"
                )

                # Ingest into correlation engine
                self.engine.ingest_aviation_data(data)

                return data
        except Exception as e:
            logger.error(f"Aviation collection error: {e}")
            return {}

    async def collect_gps(self) -> dict:
        """Collect GPS interference data from GPSJAM"""
        logger.info("Collecting GPS interference data...")

        try:
            async with GPSJamCollector() as collector:
                data = await collector.collect_all(regions=self.regions)

                logger.info(
                    f"Collected {data.get('statistics', {}).get('total_zones', 0)} interference zones"
                )

                # Ingest into correlation engine
                self.engine.ingest_gps_data(data)

                return data
        except Exception as e:
            logger.error(f"GPS collection error: {e}")
            return {}

    async def run_collection(self) -> dict:
        """Run all data collection in parallel"""
        logger.info(f"Starting collection for regions: {', '.join(self.regions)}")

        # Run all collectors in parallel
        results = await asyncio.gather(
            self.collect_cyber(),
            self.collect_maritime(),
            self.collect_news(),
            self.collect_aviation(),
            self.collect_gps(),
            return_exceptions=True,
        )

        # Process results
        collected = {
            "cyber": results[0] if not isinstance(results[0], Exception) else {},
            "maritime": results[1] if not isinstance(results[1], Exception) else {},
            "news": results[2] if not isinstance(results[2], Exception) else {},
            "aviation": results[3] if not isinstance(results[3], Exception) else {},
            "gps": results[4] if not isinstance(results[4], Exception) else {},
        }

        # Log any exceptions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                source = ["cyber", "maritime", "news", "aviation", "gps"][i]
                logger.error(f"Collection failed for {source}: {result}")

        return collected

    def run_correlation(self) -> list:
        """Run correlation engine"""
        logger.info("Running correlation analysis...")

        correlations = self.engine.run_correlation()

        logger.info(f"Found {len(correlations)} correlations")
        for corr in correlations:
            logger.warning(
                f"[{corr.severity.value.upper()}] {corr.rule_name}: "
                f"{corr.description} (confidence: {corr.confidence:.0%})"
            )

        return correlations

    def generate_outputs(self):
        """Generate output files"""
        logger.info("Generating output files...")

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # 1. Threat feed (JSON) - includes raw data for UI
        feed = self.engine.export_feed()
        # Add raw collected data for UI consumption
        if hasattr(self, 'collected_data'):
            feed["cyber"] = self.collected_data.get("cyber", {})
            feed["maritime"] = self.collected_data.get("maritime", {})
            feed["aviation"] = self.collected_data.get("aviation", {})
            feed["gps"] = self.collected_data.get("gps", {})
            feed["news"] = self.collected_data.get("news", {})
        feed_path = self.output_dir / "feed.json"
        with open(feed_path, "w", encoding="utf-8") as f:
            json.dump(feed, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"Wrote threat feed to {feed_path}")

        # 2. Cyber heatmap (JSON)
        heatmap = self.engine.get_threat_heatmap()
        heatmap_path = self.output_dir / "cyber_heatmap.json"
        with open(heatmap_path, "w", encoding="utf-8") as f:
            json.dump(heatmap, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"Wrote heatmap to {heatmap_path}")

        # 3. Daily brief (Markdown)
        brief = self.engine.generate_daily_brief()
        brief_path = self.output_dir / "daily_brief.md"
        with open(brief_path, "w", encoding="utf-8") as f:
            f.write(brief)
        logger.info(f"Wrote daily brief to {brief_path}")

        # 4. Timestamped archive
        archive_dir = self.output_dir / "archive"
        archive_dir.mkdir(exist_ok=True)
        archive_path = archive_dir / f"feed_{timestamp}.json"
        with open(archive_path, "w", encoding="utf-8") as f:
            json.dump(feed, f, indent=2, default=str, ensure_ascii=False)

        return {
            "feed": str(feed_path),
            "heatmap": str(heatmap_path),
            "brief": str(brief_path),
            "archive": str(archive_path),
        }

    async def run(self):
        """Run the complete threat mapping pipeline"""
        start_time = datetime.utcnow()
        logger.info("=" * 60)
        logger.info("GEOPOLITICAL THREAT MAPPER")
        logger.info(f"Started at: {start_time.isoformat()}Z")
        logger.info("=" * 60)

        # Step 1: Collect data
        self.collected_data = await self.run_collection()

        # Step 2: Run correlation
        correlations = self.run_correlation()

        # Step 3: Generate outputs
        outputs = self.generate_outputs()

        # Summary
        elapsed = (datetime.utcnow() - start_time).total_seconds()
        logger.info("=" * 60)
        logger.info("COLLECTION COMPLETE")
        logger.info(f"Duration: {elapsed:.1f} seconds")
        logger.info(f"Correlations found: {len(correlations)}")
        logger.info(f"Outputs: {', '.join(outputs.values())}")
        logger.info("=" * 60)

        return {
            "correlations": len(correlations),
            "outputs": outputs,
            "duration_seconds": elapsed,
        }


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Geopolitical Threat Mapper - Multi-layer situational awareness platform"
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=None,
        help="Regions to monitor (default: all critical chokepoints)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to output directory",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Load environment variables
    load_dotenv()

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create and run mapper
    mapper = ThreatMapper(
        regions=args.regions,
        config_dir=args.config,
        output_dir=args.output,
    )

    asyncio.run(mapper.run())


if __name__ == "__main__":
    main()
