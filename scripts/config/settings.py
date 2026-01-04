"""
Configuration loader for Geopolitical Threat Mapper
Follows the same pattern as AIS_Tracker for API key management
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)


@dataclass
class CyberInfrastructureConfig:
    """Layer 1: Infrastructure Exposure (Shodan-style)"""
    shodan_api_key: Optional[str] = None
    criminal_ip_api_key: Optional[str] = None
    leakix_api_key: Optional[str] = None
    zoomeye_api_key: Optional[str] = None
    netlas_api_key: Optional[str] = None

    # Endpoints
    shodan_base_url: str = "https://api.shodan.io"
    criminal_ip_base_url: str = "https://api.criminalip.io"
    leakix_base_url: str = "https://leakix.net"
    zoomeye_base_url: str = "https://api.zoomeye.ai"
    netlas_base_url: str = "https://app.netlas.io/api"

    def get_available_sources(self) -> List[str]:
        """Return list of configured infrastructure sources"""
        sources = []
        if self.shodan_api_key:
            sources.append("shodan")
        if self.criminal_ip_api_key:
            sources.append("criminal_ip")
        if self.leakix_api_key:
            sources.append("leakix")
        if self.zoomeye_api_key:
            sources.append("zoomeye")
        if self.netlas_api_key:
            sources.append("netlas")
        return sources


@dataclass
class CyberIOCConfig:
    """Layer 2: Threat Actor IOCs (OTX-style)"""
    otx_api_key: Optional[str] = None
    pulsedive_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    opencti_url: Optional[str] = None
    opencti_api_key: Optional[str] = None

    # Endpoints
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    pulsedive_base_url: str = "https://pulsedive.com/api"
    greynoise_base_url: str = "https://api.greynoise.io/v3"

    # No-auth feeds (always available)
    threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1"
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1"
    malwarebazaar_url: str = "https://mb-api.abuse.ch/api/v1"
    feodo_url: str = "https://feodotracker.abuse.ch/downloads"

    def get_available_sources(self) -> List[str]:
        """Return list of configured IOC sources"""
        # These are always available (no auth required)
        sources = ["threatfox", "urlhaus", "malwarebazaar", "feodo"]

        if self.otx_api_key:
            sources.append("otx")
        if self.pulsedive_api_key:
            sources.append("pulsedive")
        if self.greynoise_api_key:
            sources.append("greynoise")
        if self.misp_url and self.misp_api_key:
            sources.append("misp")
        if self.opencti_url and self.opencti_api_key:
            sources.append("opencti")
        return sources


@dataclass
class CyberTelemetryConfig:
    """Layer 3: Attack Telemetry (Shadowserver/DShield-style)"""
    dshield_api_key: Optional[str] = None
    shadowserver_api_key: Optional[str] = None

    # Endpoints
    dshield_base_url: str = "https://isc.sans.edu/api"
    shadowserver_dashboard_url: str = "https://dashboard.shadowserver.org"

    # No-auth feeds
    firehol_base_url: str = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"
    dataplane_base_url: str = "https://dataplane.org"
    cins_url: str = "https://cinsscore.com/list/ci-badguys.txt"

    def get_available_sources(self) -> List[str]:
        """Return list of configured telemetry sources"""
        # These are always available
        sources = ["firehol", "dataplane", "cins"]

        if self.dshield_api_key:
            sources.append("dshield")
        if self.shadowserver_api_key:
            sources.append("shadowserver")
        return sources


@dataclass
class VulnerabilityConfig:
    """Layer 4: Vulnerability Intelligence"""
    nvd_api_key: Optional[str] = None
    vuldb_api_key: Optional[str] = None

    # Endpoints (most don't require keys)
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json"
    cvedb_base_url: str = "https://cvedb.shodan.io"  # No key required
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    exploitdb_url: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    def get_available_sources(self) -> List[str]:
        """Return list of configured vulnerability sources"""
        # These are always available
        sources = ["cvedb", "cisa_kev", "exploitdb"]

        if self.nvd_api_key:
            sources.append("nvd_authenticated")
        else:
            sources.append("nvd_anonymous")
        if self.vuldb_api_key:
            sources.append("vuldb")
        return sources


@dataclass
class AviationConfig:
    """Aviation/ADS-B Layer"""
    opensky_username: Optional[str] = None
    opensky_password: Optional[str] = None
    adsbx_api_key: Optional[str] = None

    # Endpoints
    opensky_base_url: str = "https://opensky-network.org/api"
    adsbx_base_url: str = "https://adsbexchange-com1.p.rapidapi.com"

    # GPS Interference (no auth)
    gpsjam_url: str = "https://gpsjam.org"
    skai_spoofing_url: str = "https://spoofing.skai-data-services.com"

    def get_available_sources(self) -> List[str]:
        """Return list of configured aviation sources"""
        sources = ["opensky_anonymous", "gpsjam"]

        if self.opensky_username and self.opensky_password:
            sources.append("opensky_authenticated")
        if self.adsbx_api_key:
            sources.append("adsbx")
        return sources


@dataclass
class NewsConfig:
    """News & Geopolitical Events Layer"""
    news_scraper_feed_path: Optional[str] = None
    news_scraper_api_url: Optional[str] = None

    # GDELT (no auth required)
    gdelt_events_url: str = "https://api.gdeltproject.org/api/v2/doc/doc"
    gdelt_gkg_url: str = "https://api.gdeltproject.org/api/v2/context/context"

    def get_available_sources(self) -> List[str]:
        """Return list of configured news sources"""
        sources = ["gdelt"]

        if self.news_scraper_feed_path or self.news_scraper_api_url:
            sources.append("news_scraper")
        return sources


@dataclass
class MaritimeConfig:
    """Maritime Layer (integrates with AIS_Tracker)"""
    ais_tracker_api_url: Optional[str] = None
    gfw_api_key: Optional[str] = None

    # Endpoints
    gfw_base_url: str = "https://gateway.api.globalfishingwatch.org"

    def get_available_sources(self) -> List[str]:
        """Return list of configured maritime sources"""
        sources = []

        if self.ais_tracker_api_url:
            sources.append("ais_tracker")
        if self.gfw_api_key:
            sources.append("gfw")
        return sources


@dataclass
class SanctionsConfig:
    """Sanctions & Entity Data"""
    opensanctions_api_key: Optional[str] = None
    fleetleaks_api_key: Optional[str] = None

    # Endpoints
    opensanctions_base_url: str = "https://api.opensanctions.org"
    ofac_sdn_url: str = "https://www.treasury.gov/ofac/downloads/sdn.xml"
    ofac_consolidated_url: str = "https://www.treasury.gov/ofac/downloads/consolidated/consolidated.xml"

    def get_available_sources(self) -> List[str]:
        """Return list of configured sanctions sources"""
        # OFAC is always available (public download)
        sources = ["ofac_sdn", "ofac_consolidated"]

        if self.opensanctions_api_key:
            sources.append("opensanctions")
        if self.fleetleaks_api_key:
            sources.append("fleetleaks")
        return sources


@dataclass
class ServerConfig:
    """Server settings"""
    host: str = "0.0.0.0"
    port: int = 8081
    debug: bool = False
    database_path: str = "./data/threats.db"
    log_level: str = "INFO"
    log_file: str = "./logs/threat_mapper.log"

    # Update intervals (seconds)
    cyber_update_interval: int = 3600
    news_update_interval: int = 900
    aviation_update_interval: int = 300
    maritime_update_interval: int = 60


@dataclass
class Config:
    """Main configuration container"""
    cyber_infrastructure: CyberInfrastructureConfig = field(default_factory=CyberInfrastructureConfig)
    cyber_ioc: CyberIOCConfig = field(default_factory=CyberIOCConfig)
    cyber_telemetry: CyberTelemetryConfig = field(default_factory=CyberTelemetryConfig)
    vulnerability: VulnerabilityConfig = field(default_factory=VulnerabilityConfig)
    aviation: AviationConfig = field(default_factory=AviationConfig)
    news: NewsConfig = field(default_factory=NewsConfig)
    maritime: MaritimeConfig = field(default_factory=MaritimeConfig)
    sanctions: SanctionsConfig = field(default_factory=SanctionsConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    openai_api_key: Optional[str] = None

    def get_all_sources_status(self) -> Dict[str, List[str]]:
        """Get status of all configured sources by category"""
        return {
            "cyber_infrastructure": self.cyber_infrastructure.get_available_sources(),
            "cyber_ioc": self.cyber_ioc.get_available_sources(),
            "cyber_telemetry": self.cyber_telemetry.get_available_sources(),
            "vulnerability": self.vulnerability.get_available_sources(),
            "aviation": self.aviation.get_available_sources(),
            "news": self.news.get_available_sources(),
            "maritime": self.maritime.get_available_sources(),
            "sanctions": self.sanctions.get_available_sources(),
        }

    def print_status(self):
        """Print configuration status"""
        print("\n" + "="*60)
        print("GEOPOLITICAL THREAT MAPPER - CONFIGURATION STATUS")
        print("="*60)

        status = self.get_all_sources_status()
        for category, sources in status.items():
            print(f"\n{category.upper().replace('_', ' ')}:")
            if sources:
                for source in sources:
                    print(f"  ✓ {source}")
            else:
                print("  ✗ No sources configured")

        print("\n" + "="*60)


def load_config() -> Config:
    """Load configuration from environment variables"""

    config = Config(
        cyber_infrastructure=CyberInfrastructureConfig(
            shodan_api_key=os.getenv("SHODAN_API_KEY"),
            criminal_ip_api_key=os.getenv("CRIMINAL_IP_API_KEY"),
            leakix_api_key=os.getenv("LEAKIX_API_KEY"),
            zoomeye_api_key=os.getenv("ZOOMEYE_API_KEY"),
            netlas_api_key=os.getenv("NETLAS_API_KEY"),
        ),
        cyber_ioc=CyberIOCConfig(
            otx_api_key=os.getenv("OTX_API_KEY"),
            pulsedive_api_key=os.getenv("PULSEDIVE_API_KEY"),
            greynoise_api_key=os.getenv("GREYNOISE_API_KEY"),
            misp_url=os.getenv("MISP_URL"),
            misp_api_key=os.getenv("MISP_API_KEY"),
            opencti_url=os.getenv("OPENCTI_URL"),
            opencti_api_key=os.getenv("OPENCTI_API_KEY"),
        ),
        cyber_telemetry=CyberTelemetryConfig(
            dshield_api_key=os.getenv("DSHIELD_API_KEY"),
            shadowserver_api_key=os.getenv("SHADOWSERVER_API_KEY"),
        ),
        vulnerability=VulnerabilityConfig(
            nvd_api_key=os.getenv("NVD_API_KEY"),
            vuldb_api_key=os.getenv("VULDB_API_KEY"),
        ),
        aviation=AviationConfig(
            opensky_username=os.getenv("OPENSKY_USERNAME"),
            opensky_password=os.getenv("OPENSKY_PASSWORD"),
            adsbx_api_key=os.getenv("ADSBX_API_KEY"),
        ),
        news=NewsConfig(
            news_scraper_feed_path=os.getenv("NEWS_SCRAPER_FEED_PATH"),
            news_scraper_api_url=os.getenv("NEWS_SCRAPER_API_URL"),
        ),
        maritime=MaritimeConfig(
            ais_tracker_api_url=os.getenv("AIS_TRACKER_API_URL"),
            gfw_api_key=os.getenv("GFW_API_KEY"),
        ),
        sanctions=SanctionsConfig(
            opensanctions_api_key=os.getenv("OPENSANCTIONS_API_KEY"),
            fleetleaks_api_key=os.getenv("FLEETLEAKS_API_KEY"),
        ),
        server=ServerConfig(
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8081")),
            debug=os.getenv("DEBUG", "false").lower() == "true",
            database_path=os.getenv("DATABASE_PATH", "./data/threats.db"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "./logs/threat_mapper.log"),
            cyber_update_interval=int(os.getenv("CYBER_UPDATE_INTERVAL", "3600")),
            news_update_interval=int(os.getenv("NEWS_UPDATE_INTERVAL", "900")),
            aviation_update_interval=int(os.getenv("AVIATION_UPDATE_INTERVAL", "300")),
            maritime_update_interval=int(os.getenv("MARITIME_UPDATE_INTERVAL", "60")),
        ),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )

    return config


# Singleton instance
_config: Optional[Config] = None

def get_config() -> Config:
    """Get or create configuration singleton"""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reset_config():
    """Reset config singleton (forces reload on next get_config call)"""
    global _config
    _config = None


if __name__ == "__main__":
    # Test configuration loading
    config = load_config()
    config.print_status()
