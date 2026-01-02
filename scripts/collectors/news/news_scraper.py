"""
Google-News-Scraper Integration Collector

Connects to the user's Google-News-Scraper output for threat intelligence:
- APT group activity (60+ tracked groups)
- Sector-specific threats
- Geopolitical events
- Sentiment analysis
- Threat categorization
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from enum import Enum

import aiohttp

from ..base import BaseCollector

logger = logging.getLogger(__name__)


class ThreatCategory(Enum):
    """Threat categories from news"""
    APT = "apt"
    RANSOMWARE = "ransomware"
    MARITIME = "maritime"
    AVIATION = "aviation"
    INFRASTRUCTURE = "infrastructure"
    SANCTIONS = "sanctions"
    CONFLICT = "conflict"
    CYBER = "cyber"
    GPS_INTERFERENCE = "gps_interference"
    GEOPOLITICAL = "geopolitical"
    UNKNOWN = "unknown"


# APT group to country attribution
APT_ATTRIBUTION = {
    # Russia
    "APT28": "RU", "APT29": "RU", "Sandworm": "RU", "Fancy Bear": "RU",
    "Cozy Bear": "RU", "Turla": "RU", "Gamaredon": "RU", "Dragonfly": "RU",
    "Energetic Bear": "RU", "Berserk Bear": "RU", "Voodoo Bear": "RU",
    "Primitive Bear": "RU", "Venomous Bear": "RU", "Star Blizzard": "RU",
    "Midnight Blizzard": "RU", "Forest Blizzard": "RU", "Seashell Blizzard": "RU",

    # China
    "APT1": "CN", "APT3": "CN", "APT10": "CN", "APT17": "CN", "APT27": "CN",
    "APT30": "CN", "APT31": "CN", "APT40": "CN", "APT41": "CN",
    "Volt Typhoon": "CN", "Salt Typhoon": "CN", "Flax Typhoon": "CN",
    "Charcoal Typhoon": "CN", "Mustang Panda": "CN", "Winnti": "CN",
    "Stone Panda": "CN", "Gothic Panda": "CN", "Wicked Panda": "CN",
    "Double Dragon": "CN", "RedDelta": "CN", "Earth Lusca": "CN",

    # North Korea
    "APT37": "KP", "APT38": "KP", "Lazarus": "KP", "Kimsuky": "KP",
    "Reaper": "KP", "ScarCruft": "KP", "Ricochet Chollima": "KP",
    "Labyrinth Chollima": "KP", "Andariel": "KP", "BlueNoroff": "KP",

    # Iran
    "APT33": "IR", "APT34": "IR", "APT35": "IR", "APT39": "IR",
    "Charming Kitten": "IR", "Magic Hound": "IR", "Elfin": "IR",
    "OilRig": "IR", "Helix Kitten": "IR", "MuddyWater": "IR",
    "Static Kitten": "IR", "Pioneer Kitten": "IR", "Imperial Kitten": "IR",

    # Other
    "APT32": "VN", "APT36": "PK", "Transparent Tribe": "PK",
    "Sidewinder": "IN", "Bitter": "IN", "Donot": "IN",
}

# Keywords for threat category classification
CATEGORY_KEYWORDS = {
    ThreatCategory.APT: [
        "apt", "threat actor", "nation-state", "cyber espionage",
        "advanced persistent", "state-sponsored", "cyber attack",
    ],
    ThreatCategory.RANSOMWARE: [
        "ransomware", "lockbit", "blackcat", "alphv", "clop", "royal",
        "black basta", "play ransomware", "ransom", "encryption",
    ],
    ThreatCategory.MARITIME: [
        "vessel", "ship", "maritime", "tanker", "cargo", "port",
        "ais", "shadow fleet", "dark fleet", "shipping", "naval",
        "submarine", "coast guard", "sts transfer", "cable sabotage",
    ],
    ThreatCategory.AVIATION: [
        "aircraft", "aviation", "airline", "flight", "airspace",
        "adiz", "drone", "uav", "missile", "air force", "fighter",
    ],
    ThreatCategory.INFRASTRUCTURE: [
        "infrastructure", "power grid", "pipeline", "cable",
        "water treatment", "dam", "energy", "utility", "scada", "ics",
        "critical infrastructure", "subsea cable",
    ],
    ThreatCategory.SANCTIONS: [
        "sanctions", "ofac", "treasury", "evasion", "embargo",
        "blacklist", "designated", "blocked", "prohibited",
    ],
    ThreatCategory.CONFLICT: [
        "conflict", "war", "military", "attack", "strike", "bombing",
        "invasion", "occupation", "tensions", "escalation",
        "houthi", "ukraine", "taiwan", "israel", "gaza",
    ],
    ThreatCategory.GPS_INTERFERENCE: [
        "gps jamming", "gps spoofing", "gnss", "navigation",
        "interference", "electronic warfare", "gps", "positioning",
    ],
    ThreatCategory.GEOPOLITICAL: [
        "geopolitical", "diplomacy", "summit", "treaty", "alliance",
        "nato", "eu", "un", "security council", "bilateral",
    ],
}

# Region keyword mapping
REGION_KEYWORDS = {
    "baltic_sea": ["baltic", "finland", "sweden", "estonia", "latvia", "lithuania", "poland", "denmark", "kaliningrad"],
    "black_sea": ["black sea", "crimea", "ukraine", "romania", "bulgaria", "turkey", "odessa", "sevastopol"],
    "red_sea": ["red sea", "houthi", "yemen", "bab el-mandeb", "suez", "aden", "saudi", "egypt"],
    "taiwan_strait": ["taiwan", "china", "pla", "adiz", "median line", "taipei", "beijing", "south china sea"],
    "hormuz": ["hormuz", "iran", "persian gulf", "uae", "oman", "irgc", "tanker", "strait of hormuz"],
    "malacca": ["malacca", "singapore", "malaysia", "indonesia", "strait", "southeast asia"],
}


@dataclass
class NewsArticle:
    """News article from Google-News-Scraper"""
    id: str
    title: str
    source: str
    url: str
    published_at: Optional[datetime] = None
    summary: Optional[str] = None
    content: Optional[str] = None

    # Analysis from scraper
    categories: List[str] = field(default_factory=list)
    apt_groups: List[str] = field(default_factory=list)
    sectors: List[str] = field(default_factory=list)
    sentiment: Optional[str] = None  # positive, negative, neutral
    confidence_score: float = 0.0
    threat_level: int = 0  # 1-10

    # Enrichment
    threat_categories: List[ThreatCategory] = field(default_factory=list)
    attributed_countries: List[str] = field(default_factory=list)
    regions: List[str] = field(default_factory=list)
    entities: Dict[str, List[str]] = field(default_factory=dict)  # vessels, ips, domains, etc.


@dataclass
class ThreatIntelligence:
    """Aggregated threat intelligence from news"""
    timestamp: datetime
    articles_analyzed: int
    apt_mentions: Dict[str, int] = field(default_factory=dict)
    region_activity: Dict[str, int] = field(default_factory=dict)
    threat_trends: Dict[str, int] = field(default_factory=dict)
    high_priority_articles: List[NewsArticle] = field(default_factory=list)
    country_attribution: Dict[str, int] = field(default_factory=dict)


class NewsScraperCollector(BaseCollector):
    """
    Collector for Google-News-Scraper threat intelligence

    Can read from:
    - Local feed.json file
    - API endpoint (if configured)

    Expected feed.json structure:
    {
        "articles": [
            {
                "title": "...",
                "source": "...",
                "url": "...",
                "published_at": "...",
                "categories": ["APT28", "Russia", "Ukraine"],
                "sentiment": "negative",
                "confidence_score": 0.85,
                "threat_level": 8
            }
        ]
    }
    """

    def __init__(
        self,
        feed_path: Optional[str] = None,
        api_url: Optional[str] = None,
        max_age_hours: int = 168,  # 1 week default
    ):
        self.feed_path = Path(feed_path) if feed_path else None
        self.api_url = api_url
        self.max_age_hours = max_age_hours
        self.session: Optional[aiohttp.ClientSession] = None
        self._article_cache: Dict[str, NewsArticle] = {}

    async def init_session(self):
        """Initialize HTTP session for API access"""
        if self.api_url:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    def _classify_categories(self, article: Dict[str, Any]) -> List[ThreatCategory]:
        """Classify article into threat categories"""
        categories = set()
        text = f"{article.get('title', '')} {article.get('summary', '')} {' '.join(article.get('categories', []))}".lower()

        for category, keywords in CATEGORY_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                categories.add(category)

        return list(categories) if categories else [ThreatCategory.UNKNOWN]

    def _extract_apt_groups(self, article: Dict[str, Any]) -> List[str]:
        """Extract APT group mentions"""
        apt_groups = set()
        text = f"{article.get('title', '')} {article.get('summary', '')} {article.get('content', '')}".upper()
        categories = [c.upper() for c in article.get("categories", [])]

        # Check categories first
        for apt in APT_ATTRIBUTION.keys():
            if apt.upper() in categories or apt.upper() in text:
                apt_groups.add(apt)

        # Also check for common aliases
        aliases = {
            "FANCY BEAR": "APT28", "COZY BEAR": "APT29",
            "LAZARUS GROUP": "Lazarus", "HIDDEN COBRA": "Lazarus",
        }
        for alias, canonical in aliases.items():
            if alias in text:
                apt_groups.add(canonical)

        return list(apt_groups)

    def _get_attribution(self, apt_groups: List[str]) -> List[str]:
        """Get country attribution for APT groups"""
        countries = set()
        for apt in apt_groups:
            if apt in APT_ATTRIBUTION:
                countries.add(APT_ATTRIBUTION[apt])
        return list(countries)

    def _detect_regions(self, article: Dict[str, Any]) -> List[str]:
        """Detect which regions are mentioned"""
        regions = set()
        text = f"{article.get('title', '')} {article.get('summary', '')}".lower()

        for region, keywords in REGION_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                regions.add(region)

        return list(regions)

    def _extract_entities(self, article: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract entities from article (IPs, domains, vessels, etc.)"""
        entities: Dict[str, List[str]] = {
            "ips": [],
            "domains": [],
            "cves": [],
            "vessels": [],
            "hashes": [],
        }

        text = article.get("content", "") or article.get("summary", "")
        if not text:
            return entities

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        entities["ips"] = list(set(re.findall(ip_pattern, text)))

        # CVEs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        entities["cves"] = list(set(re.findall(cve_pattern, text, re.IGNORECASE)))

        # MD5/SHA hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        entities["hashes"] = list(set(re.findall(hash_pattern, text)))

        return entities

    def _parse_article(self, data: Dict[str, Any], idx: int = 0) -> NewsArticle:
        """Parse raw article data into NewsArticle"""
        # Generate ID if not present
        article_id = data.get("id") or data.get("url", f"article_{idx}")

        # Parse published date
        published_at = None
        pub_str = data.get("published_at") or data.get("date") or data.get("timestamp")
        if pub_str:
            try:
                if isinstance(pub_str, str):
                    # Try various formats
                    for fmt in [
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d",
                    ]:
                        try:
                            published_at = datetime.strptime(pub_str, fmt)
                            break
                        except ValueError:
                            continue
                    if not published_at:
                        published_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Extract APT groups and categories
        apt_groups = self._extract_apt_groups(data)
        threat_categories = self._classify_categories(data)
        regions = self._detect_regions(data)
        entities = self._extract_entities(data)
        attributed_countries = self._get_attribution(apt_groups)

        return NewsArticle(
            id=str(article_id),
            title=data.get("title", ""),
            source=data.get("source", ""),
            url=data.get("url", ""),
            published_at=published_at,
            summary=data.get("summary") or data.get("description"),
            content=data.get("content"),
            categories=data.get("categories", []),
            apt_groups=apt_groups,
            sectors=data.get("sectors", []),
            sentiment=data.get("sentiment"),
            confidence_score=data.get("confidence_score", 0.0),
            threat_level=data.get("threat_level", 0),
            threat_categories=threat_categories,
            attributed_countries=attributed_countries,
            regions=regions,
            entities=entities,
        )

    async def _load_from_file(self) -> List[Dict[str, Any]]:
        """Load articles from local feed.json file"""
        if not self.feed_path or not self.feed_path.exists():
            logger.warning(f"Feed file not found: {self.feed_path}")
            return []

        try:
            with open(self.feed_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Handle different structures
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return data.get("articles", data.get("items", []))
            return []

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing feed.json: {e}")
            return []
        except Exception as e:
            logger.error(f"Error loading feed file: {e}")
            return []

    async def _load_from_api(self) -> List[Dict[str, Any]]:
        """Load articles from API endpoint"""
        if not self.api_url or not self.session:
            return []

        try:
            async with self.session.get(self.api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, list):
                        return data
                    return data.get("articles", [])
                else:
                    logger.warning(f"API returned status {response.status}")
                    return []
        except Exception as e:
            logger.error(f"Error fetching from API: {e}")
            return []

    async def get_articles(
        self,
        max_age_hours: Optional[int] = None,
        regions: Optional[List[str]] = None,
        categories: Optional[List[ThreatCategory]] = None,
        min_threat_level: int = 0,
    ) -> List[NewsArticle]:
        """Get articles with optional filtering"""
        # Load raw data
        if self.api_url:
            raw_articles = await self._load_from_api()
        else:
            raw_articles = await self._load_from_file()

        if not raw_articles:
            return []

        # Parse and filter
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours or self.max_age_hours)
        articles = []

        for idx, raw in enumerate(raw_articles):
            article = self._parse_article(raw, idx)

            # Age filter
            if article.published_at and article.published_at < cutoff:
                continue

            # Region filter
            if regions and not any(r in article.regions for r in regions):
                continue

            # Category filter
            if categories and not any(c in article.threat_categories for c in categories):
                continue

            # Threat level filter
            if article.threat_level < min_threat_level:
                continue

            articles.append(article)
            self._article_cache[article.id] = article

        return articles

    async def get_apt_intelligence(self) -> Dict[str, Any]:
        """Get APT-specific intelligence from news"""
        articles = await self.get_articles()

        apt_mentions: Dict[str, int] = {}
        apt_articles: Dict[str, List[str]] = {}  # APT -> article IDs
        country_activity: Dict[str, int] = {}

        for article in articles:
            for apt in article.apt_groups:
                apt_mentions[apt] = apt_mentions.get(apt, 0) + 1
                if apt not in apt_articles:
                    apt_articles[apt] = []
                apt_articles[apt].append(article.id)

                # Country attribution
                if apt in APT_ATTRIBUTION:
                    country = APT_ATTRIBUTION[apt]
                    country_activity[country] = country_activity.get(country, 0) + 1

        # Sort by mention count
        top_apts = sorted(apt_mentions.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_articles": len(articles),
            "apt_mentions": dict(top_apts),
            "apt_articles": {k: v for k, v in apt_articles.items() if k in dict(top_apts)},
            "country_activity": country_activity,
            "attribution_map": APT_ATTRIBUTION,
        }

    async def get_region_intelligence(self) -> Dict[str, Any]:
        """Get region-specific intelligence from news"""
        articles = await self.get_articles()

        region_activity: Dict[str, Dict[str, Any]] = {}
        for region in REGION_KEYWORDS.keys():
            region_activity[region] = {
                "article_count": 0,
                "threat_level_avg": 0.0,
                "apt_groups": set(),
                "categories": set(),
                "recent_titles": [],
            }

        for article in articles:
            for region in article.regions:
                if region in region_activity:
                    region_activity[region]["article_count"] += 1
                    region_activity[region]["apt_groups"].update(article.apt_groups)
                    region_activity[region]["categories"].update(
                        c.value for c in article.threat_categories
                    )
                    if len(region_activity[region]["recent_titles"]) < 5:
                        region_activity[region]["recent_titles"].append(article.title)

        # Convert sets to lists and calculate averages
        for region in region_activity:
            region_activity[region]["apt_groups"] = list(region_activity[region]["apt_groups"])
            region_activity[region]["categories"] = list(region_activity[region]["categories"])

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "regions": region_activity,
        }

    async def get_high_priority_articles(
        self,
        min_threat_level: int = 7,
        limit: int = 20
    ) -> List[NewsArticle]:
        """Get high-priority threat articles"""
        articles = await self.get_articles(min_threat_level=min_threat_level)

        # Sort by threat level, then by date
        sorted_articles = sorted(
            articles,
            key=lambda a: (a.threat_level, a.published_at or datetime.min),
            reverse=True
        )

        return sorted_articles[:limit]

    async def search_articles(
        self,
        keywords: List[str],
        match_all: bool = False,
    ) -> List[NewsArticle]:
        """Search articles by keywords"""
        articles = await self.get_articles()
        keywords_lower = [k.lower() for k in keywords]

        matches = []
        for article in articles:
            text = f"{article.title} {article.summary or ''} {' '.join(article.categories)}".lower()

            if match_all:
                if all(kw in text for kw in keywords_lower):
                    matches.append(article)
            else:
                if any(kw in text for kw in keywords_lower):
                    matches.append(article)

        return matches

    async def collect_all(self) -> Dict[str, Any]:
        """Collect all news intelligence"""
        articles = await self.get_articles()
        apt_intel = await self.get_apt_intelligence()
        region_intel = await self.get_region_intelligence()
        high_priority = await self.get_high_priority_articles()

        # Aggregate statistics
        category_counts: Dict[str, int] = {}
        sentiment_counts: Dict[str, int] = {"positive": 0, "negative": 0, "neutral": 0}

        for article in articles:
            for cat in article.threat_categories:
                category_counts[cat.value] = category_counts.get(cat.value, 0) + 1
            if article.sentiment:
                sentiment_counts[article.sentiment] = sentiment_counts.get(article.sentiment, 0) + 1

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "news_scraper",
            "articles": [self._article_to_dict(a) for a in articles],
            "high_priority": [self._article_to_dict(a) for a in high_priority],
            "apt_intelligence": apt_intel,
            "region_intelligence": region_intel,
            "statistics": {
                "total_articles": len(articles),
                "high_priority_count": len(high_priority),
                "category_breakdown": category_counts,
                "sentiment_breakdown": sentiment_counts,
                "unique_apt_groups": len(apt_intel.get("apt_mentions", {})),
                "active_regions": sum(
                    1 for r in region_intel.get("regions", {}).values()
                    if r.get("article_count", 0) > 0
                ),
            }
        }

    def _article_to_dict(self, article: NewsArticle) -> Dict[str, Any]:
        """Convert NewsArticle to dictionary"""
        return {
            "id": article.id,
            "title": article.title,
            "source": article.source,
            "url": article.url,
            "published_at": article.published_at.isoformat() if article.published_at else None,
            "summary": article.summary,
            "categories": article.categories,
            "apt_groups": article.apt_groups,
            "sectors": article.sectors,
            "sentiment": article.sentiment,
            "confidence_score": article.confidence_score,
            "threat_level": article.threat_level,
            "threat_categories": [c.value for c in article.threat_categories],
            "attributed_countries": article.attributed_countries,
            "regions": article.regions,
            "entities": article.entities,
        }
