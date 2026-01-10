"""
Narrative Tracker

Ported from situation-monitor intelligence.js for tracking:
- Narrative migration from fringe to mainstream sources
- Topic momentum and trending analysis
- Disinformation pattern detection
- Multi-source coverage correlation

This provides intelligence layer enrichment for the correlation engine.
"""

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class SourceTier(Enum):
    """Source credibility tiers"""
    MAINSTREAM = "mainstream"
    ALTERNATIVE = "alternative"
    FRINGE = "fringe"
    GOVERNMENT = "government"
    THINK_TANK = "think_tank"


# Source classification (from situation-monitor constants.js)
SOURCE_TIERS = {
    # Mainstream
    "bbc": SourceTier.MAINSTREAM,
    "reuters": SourceTier.MAINSTREAM,
    "associated press": SourceTier.MAINSTREAM,
    "ap news": SourceTier.MAINSTREAM,
    "new york times": SourceTier.MAINSTREAM,
    "washington post": SourceTier.MAINSTREAM,
    "wall street journal": SourceTier.MAINSTREAM,
    "financial times": SourceTier.MAINSTREAM,
    "the guardian": SourceTier.MAINSTREAM,
    "cnn": SourceTier.MAINSTREAM,
    "nbc": SourceTier.MAINSTREAM,
    "abc": SourceTier.MAINSTREAM,
    "cbs": SourceTier.MAINSTREAM,
    "npr": SourceTier.MAINSTREAM,
    "bloomberg": SourceTier.MAINSTREAM,
    "cnbc": SourceTier.MAINSTREAM,

    # Alternative
    "the intercept": SourceTier.ALTERNATIVE,
    "propublica": SourceTier.ALTERNATIVE,
    "bellingcat": SourceTier.ALTERNATIVE,
    "the daily beast": SourceTier.ALTERNATIVE,
    "politico": SourceTier.ALTERNATIVE,
    "axios": SourceTier.ALTERNATIVE,
    "the hill": SourceTier.ALTERNATIVE,

    # Think tanks
    "csis": SourceTier.THINK_TANK,
    "brookings": SourceTier.THINK_TANK,
    "cfr": SourceTier.THINK_TANK,
    "rand": SourceTier.THINK_TANK,
    "carnegie": SourceTier.THINK_TANK,
    "atlantic council": SourceTier.THINK_TANK,

    # Government
    "white house": SourceTier.GOVERNMENT,
    "state department": SourceTier.GOVERNMENT,
    "pentagon": SourceTier.GOVERNMENT,
    "treasury": SourceTier.GOVERNMENT,
    "cisa": SourceTier.GOVERNMENT,
}

# Topic patterns for tracking (from situation-monitor intelligence.js)
TOPIC_PATTERNS = {
    "conflict": [
        r"war\b", r"invasion", r"military\s+action", r"strike[sd]?\b",
        r"bombing", r"attack", r"offensive", r"escalation",
    ],
    "sanctions": [
        r"sanction", r"embargo", r"blacklist", r"ofac", r"treasury",
        r"evasion", r"asset\s+freeze",
    ],
    "cyber": [
        r"cyber\s*attack", r"hack", r"breach", r"ransomware", r"malware",
        r"apt\s*\d+", r"threat\s+actor", r"data\s+leak",
    ],
    "maritime": [
        r"vessel", r"ship", r"tanker", r"cargo", r"maritime",
        r"shadow\s+fleet", r"dark\s+fleet", r"cable\s+sabotage", r"subsea",
    ],
    "taiwan": [
        r"taiwan", r"taipei", r"strait", r"adiz", r"pla\s+navy",
        r"chinese\s+military", r"median\s+line",
    ],
    "ukraine": [
        r"ukraine", r"kyiv", r"zelensky", r"russian\s+forces",
        r"donbas", r"crimea", r"kherson",
    ],
    "iran": [
        r"iran", r"tehran", r"irgc", r"houthi", r"proxy",
        r"nuclear\s+program", r"strait\s+of\s+hormuz",
    ],
    "north_korea": [
        r"north\s+korea", r"pyongyang", r"kim\s+jong", r"dprk",
        r"icbm", r"nuclear\s+test",
    ],
    "infrastructure": [
        r"critical\s+infrastructure", r"power\s+grid", r"pipeline",
        r"water\s+treatment", r"ics", r"scada", r"cable\s+cut",
    ],
    "ai_threat": [
        r"ai\s+weapon", r"autonomous", r"deepfake", r"disinformation",
        r"synthetic\s+media", r"ai\s+generated",
    ],
}

# Known disinformation patterns
DISINFO_PATTERNS = [
    r"false\s+flag",
    r"crisis\s+actor",
    r"psyop",
    r"staged",
    r"hoax",
    r"conspiracy",
    r"cover[\s-]?up",
]

# Prominent figures to track (from situation-monitor)
PROMINENT_FIGURES = {
    "biden": "US",
    "trump": "US",
    "putin": "Russia",
    "zelensky": "Ukraine",
    "xi jinping": "China",
    "kim jong un": "North Korea",
    "khamenei": "Iran",
    "netanyahu": "Israel",
    "erdogan": "Turkey",
    "modi": "India",
}


@dataclass
class NarrativeEvent:
    """A narrative event from news"""
    id: str
    title: str
    source: str
    source_tier: SourceTier
    topics: List[str]
    figures: List[str]
    timestamp: datetime
    url: Optional[str] = None
    disinfo_flags: List[str] = field(default_factory=list)


@dataclass
class TopicMomentum:
    """Momentum tracking for a topic"""
    topic: str
    current_count: int
    previous_count: int
    delta: int
    momentum: str  # surging, rising, stable, declining
    sources: Set[str] = field(default_factory=set)
    source_tiers: Set[SourceTier] = field(default_factory=set)


@dataclass
class NarrativeCrossover:
    """Tracks when a narrative moves from fringe to mainstream"""
    topic: str
    first_seen_tier: SourceTier
    current_tier: SourceTier
    days_to_crossover: int
    confidence: float
    articles: List[str] = field(default_factory=list)


class NarrativeTracker:
    """
    Tracks narrative evolution across sources

    Ported from situation-monitor intelligence.js with enhancements:
    - Momentum detection (surging, rising, stable, declining)
    - Source tier tracking (fringe -> mainstream migration)
    - Disinformation pattern flagging
    - Prominent figure tracking
    """

    def __init__(self, history_window_hours: int = 168):  # 1 week
        self.history_window = timedelta(hours=history_window_hours)
        self.events: List[NarrativeEvent] = []
        self.topic_history: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        self.narrative_first_seen: Dict[str, Tuple[datetime, SourceTier]] = {}

    def classify_source(self, source: str) -> SourceTier:
        """Classify a source into tiers"""
        source_lower = source.lower()
        for pattern, tier in SOURCE_TIERS.items():
            if pattern in source_lower:
                return tier
        return SourceTier.ALTERNATIVE  # Default

    def extract_topics(self, text: str) -> List[str]:
        """Extract topics from text using pattern matching"""
        text_lower = text.lower()
        matched_topics = []

        for topic, patterns in TOPIC_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    matched_topics.append(topic)
                    break  # One match per topic

        return matched_topics

    def extract_figures(self, text: str) -> List[str]:
        """Extract prominent figures mentioned"""
        text_lower = text.lower()
        mentioned = []

        for figure in PROMINENT_FIGURES.keys():
            if figure in text_lower:
                mentioned.append(figure)

        return mentioned

    def check_disinfo_patterns(self, text: str) -> List[str]:
        """Check for disinformation pattern language"""
        text_lower = text.lower()
        flags = []

        for pattern in DISINFO_PATTERNS:
            if re.search(pattern, text_lower):
                flags.append(pattern)

        return flags

    def add_article(
        self,
        title: str,
        source: str,
        timestamp: Optional[datetime] = None,
        url: Optional[str] = None,
        content: Optional[str] = None,
    ) -> NarrativeEvent:
        """Add an article to the tracker"""
        text = f"{title} {content or ''}"

        event = NarrativeEvent(
            id=f"narrative_{hash(title)}_{hash(source)}",
            title=title,
            source=source,
            source_tier=self.classify_source(source),
            topics=self.extract_topics(text),
            figures=self.extract_figures(text),
            timestamp=timestamp or datetime.utcnow(),
            url=url,
            disinfo_flags=self.check_disinfo_patterns(text),
        )

        self.events.append(event)

        # Track first seen by topic
        for topic in event.topics:
            if topic not in self.narrative_first_seen:
                self.narrative_first_seen[topic] = (event.timestamp, event.source_tier)

        # Prune old events
        self._prune_events()

        return event

    def _prune_events(self):
        """Remove events outside the history window"""
        cutoff = datetime.utcnow() - self.history_window
        self.events = [e for e in self.events if e.timestamp > cutoff]

    def calculate_momentum(self, window_minutes: int = 60) -> Dict[str, TopicMomentum]:
        """
        Calculate momentum for each topic

        Compares current window to previous window to detect:
        - surging: >100% increase
        - rising: 25-100% increase
        - stable: -25% to +25%
        - declining: >25% decrease
        """
        now = datetime.utcnow()
        current_window = now - timedelta(minutes=window_minutes)
        previous_window = current_window - timedelta(minutes=window_minutes)

        # Count by topic in each window
        current_counts: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "sources": set(), "tiers": set()}
        )
        previous_counts: Dict[str, int] = defaultdict(int)

        for event in self.events:
            for topic in event.topics:
                if event.timestamp >= current_window:
                    current_counts[topic]["count"] += 1
                    current_counts[topic]["sources"].add(event.source)
                    current_counts[topic]["tiers"].add(event.source_tier)
                elif event.timestamp >= previous_window:
                    previous_counts[topic] += 1

        # Calculate momentum
        results = {}
        for topic in set(current_counts.keys()) | set(previous_counts.keys()):
            current = current_counts[topic]["count"]
            previous = previous_counts[topic]
            delta = current - previous

            # Determine momentum level
            if previous == 0:
                momentum = "surging" if current >= 3 else "rising" if current > 0 else "stable"
            else:
                pct_change = (delta / previous) * 100
                if pct_change >= 100:
                    momentum = "surging"
                elif pct_change >= 25:
                    momentum = "rising"
                elif pct_change <= -25:
                    momentum = "declining"
                else:
                    momentum = "stable"

            results[topic] = TopicMomentum(
                topic=topic,
                current_count=current,
                previous_count=previous,
                delta=delta,
                momentum=momentum,
                sources=current_counts[topic]["sources"],
                source_tiers=current_counts[topic]["tiers"],
            )

        return results

    def detect_crossovers(self) -> List[NarrativeCrossover]:
        """
        Detect narratives that have crossed from fringe to mainstream

        This is a key signal from situation-monitor - when fringe
        narratives start appearing in mainstream sources, it can
        indicate coordinated information operations.
        """
        crossovers = []

        # Group events by topic
        topic_events: Dict[str, List[NarrativeEvent]] = defaultdict(list)
        for event in self.events:
            for topic in event.topics:
                topic_events[topic].append(event)

        # Check each topic for tier migration
        tier_order = [
            SourceTier.FRINGE,
            SourceTier.ALTERNATIVE,
            SourceTier.THINK_TANK,
            SourceTier.MAINSTREAM,
            SourceTier.GOVERNMENT,
        ]

        for topic, events in topic_events.items():
            if len(events) < 2:
                continue

            # Sort by timestamp
            sorted_events = sorted(events, key=lambda e: e.timestamp)

            # Get first seen tier
            first_event = sorted_events[0]
            first_tier = first_event.source_tier

            # Get most recent mainstream tier
            mainstream_events = [
                e for e in sorted_events
                if e.source_tier in [SourceTier.MAINSTREAM, SourceTier.GOVERNMENT]
            ]

            if mainstream_events and first_tier in [SourceTier.FRINGE, SourceTier.ALTERNATIVE]:
                first_mainstream = mainstream_events[0]
                days_to_crossover = (first_mainstream.timestamp - first_event.timestamp).days

                crossovers.append(NarrativeCrossover(
                    topic=topic,
                    first_seen_tier=first_tier,
                    current_tier=SourceTier.MAINSTREAM,
                    days_to_crossover=days_to_crossover,
                    confidence=min(1.0, len(mainstream_events) / 5),  # More coverage = higher confidence
                    articles=[e.title for e in sorted_events[:5]],
                ))

        return crossovers

    def get_prominent_figure_activity(self) -> Dict[str, Dict[str, Any]]:
        """Track mentions of prominent figures"""
        figure_activity: Dict[str, Dict[str, Any]] = {}

        for figure, country in PROMINENT_FIGURES.items():
            mentions = [e for e in self.events if figure in e.figures]

            if mentions:
                # Get topics they're associated with
                topics = set()
                for event in mentions:
                    topics.update(event.topics)

                # Get sentiment direction (rough - based on disinfo flags)
                negative = sum(1 for e in mentions if e.disinfo_flags)

                figure_activity[figure] = {
                    "country": country,
                    "mention_count": len(mentions),
                    "topics": list(topics),
                    "sources": list(set(e.source for e in mentions)),
                    "potential_negative": negative,
                    "latest": mentions[-1].title if mentions else None,
                }

        return figure_activity

    def analyze(self) -> Dict[str, Any]:
        """
        Run full narrative analysis

        Returns comprehensive intelligence on:
        - Topic momentum (what's trending)
        - Narrative crossovers (fringe -> mainstream)
        - Figure activity (who's in the news)
        - Disinformation signals
        """
        momentum = self.calculate_momentum()
        crossovers = self.detect_crossovers()
        figures = self.get_prominent_figure_activity()

        # Get disinfo-flagged articles
        disinfo_articles = [
            {
                "title": e.title,
                "source": e.source,
                "flags": e.disinfo_flags,
                "topics": e.topics,
            }
            for e in self.events if e.disinfo_flags
        ]

        # Get surging topics
        surging = [
            {
                "topic": m.topic,
                "count": m.current_count,
                "delta": m.delta,
                "sources": list(m.sources),
            }
            for m in momentum.values() if m.momentum == "surging"
        ]

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_events": len(self.events),
            "momentum": {
                topic: {
                    "current": m.current_count,
                    "previous": m.previous_count,
                    "delta": m.delta,
                    "momentum": m.momentum,
                    "source_count": len(m.sources),
                }
                for topic, m in momentum.items()
            },
            "surging_topics": surging,
            "crossovers": [
                {
                    "topic": c.topic,
                    "from_tier": c.first_seen_tier.value,
                    "to_tier": c.current_tier.value,
                    "days_to_crossover": c.days_to_crossover,
                    "confidence": c.confidence,
                }
                for c in crossovers
            ],
            "prominent_figures": figures,
            "disinfo_signals": {
                "flagged_count": len(disinfo_articles),
                "articles": disinfo_articles[:10],  # Top 10
            },
            "summary": {
                "surging_count": len(surging),
                "crossover_count": len(crossovers),
                "active_figures": len(figures),
                "disinfo_flagged": len(disinfo_articles),
            }
        }


def create_tracker_from_news(articles: List[Dict[str, Any]]) -> NarrativeTracker:
    """
    Create a NarrativeTracker from news articles

    Convenience function to integrate with NewsScraperCollector output.
    """
    tracker = NarrativeTracker()

    for article in articles:
        tracker.add_article(
            title=article.get("title", ""),
            source=article.get("source", "Unknown"),
            timestamp=datetime.fromisoformat(article["published_at"]) if article.get("published_at") else None,
            url=article.get("url"),
            content=article.get("summary") or article.get("content"),
        )

    return tracker
