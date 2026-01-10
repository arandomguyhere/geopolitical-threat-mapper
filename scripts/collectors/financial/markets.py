"""
Financial Markets Collector

Integrated from situation-monitor for economic signal layer:
- Commodities (oil, gold, natural gas)
- Crypto markets (Bitcoin, Ethereum, stablecoins)
- Sector ETFs (defense, energy, shipping)
- VIX volatility index
- Fed balance sheet data

Data Sources:
- CoinGecko API (crypto - free, no API key)
- Yahoo Finance (stocks/ETFs - scraped)
- FRED (Federal Reserve data - free)
- Alpha Vantage (optional, with API key)
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from enum import Enum

import aiohttp

from ..base import BaseCollector

logger = logging.getLogger(__name__)


class MarketSector(Enum):
    """Market sectors relevant to geopolitical analysis"""
    DEFENSE = "defense"
    ENERGY = "energy"
    SHIPPING = "shipping"
    TECHNOLOGY = "technology"
    FINANCIALS = "financials"


# Sector ETF symbols (from situation-monitor constants.js)
SECTOR_ETFS = {
    "XLE": {"name": "Energy Select", "sector": MarketSector.ENERGY},
    "XLF": {"name": "Financial Select", "sector": MarketSector.FINANCIALS},
    "XLK": {"name": "Technology Select", "sector": MarketSector.TECHNOLOGY},
    "ITA": {"name": "iShares Aerospace & Defense", "sector": MarketSector.DEFENSE},
    "PPA": {"name": "PowerShares Aerospace & Defense", "sector": MarketSector.DEFENSE},
    "BDRY": {"name": "Breakwave Dry Bulk Shipping", "sector": MarketSector.SHIPPING},
    "SEA": {"name": "US Global Sea to Sky Cargo", "sector": MarketSector.SHIPPING},
}

# Commodity symbols
COMMODITIES = {
    "CL=F": {"name": "Crude Oil (WTI)", "unit": "USD/barrel"},
    "BZ=F": {"name": "Brent Crude", "unit": "USD/barrel"},
    "NG=F": {"name": "Natural Gas", "unit": "USD/MMBtu"},
    "GC=F": {"name": "Gold", "unit": "USD/oz"},
    "SI=F": {"name": "Silver", "unit": "USD/oz"},
    "HG=F": {"name": "Copper", "unit": "USD/lb"},
}

# Crypto assets to track (relevant for sanctions evasion signals)
CRYPTO_IDS = {
    "bitcoin": {"symbol": "BTC", "name": "Bitcoin"},
    "ethereum": {"symbol": "ETH", "name": "Ethereum"},
    "tether": {"symbol": "USDT", "name": "Tether"},
    "usd-coin": {"symbol": "USDC", "name": "USD Coin"},
}

# Geopolitical prediction market questions (categories to track)
PREDICTION_CATEGORIES = [
    "conflict",
    "sanctions",
    "elections",
    "china",
    "russia",
    "iran",
    "north-korea",
    "taiwan",
    "ukraine",
]


@dataclass
class MarketData:
    """Market data point"""
    symbol: str
    name: str
    price: float
    change_pct: float
    change_24h: Optional[float] = None
    volume: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    sector: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PredictionMarket:
    """Prediction market data"""
    id: str
    question: str
    probability: float
    probability_change: float
    category: str
    volume: Optional[float] = None
    end_date: Optional[datetime] = None


class FinancialCollector(BaseCollector):
    """
    Collector for financial market data

    Provides economic signal layer for correlation engine:
    - Commodity price spikes during chokepoint incidents
    - Defense sector movements during conflict escalation
    - Crypto volatility during sanctions events
    - VIX spikes during geopolitical crises
    """

    def __init__(
        self,
        alpha_vantage_key: Optional[str] = None,
        cache_ttl_seconds: int = 300,  # 5 minute cache
    ):
        self.alpha_vantage_key = alpha_vantage_key
        self.cache_ttl = cache_ttl_seconds
        self.session: Optional[aiohttp.ClientSession] = None

        # Cache for rate limiting
        self._cache: Dict[str, Dict[str, Any]] = {}

    async def init_session(self):
        """Initialize HTTP session"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "GeopoliticalThreatMapper/1.0"},
        )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if key not in self._cache:
            return False
        cached = self._cache[key]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        return age < self.cache_ttl

    async def fetch_crypto_prices(self) -> List[MarketData]:
        """
        Fetch cryptocurrency prices from CoinGecko

        CoinGecko API is free and doesn't require an API key.
        Rate limit: 10-50 calls/minute depending on endpoint.
        """
        if self._is_cache_valid("crypto"):
            return self._cache["crypto"]["data"]

        if not self.session:
            await self.init_session()

        try:
            ids = ",".join(CRYPTO_IDS.keys())
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd&include_24hr_change=true"

            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = []

                    for coin_id, info in CRYPTO_IDS.items():
                        if coin_id in data:
                            coin_data = data[coin_id]
                            results.append(MarketData(
                                symbol=info["symbol"],
                                name=info["name"],
                                price=coin_data.get("usd", 0),
                                change_pct=coin_data.get("usd_24h_change", 0),
                                change_24h=coin_data.get("usd_24h_change", 0),
                                timestamp=datetime.utcnow(),
                                metadata={"source": "coingecko"},
                            ))

                    self._cache["crypto"] = {
                        "data": results,
                        "timestamp": datetime.utcnow(),
                    }
                    return results
                else:
                    logger.warning(f"CoinGecko API returned {resp.status}")
                    return []

        except Exception as e:
            logger.error(f"Error fetching crypto prices: {e}")
            return []

    async def fetch_commodities(self) -> List[MarketData]:
        """
        Fetch commodity prices

        Uses Yahoo Finance data (no API key required).
        Falls back to baseline values with simulated movement if unavailable.
        """
        if self._is_cache_valid("commodities"):
            return self._cache["commodities"]["data"]

        if not self.session:
            await self.init_session()

        results = []

        # Baseline prices (fallback - from situation-monitor data.js)
        baselines = {
            "CL=F": 75.0,   # WTI Crude
            "BZ=F": 80.0,   # Brent
            "NG=F": 3.0,    # Natural Gas
            "GC=F": 2000.0, # Gold
            "SI=F": 25.0,   # Silver
            "HG=F": 4.0,    # Copper
        }

        for symbol, info in COMMODITIES.items():
            try:
                # Try Yahoo Finance API
                url = f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?interval=1d&range=2d"
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        chart = data.get("chart", {}).get("result", [{}])[0]
                        meta = chart.get("meta", {})
                        price = meta.get("regularMarketPrice", baselines.get(symbol, 0))
                        prev_close = meta.get("previousClose", price)

                        if prev_close and prev_close > 0:
                            change_pct = ((price - prev_close) / prev_close) * 100
                        else:
                            change_pct = 0

                        results.append(MarketData(
                            symbol=symbol,
                            name=info["name"],
                            price=price,
                            change_pct=change_pct,
                            timestamp=datetime.utcnow(),
                            metadata={"unit": info["unit"], "source": "yahoo"},
                        ))
                    else:
                        # Use baseline with simulated movement
                        import random
                        baseline = baselines.get(symbol, 100)
                        change_pct = random.uniform(-2, 2)
                        results.append(MarketData(
                            symbol=symbol,
                            name=info["name"],
                            price=baseline * (1 + change_pct / 100),
                            change_pct=change_pct,
                            timestamp=datetime.utcnow(),
                            metadata={"unit": info["unit"], "source": "simulated"},
                        ))

            except Exception as e:
                logger.debug(f"Error fetching {symbol}: {e}")
                # Use baseline
                import random
                baseline = baselines.get(symbol, 100)
                change_pct = random.uniform(-2, 2)
                results.append(MarketData(
                    symbol=symbol,
                    name=info["name"],
                    price=baseline * (1 + change_pct / 100),
                    change_pct=change_pct,
                    timestamp=datetime.utcnow(),
                    metadata={"unit": info["unit"], "source": "simulated"},
                ))

        self._cache["commodities"] = {
            "data": results,
            "timestamp": datetime.utcnow(),
        }
        return results

    async def fetch_sectors(self) -> List[MarketData]:
        """
        Fetch sector ETF data

        Focus on defense, energy, and shipping sectors
        that correlate with geopolitical events.
        """
        if self._is_cache_valid("sectors"):
            return self._cache["sectors"]["data"]

        if not self.session:
            await self.init_session()

        results = []

        for symbol, info in SECTOR_ETFS.items():
            try:
                url = f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?interval=1d&range=2d"
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        chart = data.get("chart", {}).get("result", [{}])[0]
                        meta = chart.get("meta", {})
                        price = meta.get("regularMarketPrice", 0)
                        prev_close = meta.get("previousClose", price)

                        if prev_close and prev_close > 0:
                            change_pct = ((price - prev_close) / prev_close) * 100
                        else:
                            change_pct = 0

                        results.append(MarketData(
                            symbol=symbol,
                            name=info["name"],
                            price=price,
                            change_pct=change_pct,
                            sector=info["sector"].value,
                            timestamp=datetime.utcnow(),
                            metadata={"sector_type": info["sector"].value, "source": "yahoo"},
                        ))

            except Exception as e:
                logger.debug(f"Error fetching sector {symbol}: {e}")

        self._cache["sectors"] = {
            "data": results,
            "timestamp": datetime.utcnow(),
        }
        return results

    async def fetch_vix(self) -> Dict[str, Any]:
        """
        Fetch VIX (Volatility Index)

        VIX > 20: Elevated fear
        VIX > 30: High volatility / crisis mode
        VIX > 40: Extreme fear
        """
        if self._is_cache_valid("vix"):
            return self._cache["vix"]["data"]

        if not self.session:
            await self.init_session()

        try:
            url = "https://query1.finance.yahoo.com/v8/finance/chart/%5EVIX?interval=1d&range=2d"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    chart = data.get("chart", {}).get("result", [{}])[0]
                    meta = chart.get("meta", {})
                    value = meta.get("regularMarketPrice", 0)
                    prev_close = meta.get("previousClose", value)

                    if prev_close and prev_close > 0:
                        change_pct = ((value - prev_close) / prev_close) * 100
                    else:
                        change_pct = 0

                    result = {
                        "value": value,
                        "change_pct": change_pct,
                        "level": "extreme" if value >= 40 else "high" if value >= 30 else "elevated" if value >= 20 else "normal",
                        "timestamp": datetime.utcnow().isoformat(),
                    }

                    self._cache["vix"] = {
                        "data": result,
                        "timestamp": datetime.utcnow(),
                    }
                    return result

        except Exception as e:
            logger.error(f"Error fetching VIX: {e}")

        return {"value": 0, "change_pct": 0, "level": "unknown"}

    async def fetch_fed_balance(self) -> Dict[str, Any]:
        """
        Fetch Federal Reserve balance sheet data from FRED

        Tracks:
        - Total assets (money supply indicator)
        - Treasury holdings
        - MBS holdings

        Source: FRED (Federal Reserve Economic Data) - free, no API key
        """
        if self._is_cache_valid("fed"):
            return self._cache["fed"]["data"]

        if not self.session:
            await self.init_session()

        try:
            # FRED series for Fed balance sheet
            series_id = "WALCL"  # Total assets
            url = f"https://fred.stlouisfed.org/graph/fredgraph.csv?id={series_id}"

            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    lines = text.strip().split("\n")

                    if len(lines) >= 2:
                        # Get latest value (last line)
                        latest = lines[-1].split(",")
                        prev = lines[-2].split(",") if len(lines) >= 3 else latest

                        try:
                            value = float(latest[1])
                            prev_value = float(prev[1])
                            change_pct = ((value - prev_value) / prev_value) * 100 if prev_value else 0

                            result = {
                                "total_assets_millions": value,
                                "total_assets_billions": value / 1000,
                                "total_assets_trillions": value / 1000000,
                                "change_pct": change_pct,
                                "date": latest[0],
                                "trend": "expanding" if change_pct > 0.5 else "contracting" if change_pct < -0.5 else "stable",
                            }

                            self._cache["fed"] = {
                                "data": result,
                                "timestamp": datetime.utcnow(),
                            }
                            return result
                        except (ValueError, IndexError):
                            pass

        except Exception as e:
            logger.error(f"Error fetching Fed data: {e}")

        return {}

    async def collect_all(self) -> Dict[str, Any]:
        """Collect all financial market data"""
        # Fetch all data concurrently
        crypto_task = self.fetch_crypto_prices()
        commodities_task = self.fetch_commodities()
        sectors_task = self.fetch_sectors()
        vix_task = self.fetch_vix()
        fed_task = self.fetch_fed_balance()

        crypto, commodities, sectors, vix, fed = await asyncio.gather(
            crypto_task, commodities_task, sectors_task, vix_task, fed_task,
            return_exceptions=True
        )

        # Handle any exceptions
        if isinstance(crypto, Exception):
            logger.error(f"Crypto fetch failed: {crypto}")
            crypto = []
        if isinstance(commodities, Exception):
            logger.error(f"Commodities fetch failed: {commodities}")
            commodities = []
        if isinstance(sectors, Exception):
            logger.error(f"Sectors fetch failed: {sectors}")
            sectors = []
        if isinstance(vix, Exception):
            logger.error(f"VIX fetch failed: {vix}")
            vix = {}
        if isinstance(fed, Exception):
            logger.error(f"Fed data fetch failed: {fed}")
            fed = {}

        # Convert to correlation engine format
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "financial",
            "crypto": [self._market_data_to_dict(m) for m in crypto],
            "commodities": [self._market_data_to_dict(m) for m in commodities],
            "sectors": [self._market_data_to_dict(m) for m in sectors],
            "vix": vix,
            "fed_balance": fed,
            "predictions": [],  # Placeholder for Polymarket integration
            "statistics": {
                "crypto_count": len(crypto),
                "commodities_count": len(commodities),
                "sectors_count": len(sectors),
                "vix_level": vix.get("level", "unknown"),
                "significant_moves": sum(
                    1 for m in (crypto + commodities + sectors)
                    if abs(m.change_pct) >= 2
                ),
            }
        }

    def _market_data_to_dict(self, data: MarketData) -> Dict[str, Any]:
        """Convert MarketData to dictionary"""
        return {
            "symbol": data.symbol,
            "name": data.name,
            "price": data.price,
            "change_pct": data.change_pct,
            "change_24h": data.change_24h,
            "sector_type": data.sector,
            "timestamp": data.timestamp.isoformat(),
            **data.metadata,
        }

    async def get_market_signals(self) -> Dict[str, Any]:
        """
        Get high-level market signals for correlation

        Returns signals that indicate potential geopolitical activity:
        - Oil spike > 3% (chokepoint disruption)
        - Defense sector surge (conflict escalation)
        - VIX spike (crisis mode)
        - Crypto volatility (sanctions activity)
        """
        data = await self.collect_all()

        signals = []

        # Check oil
        for commodity in data["commodities"]:
            if "Crude" in commodity.get("name", "") and abs(commodity.get("change_pct", 0)) >= 3:
                signals.append({
                    "type": "oil_spike",
                    "severity": "high" if abs(commodity["change_pct"]) >= 5 else "medium",
                    "description": f"Oil price move: {commodity['change_pct']:+.1f}%",
                    "data": commodity,
                })

        # Check defense sector
        for sector in data["sectors"]:
            if sector.get("sector_type") == "defense" and sector.get("change_pct", 0) >= 2:
                signals.append({
                    "type": "defense_surge",
                    "severity": "medium",
                    "description": f"Defense sector up {sector['change_pct']:+.1f}%",
                    "data": sector,
                })

        # Check VIX
        vix = data["vix"]
        if vix.get("value", 0) >= 25:
            signals.append({
                "type": "vix_elevated",
                "severity": "high" if vix["value"] >= 35 else "medium",
                "description": f"VIX at {vix['value']:.1f} ({vix.get('level', 'elevated')})",
                "data": vix,
            })

        # Check crypto volatility
        for crypto in data["crypto"]:
            if abs(crypto.get("change_24h", 0)) >= 10:
                signals.append({
                    "type": "crypto_volatility",
                    "severity": "medium",
                    "description": f"{crypto['symbol']} 24h change: {crypto['change_24h']:+.1f}%",
                    "data": crypto,
                })

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "signal_count": len(signals),
            "signals": signals,
            "market_summary": {
                "vix_level": data["vix"].get("level", "unknown"),
                "oil_change": next(
                    (c["change_pct"] for c in data["commodities"] if "WTI" in c.get("name", "")),
                    0
                ),
                "defense_change": next(
                    (s["change_pct"] for s in data["sectors"] if s.get("sector_type") == "defense"),
                    0
                ),
                "btc_change": next(
                    (c["change_24h"] for c in data["crypto"] if c.get("symbol") == "BTC"),
                    0
                ),
            }
        }
