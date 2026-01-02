"""
Base collector class for all data sources
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base class for all collectors"""

    @abstractmethod
    async def init_session(self):
        """Initialize HTTP session"""
        pass

    @abstractmethod
    async def close(self):
        """Close HTTP session and cleanup"""
        pass

    async def __aenter__(self):
        """Async context manager entry"""
        await self.init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
