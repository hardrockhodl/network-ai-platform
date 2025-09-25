#!/usr/bin/env python3
"""
AI Query Processor
Delegates natural language queries to local processing engines (rule-based and optional local LLM).
"""

import logging
from typing import Dict, Any, List

from ai_engine.local_ai_processor import HybridNetworkQueryProcessor, LocalNetworkQueryProcessor
from database.models import Device

logger = logging.getLogger(__name__)

class NetworkQueryProcessor:
    """Process natural language queries using local AI components only."""

    def __init__(self) -> None:
        try:
            self.processor = HybridNetworkQueryProcessor()
        except Exception as exc:
            logger.warning(
                "Unable to initialise hybrid processor (%s); falling back to rule-based engine only",
                exc,
            )
            self.processor = LocalNetworkQueryProcessor()

    async def process_query(
        self,
        query: str,
        devices: List[Device],
        context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Delegates the query to the configured local processor."""
        return await self.processor.process_query(query, devices, context or {})
