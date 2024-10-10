import logging
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Any

from dump.analyzer.memory_analyzer import MemoryAnalyzer
from dump.memory.memory_entry import MemoryEntryProcessed
from gui.analyze_process.analysis_tab import AnalysisTab

logger = logging.getLogger(__name__)


class SearchController:
    def __init__(self, memory_analyzer: MemoryAnalyzer, analysis_tab: AnalysisTab):
        self.memory_analyzer = memory_analyzer
        self.analysis_tab = analysis_tab

    def perform_search(self, query: str) -> List[MemoryEntryProcessed]:
        """Perform a memory search based on the query."""
        try:
            results = self.memory_analyzer.search_memory_entries(query)
            logger.info(f"Search completed for query: {query}")
            return results
        except Exception as e:
            logger.error(f"Error performing search: {e}")
            return []
