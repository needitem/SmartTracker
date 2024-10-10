import logging
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Any

from dump.analyzer.memory_analyzer import MemoryAnalyzer
from dump.memory.memory_entry import MemoryEntryProcessed
from gui.analyze_process.analysis_tab import AnalysisTab

logger = logging.getLogger(__name__)


class SearchTab(ttk.Frame):
    def __init__(
        self, parent, memory_analyzer: MemoryAnalyzer, analysis_tab: AnalysisTab
    ):
        super().__init__(parent)
        self.memory_analyzer = memory_analyzer
        self.analysis_tab = analysis_tab
        self.create_widgets()

    def create_widgets(self):
        """Create search widgets."""
        self.search_label = ttk.Label(self, text="Search:")
        self.search_label.pack(pady=5)

        self.search_entry = ttk.Entry(self, width=50)
        self.search_entry.pack(pady=5)

        self.search_button = ttk.Button(
            self, text="Search", command=self.perform_search
        )
        self.search_button.pack(pady=5)

        self.results_tree = ttk.Treeview(
            self,
            columns=("Address", "String", "Integer", "Float", "Module"),
            show="headings",
        )
        self.results_tree.heading("Address", text="Address")
        self.results_tree.heading("String", text="String")
        self.results_tree.heading("Integer", text="Integer")
        self.results_tree.heading("Float", text="Float")
        self.results_tree.heading("Module", text="Module")
        self.results_tree.pack(pady=10, fill=tk.BOTH, expand=True)

    def perform_search(self):
        """Perform search using SearchController."""
        query = self.search_entry.get()
        if not query:
            messagebox.showwarning("Input Needed", "Please enter a search query.")
            return

        results = self.memory_analyzer.search_memory_entries(query)
        self.populate_results(results)

    def populate_results(self, results: List[MemoryEntryProcessed]):
        """Populate search results in the treeview."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        for entry in results:
            self.results_tree.insert(
                "",
                tk.END,
                values=(
                    entry.address,
                    entry.string,
                    entry.integer,
                    entry.float_num,
                    entry.module,
                ),
            )
