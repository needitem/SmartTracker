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

        # Add ReSearch button
        self.research_button = ttk.Button(
            self, text="ReSearch", command=self.perform_research, state=tk.DISABLED
        )
        self.research_button.pack(pady=5)

        # Add Data Type selection with 'All' option
        self.data_type_label = ttk.Label(self, text="Data Type:")
        self.data_type_label.pack(pady=5)

        self.data_type_var = tk.StringVar()
        self.data_type_combo = ttk.Combobox(
            self,
            textvariable=self.data_type_var,
            values=["All", "Integer", "Float", "String"],
            state="readonly",
            width=20
        )
        self.data_type_combo.pack(pady=5)
        self.data_type_combo.current(0)  # Set default to 'All'

        # Modify Treeview to include 'Value' column
        self.results_tree = ttk.Treeview(
            self,
            columns=("Address", "Value", "String", "Integer", "Float", "Module"),
            show="headings",
        )
        self.results_tree.heading("Address", text="Address")
        self.results_tree.heading("Value", text="Value")  # New column
        self.results_tree.heading("String", text="String")
        self.results_tree.heading("Integer", text="Integer")
        self.results_tree.heading("Float", text="Float")
        self.results_tree.heading("Module", text="Module")
        self.results_tree.pack(pady=10, fill=tk.BOTH, expand=True)

    def perform_search(self):
        """Perform search using SearchController."""
        query = self.search_entry.get()
        data_type = self.data_type_var.get()
        if not query:
            messagebox.showwarning("Input Needed", "Please enter a search query.")
            return

        results = self.memory_analyzer.search_memory_entries(query, data_type=data_type)
        self.populate_results(results)
        self.research_button.config(state=tk.NORMAL)  # Enable ReSearch

    def perform_research(self):
        """Re-perform the last search."""
        query = self.search_entry.get()
        data_type = self.data_type_var.get()
        if not query:
            messagebox.showwarning("Input Needed", "Please enter a search query.")
            return

        results = self.memory_analyzer.search_memory_entries(query, data_type=data_type)
        self.populate_results(results)
        logger.info("ReSearch completed.")

    def populate_results(self, results: List[MemoryEntryProcessed]):
        """Populate search results in the treeview."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        for entry in results:
            # Determine the value to display in the 'Value' column
            if entry.integer is not None:
                value = entry.integer
            elif entry.float_num is not None:
                value = entry.float_num
            else:
                value = entry.string if entry.string else ""

            self.results_tree.insert(
                "",
                tk.END,
                values=(
                    entry.address,
                    value,
                    entry.string if entry.string else "",
                    entry.integer if entry.integer is not None else "",
                    entry.float_num if entry.float_num is not None else "",
                    entry.module,
                ),
            )