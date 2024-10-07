# Modified gui/analyze_process/search_tab.py

import tkinter as tk
from tkinter import ttk, messagebox
import logging

from dump.dump_analyzer import DumpAnalyzer

logger = logging.getLogger(__name__)

class SearchTab(ttk.Frame):
    def __init__(self, parent, dump_analyzer: DumpAnalyzer, analysis_tab):
        super().__init__(parent)
        self.dump_analyzer = dump_analyzer
        self.analysis_tab = analysis_tab
        self.create_widgets()

    def create_widgets(self):
        # Create search options
        search_frame = ttk.Frame(self)
        search_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(search_frame, text="Search Term:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        ttk.Button(search_frame, text="Search", command=self.perform_search).pack(side=tk.LEFT)

        # Create Treeview to display search results
        self.table = ttk.Treeview(
            self,
            columns=("Address", "Offset", "Raw", "String", "Int", "Float", "Module"),
            show="headings",
        )
        for col in ("Address", "Offset", "Raw", "String", "Int", "Float", "Module"):
            self.table.heading(col, text=col)
            self.table.column(col, width=150, anchor="center")
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)

        # Add Scrollbars
        scrollbar_y = ttk.Scrollbar(self, orient="vertical", command=self.table.yview)
        scrollbar_x = ttk.Scrollbar(self, orient="horizontal", command=self.table.xview)
        self.table.configure(
            yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set
        )
        scrollbar_y.pack(side=tk.LEFT, fill=tk.Y, pady=10)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X, padx=10)

    def perform_search(self):
        """Perform search based on the input term."""
        query = self.search_entry.get().strip()
        if not query:
            logger.warning("Search query is empty.")
            messagebox.showwarning("Search Warning", "Please enter a search term.")
            return

        logger.info(f"Performing search for term: {query}")
        try:
            results = self.dump_analyzer.analyze_dump()
            filtered = [
                entry for entry in results
                if query.lower() in (entry.get("raw", "").lower()) or
                   query.lower() in (entry.get("string", "").lower())
            ]
            self.display_results(filtered)
            logger.info(f"Search completed. Found {len(filtered)} matching entries.")
        except Exception as e:
            logger.error(f"Error during search: {e}")
            messagebox.showerror("Search Error", f"An error occurred during search: {e}")

    def display_results(self, entries):
        """Display search results in the table."""
        try:
            # Clear existing data
            for item in self.table.get_children():
                self.table.delete(item)

            # Load new data
            for entry in entries:
                self.table.insert(
                    "",
                    tk.END,
                    values=(
                        entry.get("address", ""),
                        entry.get("offset", ""),
                        entry.get("raw", ""),
                        entry.get("string", ""),
                        entry.get("integer", ""),
                        entry.get("float_num", ""),
                        entry.get("module", ""),
                    ),
                )
                logger.debug(f"Displayed search entry: {entry}")

            if not entries:
                logger.info("No matching entries found.")
                messagebox.showinfo("Search Results", "No matching entries found.")
        except Exception as e:
            logger.error(f"Failed to display search results: {e}")
            messagebox.showerror("Display Error", f"An error occurred while displaying results: {e}")