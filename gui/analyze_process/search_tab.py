# gui/analyze_process/search_tab.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging

logger = logging.getLogger(__name__)


class SearchTab(ttk.Frame):
    def __init__(self, parent, dump_analyzer):
        super().__init__(parent)
        self.parent = parent
        self.dump_analyzer = dump_analyzer
        self.create_widgets()

    def create_widgets(self):
        """Create widgets for the search tab."""
        # Create search frame
        search_frame = ttk.LabelFrame(self, text="Search Memory Entries")
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        # Field selection
        ttk.Label(search_frame, text="Field:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W
        )
        self.field_var = tk.StringVar()
        fields = [
            "address",
            "offset",
            "raw",
            "string",
            "integer",
            "float_num",
            "module",
        ]
        self.field_combo = ttk.Combobox(
            search_frame, textvariable=self.field_var, values=fields, state="readonly"
        )
        self.field_combo.grid(row=0, column=1, padx=5, pady=5)
        self.field_combo.current(0)

        # Query entry
        ttk.Label(search_frame, text="Query:").grid(
            row=0, column=2, padx=5, pady=5, sticky=tk.W
        )
        self.query_var = tk.StringVar()
        self.query_entry = ttk.Entry(search_frame, textvariable=self.query_var)
        self.query_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W + tk.E)

        # Search button
        self.search_button = ttk.Button(
            search_frame, text="Search", command=self.perform_search
        )
        self.search_button.grid(row=0, column=4, padx=5, pady=5)

        # Configure grid weights
        search_frame.columnconfigure(3, weight=1)

        # Create results table
        results_frame = ttk.Frame(self)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = (
            "address",
            "offset",
            "raw",
            "string",
            "integer",
            "float_num",
            "module",
        )
        self.search_table = ttk.Treeview(
            results_frame, columns=columns, show="headings"
        )
        for col in columns:
            self.search_table.heading(col, text=col.capitalize())
            self.search_table.column(col, minwidth=100, width=150, anchor=tk.CENTER)
        self.search_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Add scrollbars
        scrollbar_y = ttk.Scrollbar(
            results_frame, orient="vertical", command=self.search_table.yview
        )
        scrollbar_x = ttk.Scrollbar(
            self, orient="horizontal", command=self.search_table.xview
        )
        self.search_table.configure(
            yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set
        )
        scrollbar_y.pack(side=tk.LEFT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

    def perform_search(self):
        """Perform a search based on the selected field and query."""
        field = self.field_var.get()
        query = self.query_var.get().strip()

        if not query:
            messagebox.showwarning("Input Error", "Please enter a query string.")
            return

        logger.info(f"Performing search on field '{field}' with query '{query}'.")
        filtered_entries = self.dump_analyzer.extract_filtered_entries(field, query)

        # Clear existing entries in the search table
        for item in self.search_table.get_children():
            self.search_table.delete(item)

        # Insert new entries
        for entry in filtered_entries:
            self.search_table.insert(
                "",
                tk.END,
                values=(
                    entry.get("address", "N/A"),
                    entry.get("offset", "N/A"),
                    entry.get("raw", "N/A"),
                    entry.get("string", "N/A"),
                    entry.get("integer", "N/A"),
                    entry.get("float_num", "N/A"),
                    entry.get("module", "N/A"),
                ),
            )

        logger.info(f"Search completed. {len(filtered_entries)} entries found.")
