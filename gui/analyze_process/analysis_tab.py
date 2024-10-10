import logging
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Any

from dump.memory.memory_entry import MemoryEntry

logger = logging.getLogger(__name__)


class AnalysisTab(ttk.Frame):
    def __init__(self, parent, dump_analyzer):
        super().__init__(parent)
        self.dump_analyzer = dump_analyzer
        self.create_widgets()

    def create_widgets(self):
        # Create Treeview for Analysis Results
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

    def load_data(self, entries: List[MemoryEntry], modules: List[Dict[str, Any]]):
        """Load analyzed memory entries into the table."""
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
                        entry.address,
                        entry.offset,
                        entry.raw,
                        entry.string,
                        entry.integer,
                        entry.float_num,
                        entry.module,
                    ),
                )
                logger.debug(f"Loaded entry: {entry}")

            logger.info("All entries loaded into the analysis table.")
        except Exception as e:
            logger.error(f"Error loading data into analysis table: {e}")
            messagebox.showerror(
                "Data Load Error", f"An error occurred while loading data: {e}"
            )

    def display_results(self, entries):
        """검색 결과를 테이블에 표시."""
        try:
            # 기존 데이터 삭제
            for item in self.table.get_children():
                self.table.delete(item)

            # 새 데이터 로드
            for entry in entries:
                self.table.insert(
                    "",
                    tk.END,
                    values=(
                        entry.address,
                        entry.offset,
                        entry.raw,
                        entry.string,
                        entry.integer,
                        entry.float_num,
                        entry.module,
                    ),
                )
                logger.debug(f"Displayed search entry: {entry}")

            if not entries:
                logger.info("No matching entries found.")
                messagebox.showinfo("Search Results", "No matching entries found.")
        except Exception as e:
            logger.error(f"Failed to display search results: {e}")
            messagebox.showerror(
                "Display Error", f"An error occurred while displaying results: {e}"
            )
