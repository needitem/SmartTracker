import tkinter as tk
from tkinter import ttk, messagebox
import logging
import os

from dump.database import Database
from dump.dump_analyzer import DumpAnalyzer

logger = logging.getLogger(__name__)


class AnalyzeProcessWindow(tk.Toplevel):
    def __init__(self, parent: tk.Tk, dump_path: str):
        super().__init__(parent)
        self.title(f"Memory Analysis - {os.path.basename(dump_path)}")
        self.geometry("1200x800")
        self.dump_path = dump_path

        # Initialize Database with the correct path
        self.db = Database(db_path=self.dump_path)

        # Create Notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Analysis Results Tab
        self.create_analysis_tab()

        # Create Search Tab
        self.create_search_tab()

    def create_analysis_tab(self):
        """Create the analysis results tab with scrollbars and selection options."""
        self.analysis_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_tab, text="분석 결과")

        # Frame for Byte Unit and Endianness Selection
        options_frame = ttk.Frame(self.analysis_tab)
        options_frame.pack(fill=tk.X, padx=10, pady=10)

        # Byte Unit Selection
        byte_unit_label = ttk.Label(options_frame, text="바이트 단위 선택:")
        byte_unit_label.pack(side=tk.LEFT)

        self.byte_unit_var = tk.IntVar(value=4)
        byte_unit_dropdown = ttk.Combobox(
            options_frame,
            textvariable=self.byte_unit_var,
            values=[4, 8, 16, 32],
            state="readonly",
            width=10,
        )
        byte_unit_dropdown.pack(side=tk.LEFT, padx=(5, 20))
        byte_unit_dropdown.bind("<<ComboboxSelected>>", self.update_byte_unit)

        # Endianness Selection
        endianness_label = ttk.Label(options_frame, text="엔디안 선택:")
        endianness_label.pack(side=tk.LEFT)

        self.endianness_var = tk.StringVar(value="little")
        endianness_dropdown = ttk.Combobox(
            options_frame,
            textvariable=self.endianness_var,
            values=["little", "big"],
            state="readonly",
            width=10,
        )
        endianness_dropdown.pack(side=tk.LEFT, padx=(5, 20))
        endianness_dropdown.bind("<<ComboboxSelected>>", self.update_endianness)

        # Start Analysis Button
        start_analysis_button = ttk.Button(
            options_frame, text="분석 시작", command=self.start_analysis
        )
        start_analysis_button.pack(side=tk.LEFT, padx=(20, 0))

        # Create Treeview
        self.table = ttk.Treeview(
            self.analysis_tab,
            columns=("Address", "Offset", "Raw", "String", "Int", "Float"),
            show="headings",
        )
        for col in ("Address", "Offset", "Raw", "String", "Int", "Float"):
            self.table.heading(col, text=col)
            self.table.column(col, width=150, anchor="center")
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)

        # Add Scrollbars
        scrollbar_y = ttk.Scrollbar(
            self.analysis_tab, orient="vertical", command=self.table.yview
        )
        scrollbar_x = ttk.Scrollbar(
            self.analysis_tab, orient="horizontal", command=self.table.xview
        )
        self.table.configure(
            yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set
        )
        scrollbar_y.pack(side=tk.LEFT, fill=tk.Y, pady=10)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X, padx=10)

    def update_byte_unit(self, event=None):
        """Handle byte unit selection changes."""
        selected_unit = self.byte_unit_var.get()
        logger.info(f"Byte unit changed to: {selected_unit} bytes")
        # Additional logic can be added here if needed

    def update_endianness(self, event=None):
        """Handle endianness selection changes."""
        selected_endianness = self.endianness_var.get()
        logger.info(f"Endianness changed to: {selected_endianness}")
        # Additional logic can be added here if needed

    def start_analysis(self):
        """Start the memory dump analysis with the selected byte unit and endianness."""
        byte_unit = self.byte_unit_var.get()
        endianness = self.endianness_var.get().lower()

        logger.info(
            f"Starting analysis with byte unit: {byte_unit} bytes and endianness: {endianness} endian"
        )

        try:
            analyzer = DumpAnalyzer(
                db_path=self.dump_path, byte_unit=byte_unit, endianness=endianness
            )
            analyzer.analyze_dump()
            # Refresh the analysis table after analysis
            self.refresh_analysis_table()
        except Exception as e:
            logger.error(f"Error during analysis: {e}", exc_info=True)
            messagebox.showerror(
                "Analysis Error", f"An error occurred during analysis: {e}"
            )

    def load_data(self):
        """Load all data into the analysis table."""
        try:
            entries = self.db.fetch_all_entries()
            for row in entries:
                try:
                    float_num = float(row["float_num"])
                    float_str = f"{float_num:.6f}"
                except (TypeError, ValueError):
                    float_str = "N/A"

                raw_data = row["raw"] or ""
                if isinstance(raw_data, str):
                    display_raw = (
                        raw_data[:100] + "..." if len(raw_data) > 100 else raw_data
                    )
                else:
                    display_raw = "N/A"

                self.table.insert(
                    "",
                    tk.END,
                    values=(
                        row["address"] or "N/A",
                        row["offset"] or "N/A",
                        display_raw,
                        row["string"] or "N/A",
                        row["integer"] if row["integer"] is not None else "N/A",
                        float_str,
                    ),
                )
            logger.info("Loaded all entries into the analysis table.")
        except Exception as e:
            logger.error(f"Error loading data into analysis table: {e}")

    def refresh_analysis_table(self):
        """Refresh the analysis table with updated data."""
        # Clear existing data
        for item in self.table.get_children():
            self.table.delete(item)
        # Reload data
        self.load_data()
        logger.info("Analysis table refreshed after new analysis.")

    def create_search_tab(self):
        """Create the search tab. Implementation depends on your requirements."""
        self.search_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.search_tab, text="검색")
        # Implement search functionality as needed
