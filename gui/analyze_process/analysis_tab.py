# gui/analyze_process/analysis_tab.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
import threading

logger = logging.getLogger(__name__)


class AnalysisTab(ttk.Frame):
    def __init__(self, parent, database):
        super().__init__(parent)
        self.parent = parent
        self.database = database
        self.create_widgets()

    def create_widgets(self):
        """Create widgets for the analysis tab."""
        # Frame for Module Base Addresses
        base_address_frame = ttk.LabelFrame(self, text="모듈 Base Address")
        base_address_frame.pack(fill=tk.X, padx=10, pady=5)

        self.base_addresses_text = tk.Text(
            base_address_frame, height=5, wrap="word", state=tk.DISABLED
        )
        self.base_addresses_text.pack(fill=tk.X, padx=5, pady=5)

        # Frame for Byte Unit and Endianness Selection
        options_frame = ttk.Frame(self)
        options_frame.pack(fill=tk.X, padx=10, pady=10)

        # Byte Unit Selection
        byte_unit_label = ttk.Label(options_frame, text="바이트 단위 선택:")
        byte_unit_label.pack(side=tk.LEFT)

        self.byte_unit_var = tk.IntVar(value=4)
        self.byte_unit_dropdown = ttk.Combobox(
            options_frame,
            textvariable=self.byte_unit_var,
            values=[1, 2, 4, 8, 16, 32],
            state="readonly",
            width=10,
        )
        self.byte_unit_dropdown.pack(side=tk.LEFT, padx=(5, 20))
        self.byte_unit_dropdown.bind("<<ComboboxSelected>>", self.update_byte_unit)

        # Endianness Selection
        endianness_label = ttk.Label(options_frame, text="엔디안 선택:")
        endianness_label.pack(side=tk.LEFT)

        self.endianness_var = tk.StringVar(value="little")
        self.endianness_dropdown = ttk.Combobox(
            options_frame,
            textvariable=self.endianness_var,
            values=["little", "big"],
            state="readonly",
            width=10,
        )
        self.endianness_dropdown.pack(side=tk.LEFT, padx=(5, 20))
        self.endianness_dropdown.bind("<<ComboboxSelected>>", self.update_endianness)

        # Start Analysis Button
        self.start_analysis_button = ttk.Button(
            options_frame, text="분석 시작", command=self.start_analysis
        )
        self.start_analysis_button.pack(side=tk.LEFT, padx=(20, 0))

        # Create Treeview with "Module" column added
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

        # Trigger the analysis process via the DumpAnalyzer instance
        # This should be connected to the DumpAnalyzer logic in your application
        if hasattr(self.parent, "dump_analyzer"):
            threading.Thread(
                target=self.parent.dump_analyzer.analyze_and_export, daemon=True
            ).start()
        else:
            logger.error("DumpAnalyzer instance not found in parent.")
            messagebox.showerror(
                "분석 오류", "DumpAnalyzer 인스턴스를 찾을 수 없습니다."
            )

    def load_data(self, entries, modules):
        """Load data into the Treeview and display module base addresses."""
        try:
            # Display Module Base Addresses
            self.base_addresses_text.config(state=tk.NORMAL)
            self.base_addresses_text.delete("1.0", tk.END)
            for module in modules:
                name = module.get("name", "Unknown")
                base_address = module.get("base_address", "Unknown")
                self.base_addresses_text.insert(
                    tk.END, f"모듈: {name}, Base Address: {base_address}\n"
                )
            self.base_addresses_text.config(state=tk.DISABLED)

            # Load Memory Entries into Treeview
            for entry in entries:
                display_raw = (
                    entry.raw[:50] + "..." if len(entry.raw) > 50 else entry.raw
                )
                self.table.insert(
                    "",
                    tk.END,
                    values=(
                        entry.address,
                        entry.offset,
                        display_raw,
                        entry.string,
                        entry.integer,
                        entry.float_num,
                        entry.module,
                    ),
                )
            logger.info("All entries loaded into the analysis table.")
        except Exception as e:
            logger.error(f"Error loading data into analysis table: {e}")
            messagebox.showerror(
                "데이터 로드 오류", f"데이터를 로드하는 중 오류가 발생했습니다: {e}"
            )

    def refresh_analysis_table(self):
        """Refresh the analysis table with updated data."""
        try:
            # Clear existing data
            for item in self.table.get_children():
                self.table.delete(item)

            # Fetch latest entries and modules from the database
            entries = self.database.fetch_all_entries()
            modules = self.database.fetch_all_modules()

            # Load data into the table and display base addresses
            self.load_data(entries, modules)

            logger.info("Analysis table refreshed with new data.")
        except Exception as e:
            logger.error(f"Error refreshing analysis table: {e}")
            messagebox.showerror(
                "새로 고침 오류", f"테이블을 새로 고치는 중 오류가 발생했습니다: {e}"
            )
