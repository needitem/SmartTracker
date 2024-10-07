# Modified gui/process_selector/main_frame.py

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
import psutil

from dump.database import Database
from dump.memory_dumper import WindowsMemoryDumper
from dump.dump_analyzer import DumpAnalyzer
from gui.analyze_process.analysis_tab import AnalysisTab
from gui.analyze_process.main_window import AnalyzeProcessWindow  # Corrected import

logger = logging.getLogger(__name__)

class ProcessSelector(ttk.Frame):
    def __init__(self, parent, db: Database):
        super().__init__(parent)
        self.parent = parent
        self.db = db  # Use shared Database instance
        self.dumper = WindowsMemoryDumper(db=self.db)
        self.dump_analyzer = DumpAnalyzer(database=self.db)
        self.create_widgets()
        self.populate_process_list()

    def create_widgets(self):
        # Create and configure Treeview for process list
        self.process_list = ttk.Treeview(self, columns=("PID", "Name", "Base Address"), show='headings')
        self.process_list.heading("PID", text="PID")
        self.process_list.heading("Name", text="Process Name")
        self.process_list.heading("Base Address", text="Base Address")
        self.process_list.pack(fill=tk.BOTH, expand=True)

        # Bind the heading click for sorting
        for col in ("PID", "Name", "Base Address"):
            self.process_list.heading(col, command=lambda _col=col: self.sort_column(_col, False))

        # Create a button to dump memory
        self.dump_button = ttk.Button(self, text="Dump Memory", command=self.dump_selected_process)
        self.dump_button.pack(pady=10)

    def populate_process_list(self):
        # Clear existing entries
        for item in self.process_list.get_children():
            self.process_list.delete(item)

        # Fetch processes (Using psutil)
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                # Assuming base_address is fetched or set to 'Unknown' for simplicity
                base_address = "Unknown"
                self.process_list.insert('', tk.END, values=(pid, name, base_address))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def sort_column(self, col, reverse):
        """Sort the Treeview columns when the header is clicked."""
        try:
            l = [(self.process_list.set(k, col), k) for k in self.process_list.get_children('')]
            if col == "PID":
                l.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=reverse)
            else:
                l.sort(reverse=reverse)
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")
            return

        # Rearrange items in sorted order
        for index, (val, k) in enumerate(l):
            self.process_list.move(k, '', index)

        # Reverse sort next time
        self.process_list.heading(col, command=lambda: self.sort_column(col, not reverse))

    def dump_selected_process(self):
        """Initiate memory dump for the selected process."""
        selected_item = self.process_list.selection()
        if not selected_item:
            logger.warning("No process selected for dumping.")
            messagebox.showwarning("No Selection", "Please select a process to dump memory.")
            return
        pid, name, base_address = self.process_list.item(selected_item, 'values')
        logger.info(f"Initiating dump for PID={pid}, Process={name}")
        threading.Thread(target=self.perform_dump, args=(int(pid),), daemon=True).start()

    def perform_dump(self, pid: int):
        """Perform the memory dump in a separate thread."""
        try:
            # Dump memory
            self.dumper.dump_memory(pid)
            logger.info(f"Memory dump completed for PID={pid}.")

            # Trigger analysis
            self.run_analysis()
        except Exception as e:
            logger.error(f"Error during memory dump for PID={pid}: {e}")
            messagebox.showerror("Dump Error", f"An error occurred during memory dump: {e}")

    def run_analysis(self):
        """Run the memory analysis and display results."""
        try:
            # Analyze the dumped memory
            self.dump_analyzer.analyze_and_export()

            # Open the analysis results window
            dump_path = self.dumper.db.db_path  # Ensure dump_path is correctly obtained
            AnalyzeProcessWindow(self.parent, dump_path)
            logger.info("Analysis results window opened successfully.")
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            messagebox.showerror("Analysis Error", f"An error occurred during analysis: {e}")