# gui/process_selector/main_frame.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
import threading
import psutil

from dump.memory_dumper import MemoryDumper
from dump.database import Database
from dump.utils import is_process_64bit
from gui.analyze_process.main_window import (
    AnalyzeProcessWindow,
)

logger = logging.getLogger(__name__)


class ProcessSelector(ttk.Frame):
    def __init__(self, parent, output_dir="memory_dumps"):
        super().__init__(parent)
        self.parent = parent  # Keep a reference to the parent
        self.output_dir = output_dir
        self.db = Database(db_path=f"{self.output_dir}/memory_analysis.db")
        self.memory_dumper = None
        self.create_widgets()

    def create_widgets(self):
        """Create widgets for the process selector."""
        # Create process list
        self.process_list = ttk.Treeview(
            self, columns=("PID", "Name"), show="headings", selectmode="browse"
        )
        self.process_list.heading("PID", text="PID")
        self.process_list.heading("Name", text="Process Name")
        self.process_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add scrollbars
        scrollbar_y = ttk.Scrollbar(
            self, orient="vertical", command=self.process_list.yview
        )
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_list.configure(yscrollcommand=scrollbar_y.set)

        # Refresh button
        self.refresh_button = ttk.Button(
            self, text="Refresh", command=self.refresh_process_list
        )
        self.refresh_button.pack(pady=5)

        # Dump button
        self.dump_button = ttk.Button(
            self, text="Dump Selected Process", command=self.dump_selected_process
        )
        self.dump_button.pack(pady=5)

        # Initially populate the process list
        self.refresh_process_list()

    def refresh_process_list(self):
        """Refresh the list of running processes."""
        logger.info("Refreshing process list.")
        try:
            for item in self.process_list.get_children():
                self.process_list.delete(item)
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    self.process_list.insert(
                        "", tk.END, values=(proc.info["pid"], proc.info["name"])
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.warning(
                        f"Failed to access process info: PID={proc.info.get('pid')}, Reason: {e}"
                    )
            logger.info("Process list refreshed successfully.")
        except Exception as e:
            logger.error(f"Error refreshing process list: {e}", exc_info=True)

    def dump_selected_process(self):
        """Dump memory of the selected process."""
        selected = self.process_list.selection()
        if not selected:
            logger.warning("No process selected for dumping.")
            messagebox.showwarning("No Selection", "Please select a process to dump.")
            return

        item = self.process_list.item(selected[0])
        pid, name = item["values"]
        logger.info(f"Selected process for dump: PID={pid}, Name={name}")

        is_64bit_process = is_process_64bit(pid)

        # Start the dump in a separate thread to keep the GUI responsive
        threading.Thread(
            target=self.perform_dump, args=(int(pid), is_64bit_process), daemon=True
        ).start()

    def perform_dump(self, pid, is_64bit_process):
        """Perform the memory dump and save base addresses."""
        try:
            self.memory_dumper = MemoryDumper(pid=pid, output_dir=self.output_dir)
            db_path = self.memory_dumper.dump_memory()
            logger.info(f"Memory dump completed. Database saved at {db_path}")
            messagebox.showinfo(
                "Dump Completed", f"Memory dump completed and saved to {db_path}"
            )

            # Instantiate the AnalyzeProcessWindow
            AnalyzeProcessWindow(parent=self.winfo_toplevel(), dump_path=db_path)

        except Exception as e:
            logger.error(f"Error during memory dump: {e}", exc_info=True)
            messagebox.showerror("Dump Error", f"Failed to dump memory: {e}")
