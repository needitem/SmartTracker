import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import logging
from dump.memory_dumper import MemoryDumper
from dump.dump_analyzer import DumpAnalyzer
from gui.analyze_process import AnalyzeProcessWindow
from dump.utils import is_process_64bit

logger = logging.getLogger(__name__)


class ProcessSelector(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.process_list = ttk.Treeview(
            tree_frame,
            columns=("PID", "Name"),
            show="headings",
            yscrollcommand=scrollbar.set,
        )
        self.process_list.heading("PID", text="PID")
        self.process_list.heading("Name", text="Process Name")
        self.process_list.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.process_list.yview)

        button_frame = ttk.Frame(self)
        button_frame.pack(pady=5)

        self.refresh_button = ttk.Button(
            button_frame, text="Refresh", command=self.refresh_process_list
        )
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.dump_button = ttk.Button(
            button_frame, text="Dump Memory", command=self.dump_selected_process
        )
        self.dump_button.pack(side=tk.LEFT, padx=5)

        self.last_dump_path = None

        self.refresh_process_list()
        logger.debug("ProcessSelector initialized.")

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

        threading.Thread(
            target=self.perform_dump, args=(int(pid), is_64bit_process), daemon=True
        ).start()

    def perform_dump(self, pid: int, is_64bit: bool):
        """Perform memory dump and analysis in a separate thread."""
        logger.info(f"Initiating memory dump for PID={pid}.")
        try:
            dumper = MemoryDumper(pid)
            db_path = dumper.dump_memory()  # Now returns the database file path
            analyzer = DumpAnalyzer(db_path)  # Removed 'is_64bit=is_64bit'
            analyzer.analyze_and_export()
            logger.info("Memory dump analysis and database insertion completed.")

            self.parent.after(0, lambda: AnalyzeProcessWindow(self.parent, db_path))
        except Exception as e:
            logger.error(f"Memory dump failed for PID={pid}: {e}", exc_info=True)
            # Capture 'e' in the lambda's default arguments
            self.parent.after(
                0,
                lambda e=e: messagebox.showerror(
                    "Dump Error", f"An error occurred: {e}"
                ),
            )
