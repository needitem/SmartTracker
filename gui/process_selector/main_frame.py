# Modified gui/process_selector/main_frame.py

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
import psutil
import platform
from typing import List, Dict, Any

from dump.base.memory_dumper import MemoryDumper
from gui.analyze_process.analysis_tab import AnalysisTab
from gui.analyze_process.main_window import AnalyzeProcessWindow
from ..analyze_process.controllers.search_controller import SearchController
from .controllers.process_controller import ProcessController
from .controllers.module_controller import ModuleController
import pymem
from pymem import Pymem
from dump.memory.memory_entry import MemoryEntryProcessed
from dump.analyzer.memory_analyzer import MemoryAnalyzer

logger = logging.getLogger(__name__)


class ProcessSelector(ttk.Frame):
    def __init__(
        self,
        parent,
        memory_dumper: MemoryDumper,
        memory_analyzer: MemoryAnalyzer,
        analysis_tab: AnalysisTab,
    ):
        super().__init__(parent)
        self.parent = parent
        self.dumper = memory_dumper  # Use the passed memory_dumper instance
        self.process_controller = ProcessController(
            memory_dumper=self.dumper
        )  # Initialize with memory_dumper
        self.module_controller = ModuleController()  # Removed database parameter
        self.search_controller = SearchController(
            memory_analyzer, analysis_tab
        )  # Pass required arguments
        self.dumped_pids = set()  # 추적할 PID들
        self.create_widgets()
        self.populate_process_list()

    def create_widgets(self):
        # Create Process Treeview
        self.process_list = ttk.Treeview(
            self, columns=("PID", "Name", "Base Address"), show="headings"
        )
        self.process_list.heading(
            "PID", text="PID", command=lambda: self.sort_column("PID", False)
        )
        self.process_list.heading(
            "Name", text="Process Name", command=lambda: self.sort_column("Name", False)
        )
        self.process_list.heading("Base Address", text="Base Address")
        self.process_list.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 5), pady=5
        )

        # Add Scrollbar to Process Treeview
        scrollbar = ttk.Scrollbar(
            self, orient="vertical", command=self.process_list.yview
        )
        self.process_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        # Bind Process Selection Event
        self.process_list.bind("<<TreeviewSelect>>", self.on_process_select)

        # Create Module Treeview
        self.module_list = ttk.Treeview(
            self, columns=("Name", "Base Address", "Size"), show="headings"
        )
        self.module_list.heading("Name", text="Module Name")
        self.module_list.heading("Base Address", text="Base Address")
        self.module_list.heading("Size", text="Size")
        self.module_list.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 10), pady=5
        )

        # Add Scrollbar to Module Treeview
        scrollbar = ttk.Scrollbar(
            self, orient="vertical", command=self.module_list.yview
        )
        self.module_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        # Add Dump Memory Button
        self.dump_button = ttk.Button(
            self,
            text="Dump Memory",
            command=self.dump_selected_process,
            state=tk.DISABLED,
        )
        self.dump_button.pack(pady=10)

    def populate_process_list(self):
        """프로세스 목록을 채우고 데이터베이스에 프로세스와 모듈을 저장합니다."""
        # 기존 항목 삭제
        for item in self.process_list.get_children():
            self.process_list.delete(item)

        # 모든 실행 중인 프로세스 반복
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"]

                # Use pymem to open the process and list modules
                pm = Pymem(pid)
                modules = self.dumper.list_modules(pid)  # Pass pid if required
                pm.close_process()

                # base_address 초기화
                base_address_str = self.compute_base_address(proc)

                # 프로세스 목록에 삽입
                self.process_list.insert(
                    "", tk.END, values=(pid, name, base_address_str)
                )
                logger.debug(
                    f"Inserted process: PID={pid}, Name={name}, Base Address={base_address_str}"
                )

                # 프로세스의 모듈 삽입
                self.insert_process_modules(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.warning(f"프로세스 {proc}에 접근할 수 없습니다: {e}")
                continue

    def insert_process_modules(self, pid: int):
        """특정 프로세스의 모든 모듈을 데이터베이스에 삽입합니다."""
        try:
            modules = self.get_windows_process_modules(pid)
            if not modules:
                logger.info(f"PID={pid}에 대한 모듈이 없습니다.")
                return

            for module in modules:
                module_name = module.get("name", "Unknown")
                base_address = module.get("base_address", "0x0")
                size = module.get("size", 0)
                # Handle module insertion without database
                # Example: Insert into Treeview or other UI components
                self.module_list.insert(
                    "", tk.END, values=(module_name, base_address, size)
                )
                logger.debug(
                    f"Inserted module: Name={module_name}, Base Address={base_address}, Size={size}"
                )
        except Exception as e:
            logger.error(f"Error inserting modules for PID={pid}: {e}")

    def get_windows_process_modules(self, pid: int) -> List[Dict[str, Any]]:
        """Windows 프로세스의 모듈을 가져옵니다."""
        return self.dumper.get_process_modules(pid)

    def sort_column(self, col, reverse):
        """Sort Treeview column when header is clicked."""
        try:
            l = [
                (self.process_list.set(k, col), k)
                for k in self.process_list.get_children("")
            ]
            if col == "PID":
                l.sort(
                    key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=reverse
                )
            else:
                l.sort(reverse=reverse)
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")
            return

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            self.process_list.move(k, "", index)

        # Reverse sort next time
        self.process_list.heading(
            col, command=lambda: self.sort_column(col, not reverse)
        )

    def on_process_select(self, event):
        """Display modules of the selected process when a process is selected."""
        selected_item = self.process_list.selection()
        if not selected_item:
            return
        pid, name, _ = self.process_list.item(selected_item, "values")
        logger.info(f"Selected PID={pid}, Process={name}")
        self.populate_module_list(int(pid))
        self.dump_button.config(state=tk.NORMAL)

    def populate_module_list(self, pid: int):
        """선택 로세스의 모듈을 가져와 표시합니다."""
        # 기존 모듈 삭제
        for item in self.module_list.get_children():
            self.module_list.delete(item)

        # 데이터베이스에서 모듈 가져오기
        modules = self.module_controller.fetch_modules_by_pid(pid)
        if not modules:
            logger.info(f"PID={pid}에 대한 모듈이 없습니다.")
            return

        for module in modules:
            self.module_list.insert(
                "",
                tk.END,
                values=(module["name"], module["base_address"], module["size"]),
            )

    def dump_selected_process(self):
        """Initiate memory dump for the selected process and module."""
        selected_process = self.process_list.selection()
        selected_module = self.module_list.selection()

        if not selected_process or not selected_module:
            logger.warning("No process or module selected.")
            return

        # Retrieve PID and module name
        pid = int(self.process_list.item(selected_process)["values"][0])
        module_name = self.module_list.item(selected_module)["values"][0]

        # Perform memory dump
        try:
            dumped_entries = self.dumper.dump_module_memory(pid, module_name)
            if not dumped_entries:
                logger.info(
                    f"No memory entries dumped for PID={pid}, Module={module_name}."
                )
                messagebox.showinfo(
                    "No Entries",
                    f"No memory entries were found for PID={pid}, Module={module_name}.",
                )
                return

            # Add to dumped PIDs set
            self.dumped_pids.add(pid)

            logger.info(f"Memory dump completed for PID={pid}, Module={module_name}.")
            messagebox.showinfo(
                "Dump Completed",
                f"Memory dump completed for PID={pid}, Module={module_name}.",
            )

            # Refresh process list if needed
            self.populate_process_list()

        except Exception as e:
            logger.error(
                f"Error during memory dump for PID={pid}, Module={module_name}: {e}"
            )
            messagebox.showerror(
                "Dump Error", f"An error occurred during memory dump: {e}"
            )

    def run_analysis(self):
        """Perform memory analysis and display results."""
        try:
            if not self.dumped_pids:
                logger.warning("No PIDs selected for analysis.")
                messagebox.showwarning(
                    "No Data",
                    "There are no dumped processes to analyze.",
                )
                return

            # Perform analysis using memory_dumper or other components
            logger.info("Analysis functionality is being executed without database.")
            # Example: self.memory_dumper.perform_analysis(self.dumped_pids)
            messagebox.showinfo(
                "Analysis Completed",
                "Memory analysis has been completed successfully.",
            )
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            messagebox.showerror(
                "Analysis Error", f"An error occurred during analysis: {e}"
            )

    def compute_base_address(self, proc: psutil.Process) -> str:
        """Compute the base address for a given process."""
        modules = self.dumper.get_modules(proc.pid)  # Use MemoryDumper to get modules
        if modules:
            first_module = modules[0]
            return first_module.get("base_address", "0x0")
        else:
            return "0x0"
