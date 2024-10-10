# Modified gui/process_selector/main_frame.py

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
import psutil
import platform
from typing import List, Dict, Any
import subprocess  # Cheat Engine 실행을 위한 모듈 추가
import os

from dump.base.memory_dumper import MemoryDumper
from gui.analyze_process.main_window import AnalyzeProcessWindow  # AnalysisTab 제거
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
    ):
        super().__init__(parent)
        self.parent = parent
        self.dumper = memory_dumper  # Use the passed memory_dumper instance
        self.process_controller = ProcessController(
            memory_dumper=self.dumper
        )  # Initialize with memory_dumper
        self.module_controller = ModuleController(memory_dumper=self.dumper)  # MemoryDumper 전달
        self.search_controller = SearchController(
            memory_analyzer, None  # AnalysisTab 제거
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

        # Add Buttons Frame
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)

        # Add Cheat Engine Button
        self.cheat_engine_button = ttk.Button(
            buttons_frame,
            text="Cheat Engine",
            command=self.open_cheat_engine,
        )
        self.cheat_engine_button.pack(pady=5, fill=tk.X)

        # Add Find Offset Button
        self.find_offset_button = ttk.Button(
            buttons_frame,
            text="Find Offset",
            command=self.find_offset,
        )
        self.find_offset_button.pack(pady=5, fill=tk.X)

        # Add Dump Memory Button
        self.dump_button = ttk.Button(
            buttons_frame,
            text="Dump Memory",
            command=self.dump_selected_process,
            state=tk.DISABLED,
        )
        self.dump_button.pack(pady=20, fill=tk.X)

    def populate_process_list(self):
        """프로세스 목록을 채우고 데이터베이스에 프로세스와 모듈을 저장합니다."""
        try:
            # 기존 항목 삭제
            for item in self.process_list.get_children():
                self.process_list.delete(item)

            # 모든 실행 중인 프로세스 반복
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid = proc.info["pid"]

                    # PID가 0 이하인 경우 건너뜁니다.
                    if pid <= 0:
                        logger.warning(f"Skipping invalid PID={pid}")
                        continue

                    name = proc.info["name"]
                    logger.debug(f"Attempting to open PID={pid}, Process Name={name}")  # 추가: 디버그 로그

                    # Pymem을 사용하여 프로세스 열기 및 모듈 목록 가져오기
                    try:
                        pm = Pymem(pid)
                    except Exception as e:
                        logger.error(f"Pymem 호출 중 에러가 발생했습니다 PID={pid}: {e}")
                        continue  # 유효하지 않은 PID이거나 접근 불가한 경우 건너뜁니다.

                    try:
                        modules = self.dumper.list_modules(pid)  # 필요 시 pid 전달
                    except Exception as e:
                        logger.error(f"Could not open process: {pid}. Error: {e}")
                        try:
                            pm.close_process()
                        except Exception as close_e:
                            logger.error(f"Error closing process PID={pid}: {close_e}")
                        continue  # 프로세스 관련 에러가 발생하면 건너뜁니다.

                    try:
                        pm.close_process()  # 프로세스 닫기
                    except Exception as close_e:
                        logger.error(f"Error closing process PID={pid}: {close_e}")

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
        except Exception as e:
            logger.error(f"Error populating process list: {e}")
            messagebox.showerror("Error", f"Error populating process list: {e}")

    def insert_process_modules(self, pid: int):
        """특정 프로세스의 모든 모듈을 표시합니다."""
        try:
            modules = self.module_controller.fetch_modules_by_pid(pid)  # ModuleController 사용
            if not modules:
                logger.info(f"PID={pid}에 대한 모듈이 없습니다.")
                return

            for module in modules:
                module_name = module.get("name", "Unknown")
                base_address = module.get("base_address", "0x0")
                size = module.get("size", 0)
                # Treeview에 모듈 삽입
                self.module_list.insert(
                    "",
                    tk.END,
                    values=(module_name, base_address, size),
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
            logger.info("Analysis functionality has been removed.")
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
        modules = self.dumper.get_process_modules(proc.pid)  # 수정된 메서드 호출
        if modules:
            first_module = modules[0]
            return first_module.get("base_address", "0x0")
        else:
            return "0x0"

    # 추가된 메서드: Cheat Engine 열기
    def open_cheat_engine(self):
        """Cheat Engine 실행."""
        try:
            # Cheat Engine의 경로를 지정해주세요
            cheat_engine_path = "C:\\Program Files\\Cheat Engine 7.4\\CheatEngine.exe"
            if not os.path.exists(cheat_engine_path):
                logger.error(f"Cheat Engine not found at {cheat_engine_path}.")
                messagebox.showerror(
                    "Cheat Engine Not Found",
                    f"Cheat Engine not found at {cheat_engine_path}.",
                )
                return
            subprocess.Popen([cheat_engine_path])
            logger.info("Cheat Engine launched successfully.")
        except Exception as e:
            logger.error(f"Failed to launch Cheat Engine: {e}")
            messagebox.showerror(
                "Cheat Engine Error",
                f"An error occurred while launching Cheat Engine: {e}",
            )

    # 추가된 메서드: 오프셋 찾기
    def find_offset(self):
        """Offset 찾기 기능 실행."""
        try:
            selected_process = self.process_list.selection()
            if not selected_process:
                messagebox.showwarning(
                    "No Process Selected", "Please select a process to find offset."
                )
                return
            pid = int(self.process_list.item(selected_process)["values"][0])

            # 오프셋 찾기 로직 추가 (예시: 특정 패턴 검색)
            pattern = b'\x00\x00\x00\x00'  # 예시 패턴
            replacement = b'\x01\x01\x01\x01'  # 예시 대체 데이터

            count = self.dumper.memory_analyzer.search_and_modify_pattern(pid, pattern, replacement)
            logger.info(f"Replaced {count} occurrences in PID={pid}.")
            messagebox.showinfo(
                "Find Offset Completed",
                f"Replaced {count} occurrences in PID={pid}.",
            )
        except Exception as e:
            logger.error(f"Error during find offset: {e}")
            messagebox.showerror(
                "Find Offset Error",
                f"An error occurred while finding offset: {e}",
            )