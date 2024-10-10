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
import struct  # 값 변환을 위한 struct 모듈 추가
from dump.base.mem_edit_handler import MemEditHandler  # MemEditHandler 가져오기

from dump.base.memory_dumper import MemoryDumper
from gui.analyze_process.main_window import AnalyzeProcessWindow  # AnalysisTab 제거
from ..analyze_process.controllers.search_controller import SearchController
from .controllers.process_controller import ProcessController
from .controllers.module_controller import ModuleController
import pymem
from pymem import Pymem
from dump.memory.memory_entry import MemoryEntryProcessed
from dump.analyzer.memory_analyzer import MemoryAnalyzer
from .views.process_list_view import ProcessListView
from .views.module_list_view import ModuleListView
from .views.button_frame import ButtonFrame
from .views.dump_memory_window import DumpMemoryWindow
from .views.modify_memory_window import ModifyMemoryWindow

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
        self.dumper = memory_dumper
        self.memory_analyzer = memory_analyzer
        self.process_controller = ProcessController(memory_dumper=self.dumper)
        self.module_controller = ModuleController(memory_dumper=self.dumper)
        self.search_controller = SearchController(memory_analyzer, None)
        self.dumped_pids = set()
        self.sort_orders = {}

        self.create_widgets()
        self.populate_process_list()

    def create_widgets(self):
        # Create Process List View
        self.process_list = ProcessListView(self, self.on_process_select)

        # Create Module List View
        self.module_list = ModuleListView(self)

        # Create Button Frame
        self.button_frame = ButtonFrame(
            self,
            modify_memory_callback=self.modify_memory,
            find_offset_callback=self.find_offset,
            dump_callback=self.dump_selected_process
        )

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
                    logger.debug(f"Attempting to open PID={pid}, Process Name={name}")

                    # Pymem을 사용하여 프로세스 열기
                    try:
                        pm = Pymem(pid)
                    except Exception as e:
                        logger.error(f"Pymem 호출 중 에러가 발생했습니다 PID={pid}: {e}")
                        continue  # 유효하지 않은 PID이거나 접근 불가한 경우 건너뜁니다.

                    try:
                        pm.close_process()  # 프로세스 닫기
                    except Exception as close_e:
                        logger.error(f"Error closing process PID={pid}: {close_e}")

                    # 프로세스 목록에 "PID"와 "Name"만 삽입
                    self.process_list.insert(
                        "", tk.END, values=(pid, name)
                    )
                    logger.debug(
                        f"Inserted process: PID={pid}, Name={name}"
                    )

                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.warning(f"프로세스 {proc}에 접근할 수 없습니다: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error populating process list: {e}")
            messagebox.showerror("Error", f"Error populating process list: {e}")

    def on_process_select(self, event):
        """선택된 프로세스의 모듈을 로드하고 표시합니다."""
        selected_item = self.process_list.selection()
        if not selected_item:
            return
        pid, name = self.process_list.item(selected_item, "values")
        logger.info(f"Selected PID={pid}, Process={name}")
        self.populate_module_list(int(pid))  # 선택된 프로세스에 대한 모듈 로드
        self.button_frame.dump_button.config(state=tk.NORMAL)

    def populate_module_list(self, pid: int):
        """선택된 프로세스의 모듈을 가져와 ModuleListView에 표시합니다."""
        try:
            # 기존 모듈 삭제
            for item in self.module_list.get_children():
                self.module_list.delete(item)

            # 데이터베이스에서 모듈 가져오기
            modules = self.module_controller.fetch_modules_by_pid(pid)
            if not modules:
                logger.info(f"PID={pid}에 대한 모듈이 없습니다.")
                return

            for module in modules:
                module_name = module.get("name", "Unknown")
                base_address = module.get("base_address", "0x0")
                size = module.get("size", 0)
                # ModuleListView에 모듈 삽입
                self.module_list.insert(
                    "", tk.END, values=(module_name, base_address, size)
                )
                logger.debug(
                    f"Inserted module: Name={module_name}, Base Address={base_address}, Size={size}"
                )
        except Exception as e:
            logger.error(f"Error inserting modules for PID={pid}: {e}")

    def dump_selected_process(self):
        """선택된 프로세스와 모듈에 대한 메모리 덤프를 시작합니다."""
        selected_process = self.process_list.selection()
        selected_module = self.module_list.selection()

        if not selected_process or not selected_module:
            logger.warning("No process or module selected for dumping.")
            messagebox.showwarning(
                "Selection Required",
                "Please select both a process and a module to dump memory.",
            )
            return

        pid = int(self.process_list.item(selected_process)["values"][0])
        module_name = self.module_list.item(selected_module)["values"][0]

        # DumpMemoryWindow 열기
        DumpMemoryWindow(self, pid, module_name)
        logger.info(f"Opened Dump Memory window for PID={pid}, Module={module_name}.")

    def run_analysis(self):
        """메모리 분석을 수행하고 결과를 표시합니다."""
        try:
            if not self.dumped_pids:
                logger.warning("No PIDs selected for analysis.")
                messagebox.showwarning(
                    "No Data",
                    "There are no dumped processes to analyze.",
                )
                return

            # 메모리 분석 수행 (기능이 제거됨)
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
        """특정 프로세스의 베이스 주소를 계산합니다."""
        modules = self.dumper.get_modules(proc.pid)  # 수정된 메서드 호출
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

            # 오프셋 찾기 로직 수정: self.memory_analyzer 사용
            pattern = b'\x00\x00\x00\x00'  # 예시 패턴
            replacement = b'\x01\x01\x01\x01'  # 예시 대체 데이터

            # 수정된 라인: self.memory_analyzer 사용
            count = self.memory_analyzer.search_and_modify_pattern(pid, pattern, replacement)
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

    def modify_memory(self):
        """선택된 프로세스와 모듈의 메모리를 수정합니다."""
        selected_process = self.process_list.selection()
        selected_module = self.module_list.selection()

        if not selected_process or not selected_module:
            logger.warning("No process or module selected for modification.")
            messagebox.showwarning(
                "Selection Required",
                "Please select both a process and a module to modify memory.",
            )
            return

        pid = int(self.process_list.item(selected_process)["values"][0])
        module_name = self.module_list.item(selected_module)["values"][0]

        # ModifyMemoryWindow 열기
        ModifyMemoryWindow(self, pid, module_name)
        logger.info(f"Opened Modify Memory window for PID={pid}, Module={module_name}.")

    def ptraddr(self, base_address: int, offsets: List[int], mod: int) -> int:
        """
        포인터 주소를 계산하는 함수.

        Args:
            base_address (int): DLL의 베이스 주소.
            offsets (List[int]): 포인터 체인 오프셋 리스트.
            mod (int): 모듈 선택 여부 (1: 모듈 선택, 기타: 다른 모듈).

        Returns:
            int: 최종 메모리 주소.
        """
        addr = base_address
        for offset in offsets:
            try:
                addr = self.pm.read_int(addr + offset)
            except Exception as e:
                logger.error(f"Error reading memory at address {hex(addr + offset)}: {e}")
                return 0
        return addr