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


class FindOffsetWindow(tk.Toplevel):
    def __init__(self, parent, search_callback):
        super().__init__(parent)
        self.title("Find Offset")
        self.geometry("600x400")
        self.search_callback = search_callback
        self.create_widgets()

    def create_widgets(self):
        """Create widgets for Find Offset window."""
        # Frame for Input Controls
        input_frame = ttk.Frame(self)
        input_frame.pack(pady=10, padx=10, fill=tk.X)

        # Value Entry
        ttk.Label(input_frame, text="Value:").grid(row=0, column=0, pady=5, sticky=tk.E)
        self.value_entry = ttk.Entry(input_frame, width=30)
        self.value_entry.grid(row=0, column=1, pady=5, padx=5, sticky=tk.W)

        # Data Type Selection
        ttk.Label(input_frame, text="Data Type:").grid(row=1, column=0, pady=5, sticky=tk.E)
        self.data_type_var = tk.StringVar()
        self.data_type_combo = ttk.Combobox(
            input_frame,
            textvariable=self.data_type_var,
            values=["Integer", "Float", "String"],
            state="readonly",
            width=28
        )
        self.data_type_combo.grid(row=1, column=1, pady=5, padx=5, sticky=tk.W)
        self.data_type_combo.current(0)

        # Search Condition Selection
        ttk.Label(input_frame, text="Search Condition:").grid(row=2, column=0, pady=5, sticky=tk.E)
        self.search_condition_var = tk.StringVar()
        self.search_condition_combo = ttk.Combobox(
            input_frame,
            textvariable=self.search_condition_var,
            values=["Exact Value", "Increased", "Decreased"],
            state="readonly",
            width=28
        )
        self.search_condition_combo.grid(row=2, column=1, pady=5, padx=5, sticky=tk.W)
        self.search_condition_combo.current(0)

        # Search Button
        self.search_button = ttk.Button(self, text="Search", command=self.start_search)
        self.search_button.pack(pady=10)

        # Frame for Search Results
        results_frame = ttk.Frame(self)
        results_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Treeview for Displaying Results
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=("Address", "Module", "Data Type"),
            show="headings",
            selectmode="browse"
        )
        self.results_tree.heading("Address", text="Address")
        self.results_tree.heading("Module", text="Module")
        self.results_tree.heading("Data Type", text="Data Type")
        self.results_tree.column("Address", width=200, anchor=tk.CENTER)
        self.results_tree.column("Module", width=200, anchor=tk.CENTER)
        self.results_tree.column("Data Type", width=120, anchor=tk.CENTER)

        # Adding Scrollbar to Treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.pack(fill=tk.BOTH, expand=True)

        # Close Button
        self.close_button = ttk.Button(self, text="Close", command=self.destroy)
        self.close_button.pack(pady=10)

    def start_search(self):
        """Initiate the search based on user input."""
        value = self.value_entry.get().strip()
        data_type = self.data_type_var.get()
        search_condition = self.search_condition_var.get()

        if not value:
            messagebox.showwarning("Input Error", "Please enter a value to search.")
            return

        try:
            if data_type == "Integer":
                search_value = int(value)
            elif data_type == "Float":
                search_value = float(value)
            elif data_type == "String":
                search_value = value  # Keep as string
            else:
                messagebox.showerror("Data Type Error", "Unsupported data type selected.")
                return
        except ValueError:
            messagebox.showerror("Value Error", f"Invalid value for data type {data_type}.")
            return

        selected_process = self.master.process_list.selection()
        if not selected_process:
            messagebox.showwarning(
                "No Process Selected", "Please select a process to find offset."
            )
            return
        pid = int(self.master.process_list.item(selected_process)["values"][0])
        process_name = self.master.process_list.item(selected_process)["values"][1]

        # Start the search in a separate thread
        threading.Thread(
            target=self.search_callback,
            args=(pid, search_value, data_type, search_condition, process_name),
            daemon=True
        ).start()

        # Optionally, disable the search button to prevent multiple clicks
        self.search_button.config(state=tk.DISABLED)

    def update_results(self, results: List[Dict[str, Any]]):
        """Update the Treeview with search results."""
        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        if not results:
            messagebox.showinfo("Find Offset", "No matching entries found.")
            return

        for result in results:
            self.results_tree.insert(
                "",
                tk.END,
                values=(
                    hex(result["address"]),
                    result["module"],
                    result["data_type"]
                )
            )

        messagebox.showinfo("Find Offset Completed", f"Found {len(results)} matching entries.")


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

        # grid layout 설정
        self.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.parent.grid_rowconfigure(0, weight=1)
        self.parent.grid_columnconfigure(0, weight=1)

        self.create_widgets()
        self.populate_process_list()

    def create_widgets(self):
        # 버튼 프레임을 grid로 배치 (상단)
        self.button_frame = ButtonFrame(
            self,
            modify_memory_callback=self.modify_memory,
            find_offset_callback=self.find_offset,
            dump_callback=self.dump_selected_process,
            refresh_callback=self.populate_process_list
        )
        self.button_frame.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="ew")

        # Process List View를 grid로 배치 (왼쪽)
        self.process_list = ProcessListView(
            self,
            self.on_process_select,
            width=300,   # 원하는 너비 설정
            height=20    # 표시될 행 수
        )
        self.process_list.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Module List View를 grid로 배치 (오른쪽)
        self.module_list = ModuleListView(self, on_select_callback=None, width=400, height=20)
        self.module_list.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        # 행과 열의 확장성을 위해 weight 설정
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

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

                    # 프로세스 목록에 "PID"와 "Name" 삽입
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
        def search_value(pid: int, value, data_type: str, search_condition: str, process_name: str):
            """
            Thread function to perform memory search based on user input.

            Args:
                pid (int): Process ID.
                value (int|float|str): The value to search for.
                data_type (str): Data type of the value.
                search_condition (str): Condition for searching.
                process_name (str): Name of the process.
            """
            results = []
            try:
                if data_type == "Integer":
                    addresses = self.memory_analyzer.search_memory_for_value(pid, value)
                    for address in addresses:
                        results.append({
                            "address": address,
                            "module": process_name,
                            "data_type": data_type
                        })
                elif data_type == "Float":
                    addresses = self.memory_analyzer.search_memory_for_float(pid, value)
                    for address in addresses:
                        results.append({
                            "address": address,
                            "module": process_name,
                            "data_type": data_type
                        })
                elif data_type == "String":
                    addresses = self.memory_analyzer.search_memory_for_string(pid, value)
                    for address in addresses:
                        results.append({
                            "address": address,
                            "module": process_name,
                            "data_type": data_type
                        })
                # Extend for 'Increased' and 'Decreased' conditions as needed

                # Update the FindOffsetWindow with results
                self.find_offset_window.update_results(results)
                logger.info(f"Find Offset completed for PID={pid}, Value={value}. Results: {results}")

            except Exception as e:
                logger.error(f"Error during find offset: {e}")
                messagebox.showerror(
                    "Find Offset Error",
                    f"An error occurred while finding offset: {e}",
                )
            finally:
                # Re-enable the search button
                self.find_offset_window.search_button.config(state=tk.NORMAL)

        # Create the Find Offset Window
        self.find_offset_window = FindOffsetWindow(self, search_callback=search_value)
        self.find_offset_window.grab_set()  # Make the window modal

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