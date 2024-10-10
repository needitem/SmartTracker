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
        self.dumper = memory_dumper  # 전달된 MemoryDumper 인스턴스 사용
        self.memory_analyzer = memory_analyzer  # 추가: MemoryAnalyzer 인스턴스 저장
        self.process_controller = ProcessController(
            memory_dumper=self.dumper
        )
        self.module_controller = ModuleController(memory_dumper=self.dumper)
        self.search_controller = SearchController(
            memory_analyzer, None  # AnalysisTab 제거
        )
        self.dumped_pids = set()
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
            text="Modify Memory",  # 버튼 텍스트 변경
            command=self.modify_memory,  # 새로운 메서드 호출
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
                        logger.debug(f"Modules for PID={pid}: {modules}")  # 추가된 로그
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
        """Initiate memory dump for the selected process and module by opening a new window."""
        try:
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

            # Open the Dump Memory Window
            DumpMemoryWindow(self, pid, module_name)
            logger.info(f"Opened Dump Memory window for PID={pid}, Module={module_name}.")

        except Exception as e:
            logger.error(f"Error opening Dump Memory window: {e}")
            messagebox.showerror(
                "Dump Memory Error",
                f"An error occurred while opening Dump Memory window: {e}",
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

            # Perform analysis using memory_analyzer
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
        # Replace 'get_process_modules' with 'get_modules'
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
        """Handles memory modification logic by opening a new window."""
        try:
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

            # Open the Modify Memory Window
            ModifyMemoryWindow(self, pid, module_name)
            logger.info(f"Opened Modify Memory window for PID={pid}, Module={module_name}.")

        except Exception as e:
            logger.error(f"Error opening Modify Memory window: {e}")
            messagebox.showerror(
                "Modify Memory Error",
                f"An error occurred while opening Modify Memory window: {e}",
            )

# Define ModifyMemoryWindow class
class ModifyMemoryWindow(tk.Toplevel):
    def __init__(self, parent, pid, module_name):
        super().__init__(parent)
        self.title("Modify Memory")
        self.geometry("400x300")
        self.pid = pid
        self.module_name = module_name
        self.create_widgets()

    def create_widgets(self):
        # Example implementation: Add widgets for memory modification
        tk.Label(self, text=f"Modify Memory for PID={self.pid}, Module={self.module_name}").pack(pady=10)
        # Add more widgets as needed
        tk.Button(self, text="Close", command=self.destroy).pack(pady=20)

# Define DumpMemoryWindow class
class DumpMemoryWindow(tk.Toplevel):
    def __init__(self, parent, pid, module_name):
        super().__init__(parent)
        self.title("Dump Memory")
        self.geometry("1000x700")  # 창 크기 조정
        self.pid = pid
        self.module_name = module_name
        self.all_entries = []  # 모든 덤프 데이터를 저장할 리스트
        self.sort_orders = {}  # 각 컬럼의 정렬 순서를 저장하는 딕셔너리
        self.create_widgets()

    def create_widgets(self):
        # 상단 프레임: 정보 및 옵션
        info_frame = ttk.Frame(self)
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        info_label = ttk.Label(
            info_frame,
            text=f"Dump Memory for PID={self.pid}, Module={self.module_name}",
            font=("Arial", 12, "bold"),
        )
        info_label.grid(row=0, column=0, columnspan=4, pady=5, sticky=tk.W)

        # 비트 크기 선택
        bit_size_label = ttk.Label(info_frame, text="Select Bit Size:")
        bit_size_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)

        self.bit_size_var = tk.IntVar(value=32)
        bit_size_options = [1, 2, 4, 8, 16, 32, 64]
        self.bit_size_combo = ttk.Combobox(
            info_frame,
            textvariable=self.bit_size_var,
            values=bit_size_options,
            state="readonly",
            width=5
        )
        self.bit_size_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.bit_size_combo.current(bit_size_options.index(32))  # 기본값 32

        # Endianness 선택
        endian_label = ttk.Label(info_frame, text="Select Endianness:")
        endian_label.grid(row=1, column=2, padx=5, pady=5, sticky=tk.E)

        self.endian_var = tk.StringVar(value="little")
        endian_options = ["little", "big"]
        self.endian_combo = ttk.Combobox(
            info_frame,
            textvariable=self.endian_var,
            values=endian_options,
            state="readonly",
            width=10
        )
        self.endian_combo.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)
        self.endian_combo.current(endian_options.index("little"))  # 기본값 little

        # 덤프 시작 버튼
        dump_button = ttk.Button(
            info_frame,
            text="Start Dump",
            command=self.start_dump
        )
        dump_button.grid(row=2, column=0, padx=5, pady=10, sticky=tk.W)

        # 검색 입력 필드 및 버튼
        search_label = ttk.Label(info_frame, text="Search:")
        search_label.grid(row=2, column=1, padx=5, pady=10, sticky=tk.E)

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(info_frame, textvariable=self.search_var, width=30)
        self.search_entry.grid(row=2, column=2, padx=5, pady=10, sticky=tk.W)

        search_button = ttk.Button(
            info_frame,
            text="Search",
            command=self.search_memory
        )
        search_button.grid(row=2, column=3, padx=5, pady=10, sticky=tk.W)

        # 필터 프레임 추가
        filter_frame = ttk.LabelFrame(info_frame, text="필터 옵션")
        filter_frame.grid(row=3, column=0, columnspan=4, padx=5, pady=10, sticky=tk.W)

        # Integer 범위 필터
        ttk.Label(filter_frame, text="Integer Min:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.int_min_var = tk.StringVar()
        self.int_min_entry = ttk.Entry(filter_frame, textvariable=self.int_min_var, width=10)
        self.int_min_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(filter_frame, text="Integer Max:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.E)
        self.int_max_var = tk.StringVar()
        self.int_max_entry = ttk.Entry(filter_frame, textvariable=self.int_max_var, width=10)
        self.int_max_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        # Float Num 범위 필터
        ttk.Label(filter_frame, text="Float Num Min:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.float_min_var = tk.StringVar()
        self.float_min_entry = ttk.Entry(filter_frame, textvariable=self.float_min_var, width=10)
        self.float_min_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(filter_frame, text="Float Num Max:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.E)
        self.float_max_var = tk.StringVar()
        self.float_max_entry = ttk.Entry(filter_frame, textvariable=self.float_max_var, width=10)
        self.float_max_entry.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)

        # is_valid 필터
        ttk.Label(filter_frame, text="Is Valid:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.is_valid_var = tk.StringVar()
        self.is_valid_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.is_valid_var,
            values=["All", "True", "False"],
            state="readonly",
            width=10
        )
        self.is_valid_combo.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.is_valid_combo.current(0)  # 기본값 All

        # 필터 적용 버튼
        apply_filter_button = ttk.Button(
            filter_frame,
            text="Apply Filter",
            command=self.apply_filter
        )
        apply_filter_button.grid(row=2, column=3, padx=5, pady=5, sticky=tk.W)

        # 트리뷰 프레임
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 스크롤바 추가
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)

        # 트리뷰 생성
        self.tree = ttk.Treeview(
            tree_frame,
            columns=(
                "Address",
                "Offset",
                "Raw",
                "String",
                "Integer",
                "Float Num",
                "Module",
                "Timestamp",
                "Process ID",
                "Process Name",
                "Permissions",
                "Processed String",
                "Is Valid",
                "Tags"
            ),
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set
        )

        # 스크롤바 설정
        tree_scroll_y.config(command=self.tree.yview)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.config(command=self.tree.xview)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # 컬럼 설정
        column_settings = {
            "Address": {"width": 120, "anchor": tk.CENTER},
            "Offset": {"width": 80, "anchor": tk.CENTER},
            "Raw": {"width": 120, "anchor": tk.CENTER},
            "String": {"width": 150, "anchor": tk.W},
            "Integer": {"width": 80, "anchor": tk.CENTER},
            "Float Num": {"width": 100, "anchor": tk.CENTER},
            "Module": {"width": 100, "anchor": tk.CENTER},
            "Timestamp": {"width": 150, "anchor": tk.CENTER},
            "Process ID": {"width": 80, "anchor": tk.CENTER},
            "Process Name": {"width": 120, "anchor": tk.W},
            "Permissions": {"width": 120, "anchor": tk.W},
            "Processed String": {"width": 150, "anchor": tk.W},
            "Is Valid": {"width": 80, "anchor": tk.CENTER},
            "Tags": {"width": 150, "anchor": tk.W},
        }

        for col in self.tree["columns"]:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col, False))
            self.tree.column(col, width=column_settings[col]["width"], anchor=column_settings[col]["anchor"])

        self.tree.pack(fill=tk.BOTH, expand=True)

        # 닫기 버튼
        close_button = ttk.Button(
            self,
            text="Close",
            command=self.destroy
        )
        close_button.pack(pady=10)

    def start_dump(self):
        try:
            bit_size = self.bit_size_var.get()
            endian = self.endian_var.get()
            dumped_entries = self.master.dumper.dump_module_memory(self.pid, self.module_name, bit_size, endian)
            if not dumped_entries:
                logger.info(
                    f"No memory entries dumped for PID={self.pid}, Module={self.module_name}."
                )
                messagebox.showinfo(
                    "No Entries",
                    f"No memory entries were found for PID={self.pid}, Module={self.module_name}.",
                )
                return

            self.all_entries = dumped_entries  # 모든 덤프 데이터를 저장
            self.master.dumped_pids.add(self.pid)
            logger.info(f"Memory dump completed for PID={self.pid}, Module={self.module_name}.")
            messagebox.showinfo(
                "Dump Completed",
                f"Memory dump completed for PID={self.pid}, Module={self.module_name}.",
            )

            # 트리뷰에 덤프된 데이터 삽입
            self.populate_treeview(self.all_entries)

        except Exception as e:
            logger.error(
                f"Error during memory dump for PID={self.pid}, Module={self.module_name}: {e}"
            )
            messagebox.showerror(
                "Dump Error", f"An error occurred during memory dump: {e}",
            )

    def populate_treeview(self, entries: List[MemoryEntryProcessed]):
        """ 덤프된 메모리 엔트리를 트리 뷰에 삽입합니다. """
        # 기존 항목 삭제
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 엔트리 삽입
        for entry in entries:
            self.tree.insert(
                "",
                tk.END,
                values=(
                    entry.address,
                    entry.offset,
                    entry.raw,
                    entry.string if entry.string else "",
                    entry.integer if entry.integer is not None else "",
                    entry.float_num if entry.float_num is not None else "",
                    entry.module,
                    entry.timestamp,
                    entry.process_id,
                    entry.process_name,
                    entry.permissions,
                    entry.processed_string if entry.processed_string else "",
                    entry.is_valid,
                    ", ".join(entry.tags) if entry.tags else ""
                )
            )

        logger.info(f"Inserted {len(entries)} memory entries into the tree view.")

    def search_memory(self):
        """트리 뷰에서 검색어에 해당하는 엔트리를 필터링합니다."""
        search_term = self.search_var.get().strip().lower()
        if not search_term:
            # 검색어가 없으면 모든 데이터를 다시 표시
            self.populate_treeview(self.all_entries)
            return

        # 필터링된 엔트리 리스트
        filtered_entries = []
        for entry in self.all_entries:
            # 모든 필드를 검색 대상으로 함
            if (
                search_term in entry.address.lower()
                or (entry.offset and search_term in entry.offset.lower())
                or (entry.raw and search_term in entry.raw.lower())
                or (entry.string and search_term in entry.string.lower())
                or (entry.process_name and search_term in entry.process_name.lower())
                or (entry.permissions and search_term in entry.permissions.lower())
                or (entry.processed_string and search_term in entry.processed_string.lower())
                or (entry.tags and any(search_term in tag.lower() for tag in entry.tags))
            ):
                filtered_entries.append(entry)

        # 트리뷰에 필터링된 데이터 표시
        self.populate_treeview(filtered_entries)
        logger.info(f"Search completed. Found {len(filtered_entries)} matching entries.")

    def sort_column(self, col, reverse):
        """트리뷰의 특정 컬럼을 정렬합니다."""
        try:
            # 현재 정렬 순서를 토글
            reverse = self.sort_orders.get(col, False)
            self.sort_orders[col] = not reverse

            # 모든 항목을 가져와 정렬
            data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]

            # 정렬 기준에 따라 적절한 데이터 타입으로 변환
            if col in ["PID", "Process ID", "Integer"]:
                data.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=reverse)
            elif col in ["Offset", "Address"]:
                data.sort(key=lambda t: int(t[0], 16) if t[0].startswith("0x") else 0, reverse=reverse)
            elif col in ["Float Num"]:
                data.sort(key=lambda t: float(t[0]) if t[0] else 0.0, reverse=reverse)
            else:
                data.sort(key=lambda t: t[0].lower(), reverse=reverse)

            # 정렬된 순서대로 트리뷰 재배치
            for index, (val, child) in enumerate(data):
                self.tree.move(child, '', index)
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")

    def apply_filter(self):
        """필터 옵션을 적용하여 트리뷰를 갱신합니다."""
        try:
            int_min = self.int_min_var.get()
            int_max = self.int_max_var.get()
            float_min = self.float_min_var.get()
            float_max = self.float_max_var.get()
            is_valid = self.is_valid_var.get()

            filtered_entries = []
            for entry in self.all_entries:
                # Integer 필터
                if int_min:
                    try:
                        if entry.integer is None or entry.integer < int(int_min):
                            continue
                    except ValueError:
                        pass
                if int_max:
                    try:
                        if entry.integer is None or entry.integer > int(int_max):
                            continue
                    except ValueError:
                        pass

                # Float Num 필터
                if float_min:
                    try:
                        if entry.float_num is None or entry.float_num < float(float_min):
                            continue
                    except ValueError:
                        pass
                if float_max:
                    try:
                        if entry.float_num is None or entry.float_num > float(float_max):
                            continue
                    except ValueError:
                        pass

                # is_valid 필터
                if is_valid == "True" and not entry.is_valid:
                    continue
                elif is_valid == "False" and entry.is_valid:
                    continue

                filtered_entries.append(entry)

            # 트리뷰에 필터링된 데이터 표시
            self.populate_treeview(filtered_entries)
            logger.info(f"Filter applied. {len(filtered_entries)} entries match the criteria.")
        except Exception as e:
            logger.error(f"Error applying filter: {e}")