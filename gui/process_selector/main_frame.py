import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
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
from dump.analyzer.memory_analyzer import MemoryAnalyzer  # 올바른 임포트 경로 유지
from gui.analyze_process.controllers.search_controller import SearchController
from gui.process_selector.controllers.process_controller import ProcessController
from gui.process_selector.controllers.module_controller import ModuleController
from gui.process_selector.views.process_list_view import ProcessListView
from gui.process_selector.views.module_list_view import ModuleListView
from gui.process_selector.views.button_frame import ButtonFrame
from gui.process_selector.views.dump_memory_window import DumpMemoryWindow
from gui.process_selector.views.modify_memory_window import ModifyMemoryWindow

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
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']

                    # PID가 0 이하인 경우 건너뜁니다.
                    if pid <= 0:
                        logger.warning(f"Skipping invalid PID={pid}")
                        continue

                    name = proc.info['name']
                    logger.debug(f"Attempting to insert PID={pid}, Process Name={name}")

                    # 프로세스 목록에 "PID"와 "Name" 삽입
                    self.process_list.insert("", tk.END, values=(pid, name))
                    logger.debug(f"Inserted process: PID={pid}, Name={name}")

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
                messagebox.showinfo("모듈 없음", f"PID={pid}에 대한 모듈이 없습니다.")
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
            messagebox.showerror("Error", f"모듈을 가져오는 중 오류가 발생했습니다: {e}")

    def find_offset(self):
        """Find the offset based on user input."""
        try:
            # 사용자로부터 검색할 값 입력 받기
            value_str = simpledialog.askstring("Find Offset", "Enter the value to search for (int, float, str):")
            if not value_str:
                logger.info("Find Offset canceled by the user.")
                return

            # 값의 타입 결정 및 변환
            try:
                if value_str.isdigit():
                    value = int(value_str)
                    data_type = "Integer"
                else:
                    try:
                        value = float(value_str)
                        data_type = "Float"
                    except ValueError:
                        value = str(value_str)
                        data_type = "String"
            except Exception as e:
                logger.error(f"Invalid input value: {e}")
                messagebox.showerror("Invalid Input", f"Invalid input value: {e}")
                return

            # 메모리 검색 수행
            results = self.memory_analyzer.search_memory_entries(value, data_type=data_type)

            # 검색 결과 처리
            if not results:
                messagebox.showinfo("No Results", f"No addresses found with the specified criteria.")
                return
            elif len(results) == 1:
                selected_address = results[0].address
                proceed = messagebox.askyesno("Confirm", f"Found one address: {selected_address}\nDo you want to modify it?")
                if proceed:
                    self.modify_memory_at_address(results[0].process_id, int(results[0].address, 16))
            else:
                # 여러 결과가 있는 경우 사용자에게 선택하도록 요청
                addresses = [entry.address for entry in results]
                address_str = "\n".join(addresses)
                selected_address_str = simpledialog.askstring("Multiple Addresses Found",
                                                              f"Multiple addresses found:\n{address_str}\nEnter the address to modify (in hex, e.g., 0x1234ABCD):")
                if selected_address_str:
                    try:
                        selected_address = int(selected_address_str, 16)
                        if selected_address in [int(addr, 16) for addr in addresses]:
                            # 해당 주소에 맞는 MemoryEntryProcessed 객체 찾기
                            corresponding_entry = next(entry for entry in results if int(entry.address, 16) == selected_address)
                            self.modify_memory_at_address(corresponding_entry.process_id, selected_address)
                        else:
                            messagebox.showerror("Invalid Address", "The entered address is not in the search results.")
                    except ValueError:
                        messagebox.showerror("Invalid Input", "Please enter a valid hexadecimal address.")
        except Exception as e:
            logger.error(f"Error in find_offset: {e}")
            messagebox.showerror("Error", f"An error occurred during Find Offset: {e}")

    def modify_memory_at_address(self, pid: int, address: int):
        """특정 주소의 메모리를 수정하는 함수."""
        # 기존 modify_memory_at_address 메서드 구현
        pass

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

    def dump_selected_process(self):
        """선택된 프로세스의 메모리를 덤프합니다."""
        selected_process = self.process_list.selection()
        selected_module = self.module_list.selection()

        if not selected_process or not selected_module:
            logger.warning("덤프할 프로세스나 모듈이 선택되지 않았습니다.")
            messagebox.showwarning(
                "선택 필요",
                "메모리를 덤프할 프로세스와 모듈을 선택해주세요.",
            )
            return

        pid, process_name = self.process_list.item(selected_process, "values")
        module_info = self.module_list.item(selected_module, "values")
        module_name = module_info[0]

        # 메모리 덤프 수행
        try:
            self.process_controller.dump_process_module(int(pid), module_name)
            messagebox.showinfo("성공", f"PID={pid}, 모듈={module_name}의 메모리를 덤프했습니다.")
            logger.info(f"PID={pid}, 모듈={module_name}의 메모리를 덤프했습니다.")
        except Exception as e:
            logger.error(f"메모리 덤프 실패 PID={pid}, 모듈={module_name}: {e}")
            messagebox.showerror("실패", f"메모리 덤프에 실패했습니다: {e}")