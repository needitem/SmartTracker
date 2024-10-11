import tkinter as tk
from tkinter import messagebox, ttk
import logging
import os
import subprocess
import struct

from dump.base.mem_edit_handler import MemEditHandler

logger = logging.getLogger(__name__)

class ModifyMemoryWindow(tk.Toplevel):
    def __init__(self, parent, pid, module_name):
        super().__init__(parent)
        self.title("Modify Memory")
        self.geometry("600x600")
        self.pid = pid
        self.module_name = module_name
        self.pm = MemEditHandler.open_process(self.pid)
        if not self.pm:
            messagebox.showerror("Process Error", f"Could not open process PID={self.pid}")
            self.destroy()
            return
        self.create_widgets()

    def create_widgets(self):
        """GUI 위젯을 생성합니다."""
        # 프로세스 및 모듈 정보 레이블
        label = ttk.Label(self, text=f"Modify Memory for PID={self.pid}, Module={self.module_name}", font=("Arial", 12, "bold"))
        label.grid(row=0, column=0, columnspan=2, pady=10)

        # DLL 선택 드롭다운
        ttk.Label(self, text="Select DLL:").grid(row=1, column=0, pady=5, sticky=tk.E)
        self.dll_var = tk.StringVar()
        try:
            modules = self.pm.list_modules()
            dll_names = [module.name.decode('utf-8') if isinstance(module.name, bytes) else module.name for module in modules]
        except Exception as e:
            logger.error(f"Error listing modules for PID={self.pid}: {e}")
            dll_names = []
        
        self.dll_combo = ttk.Combobox(
            self,
            textvariable=self.dll_var,
            values=dll_names,
            state="readonly",
            width=50
        )
        self.dll_combo.grid(row=1, column=1, pady=5, sticky=tk.W)
        if dll_names:
            self.dll_combo.current(0)  # 기본값 설정

        # 포인터 경로 입력 필드
        tk.Label(self, text="Pointer Offsets (comma-separated):").grid(row=2, column=0, pady=5, sticky=tk.E)
        self.ptr_offsets_var = tk.StringVar()
        self.ptr_offsets_entry = ttk.Entry(self, textvariable=self.ptr_offsets_var, width=50)
        self.ptr_offsets_entry.grid(row=2, column=1, pady=5, sticky=tk.W)
        tk.Label(self, text="Example: 0x10, 0x20, 0x30").grid(row=3, column=0, columnspan=2, pady=2)

        # 최종 주소 표시 레이블
        self.final_addr_label = tk.Label(self, text="Final Address: None", font=("Arial", 10, "italic"))
        self.final_addr_label.grid(row=4, column=0, columnspan=2, pady=5)

        # 주소 가져오기 버튼
        self.get_addr_button = ttk.Button(self, text="Get Address", command=self.get_final_address)
        self.get_addr_button.grid(row=5, column=0, columnspan=2, pady=5)

        # 값 타입 선택 드롭다운
        tk.Label(self, text="Value Type:").grid(row=6, column=0, pady=5, sticky=tk.E)
        self.value_type_var = tk.StringVar()
        value_types = ["Byte", "2-byte Integer", "4-byte Integer", "Float", "Double", "String"]
        self.value_type_combo = ttk.Combobox(
            self,
            textvariable=self.value_type_var,
            values=value_types,
            state="readonly",
            width=20
        )
        self.value_type_combo.grid(row=6, column=1, pady=5, sticky=tk.W)
        self.value_type_combo.current(0)  # 기본값 설정

        # 새로운 값 입력 필드
        tk.Label(self, text="New Value:").grid(row=7, column=0, pady=5, sticky=tk.E)
        self.value_var = tk.StringVar()
        self.value_entry = ttk.Entry(self, textvariable=self.value_var, width=30)
        self.value_entry.grid(row=7, column=1, pady=5, sticky=tk.W)

        # 메모리 인젝션 버튼
        self.inject_button = ttk.Button(self, text="Memory Injection", command=self.inject_memory)
        self.inject_button.grid(row=8, column=0, columnspan=2, pady=20)

        # 닫기 버튼
        ttk.Button(self, text="Close", command=self.destroy).grid(row=9, column=0, columnspan=2, pady=10)

        # 행과 열의 확장성을 위해 weight 설정
        self.grid_rowconfigure(0, weight=0)
        for i in range(1, 10):
            self.grid_rowconfigure(i, weight=0)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)

    def get_final_address(self):
        """최종 주소를 계산하고 레이블에 표시합니다."""
        dll_name = self.dll_var.get()
        ptr_offsets_str = self.ptr_offsets_var.get().strip()
        if not dll_name:
            messagebox.showerror("Input Error", "Please select a DLL.")
            return
        if not ptr_offsets_str:
            messagebox.showerror("Input Error", "Please enter pointer offsets.")
            return
        try:
            # 선택된 DLL의 베이스 주소 가져오기
            module = next((m for m in self.pm.list_modules() if m.name.decode('utf-8') == dll_name), None)
            if not module:
                messagebox.showerror("Module Error", f"Module {dll_name} not found.")
                return
            base_address = module.lpBaseOfDll

            # 포인터 경로 파싱
            ptr_offsets = [int(offset.strip(), 16) if offset.strip().startswith("0x") else int(offset.strip()) for offset in ptr_offsets_str.split(",")]
            final_address = self.master.ptraddr(base_address, ptr_offsets, 1)  # mod=1: 모듈 선택
            self.final_addr_label.config(text=f"Final Address: {hex(final_address)}")
            self.final_address = final_address
            logger.info(f"Final address calculated: {hex(final_address)}")
        except Exception as e:
            messagebox.showerror("Parsing Error", f"Error parsing pointer offsets: {e}")
            logger.error(f"Error in get_final_address: {e}")

    def inject_memory(self):
        """메모리 인젝션을 수행합니다."""
        if not hasattr(self, 'final_address'):
            messagebox.showerror("Address Error", "Please calculate the final address first.")
            return

        value_type = self.value_type_var.get()
        new_value_str = self.value_var.get().strip()
        final_address = self.final_address

        # 값 변환
        try:
            if value_type == "Byte":
                new_value = struct.pack("B", int(new_value_str))
            elif value_type == "2-byte Integer":
                new_value = struct.pack("<H" if self.master.endian_var.get() == "little" else ">H", int(new_value_str))
            elif value_type == "4-byte Integer":
                new_value = struct.pack("<I" if self.master.endian_var.get() == "little" else ">I", int(new_value_str))
            elif value_type == "Float":
                new_value = struct.pack("<f" if self.master.endian_var.get() == "little" else ">f", float(new_value_str))
            elif value_type == "Double":
                new_value = struct.pack("<d" if self.master.endian_var.get() == "little" else ">d", float(new_value_str))
            elif value_type == "String":
                new_value = new_value_str.encode('utf-8')
            else:
                messagebox.showerror("Unknown Type", f"Unsupported value type: {value_type}")
                return
        except (ValueError, struct.error) as e:
            messagebox.showerror("Invalid Value", f"Error converting value: {e}")
            return

        # 메모리 인젝션 수행
        success = MemEditHandler.write_memory(self.pm, final_address, new_value)
        if success:
            messagebox.showinfo("Success", f"Memory at address {hex(final_address)} updated successfully.")
            logger.info(f"Injected memory at address {hex(final_address)} with type {value_type} and value {new_value_str}")
        else:
            messagebox.showerror("Injection Error", "Failed to inject memory.")