import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import logging
from typing import List

from dump.base.mem_edit_handler import MemEditHandler
from dump.memory.memory_entry import MemoryEntryProcessed

logger = logging.getLogger(__name__)

class DumpMemoryWindow(tk.Toplevel):
    def __init__(self, parent, pid, module_name):
        super().__init__(parent)
        self.title("Dump Memory")
        self.geometry("1000x700")
        self.pid = pid
        self.module_name = module_name
        self.all_entries = []
        self.sort_orders = {}
        self.create_widgets()

    def create_widgets(self):
        """GUI 위젯을 생성합니다."""
        # 상단 프레임: 정보 및 옵션
        info_frame = ttk.Frame(self)
        info_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

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

        # Endianness 선택 (이미 있는 경우 수정 필요)
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

        # 검색 알고리즘 선택
        algorithm_label = ttk.Label(info_frame, text="Search Algorithm:")
        algorithm_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)

        self.algorithm_var = tk.StringVar()
        algorithm_options = [
            "Exact Value Search",
            "Byte Pattern Search",
            "Pointer Chain Scan",
            "Signature-Based Scan",
            "Change Comparison Scan"
        ]
        self.algorithm_combo = ttk.Combobox(
            info_frame,
            textvariable=self.algorithm_var,
            values=algorithm_options,
            state="readonly",
            width=25
        )
        self.algorithm_combo.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.algorithm_combo.current(0)  # 기본값 설정

        # 검색 버튼
        find_button = ttk.Button(
            info_frame,
            text="Find Offset",
            command=self.find_offset
        )
        find_button.grid(row=2, column=3, padx=5, pady=5, sticky=tk.W)

        # 트리뷰 프레임
        tree_frame = ttk.Frame(self)
        tree_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

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
        close_button.grid(row=2, column=0, pady=10)

        # 행과 열의 확장성을 위해 weight 설정
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def find_offset(self):
        """오프셋을 찾는 로직을 실행합니다."""
        algorithm = self.algorithm_var.get()
        module_name = self.module_name
        pid = self.pid

        # 검색할 값 입력 받기
        value_str = simpledialog.askstring("Find Offset", "Enter the value to search for (int, float, str):")
        if value_str is None:
            return  # 사용자가 취소한 경우

        # 값의 타입 결정
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

        # Pymem 인스턴스 생성
        try:
            pm = Pymem(pid)
        except Exception as e:
            logger.error(f"Failed to open process PID={pid}: {e}")
            messagebox.showerror("Process Error", f"Failed to open process PID={pid}: {e}")
            return

        addresses = []
        if algorithm == "Exact Value Search":
            addresses = self.memory_analyzer.find_addresses_by_value(pm, module_name, value)
        elif algorithm == "Byte Pattern Search":
            # 사용자로부터 바이트 패턴 입력 받기
            pattern_str = simpledialog.askstring("Byte Pattern Search", "Enter the byte pattern in hex (e.g., DE AD BE EF):")
            if pattern_str:
                pattern = bytes.fromhex(pattern_str.replace(" ", ""))
                addresses = self.memory_analyzer.byte_pattern_search(pm, module_name, pattern)
        elif algorithm == "Pointer Chain Scan":
            # 사용자로부터 포인터 체인 오프셋 입력 받기
            offsets_str = simpledialog.askstring("Pointer Chain Scan", "Enter the pointer offsets (comma-separated, in hex, e.g., 0x10, 0x20):")
            if offsets_str:
                try:
                    offsets = [int(offset.strip(), 16) if offset.strip().startswith("0x") else int(offset.strip()) for offset in offsets_str.split(",")]
                    # 베이스 주소는 모듈의 Base Address
                    base_address = self.memory_analyzer.find_addresses_by_value(pm, module_name, value)[0] if self.memory_analyzer.find_addresses_by_value(pm, module_name, value) else None
                    if base_address:
                        final_address = self.memory_analyzer.pointer_chain_scan(pm, base_address, offsets)
                        if final_address:
                            addresses.append(final_address)
                except ValueError:
                    messagebox.showerror("Invalid Input", "Offset values are invalid.")
        elif algorithm == "Signature-Based Scan":
            # 사용자로부터 시그니처 입력 받기 (어셈블리 명령어 시퀀스)
            signature = simpledialog.askstring("Signature-Based Scan", "Enter the assembly instructions (space-separated, e.g., mov eax, ebx):")
            if signature:
                signature_list = signature.split()
                addresses = self.memory_analyzer.signature_based_scan(pm, module_name, signature_list)
        elif algorithm == "Change Comparison Scan":
            # 변경 비교 스캔은 이전 덤프 파일 필요
            old_dump_path = simpledialog.askstring("Change Comparison Scan", "Enter the path to the old memory dump file:")
            new_dump_path = simpledialog.askstring("Change Comparison Scan", "Enter the path to the new memory dump file:")
            if old_dump_path and new_dump_path and os.path.exists(old_dump_path) and os.path.exists(new_dump_path):
                try:
                    old_dump = self.load_memory_dump(old_dump_path)
                    new_dump = self.load_memory_dump(new_dump_path)
                    addresses = self.memory_analyzer.change_comparison_scan(old_dump, new_dump)
                except Exception as e:
                    logger.error(f"Error during change comparison scan: {e}")
                    messagebox.showerror("Scan Error", f"Error during scan: {e}")
            else:
                messagebox.showerror("File Error", "Invalid or missing dump file paths.")
        
        pm.close_process()

        if not addresses:
            messagebox.showinfo("No Results", f"No addresses found with the specified criteria.")
            return

        # 결과 표시 및 선택
        if algorithm != "Change Comparison Scan":
            if len(addresses) == 1:
                selected_address = addresses[0]
                proceed = messagebox.askyesno("Confirm", f"Found one address: {hex(selected_address)}\nDo you want to modify it?")
                if proceed:
                    self.modify_memory_at_address(pid, selected_address)
            else:
                # 여러 주소가 발견된 경우 사용자에게 선택하게 함
                address_str = "\n".join([hex(addr) for addr in addresses])
                selected_address_str = simpledialog.askstring("Multiple Addresses Found",
                                                              f"Multiple addresses found:\n{address_str}\nEnter the address to modify (in hex, e.g., 0x1234ABCD):")
                if selected_address_str:
                    try:
                        selected_address = int(selected_address_str, 16)
                        if selected_address in addresses:
                            self.modify_memory_at_address(pid, selected_address)
                        else:
                            messagebox.showerror("Invalid Address", "The entered address is not in the search results.")
                    except ValueError:
                        messagebox.showerror("Invalid Input", "Please enter a valid hexadecimal address.")
        else:
            # Change Comparison Scan 결과 표시
            address_str = "\n".join([hex(addr) for addr in addresses])
            messagebox.showinfo("Change Comparison Results", f"Changed addresses:\n{address_str}")