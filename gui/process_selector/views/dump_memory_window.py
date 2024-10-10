import tkinter as tk
from tkinter import messagebox, ttk
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
        """메모리 덤프를 시작하고 결과를 트리뷰에 표시합니다."""
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
        """덤프된 메모리 엔트리를 트리뷰에 삽입합니다."""
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
        """트리뷰에서 검색어에 해당하는 엔트리를 필터링합니다."""
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
            if col in ["Process ID", "PID", "Integer"]:
                data.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=reverse)
            elif col in ["Offset", "Address", "Base Address"]:
                data.sort(key=lambda t: int(t[0], 16) if t[0].startswith("0x") else 0, reverse=reverse)
            elif col in ["Float Num"]:
                data.sort(key=lambda t: float(t[0]) if t[0] else 0.0, reverse=reverse)
            else:
                data.sort(key=lambda t: t[0].lower(), reverse=reverse)

            # 정렬된 순서대로 트리뷰 재배치
            for index, (val, child) in enumerate(data):
                self.tree.move(child, '', index)

            # 다음 클릭 시 역순으로 정렬되도록 설정
            self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))
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