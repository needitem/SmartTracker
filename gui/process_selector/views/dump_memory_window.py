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
        info_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        info_label = ttk.Label(
            info_frame,
            text=f"Dump Memory for PID={self.pid}, Module={self.module_name}",
            font=("Arial", 12, "bold"),
        )
        info_label.grid(row=0, column=0, columnspan=4, pady=5, sticky=tk.W)

        # 비트 크기 선택 등 다른 위젯들도 grid 사용
        # ...

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

    def sort_column(self, col, reverse):
        """Sort the treeview based on a given column."""
        try:
            # Get all items and sort them
            data = [(self.set(child, col), child) for child in self.get_children('')]
            if col == "PID":
                data.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=reverse)
            else:
                data.sort(reverse=reverse)

            # Rearrange items in sorted order
            for index, (val, child) in enumerate(data):
                self.move(child, '', index)

            # Toggle the sort order for the next click
            self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")