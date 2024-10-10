import tkinter as tk
from tkinter import ttk
import logging

logger = logging.getLogger(__name__)

class ProcessListView(ttk.Treeview):
    def __init__(self, parent, on_select_callback, width=None, height=20):
        super().__init__(parent, columns=("PID", "Name"), show="headings", height=height)

        # Define column headings
        self.heading("PID", text="PID", command=lambda: self.sort_column("PID", False))
        self.heading("Name", text="Process Name", command=lambda: self.sort_column("Name", False))

        # Set column widths if width is provided
        if width:
            # Distribute the provided width between columns (e.g., 30% for PID and 70% for Name)
            self.column("PID", width=int(width * 0.3), anchor=tk.CENTER)
            self.column("Name", width=int(width * 0.7), anchor=tk.W)

        # Bind the selection event to the callback
        self.bind("<<TreeviewSelect>>", on_select_callback)

        # Pack the Treeview into the parent frame
        self.pack(fill=tk.BOTH, expand=True)

    def sort_column(self, col, reverse):
        """컬럼을 정렬하는 메서드."""
        try:
            # 모든 항목을 가져와 정렬할 리스트 생성
            if col == "PID":
                data = [(int(self.set(child, col)), child) for child in self.get_children('')]
            else:
                data = [(self.set(child, col).lower(), child) for child in self.get_children('')]

            # 정렬
            data.sort(reverse=reverse)

            # 정렬된 순서대로 Treeview 재배치
            for index, (val, child) in enumerate(data):
                self.move(child, '', index)

            # 다음 클릭 시 역순으로 정렬되도록 설정
            self.heading(col, command=lambda: self.sort_column(col, not reverse))
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")