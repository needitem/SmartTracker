import tkinter as tk
from tkinter import ttk

class StatusLabel(ttk.Label):
    def __init__(self, parent, text=""):
        super().__init__(parent, text=text)
    
    def set_text(self, new_text: str):
        self.config(text=new_text)

class ProgressBar(ttk.Progressbar):
    def __init__(self, parent, mode="indeterminate", **kwargs):
        super().__init__(parent, mode=mode, **kwargs)

# **추가된 클래스: ProcessListView**
class ProcessListView(ttk.Treeview):
    def __init__(self, parent, on_select_callback, **kwargs):
        super().__init__(parent, columns=("PID", "Name", "Base Address"), show="headings", **kwargs)
        self.heading("PID", text="PID", command=lambda: self.sort_column("PID", False))
        self.heading("Name", text="Process Name", command=lambda: self.sort_column("Name", False))
        self.heading("Base Address", text="Base Address")
        self.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 5), pady=5)

        # Add Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.yview)
        self.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        # Bind selection event
        self.bind("<<TreeviewSelect>>", on_select_callback)

    def sort_column(self, col, reverse):
        try:
            l = [(self.set(k, col), k) for k in self.get_children("")]

            if col == "PID":
                l.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=reverse)
            else:
                l.sort(reverse=reverse)
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")
            return

        for index, (val, k) in enumerate(l):
            self.move(k, "", index)

        self.heading(col, command=lambda: self.sort_column(col, not reverse))

# **추가된 클래스: ModuleListView**
class ModuleListView(ttk.Treeview):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, columns=("Name", "Base Address", "Size"), show="headings", **kwargs)
        self.heading("Name", text="Module Name")
        self.heading("Base Address", text="Base Address")
        self.heading("Size", text="Size")
        self.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 10), pady=5)

        # Add Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.yview)
        self.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=5)

    def sort_column(self, col, reverse):
        # 동일한 정렬 로직 추가 가능
        pass

# **Update existing widgets.py if necessary**
# 기존 StatusLabel과 ProgressBar 클래스는 유지됩니다.