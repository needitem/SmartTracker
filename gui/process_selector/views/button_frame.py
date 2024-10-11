import tkinter as tk
from tkinter import ttk

class ButtonFrame(ttk.Frame):
    def __init__(self, parent, modify_memory_callback, find_offset_callback, dump_callback, refresh_callback):
        super().__init__(parent)
        
        # **작은 버튼 스타일 정의**
        style = ttk.Style()
        style.configure("Small.TButton",
                        font=("Arial", 10),      # 폰트 크기 감소
                        padding=(1, 1))          # 버튼 패딩 감소

        # **Refresh Process Button**
        self.refresh_button = ttk.Button(
            self,
            text="Refresh",
            command=refresh_callback,
            style="Small.TButton",            # 작은 버튼 스타일 적용
        )
        self.refresh_button.grid(row=0, column=0, pady=1, padx=1, sticky="w")  # 패딩 감소 및 정렬 변경

        # **Modify Memory Button**
        self.modify_memory_button = ttk.Button(
            self,
            text="Modify",
            command=modify_memory_callback,
            style="Small.TButton",
        )
        self.modify_memory_button.grid(row=1, column=0, pady=1, padx=1, sticky="w")

        # **Find Offset Button**
        self.find_offset_button = ttk.Button(
            self,
            text="Find Offset",
            command=find_offset_callback,
            style="Small.TButton",
        )
        self.find_offset_button.grid(row=2, column=0, pady=1, padx=1, sticky="w")

        # **Dump Memory Button**
        self.dump_button = ttk.Button(
            self,
            text="Dump",
            command=dump_callback,
            state=tk.DISABLED,
            style="Small.TButton",
        )
        self.dump_button.grid(row=3, column=0, pady=1, padx=1, sticky="w")

        # **열의 확장성을 위해 columnconfigure 추가**
        self.columnconfigure(0, weight=1)