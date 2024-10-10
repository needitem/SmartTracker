import tkinter as tk
from tkinter import ttk


# 예시: 스테이터스 레이블 위젯
class StatusLabel(ttk.Label):
    def __init__(self, parent, text=""):
        super().__init__(parent, text=text)
        self.configure(font=("Helvetica", 12, "bold"))

    def set_text(self, new_text: str):
        self.config(text=new_text)


# 예시: 프로그레스 바 위젯
class ProgressBar(ttk.Progressbar):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(length=400, mode="indeterminate")
