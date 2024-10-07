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