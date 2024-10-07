# gui/analyze_process/widgets.py
import tkinter as tk
from tkinter import ttk


class StatusLabel(ttk.Label):
    def __init__(self, parent, text=""):
        super().__init__(parent, text=text)


class ProgressBar(ttk.Progressbar):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
