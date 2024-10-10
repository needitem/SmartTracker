import tkinter as tk
from tkinter import ttk

class ButtonFrame(ttk.Frame):
    def __init__(self, parent, modify_memory_callback, find_offset_callback, dump_callback):
        super().__init__(parent)
        self.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)

        # Add Modify Memory Button
        self.modify_memory_button = ttk.Button(
            self,
            text="Modify Memory",
            command=modify_memory_callback,
        )
        self.modify_memory_button.pack(pady=5, fill=tk.X)

        # Add Find Offset Button
        self.find_offset_button = ttk.Button(
            self,
            text="Find Offset",
            command=find_offset_callback,
        )
        self.find_offset_button.pack(pady=5, fill=tk.X)

        # Add Dump Memory Button
        self.dump_button = ttk.Button(
            self,
            text="Dump Memory",
            command=dump_callback,
            state=tk.DISABLED,
        )
        self.dump_button.pack(pady=20, fill=tk.X)