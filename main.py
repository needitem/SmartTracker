# Modified main.py

import tkinter as tk
from tkinter import ttk
import logging

from dump.database import Database
from gui.process_selector.main_frame import ProcessSelector

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Memory Analyzer")
        self.geometry("800x600")

        # Initialize shared Database instance
        self.db = Database()

        # Create Notebook
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Add Process Selector tab with shared Database
        process_selector = ProcessSelector(notebook, db=self.db)
        notebook.add(process_selector, text="Select Process")

    def on_closing(self):
        """Handle application closure."""
        self.db.close()
        self.destroy()

if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()