# main.py
import tkinter as tk
from tkinter import ttk
import logging

from gui.process_selector.main_frame import ProcessSelector  # Updated import path

# Configure logging
logging.basicConfig(
    filename="app.log",
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Memory Analyzer")
        self.geometry("800x600")

        # Create notebook
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Add Process Selector tab
        process_selector = ProcessSelector(notebook)
        notebook.add(process_selector, text="Select Process")


if __name__ == "__main__":
    app = Application()
    app.mainloop()
