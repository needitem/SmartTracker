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
            self.heading(col, command=lambda: self.sort_column(col, not reverse))
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")