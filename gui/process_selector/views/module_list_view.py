import tkinter as tk
from tkinter import ttk
import logging

logger = logging.getLogger(__name__)

class ModuleListView(ttk.Treeview):
    def __init__(self, parent, on_select_callback, width=None, height=20):
        super().__init__(parent, columns=("Module Name", "Base Address", "Size"), show="headings", height=height)
        
        # Define column headings
        self.heading("Module Name", text="Module Name", command=lambda: self.sort_column("Module Name", False))
        self.heading("Base Address", text="Base Address", command=lambda: self.sort_column("Base Address", False))
        self.heading("Size", text="Size", command=lambda: self.sort_column("Size", False))
        
        # Set column widths if width is provided
        if width:
            # Distribute the provided width between columns (e.g., 40% for Module Name, 30% for Base Address, 30% for Size)
            self.column("Module Name", width=int(width * 0.4), anchor=tk.W, stretch=False)
            self.column("Base Address", width=int(width * 0.3), anchor=tk.CENTER, stretch=False)
            self.column("Size", width=int(width * 0.3), anchor=tk.CENTER, stretch=False)
        else:
            # Set default column widths
            self.column("Module Name", width=200, anchor=tk.W)
            self.column("Base Address", width=150, anchor=tk.CENTER)
            self.column("Size", width=100, anchor=tk.CENTER)
        
        # Bind the selection event to the callback
        self.bind("<<TreeviewSelect>>", on_select_callback)
        
        # Pack the Treeview into the parent frame
        self.pack(fill=tk.BOTH, expand=True)
    
    def sort_column(self, col, reverse):
        """Sort Treeview column when heading is clicked."""
        try:
            # Get all items and sort them
            if col == "Size":
                data = [(int(self.set(child, col)), child) for child in self.get_children('')]
            else:
                data = [(self.set(child, col).lower(), child) for child in self.get_children('')]
            
            # Sort data
            data.sort(reverse=reverse)
            
            # Rearrange items in sorted order
            for index, (val, child) in enumerate(data):
                self.move(child, '', index)
            
            # Update the heading to reverse sort on next click
            self.heading(col, command=lambda: self.sort_column(col, not reverse))
        except Exception as e:
            logger.error(f"Error sorting column {col}: {e}")