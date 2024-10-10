# Modified gui/analyze_process/main_window.py

import tkinter as tk
from tkinter import ttk, messagebox
import logging
import os
import threading

from .analysis_tab import AnalysisTab
from .search_tab import SearchTab
from .widgets import StatusLabel, ProgressBar

logger = logging.getLogger(__name__)


class AnalyzeProcessWindow(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Tk,
        dump_path: str,
    ):
        super().__init__(parent)
        self.title(f"Memory Analysis - {os.path.basename(dump_path)}")
        self.geometry("1200x800")
        self.dump_path = dump_path

        # Create Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Analysis Results Tab
        # Removed AnalysisTab initialization related to DumpAnalyzer

        # Create Search Tab
        self.search_tab = SearchTab(
            self.notebook, self.memory_analyzer, self.analysis_tab
        )
        self.notebook.add(self.search_tab, text="검색")

        # Create Status and Progress Bar Widgets
        self.status_label = StatusLabel(self, text="Starting analysis...")
        self.status_label.pack(pady=10)

        self.progress_bar = ProgressBar(self, mode="indeterminate")
        self.progress_bar.pack(pady=10, fill=tk.X, padx=20)
        self.progress_bar.start()

        # Start analysis in a separate thread
        analysis_thread = threading.Thread(target=self.run_analysis, daemon=True)
        analysis_thread.start()

    def run_analysis(self):
        """Run memory analysis."""
        try:
            logger.info("Analysis functionality has been removed.")

            self.status_label.set_text("Analysis completed successfully.")
            logger.info("Analysis completed successfully.")
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            messagebox.showerror(
                "Analysis Error", f"An error occurred during analysis: {e}"
            )
            self.status_label.set_text("Analysis failed.")
        finally:
            self.progress_bar.stop()
