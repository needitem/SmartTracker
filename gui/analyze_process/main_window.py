# Modified gui/analyze_process/main_window.py

import tkinter as tk
from tkinter import ttk, messagebox
import logging
import os
import threading

from dump.database import Database
from dump.dump_analyzer import DumpAnalyzer
from .analysis_tab import AnalysisTab
from .search_tab import SearchTab
from .widgets import StatusLabel, ProgressBar

logger = logging.getLogger(__name__)

class AnalyzeProcessWindow(tk.Toplevel):
    def __init__(self, parent: tk.Tk, dump_path: str):
        super().__init__(parent)
        self.title(f"Memory Analysis - {os.path.basename(dump_path)}")
        self.geometry("1200x800")
        self.dump_path = dump_path

        # Initialize Database with the correct path
        self.db = Database(db_path=self.dump_path)

        # Create DumpAnalyzer with the Database instance
        self.dump_analyzer = DumpAnalyzer(database=self.db)

        # Create Notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Analysis Results Tab with the DumpAnalyzer instance
        self.analysis_tab = AnalysisTab(self.notebook, self.dump_analyzer)
        self.notebook.add(self.analysis_tab, text="분석 결과")

        # Create Search Tab with reference to analysis_tab
        self.search_tab = SearchTab(self.notebook, self.dump_analyzer, self.analysis_tab)
        self.notebook.add(self.search_tab, text="검색")

        # Create Status and Progress Widgets
        self.status_label = StatusLabel(self, text="Starting analysis...")
        self.status_label.pack(pady=10)

        self.progress_bar = ProgressBar(self, mode="indeterminate")
        self.progress_bar.pack(pady=10, fill=tk.X, padx=20)
        self.progress_bar.start()

        # Start the analysis in a separate thread
        analysis_thread = threading.Thread(target=self.run_analysis, daemon=True)
        analysis_thread.start()

    def run_analysis(self):
        """Run the memory analysis."""
        try:
            # Analyze the dumped memory
            self.dump_analyzer.analyze_and_export()

            # Load data into the analysis tab
            self.analysis_tab.load_data(
                entries=self.dump_analyzer.memory_analyzer.processed_entries,
                modules=self.db.fetch_all_modules()
            )

            self.status_label.set_text("Analysis completed successfully.")
            logger.info("Analysis results window opened successfully.")
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            messagebox.showerror("Analysis Error", f"An error occurred during analysis: {e}")
            self.status_label.set_text("Analysis failed.")
        finally:
            self.progress_bar.stop()