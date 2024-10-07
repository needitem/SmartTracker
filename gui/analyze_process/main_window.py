# gui/analyze_process/main_window.py
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

        # Create Analysis Results Tab with the Database instance
        self.analysis_tab = AnalysisTab(self.notebook, self.db)
        self.notebook.add(self.analysis_tab, text="분석 결과")

        # Create Search Tab
        self.search_tab = SearchTab(self.notebook, self.dump_analyzer)
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
        """Run the memory analysis in a separate thread."""
        try:
            self.dump_analyzer.analyze_and_export()
            processed_count = len(self.dump_analyzer.memory_analyzer.processed_entries)
            modules = self.db.fetch_all_modules()
            self.after(
                0,
                self.on_analysis_complete,
                processed_count,
                self.dump_analyzer.memory_analyzer.processed_entries,
                modules,
            )
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            self.after(0, self.on_analysis_error, str(e))
        finally:
            self.after(0, self.progress_bar.stop)

    def on_analysis_complete(self, count, entries, modules):
        """Handle the completion of the analysis."""
        self.status_label.config(text=f"Analysis complete. {count} entries processed.")
        messagebox.showinfo("Analysis Complete", f"{count} entries have been analyzed.")
        self.analysis_tab.load_data(entries, modules)

    def on_analysis_error(self, error_message):
        """Handle errors that occur during analysis."""
        self.status_label.config(text="Analysis failed.")
        messagebox.showerror(
            "Analysis Error", f"Failed to analyze memory dump: {error_message}"
        )
