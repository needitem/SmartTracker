import tkinter as tk
from tkinter import ttk, messagebox
import logging
import sys

from dump.logging.logging_config import setup_logging  # 로깅 설정 함수 임포트
from dump.utils import admin  # 관리자 권한 함수 임포트
from dump.base.memory_dumper import MemoryDumper
from gui.process_selector.main_frame import ProcessSelector
from gui.analysis_tab import AnalysisTab
from gui.memory_analyzer import MemoryAnalyzer

# 로깅 설정 먼저 수행
logger = setup_logging(
    log_dir="logs", log_level=logging.WARNING
)  # log_level을 WARNING으로 설정

# 애플리케이션이 관리자 권한으로 실행 중인지 확인 - 일반 사용자권한으로도 작동하는거 확인
# admin.ensure_admin()

# 로깅을 사용하여 관리자 권한 확인 결과 로그 기록
logger.info("Application is running with administrator privileges.")


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Memory Analyzer")
        self.geometry("800x600")

        # Initialize MemoryDumper
        self.memory_dumper = MemoryDumper()  # Removed db parameter

        # Initialize MemoryAnalyzer
        self.memory_analyzer = MemoryAnalyzer()

        # 노트북 생성
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Initialize AnalysisTab and add to notebook
        self.analysis_tab = AnalysisTab(notebook, self.memory_analyzer)
        notebook.add(self.analysis_tab, text="Analysis")

        # Process Selector 탭 추가 (memory_dumper, memory_analyzer, analysis_tab 전달)
        process_selector = ProcessSelector(
            notebook,
            memory_dumper=self.memory_dumper,
            memory_analyzer=self.memory_analyzer,
            analysis_tab=self.analysis_tab,
        )
        notebook.add(process_selector, text="Select Process")

    def on_closing(self):
        self.destroy()


def main():
    try:
        app = Application()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
    except Exception as e:
        logger.exception("처리되지 않은 예외 발생:")
        sys.exit(1)


if __name__ == "__main__":
    main()
