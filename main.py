import tkinter as tk
from tkinter import ttk, messagebox
import logging
import sys

from dump.logging.logging_config import setup_logging  # 로깅 설정 함수 임포트
from dump.utils import admin  # 관리자 권한 함수 임포트
from dump.base.memory_dumper import MemoryDumper
from gui.process_selector.main_frame import ProcessSelector
from dump.analyzer.memory_analyzer import MemoryAnalyzer  # 올바른 임포트 경로 유지

logger = setup_logging(
    log_dir="logs", log_level=logging.DEBUG  # DEBUG 레벨로 변경하여 상세 로그 캡처
)  # log_level을 DEBUG로 설정

# 관리자 권한 확인 (필요 시 활성화)
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

        # Process Selector 탭 추가 (AnalysisTab 제거)
        process_selector = ProcessSelector(
            notebook,
            memory_dumper=self.memory_dumper,
            memory_analyzer=self.memory_analyzer,
        )
        notebook.add(process_selector, text="Select Process")

    def on_closing(self):
        self.destroy()


def main():
    try:
        admin.ensure_admin()  # 관리자 권한 확인 및 활성화
        app = Application()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
    except Exception as e:
        logger.exception("Unhandled exception occurred:")
        sys.exit(1)


if __name__ == "__main__":
    main()