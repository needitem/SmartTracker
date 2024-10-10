import logging
from pymem import Pymem
from dump.base.memory_dumper import MemoryDumper

logger = logging.getLogger(__name__)


class ProcessController:
    def __init__(self, memory_dumper: MemoryDumper):
        self.memory_dumper = memory_dumper  # MemoryDumper 인스턴스 저장
        # self.database = database  # 기존의 database 참조 제거

    def dump_process_module(self, pid: int, module_name: str):
        """Initiate dumping memory for a specific process and module."""
        try:
            self.memory_dumper.dump_module_memory(pid, module_name)  # database 호출 제거
            logger.info(f"Dumped memory for PID={pid}, Module={module_name}")
        except Exception as e:
            logger.error(
                f"Error dumping memory for PID={pid}, Module={module_name}: {e}"
            )