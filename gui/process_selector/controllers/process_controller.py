import logging
from mem_edit import Process
from dump.base.memory_dumper import MemoryDumper  # MemoryDumper 임포트 추가

logger = logging.getLogger(__name__)


class ProcessController:
    def __init__(self, memory_dumper: MemoryDumper):
        self.memory_dumper = memory_dumper

    def dump_process_module(self, pid: int, module_name: str):
        """Initiate dumping memory for a specific process and module."""
        try:
            self.memory_dumper.dump_module_memory(pid, module_name)
            logger.info(f"Dumped memory for PID={pid}, Module={module_name}")
        except Exception as e:
            logger.error(
                f"Error dumping memory for PID={pid}, Module={module_name}: {e}"
            )
