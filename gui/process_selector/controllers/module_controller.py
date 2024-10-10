import logging
from typing import List, Dict, Any
from dump.base.memory_dumper import MemoryDumper

logger = logging.getLogger(__name__)


class ModuleController:
    def __init__(self, memory_dumper: MemoryDumper):
        self.memory_dumper = memory_dumper  # MemoryDumper 인스턴스 저장

    def fetch_modules_by_pid(self, pid: int) -> List[Dict[str, Any]]:
        """Fetch modules associated with the given PID using MemoryDumper."""
        try:
            modules = self.memory_dumper.list_modules(pid)
            logger.info(f"Fetched {len(modules)} modules for PID={pid}")
            return modules
        except Exception as e:
            logger.error(f"Error fetching modules for PID={pid}: {e}")
            return []
