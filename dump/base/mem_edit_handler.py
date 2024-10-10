import logging
from mem_edit import Process
from typing import Optional

logger = logging.getLogger(__name__)


class MemEditHandler:
    """Handles interactions with mem_edit for memory operations."""

    @staticmethod
    def open_process(pid: int) -> Optional[Process]:
        """Open a process using mem_edit."""
        try:
            process = Process.open_process(pid)
            logger.debug(f"Opened process PID={pid} using mem_edit.")
            return process
        except Exception as e:
            logger.error(f"Failed to open process PID={pid} with mem_edit. Error: {e}")
            return None

    @staticmethod
    def read_memory(p: Process, address: int, size: int) -> Optional[bytes]:
        """Read memory from a process."""
        try:
            data = p.read_memory(address, size)
            logger.debug(f"Read {len(data)} bytes from address {hex(address)}.")
            return data
        except Exception as e:
            logger.error(f"Failed to read memory at address {hex(address)}. Error: {e}")
            return None

    @staticmethod
    def write_memory(p: Process, address: int, data: bytes) -> bool:
        """Write data to a specific memory address in the process."""
        try:
            p.write_memory(address, data)
            logger.debug(f"Written data to address {hex(address)}.")
            return True
        except Exception as e:
            logger.error(
                f"Failed to write memory at address {hex(address)}. Error: {e}"
            )
            return False
