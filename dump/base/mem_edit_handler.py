import logging
from pymem import Pymem  # Replaced mem_edit with pymem
from typing import Optional

logger = logging.getLogger(__name__)


class MemEditHandler:
    """Handles interactions with pymem for memory operations."""

    @staticmethod
    def open_process(pid: int) -> Optional[Pymem]:
        """Open a process using pymem."""
        try:
            pm = Pymem(pid)
            logger.debug(f"Opened process PID={pid} using pymem.")
            return pm
        except Exception as e:
            logger.error(f"Failed to open process PID={pid} with pymem. Error: {e}")
            return None

    @staticmethod
    def read_memory(pm: Pymem, address: int, size: int) -> Optional[bytes]:
        """Read memory from a process."""
        try:
            data = pm.read_bytes(address, size)
            logger.debug(f"Read {len(data)} bytes from address {hex(address)}.")
            return data
        except Exception as e:
            logger.error(f"Failed to read memory at address {hex(address)}. Error: {e}")
            return None

    @staticmethod
    def write_memory(pm: Pymem, address: int, data: bytes) -> bool:
        """Write data to a specific memory address in the process."""
        try:
            pm.write_bytes(address, data)
            logger.debug(f"Written data to address {hex(address)}.")
            return True
        except Exception as e:
            logger.error(
                f"Failed to write memory at address {hex(address)}. Error: {e}"
            )
            return False
