import ctypes
import psutil
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_base_address(pid: int) -> Optional[int]:
    """Retrieve the base address of the main module of a process."""
    try:
        process = psutil.Process(pid)
        modules = process.memory_maps()
        if modules:
            base_address = modules[0].addr.split("-")[0]
            return int(base_address, 16)
        else:
            logger.warning(f"No modules found for PID={pid}.")
            return None
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.error(f"Access denied or process does not exist: PID={pid}, Error: {e}")
        return None


def is_process_64bit(pid: int) -> bool:
    """Determine if a process is 64-bit."""
    try:
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if not handle:
            logger.error(f"Unable to open process with PID={pid}.")
            return False

        is_wow64 = ctypes.c_long()
        result = ctypes.windll.kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
        ctypes.windll.kernel32.CloseHandle(handle)
        if result:
            return not is_wow64.value
        else:
            logger.error(f"IsWow64Process failed for PID={pid}.")
            return False
    except Exception as e:
        logger.error(f"Error determining process architecture: PID={pid}, Error: {e}")
        return False
