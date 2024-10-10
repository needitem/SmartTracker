import logging
import psutil
from typing import Optional

logger = logging.getLogger(__name__)


def get_process_name(pid: int) -> Optional[str]:
    """Retrieve the name of a process by PID."""
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.error(f"Unable to retrieve process name for PID={pid}: {e}")
        return None


def get_base_address(pid: int) -> Optional[int]:
    """Retrieve the base address of the main module of a process."""
    try:
        process = psutil.Process(pid)
        modules = process.memory_maps()
        if modules:
            first_module = modules[0]
            if hasattr(first_module, "addr"):
                base_address = first_module.addr.split("-")[0]
            elif hasattr(first_module, "addr_start"):
                base_address = first_module.addr_start
            else:
                logger.error(
                    f"Memory map object does not have 'addr' or 'addr_start' attribute for PID={pid}."
                )
                return None
            try:
                return int(base_address, 16)
            except ValueError as ve:
                logger.error(
                    f"Invalid base address format for PID={pid}: {base_address}. Error: {ve}"
                )
                return None
        else:
            logger.warning(f"No modules found for PID={pid}.")
            return None
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.error(f"Access denied or process does not exist: PID={pid}, Error: {e}")
        return None
