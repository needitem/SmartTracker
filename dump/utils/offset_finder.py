import logging
from typing import List, Optional
from pymem import Pymem
from pymem.pattern import scan_pattern

logger = logging.getLogger(__name__)


def find_pointer(pm: Pymem, base_address: int, offsets: List[int]) -> Optional[int]:
    """
    Finds the final address by traversing through the pointer chain.

    Args:
        pm (Pymem): Pymem instance.
        base_address (int): The base address to start from.
        offsets (List[int]): List of offsets to traverse.

    Returns:
        Optional[int]: The final address after applying all offsets, or None if failed.
    """
    try:
        address = base_address
        for offset in offsets:
            value = pm.read_uint(address)
            address = value + offset
            logger.debug(f"Traversed to address: {hex(address)}")
        return address
    except Exception as e:
        logger.error(f"Error finding pointer: {e}")
        return None


def pattern_scan(pm: Pymem, pattern: bytes, start: Optional[int] = None, end: Optional[int] = None) -> List[int]:
    """
    Scans the memory for a specific byte pattern.

    Args:
        pm (Pymem): Pymem instance.
        pattern (bytes): The byte pattern to search for.
        start (Optional[int]): Start address for scanning.
        end (Optional[int]): End address for scanning.

    Returns:
        List[int]: List of addresses where the pattern is found.
    """
    try:
        matches = scan_pattern(pm.process_handle, pattern, start, end)
        logger.debug(f"Found {len(matches)} matches for pattern.")
        return matches
    except Exception as e:
        logger.error(f"Error during pattern scan: {e}")
        return None