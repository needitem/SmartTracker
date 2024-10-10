import re
import struct
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

import psutil
from dump.utils.pointers import find_pointer, write_pointer
import pymem
from pymem import Pymem
from dump.memory.memory_entry import MemoryEntryProcessed

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntryProcessed:
    address: str
    offset: str
    raw: str
    string: Optional[str]
    integer: Optional[int]
    float_num: Optional[float]
    module: str
    timestamp: str
    process_id: int
    process_name: str
    permissions: str
    processed_string: Optional[str] = None
    is_valid: bool = False
    tags: Optional[List[str]] = None


class MemoryAnalyzer:
    def __init__(self):
        # Removed Database dependency
        pass

    def get_module_base_address(self, module_name: str) -> Optional[int]:
        """Retrieve the base address of a given module."""
        # Since Database is removed, implement alternative logic to retrieve module information
        # Example: Use psutil or pymem to get module info
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.name().lower() == module_name.lower():
                    pm = Pymem(proc.pid)
                    for module in pm.list_modules():
                        if module.name.decode().lower() == module_name.lower():
                            base_address = module.lpBaseOfDll
                            pm.close_process()
                            return base_address
                    pm.close_process()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(
                f"Cannot access process psutil.Process(pid={proc.pid}, name='{proc.name()}'): {e}"
            )
        return None

    def extract_values(
        self, raw_data: bytes
    ) -> Tuple[Optional[str], Optional[int], Optional[float]]:
        """Extract string, integer, and float values from raw data."""
        # Extract string: meaningful ASCII strings (4+ chars, no special chars)
        try:
            decoded_str = raw_data.decode("utf-8", errors="ignore")
            meaningful_strings = re.findall(r"\b[A-Za-z0-9]{4,}\b", decoded_str)
            string_val = ", ".join(meaningful_strings) if meaningful_strings else None
        except Exception as e:
            logger.error(f"Failed to decode string from raw data: {e}")
            string_val = None

        # Extract integer (signed 4 bytes)
        try:
            if len(raw_data) >= 4:
                int_val = struct.unpack("<i", raw_data[:4])[0]
            else:
                int_val = None
        except struct.error as e:
            logger.error(f"Failed to unpack integer: {e}")
            int_val = None

        # Extract float (4 bytes)
        try:
            if len(raw_data) >= 4:
                float_val = struct.unpack("<f", raw_data[:4])[0]
            else:
                float_val = None
        except struct.error as e:
            logger.error(f"Failed to unpack float: {e}")
            float_val = None

        return string_val, int_val, float_val

    def process_entry(
        self, entry: Dict[str, Any], proc: psutil.Process
    ) -> Optional[MemoryEntryProcessed]:
        """Process a single memory entry."""
        address_str = entry.get("address")
        if address_str and isinstance(address_str, str):
            try:
                address = int(address_str, 16)
            except ValueError:
                logger.error(
                    f"Invalid address format for entry ID {entry.get('id')}: {address_str}"
                )
                return None
        else:
            logger.warning(
                f"Address is missing or not a string for entry ID {entry.get('id')}. Skipping."
            )
            return None

        module = entry.get("module", "Unknown")
        base_address = self.get_module_base_address(module)
        if base_address is None:
            logger.warning(
                f"No base address found for module {module}. Skipping entry ID {entry.get('id')}."
            )
            return None

        offset = address - base_address
        if offset < 0:
            logger.warning(
                f"Negative offset calculated for entry ID {entry.get('id')}. Skipping."
            )
            return None

        raw_data = bytes.fromhex(entry.get("raw", ""))
        string_val, int_val, float_val = self.extract_values(raw_data)

        # Enhanced MemoryEntry with additional details
        memory_entry = MemoryEntryProcessed(
            address=address_str,
            offset=hex(offset),
            raw=entry.get("raw", ""),
            string=string_val,
            integer=int_val,
            float_num=float_val,
            module=module,
            timestamp=entry.get("timestamp", ""),
            process_id=entry.get("process_id", 0),
            process_name=entry.get("process_name", "Unknown"),
            permissions=entry.get("permissions", ""),
        )

        self.processed_entries.append(memory_entry)
        logger.debug(f"Processed memory entry: {memory_entry}")
        return memory_entry

    def parse_and_process_memory_regions(
        self, data_type: str = "All", pids: Optional[List[int]] = None
    ) -> List[MemoryEntryProcessed]:
        """Parse and process memory regions based on the specified data type and PIDs."""
        if pids:
            entries = self.db.fetch_memory_entries_by_pids(pids)
            logger.info(f"Processing memory entries for selected PIDs: {pids}")
        else:
            entries = self.db.fetch_all_memory_entries()
            logger.info("Processing all memory entries.")

        logger.info(f"Retrieved {len(entries)} memory entries for processing.")
        if not entries:
            logger.warning("No memory entries available for processing.")
            return []

        processed = []
        for entry in entries:
            try:
                proc = psutil.Process(entry["process_id"])
                memory_entry = self.process_entry(entry, proc)
                if memory_entry:
                    if data_type == "All" or self.filter_entry(memory_entry, data_type):
                        processed.append(memory_entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.error(f"Cannot access process PID={entry['process_id']}: {e}")
                continue
            except Exception as e:
                logger.error(
                    f"Unexpected error processing entry ID {entry.get('id')}: {e}"
                )
                continue
        logger.info(f"Processed {len(processed)} memory entries.")
        return processed

    def filter_entry(self, entry: MemoryEntryProcessed, data_type: str) -> bool:
        """Filter memory entries based on the specified data type."""
        if data_type == "Strings" and entry.string:
            return True
        if data_type == "Integers" and entry.integer is not None:
            return True
        if data_type == "Floats" and entry.float_num is not None:
            return True
        return False

    def get_all_processes(
        self, pids: Optional[List[int]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve all processes with their modules, optionally filtered by PIDs."""
        processes_info = []
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info["pid"]
            name = proc.info["name"]
            if pids and pid not in pids:
                continue
            try:
                modules = self.db.fetch_selected_modules_by_process(pid)
                processes_info.append({"pid": pid, "name": name, "modules": modules})
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.warning(
                    f"Cannot access process psutil.Process(pid={pid}, name='{name}'): {e}"
                )
        return processes_info

    def search_memory_entries(self, query: str) -> List[MemoryEntryProcessed]:
        """
        Search memory entries based on the query.
        This is a placeholder implementation.
        """
        results = []
        try:
            # Implement search logic using pymem
            # Example: Pattern scanning or specific value searches
            # For demonstration, returning an empty list
            logger.info(f"Searching memory entries for query: {query}")
        except Exception as e:
            logger.error(f"Error during memory search: {e}")
        return results

    def search_and_modify_pattern(
        self, pid: int, pattern: bytes, replacement: bytes
    ) -> int:
        """
        Search and replace specific byte patterns in the process memory.
        """
        count = 0
        try:
            pm = Pymem(pid)
            matches = pm.pattern_scan_all(pattern)
            for address in matches:
                pm.write_bytes(address, replacement)
                # Removed database logging
                count += 1
            pm.close_process()
            logger.info(f"pymem: Replaced {count} occurrences in PID={pid}.")
        except Exception as e:
            logger.error(
                f"pymem: Unexpected error during pattern search and replace (PID={pid}): {e}"
            )
        return count

    # ... existing code ...
