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
        # Implement alternative logic to retrieve module information using pymem
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.name().lower() == module_name.lower():
                    pm = Pymem(proc.pid)
                    for module in pm.list_modules():
                        if module.name.lower() == module_name.lower():
                            base_address = int(module.lpBaseOfDll)
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

        # Assuming process_entry() is meant to process and return the entry
        logger.debug(f"Processed memory entry: {memory_entry}")
        return memory_entry

    def parse_and_process_memory_regions(
        self, data_type: str = "All", pids: Optional[List[int]] = None
    ) -> List[Dict[str, Any]]:
        """Parse and process memory regions based on the specified data type and PIDs."""
        results = []
        try:
            if pids:
                processes_info = self.get_all_processes(pids)
            else:
                processes_info = self.get_all_processes()

            for proc_info in processes_info:
                pid = proc_info["pid"]
                name = proc_info["name"]
                modules = proc_info["modules"]

                for module in modules:
                    module_name = module["name"]
                    base_address = int(module["base_address"], 16)
                    size = module["size"]

                    try:
                        pm = Pymem(pid)
                        data = pm.read_bytes(base_address, size)
                        pm.close_process()

                        # Depending on data_type, call the appropriate search method
                        if data_type == "Integer":
                            int_matches = self.find_int_in_data(data, base_address)
                            for match in int_matches:
                                results.append({
                                    "address": match,
                                    "module": module_name,
                                    "data_type": "Integer"
                                })
                        elif data_type == "Float":
                            float_matches = self.find_float_in_data(data, base_address)
                            for match in float_matches:
                                results.append({
                                    "address": match,
                                    "module": module_name,
                                    "data_type": "Float"
                                })
                        elif data_type == "String":
                            string_matches = self.find_string_in_data(data, base_address)
                            for match in string_matches:
                                results.append({
                                    "address": match,
                                    "module": module_name,
                                    "data_type": "String"
                                })
                        else:  # "All"
                            int_matches = self.find_int_in_data(data, base_address)
                            float_matches = self.find_float_in_data(data, base_address)
                            string_matches = self.find_string_in_data(data, base_address)
                            for match in int_matches:
                                results.append({
                                    "address": match,
                                    "module": module_name,
                                    "data_type": "Integer"
                                })
                            for match in float_matches:
                                results.append({
                                    "address": match,
                                    "module": module_name,
                                    "data_type": "Float"
                                })
                            for match in string_matches:
                                results.append({
                                    "address": match,
                                    "module": module_name,
                                    "data_type": "String"
                                })
                    except Exception as e:
                        logger.error(f"Error processing module {module_name} in PID={pid}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error during memory region parsing: {e}")

        return results

    def find_int_in_data(self, data: bytes, base_address: int) -> List[int]:
        """Find all integer matches in the data."""
        # Placeholder: Implement integer search logic if needed
        # Currently, returns an empty list
        return []

    def find_float_in_data(self, data: bytes, base_address: int) -> List[int]:
        """Find all float matches in the data."""
        # Placeholder: Implement float search logic if needed
        # Currently, returns an empty list
        return []

    def find_string_in_data(self, data: bytes, base_address: int) -> List[int]:
        """Find all string matches in the data."""
        matches = []
        try:
            decoded_str = data.decode("utf-8", errors="ignore")
            # Find all substrings that are meaningful and long enough
            for match in re.finditer(r'\b\w{4,}\b', decoded_str):
                byte_pos = match.start()
                address = base_address + byte_pos
                matches.append(address)
        except Exception as e:
            logger.error(f"Error decoding string data: {e}")
        return matches

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
                modules = self.get_process_modules(pid)
                processes_info.append({"pid": pid, "name": name, "modules": modules})
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.warning(
                    f"Cannot access process psutil.Process(pid={pid}, name='{name}'): {e}"
                )
        return processes_info

    def search_memory_for_value(self, pid: int, value: int) -> List[int]:
        """
        Search the process memory for all instances of a specific integer value.

        Args:
            pid (int): Process ID to search within.
            value (int): The integer value to search for.

        Returns:
            List[int]: A list of addresses where the value is found.
        """
        matches = []
        try:
            pm = Pymem(pid)
            for module in pm.list_modules():
                base_addr = int(module.lpBaseOfDll)
                size = module.SizeOfImage
                logger.debug(f"Searching in module {module.name} at {hex(base_addr)} with size {size}")
                data = pm.read_bytes(base_addr, size)
                for offset in range(0, len(data) - 3, 4):
                    try:
                        current_value = struct.unpack("<i", data[offset:offset+4])[0]
                        if current_value == value:
                            found_address = base_addr + offset
                            matches.append(found_address)
                            logger.info(f"Value {value} found at address {hex(found_address)} in module {module.name}")
                    except struct.error as e:
                        logger.warning(f"Skipping invalid data at offset {offset}: {e}")
                        continue
            pm.close_process()
            logger.info(f"Found {len(matches)} occurrences of value {value} in PID={pid}.")
            return matches
        except Exception as e:
            logger.error(f"Error searching memory for value {value} in PID={pid}: {e}")
            return []

    def search_memory_for_float(self, pid: int, value: float) -> List[int]:
        """
        Search the process memory for all instances of a specific float value.

        Args:
            pid (int): Process ID to search within.
            value (float): The float value to search for.

        Returns:
            List[int]: A list of addresses where the value is found.
        """
        matches = []
        try:
            pm = Pymem(pid)
            target_bytes = struct.pack("<f", value)  # Little endian float
            for module in pm.list_modules():
                base_addr = int(module.lpBaseOfDll)
                size = module.SizeOfImage
                logger.debug(f"Searching in module {module.name} at {hex(base_addr)} with size {size}")
                data = pm.read_bytes(base_addr, size)
                pos = data.find(target_bytes)
                while pos != -1:
                    found_address = base_addr + pos
                    matches.append(found_address)
                    logger.info(f"Float value {value} found at address {hex(found_address)} in module {module.name}")
                    pos = data.find(target_bytes, pos + 1)
            pm.close_process()
            logger.info(f"Found {len(matches)} occurrences of float value {value} in PID={pid}.")
            return matches
        except Exception as e:
            logger.error(f"Error searching memory for float value {value} in PID={pid}: {e}")
            return []

    def search_memory_for_string(self, pid: int, value: str) -> List[int]:
        """
        Search the process memory for all instances of a specific string value.

        Args:
            pid (int): Process ID to search within.
            value (str): The string value to search for.

        Returns:
            List[int]: A list of addresses where the value is found.
        """
        matches = []
        try:
            pm = Pymem(pid)
            target_bytes = value.encode('utf-8')
            for module in pm.list_modules():
                base_addr = int(module.lpBaseOfDll)
                size = module.SizeOfImage
                logger.debug(f"Searching in module {module.name} at {hex(base_addr)} with size {size}")
                data = pm.read_bytes(base_addr, size)
                pos = data.find(target_bytes)
                while pos != -1:
                    found_address = base_addr + pos
                    matches.append(found_address)
                    logger.info(f"String value '{value}' found at address {hex(found_address)} in module {module.name}")
                    pos = data.find(target_bytes, pos + 1)
            pm.close_process()
            logger.info(f"Found {len(matches)} occurrences of string value '{value}' in PID={pid}.")
            return matches
        except Exception as e:
            logger.error(f"Error searching memory for string value '{value}' in PID={pid}: {e}")
            return []

    def search_memory_entries(self, query: str, data_type: str = "All") -> List[MemoryEntryProcessed]:
        """Search memory entries based on query and data type."""
        results = []
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.info['pid']
                name = proc.info['name']
                memory_entries = self.dumper.dump_module_memory(pid, name)
                for entry in memory_entries:
                    if data_type == "All" or (
                        (data_type == "Integer" and entry.integer is not None) or
                        (data_type == "Float" and entry.float_num is not None) or
                        (data_type == "String" and entry.string is not None)
                    ):
                        results.append(entry)
        except Exception as e:
            logger.error(f"Error during memory search: {e}")

        return results