import logging
from typing import List, Dict, Any, Optional, Tuple

from dump.database import Database
from dump.memory_entry import MemoryEntry

logger = logging.getLogger(__name__)

from dump.memory_dumper import WindowsMemoryDumper  # Ensure this is correct

class MemoryAnalyzer:
    def __init__(self, db: Database):
        self.db = db
        self.processed_entries: List[MemoryEntry] = []

    def get_module_base_address(self, module_name: str) -> Optional[int]:
        """Retrieve the base address of a given module."""
        modules = self.db.fetch_all_modules()
        for module in modules:
            if module['name'].lower() == module_name.lower():
                try:
                    return int(module['base_address'], 16)
                except ValueError:
                    logger.error(f"Invalid base address format for module {module_name}: {module['base_address']}")
        return None

    def extract_values(self, raw_data: bytes) -> Tuple[Optional[str], Optional[int], Optional[float]]:
        """Extract string, integer, and float values from raw data."""
        # Extract string: meaningful ASCII strings (4+ chars, no special chars)
        try:
            decoded_str = raw_data.decode('utf-8', errors='ignore')
            meaningful_strings = re.findall(r'\b[A-Za-z0-9]{4,}\b', decoded_str)
            string_val = ', '.join(meaningful_strings) if meaningful_strings else None
        except Exception as e:
            logger.error(f"Failed to decode string from raw data: {e}")
            string_val = None

        # Extract integer (signed 4 bytes)
        try:
            if len(raw_data) >= 4:
                int_val = struct.unpack('<i', raw_data[:4])[0]
            else:
                int_val = None
        except struct.error as e:
            logger.error(f"Failed to unpack integer: {e}")
            int_val = None

        # Extract float (4 bytes)
        try:
            if len(raw_data) >= 4:
                float_val = struct.unpack('<f', raw_data[:4])[0]
            else:
                float_val = None
        except struct.error as e:
            logger.error(f"Failed to unpack float: {e}")
            float_val = None

        return string_val, int_val, float_val

    def process_entry(self, entry: Dict[str, Any]) -> Optional[MemoryEntry]:
        entry_id = entry.get("id")
        address = int(entry["address"], 16) if entry["address"] else None
        module = entry.get("module", "Unknown")

        base_address = self.get_module_base_address(module)
        if base_address is None:
            logger.warning(f"No base address found for module {module}. Skipping entry ID {entry_id}.")
            return None

        if address is None:
            logger.warning(f"Address is None for entry ID {entry_id}. Skipping.")
            return None

        offset = address - base_address
        if offset < 0:
            logger.warning(f"Negative offset calculated for entry ID {entry_id}. Skipping.")
            return None

        raw_data = bytes.fromhex(entry.get("raw", ""))
        string_val, int_val, float_val = self.extract_values(raw_data)

        memory_entry = MemoryEntry(
            address=entry["address"],
            offset=hex(offset),
            raw=entry["raw"],
            string=string_val,
            integer=int_val,
            float_num=float_val,
            module=module,
        )

        self.processed_entries.append(memory_entry)
        logger.debug(f"Processed MemoryEntry: {memory_entry}")
        return memory_entry

    def parse_and_process_memory_regions(self, data_type: str = "All") -> List[MemoryEntry]:
        """Parse and process memory regions based on the specified data type."""
        entries = self.db.fetch_all_memory_entries()
        processed = []
        for entry in entries:
            memory_entry = self.process_entry(entry)
            if memory_entry:
                if data_type == "All" or self.filter_entry(memory_entry, data_type):
                    processed.append(memory_entry)
        return processed

    def filter_entry(self, entry: MemoryEntry, data_type: str) -> bool:
        """Filter memory entries based on the specified data type."""
        if data_type == "Strings" and entry.string:
            return True
        if data_type == "Integers" and entry.integer is not None:
            return True
        if data_type == "Floats" and entry.float_num is not None:
            return True
        return False