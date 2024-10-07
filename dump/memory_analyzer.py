import struct
import logging
from typing import List, Dict, Optional, Tuple

from dump.memory_entry import MemoryEntry
from dump.database import Database

logger = logging.getLogger(__name__)


class MemoryAnalyzer:
    def __init__(self, db: Database, byte_unit: int = 4, endianness: str = "little"):
        self.db = db
        self.byte_unit = byte_unit
        self.endianness = endianness.lower()
        self.modules = self.db.fetch_all_modules()
        logger.info(
            f"MemoryAnalyzer initialized with byte_unit={self.byte_unit} and endianness={self.endianness}"
        )

    def parse_and_process_memory_regions(self) -> List[MemoryEntry]:
        """Parse and process memory regions based on the selected byte unit and endianness."""
        processed_entries = []
        entries = self.db.fetch_all_entries()

        for entry in entries:
            entry_id = entry.get("id")
            address = int(entry["address"], 16) if entry["address"] else None
            module = entry.get("module", "Unknown")

            base_address = self.get_module_base_address(module)
            if base_address is None:
                logger.warning(
                    f"No base address found for module {module}. Skipping entry ID {entry_id}."
                )
                continue

            if address is None:
                logger.warning(f"Address is None for entry ID {entry_id}. Skipping.")
                continue

            offset = address - base_address
            if offset < 0:
                logger.warning(
                    f"Negative offset calculated for entry ID {entry_id}. Skipping."
                )
                continue

            raw_data = entry.get("raw", "")
            string_val, int_val, float_val = self._extract_values(raw_data)

            processed_entry = MemoryEntry(
                address=hex(address),
                offset=hex(offset),
                raw=raw_data,
                string=string_val,
                integer=int_val,
                float_num=float_val,
            )
            processed_entries.append(processed_entry)

            # Update the database with the new offset and extracted values
            update_fields = {
                "Offset": hex(offset),
                "String": string_val,
                "Integer": int_val,
                "Float_num": float_val,
            }
            if entry_id:
                self.db.update_entry(entry_id, update_fields)

        return processed_entries

    def _extract_values(
        self, raw_data: str
    ) -> Tuple[str, Optional[int], Optional[float]]:
        """
        Extract string, integer, and float values from raw memory data based on byte unit and endianness.

        :param raw_data: Raw memory data as a hexadecimal string.
        :return: Tuple containing the extracted string, integer, and float values.
        """
        string_val = ""
        int_val = None
        float_val = None

        try:
            bytes_data = bytes.fromhex(raw_data)

            # Attempt to decode as UTF-8 string
            try:
                string_val = bytes_data.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                logger.debug("Failed to decode raw data as UTF-8 string.")

            # Determine byte order based on endianness
            if self.endianness == "little":
                byte_order = "little"
                struct_format_prefix = "<"  # Little endian
            elif self.endianness == "big":
                byte_order = "big"
                struct_format_prefix = ">"  # Big endian
            else:
                logger.warning(
                    f"Unsupported endianness '{self.endianness}'. Defaulting to little endian."
                )
                byte_order = "little"
                struct_format_prefix = "<"

            # Attempt to extract integer (based on byte_unit)
            if len(bytes_data) >= self.byte_unit:
                int_val = int.from_bytes(
                    bytes_data[: self.byte_unit], byteorder=byte_order, signed=True
                )

            # Attempt to extract float (IEEE 754, based on byte_unit)
            if self.byte_unit == 4 and len(bytes_data) >= 4:
                float_val = struct.unpack(f"{struct_format_prefix}f", bytes_data[:4])[0]
            elif self.byte_unit == 8 and len(bytes_data) >= 8:
                float_val = struct.unpack(f"{struct_format_prefix}d", bytes_data[:8])[0]
            elif self.byte_unit > 8:
                logger.debug(
                    f"Float extraction not supported for byte unit: {self.byte_unit}"
                )

        except ValueError as ve:
            logger.error(f"Value error during extraction: {ve}")
        except Exception as ex:
            logger.error(f"Unexpected error during extraction: {ex}")

        return string_val, int_val, float_val

    def get_module_base_address(self, module_name: str) -> Optional[int]:
        """Retrieve the base address of a module."""
        for module in self.modules:
            if module["name"] == module_name:
                try:
                    return int(module["base_address"], 16)
                except ValueError:
                    logger.error(
                        f"Invalid base address format for module {module_name}: {module['base_address']}"
                    )
                    return None
        logger.warning(f"Module {module_name} not found in the modules table.")
        return None
