# Modified dump/dump_analyzer.py

import csv
import logging
from typing import List, Dict, Optional

from dump.memory_analyzer import MemoryAnalyzer
from dump.database import Database
from dump.memory_entry import MemoryEntry

logger = logging.getLogger(__name__)


class DumpAnalyzer:
    def __init__(self, database: Database):
        self.db = database
        self.memory_analyzer = MemoryAnalyzer(db=self.db)
        logger.info("DumpAnalyzer initialized.")

    def analyze_and_export(self, data_type: str = "All", output_csv: str = "filtered_addresses_offsets.csv"):
        """Analyze the memory dump and export filtered results."""
        try:
            processed_entries = self.memory_analyzer.parse_and_process_memory_regions(data_type=data_type)
            self.export_to_csv(processed_entries, output_csv)
            logger.info(f"Analysis and export completed. {len(processed_entries)} entries exported to {output_csv}.")
        except Exception as e:
            logger.error(f"Error during analyze_and_export: {e}")
            raise e

    def analyze_dump(self, data_type: str = "All") -> List[Dict[str, str]]:
        """Analyze the memory dump."""
        try:
            return self.memory_analyzer.parse_and_process_memory_regions(data_type=data_type)
        except Exception as e:
            logger.error(f"Error during analyze_dump: {e}")
            raise e

    def export_to_csv(self, entries: List[MemoryEntry], output_csv: str):
        """Export analyzed memory entries to a CSV file."""
        try:
            with open(output_csv, mode="w", newline="", encoding="utf-8") as outfile:
                writer = csv.DictWriter(
                    outfile,
                    fieldnames=[
                        "Address",
                        "Offset",
                        "Raw",
                        "String",
                        "Int",
                        "Float",
                        "Module",
                    ],
                )
                writer.writeheader()
                for entry in entries:
                    writer.writerow({
                        "Address": entry.address,
                        "Offset": entry.offset,
                        "Raw": entry.raw,
                        "String": entry.string,
                        "Int": entry.integer if entry.integer is not None else "",
                        "Float": entry.float_num if entry.float_num is not None else "",
                        "Module": entry.module,
                    })
            logger.debug(f"Exported {len(entries)} entries to CSV file at {output_csv}.")
        except Exception as e:
            logger.error(f"Failed to export entries to CSV: {e}")
            raise e

    def search_memory(self, field: str, query: str) -> List[MemoryEntry]:
        """Search memory entries based on field and query value."""
        return self.memory_analyzer.search_memory(field, query)