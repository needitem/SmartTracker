import csv
import logging
from typing import List, Dict
import re
import sys
from tkinter import messagebox

from dump.memory_analyzer import MemoryAnalyzer
from dump.database import Database

logger = logging.getLogger(__name__)


class DumpAnalyzer:
    def __init__(
        self, database: Database, byte_unit: int = 4, endianness: str = "little"
    ):
        self.db = database
        self.memory_analyzer = MemoryAnalyzer(
            db=self.db, byte_unit=byte_unit, endianness=endianness
        )
        logger.info(
            f"Initialized DumpAnalyzer with byte unit: {byte_unit} bytes and endianness: {endianness}"
        )

    def analyze_and_export(self):
        """Perform memory dump analysis and export results to the database."""
        logger.info("Starting memory dump analysis and exporting to the database.")
        try:
            self.analyze_dump()
            logger.info("Memory analysis results inserted into the database.")
        except Exception as e:
            logger.error(f"Memory dump analysis failed: {e}", exc_info=True)
            # Raise exception to be handled by the GUI
            raise e

    def analyze_dump(self):
        """Perform memory dump analysis."""
        try:
            processed_entries = self.memory_analyzer.parse_and_process_memory_regions()
            logger.info(f"Analyzed {len(processed_entries)} memory entries.")
            self.db.bulk_insert_entries([entry.__dict__ for entry in processed_entries])
        except Exception as e:
            logger.error(f"Error during dump analysis: {e}", exc_info=True)
            raise e
        finally:
            self.db.close()

    def extract_filtered_entries(
        self, field: str, query: str, output_csv: str = "filtered_addresses_offsets.csv"
    ) -> List[Dict[str, str]]:
        """
        Extract addresses and offsets based on a search query and save to a new CSV.

        :param field: Field to search in (e.g., Address, Offset, etc.).
        :param query: Search query string.
        :param output_csv: Path to the output filtered CSV file.
        :return: List of filtered entries.
        """
        filtered_entries = []

        try:
            search_results = self.db.search_entries(field, query)
            if not search_results:
                logger.info(f"No entries found matching the query: {query}")
                return filtered_entries

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
                    ],
                )
                writer.writeheader()
                writer.writerows(search_results)
                filtered_entries.extend(search_results)
            logger.info(
                f"Filtered {len(filtered_entries)} entries based on the query '{query}'."
            )
        except Exception as e:
            logger.error(f"Error extracting filtered entries: {e}", exc_info=True)
            messagebox.showerror(
                "Extraction Error", f"Failed to extract filtered entries: {e}"
            )

        return filtered_entries
