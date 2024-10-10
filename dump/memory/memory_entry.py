from dataclasses import dataclass
from typing import Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    address: str
    offset: str
    raw: str
    string: Optional[str]
    integer: Optional[int]
    float_num: Optional[float]
    module: str
    timestamp: str
    process_id: int
    process_name: str  # Added field
    permissions: str


@dataclass
class MemoryEntryProcessed(MemoryEntry):
    # Additional Fields
    processed_string: Optional[str] = None
    is_valid: bool = False
    tags: Optional[List[str]] = None

    # Methods
    def process_entry(self):
        """
        Process the raw memory data to populate additional fields.
        """
        self.process_string()
        self.validate_entry()
        self.tag_entry()

    def process_string(self):
        """
        Process the raw string data.
        """
        if self.string:
            # Example processing: convert to uppercase
            self.processed_string = self.string.upper()
        else:
            self.processed_string = None

    def validate_entry(self):
        """
        Validate the memory entry based on certain criteria.
        """
        # Example validation: Check if integer is positive
        if self.integer and self.integer > 0:
            self.is_valid = True
        else:
            self.is_valid = False

    def tag_entry(self):
        """
        Add tags based on processing results.
        """
        self.tags = []
        if self.is_valid:
            self.tags.append("valid")
        else:
            self.tags.append("invalid")

        if self.processed_string:
            self.tags.append("processed_string_present")
