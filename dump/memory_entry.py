# Added memory_entry.py

from dataclasses import dataclass
from typing import Optional

@dataclass
class MemoryEntry:
    address: str
    offset: str
    raw: str
    string: Optional[str] = None
    integer: Optional[int] = None
    float_num: Optional[float] = None
    module: Optional[str] = "Unknown"