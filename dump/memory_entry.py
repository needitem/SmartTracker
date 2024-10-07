from dataclasses import dataclass
from typing import Optional


@dataclass
class MemoryEntry:
    address: str
    offset: str
    raw: str
    string: str
    integer: Optional[int]
    float_num: Optional[float]
