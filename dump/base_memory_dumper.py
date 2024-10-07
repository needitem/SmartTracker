from typing import List, Dict, Any, Optional
from dump.memory_entry import MemoryEntry

class MemoryDumper:
    """Base class for memory dumping implementations."""

    def get_process_modules(self, pid: int) -> List[Dict[str, Any]]:
        """Retrieve modules of a process."""
        raise NotImplementedError("This method should be implemented by subclasses.")

    def enumerate_memory_regions(self, pid: int) -> List[Dict[str, Any]]:
        """Enumerate memory regions of a process."""
        raise NotImplementedError("This method should be implemented by subclasses.")

    def read_memory(self, region: Dict[str, Any]) -> Optional[MemoryEntry]:
        """Read memory from a region."""
        raise NotImplementedError("This method should be implemented by subclasses.")

    def dump_memory(self, pid: int) -> Optional[MemoryEntry]:
        """Dump memory of a process."""
        raise NotImplementedError("This method should be implemented by subclasses.")