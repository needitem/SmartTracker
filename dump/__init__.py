# Initialize dump package
from .memory_analyzer import MemoryAnalyzer
from .memory_dumper import MemoryDumper
from .dump_analyzer import DumpAnalyzer
from .privilage import ensure_admin, is_admin
from .utils import get_base_address, is_process_64bit
