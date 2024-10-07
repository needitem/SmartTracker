import ctypes
import struct
import os
import logging
from abc import ABC, abstractmethod
import psutil
from typing import List, Dict, Optional

from dump.utils import is_process_64bit
from dump.database import Database

logger = logging.getLogger(__name__)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


MEM_COMMIT = 0x1000


class AbstractMemoryDumper(ABC):
    @abstractmethod
    def open_process(self):
        pass

    @abstractmethod
    def dump_memory(self):
        pass


class MemoryDumper(AbstractMemoryDumper):
    def __init__(self, pid: int, output_dir: str = "memory_dumps"):
        self.pid = pid
        self.output_dir = output_dir
        self.handle = None
        self.is_64bit = is_process_64bit(pid)
        self.modules = self.get_modules_info()

        # Define the database path within the output directory
        self.db_path = os.path.join(self.output_dir, "memory_analysis.db")
        self.db = Database(
            db_path=self.db_path
        )  # Initialize the database with the specified path

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logger.debug(f"Created output directory: {self.output_dir}")

        self.open_process()
        logger.debug(f"Initialized MemoryDumper for PID={self.pid}")

        # Insert modules into the database
        self.insert_modules()

    def open_process(self):
        """Open process handle."""
        PROCESS_ALL_ACCESS = 0x1F0FFF
        self.handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, False, self.pid
        )
        if not self.handle:
            error_code = ctypes.windll.kernel32.GetLastError()
            raise Exception(
                f"Failed to open process with PID {self.pid}. Error Code: {error_code}"
            )
        logger.debug(f"Successfully opened handle for PID={self.pid}")

    def get_modules_info(self) -> List[Dict[str, str]]:
        """Retrieve module information."""
        modules_info = []
        try:
            process = psutil.Process(self.pid)
            for m in process.memory_maps(grouped=False):
                path = m.path or "Unknown"
                rss = int(m.rss)
                try:
                    # Correctly parse the addr string to get the base address
                    base_address_str = m.addr.split("-")[0]
                    base_address = int(base_address_str, 16)
                    module_info = {
                        "Name": path,
                        "BaseAddress": hex(base_address),
                        "RSS": rss,
                    }
                    modules_info.append(module_info)
                    logger.debug(
                        f"Module: {path}, BaseAddress: {hex(base_address)}, RSS: {rss}"
                    )
                except (AttributeError, ValueError) as e:
                    logger.warning(f"Failed to parse address for module {path}: {e}")
            logger.info("Retrieved process module information.")
        except Exception as e:
            logger.error(
                f"Error retrieving modules for PID={self.pid}: {e}", exc_info=True
            )
        return modules_info

    def insert_modules(self):
        """Insert module information into the modules table."""
        if self.modules:
            self.db.bulk_insert_modules(self.modules)
            logger.info(f"Inserted {len(self.modules)} modules into the database.")
        else:
            logger.warning("No modules to insert into the database.")

    def get_memory_regions(self) -> List[tuple]:
        """Collect memory regions."""
        regions = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while address < 0x7FFFFFFFFFFFFFFF:
            result = ctypes.windll.kernel32.VirtualQueryEx(
                self.handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not result:
                break

            if mbi.State == MEM_COMMIT:
                regions.append((mbi.BaseAddress, mbi.RegionSize))
                logger.debug(
                    f"Committed memory region: BaseAddress={hex(mbi.BaseAddress)}, Size={mbi.RegionSize} bytes"
                )

            address += mbi.RegionSize
        logger.info(f"Total memory regions collected: {len(regions)}")
        return regions

    def dump_memory(self) -> str:
        """Perform memory dump."""
        try:
            logger.info("Starting memory dump process.")
            regions = self.get_memory_regions()
            logger.debug(f"Number of regions to dump: {len(regions)}")

            # Collect entries to insert into the database
            entries = []
            for base, size in regions:
                buffer = ctypes.create_string_buffer(size)
                bytes_read = ctypes.c_size_t(0)

                success = ctypes.windll.kernel32.ReadProcessMemory(
                    self.handle,
                    ctypes.c_void_p(base),
                    buffer,
                    size,
                    ctypes.byref(bytes_read),
                )

                if success and bytes_read.value > 0:
                    data = buffer.raw[: bytes_read.value]
                    entry = {
                        "Address": hex(base),
                        "Offset": hex(
                            base
                        ),  # Placeholder; actual offset calculation should be done in analyzer
                        "Raw": data.hex()[:2000],
                        "String": "",  # Placeholder
                        "Int": None,  # Placeholder
                        "Float": None,  # Placeholder
                        "Module": self.get_module_name(base),
                    }
                    entries.append(entry)
                    logger.debug(
                        f"Dumped memory region: Base={hex(base)}, Size={bytes_read.value} bytes"
                    )
                else:
                    error_code = ctypes.windll.kernel32.GetLastError()
                    logger.warning(
                        f"Failed to read memory at Base={hex(base)}, Size={size} bytes. Error Code={error_code}"
                    )
            # Bulk insert memory entries into the database
            self.db.bulk_insert_entries(entries)
            logger.info("Memory dump completed and data inserted into the database.")
            return self.db_path  # Return the database file path
        except Exception as e:
            logger.error(f"Error during memory dump: {e}", exc_info=True)
            raise e

    def get_module_name(self, address: int) -> str:
        """Retrieve the module name for a given address based on base addresses."""
        for module in self.modules:
            base_addr = int(module["BaseAddress"], 16)
            if address >= base_addr:
                return module["Name"]
        return "Unknown"

    def __del__(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            logger.debug(f"Closed handle for PID={self.pid}")
        self.db.close()
