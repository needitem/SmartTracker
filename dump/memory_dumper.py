import ctypes
import psutil
import logging
import os
import re
import struct
from typing import List, Dict, Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor

from .database import Database
from .memory_entry import MemoryEntry
from .base_memory_dumper import MemoryDumper  # Updated import

from ctypes import wintypes

logger = logging.getLogger(__name__)

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ('lpBaseOfDll', ctypes.c_void_p),
        ('SizeOfImage', wintypes.DWORD),
        ('EntryPoint', ctypes.c_void_p),
    ]

class WindowsMemoryDumper(MemoryDumper):
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    def __init__(self, db: Database):
        self.db = db
        self.handle = None

    def get_process_modules(self, pid: int) -> List[Dict[str, Any]]:
        """Retrieve modules of a process using Windows API."""
        try:
            process = psutil.Process(pid)
            main_module = process.exe()
            logger.debug(f"Process executable path: {main_module}")

            # Define necessary Windows API structures and functions
            psapi = ctypes.WinDLL('Psapi.dll')
            kernel32 = ctypes.WinDLL('kernel32.dll')

            EnumProcessModules = psapi.EnumProcessModules
            EnumProcessModules.restype = wintypes.BOOL
            EnumProcessModules.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.HMODULE),
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD)
            ]

            GetModuleFileNameExW = psapi.GetModuleFileNameExW
            GetModuleFileNameExW.restype = wintypes.DWORD
            GetModuleFileNameExW.argtypes = [
                wintypes.HANDLE,
                wintypes.HMODULE,
                wintypes.LPWSTR,
                wintypes.DWORD
            ]

            GetModuleInformation = psapi.GetModuleInformation
            GetModuleInformation.restype = wintypes.BOOL
            GetModuleInformation.argtypes = [
                wintypes.HANDLE,
                wintypes.HMODULE,
                ctypes.POINTER(MODULEINFO),
                wintypes.DWORD
            ]

            # Open the process
            process_handle = kernel32.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
                False,
                pid
            )
            if not process_handle:
                error = ctypes.GetLastError()
                logger.error(f"Failed to open process {pid}. Error code: {error}")
                return []

            # Enumerate modules
            num_modules = 256
            module_handles = (wintypes.HMODULE * num_modules)()
            cb = wintypes.DWORD()
            if not EnumProcessModules(process_handle, module_handles, ctypes.sizeof(module_handles), ctypes.byref(cb)):
                logger.error(f"EnumProcessModules failed for PID={pid}. Error code: {ctypes.GetLastError()}")
                kernel32.CloseHandle(process_handle)
                return []

            module_info_list = []
            for i in range(int(cb.value / ctypes.sizeof(wintypes.HMODULE))):
                module_handle = module_handles[i]
                module_path_buffer = ctypes.create_unicode_buffer(260)
                if not GetModuleFileNameExW(process_handle, module_handle, module_path_buffer, 260):
                    logger.error(f"GetModuleFileNameExW failed for PID={pid}. Error code: {ctypes.GetLastError()}")
                    continue

                module_path = module_path_buffer.value

                module_info = MODULEINFO()
                if not GetModuleInformation(process_handle, module_handle, ctypes.byref(module_info), ctypes.sizeof(module_info)):
                    logger.error(f"GetModuleInformation failed for PID={pid}, Module={module_path}. Error code: {ctypes.GetLastError()}")
                    continue

                base_address = hex(module_info.lpBaseOfDll)
                size = module_info.SizeOfImage

                module_info_list.append({
                    'name': os.path.basename(module_path),
                    'exe_path': module_path,
                    'base_address': base_address,
                    'size': size
                })

            kernel32.CloseHandle(process_handle)
            logger.debug(f"Retrieved {len(module_info_list)} modules for PID={pid}.")
            return module_info_list

        except Exception as e:
            logger.error(f"Failed to get process modules for PID={pid}: {e}")
            return []

    def enumerate_memory_regions(self, pid: int) -> List[Dict[str, Any]]:
        """Enumerate readable memory regions of a process."""
        # Implement actual memory region enumeration using VirtualQueryEx
        # This is a placeholder and should be replaced with real implementation
        return [
            {
                'start': '0x10000000',
                'size': 4096,
                'base_address': '0x10000000'
            },
            # Add more regions as needed
        ]

    def get_module_name(self, base_address: str) -> str:
        """Retrieve the module name based on the base address."""
        try:
            region_address = int(base_address, 16)
            modules = self.db.fetch_all_modules()
            for module in modules:
                try:
                    mod_base = int(module['base_address'], 16)
                    if mod_base <= region_address < (mod_base + module['size']):
                        return module['name']
                except ValueError as e:
                    logger.error(f"Invalid base address format for module {module['name']}: {e}")
            return "Unknown"
        except ValueError as e:
            logger.error(f"Invalid base address format: {e}")
            return "Unknown"

    def extract_values(self, raw_data: bytes) -> tuple:
        """Extract string, integer, and float values from raw data."""
        # Extract string: meaningful ASCII strings (4+ chars, no special chars)
        try:
            decoded_str = raw_data.decode('utf-8', errors='ignore')
            meaningful_strings = re.findall(r'\b[A-Za-z0-9]{4,}\b', decoded_str)
            string_val = ', '.join(meaningful_strings) if meaningful_strings else None
        except Exception:
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

    def read_memory(self, region: Dict[str, Any]) -> Optional[MemoryEntry]:
        """Read memory from a specific region."""
        try:
            start_address = int(region['start'], 16)
            size = region['size']
            # Implement the actual memory reading logic here using ReadProcessMemory
            # For demonstration, we'll mock the raw data
            raw_data = b'\xDE\xAD\xBE\xEF' * (size // 4)  # Adjust size as needed

            string_val, int_val, float_val = self.extract_values(raw_data)
            module = self.get_module_name(region['base_address'])
            hex_address = hex(start_address)
            hex_offset = hex(start_address)  # Placeholder for actual offset calculation
            hex_raw = raw_data.hex()

            memory_entry = MemoryEntry(
                address=hex_address,
                offset=hex_offset,
                raw=hex_raw,
                string=string_val,
                integer=int_val,
                float_num=float_val,
                module=module
            )

            logger.debug(f"Parsed MemoryEntry: {memory_entry}")
            return memory_entry
        except Exception as e:
            logger.error(f"Failed to read memory region {region}: {e}")
            return None

    def dump_memory(self, pid: int) -> Optional[MemoryEntry]:
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            logger.info(f"Dumping memory for PID={pid}, Process={process_name}")

            # Insert module information
            modules = self.get_process_modules(pid)
            if not modules:
                logger.warning(f"No modules found for PID={pid}.")
            for module in modules:
                self.db.insert_module(
                    name=module['name'],
                    base_address=module['base_address'],
                    size=module['size'],
                    exe_path=module['exe_path']
                )

            # Enumerate memory regions
            memory_regions = self.enumerate_memory_regions(pid)
            logger.info(f"Found {len(memory_regions)} readable memory regions.")

            # Use ThreadPoolExecutor to read memory regions concurrently
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(self.read_memory, region) for region in memory_regions]
                for future in futures:
                    memory_entry = future.result()
                    if memory_entry:
                        self.db.insert_memory_entry(memory_entry)
                        logger.debug(f"Memory entry processed and inserted: {memory_entry}")

            return None  # Or appropriate return value based on your application's flow

        except Exception as e:
            logger.error(f"Failed to dump memory for PID={pid}: {e}")
            return None
        finally:
            if self.handle:
                ctypes.windll.kernel32.CloseHandle(self.handle)
            # Removed self.db.close()
            # logger.debug("Database connection closed in MemoryDumper.")

    def __del__(self):
        try:
            if self.handle:
                ctypes.windll.kernel32.CloseHandle(self.handle)
                logger.debug("Closed process handle in destructor.")
            # Removed self.db.close()
            # logger.debug("Database connection closed in destructor.")
        except Exception as e:
            logger.error(f"Error in destructor: {e}")