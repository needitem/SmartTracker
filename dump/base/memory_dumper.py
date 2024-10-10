import ctypes
from ctypes import Structure, c_void_p, POINTER
from ctypes import wintypes
import psutil  # psutil 임포트 유지
import logging
import os
import re
import struct
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from dump.utils.helpers import get_process_name, get_base_address
from dump.utils.permissions import get_permissions
from dump.utils.admin import ensure_admin

import pymem
from pymem import Pymem

from dump.memory.memory_entry import MemoryEntryProcessed

logger = logging.getLogger(__name__)

# Windows API 함수 선언
psapi = ctypes.WinDLL("Psapi.dll")
kernel32 = ctypes.WinDLL("kernel32.dll")


class MODULEINFO_STRUCT(Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


def GetModuleInformation(
    hProcess: int,
    hModule: int,
    lpmodinfo: POINTER(MODULEINFO_STRUCT),
    cb: int,
) -> bool:
    return psapi.GetModuleInformation(hProcess, hModule, lpmodinfo, cb)


class MemoryDumper:
    def __init__(self):
        # Removed database parameter
        pass

    def list_modules(self) -> List[Dict[str, Any]]:
        """List all modules of a process."""
        modules_info = []
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                pid = proc.info["pid"]
                try:
                    # Open process with necessary access
                    handle = kernel32.OpenProcess(0x10 | 0x0200 | 0x0400, False, pid)
                    if not handle:
                        logger.error(f"Failed to open process PID={pid}")
                        continue

                    try:
                        module_count = psapi.EnumProcessModules(handle, None, 0)
                        module_array = (wintypes.HMODULE * module_count)()
                        if not psapi.EnumProcessModules(
                            handle,
                            module_array,
                            ctypes.sizeof(module_array),
                            ctypes.byref(ctypes.c_ulong()),
                        ):
                            logger.error(f"EnumProcessModules failed for PID={pid}")
                            continue

                        for module in module_array:
                            module_name = psapi.GetModuleBaseNameA(handle, module)
                            if not module_name:
                                module_name = "Unknown"

                            mod_info = MODULEINFO_STRUCT()
                            if not GetModuleInformation(
                                handle,
                                module,
                                ctypes.byref(mod_info),
                                ctypes.sizeof(mod_info),
                            ):
                                logger.error(
                                    f"GetModuleInformation failed for module {module_name} in PID={pid}."
                                )
                                continue

                            module_info = {
                                "name": os.path.basename(module_name.decode()),
                                "base_address": hex(mod_info.lpBaseOfDll),
                                "size": mod_info.SizeOfImage,
                                "exe_path": module_name.decode(),
                                "protect": get_permissions(mod_info.AllocationProtect),
                            }
                            modules_info.append(module_info)
                            logger.debug(f"Retrieved module info: {module_info}.")

                    finally:
                        kernel32.CloseHandle(handle)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.error(f"Cannot access process PID={pid}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Unexpected error retrieving process modules: {e}")

        return modules_info

    def dump_module_memory(
        self, pid: int, module_name: str
    ) -> List[MemoryEntryProcessed]:
        """Dump memory from a specific module of a process."""
        dumped_entries = []
        try:
            pm = Pymem(pid)
            base_address = self.get_module_base_address(pm, module_name)
            if not base_address:
                logger.error(f"Module {module_name} not found in PID={pid}.")
                return dumped_entries

            module = pm.list_modules()[module_name]
            size = module.size
            memory = pm.read_bytes(base_address, size)

            # Process memory data
            for i in range(0, len(memory), 16):
                raw_data = memory[i : i + 16]
                string_val, int_val, float_val = self.extract_values(raw_data)
                entry = MemoryEntryProcessed(
                    address=hex(base_address + i),
                    offset=hex(i),
                    raw=raw_data.hex(),
                    string=string_val,
                    integer=int_val,
                    float_num=float_val,
                    module=module_name,
                    timestamp=datetime.now().isoformat(),
                    process_id=pid,
                    process_name=get_process_name(pid),
                    permissions=get_permissions(module.protect),
                )
                entry.process_entry()
                dumped_entries.append(entry)
                logger.debug(f"Dumped entry: {entry}")

            logger.info(
                f"Successfully dumped memory for PID={pid}, Module={module_name}."
            )
        except Exception as e:
            logger.error(
                f"Error dumping memory for PID={pid}, Module={module_name}: {e}"
            )
        finally:
            pm.close_process()

        return dumped_entries

    def get_module_base_address(self, pm: Pymem, module_name: str) -> Optional[int]:
        """Retrieve the base address of a given module."""
        try:
            modules = pm.list_modules()
            module = modules.get(module_name, None)
            if module:
                return module.lpBaseOfDll
            else:
                return None
        except Exception as e:
            logger.error(f"Error retrieving base address for module {module_name}: {e}")
            return None

    def extract_values(
        self, raw_data: bytes
    ) -> Tuple[Optional[str], Optional[int], Optional[float]]:
        """Extract string, integer, and float values from raw data."""
        # Extract string: meaningful ASCII strings (4+ chars, no special chars)
        try:
            decoded_str = raw_data.decode("utf-8", errors="ignore")
            meaningful_strings = re.findall(r"\b[A-Za-z0-9]{4,}\b", decoded_str)
            string_val = ", ".join(meaningful_strings) if meaningful_strings else None
        except Exception as e:
            logger.error(f"Failed to decode string from raw data: {e}")
            string_val = None

        # Extract integer (signed 4 bytes)
        try:
            if len(raw_data) >= 4:
                int_val = struct.unpack("<i", raw_data[:4])[0]
            else:
                int_val = None
        except struct.error as e:
            logger.error(f"Failed to unpack integer: {e}")
            int_val = None

        # Extract float (4 bytes)
        try:
            if len(raw_data) >= 4:
                float_val = struct.unpack("<f", raw_data[:4])[0]
            else:
                float_val = None
        except struct.error as e:
            logger.error(f"Failed to unpack float: {e}")
            float_val = None

        return string_val, int_val, float_val
