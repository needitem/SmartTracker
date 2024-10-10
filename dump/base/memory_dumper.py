import ctypes
from ctypes import Structure, c_void_p, POINTER
from ctypes import wintypes
import psutil
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

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def GetModuleInformation(
    hProcess: int,
    hModule: int,
    lpmodinfo: POINTER(MEMORY_BASIC_INFORMATION),
    cb: int,
) -> bool:
    return psapi.GetModuleInformation(hProcess, hModule, lpmodinfo, cb)

class MemoryDumper:
    def __init__(self):
        # Initialize MemoryDumper
        pass

    def list_modules(self, pid: int) -> List[Dict[str, Any]]:
        """프로세스의 모든 모듈을 나열합니다."""
        try:
            pm = Pymem(pid)
            modules = []
            for module in pm.list_modules():
                modules.append({
                    "name": module.name.decode('utf-8', errors='ignore') if isinstance(module.name, bytes) else module.name,
                    "base_address": hex(module.lpBaseOfDll),
                    "size": module.SizeOfImage
                })
            pm.close_process()
            logger.debug(f"Modules for PID={pid}: {modules}")
            return modules
        except AttributeError as e:
            logger.error(f"Pymem 객체에 'list_modules' 속성이 없습니다: {e}")
            return []
        except Exception as e:
            logger.error(f"Error listing modules for PID={pid}: {e}")
            return []

    def dump_module_memory(self, pid: int, module_name: str, bit_size: int = 32, endian: str = "little") -> List[MemoryEntryProcessed]:
        """특정 프로세스와 모듈의 메모리를 덤프합니다."""
        try:
            pm = Pymem(pid)
            pm_modules = self.list_modules(pid)
            module = next((m for m in pm_modules if m["name"].lower() == module_name.lower()), None)
            if not module:
                raise KeyError(f"Module {module_name} not found in PID {pid}")
            base_address = int(module["base_address"], 16)
            size = module["size"]

            # 메모리 덤프 로직 구현
            data = pm.read_bytes(base_address, size)
            pm.close_process()

            # 메모리 데이터를 처리하여 MemoryEntryProcessed 리스트로 변환
            entries = self.process_memory_dump(data, base_address, pid, module_name, bit_size, endian)
            return entries
        except (KeyError, Exception) as e:
            logger.error(f"Error dumping memory for PID={pid}, Module={module_name}: {e}")
            return []

    def get_handle(self, pid: int) -> int:
        """프로세스 핸들을 가져옵니다."""
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            logger.error(f"Failed to open process PID={pid} for memory querying.")
        return handle

    def get_memory_protection(self, handle: int, address: int) -> int:
        """Windows 메모리 영역의 보호 플래그를 가져옵니다."""
        mbi = MEMORY_BASIC_INFORMATION()
        result = ctypes.windll.kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        )
        if result:
            return mbi.Protect
        else:
            logger.error(f"Failed to retrieve memory protection for address {hex(address)}.")
            return 0

    def process_memory_dump(self, data: bytes, base_address: int, pid: int, module_name: str, bit_size: int, endian: str) -> List[MemoryEntryProcessed]:
        """덤프된 메모리를 처리된 엔트리 리스트로 변환."""
        processed_entries = []
        try:
            chunk_size = bit_size // 8
            endian_format = '<' if endian == "little" else '>'
            handle = self.get_handle(pid)
            for offset in range(0, len(data), chunk_size):
                chunk = data[offset:offset + chunk_size]
                if len(chunk) < chunk_size:
                    continue

                # Initialize default fields
                string_val = None
                integer_val = None
                float_val = None

                # Extract Integer
                try:
                    if bit_size == 8:
                        integer_val = struct.unpack(endian_format + 'B', chunk)[0]
                    elif bit_size == 16:
                        integer_val = struct.unpack(endian_format + 'H', chunk)[0]
                    elif bit_size == 32:
                        integer_val = struct.unpack(endian_format + 'I', chunk)[0]
                    elif bit_size == 64:
                        integer_val = struct.unpack(endian_format + 'Q', chunk)[0]
                    else:
                        integer_val = struct.unpack(endian_format + 'I', chunk)[0]
                except struct.error:
                    integer_val = None

                # Extract String
                try:
                    decoded_str = chunk.decode('utf-8', errors='ignore').strip()
                    if decoded_str:
                        string_val = decoded_str
                except:
                    string_val = None

                # Extract Float (if applicable)
                try:
                    if bit_size == 32:
                        float_val = struct.unpack(endian_format + 'f', chunk)[0]
                    elif bit_size == 64:
                        float_val = struct.unpack(endian_format + 'd', chunk)[0]
                except struct.error:
                    float_val = None

                # Retrieve Permissions
                if handle:
                    protect_flags = self.get_memory_protection(handle, base_address + offset)
                else:
                    protect_flags = 0  # 기본값 설정
                permissions = get_permissions(protect=protect_flags)

                # Create MemoryEntryProcessed
                memory_entry = MemoryEntryProcessed(
                    address=hex(base_address + offset),
                    offset=hex(offset),
                    raw=chunk.hex(),
                    string=string_val,
                    integer=integer_val,
                    float_num=float_val,
                    module=module_name,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    process_id=pid,
                    process_name=get_process_name(pid) or "Unknown",
                    permissions=permissions,
                    processed_string=string_val.upper() if string_val else "",
                    is_valid=bool(integer_val) if integer_val is not None else False,
                    tags=["valid"] if bool(integer_val) else ["invalid"],
                )
                processed_entries.append(memory_entry)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception as e:
            logger.error(f"Error processing memory dump: {e}")
        return processed_entries

    def get_modules(self, pid: int) -> List[Dict[str, Any]]:
        """Alias for list_modules for backward compatibility."""
        return self.list_modules(pid)