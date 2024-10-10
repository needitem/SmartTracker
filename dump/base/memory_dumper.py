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

            # 메모리 덤프 로직 구현 (예시)
            data = pm.read_bytes(base_address, size)

            # 메모리 데이터를 처리하여 MemoryEntryProcessed 리스트로 변환
            entries = self.process_memory_dump(data, base_address, pid, module_name, bit_size, endian)
            pm.close_process()
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
        """덤프된 메모리 데이터를 처리하여 MemoryEntryProcessed 리스트로 변환합니다."""
        entries = []
        # 여기에서 메모리 데이터를 파싱하여 MemoryEntryProcessed 객체를 생성합니다.
        # 간단한 예시로 4바이트씩 읽어 정수값으로 저장
        for i in range(0, len(data), 4):
            try:
                raw = data[i:i+4]
                integer = int.from_bytes(raw, byteorder=endian, signed=True)
                entry = MemoryEntryProcessed(
                    address=hex(base_address + i),
                    offset=hex(i),
                    raw=raw.hex(),
                    string=None,
                    integer=integer,
                    float_num=None,
                    module=module_name,
                    timestamp="",
                    process_id=pid,
                    process_name="",  # 필요시 채워주세요
                    permissions="",    # 필요시 채워주세요
                    processed_string=None,
                    is_valid=False,
                    tags=None
                )
                entries.append(entry)
            except Exception as e:
                logger.error(f"Error processing memory at offset {i}: {e}")
        logger.debug(f"Processed {len(entries)} memory entries.")
        return entries

    def get_modules(self, pid: int) -> List[Dict[str, Any]]:
        """Alias for list_modules for backward compatibility."""
        return self.list_modules(pid)