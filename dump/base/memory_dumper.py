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
        # Initialize MemoryDumper
        pass

    def list_modules(self, pid: int) -> List[Dict[str, Any]]:
        """프로세스의 모든 모듈을 나열합니다."""
        try:
            pm = Pymem(pid)
            modules = []
            # for module in pm.iter_modules():  # 기존 코드: iter_modules 메서드 사용
            for module in pm.list_modules():  # 수정: list_modules로 변경
                modules.append({
                    "name": module.name,
                    "base_address": hex(module.lpBaseOfDll),
                    "size": module.SizeOfImage
                })
            pm.close_process()
            return modules
        except Exception as e:
            logger.error(f"Error listing modules for PID={pid}: {e}")
            return []

    def dump_module_memory(self, pid: int, module_name: str) -> List[MemoryEntryProcessed]:
        """특정 프로세스와 모듈의 메모리를 덤프합니다."""
        try:
            pm = Pymem(pid)
            pm_modules = self.list_modules(pid)
            module = next((m for m in pm_modules if m["name"] == module_name), None)
            if not module:
                raise KeyError(f"Module {module_name} not found in PID {pid}")
            base_address = int(module["base_address"], 16)
            size = module["size"]

            # 메모리 덤프 로직 구현
            data = pm.read_bytes(base_address, size)
            pm.close_process()

            # 예시: 메모리 덤프를 처리된 엔트리 리스트로 변환
            entries = self.process_memory_dump(data, base_address)
            return entries
        except (KeyError, Exception) as e:  # pymem.exception.PymemException 제거
            logger.error(f"Error dumping memory for PID={pid}, Module={module_name}: {e}")
            return []  # 에러 발생 시 빈 리스트 반환

    def get_process_modules(self, pid: int) -> List[Dict[str, Any]]:
        """프로세스의 모듈을 가져옵니다."""
        return self.list_modules(pid)

    def process_memory_dump(self, data: bytes, base_address: int) -> List[MemoryEntryProcessed]:
        """덤프된 메모리를 처리된 엔트리 리스트로 변환."""
        # 메모리 덤프 처리 로직 구현
        processed_entries = []
        # 예시 처리 (실제 로직에 맞게 수정 필요)
        return processed_entries