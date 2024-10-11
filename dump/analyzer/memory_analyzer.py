import re
import struct
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import psutil
import pymem
from pymem import Pymem
from dump.utils.pointers import find_pointer, write_pointer
from dump.memory.memory_entry import MemoryEntryProcessed
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntryProcessed:
    address: str
    offset: str
    raw: str
    string: Optional[str]
    integer: Optional[int]
    float_num: Optional[float]
    module: str
    timestamp: str
    process_id: int
    process_name: str
    permissions: str
    processed_string: Optional[str] = None
    is_valid: bool = False
    tags: Optional[List[str]] = None


class MemoryAnalyzer:
    def __init__(self):
        pass

    # 기존 메서드들...

    def search_memory_entries(self, value: Any, data_type: str = "All") -> List[MemoryEntryProcessed]:
        """Search memory entries based on value and data type."""
        results = []
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.info['pid']
                name = proc.info['name']
                memory_entries = self.dumper.dump_module_memory(pid, name)
                for entry in memory_entries:
                    if data_type == "All" or (
                        (data_type == "Integer" and entry.integer == value) or
                        (data_type == "Float" and entry.float_num == value) or
                        (data_type == "String" and entry.string == value)
                    ):
                        results.append(entry)
        except Exception as e:
            logger.error(f"Error during memory search: {e}")

        logger.info(f"Search for value '{value}' of type '{data_type}' found {len(results)} entries.")
        return results

    def find_addresses_by_value(self, pm: Pymem, module_name: str, value: Any) -> List[int]:
        """
        특정 모듈 내에서 주어진 값을 검색하여 주소 목록을 반환합니다.

        Args:
            pm (Pymem): Pymem 인스턴스.
            module_name (str): 검색할 모듈 이름.
            value (Any): 검색할 값 (int, float, str).

        Returns:
            List[int]: 값을 찾은 주소 목록.
        """
        addresses = []
        try:
            for module in pm.list_modules():
                if module.name.decode().lower() == module_name.lower():
                    base_address = int(module.lpBaseOfDll)
                    size = module.SizeOfImage
                    data = pm.read_bytes(base_address, size)

                    if isinstance(value, int):
                        fmt = "<i"  # 리틀 엔디언 정수
                        byte_size = struct.calcsize(fmt)
                        for i in range(0, len(data) - byte_size + 1, byte_size):
                            try:
                                current_val = struct.unpack(fmt, data[i:i+byte_size])[0]
                                if current_val == value:
                                    found_address = base_address + i
                                    addresses.append(found_address)
                            except struct.error:
                                continue

                    elif isinstance(value, float):
                        fmt = "<f"  # 리틀 엔디언 부동소수점
                        byte_size = struct.calcsize(fmt)
                        for i in range(0, len(data) - byte_size + 1, byte_size):
                            try:
                                current_val = struct.unpack(fmt, data[i:i+byte_size])[0]
                                if current_val == value:
                                    found_address = base_address + i
                                    addresses.append(found_address)
                            except struct.error:
                                continue

                    elif isinstance(value, str):
                        encoded_str = value.encode('utf-8')
                        str_len = len(encoded_str)
                        pattern = re.escape(value)
                        for match in re.finditer(pattern, data.decode('utf-8', 'ignore')):
                            found_address = base_address + match.start()
                            addresses.append(found_address)

        except Exception as e:
            logger.error(f"Error finding addresses by value: {e}")

        logger.info(f"Found {len(addresses)} addresses with value {value} in module {module_name}")
        return addresses

    def byte_pattern_search(self, pm: Pymem, module_name: str, pattern: bytes) -> List[int]:
        """
        바이트 패턴을 검색하여 주소 목록을 반환합니다.

        Args:
            pm (Pymem): Pymem 인스턴스.
            module_name (str): 검색할 모듈 이름.
            pattern (bytes): 검색할 바이트 패턴.

        Returns:
            List[int]: 패턴이 발견된 주소 목록.
        """
        addresses = []
        try:
            for module in pm.list_modules():
                if module.name.decode().lower() == module_name.lower():
                    base_address = int(module.lpBaseOfDll)
                    size = module.SizeOfImage
                    data = pm.read_bytes(base_address, size)

                    pos = data.find(pattern)
                    while pos != -1:
                        found_address = base_address + pos
                        addresses.append(found_address)
                        pos = data.find(pattern, pos + 1)

        except Exception as e:
            logger.error(f"Error during byte pattern search: {e}")

        logger.info(f"Found {len(addresses)} addresses with pattern {pattern} in module {module_name}")
        return addresses

    def pointer_chain_scan(self, pm: Pymem, base_address: int, offsets: List[int]) -> Optional[int]:
        """
        포인터 체인을 따라가며 최종 주소를 반환합니다.

        Args:
            pm (Pymem): Pymem 인스턴스.
            base_address (int): 시작 포인터 주소.
            offsets (List[int]): 오프셋 리스트.

        Returns:
            Optional[int]: 최종 주소 또는 None.
        """
        try:
            address = base_address
            for offset in offsets:
                value = pm.read_uint(address)
                address = value + offset
            return address
        except Exception as e:
            logger.error(f"Error during pointer chain scan: {e}")
            return None

    def signature_based_scan(self, pm: Pymem, module_name: str, signature: List[str]) -> List[int]:
        """
        시그니처(어셈블리 명령어)를 기반으로 패턴을 검색합니다.

        Args:
            pm (Pymem): Pymem 인스턴스.
            module_name (str): 검색할 모듈 이름.
            signature (List[str]): 어셈블리 명령어 리스트 (시그니처).

        Returns:
            List[int]: 시그니처가 발견된 주소 목록.
        """
        addresses = []
        try:
            # 시그니처를 바이트 패턴으로 변환
            md = Cs(CS_ARCH_X86, CS_MODE_64)  # 프로세스 아키텍처에 맞게 조정
            byte_pattern = b''.join([instr.encode('utf-8') for instr in signature])
            
            for module in pm.list_modules():
                if module.name.decode().lower() == module_name.lower():
                    base_address = int(module.lpBaseOfDll)
                    size = module.SizeOfImage
                    data = pm.read_bytes(base_address, size)

                    pos = data.find(byte_pattern)
                    while pos != -1:
                        found_address = base_address + pos
                        addresses.append(found_address)
                        pos = data.find(byte_pattern, pos + 1)

        except Exception as e:
            logger.error(f"Error during signature-based scan: {e}")

        logger.info(f"Found {len(addresses)} addresses with signature {signature} in module {module_name}")
        return addresses

    def change_comparison_scan(self, old_dump: Dict[int, bytes], new_dump: Dict[int, bytes]) -> List[int]:
        """
        메모리 덤프를 비교하여 변경된 주소를 찾습니다.

        Args:
            old_dump (Dict[int, bytes]): 이전 메모리 덤프 (주소: 데이터).
            new_dump (Dict[int, bytes]): 새로운 메모리 덤프 (주소: 데이터).

        Returns:
            List[int]: 변경된 주소 목록.
        """
        changed_addresses = []
        try:
            for addr, old_data in old_dump.items():
                new_data = new_dump.get(addr)
                if new_data and old_data != new_data:
                    changed_addresses.append(addr)
        except Exception as e:
            logger.error(f"Error during change comparison scan: {e}")

        logger.info(f"Found {len(changed_addresses)} changed addresses.")
        return changed_addresses