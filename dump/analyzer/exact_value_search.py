import struct
import logging
from typing import List
from pymem import Pymem

logger = logging.getLogger(__name__)

def find_addresses_by_value(pm: Pymem, module_name: str, value: int) -> List[int]:
    """
    특정 모듈 내에서 주어진 정수 값을 검색하여 주소 목록을 반환합니다.
    """
    addresses = []
    try:
        for module in pm.list_modules():
            if module.name.decode().lower() == module_name.lower():
                base_address = int(module.lpBaseOfDll)
                size = module.SizeOfImage
                data = pm.read_bytes(base_address, size)

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
    except Exception as e:
        logger.error(f"Error finding addresses by value: {e}")

    logger.info(f"Found {len(addresses)} addresses with value {value} in module {module_name}")
    return addresses