from typing import List, Optional
import logging
from pymem import Pymem

logger = logging.getLogger(__name__)


def find_pointer(pm: Pymem, base_address: int, offsets: List[int]) -> Optional[int]:
    """
    포인터를 찾아 해당 주소를 반환합니다.
    """
    try:
        address = base_address
        for offset in offsets:
            value = pm.read_int(address)
            address = value + offset
        return address
    except Exception as e:
        logger.error(f"포인터를 찾는 도중 오류 발생: {e}")
        return None


def write_pointer(pm: Pymem, address: int, data: int) -> bool:
    """
    지정된 포인터에 데이터를 씁니다.
    """
    try:
        pm.write_int(address, data)
        logger.debug(f"포인터 {hex(address)}에 데이터 {data} 작성 완료.")
        return True
    except Exception as e:
        logger.error(f"포인터에 데이터를 쓰는 도중 오류 발생: {e}")
        return False


def offset_finder(pm: Pymem, base_address: int, target_address: int) -> Optional[int]:
    """
    베이스 주소와 타겟 주소 사이의 오프셋을 찾습니다.

    Args:
        pm (Pymem): Pymem 인스턴스.
    """
    pass
