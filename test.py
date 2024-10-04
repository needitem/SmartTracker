import os
import sys
import ctypes
from memory_dump import MemoryDumper, MemoryAnalyzer
from main import (
    read_memory_integer,
    get_module_base_addresses,
)  # main.py에 정의된 함수 임포트


def get_target_pid(process_name):
    """
    대상 프로세스의 PID를 반환합니다.
    Args:
        process_name (str): 프로세스 이름.
    Returns:
        int: 프로세스 PID, 찾지 못한 경우 None.
    """
    import psutil

    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info["name"] and process_name.lower() in proc.info["name"].lower():
            return proc.info["pid"]
    return None


def main():
    # 테스트할 프로세스 이름을 지정하세요
    process_name = "notepad++.exe"  # 예시: 메모장++ 프로세스
    pid = get_target_pid(process_name)

    if not pid:
        print(f"프로세스 '{process_name}'을(를) 찾을 수 없습니다.")
        sys.exit(1)

    print(f"선택된 프로세스 '{process_name}'의 PID: {pid}")

    # 메모리 덤프 생성
    dumper = MemoryDumper(pid)
    dump_path = dumper.dump_memory()
    print(f"메모리 덤프 파일 생성 완료: {dump_path}")

    # 메모리 덤프 분석
    analyzer = MemoryAnalyzer(dump_path)
    analyzer.analyze_memory()
    print("메모리 덤프 분석 완료.")

    # 첫 번째 모듈의 베이스 주소 가져오기
    module_bases = get_module_base_addresses(pid)
    if not module_bases:
        print("모듈의 베이스 주소를 가져오는데 실패했습니다.")
        sys.exit(1)

    base_address = module_bases[0]  # 첫 번째 모듈의 베이스 주소 사용
    offset = 0x00200028  # 예시 오프셋, 실제 사용 시 변경 필요
    target_address = base_address + offset
    print(f"선택된 모듈의 베이스 주소: {hex(base_address)}")
    print(f"오프셋: {hex(offset)}")
    print(f"계산된 타겟 주소: {hex(target_address)}")

    # 특정 주소가 덤프된 메모리 영역에 포함되는지 확인
    region = analyzer.find_memory_region_containing_address(target_address)
    if region:
        base, size, data = region
        print(
            f"주소 {hex(target_address)}는 메모리 영역 {hex(base)} - {hex(base + size)}에 포함됩니다."
        )
    else:
        print(f"주소 {hex(target_address)}는 덤프된 메모리 영역에 포함되지 않습니다.")
        dumped_value = "N/A"

    # memory_dump.py에서 덤프한 데이터에서 특정 주소의 값 가져오기
    if region:
        dumped_value = analyzer.get_integer_at_address(target_address, size=4)
        if dumped_value is not None:
            print(f"메모리 덤프에서 읽은 값: {dumped_value}")
        else:
            print(
                f"메모리 덤프에서 주소 {hex(target_address)}의 데이터를 찾을 수 없습니다."
            )
            dumped_value = "N/A"
    else:
        dumped_value = "N/A"

    # main.py를 사용하여 동일한 주소의 값 읽기
    main_value = read_memory_integer(pid, target_address, size=4)
    if main_value is not None:
        print(f"main.py에서 읽은 값: {main_value}")
    else:
        print(f"main.py에서 주소 {hex(target_address)}의 데이터를 읽지 못했습니다.")
        main_value = "N/A"

    # 결과 비교
    if dumped_value != "N/A" and main_value != "N/A":
        if dumped_value == main_value:
            print("✅ 두 스크립트의 결과가 일치합니다.")
        else:
            print("❌ 두 스크립트의 결과가 일치하지 않습니다.")
            print(f"memory_dump.py 값: {dumped_value}")
            print(f"main.py 값: {main_value}")
    else:
        print("⚠️ 일부 데이터가 누락되어 비교할 수 없습니다.")


if __name__ == "__main__":
    main()
