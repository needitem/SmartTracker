import ctypes
import sys
from ctypes import wintypes

# Define necessary constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


def read_memory_integer(pid, address, size=4):
    """
    특정 프로세스의 메모리 주소에서 정수 값을 읽어옵니다.
    Args:
        pid (int): 대상 프로세스의 PID.
        address (int): 읽을 메모리 주소 (절대 주소).
        size (int): 읽을 바이트 수 (기본값은 4).
    Returns:
        int: 읽은 정수 값, 실패 시 None.
    """
    PROCESS_ACCESS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not handle:
        print(f"프로세스 {pid} 열기에 실패했습니다. 오류 코드: {ctypes.GetLastError()}")
        return None

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    success = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)
    )

    ctypes.windll.kernel32.CloseHandle(handle)

    if success and bytes_read.value == size:
        raw_data = buffer.raw[: bytes_read.value]
        integer_value = int.from_bytes(raw_data, byteorder="little")
        return integer_value
    elif success:
        print(f"{hex(address)}에서 요청한 바이트 수보다 적은 데이터를 읽었습니다.")
        return None
    else:
        print(
            f"{hex(address)}에서 메모리 읽기에 실패했습니다. 오류 코드: {ctypes.GetLastError()}"
        )
        return None


def get_module_base_addresses(pid):
    """
    지정된 PID의 프로세스에서 로드된 모든 모듈의 베이스 주소를 반환합니다.
    Args:
        pid (int): 대상 프로세스의 PID.
    Returns:
        list: 모듈의 베이스 주소 리스트.
    """
    psapi = ctypes.WinDLL("Psapi.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")

    # Define necessary types and functions
    EnumProcessModulesEx = psapi.EnumProcessModulesEx
    EnumProcessModulesEx.restype = wintypes.BOOL
    EnumProcessModulesEx.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]

    OpenProcess = kernel32.OpenProcess
    OpenProcess.restype = wintypes.HANDLE
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    CloseHandle = kernel32.CloseHandle
    CloseHandle.restype = wintypes.BOOL
    CloseHandle.argtypes = [wintypes.HANDLE]

    # Constants for EnumProcessModulesEx
    LIST_MODULES_ALL = 0x03

    # Open the target process
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        print(f"OpenProcess 실패. 오류 코드: {ctypes.GetLastError()}")
        return []

    try:
        # Allocate space for module handles
        module_count = 1024
        array_type = ctypes.c_void_p * module_count
        modules = array_type()
        needed = wintypes.DWORD()

        if not EnumProcessModulesEx(
            handle,
            modules,
            ctypes.sizeof(modules),
            ctypes.byref(needed),
            LIST_MODULES_ALL,
        ):
            print(f"EnumProcessModulesEx 실패. 오류 코드: {ctypes.GetLastError()}")
            return []

        # Calculate the number of modules returned
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        module_bases = []

        for i in range(count):
            hmodule = modules[i]
            # 올바른 포인터 타입으로 캐스팅
            base_address = ctypes.cast(hmodule, ctypes.c_void_p).value
            module_bases.append(base_address)

        return module_bases

    finally:
        CloseHandle(handle)


def get_module_base_addresses_via_pe_struct(pid):
    """
    (옵션) 필요한 경우, PE 헤더를 통해 보다 정확한 베이스 주소를 얻을 수 있습니다.
    """
    pass  # 추후 구현 가능


def get_user_input(prompt, convert_func, error_message):
    """
    사용자로부터 입력을 받고, 변환 및 유효성 검사를 수행합니다.
    Args:
        prompt (str): 사용자에게 표시할 메시지.
        convert_func (function): 입력 문자열을 변환할 함수.
        error_message (str): 변환 실패 시 표시할 메시지.
    Returns:
        변환된 값.
    """
    while True:
        user_input = input(prompt)
        try:
            return convert_func(user_input)
        except ValueError:
            print(error_message)


def main():
    """
    메인 함수: 사용자로부터 PID와 오프셋을 입력받아 메모리에서 값을 읽어옵니다.
    """
    print("=== 메모리 읽기 프로그램 ===")

    # 사용자로부터 PID 입력 받기
    pid = get_user_input(
        "대상 프로세스의 PID를 입력하세요: ",
        lambda x: int(x),
        "유효한 정수를 입력하세요.",
    )

    # 사용자로부터 오프셋 입력 받기
    offset = get_user_input(
        "오프셋을 입력하세요 (16진수는 '0x' 접두어 사용): ",
        lambda x: int(x, 16) if x.lower().startswith("0x") else int(x),
        "유효한 오프셋을 입력하세요.",
    )

    print(f"\n입력된 PID: {pid}")
    print(f"입력된 오프셋: {hex(offset) if isinstance(offset, int) else offset}")

    # 모듈 베이스 주소 가져오기
    module_bases = get_module_base_addresses(pid)
    if not module_bases:
        print("모듈의 베이스 주소를 가져오는데 실패했습니다.")
        sys.exit(1)

    base_address = module_bases[0]  # 첫 번째 모듈의 베이스 주소 사용
    target_address = base_address + offset
    print(f"선택된 모듈의 베이스 주소: {hex(base_address)}")
    print(f"계산된 타겟 주소: {hex(target_address)}\n")

    # 메모리 주소에서 정수 값 읽기
    value = read_memory_integer(pid, target_address, size=4)
    if value is not None:
        print(f"주소 {hex(target_address)}의 정수 값: {value}")
    else:
        print(f"주소 {hex(target_address)}에서 값을 읽을 수 없습니다.")


if __name__ == "__main__":
    main()
