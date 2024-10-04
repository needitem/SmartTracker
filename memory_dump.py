import psutil
import sys
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import ctypes
import ctypes.wintypes as wintypes
import struct
import string
import re
import pickle
import platform

# Constants for Windows API
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_QUERY_INFORMATION = 0x0400  # 추가된 상수
PROCESS_VM_READ = 0x0010  # 추가된 상수
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def is_process_64bit(pid):
    """
    지정된 PID의 프로세스가 64비트인지 확인합니다.
    Args:
        pid (int): 프로세스 PID.
    Returns:
        bool: 64비트 프로세스이면 True, 아니면 False.
    """
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not handle:
        raise ctypes.WinError()

    is_wow64 = ctypes.c_long()
    if not ctypes.windll.kernel32.IsWow64Process(handle, ctypes.byref(is_wow64)):
        ctypes.windll.kernel32.CloseHandle(handle)
        raise ctypes.WinError()

    ctypes.windll.kernel32.CloseHandle(handle)
    return not is_wow64.value


# 사용 예시:
# is_64bit = is_process_64bit(pid)


class MemoryDumper:
    def __init__(self, pid, output_dir="memory_dumps"):
        self.pid = pid
        self.output_dir = output_dir
        self.handle = None
        self.is_64bit = is_process_64bit(pid)  # 아키텍처 감지

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        self.open_process()

    def open_process(self):
        # 수정된 접근 권한 사용
        self.handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid
        )
        if not self.handle:
            raise ctypes.WinError()

    def close_process(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def get_memory_regions(self):
        regions = []
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        max_address = (
            0x7FFFFFFFFFFF if self.is_64bit else 0x7FFFFFFF
        )  # 64비트 또는 32비트 주소 공간 최대값

        while address < max_address:
            result = ctypes.windll.kernel32.VirtualQueryEx(
                self.handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not result:
                break

            # 모든 커밋된 메모리 영역을 덤프 대상으로 추가
            if mbi.State == MEM_COMMIT:
                regions.append((mbi.BaseAddress, mbi.RegionSize))

            address += mbi.RegionSize
        return regions

    def dump_memory(self):
        try:
            regions = self.get_memory_regions()
            filename = f"memory_dump_pid_{self.pid}.bin"
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, "wb") as f:
                for base, size in regions:
                    buffer = ctypes.create_string_buffer(size)
                    bytes_read = ctypes.c_size_t(0)
                    if ctypes.windll.kernel32.ReadProcessMemory(
                        self.handle,
                        ctypes.c_void_p(base),
                        buffer,
                        size,
                        ctypes.byref(bytes_read),
                    ):
                        # 베이스 주소와 리전 크기를 아키텍처에 맞게 패킹
                        if self.is_64bit:
                            f.write(struct.pack("<Q", base))  # 8바이트
                            f.write(struct.pack("<Q", bytes_read.value))  # 8바이트
                        else:
                            f.write(struct.pack("<I", base))  # 4바이트
                            f.write(struct.pack("<I", bytes_read.value))  # 4바이트
                        f.write(buffer.raw[: bytes_read.value])
            return filepath
        except Exception as e:
            raise e
        finally:
            self.close_process()


class MemoryAnalyzer:
    def __init__(self, dump_path):
        self.dump_path = dump_path
        self.cache_path = self.dump_path + ".cache"
        self.strings = []
        self.numbers = []
        self.memory_regions = []  # 메모리 영역 정보를 저장
        self.is_64bit = self.detect_architecture()
        self.load_cache()

    def detect_architecture(self):
        """
        덤프 파일명에서 PID를 추출하고, 해당 프로세스의 아키텍처를 확인합니다.
        Returns:
            bool: 64비트이면 True, 아니면 False.
        """
        try:
            pid = int(re.search(r"memory_dump_pid_(\d+)\.bin", self.dump_path).group(1))
            return is_process_64bit(pid)
        except:
            # 기본값 64비트
            return True

    def find_memory_region_containing_address(self, target_address):
        """
        특정 주소가 포함된 메모리 영역을 찾습니다.
        Args:
            target_address (int): 확인할 메모리 주소.
        Returns:
            tuple: (base_address, size, data) 해당 메모리 영역의 정보, 없으면 None.
        """
        for base, data in self.memory_regions:
            if base <= target_address < base + len(data):
                return (base, len(data), data)
        return None

    def load_cache(self):
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, "rb") as cache_file:
                    data = pickle.load(cache_file)
                    self.strings = data.get("strings", [])
                    self.numbers = data.get("numbers", [])
                print("Loaded analysis data from cache.")
            except Exception as e:
                print(f"Failed to load cache: {e}")
        else:
            print("No cache found. Performing analysis.")
            self.analyze_memory()
            self.save_cache()

    def save_cache(self):
        data = {"strings": self.strings, "numbers": self.numbers}
        try:
            with open(self.cache_path, "wb") as cache_file:
                pickle.dump(data, cache_file)
            print("Analysis data cached successfully.")
        except Exception as e:
            print(f"Failed to save cache: {e}")

    def analyze_memory(self):
        try:
            with open(self.dump_path, "rb") as f:
                while True:
                    if self.is_64bit:
                        base_bytes = f.read(8)
                        size_bytes = f.read(8)
                        fmt = "<Q"
                        pointer_size = 8
                    else:
                        base_bytes = f.read(4)
                        size_bytes = f.read(4)
                        fmt = "<I"
                        pointer_size = 4

                    if len(base_bytes) < pointer_size or len(size_bytes) < pointer_size:
                        break

                    base_address = struct.unpack(fmt, base_bytes)[0]
                    region_size = struct.unpack(fmt, size_bytes)[0]

                    data = f.read(region_size)
                    if len(data) < region_size:
                        break

                    self.memory_regions.append((base_address, data))

                    self.strings.extend(self.search_strings(data))
                    self.numbers.extend(self.search_numbers(data))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze memory dump: {e}")

    def search_strings(self, data, min_length=4):
        # Use regex to find printable ASCII strings
        pattern = rb"[ -~]{%d,}" % min_length
        return [
            (m.start(), m.group().decode("ascii")) for m in re.finditer(pattern, data)
        ]

    def search_numbers(self, data):
        numbers = []
        for i in range(0, len(data) - 3, 4):
            chunk = data[i : i + 4]
            if len(chunk) < 4:
                continue
            integer = struct.unpack("<I", chunk)[0]
            float_num = struct.unpack("<f", chunk)[0]
            # Simple range checks to filter meaningful numbers
            if -1e6 < float_num < 1e6:
                numbers.append((i, float_num, "Float"))
            if 0 < integer < 0xFFFFFFFF:
                numbers.append((i, integer, "Integer"))
        return numbers

    def search_specific_number(self, number):
        """
        Searches for a specific integer or float in the memory dump.
        Returns a list of tuples containing (offset, value, type).
        """
        results = []
        # Ensure data is loaded
        if not self.strings and not self.numbers:
            self.analyze_memory()

        for offset, value, val_type in self.numbers:
            if val_type == "Integer" and value == number:
                results.append((offset, value, val_type))
            elif val_type == "Float" and value == number:
                results.append((offset, value, val_type))
        return results

    def get_data_at_address(self, target_address, size=4):
        """
        특정 주소에서 데이터를 조회합니다.
        Args:
            target_address (int): 조회할 메모리 주소.
            size (int): 읽을 바이트 수 (기본값은 4).
        Returns:
            bytes: 해당 주소의 데이터, 없으면 None.
        """
        for base, data in self.memory_regions:
            if base <= target_address < base + len(data):
                offset = target_address - base
                if offset + size <= len(data):
                    return data[offset : offset + size]
        return None

    # MemoryAnalyzer 클래스 내에 특정 오프셋의 원시 데이터 출력 기능 추가
    def print_raw_data_at_offset(self, offset, size=4):
        try:
            data = self.get_data_at_address(offset, size)
            if data:
                print(f"Raw Data at {hex(offset)}: {data.hex().upper()}")
            else:
                print(f"No data found at offset {hex(offset)}.")
        except Exception as e:
            print(f"Error: {e}")

    def get_integer_at_address(self, target_address, size=4):
        """
        특정 주소에서 데이터를 정수로 조회합니다.
        Args:
            target_address (int): 조회할 메모리 주소.
            size (int): 읽을 바이트 수 (기본값은 4).
        Returns:
            int: 해당 주소의 정수 값, 없으면 None.
        """
        data = self.get_data_at_address(target_address, size)
        if data:
            return int.from_bytes(data[:size], byteorder="little")
        return None

    def print_integer_at_address(self, target_address, size=4):
        value = self.get_integer_at_address(target_address, size)
        if value is not None:
            print(f"Integer Value at {hex(target_address)}: {value}")
            return value
        print(f"No data found at address {hex(target_address)}.")
        return None


class DumpAnalyzer:
    def __init__(self, dump_path):
        self.dump_path = dump_path
        self.analyzer = MemoryAnalyzer(dump_path)

    def analyze(self):
        self.create_analysis_window()

    def create_analysis_window(self):
        self.window = tk.Toplevel()
        self.window.title("Memory Dump Analysis")
        self.window.geometry("900x600")

        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Strings Tab
        self.strings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.strings_tab, text="Strings")
        self.populate_strings()

        # Numbers Tab
        self.numbers_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.numbers_tab, text="Numbers")
        self.populate_numbers()

        # Search Tab
        self.search_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.search_tab, text="Search")
        self.setup_search()

    def populate_strings(self):
        strings = self.analyzer.strings
        # Create Treeview with Scrollbars
        tree_frame = ttk.Frame(self.strings_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        strings_tree = ttk.Treeview(
            tree_frame, columns=("Offset", "String"), show="headings"
        )
        strings_tree.heading("Offset", text="Offset (Hex)")
        strings_tree.heading("String", text="String")
        strings_tree.column("Offset", width=150, anchor="center")
        strings_tree.column("String", width=700, anchor="w")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=strings_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=strings_tree.xview)
        strings_tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        strings_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind right-click for copy
        self.add_copy_context_menu(strings_tree)

        for offset, string_found in strings:
            strings_tree.insert("", tk.END, values=(f"{offset:08X}", string_found))

        label = ttk.Label(self.strings_tab, text=f"Total Strings Found: {len(strings)}")
        label.pack(pady=5)

    def populate_numbers(self):
        numbers = self.analyzer.numbers
        # Create Treeview with Scrollbars
        tree_frame = ttk.Frame(self.numbers_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        numbers_tree = ttk.Treeview(
            tree_frame, columns=("Offset", "Value", "Type"), show="headings"
        )
        numbers_tree.heading("Offset", text="Offset (Hex)")
        numbers_tree.heading("Value", text="Value")
        numbers_tree.heading("Type", text="Type")
        numbers_tree.column("Offset", width=150, anchor="center")
        numbers_tree.column("Value", width=300, anchor="center")
        numbers_tree.column("Type", width=100, anchor="center")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=numbers_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=numbers_tree.xview)
        numbers_tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        numbers_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind right-click for copy
        self.add_copy_context_menu(numbers_tree)

        for offset, value, val_type in numbers:
            numbers_tree.insert("", tk.END, values=(f"{offset:08X}", value, val_type))

        label = ttk.Label(self.numbers_tab, text=f"Total Numbers Found: {len(numbers)}")
        label.pack(pady=5)

    def setup_search(self):
        # Create search input fields
        search_frame = ttk.Frame(self.search_tab)
        search_frame.pack(pady=10, padx=10, anchor="nw")

        # Search Type
        ttk.Label(search_frame, text="Search Type:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.search_type_var = tk.StringVar()
        search_type_combo = ttk.Combobox(
            search_frame,
            textvariable=self.search_type_var,
            values=["String", "Hex Pattern", "Number", "Address Value"],
            state="readonly",
        )
        search_type_combo.current(0)
        search_type_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Search Pattern or Number
        ttk.Label(search_frame, text="Search Pattern/Number:").grid(
            row=1, column=0, padx=5, pady=5, sticky="e"
        )
        self.search_input_var = tk.StringVar()
        search_entry = ttk.Entry(
            search_frame, textvariable=self.search_input_var, width=50
        )
        search_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Search Button
        search_button = ttk.Button(
            search_frame, text="Search", command=self.perform_search
        )
        search_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Search Results Treeview with Scrollbars
        results_frame = ttk.Frame(self.search_tab)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.search_results_tree = ttk.Treeview(
            results_frame, columns=("Offset", "Value"), show="headings"
        )
        self.search_results_tree.heading("Offset", text="Offset (Hex)")
        self.search_results_tree.heading("Value", text="Value")
        self.search_results_tree.column("Offset", width=150, anchor="center")
        self.search_results_tree.column("Value", width=750, anchor="w")

        vsb = ttk.Scrollbar(
            results_frame, orient="vertical", command=self.search_results_tree.yview
        )
        hsb = ttk.Scrollbar(
            results_frame, orient="horizontal", command=self.search_results_tree.xview
        )
        self.search_results_tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.search_results_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        # Bind right-click for copy
        self.add_copy_context_menu(self.search_results_tree)

    def perform_search(self):
        search_type = self.search_type_var.get()
        search_input = self.search_input_var.get().strip()

        # Clear previous results
        for item in self.search_results_tree.get_children():
            self.search_results_tree.delete(item)

        if not search_input:
            messagebox.showwarning(
                "Input Required", "Please enter a search pattern or number."
            )
            return

        if search_type == "String":
            results = self.analyzer.search_strings(search_input.encode("ascii"))
            for offset, string_found in results:
                self.search_results_tree.insert(
                    "", tk.END, values=(f"{offset:08X}", string_found)
                )
            messagebox.showinfo(
                "Search Complete", f"Found {len(results)} matching strings."
            )

        elif search_type == "Hex Pattern":
            try:
                pattern = bytes.fromhex(search_input)
            except ValueError:
                messagebox.showerror(
                    "Invalid Input",
                    "Please enter a valid hex pattern (e.g., DE AD BE EF).",
                )
                return

            results = []
            with open(self.analyzer.dump_path, "rb") as f:
                data = f.read()
                for match in re.finditer(re.escape(pattern), data):
                    results.append((match.start(), match.group().hex().upper()))
            for offset, hex_pattern in results:
                self.search_results_tree.insert(
                    "", tk.END, values=(f"{offset:08X}", hex_pattern)
                )
            messagebox.showinfo(
                "Search Complete", f"Found {len(results)} matching hex patterns."
            )

        elif search_type == "Number":
            try:
                if "." in search_input:
                    number = float(search_input)
                else:
                    number = int(search_input)
            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter a valid number.")
                return

            results = self.analyzer.search_specific_number(number)
            for offset, value, val_type in results:
                self.search_results_tree.insert(
                    "", tk.END, values=(f"{offset:08X}", f"{value} ({val_type})")
                )
            messagebox.showinfo(
                "Search Complete", f"Found {len(results)} matching numbers."
            )

        elif search_type == "Address Value":
            try:
                address = int(search_input, 16)
            except ValueError:
                messagebox.showerror(
                    "Invalid Input",
                    "Please enter a valid hexadecimal address (e.g., 0x7FFDF000).",
                )
                return

            data = self.analyzer.get_data_at_address(address)
            if data:
                hex_data = data.hex().upper()
                self.search_results_tree.insert(
                    "", tk.END, values=(f"{address:016X}", hex_data)
                )
                messagebox.showinfo(
                    "Search Complete", f"Retrieved data from address {address:#016X}."
                )
            else:
                messagebox.showwarning(
                    "Not Found", f"No data found at address {address:#016X}."
                )

    def add_copy_context_menu(self, tree):
        # Create a context menu
        menu = tk.Menu(tree, tearoff=0)
        menu.add_command(label="Copy", command=lambda: self.copy_selected_item(tree))

        # Bind the right-click event to show the context menu
        def show_context_menu(event):
            selected_item = tree.identify_row(event.y)
            if selected_item:
                tree.selection_set(selected_item)
                menu.post(event.x_root, event.y_root)

        tree.bind("<Button-3>", show_context_menu)

    def copy_selected_item(self, tree):
        selected = tree.focus()
        if not selected:
            return
        values = tree.item(selected, "values")
        if not values:
            return
        # Join all values into a single string separated by tabs
        copy_text = "\t".join(str(value) for value in values)
        self.window.clipboard_clear()
        self.window.clipboard_append(copy_text)
        messagebox.showinfo("Copied", "Selected item has been copied to the clipboard.")


class ProcessSelector(ttk.Frame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.pack(fill=tk.BOTH, expand=True)
        self.create_widgets()
        self.populate_processes()

    def create_widgets(self):
        # 프로세스 리스트 Treeview에 새로운 열 추가
        self.tree = ttk.Treeview(
            self,
            columns=("PID", "Name", "CPU", "Memory", "Base Address"),
            show="headings",
        )
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="Process Name")
        self.tree.heading("CPU", text="CPU (%)")
        self.tree.heading("Memory", text="Memory (%)")
        self.tree.heading("Base Address", text="Base Address")
        self.tree.column("PID", width=100, anchor="center")
        self.tree.column("Name", width=300, anchor="w")
        self.tree.column("CPU", width=100, anchor="center")
        self.tree.column("Memory", width=100, anchor="center")
        self.tree.column("Base Address", width=200, anchor="center")

        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill=tk.BOTH, expand=True)
        scrollbar.pack(side="right", fill="y")

        # Dump, Analyze, and Refresh Buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(pady=10)

        self.dump_button = ttk.Button(
            button_frame, text="Dump Memory", command=self.dump_selected_memory
        )
        self.dump_button.grid(row=0, column=0, padx=5)

        self.analyze_button = ttk.Button(
            button_frame, text="Analyze Dump", command=self.analyze_dump
        )
        self.analyze_button.grid(row=0, column=1, padx=5)

        self.refresh_button = ttk.Button(
            button_frame, text="Refresh List", command=self.refresh_process_list
        )
        self.refresh_button.grid(row=0, column=2, padx=5)

    def populate_processes(self):
        self.tree.delete(*self.tree.get_children())  # 기존 항목 삭제
        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent"]
        ):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"]
                cpu = proc.cpu_percent(interval=0.1)
                memory = f"{proc.info['memory_percent']:.2f}%"

                base_address = get_base_address(pid)
                if base_address:
                    base_address_str = f"0x{base_address:016X}"
                else:
                    base_address_str = "N/A"

                self.tree.insert(
                    "",
                    tk.END,
                    values=(pid, name, cpu, memory, base_address_str),
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def refresh_process_list(self):
        self.populate_processes()

    def dump_selected_memory(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning(
                "No Selection", "Please select a process to dump its memory."
            )
            return
        values = self.tree.item(selected, "values")
        pid = int(values[0])
        try:
            dumper = MemoryDumper(pid)
            dump_path = dumper.dump_memory()
            if dump_path:
                # Store the last dump path for analyzing
                self.last_dump_path = dump_path
                messagebox.showinfo("Dump Successful", f"Memory dumped to {dump_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def analyze_dump(self):
        if not hasattr(self, "last_dump_path") or not self.last_dump_path:
            messagebox.showwarning(
                "No Dump Found", "Please perform a memory dump first."
            )
            return

        try:
            analyzer = DumpAnalyzer(self.last_dump_path)
            analyzer.analyze()
        except Exception as e:
            messagebox.showerror("Error", str(e))


# Define necessary Windows API structures and functions
class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


# Load psapi library
psapi = ctypes.WinDLL("Psapi.dll")

# Define GetModuleInformation
GetModuleInformation = psapi.GetModuleInformation
GetModuleInformation.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    ctypes.POINTER(MODULEINFO),
    wintypes.DWORD,
]
GetModuleInformation.restype = wintypes.BOOL

# Define EnumProcessModulesEx
EnumProcessModulesEx = psapi.EnumProcessModulesEx
EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HMODULE),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
]
EnumProcessModulesEx.restype = wintypes.BOOL

# Constants
LIST_MODULES_ALL = 0x03


def get_base_address(pid):
    """
    Retrieves the base address of the main module of the given process ID.
    """
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    # Open the process
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not handle:
        return None

    try:
        hModule = wintypes.HMODULE()
        cb = wintypes.DWORD(0)

        # First call to get the number of modules
        EnumProcessModulesEx(
            handle,
            ctypes.byref(hModule),
            ctypes.sizeof(hModule),
            ctypes.byref(cb),
            LIST_MODULES_ALL,
        )
        count = int(cb.value / ctypes.sizeof(wintypes.HMODULE))
        modules = (wintypes.HMODULE * count)()

        if not EnumProcessModulesEx(
            handle, modules, ctypes.sizeof(modules), ctypes.byref(cb), LIST_MODULES_ALL
        ):
            return None

        # Get information about the first module (main module)
        module_info = MODULEINFO()
        if not GetModuleInformation(
            handle, modules[0], ctypes.byref(module_info), ctypes.sizeof(module_info)
        ):
            return None

        return module_info.lpBaseOfDll
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def find_memory_region_containing_address(self, target_address):
    """
    특정 주소가 포함된 메모리 영역을 찾습니다.
    Args:
        target_address (int): 확인할 메모리 주소.
    Returns:
        tuple: (base_address, size, data) 해당 메모리 영역의 정보, 없으면 None.
    """
    for base, data in self.memory_regions:
        if base <= target_address < base + len(data):
            return (base, len(data), data)
    return None


def main():
    if os.name != "nt":
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Unsupported OS", "This script only supports Windows.")
        sys.exit(1)
    root = tk.Tk()
    root.title("Process Selector")
    root.geometry("800x600")
    app = ProcessSelector(parent=root)
    app.mainloop()


if __name__ == "__main__":
    main()
