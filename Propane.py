# NOT MINE. Contribuited by [unknown, if you know who made this, please post an issue].
# -*- coding: utf_8 -*-

from __future__ import annotations

import sys
from ctypes import (CDLL, CFUNCTYPE, POINTER, byref, c_bool, c_int, c_size_t,
                    c_ubyte, c_uint, c_ulonglong, c_void_p, c_wchar_p, cast)
from os import chdir, system
from pathlib import Path
import struct
import os
import textwrap
import codecs

# Force UTF-8 on Windows to reduce garbling
if sys.platform == "win32":
    system('chcp 65001 > nul')
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

def detect_pe_arch(exe_path: Path) -> str:
    """Detect if PE is 32-bit or 64-bit by reading headers."""
    with open(exe_path, 'rb') as f:
        dos_sig = f.read(2)
        if dos_sig != b'MZ':
            raise ValueError("Not a valid PE executable (missing MZ signature)")
        # DOS header: e_lfanew at 0x3C
        f.seek(0x3C)
        e_lfanew_data = f.read(4)
        if len(e_lfanew_data) < 4:
            raise ValueError("Truncated DOS header")
        e_lfanew = struct.unpack('<I', e_lfanew_data)[0]

        # NT header signature
        f.seek(e_lfanew)
        sig = f.read(4)
        if sig != b'PE\0\0':
            raise ValueError("Invalid PE file (missing PE signature)")

        # Machine type (next 2 bytes)
        machine_data = f.read(2)
        if len(machine_data) < 2:
            raise ValueError("Truncated PE header")
        machine = struct.unpack('<H', machine_data)[0]

        if machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
            return '32'
        elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return '64'
        else:
            raise ValueError(f"Unsupported machine type: 0x{machine:04x}")

DLL_PROCESS_ATTACH = c_uint(1)

def get_console_width() -> int:
    """Get current console width safely, defaulting to 80."""
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

def center_text(text: str, width: int) -> str:
    """Center a single line or multi-line text, wrapping if necessary."""
    wrapped_lines = []
    for line in text.splitlines():
        if not line.strip():
            wrapped_lines.append('')
            continue
        effective_width = max(10, width - 4)
        wrapped = textwrap.wrap(line, width=effective_width)
        for w_line in wrapped:
            padding = max(0, (width - len(w_line)) // 2)
            wrapped_lines.append(' ' * padding + w_line)
    return '\n'.join(wrapped_lines)

def centered_print(text: str):
    """Print centered text in the console."""
    console_width = get_console_width()
    print(center_text(text, console_width))

def centered_input(prompt: str) -> str:
    """Display centered prompt and get input on the same line."""
    width = get_console_width()
    padding = max(0, (width - len(prompt)) // 2)
    full_prompt = ' ' * padding + prompt
    return input(full_prompt).strip()

_g_peb_cmdline_buf = None

def _update_peb_command_line(argv: list[str]) -> None:
    """Update CommandLine string in PEB ProcessParameters for target PE."""
    global _g_peb_cmdline_buf
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        from ctypes import Structure, c_ulong, c_ushort, c_void_p, byref, sizeof, cast

        class PROCESS_BASIC_INFORMATION(Structure):
            _fields_ = [
                ('Reserved1', c_void_p),
                ('PebBaseAddress', c_void_p),
                ('Reserved2', c_void_p * 2),
                ('UniqueProcessId', c_void_p),
                ('Reserved3', c_void_p),
            ]

        ntdll = ctypes.windll.ntdll
        kernel32 = ctypes.windll.kernel32

        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = c_ulong()
        h_proc = kernel32.GetCurrentProcess()
        status = ntdll.NtQueryInformationProcess(c_void_p(h_proc), 0, byref(pbi), c_ulong(sizeof(pbi)), byref(ret_len))
        if status != 0 or not pbi.PebBaseAddress:
            return

        peb_addr = pbi.PebBaseAddress
        process_params_ptr = c_void_p.from_address(peb_addr + 0x20).value
        if not process_params_ptr:
            return

        # Format command line string with proper quoting
        quoted_args = []
        for arg in argv:
            if ' ' in arg or '\t' in arg or '"' in arg or not arg:
                escaped = arg.replace('"', '\\"')
                quoted_args.append(f'"{escaped}"')
            else:
                quoted_args.append(arg)
        cmd_str = ' '.join(quoted_args)

        _g_peb_cmdline_buf = ctypes.create_unicode_buffer(cmd_str)
        buf_ptr = cast(_g_peb_cmdline_buf, c_void_p).value
        byte_len = len(cmd_str) * 2

        cmd_len_addr = process_params_ptr + 0x70
        cmd_max_len_addr = process_params_ptr + 0x72
        cmd_buf_ptr_addr = process_params_ptr + 0x78

        ctypes.c_ushort.from_address(cmd_len_addr).value = byte_len
        ctypes.c_ushort.from_address(cmd_max_len_addr).value = byte_len + 2
        ctypes.c_void_p.from_address(cmd_buf_ptr_addr).value = buf_ptr
    except Exception:
        pass

def main() -> int:
    # Restored full original ASCII art with Unicode; adjusted third line of PROPANE block by moving back 1 space to fix warble
    ascii_art = textwrap.dedent(r'''
     PROPANE


    ██████╗ ██████╗  ██████╗ ██████╗  █████╗ ███╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝
   ██████╔╝██████╔╝██║   ██║██████╔╝███████║██╔██╗ ██║█████╗
   ██╔═══╝ ██╔══██╗██║   ██║██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝
    ██║     ██║  ██║╚██████╔╝██║     ██║  ██║██║ ╚████║███████╗
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝


     ___ _  _ ___ _____ ___ _   _  ___ _____ ___ ___  _  _ ___
    |_ _| \| / __|_   _| _ \ | | |/ __|_   _|_ _/ _ \| \| / __|
     | || .` \__ \ | | |   / |_| | (__  | |  | | (_) | .` \__ \
    |___|_|\_|___/ |_| |_|_\\___/ \___| |_| |___\___/|_|\_|___/

    ''')

    centered_print(ascii_art)

    instructions = "Place Propane.py in the folder with the exe you want to run. Type the name or number of the executable you want to run. Propane can only run x64 executables, x32 will not work."
    centered_print(instructions)

    argc_explanation = "argc (argument count) is the number of command-line arguments passed to a program (in C/C++ or similar), including the executable name as argv[0]. In this script, it's optional (default 0) and lets you specify extra args to pass when running the EXE, with argc incremented by 1 to include the EXE path."
    centered_print(argc_explanation)

    # Search current folder for .exe files
    current_dir = Path.cwd()
    exe_files = list(current_dir.glob('*.exe'))
    if not exe_files:
        centered_print("No Executable Found, please place Propane.py in the folder with the exe you want to run")
        centered_input("Press Enter to exit...")  # Centered pause to prevent instant closure
        return -1

    centered_print("Found .exe files:")
    exe_map = {}
    for i, exe_file in enumerate(exe_files, start=1):
        exe_map[str(i)] = exe_file
        centered_print(f"{i}: {exe_file.name}")

    # Prompt for Ignite: (number or filename/path)
    ignite_input = centered_input('Ignite: ')
    if ignite_input in exe_map:
        exe = exe_map[ignite_input].resolve()
    else:
        exe = Path(ignite_input).resolve()

    if not exe.exists() or not exe.suffix.lower() == '.exe':
        centered_print("Invalid EXE selection or not found. ")
        return -1

    # Detect arch (for validation; assume Python bitness matches)
    try:
        arch = detect_pe_arch(exe)
        centered_print(f"Detected {arch}-bit EXE. Ensure running with matching Python bitness! ")
    except ValueError as e:
        centered_print(f"Error: {e} ")
        return -1

    # Locate libpeconv.dll in current directory (support both casing)
    peconv_dir = Path.cwd()
    dll_path = peconv_dir / 'libpeconv.dll'
    if not dll_path.exists():
        dll_path = peconv_dir / 'libPeConv.dll'
    if not dll_path.exists():
        centered_print("libpeconv.dll not found in current directory. ")
        return -1
    centered_print(f"Assuming {dll_path.name} in current directory is {arch}-bit. ")

    # Get argc/argv
    try:
        argc_input = centered_input('argc (optional, default 0): ') or '0'
        user_argc = int(argc_input)
        if user_argc < 0:
            user_argc = 0
        argv = []
        for i in range(user_argc):
            arg_input = centered_input(f'[{i + 1}] ')
            argv.append(arg_input)
        argc = user_argc + 1  # Include argv[0] = exe
        argv = [str(exe)] + argv
    except ValueError:
        argc = 1
        argv = [str(exe)]

    try:
        peconv = CDLL(str(dll_path))
    except Exception as e:
        centered_print(f"Failed to load {dll_path.name}: {e}")
        return -1

    # Bind libpeconv functions
    free_pe_buffer = peconv.free_pe_buffer
    free_pe_buffer.restype = None
    free_pe_buffer.argtypes = (POINTER(c_ubyte),)

    load_pe_executable = peconv.load_pe_executable2
    load_pe_executable.restype = POINTER(c_ubyte)
    load_pe_executable.argtypes = (c_wchar_p, POINTER(c_size_t), c_void_p)

    set_main_module_in_peb = peconv.set_main_module_in_peb
    set_main_module_in_peb.restype = c_bool
    set_main_module_in_peb.argtypes = (c_void_p,)

    load_delayed_imports = peconv.load_delayed_imports
    load_delayed_imports.restype = c_bool
    load_delayed_imports.argtypes = (POINTER(c_ubyte), c_ulonglong, c_void_p)

    run_tls_callbacks = peconv.run_tls_callbacks
    run_tls_callbacks.restype = c_size_t
    run_tls_callbacks.argtypes = (c_void_p, c_size_t, c_uint)

    get_entry_point_rva = peconv.get_entry_point_rva
    get_entry_point_rva.restype = c_uint
    get_entry_point_rva.argtypes = (POINTER(c_ubyte),)

    # Load the PE
    size = c_size_t(0)
    pe: POINTER(c_ubyte) = load_pe_executable(str(exe), byref(size), None)

    if not pe:
        centered_print("Failed to load PE into memory.")
        return -1

    pe_addr = cast(pe, c_void_p)

    # Connect the PE to the PEB
    if not set_main_module_in_peb(pe_addr):
        centered_print("Failed to set main module in PEB.")
        free_pe_buffer(pe)
        return -1

    # Update PEB ProcessParameters CommandLine for CRT apps using GetCommandLineW
    _update_peb_command_line(argv)

    # Load delayed imports (pass image size, not base address)
    if not load_delayed_imports(pe, size.value, None):
        centered_print("Failed to load delayed imports.")
        free_pe_buffer(pe)
        return -1

    # Run TLS callbacks
    run_tls_callbacks(pe_addr.value, size, DLL_PROCESS_ATTACH)

    # Calculate the entrypoint address
    entry_rva: int = get_entry_point_rva(pe)
    if not entry_rva:
        centered_print("No entry point RVA found.")
        free_pe_buffer(pe)
        return -2

    entry_va: int = pe_addr.value + entry_rva

    # Change to the executable's directory
    chdir(exe.parent)

    # Call the PE entrypoint
    entry_func = CFUNCTYPE(c_int, c_int, POINTER(c_wchar_p))(entry_va)
    c_argv = (c_wchar_p * argc)(*argv)

    try:
        return entry_func(argc, c_argv)
    except Exception as e:
        centered_print(f"Exception during PE execution: {e}")
        return -3

if __name__ == '__main__':
    sys.exit(main())