# -*- coding: utf-8 -*-
from __future__ import annotations

import codecs
import ctypes
from ctypes import (CDLL, CFUNCTYPE, POINTER, byref, c_bool, c_int, c_size_t,
                    c_ubyte, c_uint, c_ulonglong, c_void_p, c_wchar_p, cast, c_char_p)
import os
from os import chdir
from pathlib import Path
import struct
import sys
import textwrap

DLL_PROCESS_ATTACH = c_uint(1)

def configure_utf8():
    """Force UTF-8 output on Windows standard streams if supported."""
    if sys.platform == "win32":
        try:
            os.system('chcp 65001 > nul')
        except Exception:
            pass
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    if hasattr(sys.stdin, 'reconfigure'):
        try:
            sys.stdin.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

def is_admin() -> bool:
    """Check if the process is running with administrator/root privileges."""
    if sys.platform == "win32":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return hasattr(os, 'geteuid') and os.geteuid() == 0
        except Exception:
            return False

def check_pe_requires_admin(exe_path: Path) -> bool:
    """Scan PE binary or manifest for requireAdministrator execution level."""
    try:
        with open(exe_path, 'rb') as f:
            content = f.read()
        lower_content = content.lower()
        if b'requireadministrator' in lower_content:
            return True
        return False
    except Exception:
        return False

def detect_pe_arch(exe_path: Path) -> str:
    """Detect if PE is 32-bit or 64-bit by reading headers."""
    try:
        with open(exe_path, 'rb') as f:
            header = f.read(0x200)
            if len(header) < 0x40 or header[:2] != b'MZ':
                raise ValueError("Invalid PE file: missing MZ signature")

            e_lfanew = struct.unpack('<I', header[0x3C:0x40])[0]
            if e_lfanew + 24 > len(header):
                f.seek(e_lfanew)
                nt_hdr = f.read(24)
            else:
                nt_hdr = header[e_lfanew:e_lfanew+24]

            if len(nt_hdr) < 24 or nt_hdr[:4] != b'PE\0\0':
                raise ValueError("Invalid PE file: missing PE signature")

            machine = struct.unpack('<H', nt_hdr[4:6])[0]
            if machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
                return '32'
            elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                return '64'
            else:
                raise ValueError(f"Unsupported machine type: 0x{machine:04x}")
    except (OSError, struct.error) as e:
        raise ValueError(f"Error reading PE file: {e}")

def center_text(text: str, width: int) -> str:
    """Center a single line or multi-line text, wrapping if necessary."""
    wrapped_lines = []
    for line in text.splitlines():
        if not line.strip():
            wrapped_lines.append('')
            continue
        wrapped = textwrap.wrap(line, width=max(10, width - 4))
        for w_line in wrapped:
            padding = max(0, (width - len(w_line)) // 2)
            wrapped_lines.append(' ' * padding + w_line)
    return '\n'.join(wrapped_lines)

def centered_print(text: str):
    """Print centered text in the console."""
    try:
        console_width = os.get_terminal_size().columns
    except Exception:
        console_width = 80
    print(center_text(text, console_width))

def centered_input(prompt: str) -> str:
    """Display centered prompt and get input on the same line."""
    try:
        width = os.get_terminal_size().columns
    except Exception:
        width = 80
    padding = max(0, (width - len(prompt)) // 2)
    full_prompt = ' ' * padding + prompt
    try:
        return input(full_prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""

def load_and_run_pe(exe: Path, argv: list[str]) -> int:
    """Load and execute a PE file using libpeconv safely."""
    if is_admin():
        centered_print("Error: Running with administrator/root privileges is disabled. Please run Propane as a standard user.")
        return -1

    if not exe.exists() or not exe.is_file():
        centered_print(f"Error: Executable file '{exe}' not found.")
        return -1

    if check_pe_requires_admin(exe):
        centered_print(f"Error: Executable '{exe.name}' requests administrator privileges (requireAdministrator). Propane will not run admin executables.")
        return -1

    try:
        arch = detect_pe_arch(exe)
        centered_print(f"Detected {arch}-bit PE executable.")
    except ValueError as e:
        centered_print(f"Error: {e}")
        return -1

    python_bitness = '64' if sys.maxsize > 2**32 else '32'
    if arch != python_bitness:
        centered_print(f"Error: {arch}-bit EXE cannot be executed in a {python_bitness}-bit Python environment.")
        return -1

    # Locate libpeconv.dll
    peconv_dir = Path.cwd()
    dll_path = peconv_dir / 'libPeConv.dll'
    if not dll_path.exists():
        dll_path = Path(__file__).parent / 'libPeConv.dll'
        if not dll_path.exists():
            centered_print("Error: libPeConv.dll not found in current directory or script directory.")
            return -1

    centered_print(f"Assuming libPeConv.dll is {arch}-bit.")

    try:
        peconv = CDLL(str(dll_path))
    except Exception as e:
        centered_print(f"Error loading libPeConv.dll: {e}. (PE execution requires a Windows environment)")
        return -1

    # Define function signatures for libPeConv
    load_pe_executable = peconv.load_pe_executable2
    load_pe_executable.restype = POINTER(c_ubyte)
    load_pe_executable.argtypes = (c_char_p, POINTER(c_size_t), c_void_p)

    set_main_module_in_peb = peconv.set_main_module_in_peb
    set_main_module_in_peb.restype = c_bool
    set_main_module_in_peb.argtypes = (c_void_p,)

    load_delayed_imports = peconv.load_delayed_imports
    load_delayed_imports.restype = c_bool
    load_delayed_imports.argtypes = (POINTER(c_ubyte), c_ulonglong, c_void_p)

    setup_exceptions = getattr(peconv, 'setup_exceptions', None)
    if setup_exceptions:
        setup_exceptions.restype = c_bool
        setup_exceptions.argtypes = (POINTER(c_ubyte), c_size_t)

    run_tls_callbacks = peconv.run_tls_callbacks
    run_tls_callbacks.restype = c_size_t
    run_tls_callbacks.argtypes = (c_void_p, c_size_t, c_uint)

    get_entry_point_rva = peconv.get_entry_point_rva
    get_entry_point_rva.restype = c_uint
    get_entry_point_rva.argtypes = (POINTER(c_ubyte),)

    size = c_size_t(0)
    exe_path_bytes = str(exe.resolve()).encode('utf-8')
    pe: POINTER(c_ubyte) = load_pe_executable(exe_path_bytes, byref(size), None)

    if not pe:
        centered_print("Error: Failed to load PE executable.")
        return -1

    pe_addr = cast(pe, c_void_p)

    if not set_main_module_in_peb(pe_addr):
        centered_print("Error: Failed to set main module in PEB.")
        return -1

    if not load_delayed_imports(pe, pe_addr.value, None):
        centered_print("Error: Failed to load delayed imports.")
        return -1

    if setup_exceptions:
        setup_exceptions(pe, size)

    run_tls_callbacks(pe_addr.value, size, DLL_PROCESS_ATTACH)

    entry_rva: int = get_entry_point_rva(pe)
    if not entry_rva:
        centered_print("Error: No entry point RVA found.")
        return -2

    entry_va: int = pe_addr.value + entry_rva

    chdir(exe.parent)

    argc = len(argv)
    c_argv = (c_wchar_p * argc)(*argv)

    return CFUNCTYPE(c_int, c_int, POINTER(c_wchar_p))(entry_va)(argc, c_argv)

def main() -> int:
    configure_utf8()

    if is_admin():
        centered_print("Error: Running with administrator/root privileges is disabled. Please run Propane as a standard user.")
        return -1

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

    instructions = "Place Propane.py in the folder with the exe you want to run. Type the name or number of the executable you want to run. Propane can run executables matching your Python bitness."
    centered_print(instructions)

    argc_explanation = "argc (argument count) is the number of command-line arguments passed to a program, including the executable name as argv[0]."
    centered_print(argc_explanation)

    # CLI mode check
    if len(sys.argv) > 1:
        exe_path = Path(sys.argv[1]).resolve()
        args = [str(exe_path)] + sys.argv[2:]
        return load_and_run_pe(exe_path, args)

    # Interactive mode
    current_dir = Path.cwd()
    exe_files = list(current_dir.glob('*.exe'))
    if not exe_files:
        centered_print("No Executable Found, please place Propane.py in the folder with the exe you want to run.")
        centered_input("Press Enter to exit...")
        return -1

    centered_print("Found .exe files:")
    exe_map = {}
    for i, exe_file in enumerate(exe_files, start=1):
        exe_map[str(i)] = exe_file
        centered_print(f"{i}: {exe_file.name}")

    ignite_input = centered_input('Ignite: ')
    if not ignite_input:
        return -1

    if ignite_input in exe_map:
        exe = exe_map[ignite_input].resolve()
    else:
        exe = Path(ignite_input).resolve()

    if not exe.exists() or not exe.suffix.lower() == '.exe':
        centered_print("Invalid EXE selection or file not found.")
        return -1

    try:
        argc_input = centered_input('argc (optional, default 0): ') or '0'
        extra_argc = int(argc_input)
        extra_argv = []
        for i in range(extra_argc):
            arg_input = centered_input(f'[{i + 1}] ')
            extra_argv.append(arg_input)
        argv = [str(exe)] + extra_argv
    except ValueError:
        argv = [str(exe)]

    return load_and_run_pe(exe, argv)

if __name__ == '__main__':
    sys.exit(main())
