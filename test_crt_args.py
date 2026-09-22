import ctypes
from ctypes import c_void_p, c_ulong, c_ushort, byref, sizeof, Structure, c_wchar_p, CDLL, POINTER, c_ubyte, c_bool, c_uint, c_ulonglong, c_int, CFUNCTYPE, cast, c_size_t
import sys, os

ntdll = ctypes.windll.ntdll
kernel32 = ctypes.windll.kernel32

class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('Reserved1', c_void_p),
        ('PebBaseAddress', c_void_p),
        ('Reserved2', c_void_p * 2),
        ('UniqueProcessId', c_void_p),
        ('Reserved3', c_void_p),
    ]

g_cmdline_buf = None

def update_peb_cmdline(cmd_str):
    global g_cmdline_buf
    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = c_ulong()
    h_proc = kernel32.GetCurrentProcess()
    status = ntdll.NtQueryInformationProcess(c_void_p(h_proc), 0, byref(pbi), c_ulong(sizeof(pbi)), byref(ret_len))
    peb_addr = pbi.PebBaseAddress

    process_params_ptr = c_void_p.from_address(peb_addr + 0x20).value
    cmd_len_addr = process_params_ptr + 0x70
    cmd_max_len_addr = process_params_ptr + 0x72
    cmd_buf_ptr_addr = process_params_ptr + 0x78

    g_cmdline_buf = ctypes.create_unicode_buffer(cmd_str)
    buf_ptr = cast(g_cmdline_buf, c_void_p).value
    byte_len = len(cmd_str) * 2

    ctypes.c_ushort.from_address(cmd_len_addr).value = byte_len
    ctypes.c_ushort.from_address(cmd_max_len_addr).value = byte_len + 2
    ctypes.c_void_p.from_address(cmd_buf_ptr_addr).value = buf_ptr

update_peb_cmdline('"Z:\\app\\test_args.exe" hello "world with space"')

peconv = CDLL('./libpeconv.dll')
exe = 'test_args.exe'

load_pe_executable = peconv.load_pe_executable2
load_pe_executable.restype = POINTER(c_ubyte)
load_pe_executable.argtypes = (c_wchar_p, POINTER(c_size_t), c_void_p)
size = c_size_t(0)
pe = load_pe_executable(exe, byref(size), None)
pe_addr = cast(pe, c_void_p)

set_main_module_in_peb = peconv.set_main_module_in_peb
set_main_module_in_peb.restype = c_bool
set_main_module_in_peb.argtypes = (c_void_p,)
set_main_module_in_peb(pe_addr)

load_delayed_imports = peconv.load_delayed_imports
load_delayed_imports.restype = c_bool
load_delayed_imports.argtypes = (POINTER(c_ubyte), c_ulonglong, c_void_p)
load_delayed_imports(pe, size.value, None)

run_tls_callbacks = peconv.run_tls_callbacks
run_tls_callbacks.restype = c_size_t
run_tls_callbacks.argtypes = (c_void_p, c_size_t, c_uint)
run_tls_callbacks(pe_addr.value, size, 1)

get_entry_point_rva = peconv.get_entry_point_rva
get_entry_point_rva.restype = c_uint
get_entry_point_rva.argtypes = (POINTER(c_ubyte),)
entry_rva = get_entry_point_rva(pe)
entry_va = pe_addr.value + entry_rva

print("Executing PE entry point with void signature...")
res = CFUNCTYPE(c_int)(entry_va)()
print("PE exited with code:", res)
