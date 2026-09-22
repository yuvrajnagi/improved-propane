# -*- coding: utf-8 -*-
import os
import sys
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import Propane

def create_mock_pe(
    filename: Path,
    is_64bit: bool = True,
    manifest_level: str = "asInvoker",
    corrupt_dos: bool = False,
    corrupt_pe: bool = False,
    corrupt_machine: bool = False,
    truncated: bool = False
) -> Path:
    """Helper function to create synthetic PE files for testing."""
    if truncated:
        with open(filename, 'wb') as f:
            f.write(b'MZ' + b'\0' * 10)
        return filename

    # DOS Header
    dos_header = bytearray(0x40)
    dos_header[0:2] = b'XX' if corrupt_dos else b'MZ'
    e_lfanew = 0x40
    struct.pack_into('<I', dos_header, 0x3C, e_lfanew)

    # PE Signature & File Header
    pe_sig = b'XX\0\0' if corrupt_pe else b'PE\0\0'
    if corrupt_machine:
        machine = 0x1234
    elif is_64bit:
        machine = 0x8664  # AMD64
    else:
        machine = 0x014c  # i386

    num_sections = 2
    time_stamp = 0
    size_of_opt_header = 0xF0 if is_64bit else 0xE0
    characteristics = 0x0022  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    file_header = struct.pack('<HHIIIHH', machine, num_sections, time_stamp, 0, 0, size_of_opt_header, characteristics)

    # Optional Header
    opt_magic = 0x020b if is_64bit else 0x010b
    entry_point = 0x1000
    sec_align = 0x1000
    file_align = 0x200
    size_of_image = 0x3000
    size_of_headers = 0x200

    if is_64bit:
        image_base = 0x140000000
        opt_header = struct.pack(
            '<HBBIIIIIQIIHHHHHHIIIIHH',
            opt_magic, 2, 25, 0x200, 0x200, 0, entry_point, 0x1000,
            image_base, sec_align, file_align, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, size_of_headers, 0, 3, 0  # Subsystem 3 = CUI
        )
        opt_header += b'\0' * (0xF0 - len(opt_header))
    else:
        image_base_32 = 0x00400000
        opt_header = struct.pack(
            '<HBBIIIIIIIIIHHHHHHIIIIHH',
            opt_magic, 2, 25, 0x200, 0x200, 0, entry_point, 0x1000, 0x1000,
            image_base_32, sec_align, file_align, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, size_of_headers, 0, 3, 0
        )
        opt_header += b'\0' * (0xE0 - len(opt_header))

    # Section Headers
    # .text section
    sec_text = struct.pack('<8sIIIIIIHHI', b'.text\0\0\0', 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    # .rsrc section
    sec_rsrc = struct.pack('<8sIIIIIIHHI', b'.rsrc\0\0\0', 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040)

    # Padding to FileAlignment (0x200)
    headers = dos_header + pe_sig + file_header + opt_header + sec_text + sec_rsrc
    headers += b'\0' * (0x200 - len(headers))

    # .text section data
    text_data = b'\xC3' + b'\x90' * 0x1FF

    # .rsrc section data containing XML manifest with requestedExecutionLevel
    manifest_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="{manifest_level}" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>'''.encode('utf-8')

    rsrc_data = manifest_xml + b'\0' * (0x200 - len(manifest_xml))

    with open(filename, 'wb') as f:
        f.write(headers + text_data + rsrc_data)

    return filename


class TestPropane(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detect_pe_arch_valid_64bit(self):
        exe = create_mock_pe(self.test_dir / "valid64.exe", is_64bit=True)
        arch = Propane.detect_pe_arch(exe)
        self.assertEqual(arch, '64')

    def test_detect_pe_arch_valid_32bit(self):
        exe = create_mock_pe(self.test_dir / "valid32.exe", is_64bit=False)
        arch = Propane.detect_pe_arch(exe)
        self.assertEqual(arch, '32')

    def test_detect_pe_arch_corrupt_dos(self):
        exe = create_mock_pe(self.test_dir / "corrupt_dos.exe", corrupt_dos=True)
        with self.assertRaises(ValueError) as ctx:
            Propane.detect_pe_arch(exe)
        self.assertIn("missing MZ signature", str(ctx.exception))

    def test_detect_pe_arch_corrupt_pe(self):
        exe = create_mock_pe(self.test_dir / "corrupt_pe.exe", corrupt_pe=True)
        with self.assertRaises(ValueError) as ctx:
            Propane.detect_pe_arch(exe)
        self.assertIn("missing PE signature", str(ctx.exception))

    def test_detect_pe_arch_unsupported_machine(self):
        exe = create_mock_pe(self.test_dir / "bad_machine.exe", corrupt_machine=True)
        with self.assertRaises(ValueError) as ctx:
            Propane.detect_pe_arch(exe)
        self.assertIn("Unsupported machine type", str(ctx.exception))

    def test_detect_pe_arch_truncated(self):
        exe = create_mock_pe(self.test_dir / "truncated.exe", truncated=True)
        with self.assertRaises(ValueError) as ctx:
            Propane.detect_pe_arch(exe)
        self.assertIn("Invalid PE file", str(ctx.exception))

    def test_check_pe_requires_admin(self):
        exe_admin = create_mock_pe(self.test_dir / "admin.exe", manifest_level="requireAdministrator")
        exe_invoker = create_mock_pe(self.test_dir / "invoker.exe", manifest_level="asInvoker")

        self.assertTrue(Propane.check_pe_requires_admin(exe_admin))
        self.assertFalse(Propane.check_pe_requires_admin(exe_invoker))

    def test_is_admin_check(self):
        with patch('Propane.is_admin', return_value=False):
            self.assertFalse(Propane.is_admin())

        with patch('Propane.is_admin', return_value=True):
            self.assertTrue(Propane.is_admin())
            ret = Propane.load_and_run_pe(self.test_dir / "dummy.exe", ["dummy.exe"])
            self.assertEqual(ret, -1)

    def test_center_text_preserves_blank_lines(self):
        input_text = "Header\n\nLine 1\n\nFooter"
        centered = Propane.center_text(input_text, 80)
        lines = centered.splitlines()
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[1], '')
        self.assertEqual(lines[3], '')

    def test_bitness_mismatch_refusal(self):
        exe_32 = create_mock_pe(self.test_dir / "app32.exe", is_64bit=False)
        with patch('sys.maxsize', 2**63 - 1):  # 64-bit Python
            ret = Propane.load_and_run_pe(exe_32, [str(exe_32)])
            self.assertEqual(ret, -1)

    def test_load_and_run_pe_missing_file(self):
        non_existent = self.test_dir / "does_not_exist.exe"
        ret = Propane.load_and_run_pe(non_existent, [str(non_existent)])
        self.assertEqual(ret, -1)

    def test_load_and_run_pe_admin_manifest_refusal(self):
        exe_admin = create_mock_pe(self.test_dir / "admin_test.exe", manifest_level="requireAdministrator")
        with patch('Propane.is_admin', return_value=False):
            ret = Propane.load_and_run_pe(exe_admin, [str(exe_admin)])
            self.assertEqual(ret, -1)

    def test_load_and_run_pe_missing_dll(self):
        exe_64 = create_mock_pe(self.test_dir / "app64.exe", is_64bit=True)
        with patch('Propane.is_admin', return_value=False), \
             patch('sys.maxsize', 2**63 - 1), \
             patch('pathlib.Path.cwd', return_value=self.test_dir):
            ret = Propane.load_and_run_pe(exe_64, [str(exe_64)])
            self.assertEqual(ret, -1)

    def test_main_cli_mode(self):
        exe_64 = create_mock_pe(self.test_dir / "cli_app.exe", is_64bit=True)
        with patch.object(sys, 'argv', ['Propane.py', str(exe_64), 'arg1', 'arg2']), \
             patch('Propane.is_admin', return_value=False), \
             patch('Propane.load_and_run_pe', return_value=0) as mock_run:
            res = Propane.main()
            self.assertEqual(res, 0)
            mock_run.assert_called_once_with(exe_64.resolve(), [str(exe_64.resolve()), 'arg1', 'arg2'])

    def test_main_interactive_no_exe(self):
        with patch.object(sys, 'argv', ['Propane.py']), \
             patch('Propane.is_admin', return_value=False), \
             patch('pathlib.Path.cwd', return_value=self.test_dir), \
             patch('Propane.centered_input', return_value=''):
            res = Propane.main()
            self.assertEqual(res, -1)

    def test_main_interactive_select_exe(self):
        exe_1 = create_mock_pe(self.test_dir / "app1.exe", is_64bit=True)
        exe_2 = create_mock_pe(self.test_dir / "app2.exe", is_64bit=True)

        with patch.object(sys, 'argv', ['Propane.py']), \
             patch('Propane.is_admin', return_value=False), \
             patch('pathlib.Path.cwd', return_value=self.test_dir), \
             patch('Propane.centered_input', side_effect=['1', '0']), \
             patch('Propane.load_and_run_pe', return_value=0) as mock_run:
            res = Propane.main()
            self.assertEqual(res, 0)
            self.assertTrue(mock_run.called)

    def test_batch_run_many_exes(self):
        """Test Propane logic across many created EXE variations."""
        exes = [
            create_mock_pe(self.test_dir / "app1_x64.exe", is_64bit=True, manifest_level="asInvoker"),
            create_mock_pe(self.test_dir / "app2_x64.exe", is_64bit=True, manifest_level="highestAvailable"),
            create_mock_pe(self.test_dir / "app3_x86.exe", is_64bit=False, manifest_level="asInvoker"),
            create_mock_pe(self.test_dir / "app4_admin.exe", is_64bit=True, manifest_level="requireAdministrator"),
            create_mock_pe(self.test_dir / "app5_corrupt.exe", corrupt_pe=True),
        ]

        for exe in exes:
            with patch('Propane.is_admin', return_value=False):
                if "corrupt" in exe.name:
                    self.assertRaises(ValueError, Propane.detect_pe_arch, exe)
                elif "admin" in exe.name:
                    self.assertTrue(Propane.check_pe_requires_admin(exe))
                    ret = Propane.load_and_run_pe(exe, [str(exe)])
                    self.assertEqual(ret, -1)
                elif "x86" in exe.name and sys.maxsize > 2**32:
                    arch = Propane.detect_pe_arch(exe)
                    self.assertEqual(arch, '32')
                    ret = Propane.load_and_run_pe(exe, [str(exe)])
                    self.assertEqual(ret, -1)
                elif "x64" in exe.name and sys.maxsize > 2**32:
                    arch = Propane.detect_pe_arch(exe)
                    self.assertEqual(arch, '64')


if __name__ == '__main__':
    unittest.main()
