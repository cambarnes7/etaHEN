#!/usr/bin/env python3
"""
SFO Analyzer - PSP/PS3/PS4/PS5 Save File Analysis Tool
Analyzes PARAM.SFO structure and identifies potential exploitation vectors.

Based on Flatz's sfo.c parsing code - vulnerabilities identified:
1. No bounds checking on key_table_offset + key_offset
2. No bounds checking on data_table_offset + data_offset
3. strdup() reads until null - can read beyond buffer
4. No validation of param_max_length before malloc
5. Integer overflow in num_entries * sizeof(index_table)
"""

import struct
import sys
import os
from typing import Dict, List, Tuple, Optional

# SFO Constants
SFO_MAGIC = 0x46535000  # "\0PSF" in little-endian
SFO_VERSION = 0x0101    # Version 1.1

# Parameter formats
FMT_BINARY = 0x0004  # Binary data
FMT_STRING = 0x0204  # UTF-8 string (null terminated)
FMT_INT32 = 0x0404   # 32-bit integer

class SFOHeader:
    SIZE = 20

    def __init__(self, data: bytes):
        if len(data) < self.SIZE:
            raise ValueError(f"Header too small: {len(data)} < {self.SIZE}")

        self.magic, self.version, self.key_table_offset, \
        self.data_table_offset, self.num_entries = struct.unpack('<IIIII', data[:20])

    def is_valid(self) -> bool:
        return self.magic == SFO_MAGIC

    def __str__(self) -> str:
        return f"""SFO Header:
  Magic: 0x{self.magic:08X} ({'VALID' if self.is_valid() else 'INVALID!'})
  Version: 0x{self.version:04X}
  Key Table Offset: 0x{self.key_table_offset:X} ({self.key_table_offset})
  Data Table Offset: 0x{self.data_table_offset:X} ({self.data_table_offset})
  Num Entries: {self.num_entries}"""


class SFOIndexEntry:
    SIZE = 16

    def __init__(self, data: bytes, index: int):
        self.index = index
        self.key_offset, self.param_format, self.param_length, \
        self.param_max_length, self.data_offset = struct.unpack('<HHIII', data[:16])

    def get_format_name(self) -> str:
        formats = {
            FMT_BINARY: "BINARY",
            FMT_STRING: "STRING",
            FMT_INT32: "INT32"
        }
        return formats.get(self.param_format, f"UNKNOWN(0x{self.param_format:04X})")

    def __str__(self) -> str:
        return f"Entry[{self.index}]: key_off=0x{self.key_offset:X}, fmt={self.get_format_name()}, " \
               f"len={self.param_length}, max_len={self.param_max_length}, data_off=0x{self.data_offset:X}"


class SFOParam:
    def __init__(self, key: str, entry: SFOIndexEntry, value: bytes):
        self.key = key
        self.entry = entry
        self.raw_value = value

    def get_value(self):
        if self.entry.param_format == FMT_STRING:
            # Null-terminated string
            null_pos = self.raw_value.find(b'\x00')
            if null_pos >= 0:
                return self.raw_value[:null_pos].decode('utf-8', errors='replace')
            return self.raw_value.decode('utf-8', errors='replace')
        elif self.entry.param_format == FMT_INT32:
            if len(self.raw_value) >= 4:
                return struct.unpack('<I', self.raw_value[:4])[0]
            return None
        else:
            return self.raw_value.hex()

    def __str__(self) -> str:
        val = self.get_value()
        if self.entry.param_format == FMT_INT32:
            return f"{self.key}: {val} (0x{val:X})" if val else f"{self.key}: <invalid>"
        elif self.entry.param_format == FMT_STRING:
            return f"{self.key}: \"{val}\""
        else:
            return f"{self.key}: [{len(self.raw_value)} bytes] {val[:64]}{'...' if len(val) > 64 else ''}"


class SFOAnalyzer:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = None
        self.header = None
        self.entries: List[SFOIndexEntry] = []
        self.params: Dict[str, SFOParam] = {}
        self.vulnerabilities: List[str] = []

    def load(self) -> bool:
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            print(f"[+] Loaded {len(self.data)} bytes from {self.filepath}")
            return True
        except Exception as e:
            print(f"[-] Failed to load: {e}")
            return False

    def parse(self) -> bool:
        if not self.data:
            return False

        # Parse header
        self.header = SFOHeader(self.data)
        print(self.header)
        print()

        if not self.header.is_valid():
            print("[-] Invalid SFO magic!")
            return False

        # Check for vulnerabilities in header
        self._check_header_vulnerabilities()

        # Parse index entries
        print("[*] Index Table Entries:")
        offset = SFOHeader.SIZE
        for i in range(self.header.num_entries):
            if offset + SFOIndexEntry.SIZE > len(self.data):
                self.vulnerabilities.append(f"Entry {i}: Would read beyond file!")
                break

            entry = SFOIndexEntry(self.data[offset:offset + SFOIndexEntry.SIZE], i)
            self.entries.append(entry)
            print(f"  {entry}")

            # Check entry vulnerabilities
            self._check_entry_vulnerabilities(entry)

            offset += SFOIndexEntry.SIZE

        print()

        # Parse parameters
        print("[*] Parameters:")
        for entry in self.entries:
            # Get key
            key_offset = self.header.key_table_offset + entry.key_offset
            if key_offset >= len(self.data):
                self.vulnerabilities.append(f"Entry {entry.index}: Key offset 0x{key_offset:X} beyond file!")
                continue

            # Find null terminator for key
            key_end = self.data.find(b'\x00', key_offset)
            if key_end < 0:
                key_end = len(self.data)
                self.vulnerabilities.append(f"Entry {entry.index}: Key has no null terminator!")

            key = self.data[key_offset:key_end].decode('utf-8', errors='replace')

            # Get value
            data_offset = self.header.data_table_offset + entry.data_offset
            data_end = data_offset + entry.param_max_length

            if data_offset >= len(self.data):
                self.vulnerabilities.append(f"Entry {entry.index}: Data offset 0x{data_offset:X} beyond file!")
                continue

            if data_end > len(self.data):
                self.vulnerabilities.append(f"Entry {entry.index}: Data would read beyond file!")
                data_end = len(self.data)

            value = self.data[data_offset:data_end]

            param = SFOParam(key, entry, value)
            self.params[key] = param
            print(f"  {param}")

        return True

    def _check_header_vulnerabilities(self):
        """Check for exploitable conditions in header"""

        # Check if offsets point beyond file
        if self.header.key_table_offset > len(self.data):
            self.vulnerabilities.append(f"key_table_offset (0x{self.header.key_table_offset:X}) beyond file!")

        if self.header.data_table_offset > len(self.data):
            self.vulnerabilities.append(f"data_table_offset (0x{self.header.data_table_offset:X}) beyond file!")

        # Check for integer overflow in index table
        index_table_size = self.header.num_entries * SFOIndexEntry.SIZE
        if index_table_size > 0xFFFFFFFF:  # 32-bit overflow
            self.vulnerabilities.append(f"Integer overflow: num_entries * 16 = {index_table_size}")

        # Check if index table overlaps with key/data tables
        index_table_end = SFOHeader.SIZE + index_table_size
        if index_table_end > self.header.key_table_offset:
            self.vulnerabilities.append(f"Index table overlaps key table!")

    def _check_entry_vulnerabilities(self, entry: SFOIndexEntry):
        """Check for exploitable conditions in index entry"""

        # Check for size mismatches
        if entry.param_length > entry.param_max_length:
            self.vulnerabilities.append(
                f"Entry {entry.index}: param_length ({entry.param_length}) > param_max_length ({entry.param_max_length})")

        # Check for huge allocations
        if entry.param_max_length > 0x100000:  # > 1MB
            self.vulnerabilities.append(
                f"Entry {entry.index}: Huge param_max_length: {entry.param_max_length}")

        # Check key offset bounds
        key_abs_offset = self.header.key_table_offset + entry.key_offset
        if key_abs_offset > len(self.data):
            self.vulnerabilities.append(
                f"Entry {entry.index}: Key offset 0x{key_abs_offset:X} beyond file")

        # Check data offset bounds
        data_abs_offset = self.header.data_table_offset + entry.data_offset
        if data_abs_offset > len(self.data):
            self.vulnerabilities.append(
                f"Entry {entry.index}: Data offset 0x{data_abs_offset:X} beyond file")

    def print_vulnerabilities(self):
        print("\n" + "="*60)
        print("[!] VULNERABILITY ANALYSIS")
        print("="*60)

        if not self.vulnerabilities:
            print("[*] No obvious vulnerabilities found in this file.")
            print("[*] However, the PARSER may still be vulnerable to:")
        else:
            print(f"[!] Found {len(self.vulnerabilities)} potential issues:\n")
            for vuln in self.vulnerabilities:
                print(f"  [!] {vuln}")
            print()

        print("""
EXPLOITATION VECTORS (from sfo.c analysis):
============================================
1. OUT-OF-BOUNDS READ via key_offset
   - sfo.c line 107: strdup(sfo + key_table_offset + key_offset)
   - No bounds check, reads until null terminator
   - ATTACK: Set key_offset to point near end of file, leak heap data

2. OUT-OF-BOUNDS READ/WRITE via data_offset
   - sfo.c line 114: memcpy using param_max_length
   - ATTACK: Set data_offset beyond file, read uninitialized heap

3. INTEGER OVERFLOW in index calculation
   - sfo.c line 97: sizeof(header) + i * sizeof(index_table)
   - ATTACK: Set num_entries to cause 32-bit wrap

4. HEAP OVERFLOW via param_max_length
   - sfo.c line 111: malloc(param_max_length)
   - sfo.c line 114: memcpy(param->value, data, param->actual_length)
   - ATTACK: If param_max_length < actual data size, heap overflow

5. NULL TERMINATOR ISSUES
   - strdup on keys assumes null termination
   - ATTACK: Remove null terminator, cause unbounded read
""")

    def hexdump(self, offset: int = 0, length: int = 256):
        """Print hex dump of file"""
        print(f"\n[*] Hex dump at offset 0x{offset:X}, length {length}:")
        end = min(offset + length, len(self.data))

        for i in range(offset, end, 16):
            hex_part = ' '.join(f'{self.data[j]:02X}' for j in range(i, min(i+16, end)))
            ascii_part = ''.join(
                chr(self.data[j]) if 32 <= self.data[j] < 127 else '.'
                for j in range(i, min(i+16, end))
            )
            print(f"  {i:08X}  {hex_part:<48}  {ascii_part}")

    def save_modified(self, output_path: str, modifications: Dict):
        """Save modified SFO file"""
        new_data = bytearray(self.data)

        for field, value in modifications.items():
            if field == 'num_entries':
                struct.pack_into('<I', new_data, 16, value)
            elif field == 'key_table_offset':
                struct.pack_into('<I', new_data, 8, value)
            elif field == 'data_table_offset':
                struct.pack_into('<I', new_data, 12, value)
            # Add more modification options as needed

        with open(output_path, 'wb') as f:
            f.write(new_data)
        print(f"[+] Saved modified SFO to {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python sfo_analyzer.py <PARAM.SFO> [--hexdump] [--modify]")
        print("\nPlace your PARAM.SFO and P3PSAVE.BIN files in this directory:")
        print("  /home/user/etaHEN/research/psp_saves/")
        sys.exit(1)

    filepath = sys.argv[1]

    analyzer = SFOAnalyzer(filepath)
    if not analyzer.load():
        sys.exit(1)

    if not analyzer.parse():
        sys.exit(1)

    if '--hexdump' in sys.argv:
        analyzer.hexdump(0, 512)

    analyzer.print_vulnerabilities()

    # Print attack suggestions
    print("""
NEXT STEPS FOR EXPLOITATION:
============================
1. Copy this PARAM.SFO to test variations
2. Modify specific fields to trigger vulnerabilities:
   - Set key_offset = 0xFFFF (out of bounds)
   - Set num_entries = 0xFFFFFFFF (integer overflow)
   - Set param_max_length = 0x10000000 (huge allocation)
   - Remove null terminators from strings

3. Test on PS5 by replacing save file
4. Monitor klog (port 9081) for crashes
5. Use PS5Debug to catch exceptions
""")


if __name__ == '__main__':
    main()
