#!/usr/bin/env python3
"""
SFO Fuzzer - Generate malformed PARAM.SFO files to trigger parser vulnerabilities

Attack Vectors:
1. Out-of-bounds key_offset - leak heap data
2. Out-of-bounds data_offset - read beyond buffer
3. Integer overflow in num_entries - wrap index calculation
4. Huge param_max_length - heap exhaustion or overflow
5. Missing null terminators - unbounded string reads
6. Overlapping tables - corrupt adjacent data
7. Negative/huge sizes - integer underflow
"""

import struct
import sys
import os
import shutil
from pathlib import Path

# SFO Constants
SFO_MAGIC = 0x46535000
SFO_VERSION = 0x0101

FMT_BINARY = 0x0004
FMT_STRING = 0x0204
FMT_INT32 = 0x0404

class SFOFuzzer:
    def __init__(self, template_path: str):
        self.template_path = template_path
        with open(template_path, 'rb') as f:
            self.original = bytearray(f.read())

        self.output_dir = Path("fuzzed_saves")
        self.output_dir.mkdir(exist_ok=True)

        print(f"[+] Loaded template: {template_path} ({len(self.original)} bytes)")

    def save(self, data: bytearray, name: str) -> str:
        """Save fuzzed file"""
        output_path = self.output_dir / f"PARAM.SFO.{name}"
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"[+] Generated: {output_path}")
        return str(output_path)

    def fuzz_num_entries_overflow(self) -> str:
        """
        Attack: Set num_entries to 0xFFFFFFFF
        Effect: Integer overflow in loop: sizeof(header) + i * sizeof(index_table)
                Could wrap around and access unexpected memory
        """
        data = bytearray(self.original)
        # num_entries is at offset 16 (0x10)
        struct.pack_into('<I', data, 16, 0xFFFFFFFF)
        return self.save(data, "num_entries_overflow")

    def fuzz_num_entries_large(self) -> str:
        """
        Attack: Set num_entries to large but not max value
        Effect: Read many index entries beyond file bounds
        """
        data = bytearray(self.original)
        struct.pack_into('<I', data, 16, 0x10000)  # 65536 entries
        return self.save(data, "num_entries_large")

    def fuzz_key_table_offset_oob(self) -> str:
        """
        Attack: Set key_table_offset beyond file size
        Effect: strdup() reads from unmapped memory or heap
        """
        data = bytearray(self.original)
        # key_table_offset at offset 8
        struct.pack_into('<I', data, 8, 0xFFFF0000)
        return self.save(data, "key_table_oob")

    def fuzz_data_table_offset_oob(self) -> str:
        """
        Attack: Set data_table_offset beyond file size
        Effect: memcpy reads from unmapped memory
        """
        data = bytearray(self.original)
        # data_table_offset at offset 12
        struct.pack_into('<I', data, 12, 0xFFFF0000)
        return self.save(data, "data_table_oob")

    def fuzz_key_offset_oob(self) -> str:
        """
        Attack: Set first entry's key_offset to point beyond file
        Effect: strdup() reads garbage, potential info leak
        """
        data = bytearray(self.original)
        # First index entry starts at offset 20
        # key_offset is first 2 bytes
        struct.pack_into('<H', data, 20, 0xFFFF)
        return self.save(data, "key_offset_oob")

    def fuzz_data_offset_oob(self) -> str:
        """
        Attack: Set first entry's data_offset beyond file
        Effect: memcpy reads beyond buffer
        """
        data = bytearray(self.original)
        # data_offset is at index_entry + 12
        struct.pack_into('<I', data, 20 + 12, 0xFFFF0000)
        return self.save(data, "data_offset_oob")

    def fuzz_param_max_length_huge(self) -> str:
        """
        Attack: Set param_max_length to huge value
        Effect: malloc(0x7FFFFFFF) - heap exhaustion or controlled allocation
        """
        data = bytearray(self.original)
        # param_max_length at index_entry + 8
        struct.pack_into('<I', data, 20 + 8, 0x7FFFFFFF)
        return self.save(data, "param_max_length_huge")

    def fuzz_param_length_gt_max(self) -> str:
        """
        Attack: Set param_length > param_max_length
        Effect: Potential heap overflow in copy
        """
        data = bytearray(self.original)
        # param_length at index_entry + 4, param_max_length at + 8
        struct.pack_into('<I', data, 20 + 4, 0x10000)  # length = 64KB
        struct.pack_into('<I', data, 20 + 8, 0x100)    # max_length = 256
        return self.save(data, "length_gt_max")

    def fuzz_remove_null_terminator(self) -> str:
        """
        Attack: Remove null terminator from CATEGORY key
        Effect: strdup() reads beyond intended string
        """
        data = bytearray(self.original)
        # Find "CATEGORY" string and remove its null terminator
        # In original: key_table starts at 0x94
        key_table_off = struct.unpack('<I', data[8:12])[0]
        # "CATEGORY" is first key, followed by null
        # Replace null with 'X'
        cat_end = key_table_off + 8  # len("CATEGORY")
        if data[cat_end] == 0:
            data[cat_end] = ord('X')
        return self.save(data, "no_null_terminator")

    def fuzz_overlapping_tables(self) -> str:
        """
        Attack: Make key_table and data_table overlap
        Effect: Parsing one table corrupts the other
        """
        data = bytearray(self.original)
        # Set data_table to start inside key_table
        key_table_off = struct.unpack('<I', data[8:12])[0]
        struct.pack_into('<I', data, 12, key_table_off + 4)
        return self.save(data, "overlapping_tables")

    def fuzz_negative_offset(self) -> str:
        """
        Attack: Use negative offset (wraps to large positive)
        Effect: Read from address before buffer start
        """
        data = bytearray(self.original)
        # Set data_offset to -1 (0xFFFFFFFF)
        struct.pack_into('<I', data, 20 + 12, 0xFFFFFFFF)
        return self.save(data, "negative_offset")

    def fuzz_zero_size_entry(self) -> str:
        """
        Attack: Set param_length and param_max_length to 0
        Effect: Edge case - malloc(0), memcpy with 0 size
        """
        data = bytearray(self.original)
        struct.pack_into('<I', data, 20 + 4, 0)  # length = 0
        struct.pack_into('<I', data, 20 + 8, 0)  # max_length = 0
        return self.save(data, "zero_size")

    def fuzz_format_string(self) -> str:
        """
        Attack: Insert format string specifiers in SAVEDATA_DETAIL
        Effect: If printf'd without format, could leak stack data
        """
        data = bytearray(self.original)
        # Find SAVEDATA_DETAIL data location
        # Entry 2: data_offset = 0x08 from data_table
        data_table_off = struct.unpack('<I', data[12:16])[0]
        detail_offset = data_table_off + 0x08

        # Craft format string payload
        payload = b"%s%s%s%s%n%n%n%n" + b"\x00" * 100

        # Replace data
        for i, b in enumerate(payload):
            if detail_offset + i < len(data):
                data[detail_offset + i] = b

        return self.save(data, "format_string")

    def fuzz_long_string(self) -> str:
        """
        Attack: Create extremely long string in SAVEDATA_DETAIL
        Effect: Buffer overflow if destination is fixed size
        """
        data = bytearray(self.original)
        data_table_off = struct.unpack('<I', data[12:16])[0]
        detail_offset = data_table_off + 0x08

        # Create long string (fills max_length of 1024)
        payload = b"A" * 1023 + b"\x00"

        for i, b in enumerate(payload):
            if detail_offset + i < len(data):
                data[detail_offset + i] = b

        return self.save(data, "long_string")

    def fuzz_invalid_magic(self) -> str:
        """
        Attack: Corrupt magic bytes
        Effect: Test error handling path
        """
        data = bytearray(self.original)
        struct.pack_into('<I', data, 0, 0xDEADBEEF)
        return self.save(data, "invalid_magic")

    def fuzz_all_entries_oob(self) -> str:
        """
        Attack: Make ALL index entries point out of bounds
        Effect: Systematic OOB access
        """
        data = bytearray(self.original)
        num_entries = struct.unpack('<I', data[16:20])[0]

        for i in range(num_entries):
            entry_offset = 20 + i * 16
            if entry_offset + 16 <= len(data):
                struct.pack_into('<H', data, entry_offset, 0xFFFF)      # key_offset
                struct.pack_into('<I', data, entry_offset + 12, 0xFFFF0000)  # data_offset

        return self.save(data, "all_entries_oob")

    def generate_all(self):
        """Generate all fuzzed variants"""
        print("\n" + "="*60)
        print("[*] GENERATING FUZZED PARAM.SFO FILES")
        print("="*60 + "\n")

        tests = [
            ("Integer Overflow: num_entries = 0xFFFFFFFF", self.fuzz_num_entries_overflow),
            ("Large num_entries: 65536 entries", self.fuzz_num_entries_large),
            ("OOB: key_table_offset beyond file", self.fuzz_key_table_offset_oob),
            ("OOB: data_table_offset beyond file", self.fuzz_data_table_offset_oob),
            ("OOB: key_offset in first entry", self.fuzz_key_offset_oob),
            ("OOB: data_offset in first entry", self.fuzz_data_offset_oob),
            ("Huge allocation: param_max_length = 2GB", self.fuzz_param_max_length_huge),
            ("Heap overflow: length > max_length", self.fuzz_param_length_gt_max),
            ("Missing null terminator", self.fuzz_remove_null_terminator),
            ("Overlapping key/data tables", self.fuzz_overlapping_tables),
            ("Negative offset (wrap around)", self.fuzz_negative_offset),
            ("Zero size entry", self.fuzz_zero_size_entry),
            ("Format string injection", self.fuzz_format_string),
            ("Long string (1023 bytes)", self.fuzz_long_string),
            ("Invalid magic", self.fuzz_invalid_magic),
            ("All entries OOB", self.fuzz_all_entries_oob),
        ]

        generated = []
        for desc, func in tests:
            print(f"\n[*] {desc}")
            try:
                path = func()
                generated.append((desc, path))
            except Exception as e:
                print(f"    [-] Failed: {e}")

        print("\n" + "="*60)
        print(f"[+] Generated {len(generated)} test cases in {self.output_dir}/")
        print("="*60)

        return generated


def create_test_save_package(fuzzer: SFOFuzzer, test_name: str, output_dir: str = "test_saves"):
    """
    Create a complete save package ready for PS5 testing
    Copies all original save files but replaces PARAM.SFO
    """
    base_dir = Path(fuzzer.template_path).parent
    out_dir = Path(output_dir) / test_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy all files from original save
    for f in base_dir.iterdir():
        if f.name != "PARAM.SFO":
            shutil.copy(f, out_dir / f.name)

    # Copy fuzzed PARAM.SFO
    fuzzed_sfo = fuzzer.output_dir / f"PARAM.SFO.{test_name}"
    if fuzzed_sfo.exists():
        shutil.copy(fuzzed_sfo, out_dir / "PARAM.SFO")
        print(f"[+] Created test package: {out_dir}/")
        return str(out_dir)
    else:
        print(f"[-] Fuzzed SFO not found: {fuzzed_sfo}")
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python sfo_fuzzer.py <PARAM.SFO> [--package]")
        print("\nGenerates fuzzed PARAM.SFO variants to test parser vulnerabilities")
        print("\nOptions:")
        print("  --package    Also create complete save packages for testing")
        sys.exit(1)

    template = sys.argv[1]
    create_packages = '--package' in sys.argv

    fuzzer = SFOFuzzer(template)
    generated = fuzzer.generate_all()

    if create_packages:
        print("\n[*] Creating test save packages...")
        for desc, path in generated:
            test_name = Path(path).name.replace("PARAM.SFO.", "")
            create_test_save_package(fuzzer, test_name)

    print("""
TESTING INSTRUCTIONS:
=====================
1. Copy a fuzzed save to your PS5:
   - FTP to PS5 port 1337
   - Navigate to /user/home/<user_id>/savedata/CUSA33872/
   - Replace files in the save directory

2. On PS5, re-encrypt the save:
   - The save system should automatically handle this
   - OR use etaHEN's kernel to manipulate PFS directly

3. Launch Persona 3 Portable and load the save

4. Monitor for crashes:
   - nc <PS5_IP> 9081  (klog output)
   - PS5Debug for exception details

5. If crash occurs:
   - Document register state
   - Note crash address
   - Identify vulnerable code path

PRIORITY TARGETS:
================
1. num_entries_overflow - Most likely to cause crash
2. key_offset_oob - Info leak potential
3. param_max_length_huge - Heap corruption
4. length_gt_max - Classic heap overflow
""")


if __name__ == '__main__':
    main()
