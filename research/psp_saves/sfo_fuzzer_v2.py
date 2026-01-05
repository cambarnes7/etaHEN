#!/usr/bin/env python3
"""
SFO Fuzzer v2 - Subtle mutations that pass validation but may trigger bugs

Lessons from v1:
- Obvious OOB offsets are caught by validation
- Huge allocations don't crash (likely clamped)
- Need to stay within bounds but create subtle corruption

New strategies:
1. Off-by-one errors (just past valid bounds)
2. Integer edge cases (0x7FFFFFFF, 0x80000000)
3. String encoding attacks (UTF-8 overlong, invalid sequences)
4. Hash/checksum manipulation
5. Type confusion (wrong format type for data)
6. Boundary values that pass checks but cause math errors
"""

import struct
import sys
import os
import shutil
from pathlib import Path

SFO_MAGIC = 0x46535000
SFO_VERSION = 0x0101

FMT_BINARY = 0x0004
FMT_STRING = 0x0204
FMT_INT32 = 0x0404

class SFOFuzzerV2:
    def __init__(self, template_path: str):
        self.template_path = template_path
        with open(template_path, 'rb') as f:
            self.original = bytearray(f.read())

        self.output_dir = Path("fuzzed_saves_v2")
        self.output_dir.mkdir(exist_ok=True)

        # Parse original structure
        self.file_size = len(self.original)
        self.key_table_off = struct.unpack('<I', self.original[8:12])[0]
        self.data_table_off = struct.unpack('<I', self.original[12:16])[0]
        self.num_entries = struct.unpack('<I', self.original[16:20])[0]

        print(f"[+] Template: {template_path} ({self.file_size} bytes)")
        print(f"    key_table: 0x{self.key_table_off:X}, data_table: 0x{self.data_table_off:X}, entries: {self.num_entries}")

    def save(self, data: bytearray, name: str) -> str:
        output_path = self.output_dir / f"PARAM.SFO.{name}"
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"[+] Generated: {output_path}")
        return str(output_path)

    # === OFF-BY-ONE ATTACKS ===

    def fuzz_key_offset_off_by_one(self) -> str:
        """Set key_offset to point at last byte of key table"""
        data = bytearray(self.original)
        # Calculate end of key table (start of data table)
        last_valid = self.data_table_off - self.key_table_off - 1
        struct.pack_into('<H', data, 20, last_valid)  # First entry key_offset
        return self.save(data, "key_off_by_one")

    def fuzz_data_end_of_file(self) -> str:
        """Set data_offset to point at last byte of file"""
        data = bytearray(self.original)
        last_byte = self.file_size - self.data_table_off - 1
        struct.pack_into('<I', data, 20 + 12, last_byte)
        return self.save(data, "data_end_of_file")

    def fuzz_length_equals_max(self) -> str:
        """Set param_length exactly equal to param_max_length (edge case)"""
        data = bytearray(self.original)
        # Set both to same value
        struct.pack_into('<I', data, 20 + 4, 1024)   # length
        struct.pack_into('<I', data, 20 + 8, 1024)   # max_length
        return self.save(data, "length_equals_max")

    # === INTEGER EDGE CASES ===

    def fuzz_signed_boundary(self) -> str:
        """Use 0x7FFFFFFF (max signed 32-bit) for sizes"""
        data = bytearray(self.original)
        # This might pass unsigned checks but fail signed comparisons
        struct.pack_into('<I', data, 20 + 4, 0x7FFFFFFF)  # length
        struct.pack_into('<I', data, 20 + 8, 0x7FFFFFFF)  # max_length
        return self.save(data, "signed_boundary")

    def fuzz_one_less_than_overflow(self) -> str:
        """num_entries just under overflow threshold"""
        data = bytearray(self.original)
        # Calculate max entries that fit in file
        max_entries = (self.key_table_off - 20) // 16
        struct.pack_into('<I', data, 16, max_entries + 1)  # One more than fits
        return self.save(data, "entries_plus_one")

    def fuzz_size_near_filesize(self) -> str:
        """param_max_length near file size"""
        data = bytearray(self.original)
        struct.pack_into('<I', data, 20 + 8, self.file_size - 1)
        return self.save(data, "size_near_filesize")

    # === STRING ENCODING ATTACKS ===

    def fuzz_utf8_overlong(self) -> str:
        """Insert overlong UTF-8 encoding (potential filter bypass)"""
        data = bytearray(self.original)
        # Overlong encoding of '/' (0x2F) as 0xC0 0xAF
        # This is invalid UTF-8 but might bypass path checks
        detail_offset = self.data_table_off + 0x08
        # Insert overlong sequences
        payload = b"\xC0\xAF\xC0\xAE\xC0\xAE\xC0\xAF"  # Overlong "/../"
        for i, b in enumerate(payload):
            if detail_offset + i < len(data):
                data[detail_offset + i] = b
        return self.save(data, "utf8_overlong")

    def fuzz_null_in_middle(self) -> str:
        """Put null byte in middle of string (truncation attack)"""
        data = bytearray(self.original)
        detail_offset = self.data_table_off + 0x08
        # "4/7 (Tu)\x00INJECTED PAYLOAD"
        payload = b"4/7 (Tu)\x00" + b"A" * 50
        for i, b in enumerate(payload):
            if detail_offset + i < len(data):
                data[detail_offset + i] = b
        return self.save(data, "null_in_middle")

    def fuzz_high_ascii(self) -> str:
        """Use bytes 0x80-0xFF in strings"""
        data = bytearray(self.original)
        detail_offset = self.data_table_off + 0x08
        payload = bytes(range(0x80, 0x100)) + b"\x00"
        for i, b in enumerate(payload):
            if detail_offset + i < len(data):
                data[detail_offset + i] = b
        return self.save(data, "high_ascii")

    # === TYPE CONFUSION ===

    def fuzz_string_as_int(self) -> str:
        """Change CATEGORY (string) format to INT32"""
        data = bytearray(self.original)
        # First entry is CATEGORY, format at offset 22
        struct.pack_into('<H', data, 22, FMT_INT32)
        return self.save(data, "string_as_int")

    def fuzz_int_as_string(self) -> str:
        """Change PARENTAL_LEVEL (int) format to STRING"""
        data = bytearray(self.original)
        # Second entry format at offset 20 + 16 + 2 = 38
        struct.pack_into('<H', data, 38, FMT_STRING)
        return self.save(data, "int_as_string")

    def fuzz_binary_as_string(self) -> str:
        """Change SAVEDATA_FILE_LIST (binary) format to STRING"""
        data = bytearray(self.original)
        # Fifth entry (index 4), format at 20 + 4*16 + 2 = 86
        struct.pack_into('<H', data, 86, FMT_STRING)
        return self.save(data, "binary_as_string")

    # === SAVEDATA_FILE_LIST MANIPULATION ===
    # This is the most interesting target - it lists files and their hashes

    def fuzz_file_list_bad_filename(self) -> str:
        """Corrupt the filename in SAVEDATA_FILE_LIST"""
        data = bytearray(self.original)
        # SAVEDATA_FILE_LIST starts at data_table + 0x448
        file_list_off = self.data_table_off + 0x448
        # First 13 bytes are filename, replace with path traversal
        payload = b"../../../etc"
        for i, b in enumerate(payload):
            if file_list_off + i < len(data):
                data[file_list_off + i] = b
        return self.save(data, "file_list_traversal")

    def fuzz_file_list_long_name(self) -> str:
        """Overly long filename in file list"""
        data = bytearray(self.original)
        file_list_off = self.data_table_off + 0x448
        # Fill with 'A's up to the hash area
        payload = b"A" * 32 + b"\x00"
        for i, b in enumerate(payload):
            if file_list_off + i < len(data):
                data[file_list_off + i] = b
        return self.save(data, "file_list_longname")

    def fuzz_file_list_null_hash(self) -> str:
        """Zero out the file hash in SAVEDATA_FILE_LIST"""
        data = bytearray(self.original)
        file_list_off = self.data_table_off + 0x448
        # Hash starts after filename (offset ~13-16)
        hash_off = file_list_off + 16
        for i in range(32):  # Zero 32 bytes of hash
            if hash_off + i < len(data):
                data[hash_off + i] = 0
        return self.save(data, "file_list_nullhash")

    # === SAVEDATA_PARAMS MANIPULATION ===
    # Contains user IDs, PSID, account ID

    def fuzz_params_bad_userid(self) -> str:
        """Set user_id to 0xFFFFFFFF"""
        data = bytearray(self.original)
        # SAVEDATA_PARAMS at data_table + 0x10A8
        params_off = self.data_table_off + 0x10A8
        # user_id_1 at offset 16, user_id_2 at offset 36
        struct.pack_into('<I', data, params_off + 16, 0xFFFFFFFF)
        struct.pack_into('<I', data, params_off + 36, 0xFFFFFFFF)
        return self.save(data, "params_bad_userid")

    def fuzz_params_zero_psid(self) -> str:
        """Zero out PSID (console identifier)"""
        data = bytearray(self.original)
        params_off = self.data_table_off + 0x10A8
        # PSID at offset 20, 16 bytes
        for i in range(16):
            data[params_off + 20 + i] = 0
        return self.save(data, "params_zero_psid")

    # === SUBTLE CORRUPTION ===

    def fuzz_swap_entries(self) -> str:
        """Swap first two index entries"""
        data = bytearray(self.original)
        entry1 = data[20:36]
        entry2 = data[36:52]
        data[20:36] = entry2
        data[36:52] = entry1
        return self.save(data, "swapped_entries")

    def fuzz_duplicate_key(self) -> str:
        """Make two entries point to same key"""
        data = bytearray(self.original)
        # Copy first entry's key_offset to second entry
        key_off = struct.unpack('<H', data[20:22])[0]
        struct.pack_into('<H', data, 36, key_off)
        return self.save(data, "duplicate_key")

    def fuzz_circular_offset(self) -> str:
        """Set data_offset to point back to header"""
        data = bytearray(self.original)
        # This creates data that overlaps with SFO header
        # Negative relative to data_table = points before it
        # We need an offset that when added to data_table gives us < 20
        # Since we can't use negative, we'll point to index table area
        struct.pack_into('<I', data, 20 + 12, 0)  # data_offset = 0
        # Also need to adjust data_table to be small
        struct.pack_into('<I', data, 12, 20)  # data_table at offset 20 (header end)
        return self.save(data, "circular_offset")

    def generate_all(self):
        """Generate all v2 test cases"""
        print("\n" + "="*60)
        print("[*] GENERATING SUBTLE FUZZ CASES (v2)")
        print("="*60 + "\n")

        tests = [
            # Off-by-one
            ("Off-by-one: key at end of table", self.fuzz_key_offset_off_by_one),
            ("Off-by-one: data at end of file", self.fuzz_data_end_of_file),
            ("Edge: length exactly equals max", self.fuzz_length_equals_max),

            # Integer edge cases
            ("Integer: signed boundary (0x7FFFFFFF)", self.fuzz_signed_boundary),
            ("Integer: entries+1 beyond capacity", self.fuzz_one_less_than_overflow),
            ("Integer: size near file size", self.fuzz_size_near_filesize),

            # String encoding
            ("UTF-8: overlong encoding", self.fuzz_utf8_overlong),
            ("String: null in middle", self.fuzz_null_in_middle),
            ("String: high ASCII bytes", self.fuzz_high_ascii),

            # Type confusion
            ("Type: string field as int", self.fuzz_string_as_int),
            ("Type: int field as string", self.fuzz_int_as_string),
            ("Type: binary field as string", self.fuzz_binary_as_string),

            # File list manipulation
            ("FileList: path traversal", self.fuzz_file_list_bad_filename),
            ("FileList: long filename", self.fuzz_file_list_long_name),
            ("FileList: null hash", self.fuzz_file_list_null_hash),

            # Params manipulation
            ("Params: bad user ID", self.fuzz_params_bad_userid),
            ("Params: zero PSID", self.fuzz_params_zero_psid),

            # Subtle corruption
            ("Subtle: swapped entries", self.fuzz_swap_entries),
            ("Subtle: duplicate key", self.fuzz_duplicate_key),
            ("Subtle: circular offset", self.fuzz_circular_offset),
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
        print(f"[+] Generated {len(generated)} subtle test cases")
        print("="*60)

        return generated


def create_test_packages(fuzzer, base_save_dir):
    """Create complete save packages"""
    test_dir = Path("test_saves_v2")
    test_dir.mkdir(exist_ok=True)

    for sfo_file in fuzzer.output_dir.glob("PARAM.SFO.*"):
        test_name = sfo_file.name.replace("PARAM.SFO.", "")
        pkg_dir = test_dir / test_name
        pkg_dir.mkdir(exist_ok=True)

        # Copy original files
        for f in Path(base_save_dir).iterdir():
            if f.name != "PARAM.SFO":
                shutil.copy(f, pkg_dir / f.name)

        # Copy fuzzed SFO
        shutil.copy(sfo_file, pkg_dir / "PARAM.SFO")
        print(f"[+] Package: {pkg_dir}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python sfo_fuzzer_v2.py <PARAM.SFO> [--package]")
        sys.exit(1)

    template = sys.argv[1]
    fuzzer = SFOFuzzerV2(template)
    fuzzer.generate_all()

    if '--package' in sys.argv:
        base_dir = Path(template).parent
        create_test_packages(fuzzer, base_dir)

    print("""
TESTING PRIORITY (v2):
======================
1. Type confusion (string_as_int, int_as_string, binary_as_string)
   - Parser may not validate format matches data

2. SAVEDATA_FILE_LIST manipulation (traversal, longname, nullhash)
   - This controls which files are loaded and verified

3. String encoding attacks (utf8_overlong, null_in_middle)
   - May bypass string validation/filtering

4. Off-by-one (key_off_by_one, data_end_of_file)
   - Classic vulnerability pattern

5. SAVEDATA_PARAMS (bad_userid, zero_psid)
   - May affect privilege/identity checks
""")


if __name__ == '__main__':
    main()
