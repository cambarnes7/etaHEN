#!/usr/bin/env python3
"""
Luac0re Shellcode Loader for PS5

This script prepares Luac0re's emulator escape shellcode for injection
into PS2 memory via ps5debug.

The shellcode must be written to PS2 memory BEFORE triggering the
Hall of Fame overflow, which will then jump to this shellcode.

Target Address Mapping:
  PS2 Address:    0x00500000 (in PS2's 32-bit address space)
  PS2 KSEG0:      0x80500000 (cached access via KSEG0)
  Native PS5:    0x8000000500000 (64-bit address for ps5debug)

Usage:
  1. Run this script to prepare the shellcode
  2. Use ps5debug/ps4reaper to write to 0x8000000500000
  3. Inject Hall of Fame payload (see luac0re_hall_of_fame_payload.py)
  4. Trigger Hall of Fame in game
"""

import struct
import os

# Configuration
PS2_TARGET_ADDR = 0x00500000       # PS2 address (32-bit)
PS2_KSEG0_ADDR = 0x80500000        # PS2 KSEG0 address
NATIVE_TARGET_ADDR = 0x8000000500000  # Native PS5 address for ps5debug

def load_shellcode():
    """Load the extracted Luac0re shellcode"""
    shellcode_paths = [
        '../Luac0re/ps2/extracted_shellcode.bin',  # Extracted from PSU
        '../Luac0re/ps2/shellcode/shellcode.bin',  # Built from source
        'extracted_shellcode.bin',
        'shellcode.bin',
    ]

    for path in shellcode_paths:
        full_path = os.path.join(os.path.dirname(__file__), path)
        if os.path.exists(full_path):
            with open(full_path, 'rb') as f:
                return f.read(), full_path

    return None, None

def main():
    shellcode, source_path = load_shellcode()

    print("=" * 70)
    print("Luac0re Shellcode Loader for PS5 mast1c0re Research")
    print("=" * 70)
    print()

    if shellcode is None:
        print("ERROR: Shellcode not found!")
        print("Run the extraction first from the Luac0re PSU file.")
        return

    print(f"Source: {source_path}")
    print(f"Shellcode size: {len(shellcode)} bytes (0x{len(shellcode):X})")
    print()
    print("Target Addresses:")
    print(f"  PS2 Address:    0x{PS2_TARGET_ADDR:08X}")
    print(f"  PS2 KSEG0:      0x{PS2_KSEG0_ADDR:08X}")
    print(f"  Native (PS5):   0x{NATIVE_TARGET_ADDR:016X}")
    print()

    # Verify shellcode starts with valid MIPS code
    if len(shellcode) >= 4:
        first_word = struct.unpack('<I', shellcode[:4])[0]
        print(f"First MIPS instruction: 0x{first_word:08X}")
        # lui $sp, 0x01C0 = 0x3C1D01C0
        if first_word == 0x3C1D01C0:
            print("  → lui $sp, 0x01C0 (valid Luac0re entry)")
        print()

    # Save shellcode ready for loading
    output_file = 'luac0re_shellcode_ready.bin'
    with open(output_file, 'wb') as f:
        f.write(shellcode)
    print(f"Saved shellcode to: {output_file}")
    print()

    # Instructions
    print("=" * 70)
    print("NEXT STEPS:")
    print("=" * 70)
    print()
    print("1. Write shellcode to PS5 memory using ps5debug:")
    print()
    print(f"   Address: 0x{NATIVE_TARGET_ADDR:X}")
    print(f"   Size: {len(shellcode)} bytes")
    print(f"   File: {output_file}")
    print()
    print("2. In ps4reaper or your tool, load and write the binary file")
    print()
    print("3. Then inject the Hall of Fame payload:")
    print("   python3 luac0re_hall_of_fame_payload.py")
    print()
    print("4. Trigger: Options → Hall of Fame")
    print()

    # Generate hex chunks for manual entry if needed
    print("=" * 70)
    print("FIRST 128 BYTES OF SHELLCODE (for verification):")
    print("=" * 70)
    print()
    hex_str = shellcode[:128].hex().upper()
    for i in range(0, len(hex_str), 64):
        offset = i // 2
        row = hex_str[i:i+64]
        spaced = ' '.join(row[j:j+2] for j in range(0, len(row), 2))
        print(f"  +{offset:03X}: {spaced}")

    return shellcode

if __name__ == "__main__":
    main()
