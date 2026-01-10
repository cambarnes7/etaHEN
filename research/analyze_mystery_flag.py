#!/usr/bin/env python3
"""
Deep analysis of the mystery flag at 0xD11D08
This flag is WRITABLE and bypasses CFI!
"""

import sys
import struct

def read_u32(data, offset):
    return struct.unpack('<I', data[offset:offset+4])[0]

def read_u64(data, offset):
    return struct.unpack('<Q', data[offset:offset+8])[0]

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_mystery_flag.py kernel_data.bin")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print(f"Loaded {len(data)} bytes")

    # Key offsets
    MYSTERY_FLAG = 0xD11D08
    MYSTERY_MASK = 0xD11D0C
    SYSENTVEC_PS5 = 0xD11BB8
    SYSENTVEC_PS4 = 0xD11D30

    print("\n" + "="*70)
    print("MYSTERY FLAG DEEP ANALYSIS")
    print("="*70)

    flag_val = read_u32(data, MYSTERY_FLAG)
    mask_val = read_u32(data, MYSTERY_MASK)

    print(f"\nMystery Flag @ 0x{MYSTERY_FLAG:08X}: 0x{flag_val:08X}")
    print(f"Mystery Mask @ 0x{MYSTERY_MASK:08X}: 0x{mask_val:08X}")
    print(f"Mask in binary: {bin(mask_val)}")
    print(f"Number of mask bits: {bin(mask_val).count('1')}")

    # Show exact context - 256 bytes around the flag
    print("\n" + "-"*70)
    print("CONTEXT: 256 bytes around mystery flag")
    print("-"*70)

    start = MYSTERY_FLAG - 128
    for i in range(start, MYSTERY_FLAG + 128, 16):
        offset_from_flag = i - MYSTERY_FLAG
        marker = " <-- FLAG" if i == MYSTERY_FLAG else ""
        hex_bytes = " ".join(f"{data[i+j]:02X}" for j in range(16))

        # Try to interpret as ASCII too
        ascii_str = ""
        for j in range(16):
            c = data[i+j]
            ascii_str += chr(c) if 32 <= c < 127 else "."

        print(f"  0x{i:08X} ({offset_from_flag:+4d}): {hex_bytes}  |{ascii_str}|{marker}")

    # Analyze the structure between sysentvecs
    print("\n" + "-"*70)
    print(f"STRUCTURE BETWEEN SYSENTVECS (0x{SYSENTVEC_PS5:X} - 0x{SYSENTVEC_PS4:X})")
    print("-"*70)

    gap_start = SYSENTVEC_PS5 + 0x100  # After sysentvec_ps5 main fields
    gap_end = SYSENTVEC_PS4
    gap_size = gap_end - gap_start

    print(f"Gap size: 0x{gap_size:X} bytes ({gap_size} bytes)")
    print(f"Mystery flag offset from gap start: 0x{MYSTERY_FLAG - gap_start:X}")
    print(f"Mystery flag offset from sysentvec_ps5: 0x{MYSTERY_FLAG - SYSENTVEC_PS5:X}")

    # Look for patterns in the gap
    print("\n" + "-"*70)
    print("NON-ZERO DATA IN THE GAP:")
    print("-"*70)

    for i in range(gap_start, gap_end, 8):
        val = read_u64(data, i)
        if val != 0:
            val32_lo = read_u32(data, i)
            val32_hi = read_u32(data, i + 4)

            # Describe the value
            desc = ""
            if val < 0x100:
                desc = f"small int: {val}"
            elif val == 0x0FFFFFFF:
                desc = "28-bit mask"
            elif (val >> 32) == 0xFFFFFFFF:
                desc = f"kernel ptr? -> 0x{val:016X}"
            elif val < 0x10000:
                desc = f"flags? 0x{val:X}"

            offset_from_ps5 = i - SYSENTVEC_PS5
            print(f"  0x{i:08X} (+0x{offset_from_ps5:03X}): lo=0x{val32_lo:08X} hi=0x{val32_hi:08X}  {desc}")

    # Calculate exact offset from sysentvec base
    print("\n" + "-"*70)
    print("KEY OFFSETS FROM SYSENTVEC_PS5 BASE:")
    print("-"*70)

    offsets = {
        "sv_sigsize (+0x0E/+14)": SYSENTVEC_PS5 + 0x0E,
        "Mystery flag (+0x150)": MYSTERY_FLAG,
        "Mystery mask (+0x154)": MYSTERY_MASK,
    }

    for name, offset in offsets.items():
        val = read_u32(data, offset)
        print(f"  {name}: 0x{offset:08X} = 0x{val:08X}")

    # Search for other 0x0FFFFFFF masks (might be related structures)
    print("\n" + "-"*70)
    print("SEARCHING FOR OTHER 0x0FFFFFFF MASKS:")
    print("-"*70)

    for i in range(0, len(data) - 4, 4):
        val = read_u32(data, i)
        if val == 0x0FFFFFFF:
            # Check context
            before = read_u32(data, i - 4) if i >= 4 else 0
            after = read_u32(data, i + 4) if i + 4 < len(data) else 0
            print(f"  0x{i:08X}: before=0x{before:08X}, mask=0x0FFFFFFF, after=0x{after:08X}")

    # Look for the value 0x01 followed by 0x0FFFFFFF pattern elsewhere
    print("\n" + "-"*70)
    print("SEARCHING FOR 0x01 + 0x0FFFFFFF PATTERN:")
    print("-"*70)

    for i in range(0, len(data) - 8, 4):
        val1 = read_u32(data, i)
        val2 = read_u32(data, i + 4)
        if val1 == 0x00000001 and val2 == 0x0FFFFFFF:
            print(f"  Found at 0x{i:08X}")

    # Summary
    print("\n" + "="*70)
    print("ANALYSIS SUMMARY")
    print("="*70)
    print(f"""
MYSTERY FLAG DETAILS:
  - Location: 0x{MYSTERY_FLAG:08X} (kdata_base + 0xD11D08)
  - Current value: 0x{flag_val:08X} (1)
  - Associated mask: 0x{mask_val:08X} (0x0FFFFFFF = 28 bits)
  - Offset from sysentvec_ps5: +0x{MYSTERY_FLAG - SYSENTVEC_PS5:X} (+336 bytes)

POSSIBLE INTERPRETATIONS:
  1. This could be a "compat mode" or "ABI version" flag
  2. The 28-bit mask suggests it's an index or capability field
  3. Located between two sysentvec structures = ABI-related

NEXT STEPS FOR IDA:
  1. Find cross-references to kdata_base + 0xD11D08
  2. Look for code that reads this flag and branches on it
  3. Search for code using mask 0x0FFFFFFF
  4. Check if this affects privilege checks or HV behavior
""")

if __name__ == "__main__":
    main()
