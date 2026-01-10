#!/usr/bin/env python3
"""
Analyze the sysentvec structure to find sv_flags and other security fields.
Based on FreeBSD sys/sys/sysent.h structure layout.
"""

import sys
import struct

def read_u16(data, offset):
    return struct.unpack('<H', data[offset:offset+2])[0]

def read_u32(data, offset):
    return struct.unpack('<I', data[offset:offset+4])[0]

def read_u64(data, offset):
    return struct.unpack('<Q', data[offset:offset+8])[0]

def is_kernel_ptr(val):
    return (val >> 32) == 0xFFFFFFFF

def analyze_sysentvec(data, base_offset, name):
    """Analyze a sysentvec structure at the given offset"""
    print(f"\n{'='*70}")
    print(f"SYSENTVEC: {name} @ 0x{base_offset:08X}")
    print(f"{'='*70}")

    # FreeBSD sysentvec structure (approximate layout for amd64):
    # Based on https://github.com/freebsd/freebsd-src/blob/master/sys/sys/sysent.h
    #
    # struct sysentvec {
    #     int             sv_size;        // +0x00: number of syscalls
    #     struct sysent  *sv_table;       // +0x08: syscall table
    #     int             sv_transtrap;   // +0x10:
    #     int             sv_errsize;     // +0x14:
    #     const int      *sv_errtbl;      // +0x18:
    #     ...
    #     int             sv_sigsize;     // around +0x0E or after pointers
    #     ...
    #     u_long          sv_flags;       // ABI flags
    #     ...
    # }

    # Let's dump the first 256 bytes and try to identify fields
    print("\nRaw structure dump (first 256 bytes):")
    for i in range(0, 256, 16):
        offset = base_offset + i
        if offset + 16 > len(data):
            break
        hex_bytes = " ".join(f"{data[offset+j]:02X}" for j in range(16))

        # Try to interpret as values
        val1 = read_u64(data, offset)
        val2 = read_u64(data, offset + 8) if offset + 8 < len(data) else 0

        note1 = "ptr" if is_kernel_ptr(val1) else ""
        note2 = "ptr" if is_kernel_ptr(val2) else ""

        print(f"  +0x{i:03X}: {hex_bytes}  {note1:4s} {note2:4s}")

    # Known offsets from kstuff
    sv_sigsize_offset = 0x0E  # This is what kstuff modifies

    print(f"\n--- Known fields ---")
    print(f"sv_sigsize @ +0x{sv_sigsize_offset:02X}: 0x{read_u16(data, base_offset + sv_sigsize_offset):04X}")

    # Scan for potential sv_flags (should be a small integer, not a pointer)
    # Common values: SV_ABI_FREEBSD=9, SV_LP64=0x100, SV_ILP32=0x200
    # Combined: 0x109 for FreeBSD 64-bit
    print(f"\n--- Searching for sv_flags (ABI flags) ---")
    print("Looking for values like 0x109 (FreeBSD LP64), 0x1xx, etc.:")

    for i in range(0, 256, 8):
        val = read_u64(data, base_offset + i)
        # sv_flags should be a small value, not a pointer
        if not is_kernel_ptr(val) and 0 < val < 0x1000:
            print(f"  +0x{i:02X}: 0x{val:016X} ({val})")

    # Look for the syscall table pointer (sv_table)
    # Should be a kernel .data pointer, not .text
    print(f"\n--- Looking for sv_table (syscall table pointer) ---")
    for i in range(0, 64, 8):
        val = read_u64(data, base_offset + i)
        if is_kernel_ptr(val):
            # Check if it looks like a .data pointer vs .text pointer
            # .text is usually at 0xFFFFFFFFDxxxxxxx
            # .data is at 0xFFFFFFFFExxxxxxx (higher)
            text_or_data = "text" if ((val >> 24) & 0xFF) < 0xE0 else "data"
            print(f"  +0x{i:02X}: 0x{val:016X} ({text_or_data})")

    # Analyze the gap after this sysentvec
    print(f"\n--- Gap after structure ---")
    # sysentvec is typically ~0xC0-0x100 bytes
    for i in range(0xC0, 0x180, 8):
        offset = base_offset + i
        if offset + 8 > len(data):
            break
        val = read_u64(data, offset)
        if val != 0:
            ptr_or_val = "ptr" if is_kernel_ptr(val) else f"val={val}"
            print(f"  +0x{i:02X}: 0x{val:016X} ({ptr_or_val})")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_sysentvec.py kernel_data.bin")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print(f"Loaded {len(data)} bytes")

    # FW 4.03 offsets
    SYSENTVEC_PS5 = 0xD11BB8
    SYSENTVEC_PS4 = 0xD11D30

    analyze_sysentvec(data, SYSENTVEC_PS5, "sysentvec_ps5")
    analyze_sysentvec(data, SYSENTVEC_PS4, "sysentvec_ps4")

    # Compare the two structures
    print("\n" + "="*70)
    print("COMPARISON: PS5 vs PS4 sysentvec")
    print("="*70)

    print("\nDifferences in first 256 bytes:")
    for i in range(0, 256, 8):
        ps5_val = read_u64(data, SYSENTVEC_PS5 + i)
        ps4_val = read_u64(data, SYSENTVEC_PS4 + i)
        if ps5_val != ps4_val:
            print(f"  +0x{i:02X}: PS5=0x{ps5_val:016X}, PS4=0x{ps4_val:016X}")

    # Look for Sony-specific fields
    print("\n" + "="*70)
    print("SONY-SPECIFIC ANALYSIS")
    print("="*70)

    # Sony likely added fields for:
    # - Security/capability checks
    # - HV interaction
    # - Sandbox control

    print("\nLooking for Sony extensions after standard FreeBSD fields:")
    # Standard sysentvec ends around +0xA0 to +0xC0
    # Sony fields would be after that

    for i in range(0xA0, 0x150, 8):
        ps5_val = read_u64(data, SYSENTVEC_PS5 + i)
        ps4_val = read_u64(data, SYSENTVEC_PS4 + i) if SYSENTVEC_PS4 + i < len(data) else 0

        if ps5_val != 0:
            ptr_note = "ptr" if is_kernel_ptr(ps5_val) else ""
            same = "SAME" if ps5_val == ps4_val else "DIFF"
            print(f"  +0x{i:02X}: 0x{ps5_val:016X} {ptr_note:4s} [{same}]")

    print("\n" + "="*70)
    print("RECOMMENDATIONS")
    print("="*70)
    print("""
1. The sv_flags field should contain ABI flags (0x109 for FreeBSD LP64)
   - Find it in the first 0x100 bytes of sysentvec
   - This controls syscall behavior

2. Sony-specific fields are likely at +0xA0 to +0x150
   - Look for differences between PS5 and PS4 sysentvec
   - Non-pointer small integers might be security flags

3. The gap area (our mystery flag) is BETWEEN structures
   - Not part of sysentvec itself
   - Could be:
     - Padding with leftover data
     - A separate configuration structure
     - Sony's custom data

4. KEY INSIGHT: sv_sigsize at +0x0E is what kstuff modifies
   - Look for similar small integer fields that could affect security
""")


if __name__ == "__main__":
    main()
