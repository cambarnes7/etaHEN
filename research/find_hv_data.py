#!/usr/bin/env python3
"""
Find HV-related data in kernel_data.bin
Focus on GMET, NPT, and the 0xDEB7 toggle values
"""

import sys
import struct

def read_u64(data, offset):
    if offset + 8 > len(data):
        return None
    return struct.unpack('<Q', data[offset:offset+8])[0]

def is_kernel_ptr(val):
    if val == 0:
        return False
    return (val >> 32) == 0xffffffff

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_hv_data.py kernel_data.bin")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print(f"Loaded {len(data)} bytes")

    # 1. Find all 0xDEB7 locations and analyze context
    print("\n" + "="*70)
    print("ALL 0xDEB7 LOCATIONS (potential security toggles)")
    print("="*70)

    deb7_locs = []
    for i in range(0, len(data) - 2, 2):
        if data[i] == 0xB7 and data[i+1] == 0xDE:
            deb7_locs.append(i)

    print(f"Found {len(deb7_locs)} occurrences of 0xDEB7")
    print("\nAnalyzing each location:")

    interesting_deb7 = []
    for loc in deb7_locs:
        # Check if it looks like a standalone value (not part of a pointer)
        if loc >= 2:
            prev_word = struct.unpack('<H', data[loc-2:loc])[0]
        else:
            prev_word = 0

        if loc + 4 <= len(data):
            next_word = struct.unpack('<H', data[loc+2:loc+4])[0]
        else:
            next_word = 0

        # Interesting if surrounded by zeros or small values (like a flag field)
        if prev_word < 0x100 and next_word < 0x100:
            interesting_deb7.append(loc)
            ctx = data[max(0,loc-16):loc+16].hex()
            print(f"  0x{loc:08X}: {ctx}")
            print(f"             ^ prev={prev_word:04X}, next={next_word:04X}")

    print(f"\n{len(interesting_deb7)} locations look like standalone flags")

    # 2. Analyze area around "ableGMET" string (0x3A3D05)
    print("\n" + "="*70)
    print("GMET CONTROL AREA (around 0x3A3D05)")
    print("="*70)

    gmet_str_offset = 0x3A3D05
    # Look for data structures BEFORE this string (strings often follow data)
    print("\nData BEFORE 'ableGMET' string:")
    for i in range(gmet_str_offset - 0x200, gmet_str_offset, 16):
        if i < 0:
            continue
        hex_bytes = " ".join(f"{data[i+j]:02X}" for j in range(min(16, len(data) - i)))
        # Check for kernel pointers
        val = read_u64(data, i)
        ptr_note = " [ptr]" if val and is_kernel_ptr(val) else ""
        print(f"  0x{i:08X}: {hex_bytes}{ptr_note}")

    # 3. Look for structures with enable/disable patterns
    print("\n" + "="*70)
    print("SEARCHING FOR ENABLE/DISABLE FLAG PATTERNS")
    print("="*70)

    # Common patterns: 0/1 flags, or specific magic values
    # Look for isolated small integers that might be security flags

    # Search for "enable" or "disable" followed by data
    enable_off = data.find(b"enable")
    while enable_off != -1:
        # Check nearby for data structures
        if enable_off > 0x100 and enable_off < len(data) - 0x100:
            # Look at data before the string
            before = data[enable_off-64:enable_off]
            # Count small values (potential flags)
            small_vals = sum(1 for b in before if b < 16)
            if small_vals > 10:
                print(f"  'enable' at 0x{enable_off:08X} has {small_vals} small values before it")
                ctx = data[enable_off-32:enable_off+32]
                print(f"    Context: {ctx[:32].hex()} | {ctx[32:].hex()}")
        enable_off = data.find(b"enable", enable_off + 1)

    # 4. Look for NPT-related data
    print("\n" + "="*70)
    print("NPT (Nested Page Tables) REFERENCES")
    print("="*70)

    npt_off = data.find(b"npt")
    while npt_off != -1 and npt_off < len(data):
        ctx_start = max(0, npt_off - 8)
        ctx_end = min(len(data), npt_off + 40)
        ctx = data[ctx_start:ctx_end]
        try:
            ctx_str = ctx.decode('ascii', errors='replace')
            ctx_str = ''.join(c if c.isprintable() else '.' for c in ctx_str)
        except:
            ctx_str = ctx.hex()
        print(f"  0x{npt_off:08X}: {ctx_str[:60]}")
        npt_off = data.find(b"npt", npt_off + 1)

    # 5. Look for VMCB (Virtual Machine Control Block) references
    print("\n" + "="*70)
    print("VMCB (VM Control Block) REFERENCES")
    print("="*70)

    vmcb_off = data.lower().find(b"vmcb")
    while vmcb_off != -1 and vmcb_off < len(data):
        ctx_start = max(0, vmcb_off - 8)
        ctx_end = min(len(data), vmcb_off + 50)
        ctx = data[ctx_start:ctx_end]
        try:
            ctx_str = ctx.decode('ascii', errors='replace')
            ctx_str = ''.join(c if c.isprintable() else '.' for c in ctx_str)
        except:
            ctx_str = ctx.hex()
        print(f"  0x{vmcb_off:08X}: {ctx_str[:60]}")
        vmcb_off = data.lower().find(b"vmcb", vmcb_off + 1)

    # 6. Check the specific sysentvec locations for nearby interesting data
    print("\n" + "="*70)
    print("EXTENDED SYSENTVEC AREA ANALYSIS")
    print("="*70)

    sysentvec_ps5 = 0xD11BB8
    sysentvec_ps4 = 0xD11D30

    print(f"\nBetween sysentvec_ps5 and sysentvec_ps4 (0x{sysentvec_ps5:X} - 0x{sysentvec_ps4:X}):")
    print("This area might contain other ABI-related security data:")

    for i in range(sysentvec_ps5 + 0x100, sysentvec_ps4, 16):
        hex_bytes = " ".join(f"{data[i+j]:02X}" for j in range(min(16, len(data) - i)))
        # Highlight non-zero, non-pointer values
        vals = [read_u64(data, i), read_u64(data, i+8)]
        notes = []
        for v in vals:
            if v and not is_kernel_ptr(v) and v < 0x10000:
                notes.append(f"small:{v:X}")
        note_str = " ".join(notes) if notes else ""
        if note_str or any(data[i+j] != 0 for j in range(16)):
            print(f"  0x{i:08X}: {hex_bytes}  {note_str}")

    # 7. Search for specific HV control strings
    print("\n" + "="*70)
    print("HYPERVISOR CONTROL STRINGS")
    print("="*70)

    hv_strings = [b"XOM", b"xom", b"SMAP", b"GMET", b"NPT", b"ASID", b"vmrun", b"VMCB"]
    for s in hv_strings:
        off = data.find(s)
        count = 0
        while off != -1 and count < 5:
            ctx = data[max(0,off-16):off+len(s)+32]
            try:
                ctx_str = ctx.decode('ascii', errors='replace')
                ctx_str = ''.join(c if c.isprintable() else '.' for c in ctx_str)
            except:
                ctx_str = ctx.hex()
            print(f"  '{s.decode()}' at 0x{off:08X}: ...{ctx_str}...")
            off = data.find(s, off + 1)
            count += 1

    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)
    print("""
KEY TARGETS FOR IDA ANALYSIS:
1. 0x003A3D05 - "ableGMET" string - find what DATA controls this
2. 0x00330BCC - VMCB flags area - look for enable/disable bits
3. The 0xDEB7 locations that look like standalone flags
4. Area between sysentvec_ps5 and sysentvec_ps4 for other toggles
""")

if __name__ == "__main__":
    main()
