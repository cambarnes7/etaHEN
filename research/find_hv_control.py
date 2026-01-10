#!/usr/bin/env python3
"""
Find hypervisor control data in kernel_data.bin
Focus on GMET, NPT, VMCB - the actual HV controls
"""

import sys
import struct

def read_u32(data, offset):
    return struct.unpack('<I', data[offset:offset+4])[0]

def read_u64(data, offset):
    return struct.unpack('<Q', data[offset:offset+8])[0]

def is_kernel_ptr(val):
    return (val >> 32) == 0xFFFFFFFF

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_hv_control.py kernel_data.bin")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print(f"Loaded {len(data)} bytes")
    print("\n" + "="*70)
    print("HYPERVISOR CONTROL DATA SEARCH")
    print("="*70)

    # 1. Find "ableGMET" and analyze surrounding data
    gmet_str = data.find(b"ableGMET")
    if gmet_str != -1:
        print(f"\n[GMET] Found 'ableGMET' at 0x{gmet_str:08X}")

        # This is likely in a format string like "EnableGMET:%d"
        # Find the start of the string
        str_start = gmet_str
        while str_start > 0 and data[str_start-1] >= 32 and data[str_start-1] < 127:
            str_start -= 1

        str_end = gmet_str
        while str_end < len(data) and data[str_end] >= 32 and data[str_end] < 127:
            str_end += 1

        full_string = data[str_start:str_end].decode('ascii', errors='replace')
        print(f"[GMET] Full string: \"{full_string}\"")

        # The format string is in .rodata, but the DATA it prints should be in .data
        # Look for small integers (0 or 1) in the .data section that could be the GMET flag
        print(f"\n[GMET] Searching for potential GMET enable flags...")

        # Common patterns for enable/disable flags
        for pattern_name, pattern in [
            ("GMET enable (1)", b"\x01\x00\x00\x00"),
            ("GMET disable (0)", b"\x00\x00\x00\x00"),
        ]:
            # Find in data section (high offsets)
            count = 0
            for i in range(0xD00000, min(len(data), 0xE00000), 4):
                if data[i:i+4] == pattern:
                    # Check if this looks like a standalone flag
                    before = read_u32(data, i-4) if i >= 4 else 0
                    after = read_u32(data, i+4) if i+4 < len(data) else 0

                    # Interesting if surrounded by zeros or small values
                    if before < 0x100 and after < 0x100:
                        count += 1
                        if count <= 10:
                            print(f"  0x{i:08X}: {pattern_name} (before={before}, after={after})")

    # 2. Find VMCB-related strings and data
    print("\n" + "-"*70)
    print("[VMCB] Searching for VMCB configuration...")

    vmcb_strings = [
        b"NP_ENABLE",
        b"EnableGMET",
        b"EnableSEV",
        b"VMCB",
        b"vmcb",
        b"nested",
        b"NPT",
    ]

    for s in vmcb_strings:
        off = data.find(s)
        while off != -1:
            # Get context
            ctx_start = max(0, off - 20)
            ctx_end = min(len(data), off + len(s) + 40)
            ctx = data[ctx_start:ctx_end]

            # Try to decode as string
            try:
                ctx_str = ctx.decode('ascii', errors='replace')
                ctx_str = ''.join(c if c.isprintable() else '.' for c in ctx_str)
            except:
                ctx_str = ctx.hex()

            print(f"  '{s.decode()}' @ 0x{off:08X}: {ctx_str[:60]}")
            off = data.find(s, off + 1)

    # 3. Look for AMD-V specific patterns
    print("\n" + "-"*70)
    print("[AMD-V] Searching for AMD-V control patterns...")

    # VMCB offset 0x90 contains control bits
    # NP_ENABLE is bit 0 of VMCB+0x90
    # Look for code that manipulates these

    # Search for potential VMCB base pointers
    # VMCB is typically page-aligned (0x1000)
    print("\n  Looking for page-aligned pointers that could be VMCB...")
    vmcb_candidates = []
    for i in range(0xD00000, min(len(data), 0xE00000), 8):
        val = read_u64(data, i)
        # Check if it's a kernel pointer that's page-aligned
        if is_kernel_ptr(val) and (val & 0xFFF) == 0:
            vmcb_candidates.append((i, val))

    print(f"  Found {len(vmcb_candidates)} page-aligned kernel pointers")
    if vmcb_candidates:
        print("  First 10:")
        for off, val in vmcb_candidates[:10]:
            print(f"    0x{off:08X}: -> 0x{val:016X}")

    # 4. Search for the hypervisor's own data structures
    print("\n" + "-"*70)
    print("[HV DATA] Looking for hypervisor-specific data...")

    # The HV has its own code/data separate from kernel
    # On PS5, HV is loaded before kernel
    # Look for patterns that suggest HV control structures

    # Search for "hv" or "hypervisor" strings
    hv_strings = [b"hypervisor", b"hv_", b"HV_", b"HYPERVISOR"]
    for s in hv_strings:
        off = data.find(s)
        count = 0
        while off != -1 and count < 5:
            ctx = data[max(0,off-10):off+len(s)+30]
            ctx_str = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"  '{s.decode()}' @ 0x{off:08X}: {ctx_str}")
            off = data.find(s, off + 1)
            count += 1

    # 5. Look for SMAP/SMEP control
    print("\n" + "-"*70)
    print("[SMAP/SMEP] Searching for SMAP/SMEP references...")

    for s in [b"SMAP", b"SMEP", b"smap", b"smep"]:
        off = data.find(s)
        while off != -1:
            ctx = data[max(0,off-10):off+len(s)+30]
            ctx_str = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"  '{s.decode()}' @ 0x{off:08X}: {ctx_str}")
            off = data.find(s, off + 1)

    # 6. Summary and recommendations
    print("\n" + "="*70)
    print("RECOMMENDATIONS FOR HV BYPASS")
    print("="*70)
    print("""
1. GMET CONTROL:
   - The "ableGMET" string is a format string for debugging
   - Find the code that uses this string (in IDA)
   - The code will reference the actual GMET enable flag

2. VMCB ACCESS:
   - VMCB controls all AMD-V settings
   - NP_ENABLE (bit 0 of VMCB+0x90) controls NPT
   - If we can find where kernel stores VMCB pointer, we could:
     a) Read current settings
     b) Potentially modify them

3. HYPERCALL DATA:
   - PS5 uses VMMCALL for HV communication
   - Find the hypercall dispatch tables
   - Data passed to hypercalls could be modifiable

4. NEXT STEPS:
   - Load kernel dump in IDA
   - Find xrefs to GMET/VMCB strings
   - Trace back to find the enable/disable flags
   - Look for kernel variables that control HV behavior
""")

if __name__ == "__main__":
    main()
