#!/usr/bin/env python3
"""
PS5 Kernel .data Analysis Script
Analyzes kernel_data.bin to find security-critical data structures.

Usage: python3 analyze_kdata.py /path/to/kernel_data.bin
"""

import sys
import struct
from collections import defaultdict

# Known offsets for FW 4.03 (from KERNEL_ADDRESS_DATA_BASE)
KNOWN_OFFSETS = {
    0xd11bb8: "sysentvec (PS5)",
    0xd11d30: "sysentvec_ps4",
    0x170650: "apic_ops",
    0x27EDCB8: "allproc (if in range)",
    0xD20840: "pagertab",
}

def read_u8(data, offset):
    if offset + 1 > len(data):
        return None
    return struct.unpack('<B', data[offset:offset+1])[0]

def read_u16(data, offset):
    if offset + 2 > len(data):
        return None
    return struct.unpack('<H', data[offset:offset+2])[0]

def read_u32(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack('<I', data[offset:offset+4])[0]

def read_u64(data, offset):
    if offset + 8 > len(data):
        return None
    return struct.unpack('<Q', data[offset:offset+8])[0]

def is_kernel_ptr(val):
    """Check if value looks like a kernel pointer"""
    if val == 0:
        return False
    hi = (val >> 32) & 0xffffffff
    return hi == 0xffffffff

def is_kernel_text_ptr(val):
    """Check if value looks like kernel .text pointer"""
    if not is_kernel_ptr(val):
        return False
    lo = val & 0xffffffff
    top_byte = (lo >> 24) & 0xff
    return 0x80 <= top_byte <= 0xdf  # .text range

def is_kernel_data_ptr(val):
    """Check if value looks like kernel .data pointer"""
    if not is_kernel_ptr(val):
        return False
    lo = val & 0xffffffff
    top_byte = (lo >> 24) & 0xff
    return 0xe0 <= top_byte <= 0xff  # .data range

def analyze_sysentvec(data, offset, name):
    """Analyze sysentvec structure in detail"""
    print(f"\n{'='*70}")
    print(f"SYSENTVEC ANALYSIS: {name} @ offset 0x{offset:X}")
    print('='*70)

    # FreeBSD sysentvec structure (approximate)
    # struct sysentvec {
    #     int         sv_size;        // +0x00: number of syscalls
    #     struct sysent *sv_table;    // +0x08: syscall table
    #     u_int       sv_mask;        // +0x10: signal mask
    #     int         sv_sigsize;     // +0x14: signal size (THIS IS WHAT KSTUFF MODIFIES!)
    #     int         *sv_sigtbl;     // +0x18: signal table
    #     int         sv_errsize;     // +0x20: error table size
    #     int         *sv_errtbl;     // +0x28: error table
    #     int         (*sv_transtrap)(int, int); // +0x30: trap translator
    #     int         (*sv_fixup)(register_t **, struct image_params *); // +0x38
    #     void        (*sv_sendsig)(void (*)(int), struct ksiginfo *, struct sigset *); // +0x40
    #     char        *sv_sigcode;    // +0x48
    #     int         *sv_szsigcode;  // +0x50
    #     void        (*sv_prepsyscall)(struct thread *, int, int *, u_int *); // +0x58
    #     char        *sv_name;       // +0x60
    #     ... more fields
    # }

    fields = [
        (0x00, 4, "sv_size", "Number of syscalls"),
        (0x04, 4, "sv_pad?", "Padding/unknown"),
        (0x08, 8, "sv_table", "Syscall table pointer"),
        (0x10, 4, "sv_mask", "Signal mask"),
        (0x14, 2, "sv_sigsize", "KSTUFF TARGET FIELD!"),
        (0x16, 2, "sv_pad2?", "Padding"),
        (0x18, 8, "sv_sigtbl", "Signal table pointer"),
        (0x20, 4, "sv_errsize", "Error table size"),
        (0x24, 4, "sv_pad3?", "Padding"),
        (0x28, 8, "sv_errtbl", "Error table pointer"),
        (0x30, 8, "sv_transtrap", "Trap translator (FUNC PTR)"),
        (0x38, 8, "sv_fixup", "Fixup function (FUNC PTR)"),
        (0x40, 8, "sv_sendsig", "Send signal (FUNC PTR)"),
        (0x48, 8, "sv_sigcode", "Signal code pointer"),
        (0x50, 8, "sv_szsigcode", "Signal code size ptr"),
        (0x58, 8, "sv_prepsyscall", "Prep syscall (FUNC PTR)"),
        (0x60, 8, "sv_name", "ABI name string pointer"),
        (0x68, 8, "sv_coredump", "Coredump function"),
        (0x70, 8, "sv_imgact_try", "Image activator"),
        (0x78, 4, "sv_minsigstksz", "Min signal stack size"),
        (0x7C, 4, "sv_pad4?", "Padding"),
        (0x80, 8, "sv_pagesize", "Page size"),
        (0x88, 8, "sv_minuser", "Min user address"),
        (0x90, 8, "sv_maxuser", "Max user address"),
        (0x98, 8, "sv_usrstack", "User stack address"),
        (0xA0, 8, "sv_psstrings", "PS strings address"),
        (0xA8, 4, "sv_stackprot", "Stack protection flags"),
        (0xAC, 4, "sv_pad5?", "Padding"),
    ]

    print("\nField Analysis:")
    print("-" * 70)

    for field_off, size, name, desc in fields:
        abs_off = offset + field_off
        if abs_off + size > len(data):
            continue

        if size == 1:
            val = read_u8(data, abs_off)
            val_str = f"0x{val:02X}"
        elif size == 2:
            val = read_u16(data, abs_off)
            val_str = f"0x{val:04X}"
            if name == "sv_sigsize":
                val_str += f" (kstuff uses 0xFFFF=pause, 0xDEB7=resume)"
        elif size == 4:
            val = read_u32(data, abs_off)
            val_str = f"0x{val:08X}"
        else:
            val = read_u64(data, abs_off)
            val_str = f"0x{val:016X}"
            if is_kernel_text_ptr(val):
                val_str += " [.text ptr]"
            elif is_kernel_data_ptr(val):
                val_str += " [.data ptr]"

        marker = "<<<" if "KSTUFF" in name or "TARGET" in desc else ""
        print(f"  +0x{field_off:02X}: {name:20s} = {val_str} {marker}")
        print(f"         {desc}")

    # Show raw hex dump of first 0x100 bytes
    print(f"\nRaw hex dump (first 0x100 bytes):")
    print("-" * 70)
    for i in range(0, min(0x100, len(data) - offset), 16):
        hex_str = " ".join(f"{data[offset+i+j]:02X}" for j in range(min(16, len(data) - offset - i)))
        print(f"  +0x{i:03X}: {hex_str}")

def find_small_integers(data, target_values, context_size=32):
    """Find specific small integer values that might be security flags"""
    print(f"\n{'='*70}")
    print("SEARCHING FOR SECURITY FLAGS/SMALL INTEGERS")
    print('='*70)

    for target in target_values:
        if isinstance(target, int):
            # Search for 2-byte value
            target_bytes = struct.pack('<H', target & 0xFFFF)
            positions = []
            start = 0
            while True:
                pos = data.find(target_bytes, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1

            if len(positions) < 100:  # Don't spam if too many matches
                print(f"\nValue 0x{target:04X} found at {len(positions)} locations:")
                for pos in positions[:20]:  # Show first 20
                    # Check surrounding context
                    ctx_start = max(0, pos - 8)
                    ctx_end = min(len(data), pos + 10)
                    ctx = data[ctx_start:ctx_end].hex()
                    print(f"  0x{pos:08X}: ...{ctx}...")

def find_potential_config_structs(data):
    """Find potential configuration structures (arrays of small values)"""
    print(f"\n{'='*70}")
    print("SEARCHING FOR CONFIGURATION STRUCTURES")
    print('='*70)

    # Look for patterns like arrays of flags or configuration values
    # These are often 4-byte or 8-byte aligned structures with small values

    interesting = []

    for offset in range(0, len(data) - 64, 8):
        # Read 8 consecutive u32 values
        values = [read_u32(data, offset + i*4) for i in range(16)]

        # Check if they look like configuration (small values, some non-zero)
        non_zero = sum(1 for v in values if v and v != 0xffffffff)
        small_vals = sum(1 for v in values if v and v < 0x10000)

        if non_zero >= 4 and small_vals >= 4:
            # Check it's not just pointers
            ptr_count = sum(1 for v in values if is_kernel_ptr(v << 32 | v))
            if ptr_count < 2:
                interesting.append((offset, values[:8]))

    print(f"Found {len(interesting)} potential config structures")
    for offset, vals in interesting[:20]:
        val_str = " ".join(f"{v:08X}" for v in vals)
        print(f"  0x{offset:08X}: {val_str}")

def find_security_strings(data):
    """Find strings that might indicate security-related data nearby"""
    print(f"\n{'='*70}")
    print("SEARCHING FOR SECURITY-RELATED STRINGS")
    print('='*70)

    security_keywords = [
        b"security", b"auth", b"priv", b"perm", b"allow", b"deny",
        b"check", b"verify", b"valid", b"cfi", b"smap", b"smep",
        b"xom", b"npt", b"gmet", b"hyper", b"suspend", b"resume",
        b"acpi", b"apic", b"msr", b"cpuid", b"pmap", b"vm_",
        b"sysent", b"syscall", b"cap_", b"ucred", b"jail"
    ]

    for keyword in security_keywords:
        pos = 0
        matches = []
        while True:
            pos = data.lower().find(keyword, pos)
            if pos == -1:
                break
            # Extract surrounding context
            start = max(0, pos - 4)
            end = min(len(data), pos + len(keyword) + 32)
            context = data[start:end]
            # Try to decode as string
            try:
                ctx_str = context.decode('ascii', errors='replace')
                ctx_str = ''.join(c if c.isprintable() else '.' for c in ctx_str)
            except:
                ctx_str = context.hex()
            matches.append((pos, ctx_str))
            pos += 1

        if matches:
            print(f"\n'{keyword.decode()}' found {len(matches)} times:")
            for pos, ctx in matches[:5]:
                print(f"  0x{pos:08X}: {ctx[:60]}")

def analyze_near_known_offsets(data):
    """Analyze data near known important offsets"""
    print(f"\n{'='*70}")
    print("ANALYZING DATA NEAR KNOWN OFFSETS")
    print('='*70)

    for offset, name in sorted(KNOWN_OFFSETS.items()):
        if offset >= len(data):
            print(f"\n{name} @ 0x{offset:X}: BEYOND DUMP SIZE")
            continue

        print(f"\n{name} @ 0x{offset:X}:")
        print("-" * 50)

        # Dump 64 bytes around the offset
        start = max(0, offset - 16)
        for i in range(0, 96, 16):
            if start + i >= len(data):
                break
            hex_bytes = " ".join(f"{data[start+i+j]:02X}" for j in range(min(16, len(data) - start - i)))
            offset_str = f"0x{start+i:08X}"
            marker = " <--" if start + i <= offset < start + i + 16 else ""
            print(f"  {offset_str}: {hex_bytes}{marker}")

def find_writable_security_data(data):
    """
    Find data that might affect security decisions.
    Focus on: flags, counters, state machines, configuration values
    """
    print(f"\n{'='*70}")
    print("HUNTING FOR EXPLOITABLE SECURITY DATA")
    print('='*70)

    # 1. Look for boolean-like patterns (0/1 or 0/0xffffffff)
    print("\n[1] Potential boolean flags (isolated 0x00000001 values):")
    for offset in range(0, len(data) - 16, 4):
        val = read_u32(data, offset)
        if val == 1:
            # Check surrounding values aren't also 1 (not an array of 1s)
            prev_val = read_u32(data, offset - 4) if offset >= 4 else 0
            next_val = read_u32(data, offset + 4) if offset + 4 < len(data) else 0
            if prev_val != 1 and next_val != 1:
                # This could be a boolean flag
                ctx = data[max(0,offset-8):offset+12].hex()
                print(f"  0x{offset:08X}: {ctx}")

    # 2. Look for state machine values (small incrementing integers)
    print("\n[2] Potential state values (0-10 range):")
    state_candidates = []
    for offset in range(0, len(data) - 4, 4):
        val = read_u32(data, offset)
        if 0 < val <= 10:
            state_candidates.append((offset, val))

    # Group by value
    by_value = defaultdict(list)
    for offset, val in state_candidates:
        by_value[val].append(offset)

    for val in sorted(by_value.keys()):
        if len(by_value[val]) < 50:  # Not too common
            print(f"  Value {val}: {len(by_value[val])} occurrences")
            for off in by_value[val][:3]:
                print(f"    0x{off:08X}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_kdata.py kernel_data.bin")
        sys.exit(1)

    filename = sys.argv[1]
    print(f"[*] Loading {filename}...")

    with open(filename, 'rb') as f:
        data = f.read()

    print(f"[*] Loaded {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

    # Analyze sysentvec structures
    analyze_sysentvec(data, 0xd11bb8, "sysentvec_ps5")
    analyze_sysentvec(data, 0xd11d30, "sysentvec_ps4")

    # Analyze data near known offsets
    analyze_near_known_offsets(data)

    # Search for security-related strings
    find_security_strings(data)

    # Look for configuration structures
    find_potential_config_structs(data)

    # Hunt for exploitable data
    find_writable_security_data(data)

    # Search for kstuff-like values
    print(f"\n{'='*70}")
    print("KSTUFF VALUE ANALYSIS")
    print('='*70)

    # Find all 0xDEB7 and 0xFFFF occurrences (kstuff toggle values)
    deb7_count = 0
    ffff_count = 0
    for offset in range(0, len(data) - 2, 2):
        val = read_u16(data, offset)
        if val == 0xDEB7:
            deb7_count += 1
            if deb7_count <= 10:
                ctx = data[max(0,offset-8):offset+10].hex()
                print(f"  0xDEB7 @ 0x{offset:08X}: {ctx}")
        elif val == 0xFFFF:
            ffff_count += 1

    print(f"\n  0xDEB7 occurrences: {deb7_count}")
    print(f"  0xFFFF occurrences: {ffff_count}")

    print(f"\n{'='*70}")
    print("ANALYSIS COMPLETE")
    print('='*70)
    print("""
NEXT STEPS:
1. Load kernel_data.bin in IDA Pro at base 0xFFFFFFFF80000000 + offset
2. Look at sysentvec+14 field - what code references it?
3. Search for other 2-byte fields that might be security flags
4. Find structures that control page tables or memory protection
5. Look for ACPI/power management state data
""")

if __name__ == "__main__":
    main()
