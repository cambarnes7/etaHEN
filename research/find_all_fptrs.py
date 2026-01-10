#!/usr/bin/env python3
"""
Comprehensive function pointer scanner for PS5 kernel .data dump.
Finds ALL potential function pointer tables and categorizes them.

Run on the Mac where kernel_data.bin is located:
  python3 find_all_fptrs.py kernel_data.bin
"""

import sys
import struct
from collections import defaultdict

def is_kernel_text_ptr(val):
    """Check if value looks like kernel .text pointer (0xffffffffd0000000-0xffffffffdfffffff)"""
    if val == 0:
        return False
    hi = (val >> 32) & 0xffffffff
    lo = val & 0xffffffff
    if hi != 0xffffffff:
        return False
    # Kernel .text is typically 0xffffffffd0xxxxxx - 0xffffffffdxxxxxxx
    top_byte = (lo >> 24) & 0xff
    return 0xd0 <= top_byte <= 0xdf

def is_kernel_data_ptr(val):
    """Check if value looks like kernel .data pointer"""
    if val == 0:
        return False
    hi = (val >> 32) & 0xffffffff
    lo = val & 0xffffffff
    if hi != 0xffffffff:
        return False
    top_byte = (lo >> 24) & 0xff
    return 0xe0 <= top_byte <= 0xef  # .data is typically higher than .text

def scan_for_fptr_arrays(data, min_ptrs=3, max_gap=16):
    """
    Scan for arrays of consecutive function pointers.
    Returns list of (offset, count, pointers[])
    """
    candidates = []
    i = 0
    data_len = len(data)

    while i < data_len - 8:
        # Read potential pointer
        val = struct.unpack('<Q', data[i:i+8])[0]

        if is_kernel_text_ptr(val):
            # Start of potential array - scan forward
            start_offset = i
            ptrs = [val]
            j = i + 8
            gap = 0

            while j < data_len - 8 and gap < max_gap:
                next_val = struct.unpack('<Q', data[j:j+8])[0]

                if is_kernel_text_ptr(next_val):
                    ptrs.append(next_val)
                    gap = 0
                    j += 8
                elif next_val == 0:
                    # NULL is ok in function tables (optional functions)
                    gap += 8
                    j += 8
                else:
                    break

            if len(ptrs) >= min_ptrs:
                candidates.append((start_offset, len(ptrs), ptrs))
                i = j
            else:
                i += 8
        else:
            i += 8

    return candidates

def categorize_by_size(candidates):
    """Group candidates by number of pointers"""
    by_size = defaultdict(list)
    for offset, count, ptrs in candidates:
        by_size[count].append((offset, ptrs))
    return by_size

def find_unique_structures(candidates):
    """
    Find structures with unique pointer counts - these are more likely
    to be specific kernel structures (like apic_ops with exactly 28 ptrs)
    """
    by_size = categorize_by_size(candidates)
    unique = {}
    for count, entries in by_size.items():
        if len(entries) <= 3:  # Rare count = more likely a specific struct
            unique[count] = entries
    return unique

def analyze_pointer_diversity(ptrs):
    """
    Check how diverse the pointers are.
    High diversity = likely a real ops struct
    Low diversity = might be vtable or repeated pattern
    """
    unique = len(set(ptrs))
    return unique / len(ptrs) if ptrs else 0

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_all_fptrs.py kernel_data.bin")
        sys.exit(1)

    print(f"[*] Loading {sys.argv[1]}...")
    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print(f"[*] Loaded {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")
    print(f"[*] Scanning for function pointer arrays (min 3 consecutive)...")

    candidates = scan_for_fptr_arrays(data, min_ptrs=3)
    print(f"[*] Found {len(candidates)} potential function pointer arrays")

    # Filter and analyze
    print(f"\n{'='*80}")
    print("ANALYSIS BY POINTER COUNT")
    print('='*80)

    by_size = categorize_by_size(candidates)

    # Print summary
    print(f"\n[SUMMARY] Pointer count distribution:")
    for count in sorted(by_size.keys(), reverse=True):
        entries = by_size[count]
        print(f"  {count:3d} pointers: {len(entries):4d} candidates")

    # Show candidates most likely to be exploitable
    # (specific struct sizes that are rare)
    print(f"\n{'='*80}")
    print("HIGH-VALUE TARGETS (rare pointer counts, likely specific structs)")
    print("These are LESS likely to be CFI-protected (legacy/specific code)")
    print('='*80)

    # Known FreeBSD struct sizes to look for
    known_structs = {
        28: "apic_ops (CONFIRMED)",
        12: "cdevsw (character device switch - often unprotected!)",
        13: "bdevsw (block device switch)",
        8: "fileops",
        11: "vnodeop_desc",
        6: "linker_class (module loader)",
        7: "vfsops (filesystem ops)",
        15: "ifnet_ops (network interface)",
        5: "protosw (protocol switch - often unprotected!)",
        4: "domain (network domain)",
        9: "bus_methods",
        10: "device_methods",
    }

    for count in sorted(by_size.keys(), reverse=True):
        entries = by_size[count]
        if len(entries) <= 5:  # Rare = interesting
            struct_name = known_structs.get(count, "UNKNOWN")
            print(f"\n[{count} POINTERS] - {len(entries)} candidate(s) - Likely: {struct_name}")
            print("-" * 60)

            for offset, ptrs in entries:
                diversity = analyze_pointer_diversity(ptrs)
                print(f"  Offset: 0x{offset:X}")
                print(f"  Diversity: {diversity:.1%} ({len(set(ptrs))}/{len(ptrs)} unique)")
                print(f"  First ptr: 0x{ptrs[0]:016X}")
                if len(ptrs) > 1:
                    print(f"  Last ptr:  0x{ptrs[-1]:016X}")
                print()

    # Special focus on sizes known to be often unprotected
    print(f"\n{'='*80}")
    print("PRIORITY TARGETS - Known often-unprotected structures")
    print("Test these FIRST via write test")
    print('='*80)

    priority_sizes = [5, 6, 7, 12, 13]  # protosw, linker_class, vfsops, cdevsw, bdevsw

    for size in priority_sizes:
        if size in by_size:
            struct_name = known_structs.get(size, "UNKNOWN")
            print(f"\n[{size} POINTERS] - {struct_name}")
            for offset, ptrs in by_size[size][:10]:  # Show first 10
                diversity = analyze_pointer_diversity(ptrs)
                print(f"  0x{offset:06X} - diversity {diversity:.0%} - first: 0x{ptrs[0]:016X}")

    # Export all candidates to a file for detailed analysis
    output_file = "fptr_candidates.txt"
    print(f"\n[*] Writing all candidates to {output_file}...")

    with open(output_file, 'w') as f:
        f.write("# Function Pointer Array Candidates\n")
        f.write(f"# Total: {len(candidates)}\n")
        f.write("# Format: offset,count,diversity,first_ptr,last_ptr\n\n")

        for offset, count, ptrs in sorted(candidates, key=lambda x: -x[1]):
            diversity = analyze_pointer_diversity(ptrs)
            f.write(f"0x{offset:06X},{count},{diversity:.2f},0x{ptrs[0]:016X},0x{ptrs[-1]:016X}\n")

    print(f"[*] Done! Review {output_file} for complete list")

    # Generate test code
    print(f"\n{'='*80}")
    print("GENERATED TEST CODE FOR UMTX2")
    print("Add to main.js to test if pointers are CFI-protected")
    print('='*80)

    # Pick best candidates for testing
    test_candidates = []
    for size in [5, 6, 7, 12, 4]:  # Priority sizes
        if size in by_size:
            for offset, ptrs in by_size[size][:2]:
                test_candidates.append((offset, size, ptrs[0]))

    if test_candidates:
        print("\n// Add this after the APIC read test in main.js:")
        print("// Tests multiple function pointer candidates for CFI protection")
        print("")
        print("let test_offsets = [")
        for offset, size, first_ptr in test_candidates[:10]:
            struct_name = known_structs.get(size, f"{size}_ptr_struct")
            print(f"    {{ offset: 0x{offset:X}, name: '{struct_name}', size: {size} }},")
        print("];")
        print("")
        print("""for (let candidate of test_offsets) {
    let ptr_addr = krw.kdataBase.add32(candidate.offset);
    let current_val = await krw.read8(ptr_addr);
    await log(`[TEST] ${candidate.name} @ 0x${ptr_addr} = 0x${current_val}`, LogLevel.INFO);
}

// To test if CFI-protected, uncomment and test ONE at a time:
// let test_addr = krw.kdataBase.add32(0xOFFSET);
// await krw.write8(test_addr, new int64(0xDEADBEEF, 0));
// If no crash = NOT CFI protected!
""")

if __name__ == "__main__":
    main()
