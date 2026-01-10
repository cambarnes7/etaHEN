#!/usr/bin/env python3
"""
Find security-relevant flags among the 170+ locations with 0x01+0x0FFFFFFF pattern.
Focus on flags near known security structures.
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
        print("Usage: python3 find_security_flags.py kernel_data.bin")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print(f"Loaded {len(data)} bytes")

    # Known security-related offsets (FW 4.03)
    SECURITY_REGIONS = {
        "sysentvec_ps5": 0xD11BB8,
        "sysentvec_ps4": 0xD11D30,
        "ucred_area": (0xD10000, 0xD20000),  # Estimate
        "prison_area": (0xD00000, 0xD10000),  # Estimate
    }

    # Find all 0x01 + 0x0FFFFFFF patterns
    print("\n" + "="*70)
    print("CATEGORIZING FLAG LOCATIONS BY REGION")
    print("="*70)

    flag_locations = []
    for i in range(0, len(data) - 8, 4):
        val1 = read_u32(data, i)
        val2 = read_u32(data, i + 4)
        if val1 == 0x00000001 and val2 == 0x0FFFFFFF:
            flag_locations.append(i)

    print(f"Total flags found: {len(flag_locations)}")

    # Group by region
    regions = {
        "0x009A-0x009F (early data)": [],
        "0x00D0-0x00D5 (near sysentvec)": [],
        "0x0134-0x0136 (mid data)": [],
        "0x0167-0x016B (device/driver?)": [],
        "0x019C-0x01A2 (late data)": [],
        "0x01D3-0x01D5 (very late)": [],
        "other": []
    }

    for loc in flag_locations:
        if 0x009A0000 <= loc < 0x00A00000:
            regions["0x009A-0x009F (early data)"].append(loc)
        elif 0x00D00000 <= loc < 0x00D60000:
            regions["0x00D0-0x00D5 (near sysentvec)"].append(loc)
        elif 0x01340000 <= loc < 0x01370000:
            regions["0x0134-0x0136 (mid data)"].append(loc)
        elif 0x01670000 <= loc < 0x016B0000:
            regions["0x0167-0x016B (device/driver?)"].append(loc)
        elif 0x019C0000 <= loc < 0x01A30000:
            regions["0x019C-0x01A2 (late data)"].append(loc)
        elif 0x01D30000 <= loc < 0x01D60000:
            regions["0x01D3-0x01D5 (very late)"].append(loc)
        else:
            regions["other"].append(loc)

    for region, locs in regions.items():
        if locs:
            print(f"\n{region}: {len(locs)} flags")

    # Focus on the sysentvec region - these are most likely to be security-related
    print("\n" + "="*70)
    print("FLAGS NEAR SYSENTVEC (0x00D0-0x00D5) - HIGH PRIORITY")
    print("="*70)

    sysentvec_flags = regions["0x00D0-0x00D5 (near sysentvec)"]
    for loc in sysentvec_flags:
        # Check context - what's before and after?
        before_ptr = read_u64(data, loc - 8) if loc >= 8 else 0
        after_val = read_u64(data, loc + 8) if loc + 8 < len(data) else 0

        before_desc = f"ptr:0x{before_ptr:016X}" if is_kernel_ptr(before_ptr) else f"val:0x{before_ptr:016X}"
        after_desc = f"ptr:0x{after_val:016X}" if is_kernel_ptr(after_val) else f"val:0x{after_val:016X}"

        # Distance from sysentvec
        dist_ps5 = loc - 0xD11BB8
        dist_ps4 = loc - 0xD11D30

        print(f"  0x{loc:08X}: before={before_desc}, after={after_desc}")
        print(f"             dist from sysentvec_ps5: {dist_ps5:+d}, from ps4: {dist_ps4:+d}")

    # Look for flags that might control privilege/capability
    print("\n" + "="*70)
    print("SEARCHING FOR PRIVILEGE-RELATED PATTERNS")
    print("="*70)

    # Look for patterns that might be capability structures
    # Capabilities often have: [flags] [mask] [value] patterns

    print("\nLooking for capability-like structures (flag + mask + non-zero value):")
    for loc in flag_locations:
        if loc + 16 <= len(data):
            flag = read_u32(data, loc)
            mask = read_u32(data, loc + 4)
            val1 = read_u32(data, loc + 8)
            val2 = read_u32(data, loc + 12)

            # Interesting if followed by non-zero, non-pointer values
            if val1 != 0 and val2 != 0 and not is_kernel_ptr(read_u64(data, loc + 8)):
                print(f"  0x{loc:08X}: flag=0x{flag:08X}, mask=0x{mask:08X}, then 0x{val1:08X} 0x{val2:08X}")

    # Look for strings near flag locations
    print("\n" + "="*70)
    print("SEARCHING FOR STRINGS NEAR FLAGS")
    print("="*70)

    def find_nearby_string(data, offset, range_before=256, range_after=256):
        """Find printable strings near an offset"""
        strings = []
        start = max(0, offset - range_before)
        end = min(len(data), offset + range_after)

        current_string = ""
        string_start = 0
        for i in range(start, end):
            c = data[i]
            if 32 <= c < 127:
                if not current_string:
                    string_start = i
                current_string += chr(c)
            else:
                if len(current_string) >= 6:
                    strings.append((string_start, current_string))
                current_string = ""

        return strings

    # Check strings near key flag locations
    key_flags = [
        0x00D11D08,  # Our mystery flag
        0x00D11B90,  # Before sysentvec_ps5
        0x00D11CB0,  # In the gap
        0x00D11E28,  # After sysentvec_ps4
    ]

    for flag_loc in key_flags:
        if flag_loc < len(data):
            strings = find_nearby_string(data, flag_loc)
            if strings:
                print(f"\nStrings near 0x{flag_loc:08X}:")
                for soff, s in strings:
                    rel = soff - flag_loc
                    print(f"  0x{soff:08X} ({rel:+4d}): \"{s}\"")

    # Check for different flag values (not just 0x01)
    print("\n" + "="*70)
    print("SEARCHING FOR VARIANT FLAGS (different base values)")
    print("="*70)

    for base_val in [0x00, 0x02, 0x03, 0xFF]:
        count = 0
        examples = []
        for i in range(0, len(data) - 8, 4):
            val1 = read_u32(data, i)
            val2 = read_u32(data, i + 4)
            if val1 == base_val and val2 == 0x0FFFFFFF:
                count += 1
                if count <= 5:
                    examples.append(i)

        if count > 0:
            print(f"  Flag value 0x{base_val:02X} with mask 0x0FFFFFFF: {count} locations")
            for ex in examples:
                print(f"    0x{ex:08X}")

    # Summary and recommendations
    print("\n" + "="*70)
    print("RECOMMENDATIONS")
    print("="*70)
    print("""
Based on this analysis:

1. The 0x01+0x0FFFFFFF pattern is a COMMON structure (170+ instances)
   - Likely: capability entries, feature flags, or configuration data
   - Probably NOT unique security control

2. HIGH PRIORITY FLAGS TO TEST:
""")

    # Find the flags closest to sysentvec
    sysentvec_ps5 = 0xD11BB8
    close_flags = [(abs(loc - sysentvec_ps5), loc) for loc in flag_locations]
    close_flags.sort()

    print("   Flags closest to sysentvec_ps5:")
    for dist, loc in close_flags[:10]:
        print(f"     0x{loc:08X} (distance: {dist})")

    print("""
3. ALTERNATIVE APPROACH:
   Instead of these generic flags, look for:
   - The actual sv_flags field in sysentvec structure
   - Prison/jail configuration data
   - Debug/development mode flags (might be 0x00 not 0x01)

4. CHECK KERNEL POINTERS:
   The gap area contains several kernel pointers that might
   point to security-critical functions or data:
""")

    gap_start = 0xD11CB8
    gap_end = 0xD11D30
    for i in range(gap_start, gap_end, 8):
        val = read_u64(data, i)
        if is_kernel_ptr(val):
            offset = i - 0xD11BB8
            print(f"     0x{i:08X} (+0x{offset:03X}): -> 0x{val:016X}")

if __name__ == "__main__":
    main()
