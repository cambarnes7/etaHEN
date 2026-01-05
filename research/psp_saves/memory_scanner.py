#!/usr/bin/env python3
"""
PS5 Memory Scanner - Find decrypted PARAM.SFO in memory dumps

Usage:
1. Use PS5Debug to dump memory regions from ScePsP process
2. Run this script on the dumps to find PARAM.SFO location
3. Use PS5Debug to patch at that offset

Patterns we search for:
- SFO magic: 00 50 53 46 ("\0PSF")
- Known strings: "ULUS10512", "PERSONA 3 PORTABLE", "Kotoneee"
- Save structure markers
"""

import os
import sys
import struct
from pathlib import Path

# Patterns to search for
PATTERNS = {
    'sfo_magic': b'\x00PSF',  # SFO file magic
    'psp_title_id': b'ULUS10512',  # P3P US title ID
    'game_title': b'PERSONA 3 PORTABLE',
    'save_category': b'CATEGORY',
    'savedata_dir': b'SAVEDATA_DIRECTORY',
    'player_name': b'Kotoneee',  # From the user's save
    'save_title': b'SAVE DATA',
}

def search_file(filepath: str, patterns: dict) -> list:
    """Search a file for known patterns"""
    results = []

    with open(filepath, 'rb') as f:
        data = f.read()

    filesize = len(data)
    print(f"[*] Scanning {filepath} ({filesize:,} bytes)")

    for name, pattern in patterns.items():
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            results.append({
                'file': filepath,
                'pattern': name,
                'offset': pos,
                'hex_offset': f'0x{pos:X}',
                'context': data[max(0,pos-16):pos+len(pattern)+16]
            })
            offset = pos + 1

    return results

def search_for_sfo_structure(filepath: str) -> list:
    """Search specifically for valid SFO file structure"""
    results = []

    with open(filepath, 'rb') as f:
        data = f.read()

    # Look for SFO magic
    offset = 0
    while True:
        pos = data.find(b'\x00PSF', offset)
        if pos == -1:
            break

        # Validate SFO structure
        if pos + 20 <= len(data):
            magic, version, key_off, data_off, num_entries = struct.unpack(
                '<IIIII', data[pos:pos+20]
            )

            # Check if this looks like a valid SFO
            if (magic == 0x46535000 and  # "\0PSF"
                version in [0x0101, 0x0100] and  # Known versions
                key_off < 0x10000 and  # Reasonable offsets
                data_off < 0x10000 and
                num_entries < 100):  # Reasonable entry count

                # Try to extract some parameter names
                params = []
                if pos + key_off + 50 <= len(data):
                    key_data = data[pos + key_off:pos + key_off + 200]
                    # Split by null to get key names
                    keys = key_data.split(b'\x00')[:num_entries]
                    params = [k.decode('ascii', errors='ignore') for k in keys if k]

                results.append({
                    'offset': pos,
                    'hex_offset': f'0x{pos:X}',
                    'version': f'0x{version:04X}',
                    'key_table_offset': key_off,
                    'data_table_offset': data_off,
                    'num_entries': num_entries,
                    'params': params[:5],  # First 5 param names
                    'likely_valid': 'CATEGORY' in params or 'TITLE' in params
                })

        offset = pos + 1

    return results

def hexdump(data: bytes, offset: int = 0) -> str:
    """Create hexdump string"""
    lines = []
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{data[j]:02X}' for j in range(i, min(i+16, len(data))))
        ascii_part = ''.join(
            chr(data[j]) if 32 <= data[j] < 127 else '.'
            for j in range(i, min(i+16, len(data)))
        )
        lines.append(f'{offset+i:08X}  {hex_part:<48}  {ascii_part}')
    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python memory_scanner.py <memory_dump_file_or_directory>")
        print("")
        print("This tool searches memory dumps for decrypted PARAM.SFO data.")
        print("")
        print("To get memory dumps from PS5:")
        print("  1. Connect PS5Debug while P3P is running with a save loaded")
        print("  2. Find ScePsP/eboot.bin process")
        print("  3. Dump memory regions (especially heaps)")
        print("  4. Transfer dumps to PC")
        print("  5. Run this script on the dumps")
        sys.exit(1)

    target = sys.argv[1]

    if os.path.isfile(target):
        files = [target]
    elif os.path.isdir(target):
        files = list(Path(target).glob('**/*'))
        files = [str(f) for f in files if f.is_file()]
    else:
        print(f"[-] Path not found: {target}")
        sys.exit(1)

    all_pattern_results = []
    all_sfo_results = []

    for filepath in files:
        try:
            # Search for string patterns
            pattern_results = search_file(filepath, PATTERNS)
            all_pattern_results.extend(pattern_results)

            # Search for SFO structures
            sfo_results = search_for_sfo_structure(filepath)
            for r in sfo_results:
                r['file'] = filepath
            all_sfo_results.extend(sfo_results)

        except Exception as e:
            print(f"[-] Error reading {filepath}: {e}")

    # Report pattern matches
    print("\n" + "="*60)
    print("[*] PATTERN MATCHES")
    print("="*60)

    if all_pattern_results:
        for r in all_pattern_results:
            print(f"\n[+] Found '{r['pattern']}' at {r['hex_offset']} in {r['file']}")
            print(f"    Context:\n{hexdump(r['context'], r['offset']-16)}")
    else:
        print("[-] No pattern matches found")

    # Report SFO structures
    print("\n" + "="*60)
    print("[*] SFO STRUCTURES FOUND")
    print("="*60)

    if all_sfo_results:
        for r in all_sfo_results:
            valid_marker = " [LIKELY VALID!]" if r['likely_valid'] else ""
            print(f"\n[+] SFO at {r['hex_offset']} in {r['file']}{valid_marker}")
            print(f"    Version: {r['version']}")
            print(f"    Key table: 0x{r['key_table_offset']:X}")
            print(f"    Data table: 0x{r['data_table_offset']:X}")
            print(f"    Entries: {r['num_entries']}")
            print(f"    Params: {r['params']}")
    else:
        print("[-] No SFO structures found")

    # Summary
    print("\n" + "="*60)
    print("[*] SUMMARY")
    print("="*60)
    print(f"Files scanned: {len(files)}")
    print(f"Pattern matches: {len(all_pattern_results)}")
    print(f"SFO structures: {len(all_sfo_results)}")

    valid_sfos = [r for r in all_sfo_results if r['likely_valid']]
    if valid_sfos:
        print(f"\n[!] Found {len(valid_sfos)} likely valid PARAM.SFO structure(s)!")
        print("    Use PS5Debug to patch at these offsets.")
        for r in valid_sfos:
            print(f"    - {r['file']} offset {r['hex_offset']}")

if __name__ == '__main__':
    main()
