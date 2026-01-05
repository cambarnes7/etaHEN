#!/usr/bin/env python3
"""
PSP Save Data Analyzer - P3PSAVE.BIN Analysis Tool
Analyzes Persona 3 Portable save file structure for potential vulnerabilities.

PSP save files typically contain:
- Header with magic/version
- Game-specific data structures
- Potentially encrypted sections (PSP uses AES for SDDATA.BIN)

Common vulnerability targets:
- String fields without length limits
- Array indices without bounds checking
- Pointer/offset fields
- Checksum bypasses
"""

import struct
import sys
import os
from typing import Dict, List, Tuple, Optional
import json

class SaveAnalyzer:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = None
        self.findings: List[str] = []

    def load(self) -> bool:
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            print(f"[+] Loaded {len(self.data)} bytes from {self.filepath}")
            return True
        except Exception as e:
            print(f"[-] Failed to load: {e}")
            return False

    def analyze_structure(self):
        """Analyze the binary structure of the save file"""
        print("\n" + "="*60)
        print("[*] SAVE FILE STRUCTURE ANALYSIS")
        print("="*60)

        # Basic stats
        print(f"\nFile size: {len(self.data)} bytes (0x{len(self.data):X})")

        # Check for common magic bytes
        print("\n[*] Magic byte analysis:")
        self._check_magic_bytes()

        # Look for strings
        print("\n[*] String analysis:")
        self._find_strings()

        # Look for potential pointers/offsets
        print("\n[*] Potential offsets/pointers:")
        self._find_potential_offsets()

        # Entropy analysis (detect encrypted regions)
        print("\n[*] Entropy analysis (detect encryption):")
        self._analyze_entropy()

        # Pattern analysis
        print("\n[*] Repeating patterns:")
        self._find_patterns()

    def _check_magic_bytes(self):
        """Check for known magic bytes at start of file"""
        known_magics = {
            b'\x00PSF': 'SFO file (wrong file type?)',
            b'PSVS': 'PS Vita save',
            b'SCE\x00': 'SCE encrypted',
            b'PSP\x00': 'PSP format',
            b'\x89PNG': 'PNG image',
            b'\x00\x00\x00\x00': 'Null bytes (possibly encrypted)',
        }

        if len(self.data) >= 4:
            first_4 = self.data[:4]
            print(f"  First 4 bytes: {first_4.hex()} ({repr(first_4)})")

            for magic, desc in known_magics.items():
                if self.data.startswith(magic):
                    print(f"  [!] Matched: {desc}")
                    break

        # Check for P3P-specific headers
        # Persona 3 Portable uses specific save structures
        if len(self.data) >= 8:
            first_8 = self.data[:8]
            print(f"  First 8 bytes: {first_8.hex()}")

    def _find_strings(self, min_length: int = 4):
        """Find ASCII and UTF-16 strings"""
        strings_found = []

        # ASCII strings
        current = []
        offset = 0
        for i, b in enumerate(self.data):
            if 32 <= b < 127:
                if not current:
                    offset = i
                current.append(chr(b))
            else:
                if len(current) >= min_length:
                    strings_found.append((offset, ''.join(current), 'ASCII'))
                current = []

        if len(current) >= min_length:
            strings_found.append((offset, ''.join(current), 'ASCII'))

        # Print interesting strings
        interesting_keywords = ['save', 'data', 'name', 'player', 'level', 'item',
                                'persona', 'skill', 'equip', 'money', 'time', 'date',
                                'hp', 'sp', 'exp', 'status', 'flag', 'event']

        print(f"  Found {len(strings_found)} strings (>= {min_length} chars)")

        # Show first 20 and any interesting ones
        shown = 0
        for offset, string, encoding in strings_found[:20]:
            print(f"    0x{offset:06X}: \"{string}\"")
            shown += 1

        # Also show any that match keywords
        for offset, string, encoding in strings_found[20:]:
            lower = string.lower()
            if any(kw in lower for kw in interesting_keywords):
                print(f"    0x{offset:06X}: \"{string}\" [INTERESTING]")

        return strings_found

    def _find_potential_offsets(self):
        """Find 32-bit values that could be offsets into the file"""
        file_size = len(self.data)
        potential_offsets = []

        for i in range(0, len(self.data) - 4, 4):
            value = struct.unpack('<I', self.data[i:i+4])[0]
            # Check if it could be a valid offset
            if 0 < value < file_size and value != 0xFFFFFFFF:
                potential_offsets.append((i, value))

        print(f"  Found {len(potential_offsets)} potential offsets")

        # Show first 10
        for i, (offset, value) in enumerate(potential_offsets[:10]):
            # Check what's at that offset
            target_preview = self.data[value:value+8].hex() if value + 8 <= file_size else "..."
            print(f"    @0x{offset:06X}: 0x{value:08X} -> [{target_preview}]")

        return potential_offsets

    def _analyze_entropy(self, block_size: int = 256):
        """Calculate entropy in blocks to detect encrypted regions"""
        import math

        def calc_entropy(data: bytes) -> float:
            if not data:
                return 0
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            entropy = 0
            for count in freq.values():
                p = count / len(data)
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy

        print(f"  Analyzing {len(self.data) // block_size} blocks of {block_size} bytes")

        high_entropy_regions = []
        low_entropy_regions = []

        for i in range(0, len(self.data), block_size):
            block = self.data[i:i+block_size]
            entropy = calc_entropy(block)

            if entropy > 7.5:  # High entropy (likely encrypted/compressed)
                high_entropy_regions.append((i, entropy))
            elif entropy < 2.0:  # Low entropy (likely padding/nulls)
                low_entropy_regions.append((i, entropy))

        print(f"  High entropy regions (encrypted?): {len(high_entropy_regions)}")
        for offset, ent in high_entropy_regions[:5]:
            print(f"    0x{offset:06X}: entropy={ent:.2f}")

        print(f"  Low entropy regions (padding?): {len(low_entropy_regions)}")
        for offset, ent in low_entropy_regions[:5]:
            print(f"    0x{offset:06X}: entropy={ent:.2f}")

        return high_entropy_regions, low_entropy_regions

    def _find_patterns(self, pattern_length: int = 4):
        """Find repeating patterns"""
        patterns: Dict[bytes, List[int]] = {}

        for i in range(len(self.data) - pattern_length):
            pattern = self.data[i:i+pattern_length]
            if pattern not in patterns:
                patterns[pattern] = []
            patterns[pattern].append(i)

        # Find most common non-trivial patterns
        common = []
        for pattern, offsets in patterns.items():
            if len(offsets) > 3 and pattern != b'\x00\x00\x00\x00' and pattern != b'\xFF\xFF\xFF\xFF':
                common.append((pattern, offsets))

        common.sort(key=lambda x: len(x[1]), reverse=True)

        print(f"  Found {len(common)} repeating patterns")
        for pattern, offsets in common[:10]:
            print(f"    {pattern.hex()}: {len(offsets)} occurrences")

    def hexdump(self, offset: int = 0, length: int = 512):
        """Print hex dump"""
        print(f"\n[*] Hex dump at offset 0x{offset:X}, length {length}:")
        end = min(offset + length, len(self.data))

        for i in range(offset, end, 16):
            hex_part = ' '.join(f'{self.data[j]:02X}' for j in range(i, min(i+16, end)))
            ascii_part = ''.join(
                chr(self.data[j]) if 32 <= self.data[j] < 127 else '.'
                for j in range(i, min(i+16, end))
            )
            print(f"  {i:08X}  {hex_part:<48}  {ascii_part}")

    def identify_p3p_structure(self):
        """Try to identify Persona 3 Portable specific structures"""
        print("\n" + "="*60)
        print("[*] PERSONA 3 PORTABLE SPECIFIC ANALYSIS")
        print("="*60)

        # P3P save data typically includes:
        # - Player name (usually near start, UTF-16 or ASCII)
        # - Current date/time in game
        # - Money (yen)
        # - Party member stats
        # - Persona compendium
        # - Social link progress
        # - Equipment data

        print("""
Persona 3 Portable save structure (typical):
--------------------------------------------
- Header with checksum/magic
- Player name (variable length string)
- Play time (uint32 seconds?)
- In-game date (month/day/year)
- Current location
- Money (uint32)
- Party stats array
- Inventory array
- Persona compendium data
- Social link flags
- Event flags

Looking for exploitable fields:
- Player name: Buffer overflow if no length check
- Inventory: Array index overflow
- Party count: If used as loop bound
- Persona names: String overflow
""")

        # Look for potential name field (ASCII string near start)
        print("\n[*] Looking for player name field...")
        for i in range(min(256, len(self.data))):
            # Check for start of ASCII string
            if 32 < self.data[i] < 127:
                # Try to read a name-like string
                name = []
                j = i
                while j < len(self.data) and j < i + 20:
                    if 32 <= self.data[j] < 127:
                        name.append(chr(self.data[j]))
                        j += 1
                    else:
                        break
                if 3 <= len(name) <= 16:
                    print(f"    @0x{i:04X}: Possible name: \"{''.join(name)}\"")

        # Look for money (reasonable range 0 - 9,999,999)
        print("\n[*] Looking for money field...")
        for i in range(0, min(512, len(self.data) - 4), 4):
            value = struct.unpack('<I', self.data[i:i+4])[0]
            if 1000 <= value <= 9999999:
                print(f"    @0x{i:04X}: Possible money: {value}")

    def print_vulnerabilities(self):
        """Print exploitation guidance"""
        print("\n" + "="*60)
        print("[!] EXPLOITATION TARGETS")
        print("="*60)
        print("""
P3P SAVE CORRUPTION TARGETS:
============================

1. STRING FIELDS (Player Name, Persona Names)
   - Overflow beyond expected buffer
   - Remove null terminators
   - Insert format string characters (%s, %n, %x)

2. ARRAY INDICES (Inventory, Party, Skills)
   - Set count fields to 0xFFFFFFFF
   - Negative indices (0xFFFFFFFF = -1)
   - Out-of-bounds indices

3. NUMERIC OVERFLOW
   - Set money/HP/SP to 0xFFFFFFFF
   - Set counts beyond limits
   - Integer overflow in calculations

4. CHECKSUM BYPASS
   - If save has checksum, need to:
     a) Find and update it, OR
     b) Find code path that skips check

5. TYPE CONFUSION
   - If format field exists, set wrong type
   - Binary data where string expected

SCEPSP EMULATOR TARGETS:
========================
The PSP emulator (ScePsP) runs on PS5 and must parse this save.
Vulnerabilities in the emulator's save parser become PS5 vulnerabilities.

Key insight: ScePsP is a PS4-ABI userspace application.
Code exec in ScePsP = PS4 app context = kernel syscall access
""")


def main():
    if len(sys.argv) < 2:
        print("Usage: python save_analyzer.py <P3PSAVE.BIN> [--hexdump]")
        print("\nPlace your P3PSAVE.BIN file in this directory:")
        print("  /home/user/etaHEN/research/psp_saves/")
        sys.exit(1)

    filepath = sys.argv[1]

    analyzer = SaveAnalyzer(filepath)
    if not analyzer.load():
        sys.exit(1)

    analyzer.analyze_structure()
    analyzer.identify_p3p_structure()

    if '--hexdump' in sys.argv:
        analyzer.hexdump(0, 512)

    analyzer.print_vulnerabilities()


if __name__ == '__main__':
    main()
