#!/usr/bin/env python3
"""
PS5 NID Generator - converts function names to 11-char base64 NIDs
Algorithm from etaHEN's libNidResolver
"""
import hashlib
import struct
import sys

# Secret suffix appended before hashing (from etaHEN sha1-x86.c)
NID_KEY = bytes([
    0x51, 0x8D, 0x64, 0xA6,
    0x35, 0xDE, 0xD8, 0xC1,
    0xE6, 0xB0, 0x39, 0xB1,
    0xC3, 0xE5, 0x52, 0x30
])

# Custom base64 alphabet (uses +- instead of +/)
ENCODER = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"

def b64encode_custom(data: bytes) -> str:
    """Custom base64 encode for 8 bytes -> 11 chars"""
    result = []
    # Process 3 bytes at a time
    for i in range(0, 9, 3):  # 0, 3, 6
        if i < len(data):
            a = data[i] if i < len(data) else 0
            b = data[i+1] if i+1 < len(data) else 0
            c = data[i+2] if i+2 < len(data) else 0
            
            abc = (a << 16) | (b << 8) | c
            
            result.append(ENCODER[(abc >> 18) & 0x3F])
            result.append(ENCODER[(abc >> 12) & 0x3F])
            result.append(ENCODER[(abc >> 6) & 0x3F])
            result.append(ENCODER[abc & 0x3F])
    
    return ''.join(result[:11])  # Take only first 11 chars

def name_to_nid(name: str) -> str:
    """
    Generate PS5 NID from function name.
    Algorithm:
    1. Concatenate name + NID_KEY suffix
    2. SHA1 hash the combined data
    3. Take first 8 bytes, swap endianness
    4. Custom base64 encode
    5. Take first 11 characters
    """
    # SHA1(name + NID_KEY)
    data = name.encode('utf-8') + NID_KEY
    sha1_hash = hashlib.sha1(data).digest()
    
    # Take first 8 bytes and reverse (bswap64)
    first_8 = sha1_hash[:8]
    swapped = struct.pack('<Q', struct.unpack('>Q', first_8)[0])
    
    # Add a null byte for the 9th position (algorithm processes 9 bytes for 12 output chars)
    padded = swapped + b'\x00'
    
    return b64encode_custom(padded)

def main():
    if len(sys.argv) < 2:
        print("Usage: names2nid.py <names_file> [output_file]", file=sys.stderr)
        print("       names2nid.py -t <name>  # test single name", file=sys.stderr)
        sys.exit(1)
    
    if sys.argv[1] == '-t' and len(sys.argv) > 2:
        name = sys.argv[2]
        print(f"{name} -> {name_to_nid(name)}")
        return
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    results = []
    with open(input_file, 'r') as f:
        for line in f:
            name = line.strip()
            if name and not name.startswith('#'):
                nid = name_to_nid(name)
                results.append(f"{nid}\t{name}")
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(results) + '\n')
        print(f"Generated {len(results)} NIDs to {output_file}", file=sys.stderr)
    else:
        for r in results:
            print(r)

if __name__ == "__main__":
    main()
