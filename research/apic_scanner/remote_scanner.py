#!/usr/bin/env python3
"""
APIC_OPS Scanner - Remote kernel memory scanner via PS4DBG protocol
For PS5 FW 4.03 - Scans for consecutive kernel .text pointers
"""

import socket
import struct
import sys
import time

# PS4DBG Protocol
PS4DBG_PORT = 744
CMD_PACKET_MAGIC = 0xFFAABBCC
CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
CMD_SUCCESS = 0x80000000

# Kernel constants for FW 4.03
KERNEL_TEXT_START = 0xFFFFFFFF80000000
KERNEL_TEXT_END   = 0xFFFFFFFF84000000

# Search parameters
SEARCH_START_OFFSET = 0x2000000   # Offset from kernel base
SEARCH_END_OFFSET   = 0x7000000
CHUNK_SIZE = 0x1000  # 4KB chunks
MIN_CONSECUTIVE = 6

class PS4DBG:
    def __init__(self, ip, port=PS4DBG_PORT):
        self.ip = ip
        self.port = port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.ip, self.port))
        print(f"[+] Connected to {self.ip}:{self.port}")

    def disconnect(self):
        if self.sock:
            self.sock.close()

    def send_cmd(self, cmd, data=b''):
        packet = struct.pack('<III', CMD_PACKET_MAGIC, cmd, len(data))
        self.sock.send(packet + data)

    def recv_status(self):
        data = self.sock.recv(4)
        if len(data) < 4:
            return None
        return struct.unpack('<I', data)[0]

    def recv_data(self, length):
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def kernel_base(self):
        self.send_cmd(CMD_KERN_BASE)
        status = self.recv_status()
        if status != CMD_SUCCESS:
            raise Exception(f"CMD_KERN_BASE failed: {hex(status) if status else 'no response'}")
        data = self.recv_data(8)
        return struct.unpack('<Q', data)[0]

    def kernel_read(self, address, length):
        data = struct.pack('<QI', address, length)
        self.send_cmd(CMD_KERN_READ, data)
        status = self.recv_status()
        if status != CMD_SUCCESS:
            return None
        return self.recv_data(length)

def is_kernel_text_ptr(val, kbase):
    """Check if value looks like a kernel .text pointer"""
    # Adjust for actual kernel base
    text_start = kbase
    text_end = kbase + 0x4000000  # ~64MB for .text
    return text_start <= val < text_end

def scan_chunk(dbg, addr, kbase):
    """Scan a chunk for consecutive kernel .text pointers"""
    data = dbg.kernel_read(addr, CHUNK_SIZE)
    if not data:
        return []

    candidates = []
    consecutive = 0
    potential_start = 0

    # Parse as array of uint64
    num_ptrs = len(data) // 8
    for i in range(num_ptrs):
        val = struct.unpack_from('<Q', data, i * 8)[0]

        if is_kernel_text_ptr(val, kbase):
            if consecutive == 0:
                potential_start = addr + (i * 8)
            consecutive += 1
        else:
            if consecutive >= MIN_CONSECUTIVE:
                candidates.append((potential_start, consecutive))
            consecutive = 0

    # Check end of buffer
    if consecutive >= MIN_CONSECUTIVE:
        candidates.append((potential_start, consecutive))

    return candidates

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <PS5_IP> [start_offset] [end_offset]")
        print(f"Example: {sys.argv[0]} 192.168.0.88")
        print(f"Example: {sys.argv[0]} 192.168.0.88 0x6400000 0x6800000")
        sys.exit(1)

    ip = sys.argv[1]
    start_off = int(sys.argv[2], 16) if len(sys.argv) > 2 else SEARCH_START_OFFSET
    end_off = int(sys.argv[3], 16) if len(sys.argv) > 3 else SEARCH_END_OFFSET

    dbg = PS4DBG(ip)

    try:
        dbg.connect()

        # Get kernel base
        print("[*] Getting kernel base...")
        kbase = dbg.kernel_base()
        print(f"[+] Kernel base: {hex(kbase)}")

        search_start = kbase + start_off
        search_end = kbase + end_off
        total_chunks = (search_end - search_start) // CHUNK_SIZE

        print(f"\n=== APIC_OPS Scanner for FW 4.03 ===")
        print(f"Search range: {hex(search_start)} - {hex(search_end)}")
        print(f"Looking for {MIN_CONSECUTIVE}+ consecutive .text pointers")
        print(f"Total chunks: {total_chunks}\n")

        all_candidates = []
        chunks_done = 0

        for addr in range(search_start, search_end, CHUNK_SIZE):
            candidates = scan_chunk(dbg, addr, kbase)

            for (cand_addr, count) in candidates:
                print(f"[CANDIDATE] addr={hex(cand_addr)} count={count} offset={hex(cand_addr - kbase)}")
                all_candidates.append((cand_addr, count))

            chunks_done += 1
            if chunks_done % 512 == 0:
                pct = (chunks_done / total_chunks) * 100
                print(f"[PROGRESS] {chunks_done}/{total_chunks} ({pct:.1f}%) - {hex(addr)}")

        print(f"\n=== Scan Complete ===")
        print(f"Found {len(all_candidates)} candidates\n")

        if all_candidates:
            # Sort by count descending
            all_candidates.sort(key=lambda x: x[1], reverse=True)
            print("Top candidates (sorted by consecutive pointer count):")
            for addr, count in all_candidates[:20]:
                offset = addr - kbase
                print(f"  {hex(addr)} (offset {hex(offset)}) - {count} pointers")

            print(f"\nMost likely apic_ops: {hex(all_candidates[0][0])} with {all_candidates[0][1]} consecutive pointers")
            print(f"Kernel offset: {hex(all_candidates[0][0] - kbase)}")

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        dbg.disconnect()

if __name__ == "__main__":
    main()
