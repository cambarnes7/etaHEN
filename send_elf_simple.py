#!/usr/bin/env python3
"""Minimal ELF sender for etaHEN - no external dependencies."""
import argparse
import socket
import struct
import time
from pathlib import Path

ELF_PORT = 9027
MAX_NAME_LEN = 32
DAEMON_TYPE = b'\x01'
GAME_TYPE = b'\x02'


def send_elf(host: str, elf_path: Path, name: str, game: bool = False):
    data = elf_path.read_bytes()

    # pad or truncate name to 32 bytes
    name_bytes = name.encode('latin-1')
    if len(name_bytes) > MAX_NAME_LEN:
        name_bytes = name_bytes[:MAX_NAME_LEN]
    else:
        name_bytes += b'\x00' * (MAX_NAME_LEN - len(name_bytes))

    # retry connection until the port is ready (matches original send_elf.py behavior)
    while True:
        try:
            sock = socket.create_connection((host, ELF_PORT), timeout=10)
            break
        except OSError:
            print('Waiting for port to be ready...')
            time.sleep(1)

    with sock:
        sock.sendall(GAME_TYPE if game else DAEMON_TYPE)
        sock.sendall(name_bytes)
        sock.sendall(struct.pack('<Q', len(data)))
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)

        # read any response/log output
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            print(chunk.decode('latin-1', errors='replace'), end='')

    print('done')


def main():
    parser = argparse.ArgumentParser(description='Send an ELF to etaHEN')
    parser.add_argument('ip', help='PS5 IP address')
    parser.add_argument('elf', help='Path to the ELF file')
    parser.add_argument('--name', default=None, help='Process name (default: ELF filename without extension)')
    parser.add_argument('--game', action='store_true', help='Set process type to game')
    args = parser.parse_args()

    elf_path = Path(args.elf)
    if not elf_path.exists():
        print(f'{elf_path} does not exist')
        return

    name = args.name or elf_path.stem
    print(f'Sending {elf_path} as "{name}" to {args.ip}:{ELF_PORT}')
    send_elf(args.ip, elf_path, name, args.game)


if __name__ == '__main__':
    main()
