# CLAUDE.md - etaHEN Development Guide

## Project Overview

etaHEN is an All-In-One PS5 Jailbreak/Homebrew enabler written in C/C++. It provides a comprehensive ecosystem for running custom software, debugging applications, and managing the PS5 system.

- **Version**: 2.4B
- **License**: GPLv3
- **Target**: PlayStation 5 (x86_64-sie-ps5)

## Build System

### Requirements
- CMake 3.20+
- Clang compiler (LLVM)
- `PS5_PAYLOAD_SDK` environment variable must be set
- Python3 (for build scripts)

### Build Commands
```bash
cd "Source Code"
mkdir build && cd build
cmake ..
make
```

### Output
- Binaries output to `Source Code/bin/`
- Final payload is LZMA compressed

## Project Structure

```
Source Code/
├── daemon/              # Main runtime daemon (port 9028)
├── shellui/             # Shell UI modifications and Mono hooks
├── bootstrapper/        # Initial payload loader
│   └── Byepervisor/     # Kernel exploit and hypervisor patches
├── util/                # Utility daemon (FTP, PKG installer, cheats)
├── libhijacker/         # Core hijacking/jailbreak library
├── libNidResolver/      # Symbol resolution library
├── libSelfDecryptor/    # SELF file decryption
├── libNineS/            # Low-level kernel utilities
├── libelfldr/           # ELF loader functionality
├── unpacker/            # Payload unpacking with LZMA
├── fps_elf/             # FPS counter/overlay module
├── lib/                 # Pre-compiled PS5 SDK libraries
├── extern/              # External deps (cJSON, pugixml, 7zip, tiny-json)
└── include/             # Shared headers and SDK includes
```

## Key Components

### Daemons
- **daemon/** - Main IPC server on port 9028, handles commands and messaging
- **util/** - Utility services: FTP (1337), PKG installer (12800), Discord RPC

### Core Libraries
- **libhijacker/** - Process hijacking, kernel r/w, firmware offsets
- **libNidResolver/** - PS5 function symbol resolution via NIDs
- **libSelfDecryptor/** - SELF/SPRX decryption
- **libNineS/** - Raw kernel syscall interface
- **libelfldr/** - Custom ELF loading

### UI/Hooks
- **shellui/** - Mono/.NET runtime hooks for PS5 shell modifications
- **fps_elf/** - FPS/system metrics overlay

### Exploitation
- **bootstrapper/** - Entry point, loads compressed payload
- **Byepervisor/** - Hypervisor patches, kernel exploits

## Coding Conventions

### Languages
- C++20 for main application code
- C11 for low-level/kernel interactions
- x86-64 assembly for shellcode and critical paths

### Style Guidelines
- Use namespaces: `dbg::`, `offsets::`, `hijacker::`
- Smart pointers (UniquePtr, SharedPtr) for memory management
- Defensive programming with null/bounds checks
- No exceptions in kernel-facing libraries
- Stack protection enabled (`-fstack-protector-all`)

### File Organization
- Headers in `include/` subdirectories
- Source files in `source/` or `src/` subdirectories
- Each component has its own `CMakeLists.txt`
- External dependencies in `extern/`

## Firmware Support

The codebase supports 40+ PS5 firmware versions (1.00-4.51+). Firmware-specific code uses:
- `offsets.cpp` in libhijacker for memory offsets
- Byepervisor for version-specific kernel patches
- Dynamic offset resolution at runtime

## Configuration

Runtime config: `/data/etaHEN/config.ini`

Key INI options:
- FTP, Discord RPC, game overlays
- Toolbox, cheats, firmware-specific features

## Network Ports

| Port  | Service |
|-------|---------|
| 1337  | FTP server |
| 9020-9028 | IPC/Control |
| 9081  | Klog server |
| 9090  | Direct PKG installer |
| 12800 | PKG installer WebUI |
| 8000  | Discord RPC |

## Common Patterns

### Function Hooking (shellui)
Uses Detour pattern for Mono runtime hooks in `HookFunctions.cpp`

### IPC Messaging
Socket-based messaging via daemon on port 9028, see `msg.cpp`

### Kernel Access
Use `kernel_copyin`/`kernel_copyout` for kernel memory operations

### Process Hijacking
Via libhijacker's debugger interface for process control

## External Dependencies

- **tiny-json** / **cJSON** - JSON parsing
- **pugixml-1.15** - XML parsing
- **7zip-sdk** - LZMA compression
- **pfd_sfo_tools** - PS5 file format utilities

## Important Notes

- Always test against multiple firmware versions when modifying offsets
- Kernel-facing code must be defensive (no exceptions, null checks)
- Payloads are LZMA compressed in final build
- Shell UI modifications require Mono runtime knowledge
