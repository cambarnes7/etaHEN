#!/bin/bash
# Setup script for etaHEN PS5 SDK build environment
# This creates the ps5-sdk-root directory needed to cross-compile etaHEN.
#
# Prerequisites:
#   - clang and clang++ (LLVM 15+)
#   - ld.lld (LLVM linker)
#   - cmake (3.20+)
#   - ninja-build
#   - lzma (xz-utils)
#   - git
#
# On Ubuntu/Debian:
#   sudo apt install clang lld cmake ninja-build xz-utils git
#
# Usage:
#   ./setup-ps5-sdk.sh [output-dir]
#   Default output-dir: ./ps5-sdk-root

set -e

SDK_DIR="${1:-$(pwd)/ps5-sdk-root}"
SDK_DIR="$(cd "$(dirname "$SDK_DIR")" && pwd)/$(basename "$SDK_DIR")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== etaHEN PS5 SDK Setup ==="
echo "Output directory: $SDK_DIR"
echo ""

# Check prerequisites
for cmd in clang clang++ ld.lld cmake ninja objcopy; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Please install it first."
        echo "  Ubuntu/Debian: sudo apt install clang lld cmake ninja-build xz-utils binutils"
        exit 1
    fi
done

if ! command -v lzma &>/dev/null; then
    echo "ERROR: 'lzma' not found. Please install xz-utils."
    echo "  Ubuntu/Debian: sudo apt install xz-utils"
    exit 1
fi

# Clone ps5-payload-sdk if not cached
PAYLOAD_SDK_DIR="/tmp/ps5-payload-sdk-$$"
echo ">>> Cloning ps5-payload-sdk..."
git clone --depth 1 https://github.com/john-tornblom/ps5-payload-sdk.git "$PAYLOAD_SDK_DIR"

# Create SDK directory structure
echo ">>> Creating SDK directory structure..."
mkdir -p "$SDK_DIR"/{bin,cmake,include}

# Copy and merge headers
echo ">>> Merging headers..."
cp -r "$PAYLOAD_SDK_DIR"/include_bsd/* "$SDK_DIR/include/"
# PS5-specific headers go under include/ps5/ (etaHEN expects this layout)
mkdir -p "$SDK_DIR/include/ps5"
cp -r "$PAYLOAD_SDK_DIR"/include_ps5/* "$SDK_DIR/include/ps5/"

# Copy linker script from etaHEN source tree (not from ps5-payload-sdk which uses a different format)
cp "$SCRIPT_DIR/Source Code/linker.x" "$SDK_DIR/linker.x"

# Add ENTRY(_start) to linker script (required for proper ELF entry point)
if ! grep -q 'ENTRY(_start)' "$SDK_DIR/linker.x"; then
    sed -i '1i ENTRY(_start)\n' "$SDK_DIR/linker.x"
fi

# Add __text_end symbol to linker script (etaHEN's backtrace.cpp references it)
if ! grep -q '__text_end' "$SDK_DIR/linker.x"; then
    sed -i 's/PROVIDE_HIDDEN(__text_stop = .);/PROVIDE_HIDDEN(__text_stop = .);\n\t\tPROVIDE_HIDDEN(__text_end = .);/' "$SDK_DIR/linker.x"
fi

# Add __init_array_end and __fini_array_end symbols (CRT expects these)
if ! grep -q '__init_array_end' "$SDK_DIR/linker.x"; then
    sed -i 's/PROVIDE_HIDDEN(__init_array_stop = .);/PROVIDE_HIDDEN(__init_array_stop = .);\n        PROVIDE_HIDDEN(__init_array_end = .);/' "$SDK_DIR/linker.x"
fi
if ! grep -q '__fini_array_end' "$SDK_DIR/linker.x"; then
    sed -i 's/PROVIDE_HIDDEN(__fini_array_stop = .);/PROVIDE_HIDDEN(__fini_array_stop = .);\n        PROVIDE_HIDDEN(__fini_array_end = .);/' "$SDK_DIR/linker.x"
fi

# Build CRT (C Runtime startup code) from ps5-payload-sdk
echo ">>> Building CRT (crt1.o)..."
mkdir -p "$SDK_DIR/lib"
CRT_DIR="$PAYLOAD_SDK_DIR/crt"
CRT_CFLAGS="-ffreestanding -fno-builtin -nostdlib -fPIC -target x86_64-sie-ps5 -fno-plt -fno-stack-protector -Wall -Werror"
for src in crt klog kernel rtld patch mdbg env; do
    clang -c $CRT_CFLAGS -o "$CRT_DIR/$src.o" "$CRT_DIR/$src.c"
done
ld.lld -r -o "$SDK_DIR/lib/crt1.o" "$CRT_DIR"/crt.o "$CRT_DIR"/klog.o "$CRT_DIR"/kernel.o "$CRT_DIR"/rtld.o "$CRT_DIR"/patch.o "$CRT_DIR"/mdbg.o "$CRT_DIR"/env.o

# Remove conflicting FreeBSD stdatomic.h (uses C-only _Bool, breaks C++ builds)
if [ -f "$SDK_DIR/include/stdatomic.h" ]; then
    rm "$SDK_DIR/include/stdatomic.h"
fi

# Remove old libc++ headers if present (conflict with system libc++)
if [ -d "$SDK_DIR/include/c++" ]; then
    rm -rf "$SDK_DIR/include/c++"
fi

# Add max_align_t to FreeBSD stddef.h (required by libc++)
if ! grep -q '_MAX_ALIGN_T_DECLARED' "$SDK_DIR/include/stddef.h"; then
    sed -i '/#endif \/\* _STDDEF_H_ \*\//i\
#ifndef _MAX_ALIGN_T_DECLARED\
#define _MAX_ALIGN_T_DECLARED\
typedef struct {\
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));\
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));\
} max_align_t;\
#endif' "$SDK_DIR/include/stddef.h"
fi

# Add extra kernel function declarations needed by etaHEN
if ! grep -q 'kernel_getlong' "$SDK_DIR/include/ps5/kernel.h"; then
    sed -i '/#endif \/\/ PS5SDK_KERNEL_H/i\
// Convenience kernel read/write helpers (used by etaHEN)\
intptr_t kernel_getlong(intptr_t kaddr);\
int32_t  kernel_setlong(intptr_t kaddr, intptr_t value);\
uint16_t kernel_getshort(intptr_t kaddr);\
int32_t  kernel_setshort(intptr_t kaddr, uint16_t value);\
int32_t  kernel_mprotect(pid_t pid, intptr_t addr, size_t len, int prot);\
\
intptr_t kernel_dynlib_dlsym(pid_t pid, int handle, const char *sym);' "$SDK_DIR/include/ps5/kernel.h"
fi

# Add NID header needed by libNineS
cat > "$SDK_DIR/include/ps5/nid.h" << 'NIDEOF'
/* PS5 NID encoding header for etaHEN */

#ifndef PS5SDK_NID_H
#define PS5SDK_NID_H

#include <stddef.h>

/**
 * @brief Encode a symbol name into its NID representation
 *
 * @param symbol the symbol name to encode
 * @param nid output buffer (must be at least 12 bytes)
 */
void nid_encode(const char *symbol, char *nid);

#endif // PS5SDK_NID_H
NIDEOF

# Create CMake toolchain
echo ">>> Creating CMake toolchain..."
cat > "$SDK_DIR/cmake/toolchain-ps5.cmake" << 'TOOLEOF'
# PS5 Toolchain for etaHEN

cmake_minimum_required(VERSION 3.20)

if(DEFINED CMAKE_CROSSCOMPILING)
    set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)
    return()
endif()

set(TOOLCHAIN_PATH "${CMAKE_CURRENT_LIST_DIR}/..")

set(CMAKE_SYSTEM_NAME FreeBSD)
set(CMAKE_SYSTEM_VERSION 11)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(PS5 1)

# Skip linking during compiler test (no CRT files for cross-compilation)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(PS5_PAYLOAD_SDK "${TOOLCHAIN_PATH}" CACHE PATH "Path to PS5 payload SDK")

set(CMAKE_C_STANDARD_DEFAULT 17)
set(CMAKE_CXX_STANDARD_DEFAULT 20)

set(TOOLCHAIN_TRIPLE x86_64-pc-freebsd12-elf)

set(CMAKE_ASM_COMPILER_TARGET ${TOOLCHAIN_TRIPLE})
set(CMAKE_C_COMPILER_TARGET   ${TOOLCHAIN_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${TOOLCHAIN_TRIPLE})

set(CMAKE_ASM_FLAGS_INIT "")
set(CMAKE_C_FLAGS_INIT   "")

set(CMAKE_CXX_FLAGS_INIT "")

set(CMAKE_EXE_LINKER_FLAGS "-Wno-unused-command-line-argument -fPIC -nodefaultlibs -T${CMAKE_CURRENT_LIST_DIR}/../linker.x ${CMAKE_CURRENT_LIST_DIR}/../lib/crt1.o")
set(CMAKE_SHARED_LINKER_FLAGS "-Wno-unused-command-line-argument -nostdlib")
add_link_options("LINKER:SHELL:-shared --build-id=none -zmax-page-size=16384 -zcommon-page-size=16384 --hash-style=sysv")

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_C_LINKER_WRAPPER_FLAG "-Xlinker" " ")
TOOLEOF

# Create compiler wrappers
echo ">>> Creating compiler wrappers..."

cat > "$SDK_DIR/bin/ps5-clang++" << 'CXXEOF'
#!/bin/bash
# Wrapper around clang++ that adds libc++ include paths for PS5 cross-compilation.

# Ensure prospero-lld is on PATH for PS5 target linking
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$SCRIPT_DIR:$PATH"

LIBCXX_DIR=""
for dir in /usr/lib/llvm-*/include/c++/v1; do
    if [ -d "$dir" ]; then
        LIBCXX_DIR="$dir"
    fi
done

if [ -n "$LIBCXX_DIR" ]; then
    exec /usr/bin/clang++ -isystem "$LIBCXX_DIR" "$@"
else
    exec /usr/bin/clang++ "$@"
fi
CXXEOF
chmod +x "$SDK_DIR/bin/ps5-clang++"

cat > "$SDK_DIR/bin/ps5-clang" << 'CCEOF'
#!/bin/bash
# Wrapper around clang that ensures prospero-lld is on PATH for PS5 target linking

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$SCRIPT_DIR:$PATH"

exec /usr/bin/clang "$@"
CCEOF
chmod +x "$SDK_DIR/bin/ps5-clang"

# Build prospero-lld wrapper
# The x86_64-sie-ps5 clang target expects a linker named 'prospero-lld'.
# We can't use a symlink to ld.lld (lld checks argv[0] and doesn't recognize
# 'prospero-lld'). We can't use a bash script (clang uses posix_spawn internally).
# So we compile a tiny C binary that sets argv[0] and execs ld.lld.
echo ">>> Building prospero-lld linker wrapper..."
LLD_PATH="$(command -v ld.lld)"
cat > /tmp/prospero-lld.c << LLDEOF
#include <unistd.h>
int main(int argc, char *argv[]) {
    argv[0] = "${LLD_PATH}";
    return execv("${LLD_PATH}", argv);
}
LLDEOF
cc -o "$SDK_DIR/bin/prospero-lld" /tmp/prospero-lld.c
rm /tmp/prospero-lld.c

# Clean up
rm -rf "$PAYLOAD_SDK_DIR"

echo ""
echo "=== PS5 SDK setup complete ==="
echo "SDK location: $SDK_DIR"
echo ""
echo "To build etaHEN:"
echo ""
echo "  # 1. Build the Byepervisor kernel payload:"
echo "  cd 'Source Code/bootstrapper/Byepervisor/hen'"
echo "  mkdir -p build"
echo "  PS5_PAYLOAD_SDK=$SDK_DIR/ CXX=clang++ AS=clang make -j\$(nproc)"
echo "  cd ../../../.."
echo ""
echo "  # 2. Build etaHEN:"
echo "  cd 'Source Code'"
echo "  cmake -B build -G Ninja \\"
echo "    -DCMAKE_TOOLCHAIN_FILE=$SDK_DIR/cmake/toolchain-ps5.cmake \\"
echo "    -DCMAKE_C_COMPILER=$SDK_DIR/bin/ps5-clang \\"
echo "    -DCMAKE_CXX_COMPILER=$SDK_DIR/bin/ps5-clang++ \\"
echo "    -DCMAKE_BUILD_TYPE=Debug"
echo "  cmake --build build"
echo ""
echo "  Output: Source Code/bin/etaHEN.elf"
