cmake_minimum_required (VERSION 3.20)

project("etaHEN")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

# Fix cross-compilation linking on macOS with LLVM 18+:
# Subprojects set --target=x86_64-sie-ps5 in CMAKE_CXX_FLAGS (used for
# both compile and link). Modern clang recognizes this as a PS5 target and
# activates Sony's linker driver, which adds flags (--default-script, CRT
# objects, etc.) that only work with Sony's modified lld. Fix:
#   1. Override linker target to x86_64-freebsd-pc-elf (last --target wins)
#   2. Re-add -fuse-ld=lld (works with freebsd target)
#   3. Use -nostdlib to prevent FreeBSD CRT objects / default libs
#   4. Allow unresolved symbols — PS5 ELF loader resolves them at runtime
#      via the .dynsym table (NID resolution system)
string(REPLACE "-fuse-ld=lld" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --target=x86_64-freebsd-pc-elf -fuse-ld=lld -nostdlib -Wl,--unresolved-symbols=ignore-all")

# Add PS5 SDK lib path for additional libraries
link_directories("${PS5_PAYLOAD_SDK}/lib")

# Create empty stub archives for libraries that may not exist on all
# platforms (e.g. OpenSSL). The curl in this project was likely built
# against wolfSSL/mbedTLS instead. --unresolved-symbols=ignore-all
# handles any missing symbols at link time.
foreach(_stublib crypto ssl)
    if(NOT EXISTS "${PROJECT_ROOT}/lib/lib${_stublib}.a")
        file(WRITE "${PROJECT_ROOT}/lib/lib${_stublib}.a" "!<arch>\n")
    endif()
endforeach()

# The PS5 SDK names SQLite as libsqlite.a but the project links -lsqlite3
if(NOT EXISTS "${PROJECT_ROOT}/lib/libsqlite3.a" AND EXISTS "${PROJECT_ROOT}/lib/libsqlite.a")
    file(CREATE_LINK "${PROJECT_ROOT}/lib/libsqlite.a" "${PROJECT_ROOT}/lib/libsqlite3.a" COPY_ON_ERROR)
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)	# static libs are archive

include_directories	(SYSTEM "${PROJECT_ROOT}/include")
include_directories(SYSTEM "${PS5_PAYLOAD_SDK}/include/c++/v1")
include_directories(SYSTEM "${PS5_PAYLOAD_SDK}")
include_directories(SYSTEM "${PS5_PAYLOAD_SDK}/include")

add_subdirectory(libhijacker)
add_subdirectory(libNidResolver)
# add_subdirectory(libRPI)
add_subdirectory(libSelfDecryptor)
add_subdirectory(libNineS)
add_subdirectory(libelfldr)
add_subdirectory(shellui)
add_subdirectory(fps_elf)
add_subdirectory(daemon)
add_subdirectory(util)
add_subdirectory(bootstrapper)
add_subdirectory(unpacker)