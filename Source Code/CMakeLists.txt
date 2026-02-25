cmake_minimum_required (VERSION 3.20)

project("etaHEN")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

# Fix cross-compilation linking on macOS: subprojects set
# --target=x86_64-sie-ps5 in CMAKE_CXX_FLAGS, which clang uses for
# both compiling AND linking. The x86_64-sie-ps5 target driver adds
# Sony-specific linker flags (--default-script, CRT objects) that only
# work with Sony's modified lld. Fix: override the linker target back
# to x86_64-freebsd-pc-elf (appears after CXX_FLAGS so last --target
# wins), re-add -fuse-ld=lld, and use -nostdlib to prevent default
# CRT objects from either target.
string(REPLACE "-fuse-ld=lld" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --target=x86_64-freebsd-pc-elf -fuse-ld=lld -nostdlib")
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