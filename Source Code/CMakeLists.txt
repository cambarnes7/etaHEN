cmake_minimum_required (VERSION 3.20)

project("etaHEN")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

# Strip -fuse-ld=lld from linker flags — the toolchain sets it for the
# x86_64-freebsd-pc-elf target (used by CMake's compiler test), but
# subprojects override the target to x86_64-sie-ps5 which doesn't
# support -fuse-ld. Homebrew's clang finds ld.lld automatically.
string(REPLACE "-fuse-ld=lld" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
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