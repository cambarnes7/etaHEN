cmake_minimum_required (VERSION 3.20)

project("etaHEN")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)	# static libs are archive

# Replicate ps5-payload-sdk prospero-lld linker flags
# (prospero-lld adds these automatically but we invoke lld directly on macOS)
add_link_options(
    "LINKER:--pie"
    "LINKER:-T,${PROJECT_ROOT}/elf_x86_64.x"
    "LINKER:--eh-frame-hdr"
    "LINKER:-zmax-page-size=0x4000"
    "LINKER:--hash-style=gnu"
)

# Replicate ps5-payload-sdk prospero-clang compiler flags
add_compile_options(-fno-plt -femulated-tls)

include_directories	(SYSTEM "${PROJECT_ROOT}/include")
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