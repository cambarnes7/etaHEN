cmake_minimum_required(VERSION 3.20)
project(test_payload C)

set(CMAKE_C_FLAGS "--target=x86_64-sie-ps5 -fPIC -fno-plt -fno-stack-protector -march=znver2 -Wall")

link_directories("${CMAKE_SOURCE_DIR}/lib")

add_executable(test_payload main.c)
target_link_libraries(test_payload kernel_sys SceLibcInternal)

set_target_properties(test_payload PROPERTIES OUTPUT_NAME "test_payload.elf")

add_custom_command(TARGET test_payload POST_BUILD
    COMMAND llvm-objcopy --remove-section .debug_info --remove-section .debug_abbrev
            --remove-section .debug_line --remove-section .debug_str
            --remove-section .debug_loc --remove-section .debug_aranges
            --remove-section .debug_ranges --remove-section .debug_pubnames
            --remove-section .debug_pubtypes --remove-section .debug_frame
            --strip-unneeded $<TARGET_FILE:test_payload>
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:test_payload>
            "${CMAKE_SOURCE_DIR}/bin/test_payload.elf"
)
