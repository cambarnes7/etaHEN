/*
 * Linker script for PS5 HV research kernel module (flat binary)
 *
 * Produces a position-independent flat binary suitable for
 * loading into kernel memory via DMAP.
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(kmod_main)

SECTIONS
{
    . = 0;

    .text : {
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    . = ALIGN(16);

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.* COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
