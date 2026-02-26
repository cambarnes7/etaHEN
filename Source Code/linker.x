/* Linker script based on ps5-payload-sdk elf_x86_64.x by John Tornblom
   Modified for etaHEN to add __text_end, __payload_start/end symbols
   and merge .ctors into init_array */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS {
	ph_text   PT_LOAD FLAGS (0x5);
	ph_rodata PT_LOAD FLAGS (0x4);
	ph_data   PT_LOAD FLAGS (0x6);
	ph_dyn    PT_DYNAMIC;
}

SECTIONS {
	PROVIDE (__payload_start = .);

	.text : ALIGN(CONSTANT(MAXPAGESIZE)) {
	    PROVIDE_HIDDEN (__text_start = .);
	    *(.text .text.*)
	    PROVIDE_HIDDEN (__text_stop = .);
	    PROVIDE_HIDDEN (__text_end = .);
	} : ph_text

	.rodata : ALIGN(CONSTANT(MAXPAGESIZE)) {
	    *(.rodata .rodata.*)

	    PROVIDE_HIDDEN(__init_array_start = .);
	    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
	    KEEP(*(.init_array .ctors))
	    PROVIDE_HIDDEN(__init_array_end = .);

	    PROVIDE_HIDDEN(__fini_array_start = .);
	    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
	    KEEP(*(.fini_array .dtors))
	    PROVIDE_HIDDEN(__fini_array_end = .);
	} : ph_rodata

	.rela : { *(.rela *.rela.*) }

	.data : ALIGN(CONSTANT(MAXPAGESIZE)) {
	    *(.data .data.*)
	} : ph_data

	.dynamic : ALIGN(CONSTANT(MAXPAGESIZE)) {
	    PROVIDE_HIDDEN (_DYNAMIC = .);
	    *(.dynamic)
	} : ph_data : ph_dyn

	.got : {
	    *(.got .got.*)
	} : ph_data

	.bss (NOLOAD) : ALIGN(CONSTANT(MAXPAGESIZE)) {
	    PROVIDE_HIDDEN (__bss_start = .);
	    *(.bss .bss.*);
	    *(COMMON)
	    PROVIDE_HIDDEN (__bss_end = .);
	} : ph_data

	PROVIDE (__payload_end = .);
}
