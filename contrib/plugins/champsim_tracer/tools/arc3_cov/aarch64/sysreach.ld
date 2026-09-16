ENTRY(_start)
SECTIONS {
    . = 0x40100000;
    __text_start = .;
    .text      : { *(.text.boot) *(.text) }
    __text_end = .;
    .rodata    : { *(.rodata) *(.rodata.*) }
    .data      : { *(.data) }
    . = ALIGN(4096);
    .bss       : { *(.bss) *(COMMON) }
}
