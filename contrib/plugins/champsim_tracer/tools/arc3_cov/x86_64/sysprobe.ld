ENTRY(_start)
SECTIONS {
    . = 0x100000;
    __load_start = .;
    .multiboot : { *(.multiboot) }
    .text      : { *(.text) }
    .rodata    : { *(.rodata) *(.rodata.*) }
    .data      : { *(.data) }
    __load_end = .;
    .bss       : { *(.bss) *(COMMON) }
    __bss_end  = .;
}
