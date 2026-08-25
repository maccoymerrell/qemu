# arc3_qemuid — QEMU's own instruction identity, and how far it goes

## What is here

`idprobe.c`
:   A minimal TCG plugin that dumps, for every translated instruction,
    QEMU's decode identity beside the disassembler's opinion of the same
    bytes.  One TSV line per instruction:
    `vaddr <TAB> decode_id <TAB> decode_name <TAB> bytes <TAB> disas`.
    It is deliberately not part of the tracer: the export has to be
    readable by something that carries no other belief about the
    instruction.

`static_census.py`
:   Scans `target/i386/tcg/decode-new.c.inc` and enforces the one
    property the i386 id derivation depends on — that no two
    identity-bearing slots share a source line, because on i386 the id
    IS the source line.  Exits 1 on a collision.  It refuses to report
    zero slots, so a scanner that stops matching the source fails loudly
    instead of printing a clean sheet.

`census.py`
:   The per-row mapping census: how much identity the slot name alone
    loses, and where the slot is coarser or finer than the
    disassembler's mnemonic.

`REPRODUCE.sh <out-dir> [build-dir]`
:   Build, run, census, verdict.  Every rc is checked where it is
    produced; a workload cell that produces no records fails the run.

## Reading the census honestly

**Coarser in the operand-size dimension is granularity, not
disagreement.**  QEMU resolves `X86_SIZE_v` at decode time, so one row
serves `andb`/`andw`/`andl`/`andq` while the disassembler spells the
width into the mnemonic.  Section B of the census is dominated by this
and it convicts nothing.  It is the same class as the gem5 micro-op
count adjudicated 2026-08-24.

**Finer is the interesting direction.**  When one mnemonic splits across
several slots, QEMU is distinguishing encodings the mnemonic does not —
`pushq` across 11 slots is the `0x50+r` register forms, the immediate
forms and the memory form, which are genuinely different rows.

**The name is provenance, never identity.**  Two independent reasons,
both measured:

  * it is not unique — 472 of 854 slots share a name, and 85.5% of
    executed instructions on the census workload carried a name that did
    not determine their slot;
  * it is the generator, not the instruction — `cmp` decodes through
    slots named `SUB`, `test` through a slot named `AND`, because QEMU
    implements them with the flag-setting half of those generators and
    writes the discarded destination out of the row (`X86_OP_ENTRYrr`).

The second is the one that bites a reader who assumes a mnemonic.  The
fix is not to invent better names: a name QEMU's source does not use
would be fabrication.  The slot carries the identity.

## The granularity floor, stated rather than hidden

QEMU's i386 table has no per-instruction identity for the x87 escape
space: root opcodes `0xD8`..`0xDF` are eight slots that all name `x87`
and all dispatch to `gen_x87`, which switches on the modrm byte
internally.  Five more slots name `multi0F` for opcodes not yet
converted to the new decoder.  Thirteen slots in total, and 7 of ~265k
translated instructions on the census workload.  A finer x87 identity
would require converting `gen_x87` to table rows in QEMU itself; that
is a real fix path, not a plugin limitation.

## Contract

The exported pair, its guarantees, and the shape the other three targets
must implement are in
`/mnt/md0/QEMU/cst_runs/p3/arc3/DECODE_IDENTITY_CONTRACT.md` and in the
doc comments on `qemu_plugin_insn_decode_id` /
`qemu_plugin_insn_decode_name`.

Author: Maccoy Merrell
