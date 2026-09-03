# THE REFERENCE-COVERAGE ADJUDICATION, PER REGISTER AND PER ISA

> **RE-DERIVED AT exec112 (PASS 64).  TWELVE OF THE NINETEEN ROWS BELOW ARE
> REFUTED BY MEASUREMENT AND SEVEN SURVIVE.**  The census's LLVM side was
> indexed through CAPSTONE's register table, so a register Capstone cannot
> name had no key at all and every LLVM token for it mapped to nothing:
> `llvm_rd = 0` BY CONSTRUCTION, whatever `MCInstrDesc` says (FINDING 62-B).
> The index is now re-derived off QEMU's OWN system-register names -- the
> boundary states both the spelling and the architectural role, and the
> generic id comes from the role, so nothing here is a hand-written
> correspondence.  The census also LABELS the two ways a zero can be
> manufactured instead of scoring them as measurements.  What that changed is
> in "THE RE-DERIVATION" below; the original rows are kept underneath it
> unedited, because a refuted row is evidence and deleting it would hide the
> shape of the mistake.

exec103 named a class of `SR-rd-phantom` residue rows and offered one
sentence to justify them: registers *"LLVM's MCInstrDesc simply has no
operand for"*.  exec106 tested that sentence with a census
(`ISAX_DUMP_REGCOV=1`) instead of trusting it, and it did not hold
uniformly.  This file is the adjudication that measurement earns — one row
per (ISA, register), with the census attached and a deletion check that a
future reader can run.

It exists as a document and not as allowlist lines for a reason stated in
the last section.

## WHAT THE CENSUS COUNTS

Over every encoding the `--srcenc` corpus reaches, for each generic
register: how many encodings LLVM's read description could name it on
(`llvm_rd`), how many its write description could (`llvm_wr`), and how many
the wire publishes it as a source on (`wire_src`).  The LLVM side is the
GENEROUS expansion — every candidate id an LLVM token could mean — because
an over-count can only make the coverage claim harder to support.

`llvm_rd = 0` AND `llvm_wr = 0` with `wire_src > 0` is the claim's exact
shape: the reference has no operand for the register anywhere in the
population, so the disagreement is a boundary of the REFERENCE and not a
defect in the tracer.  Anything else is a disagreement about content, and
content is argued, not exempted.


## THE RE-DERIVATION (exec112, PASS 64)

The census now prints one of THREE tags on a row that reads `llvm_rd = 0`
and `llvm_wr = 0` with `wire_src > 0`, and only the first justifies an
adjudication:

  * `REFERENCE-HAS-NO-OPERAND` -- the index CAN name the register, no token
    for it is dropped, and LLVM still names it nowhere.  A measurement.
  * `UNANSWERABLE-NO-INDEX-KEY` -- no LLVM token maps to the register at
    all.  The zero is the index's, not the reference's.
  * `UNANSWERABLE-TOKEN-DROPPED` -- every spelling that maps to it is on
    `is_dropped_reg()`'s fold list, so the census threw the answer away.

Measured at this tip over the same four corpora, with the index keyed off
QEMU's names (878 keys learned on aarch64, 11 on x86_64, 4 on riscv64, 0 on
mipsel -- the mipsel boundary states no named system-register operand):

| ISA | register | before | NOW | verdict |
| --- | --- | ---: | --- | --- |
| aarch64 | `REG_SYSFPEN`  | 0 / 0 | llvm_rd **2,673**  | REFUTED |
| aarch64 | `REG_SYS`      | 0 / 0 | llvm_rd **24,687** | REFUTED |
| aarch64 | `REG_SYSMMU`   | 0 / 0 | llvm_rd **22,320** | REFUTED |
| aarch64 | `REG_SYSDBG`   | 0 / 0 | llvm_rd **13,977** | REFUTED |
| aarch64 | `REG_SYSPERF`  | 0 / 0 | llvm_rd **19,053** | REFUTED |
| aarch64 | `REG_VCTRL`    | 0 / 0 | named              | REFUTED |
| aarch64 | `REG_SYSEXC`   | 0 / 0 | llvm_rd **13,950** | REFUTED |
| aarch64 | `REG_SYSID`    | 0 / 0 | llvm_rd **11,160** | REFUTED |
| aarch64 | `REG_SYSCACHE` | 0 / 0 | llvm_rd **11,362** | REFUTED |
| aarch64 | `REG_SYSTIMER` | 0 / 0 | llvm_rd **5,580**  | REFUTED |
| aarch64 | `REG_SSP`      | 0 / 0 | llvm_rd **2,618**  | REFUTED |
| x86_64  | `REG_SSP`      | 0 / 0 | UNANSWERABLE-TOKEN-DROPPED | REFUTED |
| x86_64  | `REG_SYS`      | 0 / 0 | REFERENCE-HAS-NO-OPERAND | SURVIVES |
| x86_64  | `REG_SYSMMU`   | 0 / 0 | REFERENCE-HAS-NO-OPERAND | SURVIVES |
| x86_64  | `REG_SYSTIMER` | 0 / 0 | REFERENCE-HAS-NO-OPERAND | SURVIVES |
| riscv64 | `REG_SYS`      | 0 / 0 | REFERENCE-HAS-NO-OPERAND | SURVIVES |
| mipsel  | `REG_SYSEXC`   | 0 / 0 | REFERENCE-HAS-NO-OPERAND | SURVIVES |
| mipsel  | `REG_SYSDBG`   | 0 / 0 | REFERENCE-HAS-NO-OPERAND | SURVIVES |
| mipsel  | `REG_SYSTIMER` | 0 / 0 | REFERENCE-HAS-NO-OPERAND | SURVIVES |

WHY AARCH64 MOVED AND MIPSEL DID NOT.  LLVM's AArch64 has no system-register
CLASS -- `MRS`/`MSR` take an immediate -- which is what the original rows
said, and it is still true of the register file.  What LLVM DOES have is the
system register's NAME in the printed operand, and the boundary spells the
same names (`cap_aarch64_copy_sysreg_name`), so once QEMU's spelling is a key
the two sides join on it.  On mipsel the boundary states no named
system-register operand at all, so no key was learned and the three
surviving rows rest on Capstone's own MIPS coprocessor tokens, which the
index has always had.

WHAT THIS COSTS THE RESIDUE, RE-QUOTED HONESTLY.  The nineteen rows were
quoted at 3,284 of 7,040 residue signatures -- 47% of the gate's denominator,
85% of aarch64's.  The seven that survive cover **718** signatures:
60 on x86_64, 90 on riscv64, 568 on mipsel, and **0 on aarch64**.  The
difference is not a saving; it is 2,566 signatures that are REAL
disagreements and stay in the residue where a maintainer can see them.

THE SEVEN ARE LANDED, as globbed rows at the end of `isaxcheck_allow.txt`
with this census attached.  The glob is on the MNEMONIC only: the qualifier
is the whole difference set, so a row is licensed only where the register is
the entire disagreement -- which is exactly the claim being made.

REG_SSP's own history is the reason the labels exist.  Its row read
`llvm_rd = 0` for TWO independent reasons, either of which alone
manufactures the zero: Capstone's x86 enum has no `X86_REG_SSP`, so the index
had no key; and `ssp` is on the drop list, so the token is folded out before
the census counts it.  LLVM names SSP implicitly on 66 x86 opcodes, `callq`
among them.  The row was written as a boundary of the reference and it was a
boundary of this tool.

## THE ORIGINAL ROWS, AS WRITTEN AT exec109 (KEPT FOR THE RECORD)

### THE ROWS THAT PASS, MEASURED AT THIS TIP

Corpus: the four `--srcenc` corpora captured fresh from this tip's sled
sweep (x86_64 6,416,314 / aarch64 1,408,171 / riscv64 86,889 / mipsel
548,886 encodings), byte-identical to exec107's.

| ISA | register | llvm_rd | llvm_wr | wire_src |
| --- | --- | ---: | ---: | ---: |
| aarch64 | `REG_SYSFPEN`  | 0 | 0 | 715,802 |
| aarch64 | `REG_SYS`      | 0 | 0 | 13,203 |
| aarch64 | `REG_SYSMMU`   | 0 | 0 | 2,728 |
| aarch64 | `REG_SYSDBG`   | 0 | 0 | 1,969 |
| aarch64 | `REG_SYSPERF`  | 0 | 0 | 1,635 |
| aarch64 | `REG_VCTRL`    | 0 | 0 | 1,343 |
| aarch64 | `REG_SYSEXC`   | 0 | 0 | 793 |
| aarch64 | `REG_SYSID`    | 0 | 0 | 739 |
| aarch64 | `REG_SYSCACHE` | 0 | 0 | 323 |
| aarch64 | `REG_SYSTIMER` | 0 | 0 | 320 |
| aarch64 | `REG_SSP`      | 0 | 0 | 51 |
| mipsel  | `REG_SYSEXC`   | 0 | 0 | **209,878** |
| mipsel  | `REG_SYSDBG`   | 0 | 0 | 289 |
| mipsel  | `REG_SYSTIMER` | 0 | 0 | 128 |
| riscv64 | `REG_SYS`      | 0 | 0 | 10,009 |
| x86_64  | `REG_SYS`      | 0 | 0 | 42,749 |
| x86_64  | `REG_SYSMMU`   | 0 | 0 | 37,214 |
| x86_64  | `REG_SYSTIMER` | 0 | 0 | 7,108 |
| x86_64  | `REG_SSP`      | 0 | 0 | 5,126 |

**THE mipsel `REG_SYSEXC` NUMBER IS WHY THIS WAS NOT WRITTEN EARLIER.**
exec106 measured it at 163,536 on a corpus captured before its own
`06c6cf6186` landed.  At this tip, on a corpus captured after it, it is
209,878 — a difference of exactly **46,342**, which is exactly the number
of MDMX/MSA-space rows exec107 measured moving in the corpus.  A row
written against the old figure would have carried a census that had already
stopped being true, which is the failure mode this file is supposed to
prevent, not repeat.

NINETEEN ROWS IN TOTAL.  x86_64's census is the slowest arm (6.4M
encodings) and finished after the first four ISAs; its four rows reproduce
exec106's readings to the unit, which is the expected result -- nothing
between the two passes touched an x86 translator.

## THE ROWS THAT DO NOT PASS, AND WHAT EACH IS OWED INSTEAD

### `REG_FCSR` — a DIRECTION disagreement, not a coverage boundary

LLVM names this register on EVERY ISA:

    x86_64   llvm_rd=22,124  llvm_wr=437,540  wire_src=438,838
    aarch64  llvm_rd=52,623  llvm_wr=0        wire_src=168,350
    mipsel   llvm_rd=9,000   llvm_wr=8,928    wire_src=39,568
    riscv64  llvm_rd=5,056   llvm_wr=0        wire_src=16,672

So these rows are not at the edge of the reference's vocabulary; the
reference is speaking, and it is saying something different.  On x86_64 it
describes the FPU status word as WRITTEN twenty times more often than read,
while the wire publishes it as a SOURCE.  Both statements can be true of
the same instruction, and neither is a coverage question:

  * an accumulating status register — x87's status word, RISC-V's `fflags`,
    MIPS's `FCSR` cause/flag bits — is read-modify-written by every
    operation that can raise a flag.  Its new value is a function of its
    old one, so the READ is architectural under R17's value-read test and
    under R16's rule that an ISA-defined dependency is recorded regardless
    of semantics.
  * LLVM's `Defs`/`Uses` lists are a REGISTER-ALLOCATION model.  A register
    that is clobbered is listed in `Defs` whether or not the new value
    depends on the old, because that is all the allocator needs to know.
    An accumulating status word is precisely the case where those two
    readings diverge.

The argument belonged with exec105's x87 push/pop ledger, which is the same
question about the same file of registers, and it was PARKED there.  **THE
LEDGER IS CLOSED AND THE ARGUMENT LANDS WITH IT.**  What was reasoning is
now two measurements, on two ISAs, in this file's own corpus:

  * `d1bf96151d` states the WRITE half of the aarch64 FP status word at
    `fpstatus_ptr()`, where the READ half was already stated, and refuses it
    for exactly the two flavours QEMU's own `vfp_get_fpsr_from_host()`
    excludes because FPCR.AH suppresses the cumulative bits.  8,218 aarch64
    encodings now carry the register in BOTH directions.  Nothing had to
    choose between them.
  * `93247f8507` declares FPSR.QC, whose stickiness makes the read
    architectural under R17's merging-partial-write rule, and the wire's
    SOURCE list gains it on 1,344 encodings at the same time as QEMU's write
    list does.

An accumulating status register is read AND written by the same instruction.
LLVM lists it under `Defs` because a register-allocation model needs no
finer answer; this format needs one and records both.  The two counts were
never in conflict, and the row is SETTLED rather than exempted: **no
coverage exemption is written for `REG_FCSR`, and none is needed.**

### `REG_SYSMMU` on mipsel — REFUTED, and dropped

    mipsel  llvm_rd=13,101  llvm_wr=13,056  wire_src=1,030

LLVM models it.  There is nothing to exempt, and the claim is DROPPED
rather than re-argued: no row is owed, and the 1,030 publications are
either justified on their own merits at the decode site or they are a
defect, which is a question about MIPS TLB instructions and not about the
reference's vocabulary.

Note that `REG_SYSMMU` PASSES on aarch64 (0/0/2,728) and `REG_VCTRL` passes
on aarch64 while LLVM names it on riscv64.  A justification written once
and applied across ISAs would have been wrong in both directions; that is
why every row above carries its ISA.

### `REG_CTRL0` on mipsel — NO SUBJECT

`wire_src = 0`.  The corpus never publishes it and the residue files
mention it zero times.  An allowlist row for it would have matched nothing
from the day it was written — the dead-rule shape, planted by hand.  No row.

## THE DELETION CHECK

Each row above is deletable, and the check is the census that created it:
re-run `ISAX_DUMP_REGCOV=1 isaxcheck --isa=<isa> --srcenc=<corpus>` and
delete any row whose `llvm_rd` or `llvm_wr` has become non-zero.  A row that
survives an LLVM version bump on that check has been re-measured, not
re-asserted.

## WHAT LANDING THESE AS ALLOWLIST ROWS WOULD COST, MEASURED

`isaxcheck_allow.txt` rows would remove the covered signatures from the
`--srcenc` residue.  At this tip the residue is 7,040 signatures across
eight arms (x86_64 502, aarch64 1,079, riscv64 1,046, mipsel 893, each
twice).  Of the three ISAs whose census is complete here:

    aarch64  residue 1,079   covered by the passing registers  918
    mipsel   residue   893   covered by the passing registers  645
    riscv64  residue 1,046   covered by the passing registers   44
    x86_64   residue   502   covered by the passing registers   35
    ---------------------------------------------------------------
    per arm    3,520                                          1,642
    both arms  7,040                                          3,284

So the rows would remove **3,284 of the 7,040** residue signatures -- 47%
of a standing gate's denominator, and 85% of aarch64's.  That is a large,
single, reversible decision about a bar, and this is the pass that just
re-quoted that residue clean.  The adjudication is therefore WRITTEN, with
its census and its deletion check, and the allowlist lines are left for the
maintainer to accept as one decision rather than smuggled in beside a
measurement of the thing they change.

Author: Maccoy Merrell.
