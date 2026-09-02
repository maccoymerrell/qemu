# THE REFERENCE-COVERAGE ADJUDICATION, PER REGISTER AND PER ISA

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

## THE ROWS THAT PASS, MEASURED AT THIS TIP

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

**THE mipsel `REG_SYSEXC` NUMBER IS WHY THIS WAS NOT WRITTEN EARLIER.**
exec106 measured it at 163,536 on a corpus captured before its own
`06c6cf6186` landed.  At this tip, on a corpus captured after it, it is
209,878 — a difference of exactly **46,342**, which is exactly the number
of MDMX/MSA-space rows exec107 measured moving in the corpus.  A row
written against the old figure would have carried a census that had already
stopped being true, which is the failure mode this file is supposed to
prevent, not repeat.

x86_64's census is the slowest arm (6.4M encodings) and had not finished
when this document was written; exec106's x86_64 readings were
`REG_SYS 42,749`, `REG_SYSMMU 37,214`, `REG_SYSTIMER 7,108`, `REG_SSP
5,126`, and they are QUOTED, not re-measured.  They are not entered above.

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

The argument therefore belongs with exec105's x87 push/pop ledger, which is
the same question about the same file of registers, and it is PARKED there
by standing instruction. **No coverage exemption may be written for
`REG_FCSR`, and this file records the refusal rather than leaving the row
looking un-adjudicated.**

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
    ---------------------------------------------------------------
    three ISAs 3,018                                          1,607

So the rows would move a standing gate's denominator by a little over half
its rows on those three arms.  That is a large, single, reversible decision
about a bar, its x86_64 quarter is not yet measured at this tip, and this
is the pass that just re-quoted the residue clean.  The adjudication is
therefore WRITTEN, with its census and its deletion check, and the
allowlist lines are left for the maintainer to accept as one decision
rather than smuggled in beside a measurement of the thing they change.

Author: Maccoy Merrell.
