# ARC 3 coverage — x86_64 register attribution

The whole x86_64 opcode space, one row per XED iform, comparing the register
SOURCE and DESTINATION sets the ChampSim Tracer records against a ranked
reference: Intel XED (rank 1), iced-x86 (rank 2) and LLVM MC (rank 3).
Comparison happens in the tracer's own `GenericRegId` vocabulary, read out of
`champsim_tracer_mnemonics_x86.h`; a reference register with no row there is
reported `UNMAPPED:<name>` and never silently agrees.

`REPRODUCE.sh` runs it end to end.

| file | what it is |
| --- | --- |
| `xl3.cc` | XED + LLVM MC elaborator, one TSV row per encoding per tool |
| `icedtsv.py` | iced-x86 elaborator, same TSV schema |
| `mkprobe.py` | per-opcode probe encodings (EVEX mask slots re-probed `aaa=001`) |
| `xediform.c` | iform + length, for verifying a re-encoded variant is the same opcode |
| `compare_attrib.py` | the comparison, the adjudications, the mechanism roll-up |

## R7.1 is applied by CORRECTING THE REFERENCE

The ruling, verbatim (2026-08-23):

> Things like narrow writes into registers are irrelevant (rename doesn't
> care, because it doesn't know the data-width-scope of the next reader). I
> know for a fact that during execution we track register-data-width, so the
> fact that a register's upper contents may not be modified does not imply it
> is a source AND a destination for the instruction unless the instruction
> specifically takes it as a source.

XED, iced-x86 and LLVM MC all model the HARDWARE bit-preserve.  That is a
different question from the one the wire answers — the wire records the
regfile dependency a renaming machine must respect (R7) — so emitting the
preserve-read was a REFERENCE defect.  It is corrected in the elaborators,
not labelled downstream: **a label cannot change set identity, so a labelled
row can never leave the disagree column.**  This is the same disposition
mipsel took for R7.7, where the reference's invented `REG_LLBIT` was deleted.

Two rules carry it, and both are STANDING rules rather than deletions: the
preserve-read is still DETECTED, counted, and the counts printed on stderr,
so a reference that starts inventing them again is visible.  A count that
falls to zero means the rule stopped reaching its subject and is no longer
proving anything — an inert rule is a finding, not a pass.

**R7.1-NARROW** — a sub-width register write, and a partial flag write, imply
no read.  `setz %al` does not read RAX; `inc` does not read RFLAGS to leave
CF alone; legacy `aesimc` writing 128 of 512 does not read ZMM.

**R7.1-SCALAR** — the same ruling where XED spells the preserve as an operand
ACTION rather than a width.  A legacy scalar SSE form declares its
destination `REG0=XMM_R():rw`, and for `sqrtsd` the `r` half is purely the
surviving upper lanes while for `addsd` it is also the first addend — the two
declarations are byte-identical in `xed-isa.txt`, so the elaborator has to be
told which operations are unary.  The scope is derived from the WHOLE class,
not from the rows that disagreed: enumerating every legacy pattern declaring
`REG0=XMM_R():rw` under `simd_scalar` yields exactly 24 iclasses, of which
ten compute the destination from their other operands alone.  Those ten are
listed in `xl3.cc`; the other fourteen deliberately are not, and that split
is the whole content of the rule.

What R7.1 does **not** cover, and must not be swept into:

* an RFLAGS source that SURVIVES the correction is a real edge — either a
  flag the instruction tests (`cmc`, `rcl`, `in`/`out`'s IOPL gate) or R4's
  conditional flag write (`shl %cl` leaves the flags alone when the count is
  zero, so the old value really does flow through).  `xl3.cc` emits a
  `flagwhy` column saying which, so the roll-up measures the split instead of
  guessing it from the signature shape.
* the tracer recording NOTHING where the reference records a flag WRITE
  (`cli` writes IF).  That is a Capstone access-flag gap.

## Adjudications

XED is rank 1.  A correction is applied only where iced-x86 **and** LLVM MC
both contradict it, explicitly and counted; nothing is averaged.

* **ADJ-1** — EVEX `aaa=000` means *unmasked*, not *reads k0*.
* **ADJ-2** — XED marks a read-modify operand write-only.  Removing the
  preserve-read exposed this rather than causing it: `extrq %xmm0,i,i`
  EXTRACTS a bitfield FROM the register it writes, so the register really is
  a source, and XED's operand action is simply wrong.

## Falsification

An agreement rate quoted off an instrument nobody has watched fail vouches
for nothing.  `REPRODUCE.sh` damages the tracer arm with
`--falsify=drop-src:<mnem>` and requires the agreement count to fall by
exactly the agreeing rows of that mnemonic.
