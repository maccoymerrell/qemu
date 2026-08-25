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
| `reach_probe.c` | executes an encoding under qemu-x86_64; SIGILL is TCG refusing it |
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

## Reachability is measured, not named

Whether a QEMU x86_64 guest can execute an encoding is what decides whether a
tracer decode gap there costs anything, so the column is the verdict of
running the bytes, not a test on XED's extension string.  `reach_probe.c`
writes each encoding into an executable page and calls it; run under
`qemu-x86_64 -cpu max`, a SIGILL is QEMU's own TCG front end refusing the
opcode.  `compare_attrib.py` exits rather than run without `reach.tsv`.

The name test it replaced is kept only to be contradicted, and its count of
contradictions is printed.  It was wrong by 286 rows.  128 of them are APX:
XED keeps a promoted instruction's ORIGINAL extension — `BMI1`, `BMI2`,
`ADOX_ADCX`, `LZCNT`, `MOVBE`, `RAO`, `USER_MSR` — and carries APX only in the
ISA-SET, so a test on the extension called every EVEX-promoted `andn`, `bextr`
and `adcx` reachable when QEMU TCG has no APX at all.  The other 158 are
AVX_VNNI, AVX_IFMA, SM3, SM4, SHA512, KEYLOCKER, RAO and the rest, none of
which appears in `target/i386/tcg/decode-new.c.inc`.

**What the probe cannot see**, and what the report therefore does not claim:
an instruction QEMU implements only at CPL 0 would SIGILL here for the
privilege rather than for the opcode.  Every SIGILL row was cross-checked
against `decode-new.c.inc` and is absent from it entirely, so the two agree
today; a future divergence is a finding, not a footnote.

## A GREEN isaxcheck GATE IS NOT A MEASUREMENT OF THIS ARM

Recorded because it went wrong, in the verdict document itself, and the shape
is general rather than x86-specific.

`isaxcheck --isa=... --layer={boundary,fields}` and this attribution arm are
two instruments reading two different things.  The gate sweeps encodings and
compares the tracer against LLVM through an allowlist; the arm compares the
tracer's `InsnFields` against XED/LLVM/iced over the opcode DENOMINATOR, out
of `tracer_batch.tsv` on disk.  `compare_attrib.py` NEVER re-probes: it reads
whatever tracer snapshot the working directory happens to hold.

Measured 2026-08-25: `0acd1e32e5` gave the x87 control word its own generic
id and `fa05561046` changed what `FSTENV` writes.  Both verified themselves
against the gate, which was green, is green, and says nothing about this arm.
Re-probing at HEAD moved **119 of the 8,880 rows**, and the published verdict
— computed from a table written four hours before those commits — read
`6182 COVERED / 2698 UNREACHABLE / 0 UNCOVERED` where the tip read
`6065 / 2698 / 117`.

SO: any change that touches `disas/capstone.c`, `champsim_tracer_decode.cc`,
the generic register ids or a per-ISA mnemonic table must re-run the
ATTRIBUTION arm of every affected ISA, not only the gate.  The four entry
points are

    x86_64   isaxcheck --isa=x86_64 --layer=fields --batch < probe_uniq.hex
             > tracer_batch.tsv ; python compare_attrib.py ; python qemu_reach_matrix.py
    aarch64  python ../aarch64/reprobe.py <isaxcheck> ; python ../aarch64/compare.py
    riscv64  python ../riscv64/attrib/compare.py
    mipsel   python ../mipsel/attrib/emit.py

and `coverage_report.py` afterwards.  The tell that this was skipped is a
verdict whose numbers match the previous document exactly across a commit that
changed the decode.
