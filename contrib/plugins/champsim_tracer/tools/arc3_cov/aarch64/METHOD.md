# ARC 3 — aarch64 register attribution, measured

**3,920 opcode subjects. 2,779 agree, 1,141 disagree, 0 unprobed.**

The question is narrow: for every opcode in the aarch64 space, is the
register SOURCE and DESTINATION set the tracer records today the set the
architecture defines?  Today those sets come from Capstone; ARC 3 replaces
them with QEMU-derived truth, and this is the before-picture that says how
much replacing is owed.

## The reference is the pseudocode, executed

Rank 1 for this ISA is the Arm MRA (`ISA_A64_xml_A_profile-2022-12`).  Its
instruction pages carry the decode and execute ASL, and every register
access in them is tagged — `impl-aarch64.X.read.2`, `impl-aarch64.Z.write.2`
— so the architecture states which registers an instruction reads and
writes rather than leaving it to be inferred from a disassembler's operand
list.  Nothing here consults Capstone (R7).

`aslparse.py` is an ASL lexer and parser; `aslinterp.py` a partial
evaluator.  For each subject the representative encoding's field bits are
read out of the `regdiagram`, the decode ASL is evaluated **concretely**
against them, and the execute ASL is evaluated with register and memory
contents unknown.  A branch on an unknown condition executes **both** arms
and unions their effects — R5 mechanised, so `csel` names `Xn`, `Xm` and
`NZCV`, and a conditional write is recorded whether or not it fires.

Shared-library functions are inlined so implicit operands arrive:
`ConditionHolds` is why a conditional select reads the flags, `FPAdd` →
`FPProcessException` is why floating-point arithmetic writes `FPSR`.  The
exception-delivery, address-translation, debug, profiling and trap-check
families are cut; the cut is a list in `mra_ref.py`, not a hand-wave.

## The one place the reference follows the tracer instead of the architecture

The FP/SVE/SME **enable** registers — `CPACR_EL1`, `CPTR_EL2`, `CPTR_EL3` —
are filtered out twice over, by `CUT_EXACT` on the `Check*Enabled` family and
by `CONFIG_REGS` in `sysreg_lookup`.  Under R7.4 those reads are real: a
pending write to `CPACR_EL1.FPEN` has to resolve before an FP instruction can
know whether it traps, which is an edge a renaming regfile must respect.  They
stay filtered because the tracer does not record them yet, and the two arms
have to be comparable.

It is a blind spot with a measured size.  Lifting both filters together makes
**2,803 of the 3,810 probed subjects** gain a `SYS` source — 771 mnemonics,
the whole of advsimd/float/fpsimd/sve/sve2/SME — and **none of them already
carries one**, so every one would be a new edge.  All 2,803 land on `REG_SYS`,
which on AArch64 is the entire system-register file bar NZCV, FPCR, FPSR,
FPMR, TPIDR and the 23 `REG_SYSID` constants.  Recording them onto that one id
would make every FP instruction depend on every unrelated `MSR` — R8.5's
situation, at 280× the riscv64 scale that left ten rows folded.  The AArch64
system-register file has to be split first, exactly as `58202796b9` split
mipsel's CP0 file before R7.6 could be honoured.

## Liveness, because the pseudocode uses destinations as scratch

`LD1 {V4.4S}, [X3]` reads `V4` in the ASL — into a scratch variable, one
element at a time, and writes it straight back.  Taken literally the
reference would claim a dependency that does not exist.  A read is dropped
when its value is never consumed, or when the variable it feeds is written
back to the same register with every bit overwritten on a path that
certainly executes.  Both conditions are load-bearing: single-lane `LD1`,
merging-predicated SVE and the accumulating dot products keep their read,
and `LDFF1` keeps its destination read because unloaded elements genuinely
retain their old value.

## Running it

```sh
python sweep.py          # MRA -> ref_mra.json      (~30 s, 3,814 subjects)
python compare.py        # + tracer + LLVM -> attrib.tsv, attrib_signatures.txt
python adjudicate.py     # -> attrib_adjudication.txt
```

The tracer column comes from
`isaxcheck --isa=aarch64 --layer=fields --hex=<bytes>`, one process per
encoding.  `_ref/` under the run directory holds the MRA tarballs.

## What the measurement rests on

Both sides are canonicalised to full-width names (R4), so no sub-register
difference is ever counted as a disagreement.  LLVM MC rides along as an
independent third column on every row, and supplies the reference for the
106 post-2022-12 encodings the 2022-12 MRA does not name.

Two tiers are distinguished.  Tier A is the operand space both models can
express.  Tier B is execution context — `PSTATE.SM`, `PSTATE.EL`,
`PSTATE.UAO`, the PC — which the tracer's generic register space has no
class for at all; those are counted in their own table rather than folded
into the verdict, because a representational boundary is not an attribution
error.

Power: all 2,746 agreeing rows with a non-empty operand set were perturbed
and re-compared, and all 2,746 flipped.  The instrument fires.

`attrib/attrib_adjudication.txt` carries the per-signature verdicts, the
Tier-B census, the per-class breakdown, and the blind spots.
