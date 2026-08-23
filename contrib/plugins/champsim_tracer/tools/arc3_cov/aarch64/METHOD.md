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

## The enable gate, no longer a blind spot

The FP/SVE/SME **enable** registers — `CPACR_EL1`, `CPTR_EL2`, `CPTR_EL3` —
used to be filtered out twice over, by `CUT_EXACT` on the `Check*Enabled`
family and by `CONFIG_REGS` in `sysreg_lookup`, because the tracer did not
record them and the two arms had to be comparable.  That was the one place
this reference followed the tracer instead of the architecture, and it is
closed: R7.4 rules the read real — a pending write to `CPACR_EL1.FPEN` has
to resolve before an FP instruction can know whether it traps — the decode
boundary records it, and both filters are lifted.

The gate has its own token, `SYSFPEN`, matching the tracer's own
`REG_SYSFPEN`; folded into `SYS` the comparison could not tell a correct
gate read from a read of any other system register.  `SMCR_ELx` and
`ZCR_ELx` likewise resolve to `VCTRL`, the vector-configuration role,
which is what makes `SMCR_ELx.EZT0` — the second gate the `ZT0` forms
read — visible as itself.

**2,805 of the 3,810 probed subjects now agree WITH the gate on both
sides**, where before they agreed without it.  Eight subjects do not:
six are post-2022-12 encodings scored against LLVM MC, which has no
legality axis and can never carry the read, and two are `SMSTART` /
`SMSTOP`, where Capstone attaches the `MSR (immediate)` SVCR form no
feature group and no operand this boundary classifies, so the tracer
records that instruction as reading and writing nothing at all.

What is still cut, and deliberately: `CONFIG_REGS` drops `SCTLR`, `HCR`,
`SCR` and the translation-configuration registers those same check
functions reach — they say how the address space is configured, not
whether this instruction is enabled — and `IsSVEEnabled`, `IsInHost` and
`ELStateUsingAArch32K` stay in `CUT_EXACT`.

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
