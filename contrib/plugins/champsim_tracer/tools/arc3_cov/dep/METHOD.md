# ARC 3 — the riscv64 and mipsel INTRA-INSTRUCTION DEPENDENCY leg

Author: Maccoy Merrell.

## Why this leg exists

The dependency map is being moved off Capstone's `.dep_refine` classifiers and
onto QEMU's own emitters (`DEPMAP_DESIGN.md`).  Nothing that was already in
this arc can check the result:

* **Capstone** states architectural OPERANDS.  A static decoder has no notion
  of which operand feeds which result, so it cannot state a dependency at all
  — which is the whole reason the refiners existed.
* **`irdf`** compares the tracer's static claim against QEMU's own TCG
  translation.  Both sides are QEMU.  CP-M and CP-H are QEMU-derived, so a
  green `irdf` arm is evidence about an internal consistency and nothing else.

**gem5 is neither.**  It cracks a macro-op into micro-ops each carrying an
explicit `srcRegIdx`/`destRegIdx` list, and its O3 model RENAMES over those
lists — which IS the R7 regfile-dependency semantics, at intra-instruction
granularity.  The patched `ExeTracer` already prints both lists per micro-op
as `SR=[cls:idx,…]` / `DR=[…]` (`arc3_cov/gem5/gem5.patch`), so the reference
is read off gem5's own operand declaration rather than recovered from
disassembly text.  **riscv64 has a second, independent execution reference**
in patched Spike, and the two are scored against EACH OTHER as well as against
the map.

## Shape

    guest ELF ─┬─> gem5.opt --debug-flags=…,ExecRegDelta  ──> exec.log ─┐
               ├─> spike --log-commits (riscv64 only)  ──> commits.log ─┤
               └─> qemu-<isa> + libchampsim_tracer.so ──> .cst ─────────┴─> compare

## What is read on the tracer side, and what is NOT re-derived

Three separate rules turn the wire's raw masks into what a consumer sees, and
ALL THREE live in `cst_decode`:

1. an ABSENT `HAS_REG` block is not an absent dependency — `format.rst`
   defines it as the all-to-all over-approximation and the renderer
   synthesizes `all_inputs & ~addr_only_srcs` in its place;
2. a SATURATED mask has the addressing-only sources stripped from it, so an
   address register is not a second, direct edge into a sink it already
   reaches through the memop;
3. the immediate bit sits at a different index in the address masks than in
   the data masks, because the address masks have no load slots.

Reimplementing those here would be the fabrication this arc is about —
`DEPMAP_DESIGN.md` §1 names the mechanism, "re-derivation is where fabrication
enters".  So the map is read from `cst_decode --show-deps`, which is the
renderer's own answer, and the RAW view is used only to CHECK that reading:
it supplies the `REG_*` vocabulary and the `n_dst` arity the rendered
annotation is zipped against.  A display name bound to two different `REG_*`
ids REFUSES rather than picking a winner.

## The axes

| axis | what it convicts |
|---|---|
| `dep-src-set` | a register the reference reads and the wire does not declare (MISSING EDGE); a register the wire declares and the reference never reads (FALSE EDGE) |
| `dep-dst-set` | a destination only one side has — present so the closure axis cannot quietly skip one |
| `dep-dst-closure` | per destination, the architectural registers reaching it.  **The axis this leg exists for** |
| `dep-dst-discrimination` | where the reference gives two destinations DIFFERENT closures, does the map also distinguish them?  A map that flattens an intra-instruction chain agrees on every union and fails only here |
| `dep-mask-coverage` | **SELF, no reference side.** every DECLARED source must reach some sink through some mask |

**The tracer's source set is the DECLARED operand list, not the union of the
masks.**  The two are different objects and conflating them manufactures
defects: a conditional branch and a `jr` have no register destination and no
memory operand, so they have NO SINK for a mask to route a source to, and
their mask union is empty while their declared source list names the compare
or target register.  Read through the masks alone, `bne r8, r9` came back as a
tracer that names no sources at all and this leg's first reading reported
eight MISSING-EDGE rows that were its own.

## The scope guard is enforced, not declared

gem5's micro-op COUNT never appears in an axis.  It is gem5's implementation
choice — the same class as the aarch64 memop-count bucket this arc resolved by
scoring bytes rather than counts.  The census is PRINTED, because it is the
measurement that says what `dep-dst-discrimination` can reach, and the answer
is a finding in its own right:

> **gem5 cracks nothing on mipsel.**  147 of 147 instructions are one
> micro-op, so every destination of an instruction necessarily has the same
> source closure and the reference distinguishes no two destinations.
> `dep-dst-discrimination` is **INERT BY CONSTRUCTION** there: a limit of the
> reference, not a gap in the probe, and no mipsel probe can make it fire.
> On riscv64 gem5 cracks exactly 2 of 284 instructions (`vmseq.vv`,
> `vpinvd.v`), and both have a single architectural destination, so the axis
> is INERT there too — for a different and weaker reason.

The maintainer's premise — that gem5 cracks macro-ops into micro-ops — holds
for x86 and ARM and **does not hold for the MIPS and RISCV decoders**.  That
bounds what gem5 can convict on these two ISAs, and it is stated rather than
absorbed.

## R7.1 is enforced on the reference side

A narrow write does NOT acquire a preserve-read.  Where a reference names the
merged-into register as a source of a partial write, the row is REFERENCE-side
over-naming, exactly as XED's was.  **Predication is a different question and
is not covered by that rule**: a predicated destination really is a source.

## Every adjudication is MEASURED (R8.7)

No label is assigned from a mnemonic.  Each reads one of three measured
things: the two sets, the reference's own disassembly text for that
instruction, or a **vocabulary census of the whole run**.  The census is what
makes "the reference does not model this state" a measurement rather than an
excuse — a register the reference never names once, over every probe, is
state it does not have; a register it names elsewhere and omits here is a
disagreement and stays one.

A row can carry two mechanisms at once.  The riscv64 vector rows carry a
register the reference does not model AND the saturated default, so the part
the reference cannot model is REMOVED and the RESIDUE is labelled; collapsing
them onto whichever test fired first would leave one of the two invisible.

## The negative control, and the two defects it found in itself

`selftest_dep.py` breaks the TRACER record per axis, on an instruction that
carries a subject for it, and requires the disagreement count to STRICTLY
INCREASE.  The set axes get TWO mutations, drop and invent.

Measured at this tip: **mipsel 28/28 FIRED, riscv64 49/49 FIRED**.

It did not pass first time, and both failures were the instrument's own:

* the INVENT mutations added `REG_GPR31` unconditionally, and the riscv64
  probes open with `add %gp31, … -> %gp31`, so under set semantics the
  mutation was a no-op and **seven of seven riscv64 guests reported DID NOT
  FIRE** for an axis that was working.  The pool now picks a register the
  instruction names nowhere.
* the map reader anchored the annotation on `"; deps:"`, and
  `emit_disasm_trailing_meta` writes the comment block as a SEQUENCE of items,
  so every ATOMIC mipsel instruction renders as `; atomic deps: …` and was
  read as having no map at all — then scored as an empty tracer set against a
  reference naming real registers.  **Five manufactured MISSING-EDGE rows,
  with the tracer's actual map sitting in the line the whole time.**

A third was found the same way: the private copy of gem5's trace-line regex
was written against a log taken without `ExecThread`, and under the canonical
flag set it parsed **zero** lines and reported every axis INERT while the
reference sat there complete.  Both readers now share `gem5_ref._LINE`.

## Prerequisites

Inherited from the execution leg, unchanged: `compare_dep.py` calls
`compare_exec_gem5.gem5_prereqs`, so the libpython shim, the ABI-poisoned
`LD_LIBRARY_PATH` sanitiser, the deep `m5.instantiate()` start proof and the
"Exiting @ tick … because exiting with last active thread context" completion
gate all apply here and all refuse with exit 3 rather than a signal.

`riscv64` needed two additions and neither is a transcription:
* `gem5_ref.REGMAP['riscv64']`, registered with `setdefault` from
  `dep_ref_gem5` so a later entry in `gem5_ref` wins over it rather than being
  shadowed;
* `build/RISCV/gem5.opt`, built at this tip with `scons … -j 12`.

Spike needs `dtc` on PATH (it shells out to build a device tree, and dies with
`Failed to run dtc` before writing a line) and `riscv-pk` (bare-metal Spike
maps memory at 0x80000000 while the probes link at 0x10000, so a bare run dies
with `Memory address 0x101f0 is invalid`).  Both are named prerequisites.

## Exit codes — from the process, never through a pipe

    0  every axis carried facts, no TRACER-SUBSET and no UNACCOUNTED row
    1  scored, and the headline is non-zero
    2  an axis is INERT
    3  REFUSED — a prerequisite is absent, or the reference did not run to
       completion.  Nothing was scored.

## Running it

    # probes
    python ../riscv64/spike/probes/mkprobes.py   <out>/probes_rv
    python ../gem5/probes/mkprobes_mipsel.py     <out>/probes_mipsel

    # the comparison (under the interpreter gem5 was built against)
    python compare_dep.py --isa mipsel \
        --gem5-dir /mnt/md0/QEMU/cst_runs/p3/arc3/gem5exec/gem5 \
        --qemu-dir /mnt/md0/QEMU/qemu \
        --decode /mnt/md0/QEMU/qemu/build/contrib/plugins/cst_decode \
        -o <out>/mipsel --tsv <out>/mipsel/rows.tsv \
        <out>/probes_mipsel/p_int  <out>/probes_mipsel/p_mem \
        <out>/probes_mipsel/p_fp   <out>/probes_mipsel/p_flow

    # the negative control -- run it before believing a clean run
    python selftest_dep.py --isa mipsel --decode … --rundir <out>/mipsel \
        --probes <out>/probes_mipsel p_int p_mem p_fp p_flow

    # riscv64 only: the second reference, and the two against each other
    python crosscheck_spike.py --spike … --pk … --dtc-dir … --decode … \
        --rundir <out>/riscv64 --probes <out>/probes_rv -o <out>/spike \
        p_int p_mem p_muldiv p_atomic p_fp p_flow p_vec
