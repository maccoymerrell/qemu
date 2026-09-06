# ARC-3 measurement instruments

The five instruments the ARC-3 dataflow waves are scored with.  They used to
exist as a copy per wave under `cst_runs/p3/arc3/exec2*/`, which is how two
of them drifted into reporting an absent subject as a clean zero.  This is
the one location; later waves cite these paths and nothing else.

| tool | what it answers |
| --- | --- |
| `keyfacts.py` | extract per-PC facts from `cst_decode --format=raw` (`.key`), or the per-destination-register form (`--dst`, `.dkey`) |
| `setproof.py` | did a set of published facts move between two arms — CHANGED / REAL-LOST / REAL-GAIN / FLOOR, each with the reading's own COVERAGE; `--compare` scores two readings at matched coverage |
| `score_families.py` | the J3 mutation battery over all four dependency families, floor-excluded, under both floor definitions |
| `score_dst.py` | the destination family keyed per destination REGISTER |
| `nodep_census.py` | the absolute census of slots naming no architectural register (the #230 class) |
| `identsplit.py` | per-FIELD diff of a QID_SPLIT identity row's candidates: is the split about the INSTRUCTION, or only about which refiner is named |
| `cph_census.py` | the CP-H write-state census over an arm root's `corpus_mech_<isa>.tsv`, and the MUST-BE-0 property that an incomplete extraction may never also claim a complete publish |
| `abandoned_families.py` | decompose the `...ABANDONED` write-list class by `(generic opcode, shape of the named prefix)`, so one reason with millions of rows becomes families a declaration can be aimed at |
| `srcbar.py` | THE SOURCE BAR: the tip arm against the banked deletion arm, over `REACH=INSTRUCTION` rows only, decomposed by mechanism AND by family `(decode rule, mnemonic)` |
| `mechclass.py` | the mechanism a source loss belongs to -- `Q-SILENT` / `R-REFUSED` / `R-SHORT` / `NO-BLOCK` / `SURV-ONLY` -- read off arm A's own row |
| `barledger.py` | joins the bar's families to `BAR_CLASSES.tsv` and REFUSES unless EVERY family carries a disposition and a citation |

Every tool takes `--selftest`, which plants a defect and requires the tool to
fail on it.  Run them all before quoting any of them -- with the runner, not
by hand:

```sh
./selftest_all.sh            # 23 instruments found, 23 green, 0 RED
```

**Do not write the loop out again.**  The loop that used to stand here named
eight of the directory's files.  A pass ran it, reported "8 of 8", and quoted
the instruments as verified; three of the fourteen files it did not name had
no `--selftest` at all, and one of those three answered with an uncaught
`IndexError` rather than a refusal (FINDING 83-D).  A hand list cannot report
on what it does not mention -- the survivorship-bias failure this tree files
against enumerated zeros.  `selftest_all.sh` takes the directory as its
subject set, so a new instrument is IN the count the moment it exists, and a
module with no `--selftest` is a FAILURE rather than an absence.

It also tries both argument grammars.  Tools that plant files on disk take
`--selftest DIR`; tools that plant them in memory take `--selftest` alone and
refuse an extra word.  Both are legitimate, the runner prints which one
answered, and a runner that knew only one convention reported six green tools
as RED the first time it was pointed at the directory.

## Why `cph_census.py` is in the tree and not in a run directory

It was written twice as a pass-local script, and after the second time the
derivation was lost with the run directory that held it.  An aarch64 number
that had already been published could then not be re-derived from the tree at
all; the only route back to it was to write the script again from the shape of
its own output.  A census the tree cannot reproduce is a number, not a
measurement.

The output format is unchanged from those pass-local versions on purpose, so
every banked `CENSUS.txt` stays comparable to one produced here — the tool as
it stands reproduces exec135's four-ISA census byte for byte from
`sled_tip81a`.

What the promotion added is the column guard.  The pass-local version reached
its columns with `.get(name, "")`, so a corpus that renamed `WSTQ` would have
scored every row REFUSED, and one that renamed `PUBD` and `wstate` would have
made the MUST-BE-0 property VACUOUS — printing `: 0` and `CENSUS PASSED` while
looking at nothing.  Each named column is now dropped in its own selftest arm
and each drop must REFUSE.

## Why `identsplit.py` exists

A QID_SPLIT row is decided by comparing the WHOLE `Entry`, so one word
covers two different findings: candidates that disagree about what the
instruction IS, and candidates that agree on every field the wire carries
and differ only in whether a refiner is named.  Those have different
dispositions, and reading a row's disposition off the whole-Entry verdict
is how a taxonomy ruling gets written as if it were a QEMU fact.

The tool also keeps `.refine` and `.dep_refine` apart, which the standing
adjudications turn on and a single "refiner" bucket would hide.
`.dep_refine` writes dependency masks only; `.refine` runs FIRST and
rewrites the classification, opcode included.  Measured at EXEC39: the
DEP-REFINER-ONLY set the tool reports is EXACTLY the set of rows the
maintainer's standing refiner adjudications already cover, plus one that
was not yet written, which is the cross-check that says the verdict means
what it claims.

The verdict is an input to an adjudication and never a substitute for
one.  DEP-REFINER-ONLY says only that the row is in the shape a refiner
adjudication MAY be written for; the adjudication still has to name a
QEMU source fact, and it still has to survive the wire's own acceptance.

## The three rules these tools encode

**An empty comparison side is a FAILURE, never a floor (#235/#238).**  The
two-column ancestor of `setproof.py`, handed an arm with no rows, reported
the whole opposite side as build noise and exited 0.  Measured on a planted
empty riscv64 arm: the old tool printed `riscv64 common=0 CHANGED=0
REAL-LOST=0 floor=77193` and exited 0; `setproof.py` prints
`riscv64 NOT SCORED -- vacuity`, names the file, totals only the ISAs it
actually scored, and exits 2.

**The floor is stated, never assumed (#212/#214).**  The published PC set is
not stable across BUILDS of identical source — two full builds of the same
tree published 4 riscv64 PCs on one side and 6 on the other, with 0 of the
12,016 common keys differing.  A key present in one arm only is FLOOR and is
never counted as a loss or a gain.  A family that disappears at a PC both
arms published is REAL-LOST and always is.

**A reading states its own COVERAGE, and two readings are compared at the
MATCHED coverage — never as report bytes (PASS 34).**  `setproof.py`'s
BEFORE arm is a banked baseline that does not move; its AFTER arm is a fresh
run, and which PCs that run executes is *not* stable.  Measured across
PASSes 31-34 against one banked baseline, `strncmp`'s aligned fast path ran
in PASS 34 and not in 31-33, and eleven CHANGED rows arrived with it — no
fact having moved.  So the per-ISA line now carries
`COVERAGE baseline_pcs=… compared_pcs=… skipped_floor=…`, `--verdicts`
banks the per-key verdicts, and `--compare A.tsv B.tsv` scores two readings
at the PCs they BOTH covered.  That mode will not print the word
`IDENTICAL` unless the coverages match as well as the verdicts; when only
the verdicts match it says `IDENTICAL-AT-MATCHED-COVERAGE` and prints the
coverage delta.  Readings taken against different baselines, and readings
whose matched coverage is empty, are refusals.

**A dependency array is keyed by its destination REGISTER, not its slot
(#231).**  `dst_dep[]` has one mask per wire destination slot and the slot
list is the operand walk's, so an array diff reports movement whenever the
walk's list changes.  Measured, the array-keyed form overstated the mover
count by 219x.

## The control arm, and what an empty one hides

A battery whose dependency columns are all zero says nothing unless
something in the same run moved, so every scorer here requires its control
to have moved.  `score_families.py` uses `mnem__`.

**`score_dst.py` does not, and could not (#249).**  Under the `mnem`
mutation on aarch64, riscv64 and mipsel every instruction is an unknown
mnemonic, the refiner emits no dep block, and the tracer publishes **zero**
`dst_dep` blocks — so the destination family's control arm deleted the
population it was the control for, and on x86_64, where 99 rows survived, it
moved none of them.  Every dst zero ever scored against it was unquotable.
The superseded `scoredst.py` printed `rows=0 name_moved=0 vanished=0` for
the three empty cells, which reads as a clean control.

The destination family's arms are therefore its own list, `L.DST_ARMS`, with
`dstmsk` as `L.DST_CONTROL`:

| arm | what it mutates | what its movers are |
| --- | --- | --- |
| `dstmsk` | the published mask, on the line that writes it (`apply_dst`) | every destination QEMU's provenance decided — **the control** |
| `refmsk` | the refiner's mask, in the window before `qdep_apply` overwrites it | every destination the wire still takes from Capstone |

The two are disjoint and exhaustive by construction, and measured at
`6ec94b8c09` they sum exactly: x86_64 3,756 + 676 = 4,432; aarch64
907 + 0 = 907; riscv64 2,266 + 0 = 2,266; mipsel 1,759 + 2 = 1,761.  That
identity is the standing self-check — a row that neither arm moves is a
published mask with no writer, and a row both move is a double write.

Both are driven by `QEMU_DF_MUTATE`, the destination-side sibling of
`QEMU_CAP_MUTATE`.  Two further candidates were built and MEASURED before
these two were kept, and each lost for a reason worth not repeating:

* `wracc` (Capstone, the write bit set on every operand) suppressed the
  family outright on aarch64 and mipsel — `mnem`'s defect again, in a new
  place.
* `wprov` (QEMU, the write provenance corrupted at `plugins/api.c`'s two
  exits) moved 636 / 0 / 352 / 206 rows.  It can only move a row where
  QEMU's answer and the refiner's DIFFER, and on aarch64 they agree — a
  load's destination is `LOAD0` to both — so its aarch64 zero means
  agreement, not decoupling.  A zero that cannot be read is worse than no
  arm.

## The second empty subject: a full file that shares no PC

`require_subject()` catches an arm with no rows.  It does not catch an arm
whose rows are all at PCs the reference never published, and that
comparison has no subject either.  Measured on this battery: under `access`
the aarch64 and mipsel destination lists empty and refill with a disjoint
set, so the reference's 882 / 1,555 PCs and the arm's 457 / 959 intersect in
**zero**, and the scorer printed `rows=0 name_moved=0` — an inert-looking
arm that had scored nothing at all.  `require_overlap()` names those as
failures.  It follows that the `access` arm cannot state a destination-family
zero on aarch64 or mipsel with this key, and that limit is a result, not a
gap to be papered over.

## Why the census is not a scorer

J3 measures COUPLING: whether a fact MOVES when Capstone is corrupted.  A
fact that is uniformly wrong in BOTH arms does not move, so J3 returns a
correct zero about an incorrect wire — that is exactly how #230's 340 false
call rows survived every arm.  `nodep_census.py` is absolute rather than
differential and is the only instrument in this directory that can see such
a fact.  Run it in every acceptance.

## The bar's adjudication table

`srcbar.py --tsv` turns the source bar into 170 families.  That is progress
and it is not an answer: 170 rows nobody has ruled on is the same silence in
a longer form.  `BAR_CLASSES.tsv` carries the disposition of each, and
`barledger.py` makes the join TOTAL BY CONSTRUCTION -- a family matching no
class refuses, a family matching two refuses, a class matching no family is
reported DEAD, a `BLOCKED` row whose note asks no question refuses, and a
disposition with no citation refuses.

The three dispositions are exhaustive by rule of the program:
`QEMU-STATES-IT` (QEMU's translation contains the read, the extraction does
not carry it out -- a defect with a source site, and a wire change that owes
R13 legs), `RULED` (an architectural fact or standing ruling says the
register is not a source, so the arm that drops it is right -- and the row
must carry a WHOLE-POPULATION arm, never a sample), and `BLOCKED` (a named
question, written out).  There is no fourth answer and no silent row.
