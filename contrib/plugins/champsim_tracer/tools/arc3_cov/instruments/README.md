# ARC-3 measurement instruments

The five instruments the ARC-3 dataflow waves are scored with.  They used to
exist as a copy per wave under `cst_runs/p3/arc3/exec2*/`, which is how two
of them drifted into reporting an absent subject as a clean zero.  This is
the one location; later waves cite these paths and nothing else.

| tool | what it answers |
| --- | --- |
| `keyfacts.py` | extract per-PC facts from `cst_decode --format=raw` (`.key`), or the per-destination-register form (`--dst`, `.dkey`) |
| `setproof.py` | did a set of published facts move between two arms — CHANGED / REAL-LOST / REAL-GAIN / FLOOR |
| `score_families.py` | the J3 mutation battery over all four dependency families, floor-excluded, under both floor definitions |
| `score_dst.py` | the destination family keyed per destination REGISTER |
| `nodep_census.py` | the absolute census of slots naming no architectural register (the #230 class) |

Every tool takes `--selftest`, which plants a defect and requires the tool to
fail on it.  Run all five before quoting any of them:

```sh
for t in keyfacts setproof score_families score_dst nodep_census; do
    python "$t.py" --selftest || echo "SELFTEST RED: $t"
done
```

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

**A dependency array is keyed by its destination REGISTER, not its slot
(#231).**  `dst_dep[]` has one mask per wire destination slot and the slot
list is the operand walk's, so an array diff reports movement whenever the
walk's list changes.  Measured, the array-keyed form overstated the mover
count by 219x.

## The control arm, and what an empty one hides

`score_families.py` and `score_dst.py` both require the `mnem__` control to
have moved something: a battery whose dependency columns are all zero says
nothing unless something in the same run moved.  Under the `mnem` mutation
on aarch64, riscv64 and mipsel every instruction is an unknown mnemonic and
the tracer publishes **zero** `dst_dep` blocks, so the control arm's `.dkey`
is empty on three of four ISAs.  The superseded `scoredst.py` printed
`rows=0 name_moved=0 vanished=0` for those cells — which reads as a clean
control and is in fact no control at all.  `score_dst.py` fails them.

## Why the census is not a scorer

J3 measures COUPLING: whether a fact MOVES when Capstone is corrupted.  A
fact that is uniformly wrong in BOTH arms does not move, so J3 returns a
correct zero about an incorrect wire — that is exactly how #230's 340 false
call rows survived every arm.  `nodep_census.py` is absolute rather than
differential and is the only instrument in this directory that can see such
a fact.  Run it in every acceptance.
