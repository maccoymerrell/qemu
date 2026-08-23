# ARC 3 — how a disagreement is reported

A disagreement count is not a result.  "554 disagree" is equally consistent
with 554 rows where the tracer records **more** than the reference — which is
the project's goal — and with 554 rows where it silently **drops** execution
information, which is the one outcome that disqualifies the trace.  Every
disagreeing row therefore carries two independent answers, and the report
prints their cross-tabulation.

## The two axes

**DIRECTION — which way the two sets differ.**  Measured from the sets, never
read off a label.  The two sides are compared as one role-tagged set each
(`S:REG_X`, `D:REG_X`), so a register the reference calls a source and the
tracer calls a destination is not containment in either direction.

| value | meaning | verdict |
|---|---|---|
| `TRACER-SUPERSET` | the tracer's set strictly contains the reference's | OK |
| `TRACER-SUBSET` | the reference's set strictly contains the tracer's | DEFECT |
| `ORTHOGONAL` | neither contains the other | named |
| `UNACCOUNTED` | no rule explains the row | **must be 0** |

**CATEGORY — why.**  The mechanism: `tracer-defect`, `capstone-defect`,
`reference-defect`, `reference-gap`, `scope-exclusion`, `vocabulary-gap`,
`vocabulary-difference`, `representative-artifact`, `needs-ruling`.  The
vocabulary is fixed in `arc3_taxonomy.CATEGORIES`; a harness may not invent a
category without adding it there, so the four ISAs stay comparable.

The set relation is always computed.  The **reported** direction is that
relation only when a rule accounts for the row; otherwise it is `UNACCOUNTED`,
because a row nobody has interrogated has no direction anyone is entitled to
claim.

**The headline is `TRACER-SUBSET + UNACCOUNTED`** — the rows where information
is dropped, plus the rows where the reason for the difference is unknown.  The
agreement rate is not the headline and is not quoted without them.

## What accounts for a row

`arc3_rules.py` maps each harness's own adjudication labels onto the two axes.
A label accounts for its rows only if it names a **mechanism**.  Two kinds of
label do not, and their rows stay `UNACCOUNTED`:

* a label that only restates which way the sets differ — x86_64's
  `M8 other missing register`, riscv64's derived `TRACER-GAP` / `TRACER-EXTRA` /
  `MIXED` fallbacks;
* a label that groups rows of more than one mechanism, so it cannot say which
  a given row is — x86_64's `M7 … (phantom)`, aarch64's `MIXED — 10 rank-2 gap,
  5 reference defect`.

A label present in the data with no rule at all is likewise `UNACCOUNTED`, and
is printed under **LABELS WITH NO RULE** so the gap is never silent.

## Two checks that make the classification falsifiable

**Direction conflict.**  A rule whose mechanism admits only one set relation
(`reference-gap` can only be `TRACER-SUPERSET`; `vocabulary-gap` can only be
`TRACER-SUBSET`; a `CLOSED` aarch64 adjudication can have no rows at all)
declares it.  A row whose measurement lies outside its rule's expectation is
**reported as a conflict, never reclassified**: the adjudication does not fit
the row it is charged to, and that is a finding about the adjudication.

**Stated-row-count.**  An aarch64 adjudication whose prose says "42 rows." is
making a checkable claim about the measurement.  Every such claim is checked
against the count actually measured, and a mismatch is printed.  A `CLOSED`
adjudication is exempt — its number is the size of the class *before* it was
closed — but is instead required to measure zero.

## Proving the instrument can fire

An agreement rate quoted off a classifier nobody has watched fail vouches for
nothing.  All four arms are exercised in both directions:

| ISA | damage | result |
|---|---|---|
| x86_64 | `isaxcheck --falsify=drop-src:movq` | 16 MOVQ rows → `TRACER-SUBSET` |
| x86_64 | `isaxcheck --falsify=add-dst:movq` | 12 MOVQ rows → `TRACER-SUPERSET` |
| riscv64 | `CST_FALSIFY=drop-src:ctz` | ctz → `TRACER-SUBSET` |
| riscv64 | `CST_FALSIFY=add-dst:fadd.s` | fadd.s → `TRACER-SUPERSET` |
| mipsel | erase `tr_src` / plant `tr_dst` in `rows_adj.json` | → `TRACER-SUBSET` / `TRACER-SUPERSET` |
| conflict detector | assert `M5` is a superset mechanism | 127 conflicts, back to 0 on restore |

mipsel is damaged at the parsed tracer arm rather than inside `isaxcheck`,
because its probe path uses `--hex`, which prints the fields block **before**
`compare()` applies `--falsify`.  `--falsify` moves that run's gate
(`unallowed 0 → 1`) but cannot move the printed block the mipsel harness
scrapes, so the mipsel attribution comparison has no `--falsify` power today.

## What this does not measure

**Memops.**  Count, address and data for every load and store are half the
deliverable and **no ISA harness compares any of them**.  The x86_64 tracer arm
parses `f_loads` / `f_stores` and never uses them; the aarch64 reference carries
`mem_r` / `mem_w` per subject and the comparison never reads them.  Every report
says so in its own body; the register numbers must not be quoted as memop
coverage.

**Execution.**  Only x86_64 is scored against a real run (PIN, whose `INS_RegR`
is explicit-operand only, so its *silence* proves nothing and only its positive
evidence counts).  riscv64's execution reference is Spike and is not wired in;
aarch64 and mipsel have no execution reference at all.  A static-only result is
labelled as such in every table and is never quoted as execution-validated.

## Running it

Each ISA harness computes the classification itself and writes it into its own
`attrib.tsv` as `set_relation`, `direction`, `category`, `accounted`, and prints
the cross-tabulation at the top of its report.  The four-ISA view re-reads those
columns and derives nothing, so the aggregate and the per-ISA reports cannot
disagree:

```sh
python coverage_report.py -o COVERAGE_TWOAXIS.txt --rows unaccounted_rows.tsv
```

`--rows` writes **every** unaccounted row, so the top-50 listing in the report
never stands in for the full list.
