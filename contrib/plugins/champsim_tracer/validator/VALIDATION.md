# ChampSim Tracer — Unified Validation System

This document describes the **one unified validation entrypoint** for the
ChampSim Tracer plugin and its tools, and inventories every check it
composes.  It is the operator's reference for `champsim_tracer_validator
full`.

> Author: Maccoy Merrell.  The Sphinx page `docs/validator.rst` is the
> narrative reference; this file is the operational spec for the `full`
> harness and the coverage contract.

---

## TL;DR

```sh
# one command, four tiers, one exit code, machine-readable summary
python -m champsim_tracer_validator full --build-dir /mnt/md0/QEMU/qemu/build

# see the coverage map + check table without running anything
python -m champsim_tracer_validator full --build-dir <build> --dry-run

# restrict to a tier (or a single check) while iterating
python -m champsim_tracer_validator full --build-dir <build> --tier quick
python -m champsim_tracer_validator full --build-dir <build> --only multiproc.latch_mips --no-wait
```

`full` exits **0** iff every gating check passed (or skipped) **and** the
feature-coverage registry has no gap.  A `full_summary.json` is written to
the work-root (default `/mnt/md0/QEMU/cst_runs/valunify/`).

Use Anaconda Python (`PATH=/home/maccoy-merrell/anaconda3/bin:$PATH`).

---

## Design

Everything the validator can check is a **feature** (a plugin option or a
wire record) registered in `FEATURES` (in `_full.py`).  Each **check**
declares the features it exercises.  Checks are grouped into four **tiers**:

| Tier | What it runs |
| --- | --- |
| **quick** | user-mode 4-ISA correctness (`all`), plus iframe / wpprune / symbol-start / tb-flush variants, plus the golden byte-and-render net |
| **system** | system-mode marker/pin suites: `all --system` (x86), ASID-churn (`churn_test`, x86 + mipsel), SMP guest-thread identity (`thread_test --system`), guest-clock progress across wrong-path excursions (`system.clock_progress_*`, all four ISAs) |
| **multiproc** | the folded-in multi-process ASID harnesses: trace-all differential, mipsel narrow-ASID latch + recycle, x86 dead-latch kill |
| **features** | devio, physaddr, `--verify-branch`, simpoint segmentation, aarch64 tagged-pointer, WP synthetic fault, long-tail options smoke |

### One exit code, machine-readable summary

`full` prints a per-tier / per-check table and writes `full_summary.json`
(`schema: champsim_tracer_validator/full/v1`) with, for each check:
`status` (pass / fail / skip / xfail), `duration_s`, the `features` it
exercises, and any structured `subchecks`.  The summary also carries the
**coverage manifest**: `coverage.map` (feature → exercising check ids),
`coverage.static_gap`, `coverage.runtime_covered`, and
`coverage.runtime_uncovered`.

### Coverage enforcement

`full` **fails** if any registered feature has **no** exercising check
(`static_gap` non-empty) or if a check claims an unregistered feature.
This makes it impossible to silently rot a feature out of validation:
adding a plugin option means registering it in `FEATURES`, which forces a
check to exist.  Run `--dry-run` to see the gap check without executing.

`runtime_uncovered` (features with no *passing* exerciser this run) is
reported but does not gate — a skipped tier (missing cross-compiler, no
systest rootfs) or a non-gating XFAIL leaves its features runtime-uncovered
without failing the gate.

### Reliability contract (baked in)

* **Quiet-host wait.** Unless `--no-wait`, `full` loop-waits until **0**
  foreign qemu processes are running before it starts.  Golden
  determinism and system-mode timing produce false REDs under concurrent
  load, so the gate refuses to start on a busy host.  Detection is by
  process *comm* (a wait-loop shell that merely mentions "qemu" in its
  argv is not counted).
* **Unique output dirs.** Each check runs under its own subdir of the
  work-root — no shared-work-root collisions.
* **Self-cleaning, scoped.** After each check, a leaked qemu is reaped —
  but **only** processes whose command line references that check's own
  work-root, so a concurrent session's qemu is never touched.
* **Hang-proof.** Every qemu-system boot is wall-clock capped (killed with
  its whole process group on expiry); every offline-tool call is capped
  (a truncated `.cst` can't spin a decoder); every heavy legacy-command
  check runs as an isolated CLI subprocess with a timeout.  A wedged boot
  is reported, never hangs the run.
* **Address-space cap.** `full` sets `RLIMIT_AS` to 24 GiB (matching
  `ulimit -v 25165824`); children inherit it.

### Non-gating checks (XFAIL)

A check may carry a `known_issue` marking it **non-gating**: its failure is
reported as **XFAIL** (loud, listed in the summary) but does not flip the
exit code.  This is reserved for a *confirmed upstream break* or a
*genuinely timing-sensitive* scenario that would otherwise emit a false
RED.  Currently:

* `system.user_x86` — the full-oracle system battery deterministically
  exposes an **open plugin bug class** (see "Known upstream issues"):
  system-mode per-insn value capture diverging from the dataflow oracle
  (metaflags parity, regdata dst snapshots).  Non-gating until the plugin
  fix lands; `system.churn_*` and `system.thread_x86` keep the marker/pin
  machinery as hard gates and claim those features in the coverage map.
* `multiproc.dead_latch_x86` — dead-latch aging is wall-clock/scheduling
  sensitive (detector vs. poweroff backstop) and the boot is hard-capped;
  non-gating so contention can't wedge or false-RED it.
* `multiproc.trace_all_x86` — trace-all peer capture depends on the guest
  scheduling the unmarked peer *inside* the marked window; non-gating as a
  contention safety net (it is otherwise a hard 6/6 with the ordered
  launch, and the latch-differential half always asserts).

### System-mode guest CPU

`system.user_x86` boots with `CST_QEMU_EXTRA_ARGS="-cpu max"`: the
`--coverage` probe set includes AVX blocks, and qemu-system's default
`qemu64` model has no AVX — without the override the guest workload dies
with SIGILL at the first `vmovdqu` (#UD) and the marker window closes
UNDER at a few thousand insns, cascading into spurious identity/thread
errors.  qemu-user is effectively `cpu=max`, so the override aligns the
two modes.

### System-mode oracle relaxation

`validate()` skips the per-event indirect-WP shape assertion
(`_check_indirect_wp_assertions`) when `marker=True`: under a system-mode
marker run the kernel interleaves with the pinned process and individual
WP kicks are legitimately suppressed (WP-skip / first-TB-unavailable), so
"every indirect execution carries a WP" is only intermittently true there.
User mode remains fully strict.

---

## Inventory & classification of pre-existing validation

The unification folded in, revived, or retired every pre-existing piece:

| Artifact | State found | Action |
| --- | --- | --- |
| `all` (user 4-ISA, ~48 checks in `validator.py::validate`) | current, exercised | **tier: quick** (per-ISA) + system |
| `simpoint_test` | current | **tier: features** (`features.simpoint`) |
| `thread_test` (user + `--system --smp`) | current | **tier: system** (`system.thread_x86`) |
| `churn_test` (4-ISA; ASID churn on x86 + mipsel) | current | **tier: system** (`system.churn_*`, `system.clock_progress_*`) |
| `tests/golden_net.py` + `tests/golden/` | current (fresh 07-16) | **tier: quick** (`quick.golden`); quiet-host wait now baked in |
| `validator/tests/tagged_ptr_addr.sh` | current | **tier: features** (`features.tagged_ptr`) |
| `.../tests/test_wp_synthetic_fault.py` | current (matches live FAULT→budget policy) | **tier: features** (`features.wp_fault`) |
| `cst_decode --verify-branch` | present, unexercised | **tier: features** (`features.branch_verify`) |
| `physaddr` / `devio` wire records | present, unexercised by any harness | **tier: features** — new `run_physaddr_probe` / `run_devio_probe` |
| `/mnt/md0/QEMU/cst_runs/multiasid_b4/mp_trace_all.py` | out-of-repo, has verify | **imported** → `_multiproc.run_trace_all_differential` |
| `/mnt/md0/QEMU/cst_runs/multiasid_b4/mp_harness_mips.py` | out-of-repo, has verify | **imported** → `_multiproc.run_mips_latch` |
| `/mnt/md0/QEMU/cst_runs/multiasid_b4/mp_harness.py` (kill/noend) | out-of-repo, **no** assertions | **imported + given assertions** → `_multiproc.run_x86_dead_latch_kill` |
| `validator/tests/run_roundtrip.sh` | current but discouraged (CLAUDE.md: don't call directly) | **superseded** by `full`/`all`; left in place, not wired |
| `validator/tests/large_scale.sh` | current standing seed-sweep | **complementary** (a large unmoderated sweep, not a gate); left in place |
| `validator/tests/test_decoder_smoke.py` | misnamed 2-arg `.cst` diff tool, not a pytest test | left as a debug tool (near-dup of `_diff_entries.py`); not wired |
| `validator/tests/test_wrong_path_chains.py` | reconciled 2026-07-17 — the ROTTED dep-branch-kill assertions were replaced with LIVE continue-to-budget verdict cases (fault-licensed divergence, positional non-excuse, terminator gate, retired-kill inversion) after `_check_wrong_path_chains` was reconciled with the plugin's live policy | **revived** (verdict-level oracle for `wrong_path_chains`; the plugin-behaviour half stays `features.wp_fault`) |
| `validator/README.md` | **ROTTED** — documents the removed `genval` CLI | **rewritten** to the current CLI + this file |

The out-of-repo harnesses formerly under `multiasid_b4/` are now
`champsim_tracer_validator/_multiproc.py` with parameterized paths (no
hardcoded repo/build/out dirs, no `sys.path` hack, deduplicated
decode/audit helpers).

---

## Known upstream issues surfaced (not validator faults)

* **`trace_window=symbol` never opens a segment** on the synthetic
  `-nostartfiles` binaries — even for `_start`.  Repro:
  `qemu-x86_64 -plugin libchampsim_tracer.so,outfile=o,wpdepth=64,trace_window=symbol:name=blk_1+occurrence=1+simulation=50000,memdata=1 <validator binary>`
  → no `.cst`, stats show `traced_icount=0`; every `name=` value fails
  (`blk_N`, `_start`), both `+` and `;` separators.  Suspected mechanism:
  the trigger at `champsim_tracer.cc:3546-3573` reads
  `cur_tb_tmpl->symbol_name`, but before any segment is active no template
  has been built for the executing TB, so `cur_tb_tmpl` is null and the
  occurrence counter never advances.  Symbol *resolution* is correct — an
  icount-window trace of the same binary decodes templates with
  `symbol="blk_N"`.  `quick.symbol_start` **SKIPs** with this diagnostic
  rather than emitting a false FAIL.

* **System-mode per-insn value-capture divergence (deterministic).**
  Repro: `CST_QEMU_EXTRA_ARGS="-cpu max" python -m
  champsim_tracer_validator all --isa x86_64 --seed 0x1111 --build-dir
  <build> -o <out> --system --marker --coverage --regdata --hot-iters 200
  --stop 200000` → reproducible errors on every run while the identical
  user-mode run passes all oracles:
  - `metaflags`: probe insn at pc=0x402984 records `mflags=0x00`
    (Z=0/N=0/P=0) while the captured dst value 0x212 requires P=1; a
    second site at pc=0x40200b records P=1 where the dst value requires
    P=0.
  - `regdata_reconstruction`: wrong dst snapshots on INT_ADD/INT_SUB —
    in one case the recorded dst is a **code address** (0x4019d1)
    instead of the ALU result, i.e. snapshot-slot contamination, not a
    value-computation error.
  Both smell like one bug class: system-mode regdata/metaflags capture
  racing the kernel-excursion machinery.  `system.user_x86` is marked
  non-gating (XFAIL) until the plugin fix lands.

---

## Green-run record

First fully green end-to-end `full` run (quiet host, 0 foreign qemu):
2026-07-17, work-root `/mnt/md0/QEMU/cst_runs/valunify/GATE2`,
`counts: pass=20 fail=0 skip=1 xfail=2`, `OVERALL: PASS (exit 0)`;
runtime-uncovered only `behavior:dead_latch`, `opt:latch_timeout`
(both attached to the non-gating dead-latch check) and
`opt:window_symbol` (attached to the documented plugin trigger bug).

---

## CLI reference (`full`)

| Flag | Meaning |
| --- | --- |
| `--build-dir DIR` | QEMU build dir (qemu-\<isa\>, qemu-system-\<isa\>, plugin, tools) — required |
| `-o, --work-root DIR` | output root (default `/mnt/md0/QEMU/cst_runs/valunify`) |
| `--tier T` | restrict to tier(s) `quick|system|multiproc|features` (repeatable) |
| `--only ID` | restrict to check id(s), e.g. `multiproc.latch_mips` (repeatable) |
| `--seed HEX` | base seed for generated workloads (default `0x1111`) |
| `--no-wait` | skip the quiet-host wait (use only when you own the host) |
| `--max-wait S` | cap on the quiet-host wait (default 3600s) |
| `--dry-run` | print the coverage map + check table without running |
| `--summary-json PATH` | also write the JSON summary here |

The legacy subcommands (`generate build trace analyze validate all
simpoint_test thread_test churn_test`) are unchanged and keep working.
