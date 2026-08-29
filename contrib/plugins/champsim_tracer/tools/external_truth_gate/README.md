# The R13 external-truth gate

`../external_truth_gate.sh` is the one entry point a wave's COMMON section
cites for ruling R13: the trace's facts scored against external references
rather than against the tracer's own instruments.

    external_truth_gate.sh <evidence-root> [--build-dir DIR] [--only legs]
    external_truth_gate.sh --selftest [scratch-dir]

## What it reads

Thirteen legs, one row each in `ADJUDICATED.tsv`.  The count is a fact
about the manifest, not a round number: the `gem5wp` family gained its
`x86_64` row when that leg was built, and this file said "twelve" for a
day afterwards.  If the two ever disagree again, the manifest is right.

| leg | what it is |
| --- | --- |
| `isax` | the eight-arm boundary/fields gate, Capstone as an EXTERNAL reference against LLVM MC, four ISAs |
| `static` × 4 | the whole-opcode-space register-attribution sweep — XED, iced-x86, LLVM MC, Arm MRA, Sail, binutils `mips-opc` — read off the four-ISA cross-tabulation |
| `gem5cp` × 2 | gem5 correct-path execution, aarch64 and mipsel: destination sets and VALUES, memop count / address / width, store and load data |
| `gem5wp` × 3 | gem5 wrong-path, aarch64 / x86_64 / mipsel: every excursion rebuilt from the trace alone and re-executed |
| `spikecp` | Spike correct-path execution, riscv64, including CSR sets and values |
| `spikewp` | Spike wrong-path, riscv64 |
| `pin` | PIN correct-path execution, x86_64: register sets, register VALUES, memop count / address / width / data |

## What makes it fail

A leg's HEADLINE is the count of rows where the tracer drops information a
reference states, or where the difference is not understood — never a bare
agreement rate. The gate fails when

* a report the manifest names is missing — a leg that did not run has not
  passed, and absence is never a pass;
* a headline cannot be parsed — the report changed shape or the leg died
  before writing it, and either way that is a failure and not a zero;
* a headline EXCEEDS its adjudicated ceiling — a disagreement nobody has
  adjudicated row by row;
* the leg's scored population is below its floor — a leg that compared
  almost nothing reports few disagreements for the wrong reason;
* a report is older than the binaries it claims to have measured
  (`--build-dir`) — a green taken against a previous build is not a green.
  The reference is the newest of the plugin, `cst_decode` **and every
  emulator in the build directory**: an execution leg's facts are produced
  by the translator, so a QEMU-side fix with no plugin change would
  otherwise leave every execution report looking fresh.

  The reference is a **behaviour** time, not a link time. QEMU rebuilds
  `qemu-version.h` from `git describe`, so any commit at all relinks all 62
  emulators and moves all 62 mtimes; keyed on mtime, the guard called every
  execution leg stale after a comment. Each binary is now held at the moment
  its behaviour-bearing bytes last changed — a sha256 over its allocatable
  `PROGBITS` section contents and `NOBITS` sizes, with the version stamp
  masked out, remembered in `<build-dir>/.cst_behavior_ref.json`. A relink
  that reproduces the same bytes does not move the bar; a real change does,
  and the gate names the binary that moved it. One case is deliberately NOT
  absorbed: a version string whose LENGTH changes (`-dirty` appearing or
  going) shifts every rodata object after it and therefore shifts real
  bytes, so the guard reports stale — the conservative direction. See
  `behavior_digest.py`.

## What it does not do

It does not run the legs. gem5, Spike and PIN take hours and need guests this
repository does not carry; each leg has its own REPRODUCE script under
`arc3_cov/` and `arc3_pinexec/`. This gate is what turns their output into a
pass or a failure, and the staleness guard is what stops an old run being
quoted as a current one.

## Ceilings are not targets

Every ceiling above zero carries its adjudication and, where one exists, the
work item whose landing must lower it. A ceiling with no `retired_by` is one
this project accepts as a property of the REFERENCE — the reference under-models
something the tracer records correctly — not as a property of the trace.

Author: Maccoy Merrell.
