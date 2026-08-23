# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is a **fork of QEMU** whose primary in-house contribution is the **`champsim_tracer`** TCG plugin under
`contrib/plugins/champsim_tracer/`. The plugin emits binary `.cst` traces (CP + wrong-path) consumed by
ChampSim-style simulators. Almost all active development happens in that directory plus a few QEMU base
modifications the plugin depends on (see `docs/qemu_modifications.rst`).

The base QEMU code is upstream and largely untouched. When in doubt about whether a change belongs here,
assume it touches the plugin and its supporting QEMU hooks, not arbitrary QEMU subsystems.

## Build

Standard from-scratch:

```sh
mkdir build && cd build
../configure --enable-plugins \
             --target-list=x86_64-linux-user,aarch64-linux-user,riscv64-linux-user,mipsel-linux-user,\
x86_64-softmmu,aarch64-softmmu,riscv64-softmmu,mipsel-softmmu
make                                  # full build
```

Incremental (no meson reconfigure needed when source files change but file lists don't):

```sh
ninja -C build contrib-plugins        # plugin .so + cst_decode + cst_audit + cst_visualize (~10-20s)
ninja -C build qemu-x86_64 qemu-aarch64 qemu-riscv64 qemu-mipsel
```

When `meson.build` file lists change, plain `make`/`ninja` reconfigures automatically — don't run
`meson setup --reconfigure` unless something is wedged. Don't brute-force standalone meson invocations;
the documented `../configure` flow is what's expected.

Some Python tooling on PATH (e.g. `gdbus-codegen`) needs Anaconda Python 3.11 (has `distutils`); a venv
Python 3.12 will fail. Prepend `PATH=/home/maccoy-merrell/anaconda3/bin:$PATH` if needed.

Capstone is auto-fetched by meson from `subprojects/capstone.wrap` (currently `6.0.0-Alpha7`). The plugin
always links the wrap copy, even if a system Capstone is installed.

## Run, decode, audit

```sh
qemu-x86_64 -plugin ./build/contrib/plugins/libchampsim_tracer.so,outfile=run,wpdepth=64 ./prog
build/contrib/plugins/cst_decode  run.cst | head        # objdump-style disassembly
build/contrib/plugins/cst_audit   run.cst               # byte-budget breakdown (must roll up to 100%)
```

See `contrib/plugins/champsim_tracer/docs/quickstart.rst` for the option reference and reproducibility flags
(`-seed`, `-B`, `-R`, `taskset`, `setarch -R`).

## Validator (end-to-end self-check)

The seed-driven generator validates the plugin across 4 ISAs. Canonical entrypoint:

```sh
# run from contrib/plugins/champsim_tracer/validator/
python -m champsim_tracer_validator all --isa x86_64 --seed 4242 \
       --build-dir /mnt/md0/QEMU/qemu/build -o /mnt/md0/QEMU/cst_runs/<name>
```

`--isa`, `--seed`, `--build-dir` and `-o` are all required, and there is **no `--run` flag**.
`--compress` here takes a keyword (`none|xz|zstd|gzip`), unlike the plugin's own `compress=` option,
which takes a command string.

The whole-suite entrypoint is a different subcommand, `full`:

```sh
python -m champsim_tracer_validator full --build-dir <build> -o <out-dir>
```

When validating a build dir that is **not** the canonical `build/`, set `CST_DECODE` to that dir's
`cst_decode`. `_cst_decode_runner.py` otherwise falls back to `../../build/contrib/plugins/cst_decode`
and decodes the traces with the shared binary, producing false system-tier failures.

Do **not** invoke `tests/run_roundtrip.sh` directly. When changing the `--format=legacy` output of `cst_decode`,
update `validator/champsim_tracer_validator/_cst_decode_runner.py` (it shells out to `cst_decode --format=legacy`
and parses the textual output).

## Documentation

Sphinx site under `contrib/plugins/champsim_tracer/docs/`:

```sh
make -C contrib/plugins/champsim_tracer/docs html       # _build/html/index.html
make -C contrib/plugins/champsim_tracer/docs latexpdf   # needs texlive-xetex + fonts-freefont-otf
```

If `sphinx-build` isn't on PATH, prefix with `SPHINXBUILD=/home/maccoy-merrell/anaconda3/bin/sphinx-build`.
The doc tree (`architecture.rst`, `concepts.rst`, `decoder.rst`, `extending.rst`, `format.rst`,
`limitations.rst`, `quickstart.rst`, `reference.rst`, `troubleshooting.rst`) is the authoritative source
for plugin behaviour — read it before guessing.

The wire-format spec is `contrib/plugins/champsim_tracer/docs/format.rst` (the single
source of truth).

## Plugin architecture (big picture)

Read `docs/architecture.rst` for the full picture; the key load-bearing pieces:

- **Plugin is C++17 throughout** (one TU per subsystem in `contrib/plugins/champsim_tracer/`, plus per-ISA
  `_mnemonics_<isa>.h`). The only C boundary is the QEMU plugin entry points. Do **not** add C TUs or
  `extern "C"` wrappers.

- **Two flow loops:** *CP* (correct path) in `vcpu_tb_exec` walks the previously-executed QEMU TB's
  fragment list, attributes stats, folds into a true-BB chain, and emits a body record. *WP*
  (wrong path) is a synchronous nested loop kicked from `emit_finalized_bb` that flips
  `cpu->plugin_spec_mode`, redirects PC, and runs `cpu_plugin_exec_tb` until the `wpdepth` budget exhausts,
  then restores state.

- **TBs are not basic blocks.** A QEMU TB can split a true BB (page boundary) or contain multiple true
  BBs (mid-TB-branch ISAs like MIPS `teq`). The translation-time **fragment splitter**
  (`split_tb_into_fragments`) partitions each TB at non-final branch terminators; the **chain assembler**
  (`BBChainAssembler`) folds fragments across TBs into true BBs sealed at the next branch. Always reason
  about true BBs, not TBs.

- **Two caches:** `tb_templates_` (a vector of per-fragment templates; dropped wholesale on
  `vcpu_tb_flush`) and `bb_map_` (the true-BB cache, keyed by branch-target start_pc; cleared on segment
  switch). `bb_map_` is what the trace's templates section serialises.

- **Synchronization:** `exec_lock` serialises `vcpu_tb_exec` (including any nested WP simulation); `data_lock`
  is grabbed inside that window for cache mutations. `unknown_warn_lock` serialises the sidecar log.

- **Multi-vCPU:** one body stream per segment, interleaved across vCPUs through `exec_lock`. `thread_id`
  in records is a **guest-thread identifier, never a vCPU id** — the vCPU is deliberately absent from the
  wire (`docs/format.rst` is the contract). System mode derives it from the guest's per-thread pointer
  register, sampled at every privilege level where the target reports
  `qemu_plugin_thread_ptr_tracks_current()`, so a task switch inside the kernel retags the strand; user
  mode uses `cpu_index`, which qemu-user allocates one-per-guest-thread. Each thread has its own
  `FieldStateTable`; an initial `BODY_TAG_REGFILE` rides with the body stream before each thread's first
  entry.

- **Wire format:** frozen during pre-release. `CST_MAGIC` is the format-epoch identifier — it **may**
  bump at a formal release, but **do not bump it now**, and don't write "never changes" into the spec
  or docs.

## Working rule: do not stall

Adopted 2026-08-22 after it had to be enforced by hand three times in one
session.

**When the next step is work rather than analysis, take the step.** Do not
produce a summary, a plan, or a statement of intent in its place. "I'll do X
next" is not a deliverable; X is. Writing down that a task is ready to
implement, and then stopping, is the failure this rule exists to prevent.

Specifically:

- Finishing a piece of analysis is not finishing the task. If the analysis
  names an action and nothing blocks it, do it in the same turn.
- Do not stop to ask permission for work already directed. A ruling given
  once stands; re-asking is stalling with extra steps.
- Do not stop because context feels short. Land the smallest COMPLETE,
  verified increment and commit it -- a half-built change left uncommitted
  is the worst outcome, and "I'm running low" is not a reason to produce
  nothing.
- Do not stop at a wrong result. A red measurement is the start of the next
  step, not the end of the current one.
- Reporting is owed at the END of work, not INSTEAD of it.

The one thing that legitimately stops work: an action that is destructive,
outward-facing, or genuinely ambiguous in a way that would waste the work if
guessed wrong. Name it in one sentence, then continue with everything it
does not block.

## Conventions

- The user (Maccoy Merrell) is the sole plugin author. Use his name for author/copyright fields, not
  generic phrasing.
- In prose use the friendly name **"ChampSim Tracer"**. In code, file paths, identifiers, build targets,
  etc., keep `champsim_tracer`.
- The per-ISA mnemonic tables (`champsim_tracer_mnemonics_<isa>.h`) are **auto-generated** by
  `champsim_tracer_mnemonic_audit.py`. Don't hand-edit the rows; modify the generator and re-emit.
  Before doing a large mechanical edit anywhere, grep for "generated by" / "Auto-generated" first.
- The dependency refiner classifier (`.dep_refine` in `InsnClassification`) picks from Capstone detail,
  **not** from `GEN_OP_*`. The `GEN_OP_*` mapping is the existing name-based classifier; the refiner is
  orthogonal and refines per dataflow-behaviour groups (wide per refiner, complementary across the set).
- The 4-per-slot dynamic **lane-mask model** (src / dst / load / store) is the required design: the
  opcode `kind` only says where to read; the actual mask is computed dynamically from the operand /
  memop layout.
- When the root cause of a bug is **upstream** (QEMU, glibc, Capstone), report it as a bug with a fix
  path — don't automatically downgrade it into a documented plugin limitation. Known Capstone bugs
  (PEXTR access, MIPS MSA, x86 store-moves) have boundary workarounds in `disas/capstone.c` and
  `champsim_tracer_decode.cc`; revisit on a Capstone version bump.
- Capstone in QEMU uses AT&T operand syntax → operand array order is reversed vs Intel docs.

## Repository layout (the parts that matter here)

| Path | What lives there |
| --- | --- |
| `contrib/plugins/champsim_tracer/` | The plugin itself, header/TU per subsystem |
| `contrib/plugins/champsim_tracer/tools/` | `cst_decode`, `cst_audit`, `cst_visualize` (C++ offline tools) |
| `contrib/plugins/champsim_tracer/validator/` | Seed-driven multi-ISA self-check harness |
| `contrib/plugins/champsim_tracer/docs/` | Sphinx documentation (the canonical reference) |
| `contrib/plugins/champsim_tracer/docs/format.rst` | Wire-format spec |
| `contrib/plugins/meson.build` | Build entry for the plugin and tools |
| `disas/capstone.c` | Capstone boundary including the access-flag bug workarounds |
| `subprojects/capstone.wrap` | Pinned Capstone revision |

## Branch and remote

Active dev branch: **`champsim-trace`** (PRs against `master`, which is the QEMU base). The user's fork
lives at `github.com/maccoymerrell/qemu`.

### The branch is the only source of truth — work ratchets onto it

This is not a style preference. Work once spread across ~130 checkouts and a dozen branches, passed
worktree-to-worktree instead of landing, until nobody could say which tree was current. Fixes were
"done" in three places and on the branch in none, and several were nearly lost. The rules below exist
so that cannot recur.

1. **Base every piece of work on `champsim-trace`.** Not on another worktree, not on `origin`
   (`origin` is upstream QEMU and does not contain the plugin at all — an agent worktree branched
   from it silently gets a tree with no `contrib/plugins/champsim_tracer`). `.claude/settings.local.json`
   sets `worktree.baseRef: head` so agent worktrees branch from the local HEAD; verify anyway.

2. **Prefer working directly in `/mnt/md0/QEMU/qemu`.** Use a worktree only when parallel agents would
   otherwise collide on the same files, and create it explicitly from `champsim-trace`, naming the base
   sha in the report.

3. **Land it or lose it.** A worktree is scratch space, never a holding pen. When a change builds and
   its check passes, commit it to `champsim-trace` in that session. Never hand uncommitted work to the
   next worktree — that is exactly how the mess formed.

4. **State the base sha when starting, and re-sync before landing.** An agent that began hours ago is
   working against a stale tree; rebase onto the current tip before committing rather than merging a
   diff that silently reverts someone else's landed fix.

5. **Every agent brief must say which tree to use and how to prove it.** A verification the agent runs
   itself, e.g.:
   `test -d contrib/plugins/champsim_tracer && git rev-parse --abbrev-ref HEAD` — and it must STOP and
   report if the tree is wrong rather than working around it.

6. **Before deleting any checkout, prove nothing unique is in it.** `git patch-id --stable` against the
   merged equivalent for commits, and archive the working diff. Subjects and commit messages are not
   proof — rebased copies share both.
