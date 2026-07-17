# champsim_tracer_validator — procedural validation of the ChampSim Tracer plugin

A seed-driven generator produces freestanding assembly programs with known,
deterministic control flow, load/store addresses and data, and opcode
composition.  The programs are compiled for the four supported ISAs
(x86_64, aarch64, riscv64, mipsel), traced under QEMU with the plugin, and
verified against the metadata emitted alongside each program.

**For the unified, one-command validation system (tiers, coverage map,
single exit code), see [`VALIDATION.md`](VALIDATION.md).**  The canonical
entrypoint is:

```sh
python -m champsim_tracer_validator full --build-dir /mnt/md0/QEMU/qemu/build
```

Use the Anaconda interpreter (`PATH=/home/maccoy-merrell/anaconda3/bin:$PATH`).

## The CLI

The package is `champsim_tracer_validator` (invoked with `python -m`).  Its
subcommands:

| Subcommand | Role |
| --- | --- |
| `generate` | emit a seed-driven `<prog>_<isa>.S` + `<prog>_<isa>.meta.json` |
| `build` | assemble/link the source for an ISA (missing toolchains skip, not error) |
| `trace` | run the plugin on the binary → `<prog>_<isa>.cst` |
| `analyze` | disassemble the ELF (Capstone) and annotate the metadata with ground truth |
| `validate` | decode the trace (`cst_decode --format=legacy`) and check it against the metadata (~48 checks in `validator.py::validate`) |
| `all` | generate → build → trace → analyze → validate for the requested ISA(s) |
| `simpoint_test` | per-simpoint segment independence + cross-segment consistency |
| `thread_test` | 2-thread guest-thread identity (user, or `--system --smp N`) |
| `churn_test` | multi-process ASID-churn pin (x86 + mipsel) |
| **`full`** | **the unified run — all of the above plus goldens, multi-proc harnesses, and feature probes, in four tiers with a coverage map and one exit code** |

Example single run:

```sh
python -m champsim_tracer_validator all --seed 0x0102 --isa x86_64 \
    --build-dir ../../../build -o /mnt/md0/QEMU/cst_runs/out01
```

Do **not** invoke `tests/run_roundtrip.sh` directly (it is a superseded thin
wrapper around `all`); use `full`/`all`.

## Package layout

| Path | Role |
| --- | --- |
| `champsim_tracer_validator/__main__.py` | CLI entrypoint (all subcommands) |
| `champsim_tracer_validator/_full.py` | the unified `full` orchestrator: feature registry, tiers, coverage map, quiet-host wait, JSON summary |
| `champsim_tracer_validator/_multiproc.py` | folded-in multi-process ASID harnesses (trace-all, mipsel latch, dead-latch) + physaddr / devio probes |
| `champsim_tracer_validator/generator.py` | CFG builder + assembly emitter + metadata writer |
| `champsim_tracer_validator/asm_blocks.py` | assembly-only `CodeBlock` library |
| `champsim_tracer_validator/classify.py` | Capstone mnemonic → `GenericOpcode` classifier |
| `champsim_tracer_validator/analyzer.py` | disassemble ELF, annotate metadata with ground truth |
| `champsim_tracer_validator/validator.py` | compare a decoded trace to metadata (the check battery) |
| `champsim_tracer_validator/_system.py` | system-mode boot staging + console/stat parsing |
| `tests/` | `golden_net.py` (byte + render golden net), `run_roundtrip.sh` (superseded), `large_scale.sh` (standing sweep), `tagged_ptr_addr.sh` |

## Why the generated program is so restricted

Deterministic wrong-path validation requires that, for every conditional
branch, the side execution did *not* take is still a legal, decodable
instruction stream the plugin will walk naturally for up to `wpdepth` BBs.
Generated programs are therefore a chain of **diamonds**:

```
          root (ends in cond branch)
          /  \
         T    F          <-- both sides are real, reachable code
         |    |
        ...  ...         <-- each side is a short chain
         \   /
         join
           |
         next diamond...
```

The branch at `root` is data-dependent on a compile-time-fixed arena slot,
so its outcome is 100 % predictable to both the CP tracer and to the
validator.  Whichever side CP takes, the *other* side is exactly the
wrong-path chain the plugin emits.  Long-running traces use explicit loop
head/body/exit regions (`--hot-iters`) rather than in-block hot loops, so
generator `CodeBlock`s and guest basic blocks stay aligned by construction.
