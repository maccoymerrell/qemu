# champsim_tracer_genval — procedural validation of the champsim_tracer plugin

This directory contains a seed-driven generator that produces C++ programs
with known, deterministic control flow, load/store addresses, load/store
data, and opcode composition.  The programs are compiled for each of the
four ISAs supported by the champsim_tracer plugin (x86_64, aarch64, riscv64,
mipsel), traced under QEMU with the plugin, and then verified against the
metadata that was emitted alongside the program at generation time.

The goal is to produce a repeatable, automatable validation harness that
exercises the plugin across:

  * every `GenericOpcode` class we can coax out of GCC,
  * every `BranchType` (direct jump, conditional direct, direct call,
    return, syscall, indirect jump/call),
  * dense load/store traffic with predictable addresses + data,
  * predictable wrong-path chains (via a fully static CFG with
    compile-time-deterministic branch outcomes).

## High-level pipeline

```
             +--------+     +-----------+     +---------+
   seed ---> | genval |---> | <prog>.cpp|---> | <isa>-  |
             | generate|    | <meta>.json     |  gcc    |
             +--------+     +-----------+     +---------+
                                                   |
                                                   v
                                             <prog>_<isa>
                                                   |
               +-----------+                      v
               | champsim_tracer   | <--- qemu-<isa> -plugin libchampsim_tracer
               | plugin    |             ...prog_<isa>
               +-----------+
                     |
                     v
                <prog>.wpt
                     |
                     v
             +---------------+         +------------------+
             | champsim_tracer_decode| ---+--> | genval validate  |
             +---------------+    |    +------------------+
                                  |
                           +------+------+
                           | objdump +  |
                           | classify.py|      (ground-truth opcode
                           +------------+       counts per BB)
```

1. **`genval generate --seed S --blocks N -o out/`** walks a seed-driven
   graph builder, assembles a reachable CFG of `~N` `CodeBlock` nodes,
   emits a standalone, freestanding C++ source file plus a JSON metadata
   sidecar describing the expected correct-path BB sequence, per-BB
   memory-access sets, and per-branch wrong-path targets.

2. **`genval build -o out/ [ISAs...]`** invokes each available cross
   compiler (`g++`, `aarch64-linux-gnu-g++`, `riscv64-linux-gnu-g++`,
   `mipsel-linux-gnu-g++`) to produce `out/<prog>_<isa>` binaries.
   Missing toolchains are skipped, not errors.

3. **`genval trace`** runs each `out/<prog>_<isa>` under `qemu-<isa>` with
   `libchampsim_tracer.so`, producing `out/<prog>_<isa>.wpt` / `.txt`.

4. **`genval analyze`** disassembles the compiled binary with Capstone
   (reusing the mnemonic → `GenericOpcode` mapping from
   `champsim_tracer_mnemonic_survey.py`) and extends the metadata with
   *per-block expected opcode sequences* — the ground truth for template
   validation.

5. **`genval validate`** decodes the `.wpt` file (via
   `champsim_tracer_decode.decode_champsim_tracer`) and checks, for every assertion in
   the metadata:
     * correct-path BB execution order matches `metadata.correct_path`,
     * every CP BB's dynamic load/store addresses match the planned set,
     * every CP BB's load/store data values match the planted data,
     * every BB template's instruction opcode sequence matches the
       disassembly-derived ground truth,
     * every BB ending in a conditional direct branch has a wrong-path
       chain whose template IDs match the statically-predicted WP path
       (taken side if CP took the fall-through, fall-through side if CP
       took the taken side, continued naturally until depth exhausts
       or an exit syscall is hit),
     * register IDs and immediates on every instruction match the
       disassembly.

## Why the generated program is so restricted

Deterministic wrong-path validation requires that, for every conditional
branch, the "other" side of the branch — the one execution did *not*
take — must still be a legal, decodable instruction stream that the
plugin will walk naturally for up to `max_wrong_path_depth=64` BBs.

To guarantee this while keeping the CFG non-trivial, generated programs
are built as a chain of **diamonds**:

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

The branch at `root` is data-dependent on a compile-time-fixed arena
slot, so the outcome is 100% predictable to both the CP tracer and to
us at generation time.  Whichever side CP takes, the *other* side is
exactly the wrong-path chain the plugin will emit (up to `depth` BBs,
then joining into the next diamond and so on).

Because arena slots that drive branch decisions are written **once** at
program start and never mutated, wrong-path execution — which runs over
real memory but has its register state snapshotted — cannot corrupt CP
control flow.  Any stores performed on wrong-path go to arena regions
that are not read until the store has faded into the past; we arrange
the CFG so that the "load arena" slots each CP BB reads are disjoint
from the "store arena" slots any WP BB it might trigger can write.

## Files

| Path | Role |
| --- | --- |
| `genval.py` | CLI entrypoint: `generate / build / trace / analyze / validate / all` |
| `genval/blocks.py` | `CodeBlock` library — straight-line, branching, memops, fpops, calls |
| `genval/generator.py` | CFG builder + C++ emitter + metadata writer |
| `genval/classify.py` | Capstone-backed mnemonic → `GenericOpcode` classifier |
| `genval/analyzer.py` | Disassemble compiled ELF, annotate metadata with ground truth |
| `genval/validator.py` | Compare decoded trace to metadata |
| `toolchain.sh` | Per-ISA compiler invocations (delegated to by the CLI) |
| `tests/run_roundtrip.sh` | End-to-end: generate → build → trace → validate |

## Relationship to the PIN tracer

Metadata in `*.meta.json` is tracer-agnostic: it describes the expected
*behaviour* of the program, not the shape of the champsim_tracer binary format.
A future `validator_pin.py` could consume the same metadata and check a
PIN-generated trace in the same way.  Cross-tracer equivalence is then
"both validators pass on the same binary + metadata."
