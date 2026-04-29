# champsim_tracer_genval — procedural validation of the champsim_tracer plugin

This directory contains a seed-driven generator that produces freestanding
assembly programs
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
   seed ---> | genval |---> | <prog>.S  |---> | <isa>-  |
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
                <prog>.cst
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
  graph builder, assembles a reachable CFG of `~N` assembly `CodeBlock` nodes,
  emits a standalone freestanding assembly source file plus a JSON metadata
   sidecar describing the expected correct-path BB sequence, per-BB
   memory-access sets, and per-branch wrong-path targets.

2. **`genval build -o out/ [ISAs...]`** invokes each available cross
   compiler (`g++`, `aarch64-linux-gnu-g++`, `riscv64-linux-gnu-g++`,
  `mipsel-linux-gnu-g++`) to assemble and link `out/<prog>_<isa>` binaries.
   Missing toolchains are skipped, not errors.

3. **`genval trace`** runs each `out/<prog>_<isa>` under `qemu-<isa>` with
   `libchampsim_tracer.so`, producing `out/<prog>_<isa>.cst` / `.txt`.

4. **`genval analyze`** disassembles the compiled binary with Capstone
   (reusing the mnemonic → `GenericOpcode` mapping from
   `champsim_tracer_mnemonic_survey.py`) and extends the metadata with
   *per-block expected opcode sequences* — the ground truth for template
   validation.

5. **`genval validate`** decodes the `.cst` file (via
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

Because arena slots that drive branch decisions are manipulated in
explicit basic blocks, wrong-path execution runs over the exact code the
validator models. Long-running traces now use explicit loop
head/body/exit regions rather than in-block hot loops, so generator
`CodeBlock`s and guest basic blocks stay aligned by construction.

## Files

| Path | Role |
| --- | --- |
| `genval.py` | CLI entrypoint: `generate / build / trace / analyze / validate / all` |
| `genval/asm_blocks.py` | Active assembly-only `CodeBlock` library |
| `genval/generator.py` | CFG builder + assembly emitter + metadata writer |
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

---

## Current validation status (as of 2026-04-28)

### Multi-ISA seed sweep

A 40-run matrix (4 ISAs × 10 seeds) and a 12-run regdata matrix
(4 ISAs × 3 seeds with `--regdata`) both completed with **0 errors and
0 warnings** (info-level coverage and address-recompute summaries only).

### Active validator checks

All of the following checks are wired into `validate()` and confirmed
passing across all ISAs and seeds:

| Check | Description |
| --- | --- |
| `_check_blocks_covered` | Every expected CP block ID appears in the trace |
| `_check_cp_execution_order` | CP basic-block sequence matches `metadata.correct_path` |
| `_check_cp_memops` | Load/store addresses and data values match planted values |
| `_check_memop_insn_attribution` | Each mem-op in the trace is attributed to the correct instruction PC |
| `_check_address_recompute` | Arena addresses recomputed from reg snapshots match observed addresses |
| `_check_opcode_coverage` | Per-ISA opcode coverage across the reachable block set |
| `_check_branch_coverage` | Per-ISA branch-type coverage across the reachable block set (added 2026-04-28) |
| `_check_wrong_path_chains` | WP chain block IDs and order match statically-predicted wrong paths |

`_check_address_recompute` with `--regdata` confirmed across all ISAs
with `errors=0` and nonzero `ok` counts:

| ISA | ok | skipped | errors |
| --- | --- | --- | --- |
| x86_64 | 132 | 0 | 0 |
| aarch64 | 132 | 0 | 0 |
| riscv64 | 172 | 0 | 0 |
| mipsel | 264 | 0 | 0 |

### Opcode coverage

Coverage is reported as `seen / total_reachable` where `total_reachable =
seen + reachable_unseen`.  Blocks whose opcode types are fully absent from
the block library (ISA not yet implemented) appear in `reachable_unseen`;
`asserted_unseen` is 0 for all ISAs, meaning no opcode class expected to
be present was actually missing.

| ISA | seen | total reachable | coverage |
| --- | --- | --- | --- |
| x86_64 | 7 | 47 | **14.9 %** |
| aarch64 | 8 | 44 | **18.2 %** |
| riscv64 | 8 | 30 | **26.7 %** |
| mipsel | 9 | 36 | **25.0 %** |

### Branch-type coverage

| ISA | seen | total reachable | coverage |
| --- | --- | --- | --- |
| x86_64 | 4 | 5 | **80.0 %** |
| aarch64 | 4 | 9 | **44.4 %** |
| riscv64 | 4 | 8 | **50.0 %** |
| mipsel | 3 | 9 | **33.3 %** |

Branch-type coverage is capped by which branch types the assembly block
library (`genval/asm_blocks.py`) currently emits.  Indirect
branches, direct calls, returns, and syscalls exist in the ISA but have
not yet been added to the block library, accounting for the `reachable_unseen`
entries above.

### Known issues resolved

| Issue | Fix |
| --- | --- |
| `AttributeError: type object 'IntAdd' has no attribute 'terminal'` in coverage mode | Added `terminal: ClassVar[bool] = False` default to the `CodeBlock` base class in `asm_blocks.py`; `ExitBlock` keeps `terminal = True` |
| AArch64 non-encodable immediate in `eor` / `xor` variants | Replaced non-encodable immediates with register-materialised constants in `asm_blocks.py` |
| RISC-V 12-bit `addi`/offset constraint violations | Rewrote affected emit paths to use scratch-register addressing for large offsets and reg-to-reg arithmetic for large adds |
| MIPSel arena-base materialisation fragility | Switched to explicit `lui`/`addiu` two-instruction address materialisation |
| LIEF 0.17.x enum API drift (`ELF_CLASS`, `ELF_DATA`, section flags) | Added compatibility shims in `champsim_tracer_mnemonic_survey.py` |
