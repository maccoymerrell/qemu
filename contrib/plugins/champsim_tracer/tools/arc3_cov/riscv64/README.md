# riscv64 register-attribution cross-check (ARC 3 measurement)

Measures how right the tracer's per-instruction register SOURCE and DESTINATION
sets are today, per opcode, over the whole riscv64 opcode space, against
Sail-RISCV as the ranked reference.

## Pieces

| File | Role |
| --- | --- |
| `sail_effects.py` | Interprocedural, value-aware register-effect extraction from the Sail model. Parses `function clause execute` bodies, propagates the operand values the encoding fixes, prunes `match`/`if` arms that encoding cannot reach, and resolves reads/writes through the call graph down to the leaf accessors. |
| `expand_vals.py` | The denominator's `expand.py` with the per-variable concrete assignment recorded alongside each row, so a reference environment can be built for each representative encoding. Emits identical words to the unpatched script. |
| `compare.py` | Instantiates the reference per opcode, runs `isaxcheck --layer=fields --batch` for the tracer's own InsnFields, compares as sets, adjudicates, and writes `attrib.tsv` + `attrib_signatures.txt`. One `--batch` pass per profile. |
| `emit.py` | Classifies the parsed Sail rows into `opcodes.tsv` (the denominator) and `excluded.tsv`, and writes `manifest.json`. Re-probes every representative encoding with the current `isaxcheck` on each run rather than trusting the flags in `rows.json`, and refuses to finish if any named exclusion reason has stopped matching rows. |
| `zcmp_profile.py` | The Zcmp/Zcmt enumeration profile: its eight opcodes, their QEMU-truth reference sets with per-row citations, and the decoder settings the second pass needs. |

## Running

The scripts expect the denominator tree built by the coverage run
(`clauses.json`, `rows.json`, `sail_parse.py`, `gen_opcodes.py`, `expand.py`,
`ref/sail-riscv`) in the parent directory:

```sh
cd /mnt/md0/QEMU/cst_runs/_arc3_cov/riscv64
python emit.py                       # re-probes, writes opcodes.tsv + excluded.tsv
python -c "import sys,runpy; sys.path.insert(0,'.'); runpy.run_path('attrib/expand_vals.py', run_name='__main__')"
python attrib/compare.py
```

`emit.py` re-decodes every representative encoding with `isaxcheck` before it
classifies anything (`CST_ISAXCHECK` overrides the binary), prints any row
whose decode status has moved since `rows.json`, and writes the refreshed
status back.  An exclusion reason that names a specific extension and matches
no row ends the run: a justification nobody can check is how `ssamoswap.w` and
`ssamoswap.d` stayed excluded as undecodable for as long as it took
`CS_MODE_RISCV_ZICFISS` to be switched on.

## Profiles

The riscv64 opcode space is not enumerable in one decoder configuration.
Zcmp and Zcmt occupy the compressed FP-store encodings, so they are mutually
exclusive with the Zcd that C+D implies -- QEMU refuses to build a CPU with
both (`target/riscv/tcg/tcg-cpu.c:767`) and forcing Capstone's
`CS_MODE_RISCV_ZCMP_ZCMT_ZCE` on top of the RV64GC mode rewrites 331 correct
decodes.  They are not out of the tracer's scope either: `cap_mode_riscv()`
turns a `zcmp` / `zcmt` / `zce` token in the guest ELF's `Tag_RISCV_arch` into
exactly that mode bit.

So `opcodes.tsv` carries a `profile` column and `compare.py` runs one
`--batch` pass per profile:

| profile | rows | decoder | reference |
| --- | ---: | --- | --- |
| `rv64gc` | 1062 | the shipped `kIsaTable` riscv64 row | Sail-RISCV |
| `zcmp` | 8 | `--cs-mode-add=zcmp` plus the matching `--mattr` | QEMU's own translation (R6) |

Sail has no clause for either extension and LLVM MC, though it decodes all
eight once told `+zcmp,+zcmt`, models none of their register traffic -- its
`MCInstrDesc` reports `RD{} WR{}` for `cm.push` exactly as Capstone does, so a
reference built from it would agree with the subject by being equally empty.
The `zcmp` rows are therefore referenced to QEMU's translator, line-cited per
row in `zcmp_profile.py`, which is the same R6 leg the mipsel harness uses for
its trap footprint.

## Scope

The reference is the instruction's effect on the visible register file plus the
CSRs its own semantics consult. Address translation, PMP, platform devices,
trap entry, CSR access-permission gates and extension dirty-state bookkeeping
are excluded on both sides; the exclusion list is enumerated in
`sail_effects.BLACKLIST` and restated in the generated summary rather than left
implicit.
