# riscv64 register-attribution cross-check (ARC 3 measurement)

Measures how right the tracer's per-instruction register SOURCE and DESTINATION
sets are today, per opcode, over the whole riscv64 opcode space, against
Sail-RISCV as the ranked reference.

## Pieces

| File | Role |
| --- | --- |
| `sail_effects.py` | Interprocedural, value-aware register-effect extraction from the Sail model. Parses `function clause execute` bodies, propagates the operand values the encoding fixes, prunes `match`/`if` arms that encoding cannot reach, and resolves reads/writes through the call graph down to the leaf accessors. |
| `expand_vals.py` | The denominator's `expand.py` with the per-variable concrete assignment recorded alongside each row, so a reference environment can be built for each representative encoding. Emits identical words to the unpatched script. |
| `compare.py` | Instantiates the reference per opcode, runs `isaxcheck --layer=fields --batch` for the tracer's own InsnFields, compares as sets, adjudicates, and writes `attrib.tsv` + `attrib_signatures.txt`. |

## Running

The scripts expect the denominator tree built by the coverage run
(`opcodes.tsv`, `clauses.json`, `rows.json`, `gen_opcodes.py`, `expand.py`,
`ref/sail-riscv`) in the parent directory:

```sh
cd /mnt/md0/QEMU/cst_runs/_arc3_cov/riscv64
python -c "import sys,runpy; sys.path.insert(0,'.'); runpy.run_path('attrib/expand_vals.py', run_name='__main__')"
python attrib/compare.py
```

## Scope

The reference is the instruction's effect on the visible register file plus the
CSRs its own semantics consult. Address translation, PMP, platform devices,
trap entry, CSR access-permission gates and extension dirty-state bookkeeping
are excluded on both sides; the exclusion list is enumerated in
`sail_effects.BLACKLIST` and restated in the generated summary rather than left
implicit.
