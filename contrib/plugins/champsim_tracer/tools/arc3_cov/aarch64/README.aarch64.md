# ARC 3 coverage denominator — aarch64

These scripts enumerate the A64 **opcode space** that the ARC 3 coverage
claim is measured against.  They lived in a second top-level directory,
`tools/arc3_coverage/`, next to the enumerator they belong to; they are
aarch64-only and `adjudicate.py` in this directory already cites
`build_opcodes.py` by name, so one directory is where they go.  They read the Arm Machine Readable
Architecture XML (rank-1 reference for this ISA) and never consult
Capstone, which is the subject under test (ruling R7).

```sh
# rank-1 reference, once:
#   archive.org/download/arm-xml-a-profile-2022-12/ISA_A64_xml_A_profile-2022-12.tar.gz
#   archive.org/download/arm-xml-a-profile-2022-12/SysReg_xml_A_profile-2022-12.tar.gz
python build_opcodes.py <ISA_A64_xml_A_profile-2022-12/> <outdir>   # opcodes.tsv
python build_sysreg.py  <SysReg_xml_A_profile-2022-12/>  <out.tsv>  # selectors

# release-gap measurement: exhaustive top-22-bit LLVM mnemonic census,
# then one rank-2 row per operand shape for anything the MRA release
# predates.
python census.py | isaxcheck --isa=aarch64 --batch \
      | awk -F'\t' 'NR>1 && $17=="1"{n=split($19,a," "); print tolower(a[1])}' \
      | sort | uniq -c | sort -rn > llvm_census.txt
python census.py | isaxcheck --isa=aarch64 --batch | python harvest_gap.py
python append_gap.py
```

One row per Arm-named encoding — that naming is already the operand-shape
split ARC 3 wants — with encodings occupying the identical bit range and
an `Unconditionally` alias condition merged as pure re-spellings.  Every
representative encoding is verified by decoding it with `isaxcheck`.

The produced denominator, its README and its evidence live outside the
tree, under `/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64/`.

## Reachability: which encodings a QEMU guest can actually execute

The opcode denominator says what the architecture defines.  Whether a given
encoding is REACHABLE under QEMU is a separate question, and one signal cannot
answer it: a SIGILL at EL0 is equally consistent with the translator having no
pattern for the encoding, with an architectural ENABLE not being set, and with
the encoding living above EL0.  Three legs separate them, and every subject
carries all three on its row.

```sh
# leg 1+2 -- EL0, once per architectural enable state.  The arms are a UNION:
# an encoding is reachable if it runs under ANY of them.
qemu-aarch64 -cpu max ./reach_probe_a64 --pre=off     < all.hex > pre_off.tsv
qemu-aarch64 -cpu max ./reach_probe_a64 --pre=smstart < all.hex > pre_smstart.tsv
qemu-aarch64 -cpu max ./reach_probe_a64 --pre=sm      < all.hex > pre_sm.tsv
qemu-aarch64 -cpu max ./reach_probe_a64 --pre=za      < all.hex > pre_za.tsv

# leg 3 -- EL1, under qemu-system-aarch64, reporting ESR_EL1.EC per encoding.
# Sharded because an encoding really can wedge the machine at EL1 and each
# wedge costs a pass; the parallel cap is the host courtesy ceiling.
cp all.hex evidence/reach_in.hex
./sysreach_batch.sh evidence 200 8          # -> evidence/el1.tsv

# the verdict, per row, with the legs printed on it
python reach_adjudicate.py --el0 off=pre_off.tsv --el0 smstart=pre_smstart.tsv \
       --el0 sm=pre_sm.tsv --el0 za=pre_za.tsv --el1 evidence/el1.tsv \
       --gates unprobed_verdicts.tsv --out reach_verdicts.tsv
```

`EC == 0x00` at EL1 is the architecture's UNDEFINED and, with FP, SVE and SME
all enabled at maximum vector length, can only be the translator refusing the
encoding.  Any other EC — a data abort, an alignment fault, an FP exception, a
Memory-Copy/Set exception — means QEMU decoded it and then took an
architectural exception, so the row is reachable.  A row with no leg is
REFUSED by name and the tool exits non-zero, because a missing leg scoring as
a verdict is exactly how the UNREACHABLE column came to read zero.

The EL1 leg does not separate "unimplemented" from "implemented only at EL2 or
EL3"; that residue is sized per row rather than folded into the verdict.

## The MRA sweep and vector length

`mra_sweep.py` runs the reference over the denominator at one vector length and
records, alongside the register sets and the memory counts, the BYTE totals,
whether each total is complete, and the interpreter's notes.  The notes are
load-bearing: `undefined-path` says the ASL reached its own UNDEFINED statement
at that vector length, which is what distinguishes an encoding that is not
DEFINED at a length from a register set that MOVED with it.  A sweep without
them cannot make that distinction, and `memop_axis_verdict.py` refuses rather
than report the wrong one.

```sh
python mra_sweep.py --vl 512 --out ref_512.json
python mra_sweep.py --vl 128 --out ref_128.json
python memop_axis_verdict.py --ref-a ref_512.json --ref-b ref_128.json \
       --batch a64_batch.tsv --decode run_dec.txt --run-vl 512
```

`--run-vl` is the vector length the run in `--decode` executed at.  Given it,
the vector-length-dependent rows are scored against the reference swept at that
same length instead of being set aside; the sweep records its own length so the
two can be checked against each other, and a mismatch refuses.
