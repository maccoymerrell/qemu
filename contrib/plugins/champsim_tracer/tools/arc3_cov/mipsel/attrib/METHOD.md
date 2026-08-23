# ARC 3 register attribution -- mipsel, whole opcode space

Author: Maccoy Merrell.  Tree: /mnt/md0/QEMU/qemu @ 5379a000ac (champsim-trace).

## The number

| | |
| --- | ---: |
| opcodes attempted | **977** |
| tracer set == adjudicated reference set | **730** |
| disagree | **247** |
| **unprobed** | **0** |

Denominator: `opcodes.tsv`, the 977-row mipsel opcode space built by `METHOD.md`
in this directory.  Every row was probed on both sides; no row is excluded, and
no row is counted as agreeing because it could not be reached.

## What is compared

For each opcode, one representative little-endian encoding, and two sets:

* **tracer** -- `isaxcheck --isa=mipsel --layer=fields`, whose `SRC{}`/`DST{}`
  are the tracer's own `InsnFields` through `decode_detail_to_generic()`, i.e.
  what the trace is actually built from, not the Capstone boundary behind it.
* **reference** -- the ranked mipsel reference set, adjudicated per row.

Both are canonicalised into the tracer's own generic register namespace before
comparison (`attrib/canon.py`), so a naming difference is never a disagreement.
Per **R4** a sub-register difference is not a disagreement either: `HI<n>` and
`LO<n>` are the two halves of the 64-bit accumulator `AC<n>` and both
canonicalise to `REG_ACC<n>`; LLVM's `D<n>_64` (FGR64) canonicalises to
`REG_FPR<n>`.  `REG_ZERO` and `REG_IP` are dropped on both sides.

## The references, in rank order

1. **LLVM MC 18.1.3**, subtarget `mips32r2` + the full ASE set the tracer's own
   `kIsaTable` mipsel row selects.  Walked at the **`MCInstrDesc`** level, not
   `MCInst`: for `LWL`/`LWR`/`MOVF` the disassembler leaves the `TIED_TO`
   operand unmaterialised, so a consumer that walks `MCInst::getNumOperands()`
   silently loses the read-modify-write edge.  Implicit use/def lists included.
2. **binutils 2.42 `opcodes/mips-opc.c`**, linked and queried, not transcribed:
   the `pinfo`/`pinfo2` implied-register flags of every matching row.
3. **sail-cheri-mips** -- **not available in this environment**.  Where it is
   the named authority (the LL/SC link bit) the claim is carried by QEMU
   instead; this is stated per rule below rather than hidden.

Plus **QEMU's own modelling (R6)** for the three classes the arc brief names as
having no static mipsel reference: the trap footprint, FCSR on ordinary FP
arithmetic, and DSPControl.

## Adjudication rules

Every departure from the rank-1 answer carries a rule id, recorded per row in
`attrib.tsv`.  Nothing is averaged.

| rule | opcodes | what it decides |
| --- | ---: | --- |
| `L-AT` | 4 | LLVM defect. `BC1F/BC1T/BC1FL/BC1TL` carry `Defs=[AT]`, an artifact of the assembler's branch expansion, not an architectural write (**R2**). binutils names no such write. Removed from the reference -- **the tracer was right**. |
| `L-DSPCTL` | 6 | LLVM defect. `BPOSGE32`/`RDDSP` read DSPControl, `WRDSP` writes it, `MTHLIP` reads and writes it; none appears in the `MCInstrDesc` implicit lists. Added -- **the tracer was right**. |
| `L-MSACTL` | 1 | LLVM defect. `CTCMSA` models the MSA control register as a USE; the instruction writes it (`helper_msa_ctcmsa` assigns `env->active_tc.msacsr`). Corrected -- **the tracer was right**. |
| `Q-FCR31` | 89 | QEMU truth. 108 helpers in `target/mips/tcg/fpu_helper.c` call `update_fcr31()`, which does `SET_FP_CAUSE(env->active_fpu.fcr31, ...)` unconditionally and reads `GET_FP_ENABLE(fcr31)` and the fcr31 rounding mode. `abs`/`neg`/`class`/the pure moves do not, and are correctly excluded. |
| `Q-MSACSR` | 100 | QEMU truth. 50 MSA float helpers in `msa_helper.c` reach `update_msacsr()` (call-graph closure over the `MSA_FLOAT_*` macros, which is how the compare helpers get there). `fclass`/`fill` do not, and are correctly excluded. |
| `Q-TRAP` | 15 | QEMU truth. `target/mips/tcg/system/tlb_helper.c` `set_EPC` (:1421-1440) writes `CP0_EPC`, `CP0_Cause.BD`, `CP0_Status.EXL` and reads `CP0_Status`; :1051/:1066 writes `CP0_BadInstr`. Per **R5** a conditional trap still names the write. |
| `Q-CP0` | 15 | QEMU truth. The TLB and CP0-control helpers name their registers exactly: `r4k_helper_tlbr` writes EntryHi/EntryLo0/EntryLo1/PageMask, `r4k_helper_tlbp` writes Index, `helper_di`/`helper_ei` read and write `CP0_Status`, `helper_dvpe`/`helper_evpe` read-modify-write `CP0_MVPControl`. |
| `Q-LLBIT` | 4 | The link bit. `LL`/`LLE` write it, `SC`/`SCE` read and clear it -- the entire point of the pair. QEMU models it (`env->lladdr`, `env->llval`); sail-cheri-mips is the static reference that would corroborate it and is unavailable here. |
| `B2-MTFILE` | 24 | Rank 2 decides. The MT ASE `MFTR`/`MTTR` `(u, sel)` pair selects the register **file** of the far operand; binutils is the only reference that names it per form. LLVM, Capstone and the tracer collapse all 24 into one GPR<->GPR move (**C4**). |
| `R1-TIED` | 2 | Rank 1 decides. `LWLE`/`LWRE` merge into the destination, so the destination is also a source (**R5**/**C4**). |

### Rulings made against a reference

* **binutils `WR_HI`/`WR_LO` on the DSP multiply-to-GPR forms is overruled.**
  `mul.ph`, `mul_s.ph`, `muleq_s.w.ph[lr]`, `muleu_s.ph.qb[lr]`, `mulq_rs.ph`,
  `mulq_s.ph` carry the flag, but QEMU writes only `cpu_gpr[ret]`
  (`MUL_RETURN32_32_ph`), and LLVM declares no implicit def.  Those bits drive
  the assembler's mult/div **hazard** nop insertion, not a dataflow claim.
  Three sources against one; the tracer agrees with the adjudicated answer.
* **`dmt`/`emt` are taken from the MT ASE definition, not from QEMU.**
  `helper_dmt` is a `/* TODO */ return 0;` stub, so **R6**'s premise does not
  hold for it.  The architectural read-modify-write of `VPEControl` is used.
  This is a QEMU gap, reported as such.

## Verification of the measurement itself

* **Falsification.** All 730 agreeing rows were perturbed (drop one source, or
  plant a phantom destination where there is none) and re-compared: **730/730
  were flagged**.  The comparison cannot report agreement it has not checked.
* **Vacuous agreement.** Exactly **1** of the 730 agrees with both sets empty
  (`sync`, correctly empty); 35 agree with an empty destination set, all of them
  stores, branches and prefetches.
* **C3, measured rather than assumed.** For each opcode, every register-shaped
  field the decode pattern leaves free was rewritten to a fresh distinct value.
  969 opcodes have such a field; 965 still decode to the same mnemonic, and for
  **965/965** the tracer's operand-set shape is invariant under the permutation.
  Field genericity is a measured fact for this run, not a premise.
* **Two independent tracer paths.** The 977 rows were probed once with
  `--layer=fields --hex` (one process per encoding, binary `ca31c242...`) and
  again with the `--batch` fields columns added at tip `5379a000ac`
  (binary `e5a4a05f...`).  **977/977 identical.**
* **Rank-1 against rank-2.** 153 binutils implied-register assertions
  (`RD_HI`/`RD_LO`/`WR_HI`/`WR_LO`/`WR_$31`/`RD_$31`/`WR_CC`/`RD_CC`) were
  checked against the LLVM-derived reference.  26 did not hold; all 26 were
  adjudicated above (24 MT ASE file rows, and the DSP hazard-flag ruling).
* **Probe integrity.** A first pass silently lost 612 of 977 rows when the
  shared `build/` binary was relinked mid-run.  It was caught because the pass
  counts its own rows; every run since uses a snapshotted binary and asserts
  `rows == 977`.

## Findings that are not row disagreements

* **`FCC` is split from `FCSR` in the tracer's canonical model.** `FCC0..7` are
  bits of `FCR31`, but the tracer names them `REG_PRED0..7` while naming
  `FCR31` `REG_FCSR`.  A `ctc1` to `FCR31` followed by a `bc1t` is therefore a
  broken dependence.  It is not counted as a row disagreement because the
  representative `cfc1`/`ctc1` encodings select `FCR5`, not `FCR31`, so both
  sides are right at the probed encoding.  Affects `cfc1`, `ctc1`, `cftc1`,
  `cttc1` as a model question.
* **`rdhwr`'s representative encoding parks its destination on `$zero`.** It was
  re-probed with `rt=$a0` (`3be8047c`): the destination is attributed correctly
  (`REG_GPR4`).  No gap.

## Reproduce

```sh
cd /mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel/attrib
R=/mnt/md0/QEMU/cst_runs/_arc3_refs/mipsel/work
F='+mips32r2,+msa,+dsp,+dspr2,+dspr3,+fp64,+eva,+virt,+ginv,+crc,+abs2008,+nan2008,+mt,+mips3d'
awk -F'\t' 'NR>1{h=$3;print $1" "substr(h,7,2) substr(h,5,2) substr(h,3,2) substr(h,1,2)}' \
    ../opcodes.tsv > enc_word.txt
$R/llvm_probe --cpu=mips32r2 --feats="$F" < enc_word.txt > llvm_raw.txt
$R/binutils_probe                          < enc_word.txt > bu_raw.txt
awk -F'\t' 'NR>1{print $3}' ../opcodes.tsv | \
    /mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck \
        --isa=mipsel --layer=fields --batch > batch_tip.tsv
python qemu_classes.py /mnt/md0/QEMU/qemu     # the R6 leg, out of QEMU's own C
python parse.py && python build_ref.py && python adjudicate.py && python emit.py
```

`qemu_classes.py`, `parse.py`, `canon.py`, `build_ref.py`, `adjudicate.py` and
`emit.py` are mirrored into the repo at
`contrib/plugins/champsim_tracer/tools/arc3_cov/mipsel/attrib/`.  Running that
mirrored copy from an empty directory reproduces `attrib.tsv` and
`attrib_signatures.tsv` byte-identically, including regenerating the FCR31 and
MSACSR class membership from the QEMU tree rather than reusing this run's.

## Outputs

* `attrib.tsv` -- 977 rows, one per opcode: verdict, signature, both sets, the
  four set differences, the adjudication rules applied, and both references'
  raw answers.
* `attrib_signatures.tsv` -- the 16 distinct disagreement signatures with counts
  and the opcodes in each.
