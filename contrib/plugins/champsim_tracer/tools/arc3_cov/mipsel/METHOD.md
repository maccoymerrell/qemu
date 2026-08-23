# ARC 3 coverage denominator -- mipsel opcode space

Author: Maccoy Merrell.  Tree: /mnt/md0/QEMU/qemu @ 54b5c49c1e (champsim-trace).

## The number

**977 opcodes** (975 distinct mnemonics; `rddsp` and `wrdsp` each contribute two
operand shapes).  One row per opcode in `opcodes.tsv`, each with one
representative little-endian encoding that both reference decoders accept.

## Denominator, and why it is defensible

Per C3 the denominator is the OPCODE space, not the encoding space.  MIPS is a
fixed-format RISC: an instruction's operand shape is fully determined by its
`(match, mask)` decode pattern, and the register / immediate / target fields
inside that pattern are generic.  So one representative encoding per decode
pattern suffices, and a shape whose operand set differs is necessarily a
different pattern.

The enumeration source is the ranked mipsel reference set, used in rank order:

* **binutils 2.42 `opcodes/mips-opc.c`** supplies the row universe.  This is
  the 2,872-row `mips_opcodes[]` array itself -- compiled and linked, not
  transcribed -- together with its own `decode_mips_operand()`, which is the
  function the GNU assembler and disassembler call to place every operand
  field.  Representative encodings are therefore built out of the reference's
  own bit layout.
* **LLVM MC 18.1.3** (rank 1 for mipsel: the only source with tied
  destinations, FCR31 and the FR=0 AFGR64 pairing) is the decode gate and the
  naming authority.  Where LLVM's mnemonic for a pattern is one of that
  pattern's own alternate spellings, LLVM's name is the primary one
  (this is why the MIPS32r2 rotate appears as `rotr`, not binutils' `ror`).

binutils is used for enumeration rather than LLVM because it is the exhaustive
*named-row-with-encoding* table, and because the prior exhaustive 2^32 mipsel
sweep (`/mnt/md0/QEMU/cst_runs/_arc3_refs/mipsel/work/SWEEP_FULL.txt`) measured
that LLVM accepts only 1,343,616 encodings binutils rejects -- all of them
`wrdsp` mask-field values, an opcode already in this list.  Enumerating from
binutils therefore cannot miss an opcode LLVM decodes.

Scope is the mipsel decode target as the tracer's own cross-checker defines it
(`contrib/plugins/champsim_tracer/tools/isaxcheck.cc`, `kIsaTable` mipsel row):
`mips32r2` plus `msa, dsp, dspr2, dspr3, fp64, eva, virt, ginv, crc, abs2008,
nan2008, mt, mips3d`.

## Row-level accounting (all 2,872 named binutils rows)

| rows | disposition |
| ---: | --- |
|  977 | **opcodes in `opcodes.tsv`** |
| 1299 | outside the mipsel ISA/ASE scope (MIPS64-only, MIPS32R6-only, vendor/ASE not selected) |
|  233 | assembler macros (`INSN_MACRO`): expand to a sequence, no encoding of their own (168 in scope, 65 out) |
|  165 | decode patterns no reference decoder accepts at this target (see below) |
|   86 | second assembler syntax for an identical `(match, mask)` pattern |
|   81 | operand-syntax variant subsumed by the same instruction's general form |
|   21 | rows the table itself flags `INSN2_ALIAS` (alternate spellings; R3) |
|    6 | R3 idioms: fixed-field forms of another opcode (`nal`, `neg`, `negu`, `not`, `pause`, `sync.p`) |
|    2 | raw-field assembler spelling of the MT ASE move (`mftr`, `mttr`) |
|    2 | assembler coprocessor escapes (`c0`, `c1`: raw 25-bit COPz payload) |
| 2872 | total |

Per-row detail with reasons: `excluded.tsv` (1,895 entries; the 165 undecodable
patterns are listed once per pattern).

## Shapes

`rddsp` and `wrdsp` each appear twice: the DSP control register's explicit-mask
form and its all-fields form are distinct decode patterns with distinct operand
sets.  The 24 named `mft*`/`mtt*` MT-ASE forms are kept separately rather than
folded into LLVM's single `MFTR`/`MTTR`, because the `u`/`sel` fields select a
different *source register file* per form (GPR, FPR, CP0, DSP accumulator,
HI/LO) -- a materially different operand set, which is exactly what this
coverage claim measures.  LLVM names all 24 `mftr`/`mttr`; that is the only
mnemonic divergence in the list.

## Verification

Every one of the 977 representative encodings was decoded individually:

```sh
build/contrib/plugins/isaxcheck --isa=mipsel --hex=<bytes>
```

977 checked, 0 failures -- both the Capstone decode boundary (`boundary ok=1`)
and the LLVM reference (`llvm ok=1`) accept every row.  Log:
`work/hexverify.log`.  Per-row decode text, both decoders:
`opcodes_verified.tsv`.

The 165 excluded patterns were not dropped on a single failed probe.  For each
one, **the whole free-bit space of the pattern was enumerated exhaustively**
(65.2M encodings in total across the 165) and passed through
`isaxcheck --batch`; not one encoding of any of them is accepted by either
decoder.  The families are:

| patterns | family | why it is out of scope |
| ---: | --- | --- |
| 108 | MIPS-3D / paired-single COP1 `fmt=PS` (`*.ps`, `cabs.*`, `recip1/2`, `rsqrt1/2`, `bc1any*`) | LLVM's Mips backend models only a fragment of paired-single; the rest has no decoder at this target |
|  17 | COP2 (`bc2*`, `cfc2`, `ctc2`, `mfhc2`, `mthc2`, `c2`) | no COP2 register file is modelled |
|  16 | `udi0`..`udi15` | user-defined instruction slots: no architectural semantics to record |
|  12 | MIPS VZ guest context (`tlbg*`, `hypcall`, `mfgc0`, `mtgc0`) | VZ is not modelled |
|   6 | CRC ASE (`crc32*`) | LLVM gates CRC at MIPS32R6; the target is r2 |
|   2 | GINV ASE (`ginvi`, `ginvt`) | LLVM gates GINV at MIPS32R6 |
|   2 | shadow-GPR moves (`rdpgpr`, `wrpgpr`) | not modelled |
|   1 | `prefx` | not modelled |
|   1 | `bposge32c` (DSPr3) | not modelled |

One pattern that failed the first probe was *repaired* rather than excluded:
`rdhwr` (`7c00003b/ffe007ff`).  LLVM restricts the hardware-register field to
the architecturally defined HWRs, so the generic fill `rd=5` was a bad row; the
exhaustive search found `rd=29`, and `rdhwr` is in the list.

A wider ASE sweep was run as a control: enabling MDMX, DSP64, MSA64, MCU, XPA,
SMARTMIPS and MIPS16e2 adds 250 binutils rows.  None decodes as its named
instruction at the mipsel target; the 20 encodings among them that decode at
all resolve to MSA opcodes already enumerated here.  Nothing is lost by the
narrower scope.

## Reproduce

```sh
cd /mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel/work
B=/mnt/md0/QEMU/cst_runs/_arc3_refs/mipsel/work/bu/binutils-2.42
S=/mnt/md0/QEMU/cst_runs/_arc3_refs/mipsel/work/shim
gcc -c -O1 -std=gnu11 -o mips-opc.o -I $S -I $B/include -I $B/opcodes $B/opcodes/mips-opc.c
gcc -O1 -std=gnu11 -I $S -I $B/include -I $B/opcodes -o mips_enum mips_enum.c mips-opc.o
for v in 0 1 2 3; do ./mips_enum --variant=$v > raw_v$v.tsv; done
python build_list.py          # pattern grouping + first-pass encoding selection
python repair2.py             # exhaustive free-space search for the residue
python finalize.py            # subsumption, naming, verification, output
```

The same sources are in the repo at
`contrib/plugins/champsim_tracer/tools/arc3_cov/mipsel/`; `repair.py` (a
sampling first attempt, superseded by the exhaustive `repair2.py`) is not
mirrored.
