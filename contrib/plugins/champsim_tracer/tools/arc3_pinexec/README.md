# arc3_pinexec — Intel PIN as the x86_64 EXECUTION reference

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

A static decoder can say what an encoding *may* touch.  Only an execution
reference can say what one dynamic instruction *did* touch: the real value in
a register, the real effective address, the real bytes moved, one-to-one
against a real run.  PIN is that reference on x86_64, and this directory is
the harness that pairs it against a `champsim_tracer` trace of the same
program point.

Static decode is the FALLBACK for instructions execution cannot reach, not
the primary.

## What is here

| file | what it is |
| --- | --- |
| `champsim_memop_pintool.cpp` | the memop pintool: per dynamic instruction, per memory operand — COUNT, ADDRESS, WIDTH and DATA |
| `champsim_reg_pintool.cpp` | the register pintool: per dynamic instruction, every source and destination register the ISA names — id, width, and VALUE |
| `pinreglib.py` | reader for the register record, plus the shared register vocabulary |
| `cmp_reg.py` | the register cross-check: src set, dst set, dst VALUE, src VALUE, rip-as-source |
| `Makefile` | builds it against the PIN kit (`make PIN_ROOT=...`) |
| `run_reg_arm.sh` | the register arm end to end: pintool build, both halves under one minimal environment, the pairing, and all five negative controls |
| `pinmemlib.py` | reader for the 392-byte reference record |
| `qextract_mem.py` | `cst_decode --format=disasm --objdump` → one JSON object per correct-path instruction, carrying memop values (`lv`/`sv`) as well as addresses and widths |
| `cmp_memop.py` | the cross-check: COUNT / ADDRESS / WIDTH / DATA, every disagreement carrying a CATEGORY and a DIRECTION |
| `memcheck_self.py` | store-to-load self-consistency of ONE stream, reference-free |
| `negative_control.py` | injects one named memop defect class, so a green result has to be earned |
| `adjudicate_x86.py` | settles a PIN/tracer register disagreement with a third decoder (iced-x86) |

The register arm used to be `pin_compare/tool_wide/` — the widened ChampSim
`input_instr`, 8 destination / 16 source slots — with
`pin_repair3/_work/compare.py`.  That record carries register IDENTIFIERS
only, and its operand list came from `INS_RegR`/`INS_RegW`, which report the
EXPLICIT operands.  `champsim_reg_pintool.cpp` supersedes it on both counts;
see "The register arm" below.  `tool_wide` is still the arm that carries
branch geometry and de-duplicated memop addresses.

## Running it

```sh
# reference half
make PIN_ROOT=/mnt/md0/PIN/pin-external-4.2-99776-g21d818fa2-gcc-linux
setarch -R $PIN_ROOT/pin -t obj-intel64/champsim_memop_pintool.so \
        -o memop.bin -s 0 -t 400000 -- ./prog

# tracer half — memdata=1 is what puts `ld=`/`st=` VALUES on the wire
setarch -R qemu-x86_64 -plugin .../libchampsim_tracer.so,outfile=q,wp=0,memdata=1,regdata=1 ./prog
cst_decode --format=disasm --objdump q.cst | python qextract_mem.py - 400000 > qm.jsonl

# the cross-check, and the reference-free check beside it
PYTHONPATH=. python cmp_memop.py --pin memop.bin --qemu qm.jsonl --anchor 0 --out cmp_memop.txt
PYTHONPATH=. python memcheck_self.py --qemu qm.jsonl
```

## The register arm

```sh
# reference half -- id AND value, explicit AND implicit
setarch -R $PIN_ROOT/pin -t obj-intel64/champsim_reg_pintool.so \
        -o reg.bin -s 0 -t 400000 -- ./prog

# tracer half -- regdata=1 is what puts destination VALUES on the wire
setarch -R qemu-x86_64 -plugin .../libchampsim_tracer.so,outfile=q,wp=0,memdata=1,regdata=1 ./prog
cst_decode --format=disasm --objdump q.cst | python qextract_mem.py - 400000 > q.jsonl

PYTHONPATH=. python cmp_reg.py --pin reg.bin --qemu q.jsonl \
        --anchor 0 --qskip 1 --out cmp_reg.txt --maxreport 99999
```

Run both halves under the SAME minimal environment (`env -i VAR=1 ...`):
the two processes place their stacks independently, and an environment block
of a different length multiplies the number of distinct pointer deltas the
comparison has to establish.

Five axes, and what each is worth:

| axis | reference | tracer side |
| --- | --- | --- |
| src register set | XED's FULL template operand list, explicit AND suppressed, plus memory base/index/segment and the RFLAGS read set | the wire's source refs |
| dst register set | same list, write side | the wire's destination refs |
| dst register VALUE | `PIN_GetContextRegval` at the NEXT instruction's IPOINT_BEFORE, i.e. after this one retired | `%r[0x../wN]` under `regdata=1` |
| src register VALUE | the same call at this instruction's own IPOINT_BEFORE | RECONSTRUCTED: a shadow register file replayed from the tracer's own published destination writes |
| rip as a source | the record's own `ip` | the record's own `pc`, under a code delta the pairing measured |

Three things this arm gets right that the `INS_RegR` arm could not:

**PIN's silence is now evidence.**  XED's template operand list is the decode
tables' own account of what an instruction touches, suppressed operands
included, so a register absent from it is a register the instruction does not
name.  The old arm could convict a SUBSET and never a SUPERSET.

**The decode sets CET.**  `xed3_operand_set_cet(&d, 1)` before `xed_decode`.
Without it `f3 0f 1e fa` decodes as `nop edx, edi` — two register reads
`endbr64` does not perform — and `f3 48 0f 1e c8` (`rdsspq`) as a
register-reading nop.

**A conditionally written operand is a source.**  The action comes from
`xed_decoded_inst_operand_action`, and `CW`/`RCW` count as READ: when a
`cmov`'s condition fails the destination keeps the value it already held, so
that value flows to the result.  This is what iced-x86 encodes as
`COND_WRITE`.

Three reference corrections live in the pintool, each with its adjudication
in the comment beside it: `push`/`pop`/`call`/`ret` step rSP (XED expresses
that only through the `STACKPUSH`/`STACKPOP` pseudo-registers), `leave`
WRITES rSP without reading it (XED marks it read-write; the SDM and iced-x86
do not), and a string operation writes the pointer register it steps.

## How a disagreement is reported

A bare disagree count is not a result.  Every disagreeing row carries a
direction:

| direction | meaning | verdict |
| --- | --- | --- |
| `TRACER-SUPERSET` | we record something true the reference omits | OK |
| `TRACER-SUBSET` | the reference records something we drop | DEFECT |
| `ORTHOGONAL` | different vocabulary for the same fact | OK, named |
| `UNACCOUNTED` | not yet interrogated | must be 0 |

## Two things the harness must not be allowed to do

**PIN's silence was not evidence, and where it still is not, say so.**  On
the OLD register arm (`tool_wide`, `INS_RegR`) PIN reported EXPLICIT operands
only, so a register it did not name was not a register we were wrong to name;
only its POSITIVE evidence counted, adjudicated against a third decoder by
`adjudicate_x86.py`.  `champsim_reg_pintool.cpp` removes that limit — it
walks XED's full template operand list with CET set — so on the register arm
BOTH directions now carry evidence.  Any result still quoted from `tool_wide`
carries the old one-directional caveat.

**The delta model must not establish itself.**  The two runs are different
processes: their images load identically (non-PIE static guest) but their
stacks, environment blocks and mappings do not, so a pointer differs by a
constant per region.  Accepting any *frequent* delta as explained would let a
systematic address error mint its own explanation — a tracer that shifted
every stack access by 8 bytes would score 100%.  That is not hypothetical:
it is what the `addr` negative control measured before the constraint below
existed, and the harness reported a clean sheet.

So a delta is ESTABLISHED only if it has `--minsupport` witnesses **and** the
address range it covers is disjoint from every stronger delta's range — the
piecewise-constant map that a set of relocated mappings actually produces.
Deltas rejected for overlap are scored UNACCOUNTED, not absorbed.

## The negative control is part of the result

`negative_control.py` injects one defect class at a time.  A row that does
not move under its own mutation is BLIND, and that is a finding about the
harness, not a clean bill of health for the tracer.

| mutation | which instrument convicts it |
| --- | --- |
| `drop` / `extra` (a memop added or removed) | `cmp_memop` COUNT |
| `width` (an access size halved) | `cmp_memop` WIDTH |
| `addr` (an address moved 8 bytes) | `cmp_memop` ADDRESS, and `memcheck_self` |
| `value` (a data bit flipped) | `memcheck_self`; `cmp_memop` DATA moves but its CATEGORY layer absorbs most of them |

That last row is the honest limit of a cross-run value comparison: at an
address the two processes already hold different bytes in, a value difference
cannot by itself convict either instrument.  `memcheck_self.py` is what
convicts it, because it needs no second process — it replays the stream's own
stores and asserts that every later load of those bytes reads back what the
stream itself recorded storing.

## The register arm's negative controls

`cmp_reg.py --mutate` injects one defect class into the TRACER side.

| mutation | which instrument convicts it |
| --- | --- |
| `dropsrc` / `extrasrc` | `src register set` |
| `dropdst` | `dst register set` |
| `dstvalue` | `dst register VALUE` exact count — and, because a wrong published write is also wrong everywhere it is later read, `src register VALUE` with it |
| `srcvalue` | `src register VALUE` exact count **alone**: it corrupts only the value that reaches the shadow register file, leaving the destination comparison byte-identical to baseline |

`srcvalue` is the only control that isolates the SOURCE-value axis, and that
is the point of it.  That axis is the one whose tracer side is RECONSTRUCTED —
a shadow register file replayed from the tracer's own published destination
writes — rather than read off the wire, so the thing needing proof is that the
propagation from a corrupted producer actually reaches a later consumer.  A
control that moves the destination comparison at the same time cannot show
that; the movement could be the destination axis leaking sideways.  `srcvalue`
therefore mutates `_sv` (the shadow publication) and not `_dv` (the
destination comparison), and the shape that convicts is: dst-VALUE columns
UNCHANGED, src-VALUE columns MOVED.

Every run — control and baseline alike — appends one machine-parsable
`CONTROL SUMMARY` line carrying **every** axis to `--summary FILE`.  A control
row that does not report the axis it exists to convict is not evidence about
that axis, whatever field the mutation touched.

`run_reg_arm.sh <outdir>` runs the whole arm: it builds the pintool, runs both
halves under one minimal environment, and pairs baseline plus all five
controls through the `--anchor 0 --qskip 1` the pairing needs.  Without the
anchor `cmp_reg.py` exits 2 with "no anchor; the pair is not aligned" rather
than scoring a misaligned pair, which is the correct refusal and not something
to route around.

A cross-run value comparison has an honest limit, and it is the same one the
memop arm documents: where the two processes legitimately hold different
values, a value difference cannot by itself convict either instrument.  The
model that keeps it from laundering everything is the DELTA DOMAIN: a
PIN-QEMU pointer delta is ESTABLISHED only with `--minsupport` witnesses AND
a page domain disjoint from every stronger delta's, and a value inside an
established page whose delta is WRONG is scored `IN-MAPPING-WRONG-DELTA` /
UNACCOUNTED rather than absorbed as "both look like pointers".  That is what
makes the `dstvalue` control fire.

## The reference corrections, and the falsifier that convicts them

The reference is CORRECTED where it is provably wrong, never labelled around
(R7.1, R7.7).  Two corrections live in `champsim_reg_pintool.cpp`:

* `xed3_operand_set_cet(&d, 1)` before the decode.  PIN's own decode leaves
  the CET operand clear, and `f30f1efa` then decodes not as `endbr64` but as
  `NOP_GPRv_GPRv_0F1E`, a two-register-reading nop.  The same unset bit turns
  `rdsspq` into a phantom `rax,rcx` read.
* `leave`'s rSP is scored a WRITE, not a read-write.  The SDM defines LEAVE as
  `rSP <- rBP; POP rBP` — the incoming rSP is discarded, never read — and
  iced-x86, a third decoder that is neither instrument, agrees.

A correction is only worth as much as the control that shows it mattered.
Rebuilding the pintool with both corrections REMOVED and re-pairing the same
tracer stream (`item45/uncorrected/`) puts the whole class back:

| register-SET disagreement | reference UNCORRECTED | reference CORRECTED |
| --- | ---: | ---: |
| `endbr64` `ref_only=rdi,rdx` TRACER-SUBSET | 197 | **0** |
| `leave` `ref_only=rsp` TRACER-SUBSET | 19 | **0** |
| `rdsspq` `ref_only=rax,rcx` UNACCOUNTED | 1 | **0** |
| `rdsspq` dst `tracer_only=rax` TRACER-SUPERSET | 1 | **0** |
| `xgetbv` `xcr0`→`sys` ORTHOGONAL (a vocabulary fold) | 1 | 1 |
| src-set mismatched, all causes | 218 | **1** |
| the criterion, `SUBSET + UNACCOUNTED` | 518 | **301** |

Every removed row is the reference's defect, and every one of them scored the
tracer as DROPPING a register it is right not to name.  On the corrected
reference the register-SET axis has exactly one disagreeing row left, and it
is an ORTHOGONAL vocabulary fold rather than information the tracer lacks:
`SUBSET 0`, `SUPERSET 0`, `UNACCOUNTED 0` over 395,854 pairs.  The residual
301 is entirely on the VALUE axes.

## What the register arm measures today

396,044 byte-identical instruction pairs of a static, non-PIE x86_64 guest,
both halves run under one minimal environment.  Every number below is read
off `cmp_reg.py`, not asserted.

| axis | probed | agreeing | SUPERSET | ORTHOGONAL | SUBSET | UNACCOUNTED |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| src register set | 396,044 | 396,043 | 0 | 1 | **0** | **0** |
| dst register set | 396,044 | 396,044 | 0 | 0 | **0** | **0** |
| dst register VALUE | 567,217 | 549,464 | — | 17,576 | 26 | 151 |
| src register VALUE | 492,221 | 490,162 | — | 1,952 | 0 | 107 |
| rip as a source | 46,634 | 46,632 | — | 0 | 0 | 2 |

"agreeing" is exact plus same-pointer-under-an-ESTABLISHED-delta.  A
further 258 destination reads are `REP-DEFERRED-WRITE` / ORTHOGONAL: the
reference emits one record per REP iteration and the wire publishes the
write once, on the entry that completes it.

The one ORTHOGONAL set row is `xgetbv`: the reference names `XCR0`, the
tracer names `REG_SYS`, which is the generic role XCR0 belongs to.  It is
listed in `VOCAB_FOLD` so the fold is visible rather than silently equated.

The 26 SUBSET rows are one named defect, and it is **upstream QEMU's**, not
the plugin's.  `SYSCALL` sets `RCX <- RIP-of-next` and `R11 <- RFLAGS`.
QEMU's linux-user `helper_syscall`
(`target/i386/tcg/user/seg_helper.c:29`) raises `EXCP_SYSCALL` and never
performs that clobber, so the two registers the ISA says the instruction
produces keep whatever they held.  The tracer names them correctly and
publishes the value QEMU has.  Fix path: perform the architectural clobber
in the user-mode helper as the system-mode one does.  Not done here: it
changes guest-visible architectural state and would invalidate banked
golden traces.

The 260 UNACCOUNTED value rows (0.025% of 1.06M probed) are one shape and
its closure: a pointer whose page carries several distinct PIN-QEMU deltas
at once — the vDSO/vvar data page, and one stack page — so no single delta
is established for it, and every value later computed from it is
unexplained too.  The measurement that would close them is a finer domain
than a page: the two runs' mappings paired by their own contents rather
than by address.
