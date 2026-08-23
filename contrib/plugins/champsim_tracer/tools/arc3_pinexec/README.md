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
| `champsim_memop_pintool.cpp` | the pintool: per dynamic instruction, per memory operand — COUNT, ADDRESS, WIDTH and DATA |
| `Makefile` | builds it against the PIN kit (`make PIN_ROOT=...`) |
| `pinmemlib.py` | reader for the 392-byte reference record |
| `qextract_mem.py` | `cst_decode --format=disasm --objdump` → one JSON object per correct-path instruction, carrying memop values (`lv`/`sv`) as well as addresses and widths |
| `cmp_memop.py` | the cross-check: COUNT / ADDRESS / WIDTH / DATA, every disagreement carrying a CATEGORY and a DIRECTION |
| `memcheck_self.py` | store-to-load self-consistency of ONE stream, reference-free |
| `negative_control.py` | injects one named memop defect class, so a green result has to be earned |
| `adjudicate_x86.py` | settles a PIN/tracer register disagreement with a third decoder (iced-x86) |

The register arm of the same pairing is `pin_compare/tool_wide/` (the widened
ChampSim `input_instr`, 8 destination / 16 source registers) with
`pin_repair3/_work/compare.py`.  It carries memory operands only as a
de-duplicated effective address with no width and no value, which is why the
memop half needed a tool of its own.

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

**PIN's silence is not evidence.**  `INS_RegR` reports EXPLICIT operands
only, so a register PIN does not name is not a register we are wrong to
name.  Only PIN's POSITIVE evidence counts, and even that is adjudicated
against a third decoder rather than taken as an oracle — PIN's own decode is
XED with the CET operand unset, which mis-decodes `endbr64` as
`nop edx, edi` and `rdsspq` as a register-reading nop.  `adjudicate_x86.py`
is where that adjudication happens.

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
