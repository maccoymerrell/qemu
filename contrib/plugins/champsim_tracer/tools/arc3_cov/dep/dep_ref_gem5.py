"""
gem5 as the INTRA-INSTRUCTION DEPENDENCY reference.

WHY GEM5 IS THE ONLY REFERENCE THAT CAN CONVICT THIS MAP
=======================================================
The dependency map is being moved off Capstone and onto QEMU's own emitters
(``DEPMAP_DESIGN.md``).  Checking a QEMU-derived map against QEMU proves
nothing, and the two static references this arc already has cannot reach the
question at all: Capstone states ARCHITECTURAL OPERANDS, and a static decoder
has no notion of which operand feeds which result.

gem5 does.  It cracks a macro-op into micro-ops each carrying an explicit
``srcRegIdx``/``destRegIdx`` list, and its O3 model RENAMES over exactly those
lists -- which IS the R7 regfile-dependency semantics, at intra-instruction
granularity.  The patched ``ExeTracer`` prints both lists per micro-op as
``SR=[cls:idx,...]`` and ``DR=[...]`` (``arc3_cov/gem5/gem5.patch``), so the
reference here is read off gem5's own operand declaration rather than
recovered from disassembly text.

THE CLOSURE, AND WHY IT IS NOT A UNION
======================================
A macro-op's micro-ops are chained through registers the guest architecture
does not have.  Taking the union of every micro-op's ``SR`` would therefore
report gem5's SCRATCH REGISTERS as architectural sources, and -- worse -- an
architectural register that a macro-op WRITES in one micro-op and READS BACK
in a later one would be reported as an external source of the whole
instruction when it is nothing of the kind.

So provenance is propagated instead: each micro-op's destinations inherit the
architectural provenance of its sources, a register is an EXTERNAL source only
at its FIRST read (before any micro-op of the same macro-op has written it),
and the answer for a destination is the architectural set that reaches it.
That is the same relation the tracer's masks state, which is what makes the
two comparable.

THE SCOPE GUARD IS PART OF THE REFERENCE, NOT A CAVEAT ON IT
===========================================================
gem5's micro-op decomposition is gem5's IMPLEMENTATION CHOICE.  The number of
micro-ops is not an architectural fact and is never scored -- it is the same
class as the aarch64 memop-count bucket this arc resolved by scoring bytes
instead of counts.  What IS scored is the relation the decomposition induces
between architectural registers, because renaming makes that relation
observable and the O3 model depends on it being right.

WHAT THIS REFERENCE CANNOT SAY, STATED SO IT IS NEVER SCORED AS DISAGREEMENT
===========================================================================
* **It cannot separate a load's ADDRESS from its DATA.**  ``lw r8, 0(r16)``
  is one micro-op with ``SR=[integer:16]`` and ``DR=[integer:8]``; gem5 says
  r16 feeds r8 and has no way to say that it does so as an address rather
  than as a datum.  The tracer states both facts separately.  Comparison is
  therefore made on the tracer's CLOSURE -- the load slot resolved back
  through its address mask -- and the finer statement is accounted
  ``REF-CANNOT-SEPARATE-ADDR-FROM-DATA``, which is a NAMED rule and not a
  blanket superset excuse.
* **It states no intra-micro-op structure.**  Within one micro-op every
  source is a source of every destination.  A tracer map that is FINER inside
  a single micro-op cannot be convicted here, and is reported rather than
  scored.
* **R7.1: a narrow write does NOT acquire a preserve-read.**  Where gem5
  names the merged-into register on a partial write, the row is
  REFERENCE-side over-naming, exactly as XED's was.

Author: Maccoy Merrell.
"""
import os
import re
import sys

_GEM5_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'gem5')
if _GEM5_DIR not in sys.path:
    sys.path.insert(0, _GEM5_DIR)
import gem5_ref                                                 # noqa: E402

INTERNAL = gem5_ref.INTERNAL

#: THE LINE GRAMMAR IS NOT RESTATED HERE.
#:
#: gem5's trace line grows and shrinks with the debug flags -- ``ExecThread``
#: inserts a ``T0 :`` column, ``ExecOpClass`` an ``: IntAlu :`` one -- so a
#: second pattern written against one flag set silently matches NOTHING under
#: another.  Measured: a private copy of this regex, written against a log
#: taken without ``ExecThread``, parsed zero lines from the canonical run and
#: reported every axis INERT while the reference was sitting there complete.
#: Both readers therefore share ``gem5_ref``'s pattern, whose groups are
#: (thread, pc, micro-pc, rest).
_LINE = gem5_ref._LINE
_DR = gem5_ref._DR
_SR = gem5_ref._SR
_FL = gem5_ref._FL


# --------------------------------------------------------------- riscv64
#
# The generic vocabulary is NOT invented here.  It is the one
# ``riscv64/spike/spike_ref.to_generic`` already publishes, so that the two
# riscv64 references cannot disagree about which architectural register a
# given index is -- a disagreement there would show up as a tracer defect on
# whichever reference was scored second.
_RV_ROLE = {0: 'REG_ZERO', 1: 'REG_LR', 2: 'REG_SP', 8: 'REG_FP_REG'}

#: gem5 RISCV int_reg: x0..x31 are 0..31, ``_Ureg0Idx == NumArchRegs == 32``
#: is micro-op scratch (``src/arch/riscv/regs/int.hh``).  Vector: 32 standard
#: registers then ``NumVecInternalRegs == 8`` used by vector uops
#: (``src/arch/riscv/regs/vector.hh``).
_RV_INT_ARCH = 32
_RV_VEC_ARCH = 32


def _riscv_reg(cls, idx):
    if cls == 'integer':
        if idx < _RV_INT_ARCH:
            return _RV_ROLE.get(idx, 'REG_GPR%d' % idx)
        return INTERNAL                      # _Ureg0Idx and above: uop scratch
    if cls == 'floating_point':
        if idx < 32:
            return 'REG_FPR%d' % idx
        return INTERNAL
    if cls == 'vector':
        if idx < _RV_VEC_ARCH:
            return 'REG_VEC%d' % idx
        return INTERNAL                      # vector uop scratch
    if cls == 'invalid':
        return INTERNAL
    if cls == 'miscellaneous':
        return 'MISC:%d' % idx
    return None


#: Registered rather than transcribed into ``gem5_ref`` so the two modules
#: cannot drift, and ``setdefault`` so that a later ``gem5_ref`` entry of its
#: own wins over this one instead of being shadowed by it.
gem5_ref.REGMAP.setdefault('riscv64', _riscv_reg)


class Insn(object):
    """One architectural instruction's dependency relation, as gem5 states it."""

    __slots__ = ('pc', 'uops', 'disas', 'dst_closure', 'ext_srcs',
                 'arch_dsts', 'unmapped', 'internal_seen', 'ctrl')

    def __init__(self, pc):
        self.pc = pc
        self.uops = 0
        self.disas = ''
        self.dst_closure = {}   # REG_* -> set(REG_*) reaching it
        self.ext_srcs = set()   # REG_* read from outside the instruction
        self.arch_dsts = []     # REG_* written, in first-write order
        self.unmapped = []      # gem5 tokens no vocabulary rule reaches
        self.internal_seen = 0  # scratch/internal operand sightings
        self.ctrl = False

    def __repr__(self):
        return 'g5dep(pc=0x%x uops=%d dst=%r src=%r)' % (
            self.pc, self.uops, self.dst_closure, self.ext_srcs)


def _toks(field):
    return [t.strip() for t in field.split(',') if t.strip()]


def parse(logpath, isa, ranges=None, gem5_dir=None):
    """``([Insn], notes)`` -- one record per architectural instruction.

    ``ranges`` bounds the stream to the guest's executable segments, the same
    way the execution leg does; without it gem5's SE-mode preamble would be
    scored against a tracer stream that never contained it.
    """
    mapper = gem5_ref.REGMAP.get(isa)
    if mapper is None:
        raise RuntimeError(
            'no gem5 register vocabulary for %s.  Add one to '
            'gem5_ref.REGMAP (or to dep_ref_gem5) rather than scoring every '
            'register as unmapped, which would read as agreement.' % isa)
    if isa == 'aarch64':
        if gem5_dir is None:
            raise RuntimeError('aarch64 needs gem5_dir to read miscRegName')
        gem5_ref.load_misc_names(gem5_dir)

    out = []
    notes = []
    unmapped_total = {}
    cur = None
    prev_upc = None
    prov = {}          # gem5 token -> set(REG_*) provenance, per macro-op

    def finish():
        pass

    for line in open(logpath, 'r', errors='replace'):
        m = _LINE.match(line)
        if not m:
            continue
        pc = int(m.group(2), 16)
        upc = int(m.group(3)) if m.group(3) is not None else None
        rest = m.group(4)
        if ranges is not None and not any(lo <= pc < hi for lo, hi in ranges):
            continue

        # A new architectural instruction starts when the line carries no
        # micro-PC, or when the micro-PC is not one more than the previous --
        # which is what a loop back onto the same PC looks like, and is why
        # the PC alone cannot delimit them.
        new = (cur is None or cur.pc != pc or upc is None or
               prev_upc is None or upc != prev_upc + 1)
        if new:
            cur = Insn(pc)
            out.append(cur)
            prov = {}
        prev_upc = upc
        cur.uops += 1
        if not cur.disas:
            cur.disas = rest.split(' : ')[0].strip()
        f = _FL.search(rest)
        if f and 'IsControl' in f.group(1).split('|'):
            cur.ctrl = True

        msr = _SR.search(rest)
        mdr = _DR.search(rest)
        src_toks = _toks(msr.group(1)) if msr else []
        dst_toks = _toks(mdr.group(1)) if mdr else []

        def generic(tok):
            cls, _, idx = tok.rpartition(':')
            try:
                return mapper(cls, int(idx))
            except ValueError:
                return None

        # ---- provenance in
        insrc = set()
        for t in src_toks:
            g = generic(t)
            if g is None:
                cur.unmapped.append(t)
                unmapped_total[t] = unmapped_total.get(t, 0) + 1
                continue
            if g is INTERNAL:
                cur.internal_seen += 1
                insrc |= prov.get(t, set())
                continue
            if t in prov:
                # produced by an earlier micro-op of THIS instruction, so it
                # is an internal carrier here and NOT an external source
                insrc |= prov[t]
            else:
                insrc.add(g)
                cur.ext_srcs.add(g)

        # ---- provenance out
        for t in dst_toks:
            g = generic(t)
            if g is None:
                cur.unmapped.append(t)
                unmapped_total[t] = unmapped_total.get(t, 0) + 1
                continue
            prov[t] = set(insrc)
            if g is INTERNAL:
                cur.internal_seen += 1
                continue
            if g not in cur.arch_dsts:
                cur.arch_dsts.append(g)
            cur.dst_closure[g] = set(insrc)

    finish()
    if unmapped_total:
        notes.append('gem5 operands no vocabulary rule reaches (COUNTED, '
                     'never folded into agreement): %s'
                     % ', '.join('%s x%d' % (k, v) for k, v in
                                 sorted(unmapped_total.items())))
    return out, notes
