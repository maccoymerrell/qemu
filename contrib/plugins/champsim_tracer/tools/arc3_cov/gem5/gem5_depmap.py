"""
The INTRA-INSTRUCTION dependency reference, built out of gem5's micro-ops.

WHY THIS EXISTS AND WHY IT IS NOT THE SAME AS ``gem5_ref``
==========================================================
``gem5_ref`` folds a macro-op's micro-ops back together and answers SET
questions: which registers did this instruction write, which did it read, what
did it move to memory.  The dependency map answers a finer one -- which of the
instruction's inputs reaches which of its outputs -- and no set can express it.
An instruction reading {a, b} and writing {x, y} has four possible edges, and
the wire's ``dst_dep_mask`` / ``store_data_dep_mask`` / ``load_addr_dep_mask``
/ ``store_addr_dep_mask`` families state exactly which of them exist.

QEMU cannot be the reference for that claim.  CP-M and CP-H derive the map
from QEMU's own emitters, so scoring it against QEMU is scoring a thing
against itself.  gem5 can: it cracks a macro-op into micro-ops that each carry
an explicit ``srcRegIdx`` / ``destRegIdx`` list, and its O3 model RENAMES over
those lists -- which IS the R7 regfile-dependency semantics, at
intra-instruction granularity.  The cracking makes the edges observable:
``sub %ebx, 0x28(%r14)`` is three micro-ops, and the third one names its
stored datum as the second one's result and never as ``r14``.

HOW THE EDGES ARE RECOVERED
---------------------------
Per macro-op, in micro-op order, a PROVENANCE map is carried:

    prov[reg] = the set of MACRO-OP INPUTS whose values reach ``reg``

A register the macro-op has not yet written provenances to itself -- it is an
input.  A register an earlier micro-op wrote provenances to whatever fed that
micro-op, which is what threads an edge through gem5's scratch file
(``t1``/``ureg0``) without the scratch register ever appearing in the answer.
A loaded value provenances to the token ``LD``; the address registers that
produced it go to ``load_addr`` instead, never into the value's set.  That
separation is the single edge DEPMAP_DESIGN.md §5 names as the one a
ChampSim-class consumer most needs, and here it falls out of gem5's own
micro-op boundary rather than being re-derived.

WHAT IS DELIBERATELY NOT SCORED, AND WHY
----------------------------------------
* **micro-op COUNT.**  gem5's cracking is gem5's implementation choice, not
  architecture.  Nothing here compares how many micro-ops a macro-op has, and
  the load tokens are collapsed to one symbol so that ``ldp``'s two loads
  against the wire's one memop SLOT is not scored as disagreement (the same
  granularity class the aarch64 738-row memop-count bucket was resolved in).
* **R7.1 preserve-reads.**  gem5 reads back what a narrow write preserves;
  the maintainer ruled that a narrow write does NOT acquire a source.  Those
  self-sources are dropped HERE, on the reference side where they arise, and
  every drop is counted.
* **immediates.**  gem5 names no immediate operand in ``SR=``, so an
  immediate edge is not observable in this reference and the ``imm`` bit is
  removed from BOTH sides before scoring.  The count of masks that carried it
  is reported, so the blind spot has a size.
* **gem5's segment-base and micro-scratch registers**, per ``x86_vocab`` --
  they are modelling artefacts, not architectural state (R2).

Author: Maccoy Merrell.
"""
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import gem5_ref                                                 # noqa: E402

INTERNAL = gem5_ref.INTERNAL

#: the single token every loaded value provenances to.  ONE symbol, not one
#: per load: see the granularity note above.
LOAD_TOKEN = 'LD'

# ``  1000: system.cpu: T0 : 0x4000fc. 0 :   <rest>``
_LINE = re.compile(
    r'^\s*\d+:\s+\S+:\s+(?:A\d+\s+)?(?:T(\d+)\s+:\s+)?'
    r'0x([0-9a-f]+)(?:\.\s*(\d+))?\s+:\s+(.*)$')
_SR = re.compile(r'\sSR=\[([^\]]*)\]')
_DR = re.compile(r'\sDR=\[([^\]]*)\]')
_FL = re.compile(r'\sflags=\(([^)]*)\)')
_A = re.compile(r'\sA=0x([0-9a-f]+)')
_S = re.compile(r'\sS=(\d+)')


def _regs(text):
    """``integer:14,invalid:0`` -> [('integer', 14), ...], placeholders gone.

    ``invalid:0`` is gem5's unused-operand-slot filler; every x86 micro-op
    prints a fixed-width operand list, so dropping it here is not a decision
    about a register.
    """
    out = []
    for tok in text.split(','):
        tok = tok.strip()
        if not tok or ':' not in tok:
            continue
        cls, _, idx = tok.rpartition(':')
        if cls == 'invalid':
            continue
        try:
            out.append((cls, int(idx)))
        except ValueError:
            pass
    return out


class Uop(object):
    __slots__ = ('pc', 'idx', 'macro', 'disas', 'opclass', 'srcs', 'dsts',
                 'is_load', 'is_store', 'is_amo', 'addr', 'size', 'flags',
                 'srl', 'drl')


def _split_rest(rest):
    """``[MACRO : ]disas : OpClass :  <fields>`` -> (macro, disas, fields).

    Split on ``' : '`` so that x86's ``DS:[r14 + 0x28]`` -- a colon with no
    surrounding spaces -- cannot be mistaken for a field boundary.
    """
    parts = rest.split(' : ')
    if len(parts) >= 4:
        return parts[0].strip(), parts[1].strip(), parts[-1]
    if len(parts) == 3:
        return None, parts[0].strip(), parts[-1]
    return None, parts[0].strip(), parts[-1] if len(parts) > 1 else ''


def parse_uops(path):
    """gem5 ``exec.log`` -> [[Uop, ...], ...], one list per MACRO-op."""
    macros, cur = [], None
    prev_idx = None
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            m = _LINE.match(line)
            if not m:
                continue
            pc = int(m.group(2), 16)
            uidx = int(m.group(3)) if m.group(3) is not None else None
            macro, disas, fields = _split_rest(m.group(4))

            u = Uop()
            u.pc, u.idx, u.macro, u.disas = pc, uidx, macro, disas
            u.opclass = ''
            sr = _SR.search(fields)
            dr = _DR.search(fields)
            fl = _FL.search(fields)
            a = _A.search(fields)
            s = _S.search(fields)
            u.srcs = _regs(sr.group(1)) if sr else []
            u.dsts = _regs(dr.group(1)) if dr else []
            # The RAW, positional operand lists.  gem5 declares a PRESERVE
            # source in the SLOT of the destination it preserves, and the
            # register identity alone cannot tell that apart from a real
            # input: `inc r9` prints SR[2]=condition_code:1 against
            # DR[2]=condition_code:1 while `adc rdi` prints SR[3] against
            # DR[2].  Keeping the placeholders is what makes the slots line
            # up, so these lists are NOT filtered.
            u.srl = ([t.strip() for t in sr.group(1).split(',')]
                     if (sr and sr.group(1)) else [])
            u.drl = ([t.strip() for t in dr.group(1).split(',')]
                     if (dr and dr.group(1)) else [])
            u.flags = fl.group(1) if fl else ''
            u.addr = int(a.group(1), 16) if a else None
            u.size = int(s.group(1)) if s else None
            u.is_load = 'IsLoad' in u.flags
            u.is_store = 'IsStore' in u.flags
            u.is_amo = 'IsAtomic' in u.flags

            new_macro = (cur is None or uidx is None or uidx == 0
                         or prev_idx is None or uidx <= prev_idx
                         or pc != cur[0].pc)
            if new_macro:
                cur = [u]
                macros.append(cur)
            else:
                cur.append(u)
            prev_idx = uidx
    return macros


# ------------------------------------------------------- operand-text naming
#
# The address/data split of a STORE micro-op is taken from gem5's OWN
# DISASSEMBLY -- the registers inside the brackets are the address, the rest
# are the datum -- and never from the position of an operand in ``SR=``.
# Operand ORDER differs between the two targets measured here (aarch64 prints
# address-first, x86 prints index/base/data), so a positional rule would be an
# assumption that happens to hold on one ISA.  A store whose text cannot be
# split is counted AMBIGUOUS and scored on neither half.

_ARM_NAMES = {}
for _i in range(31):
    _ARM_NAMES[('integer', _i)] = {'x%d' % _i, 'w%d' % _i}
_ARM_NAMES[('integer', 34)] = {'xzr', 'wzr', 'zr'}
for _i, _n in ((35, 'ureg0'), (36, 'ureg1'), (37, 'ureg2')):
    _ARM_NAMES[('integer', _i)] = {_n}
for _i in (38, 39, 40, 41, 42):
    _ARM_NAMES[('integer', _i)] = {'sp', 'wsp'}
for _i in range(32):
    _ARM_NAMES[('vector', _i)] = set(
        '%s%d' % (p, _i) for p in 'vqdshbz')
    _ARM_NAMES[('vector_predicate', _i)] = {'p%d' % _i}
for _i in range(32 * 64):
    _ARM_NAMES.setdefault(('vector_element', _i),
                          set('%s%d' % (p, _i // 64) for p in 'vqdshbz'))

_WP = os.path.join(HERE, 'wp')
if _WP not in sys.path:
    sys.path.insert(0, _WP)
import x86_vocab as _x86v                                       # noqa: E402

_X86_NAMES = {}
for _i, _ns in _x86v.INT_NAMES.items():
    _X86_NAMES[('integer', _i)] = set(_ns)
for _i in range(16, 32):
    _t = 't%d' % (_i - 16)
    _X86_NAMES[('integer', _i)] = {_t, _t + 'd', _t + 'w', _t + 'b'}
for _i in range(8, 40):
    _v = (_i - 8) // 2
    _half = 'low' if (_i - 8) % 2 == 0 else 'high'
    _X86_NAMES[('floating_point', _i)] = {
        '%%xmm%d_%s' % (_v, _half), 'xmm%d_%s' % (_v, _half),
        '%%xmm%d' % _v, 'xmm%d' % _v}
# The micro-op FP scratch, the x87 stack and the MMX view of the same file.
# They are NOT architectural state -- ``x86_vocab`` maps 40..47 to INTERNAL --
# but the store split needs their SPELLING: an x87 store moves its datum out
# of ``%ufp1``, and without a name for it the datum has no operand text and
# the store-data axis silently reads EMPTY.  Measured: 4 FSTP rows.
for _i in range(40, 48):
    _X86_NAMES[('floating_point', _i)] = {'%%ufp%d' % (_i - 40),
                                          'ufp%d' % (_i - 40)}
for _i in range(48, 56):
    _X86_NAMES[('floating_point', _i)] = {'%%st(%d)' % (_i - 48),
                                          'st(%d)' % (_i - 48)}
for _i in range(0, 8):
    _X86_NAMES[('floating_point', _i)] = {'%%mmx%d' % _i, 'mmx%d' % _i,
                                          '%%st(%d)' % _i}

NAMES = {'aarch64': _ARM_NAMES, 'x86_64': _X86_NAMES}

_BRACKET = re.compile(r'\[([^\]]*)\]')
_WORD = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def _split_store(isa, u, srcs=None):
    """(address regs, data regs, ok) for one store micro-op.

    ``ok`` is False when gem5's text names a source in both halves or in
    neither; such a micro-op contributes to no store axis and is counted.
    """
    names = NAMES.get(isa)
    if names is None:
        return [], [], False
    brs = _BRACKET.findall(u.disas)
    if not brs:
        return [], [], False
    inside = set()
    for b in brs:
        inside.update(w.lower() for w in _WORD.findall(b))
    outside_txt = _BRACKET.sub(' ', u.disas)
    outside = set(w.lower() for w in _WORD.findall(outside_txt))

    addr, data, ok = [], [], True
    for s in (u.srcs if srcs is None else srcs):
        cand = names.get(s)
        if not cand:
            # A source with no spelling this table knows -- a segment base or
            # a misc register.  It is classified by its GENERIC mapping
            # instead: an INTERNAL one is a modelling artefact and belongs to
            # neither half.
            g = gem5_ref.REGMAP[isa](s[0], s[1])
            if g is INTERNAL:
                continue
            ok = False
            continue
        in_a = bool(cand & inside)
        in_d = bool(cand & outside)
        if in_a and not in_d:
            addr.append(s)
        elif in_d and not in_a:
            data.append(s)
        else:
            ok = False
    return addr, data, ok


_FIRST_OP = re.compile(r'^\s*\S+\s+([^,]*)')


def _full_written(isa, u):
    """The (cls, idx) this micro-op writes at FULL architectural width.

    A write is full when gem5's own destination text carries the register's
    widest spelling.  That text -- not the opcode, and not the register
    identity -- is the whole of the R7.1 adjudication: `movi r13b` is a
    narrow write whose self-read is a preserve, `mov r11, r11, r11` is a full
    one whose self-read is a real cmovcc source.

    On AArch64 there is no partial general-purpose or vector write to model: a
    `w`-form result zeroes bits 63:32 and an `s`/`d`-form vector result zeroes
    the rest of the register, so every architectural destination is written in
    full.  NZCV is the exception, and it is the exception on both targets:
    a packed field register has no full-width spelling at all.
    """
    m = _FIRST_OP.match(u.disas)
    first = m.group(1).strip().lower().lstrip('%') if m else ''
    out = set()
    for d in u.dsts:
        cls, i = d
        if cls == 'condition_code':
            continue
        if isa == 'x86_64':
            if cls == 'integer':
                full = _x86v.INT_FULL_NAME.get(i)
                if 16 <= i < 32:
                    full = 't%d' % (i - 16)
                if full is not None and first == full:
                    out.add(d)
            elif cls == 'floating_point':
                # An XMM half alone is partial; the tracer's id names the
                # whole register, so only the pair is a full write.  Both
                # halves of one register appearing in the same micro-op is
                # the only form this leg has observed, and it is checked
                # rather than assumed.
                if (cls, i ^ 1) in set(u.dsts):
                    out.add(d)
            else:
                out.add(d)
        else:
            out.add(d)
    return out


def _named_sources(isa, u):
    """The (cls, idx) the micro-op NAMES in its own source operand text.

    `adc rdi, rdi, rbx` names rdi and it is an architectural input;
    `mov2int rbx, %xmm3_low, 0` does not name rbx and its read is gem5's own
    merge.  The operand LISTS cannot make that distinction -- both print the
    register -- so it is taken from the disassembly.
    """
    _, _, after = u.disas.partition(',')
    after = after.lower()
    names = NAMES.get(isa) or {}
    out = set()
    for s in u.srcs:
        cand = names.get(s)
        if cand is None:
            # cc / misc registers carry no operand text at all, so the text
            # can never witness them; they are treated as NAMED and left to
            # the slot rule, which is the only evidence available for them.
            out.add(s)
            continue
        if any(re.search(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % re.escape(n),
                         after) for n in cand):
            out.add(s)
    return out


def _textless(isa, s):
    """True when gem5 prints no operand text for this register class at all.

    Condition codes and misc registers are carried in the operand LISTS only,
    so the disassembly can never witness them and the SLOT rule is the only
    evidence there is.  Every other class has a spelling, and for those the
    text is the evidence -- the slot rule is NOT applied to them, because on
    x86 a read-modify-write micro-op puts its real input in slot 0 against the
    same destination (`subi t1d, t1d, 0x1`) and the slot rule alone would read
    that genuine operand as a preserve.
    """
    return (NAMES.get(isa) or {}).get(s) is None


def _preserve_reads(isa, u):
    """R7.1: the sources this micro-op reads ONLY to preserve what it does not write.

    Verbatim ruling: "the fact that a register's upper contents may not be
    modified does not imply it is a source AND a destination for the
    instruction unless the instruction specifically takes it as a source."
    gem5 models the preserve at the hardware level and therefore names one.
    The drop happens HERE, on the reference side where it arises, and is
    counted; the tracer is never "fixed" toward gem5 on these.
    """
    written = set(u.dsts)
    if not written:
        return set()
    full = _full_written(isa, u)
    named = _named_sources(isa, u)
    same_slot = set()
    for slot, tok in enumerate(u.srl):
        if not tok or tok.startswith('invalid'):
            continue
        if slot < len(u.drl) and u.drl[slot] == tok:
            cls, _, idx = tok.rpartition(':')
            try:
                same_slot.add((cls, int(idx)))
            except ValueError:
                pass
    out = set()
    for s in u.srcs:
        if s not in written or s in full:
            continue
        if _textless(isa, s):
            if s in same_slot:
                out.add(s)
        elif s not in named:
            out.add(s)
    return out


class MacroDep(object):
    """The intra-instruction dependency map of ONE executed instruction."""

    __slots__ = ('pc', 'uops', 'dst_dep', 'load_addr', 'store_addr',
                 'store_data', 'srcs', 'dsts', 'notes', 'ambiguous_store',
                 'disas', 'macro')

    def __init__(self, pc):
        self.pc = pc
        self.uops = 0
        self.dst_dep = {}        # generic dst id -> set(token)
        self.load_addr = []      # [set(token)]
        self.store_addr = []
        self.store_data = []
        self.srcs = set()        # every macro-op input token named anywhere
        self.dsts = set()
        self.notes = collections.Counter()
        self.ambiguous_store = 0
        self.disas = ''
        self.macro = None

    def __repr__(self):
        return 'MacroDep(pc=0x%x dst=%r la=%r sd=%r)' % (
            self.pc, self.dst_dep, self.load_addr, self.store_data)


def build(isa, uops):
    """[Uop] of one macro-op -> MacroDep."""
    mapper = gem5_ref.REGMAP[isa]
    md = MacroDep(uops[0].pc)
    md.uops = len(uops)
    md.disas = ' ; '.join(u.disas for u in uops)
    md.macro = uops[0].macro
    prov = {}

    def resolve(regs):
        out = set()
        for s in regs:
            if s in prov:
                out |= prov[s]
                continue
            g = mapper(s[0], s[1])
            if g is INTERNAL:
                # A scratch register READ before this macro-op wrote it.  It
                # carries no architectural value; gem5's own micro-code
                # initialises it.  Counted, never folded into agreement.
                md.notes['scratch-read-undefined'] += 1
                continue
            if g is None:
                md.notes['unmapped-src'] += 1
                out.add('?%s:%d' % s)
                continue
            out.add(g)
            md.srcs.add(g)
        return out

    for u in uops:
        pres = _preserve_reads(isa, u)
        srcs = [s for s in u.srcs if s not in pres]
        if pres:
            md.notes['r7.1-preserve-read-dropped'] += len(pres)

        # An ATOMIC micro-op is BOTH halves and gem5 flags it neither IsLoad
        # nor IsStore: `swp64 x13, x12, [x21]` prints flags=(IsInteger|
        # IsAtomic) alone.  Treating it as a plain ALU op -- which is what
        # happens if only IsLoad/IsStore are consulted -- makes the ADDRESS
        # register a data source of the returned value and manufactures a
        # MISSING-EDGE against every LSE atomic.  Measured: 11 such rows
        # before this branch existed.
        is_ld = u.is_load or u.is_amo
        is_st = u.is_store or u.is_amo
        if is_st:
            a, d, ok = _split_store(isa, u, srcs)
            if u.is_amo:
                # THE REFERENCE REFUSES HERE.  gem5 performs the whole
                # read-modify-write inside ONE micro-op, so the datum it
                # writes back never appears as a separate source: `swp`'s
                # store data really is just its operand register, and
                # `ldadd`'s really is a function of the loaded value, and the
                # micro-op prints the SAME operand list for both.  An axis
                # that cannot tell those apart must refuse rather than
                # convict the trace on one of them.
                md.notes['amo-store-data-unobservable'] += 1
            if u.is_amo:
                # The returned old value's register is named in the operand
                # list as well as in DR; it is a DESTINATION, never the datum
                # the atomic writes.
                dset = set(u.dsts)
                d = [x for x in d if x not in dset]
            if ok and not u.is_amo:
                md.store_addr.append(resolve(a))
                md.store_data.append(resolve(d))
            elif ok:
                md.store_addr.append(resolve(a))
                resolve(d)
            else:
                md.ambiguous_store += 1
                md.notes['store-split-ambiguous'] += 1
                resolve(srcs)          # still counts the inputs as named
        if is_ld:
            md.load_addr.append(resolve(
                srcs if not is_st else _split_store(isa, u, srcs)[0]))
            for d in u.dsts:
                prov[d] = {LOAD_TOKEN}
        if not is_ld and not is_st:
            p = resolve(srcs)
            for d in u.dsts:
                prov[d] = set(p)

    # HALVES ARE ONE REGISTER.  gem5 models an XMM as two 64-bit halves and a
    # vector as 64 elements, and a macro-op can write them from different
    # sources in different micro-ops -- `punpckhqdq %xmm1, %xmm2` writes
    # xmm1_low from xmm1_high and xmm1_high from xmm2_high.  The tracer names
    # ONE register, so the architectural destination's set is the UNION over
    # every gem5 key that maps to it.  Taking the last writer instead reported
    # `punpckhqdq` as depending on xmm2 alone, and `movss xmm7, mem` as
    # depending on nothing at all.
    for key, p in prov.items():
        g = mapper(key[0], key[1])
        if g is INTERNAL or g is None:
            if g is None:
                md.notes['unmapped-dst'] += 1
            continue
        md.dsts.add(g)
        md.dst_dep.setdefault(g, set()).update(p)
    return md


def build_all(isa, path):
    """gem5 ``exec.log`` -> [MacroDep] in execution order."""
    return [build(isa, m) for m in parse_uops(path)]
