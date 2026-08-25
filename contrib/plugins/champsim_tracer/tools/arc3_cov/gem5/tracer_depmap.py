"""
The TRACER side of the intra-instruction dependency comparison.

``cst_decode --show-deps`` renders, per executed instruction, exactly the map
the wire states -- and, where the wire states nothing, the DEFAULT a consumer
is required to assume.  That default is the format's own: ``docs/format.rst``,
"absence of ``CST_INSN_FLAG_HAS_DEP_BLOCK`` is the implicit all-to-all
over-approximation".  Reading the map through the decoder rather than out of
the wire is deliberate: what is being scored is what a CONSUMER SEES, which is
the union of the wire's claim and the format's default, and the decoder is the
one place that union is defined.

    deps: %flags=[%gp3,ld0] sdata0=[%gp3,ld0] | laddr0=[%gp12] saddr0=[%gp12]

Every operand is already a GenericRegId in the decoder's short spelling, which
is the same namespace ``gem5_ref`` maps gem5's ``class:index`` into, so the two
sides meet without a third vocabulary.

Author: Maccoy Merrell.
"""
import re

#: ``%gp13`` -> ``REG_GPR13``.  The inverse of ``regref_from_name`` in
#: ``cst_decode_main.cc``; the compressions there are the only ones here.
_PREFIX = (('%gp', 'REG_GPR'), ('%f', 'REG_FPR'), ('%v', 'REG_VEC'),
           ('%p', 'REG_PRED'), ('%b', 'REG_BOUND'), ('%m', 'REG_MATRIX_'))
_SPECIAL = {'%fpr': 'REG_FP_REG', '%vr': 'REG_VEC_REG',
            '%pr': 'REG_PRED_REG', '%mflags': 'REG_METAFLAGS'}


def regid(tok):
    """A decoder register reference -> its GenericRegId name.

    ``ld<N>`` and ``imm`` are returned verbatim; they are not registers and
    the caller decides what to do with them.
    """
    tok = tok.strip()
    if not tok:
        return None
    if tok in _SPECIAL:
        return _SPECIAL[tok]
    if not tok.startswith('%'):
        return tok
    for pre, full in _PREFIX:
        if tok.startswith(pre) and tok[len(pre):].isdigit():
            return full + tok[len(pre):]
    if tok.startswith('%m') and not tok[2:].isdigit():
        pass
    return 'REG_' + tok[1:].upper()


#: ``0x0000004000f8: 4b 85 40 f8   add ...`` and, on a binary with symbols,
#: ``0x000000401b6a <_start>: 48 89 e2   mov ...``.  The symbol column is
#: OPTIONAL and must be allowed for: without it every line of a real
#: workload's decode fails to match and the comparison silently scores 43
#: instructions instead of thousands.
_LINE = re.compile(
    r'^0x([0-9a-f]+)(?:\s+<[^>]*>)?:\s+((?:[0-9a-f]{2} )+)\s*(.*)$')
_DEPS = re.compile(r'deps:\s*(.*)$')
_TOK = re.compile(r'(\|)|([A-Za-z%][\w%()]*?)=\[([^\]]*)\]')


class Insn(object):
    __slots__ = ('pc', 'bits', 'dst_dep', 'store_data', 'load_addr',
                 'store_addr', 'order', 'text')

    def __init__(self, pc, bits):
        self.pc = pc
        self.bits = bits
        self.dst_dep = {}      # GenericRegId -> set(token)
        self.store_data = []   # [set(token)]
        self.load_addr = []
        self.store_addr = []
        self.order = []        # destination ids in wire order
        self.text = ''

    def __repr__(self):
        return 'trInsn(pc=0x%x dst=%r sd=%r la=%r)' % (
            self.pc, self.dst_dep, self.store_data, self.load_addr)


def iter_parse(lines):
    """Stream ``cst_decode --show-deps`` output, yielding one Insn per line.

    The streaming form exists because a whole-workload decode is tens of
    millions of lines: eager materialisation of a decode is a BUG in this
    tree, not a style choice.
    """
    for line in lines:
        if line.startswith(';') or not line.startswith('0x'):
            continue
        m = _LINE.match(line.rstrip('\n'))
        if not m:
            continue
        ins = Insn(int(m.group(1), 16),
                   bytes(int(b, 16) for b in m.group(2).split()))
        ins.text = m.group(3)
        d = _DEPS.search(m.group(3))
        if d:
            _parse_deps(ins, d.group(1))
        yield ins


def parse(path_or_lines):
    """``cst_decode --show-deps`` output -> [Insn] in execution order.

    Instructions whose line carries no ``deps:`` annotation are returned with
    empty maps AND recorded, never skipped: a line the decoder declined to
    annotate is a fact about coverage, and dropping it here would let the
    comparison report a denominator it never met.
    """
    if isinstance(path_or_lines, str):
        fh = open(path_or_lines, 'r', errors='replace')
        close = True
    else:
        fh, close = path_or_lines, False
    out = []
    try:
        for line in fh:
            if line.startswith(';') or not line.startswith('0x'):
                continue
            m = _LINE.match(line.rstrip('\n'))
            if not m:
                continue
            ins = Insn(int(m.group(1), 16),
                       bytes(int(b, 16) for b in m.group(2).split()))
            ins.text = m.group(3)
            d = _DEPS.search(m.group(3))
            if d:
                _parse_deps(ins, d.group(1))
            out.append(ins)
    finally:
        if close:
            fh.close()
    return out


#: the ONE symbol every loaded value collapses to.  gem5 cracks a paired load
#: into two micro-ops and the wire gives the whole instruction one memop SLOT
#: (format.rst 4.5), so keeping the slot NUMBER would score gem5's cracking --
#: an implementation choice -- as a dependency disagreement.
_LD = re.compile(r'^ld\d+$')


def _parse_deps(ins, text):
    for m in _TOK.finditer(text):
        if m.group(1):
            continue
        lhs, rhs = m.group(2), m.group(3)
        # The deps annotation is ONE item of the decoder's trailing comment
        # block and the items that follow it (`prof: ... cp=[...]`) share the
        # `key=[value]` spelling.  Parsing stops at the first key that is not
        # a dependency family, so a profile range can never be read as a
        # destination -- which it was, silently, before this line existed.
        if not (lhs.startswith('%') or lhs.startswith('sdata')
                or lhs.startswith('laddr') or lhs.startswith('saddr')):
            break
        vals = set()
        for t in rhs.split(','):
            t = t.strip()
            if not t:
                continue
            # A lane-annotated operand (`%v0{0..3}`) keeps only its register.
            t = t.split('{')[0]
            vals.add('LD' if _LD.match(t) else regid(t))
        if lhs.startswith('sdata'):
            ins.store_data.append(vals)
        elif lhs.startswith('laddr'):
            ins.load_addr.append(vals)
        elif lhs.startswith('saddr'):
            ins.store_addr.append(vals)
        else:
            g = regid(lhs.split('{')[0])
            ins.dst_dep[g] = vals
            ins.order.append(g)


#: Everything the tracer names as an input of the instruction, across every
#: family.  This is the set the common universe is intersected from.
def sources(ins):
    out = set()
    for v in ins.dst_dep.values():
        out |= v
    for v in ins.store_data + ins.load_addr + ins.store_addr:
        out |= v
    return out
