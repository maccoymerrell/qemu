"""
Spike (riscv-isa-sim) as the riscv64 EXECUTION reference for ARC 3.

Spike is an execution reference, not a decoder: every record below is a fact
about one retired instruction in one real run -- the value that landed in the
destination register, the address the memory operation went to, the bytes a
store wrote.  A static decoder can state which register an opcode *may* write;
only an execution reference states what it *did*.

WHAT THE COMMIT LOG EXPOSES, AND WHAT IT DOES NOT
=================================================
This is the whole contract, read off ``riscv/execute.cc``
(``commit_log_print_insn``) and ``riscv/mmu.cc`` rather than off the manual,
because the claim this harness is allowed to make is bounded by it.

THE REFERENCE IS PATCHED.  Upstream Spike's commit log is
destination-oriented and silent about sources, and its load records carry a
literal ``0`` where the datum should be.  That silence bounded three facets of
this leg to ``NONE``, and a reference gap is not a verdict, so the reference
was changed rather than excused.  The patch, the Spike revision it applies to
and the reasoning are in ``spike-patches/``.  ``require_patched()`` below
refuses a commit log produced by an unpatched binary, so a stale Spike reports
as an error instead of as three axes that quietly agree with nothing.

EXPOSED
  * destination register writes -- bank, index and full value, for the
    integer file (``x``), the FP file (``f``), the vector file (``v``) and
    the CSRs (``c<num>_<name>``).  ``log_reg_write`` is keyed on the
    written register, so the log is destination-oriented by construction.
  * SOURCE register reads -- bank, index and full value, for the same four
    banks, under the ``read`` token.  PATCHED IN: recorded at the decode
    site (``READ_REG``/``READ_FREG``), at ``vectorUnit_t::elt`` for the
    vector file, and at ``processor_t::get_csr`` for the CSR a ``csrr*``
    addressed.  ``x0`` IS reported: an x0 source is a real fact about the
    encoding, unlike an x0 destination.
  * memory READ address, data AND width, under the ``memr`` token.
    PATCHED IN: ``mmu.cc`` now records the bytes the load returned, and
    the printer emits the datum at ``size << 3`` bits so the width is
    recoverable from the hex digit count.
  * memory WRITE address, data AND width.  ``mmu.cc:406`` pushes
    ``(addr, data, size)`` and the printer emits the value at ``size << 3``
    bits, so the width is recoverable from the hex digit count.
  * the privilege level the instruction retired at.

NOT EXPOSED -- and therefore never claimed by this harness
  * IMPLICIT CSR reads.  An FP operation reads ``frm`` through the
    ``csr_t`` object rather than through ``get_csr``, and a vector
    operation reads ``vl``/``vtype`` off the vector unit.  Those are not
    operands and are deliberately not recorded; the CSR source axis
    therefore covers exactly the CSR a ``csrr*`` instruction addressed.
  * ANY INSTRUCTION THAT TRAPS.  ``execute_insn_logged`` calls the printer
    only when the instruction completes, so a trapping instruction leaves
    no commit line.  The alignment in ``compare_exec.py`` therefore admits
    deletions on the reference side and names each one.

A NOTE ON ``-l`` WITHOUT ``--log-commits``
  ``processor_t::disasm`` DEDUPLICATES: a repeat of the same (pc, bits)
  prints nothing and bumps a counter that is later summarised as
  "Executed N times".  Those lines are consequently NOT a 1-to-1 stream and
  are not parsed here.  Only the commit lines are 1-to-1.

Author: Maccoy Merrell.
"""
import re

#: ``core   0: <priv> 0x<pc> (0x<bits>)`` then the effect tokens.
_COMMIT = re.compile(
    r'^core\s+(?P<core>\d+):\s+(?P<priv>[0-3])\s+'
    r'0x(?P<pc>[0-9a-f]+)\s+\(0x(?P<bits>[0-9a-f]+)\)(?P<rest>.*)$')

#: one effect token pair: a register NAME then its value.  Kept as a name
#: test rather than a "everything that is not a section keyword" test, so a
#: new token added to the log upstream cannot be silently eaten as a register.
_REGNAME = re.compile(r'^(?:[xfv]\d+|c\d+_\S+)$')

#: the vector shape header spike interleaves before the first vector write:
#: ``e64 m1 l2`` / ``e8 mf2 l16``.  Not a register, and skipped as such.
_VSHAPE_TOK = re.compile(r'^(?:e\d+|mf?\d+|l\d+)$')

#: tokens that open a section of the effect list.  Everything before the first
#: one is the destination list; after it the role of each group is stated by
#: the token itself, never inferred from arity or from ordering.
_SECTIONS = ('read', 'memr', 'mem')


class Insn(object):
    """One retired instruction, as the execution reference saw it."""

    __slots__ = ('pc', 'bits', 'nbytes', 'priv', 'writes', 'reads',
                 'loads', 'stores')

    def __init__(self, pc, bits, nbytes, priv):
        self.pc = pc
        self.bits = bits
        self.nbytes = nbytes
        self.priv = priv
        self.writes = []      # [(spike_name, value)]
        self.reads = []       # [(spike_name, value)]   -- PATCHED IN
        self.loads = []       # [(addr, data, width_bytes)]
        self.stores = []      # [(addr, data, width_bytes)]

    def __repr__(self):
        return 'Insn(pc=0x%x bits=0x%x w=%r r=%r ld=%r st=%r)' % (
            self.pc, self.bits, self.writes, self.reads,
            self.loads, self.stores)


def _parse_effects(rest):
    """The effect list of one commit line -> (writes, reads, loads, stores).

    TOKEN-DIRECTED, not arity-directed.  Before the reference was patched a
    load printed one value and a store two, so the parser separated them by
    counting -- which stops being sound the moment a load carries its datum.
    Every group now states its own role (`read`, `memr`, `mem`), and the
    destination list is what precedes the first of those tokens.
    """
    toks = rest.split()
    writes, reads, loads, stores = [], [], [], []
    i, n = 0, len(toks)

    while i < n and toks[i] not in _SECTIONS:
        t = toks[i]
        if _REGNAME.match(t) and i + 1 < n and toks[i + 1].startswith('0x'):
            writes.append((t, int(toks[i + 1], 16)))
            i += 2
        else:
            # the vector shape header, or padding.  Anything else here is a
            # token this parser does not know; it is skipped, and the
            # `require_patched` gate plus the negative control are what keep
            # a silently-dropped effect from reading as agreement.
            i += 1

    while i < n:
        t = toks[i]
        if t == 'read' and i + 2 < n:
            reads.append((toks[i + 1], int(toks[i + 2], 16)))
            i += 3
        elif t in ('memr', 'mem') and i + 2 < n:
            addr, data = toks[i + 1], toks[i + 2]
            # the printer emits the datum at (size << 3) bits, i.e. 2 hex
            # digits per byte, so the width is recoverable from the length.
            rec = (int(addr, 16), int(data, 16), (len(data) - 2) // 2)
            (loads if t == 'memr' else stores).append(rec)
            i += 3
        else:
            i += 1
    return writes, reads, loads, stores


def require_patched(path, ninsns):
    """Refuse a commit log that an UNPATCHED spike produced.

    Three axes of this leg exist only because the reference was patched.  A
    stale binary would produce a log with no `read` and no `memr` token at
    all, and every one of those axes would then compare an empty reference
    against an empty tracer projection and report agreement -- the exact
    shape of check this project does not accept.  So it is an error, named.
    """
    if not ninsns:
        return
    with open(path, 'r', errors='replace') as fh:
        blob = fh.read()
    missing = [t for t in (' read ', ' memr ') if t not in blob]
    if missing:
        raise RuntimeError(
            'this commit log carries no %s token: the spike that produced it '
            'is not the patched one this leg requires (see spike-patches/'
            'README.md, revision 262df8bfac33b0419688429dd066487744db5c79)'
            % ' or '.join(t.strip() for t in missing))


def parse_commit_log(path, pc_lo=None, pc_hi=None, priv=None):
    """Commit log -> [Insn], in retirement order.

    ``pc_lo``/``pc_hi`` restrict to one address range (used to select the
    guest program out of a run that also executes the proxy kernel);
    ``priv`` restricts to one privilege level.  Both filters are applied to
    the same lines, so a mismatch between them is visible to the caller
    rather than silently reconciled.
    """
    out = []
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            m = _COMMIT.match(line)
            if m is None:
                continue                      # disasm / >>>> / exception lines
            pc = int(m.group('pc'), 16)
            if pc_lo is not None and not (pc_lo <= pc < pc_hi):
                continue
            p = int(m.group('priv'))
            if priv is not None and p != priv:
                continue
            bits_s = m.group('bits')
            ins = Insn(pc, int(bits_s, 16), len(bits_s) // 2, p)
            (ins.writes, ins.reads,
             ins.loads, ins.stores) = _parse_effects(m.group('rest'))
            out.append(ins)
    return out


# ------------------------------------------------------------------ vocabulary
#: spike's register spelling -> the tracer's GenericRegId spelling.
#: x0/x1/x2/x8 carry role names in the tracer's vocabulary; the rest are
#: positional.  Taken from champsim_tracer_mnemonics_riscv.h, not guessed.
_ROLE = {0: 'REG_ZERO', 1: 'REG_LR', 2: 'REG_SP', 8: 'REG_FP_REG'}

#: CSRs the tracer folds into a single generic id rather than naming one by
#: one.  Both directions of the fold are stated so a disagreement caused by
#: the fold is reported as vocabulary, never as a dropped write.
_CSR_FOLD = {
    'fflags': 'REG_FCSR', 'frm': 'REG_FCSR', 'fcsr': 'REG_FCSR',
    'vstart': 'REG_VCTRL', 'vxsat': 'REG_VCTRL', 'vxrm': 'REG_VCTRL',
    'vcsr': 'REG_VCTRL', 'vl': 'REG_VCTRL', 'vtype': 'REG_VCTRL',
    'vlenb': 'REG_VCTRL',
}


def to_generic(name):
    """Spike register spelling -> tracer spelling, or None when unmappable.

    None is a real answer: it means the execution reference names a register
    the tracer's vocabulary has no id for, which is a vocabulary-gap row, not
    a silently dropped one.
    """
    if name.startswith('c') and '_' in name:
        csr = name.split('_', 1)[1]
        return _CSR_FOLD.get(csr, 'CSR:' + csr)
    bank, idx = name[0], int(name[1:])
    if bank == 'x':
        return _ROLE.get(idx, 'REG_GPR%d' % idx)
    if bank == 'f':
        return 'REG_FPR%d' % idx
    if bank == 'v':
        return 'REG_VEC%d' % idx
    return None


#: ``core   0: exception trap_user_ecall, epc 0x…``  (processor.cc:406, printed
#: only when ``-l`` is on, which is why this harness always passes it).
_TRAP = re.compile(r'^core\s+\d+:\s+exception\s+(?P<name>\S+),\s+'
                   r'epc\s+0x(?P<epc>[0-9a-f]+)')


def parse_traps(path):
    """{epc: [trap name, ...]} -- the instructions that left no commit line.

    ``execute_insn_logged`` prints a commit line only when the instruction
    completes, so a trapping instruction is absent from the commit stream.
    Reading the trap lines lets that absence be PROVEN for a given PC instead
    of inferred from the fact that nothing lined up there.
    """
    out = {}
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            m = _TRAP.match(line)
            if m:
                out.setdefault(int(m.group('epc'), 16), []).append(
                    m.group('name'))
    return out


#: the tracer folds several architectural CSRs onto one GenericRegId.  The
#: fold is declared here in BOTH directions so a comparison can say "the id
#: cannot represent these two writes" instead of silently picking one.
FOLD_MEMBERS = {
    'REG_FCSR': ('fcsr', 'fflags', 'frm'),
    'REG_VCTRL': ('vstart', 'vxsat', 'vxrm', 'vcsr', 'vl', 'vtype', 'vlenb'),
}

#: tracer-side ids that are CSR state rather than an architectural register
#: file entry.  Kept apart from GPR/FPR/VEC so a vocabulary question about
#: CSRs can never dilute -- in either direction -- the register-file result.
CSR_IDS = frozenset(('REG_FCSR', 'REG_VCTRL', 'REG_FLAGS'))


def bank(name):
    """'x' | 'f' | 'v' | 'csr' for a spike register spelling."""
    if name.startswith('c') and '_' in name:
        return 'csr'
    return name[0]


def fcsr_field(csr, fcsr_value):
    """The part of a tracer REG_FCSR value that spike's `csr` names.

    fcsr is {frm[2:0], fflags[4:0]}, so a reference write to fflags is
    comparable against the low five bits and a write to frm against the next
    three.  Stated rather than assumed, because comparing a 5-bit field
    against a whole fcsr word would agree only while frm happened to be 0.
    """
    if csr == 'fflags':
        return fcsr_value & 0x1f
    if csr == 'frm':
        return (fcsr_value >> 5) & 0x7
    return fcsr_value


#: CSRs spike writes that the architecture the guest was built for does not
#: have.  `mtype` (0xC23) belongs to the matrix/Zvt extension spike carries at
#: this revision; `vectorUnit_t::set_vl` clears it as its own bookkeeping
#: (vector_unit.cc:148-152), so every vsetvl logs a write to it.  RVV 1.0
#: vsetvli writes vstart, vl and vtype and nothing else.  Naming these keeps a
#: reference artifact from being reported as a hole in the tracer.
NONARCH_CSRS = frozenset(('mtype',))
