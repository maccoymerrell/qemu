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

EXPOSED
  * destination register writes -- bank, index and full value, for the
    integer file (``x``), the FP file (``f``), the vector file (``v``) and
    the CSRs (``c<num>_<name>``).  ``log_reg_write`` is keyed on the
    written register, so the log is destination-oriented by construction.
  * memory READ address.  ``mmu.cc:313`` pushes ``(addr, 0, len)``.
  * memory WRITE address, data AND width.  ``mmu.cc:406`` pushes
    ``(addr, data, size)`` and the printer emits the value at ``size << 3``
    bits, so the width is recoverable from the hex digit count.
  * the privilege level the instruction retired at.

NOT EXPOSED -- and therefore never claimed by this harness
  * REGISTER READS.  Spike keeps no ``log_reg_read``.  There is no source
    operand information in the commit log at all.  The read axis is a
    reference-gap on the execution leg; it stays with the static (Sail)
    leg, and no result on this leg may be quoted as covering it.
  * LOAD DATA.  The tuple ``mmu.cc:313`` pushes carries a literal ``0`` in
    the data slot and the printer prints only ``std::get<0>``.  Load data
    is therefore uncomparable here even though the tracer records it --
    which is a one-sided surplus, not a disagreement.
  * LOAD WIDTH.  ``len`` is in the tuple and is never printed.
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

#: a register write: ``x5  0x…``, ``f0  0x…``, ``v3 0x…``, ``c768_mstatus 0x…``
_REGW = re.compile(r'(?P<name>(?:[xfv]\s*\d+|c\d+_\S+))\s+0x(?P<val>[0-9a-f]+)')

#: the vector shape header spike interleaves before the first vector write
_VSHAPE = re.compile(r'\be\d+\s+m(?:f)?\d+\s+l\d+\b')


class Insn(object):
    """One retired instruction, as the execution reference saw it."""

    __slots__ = ('pc', 'bits', 'nbytes', 'priv', 'writes', 'loads', 'stores')

    def __init__(self, pc, bits, nbytes, priv):
        self.pc = pc
        self.bits = bits
        self.nbytes = nbytes
        self.priv = priv
        self.writes = []      # [(spike_name, value)]
        self.loads = []       # [addr]                 -- no data, no width
        self.stores = []      # [(addr, data, width_bytes)]

    def __repr__(self):
        return 'Insn(pc=0x%x bits=0x%x w=%r ld=%r st=%r)' % (
            self.pc, self.bits, self.writes, self.loads, self.stores)


def _parse_mem(rest):
    """The ``mem`` groups.  One value -> a load; two -> a store.

    The arity is what separates the two, so no assumption about the order in
    which spike emits loads and stores is needed (it emits loads first, but
    relying on that would be relying on something the log does not state).
    """
    loads, stores = [], []
    parts = rest.split('mem')
    for chunk in parts[1:]:
        vals = re.findall(r'0x([0-9a-f]+)', chunk)
        if not vals:
            continue
        if len(vals) == 1:
            loads.append(int(vals[0], 16))
        else:
            addr = int(vals[0], 16)
            # width is recoverable: the printer emits the datum at
            # (size << 3) bits, i.e. 2 hex digits per byte.
            stores.append((addr, int(vals[1], 16), len(vals[1]) // 2))
    return loads, stores


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
            rest = m.group('rest')
            reg_part = rest.split('mem', 1)[0]
            reg_part = _VSHAPE.sub(' ', reg_part)
            for rm in _REGW.finditer(reg_part):
                ins.writes.append((rm.group('name').replace(' ', ''),
                                   int(rm.group('val'), 16)))
            ins.loads, ins.stores = _parse_mem(rest)
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
