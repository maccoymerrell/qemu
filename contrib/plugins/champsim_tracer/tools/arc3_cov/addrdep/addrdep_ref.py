"""
The REFERENCE side of the address-DEPENDENCY facet, for all four ISAs.

WHAT THE FACET IS, AND WHY IT IS NOT THE ADDRESS
------------------------------------------------
The memop-ADDRESS axis asks what number an access computed.  This one asks
WHICH REGISTERS it computed that number FROM -- the edges a consumer needs to
model address generation, to decide when a load's address is ready, and to
place an AGU dependency in a renaming machine.  The tracer publishes them
(``load_addr_dep_mask[]`` / ``store_addr_dep_mask[]``, the ``HAS_ADDR``
sub-block), and until this file existed no reference on any ISA had ever been
asked the question, so the published masks were unfalsified.

THE REFERENCES, AND WHY EACH IS INDEPENDENT
-------------------------------------------
``x86_64``   iced-x86.  ``InstructionInfoFactory.used_memory()`` enumerates
             every access the instruction makes -- explicit, and the implicit
             stack and string accesses too -- each with its base register,
             index register and DIRECTION.  A separate decoder from Capstone
             with a separate operand model, and it is the only one of the four
             that can also supply the load/store SPLIT.

the others   LLVM MC's own operand text, taken from the SAME ``isaxcheck
             --batch`` row that carries the tracer side, and parsed for the
             addressing syntax: ``[x1, x2, lsl #3]`` on AArch64, ``8(a1)`` on
             RISC-V, ``8($5)`` on MIPS.  LLVM is the ranked secondary
             reference on every ISA in this arc; here it is the primary,
             because Capstone -- which the tracer decodes with -- is not
             admissible as its own reference.

WHAT IS COMPARED, AND WHY IT IS THE UNION
-----------------------------------------
Per direction, the UNION of the address-dependency registers over every access
the instruction makes -- not slot for slot.  A reference is free to crack one
architectural access into a different number of operations than the tracer
records, and scoring slot against slot would measure that GRANULARITY rather
than the dependency.  It is the same resolution the memop-count bucket reached
by scoring BYTES.

VOCABULARY
----------
Every reference register name is translated through the tracer's OWN register
table, exactly as ``compare_attrib.py`` does, so a reference register with no
row in that table is reported UNMAPPED and never becomes a silent agreement.

Author: Maccoy Merrell.
"""
import os
import re

TREE = os.environ.get(
    'CST_TREE', '/mnt/md0/QEMU/qemu')
HDR = os.path.join(TREE, 'contrib/plugins/champsim_tracer')

#: isaxcheck's ISA spelling -> the header its register table lives in.
_HDR = {'x86_64': 'champsim_tracer_mnemonics_x86.h',
        'aarch64': 'champsim_tracer_mnemonics_aarch64.h',
        'riscv64': 'champsim_tracer_mnemonics_riscv.h',
        'mipsel': 'champsim_tracer_mnemonics_mips.h'}

_ROW = re.compile(r'\s+\[[A-Z0-9]+_REG_([A-Z0-9_]+)\]\s*=\s*\{\s*'
                  r'\.reg_id\s*=\s*(REG_[A-Z0-9_]+)'
                  r'(?:.*?\.name\s*=\s*"([^"]*)")?')


def tracer_vocab(isa):
    """(by Capstone spelling, by QEMU/ABI spelling) -> GenericRegId name.

    Both keys come from the tracer's own table: the enum spelling is what
    AArch64 and x86 disassembly prints, and ``.qemu_reg.name`` is the ABI
    spelling RISC-V and MIPS disassembly prints.  Reading them from the table
    rather than restating them here is what keeps the reference honest when
    the table moves -- a register that leaves the table stops resolving and
    is reported UNMAPPED, instead of quietly keeping an answer.
    """
    by_enum, by_abi = {}, {}
    path = os.path.join(HDR, _HDR[isa])
    for line in open(path):
        m = _ROW.match(line)
        if not m:
            continue
        by_enum.setdefault(m.group(1), m.group(2))
        if m.group(3):
            by_abi.setdefault(m.group(3), m.group(2))
    if not by_enum:
        raise SystemExit('addrdep_ref: no register rows parsed from %s -- the '
                         'table changed shape and this reference would score '
                         'every row UNMAPPED' % path)
    return by_enum, by_abi


# The architectural zero register is a dataflow no-op and the program counter
# travels through the branch taxonomy, not through a register edge.  Both are
# dropped on BOTH sides, for the same reasons isax_generic_reg_dropped() drops
# them from the register-set comparison; dropping on one side only would
# manufacture a disagreement out of a convention.
DROPPED = frozenset(('REG_ZERO', 'REG_PC'))


class Access(object):
    """One memory access, as the reference describes it."""
    __slots__ = ('regs', 'is_load', 'is_store', 'unmapped')

    def __init__(self, regs, is_load, is_store, unmapped=()):
        self.regs = frozenset(regs)
        self.is_load = is_load
        self.is_store = is_store
        self.unmapped = tuple(unmapped)


# ------------------------------------------------------------------- x86_64
def _iced():
    import sys
    for p in (os.environ.get('CST_ICED_PYLIB'),
              '/mnt/md0/QEMU/cst_runs/_arc3_refs/x86_64/pylib',
              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '..', 'x86_64', 'pylib')):
        if p and os.path.isdir(os.path.join(p, 'iced_x86')):
            if p not in sys.path:
                sys.path.insert(0, p)
            break
    import iced_x86
    return iced_x86


class X86Ref(object):
    """iced-x86.  The only one of the four that supplies the direction."""

    has_direction = True
    name = 'iced-x86'

    def __init__(self, isa):
        self.i = _iced()
        self.RN = {v: k for k, v in vars(self.i.Register).items()
                   if isinstance(v, int) and not k.startswith('_')}
        self.factory = self.i.InstructionInfoFactory()
        self.by_enum, self.by_abi = tracer_vocab(isa)
        A = self.i.OpAccess
        self.READS = (A.READ, A.COND_READ, A.READ_WRITE, A.READ_COND_WRITE,
                      A.NO_MEM_ACCESS + 1000)     # sentinel, never equal
        self.WRITES = (A.WRITE, A.COND_WRITE, A.READ_WRITE,
                       A.READ_COND_WRITE)
        self.READS = (A.READ, A.COND_READ, A.READ_WRITE, A.READ_COND_WRITE)

    def _map(self, reg, out, unmapped):
        """One reference register -> the tracer's vocabulary.

        The 64-bit flat segments (CS/DS/ES/SS) have an architecturally ZERO
        base, so naming them would be naming a register that contributes
        nothing to the address -- exactly the over-naming R7.1 struck down on
        the register-set axis.  FS and GS DO have a base and are kept.
        """
        n = self.RN.get(reg, '')
        if not n or n == 'NONE':
            return
        if n in ('CS', 'DS', 'ES', 'SS'):
            return
        g = self.by_enum.get(n) or self.by_abi.get(n.lower())
        if g is None:
            unmapped.append(n)
        elif g not in DROPPED:
            out.add(g)

    def accesses(self, hexs, l_text):
        b = bytes.fromhex(hexs)
        dec = self.i.Decoder(64, b, ip=0x100000)
        if not dec.can_decode:
            return None
        ins = dec.decode()
        if ins.is_invalid:
            return None
        out = []
        for m in self.factory.info(ins).used_memory():
            regs, unmapped = set(), []
            self._map(m.base, regs, unmapped)
            self._map(m.index, regs, unmapped)
            self._map(m.segment, regs, unmapped)
            out.append(Access(regs, m.access in self.READS,
                              m.access in self.WRITES, unmapped))
        return out


# ------------------------------------------- aarch64 / riscv64 / mipsel
#: AArch64: everything between the brackets that is a register.
#
# THE LOOKBEHIND IS LOad-BEARING.  AArch64 assembly uses brackets for three
# different things, and only one of them is an address: a memory operand
# (`ldr x0, [x1, x2]`), a vector ELEMENT index (`mov v0.d[1], x0`) and an SME
# tile SLICE (`mov { z8.b, z9.b }, za0v.b[w14, 6:7]`).  A memory bracket always
# follows a separator; the other two are glued to the register spelling they
# index.  Without this the SME slice register read as an address base and the
# aarch64 leg reported 323 TRACER-SUBSET rows against a reference that was
# naming a tile index -- reference-side over-naming of exactly the shape R7.1
# struck down elsewhere in this arc.
_A64_MEM = re.compile(r'(?<![A-Za-z0-9.])\[([^\]]*)\]')
_A64_REG = re.compile(r'\b([wx](?:[12]?[0-9]|3[01])|sp|wsp|[wx]zr|z(?:[12]?[0-9]|3[01]))\b')
#: RISC-V and MIPS spell it displacement(base) -- and MIPS also spells the
#: INDEXED forms register(base) (`lbux $4, $5($6)`, `ldxc1 $f4, $5($6)`),
#: where the first register is as much an address input as the second.
_DISP_BASE = re.compile(
    r'(?:(-?0x[0-9a-fA-F]+|-?\d+)|\$?([a-z][a-z0-9]*|\d+))?'
    r'\(\s*\$?([a-z0-9]+)\s*\)')


class TextRef(object):
    """LLVM MC's operand text, parsed for the addressing form.

    No direction: the text says WHERE the address comes from, not which way
    the bytes moved, and LLVM's ``mayLoad``/``mayStore`` are instruction-level
    over-approximations that must not be promoted into a per-access claim.
    The union axis is what this reference can answer, and it is the axis the
    facet is about.
    """

    has_direction = False
    name = 'LLVM MC operand text'

    def __init__(self, isa):
        self.isa = isa
        self.by_enum, self.by_abi = tracer_vocab(isa)

    def _resolve(self, tok, out, unmapped):
        t = tok.strip().lstrip('$')
        if not t:
            return
        g = None
        if self.isa == 'mipsel' and t.isdigit():
            # LLVM prints MIPS GPRs numerically.  The tracer's file is
            # REG_GPR0..31 by construction, and the table agrees (A1 -> GPR5,
            # T3 -> GPR11), so the index IS the vocabulary here.
            n = int(t)
            g = 'REG_GPR%d' % n if 0 <= n <= 31 else None
        if g is None:
            g = self.by_enum.get(t.upper()) or self.by_abi.get(t)
        if g is None and self.isa == 'aarch64':
            # `w3` and `x3` are the same architectural register at two
            # widths, and the tracer's table has a row for each; a width the
            # table happens not to carry still resolves through its twin.
            if re.fullmatch(r'[wx]\d+', t):
                g = self.by_enum.get('X' + t[1:])
            elif re.fullmatch(r'z\d+', t):
                g = 'REG_VEC' + t[1:]
        if g is None:
            unmapped.append(t)
        elif g not in DROPPED:
            out.add(g)

    def accesses(self, hexs, l_text):
        if not l_text or l_text in ('-', ''):
            return None
        regs, unmapped = set(), []
        found = False
        if self.isa == 'aarch64':
            for body in _A64_MEM.findall(l_text):
                found = True
                for tok in _A64_REG.findall(body):
                    self._resolve(tok, regs, unmapped)
        else:
            for disp, idx, base in _DISP_BASE.findall(l_text):
                found = True
                self._resolve(base, regs, unmapped)
                if idx:
                    self._resolve(idx, regs, unmapped)
        if not found:
            return []
        # Direction unknown: one access, claimed on neither side.  The scorer
        # compares the UNION for this reference and says so.
        return [Access(regs, False, False, unmapped)]


def build(isa):
    return X86Ref(isa) if isa == 'x86_64' else TextRef(isa)
