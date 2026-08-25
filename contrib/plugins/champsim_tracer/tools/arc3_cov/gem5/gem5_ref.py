"""
The reference side of the aarch64 / mipsel EXECUTION cross-check: gem5's own
``Exec`` debug trace, parsed back into per-instruction records with the same
shape ``tracer_log.Insn`` has.

WHY gem5 AND WHAT MAKES IT INDEPENDENT
--------------------------------------
gem5 decodes the guest ISA with its own decoder and executes it with its own
semantics; no part of QEMU is involved.  That is the property the aarch64 and
mipsel legs were missing: every earlier number on those two ISAs came either
from a static decoder (Arm's MRA, binutils, LLVM MC), which cannot supply an
address or a value, or from ``irdf``, which compares the tracer against QEMU's
own TCG translation and is therefore QEMU-internal.

WHAT THE STOCK TRACE DOES AND DOES NOT CARRY
--------------------------------------------
Stock ``--debug-flags=Exec`` prints, per micro-op, the PC, the disassembly, the
OpClass, ``D=`` (the value the micro-op produced) and ``A=`` (its effective
address).  Three things a 1-to-1 comparison needs are missing from it, and this
harness's gem5 is patched to add them (``gem5.patch`` beside this file):

  ``S=`` / ``MF=``   the access WIDTH and the request flags.  Without a width,
                     an address comparison cannot say whether the two tools
                     agree about how many bytes moved.
  ``DR=`` / ``SR=``  the architectural registers the micro-op writes and reads,
                     as class:index, so the destination set does not have to be
                     recovered from disassembly text.
  direction          bits 62/63/61 of ``MF=``, set at gem5's ``readMem`` /
                     ``writeMem`` / ``amoMem`` call sites.  The OpClass alone
                     cannot carry this: a read-modify-write micro-op has ONE
                     OpClass and performs BOTH halves, so classifying by
                     OpClass would drop one of them silently.

and one more: for a STORE, gem5 leaves ``D=`` unset, because the trace record's
data field is written by the destination-register write and a store has no
destination register.  The patch publishes the stored bytes there.

MICRO-OPS
---------
gem5 cracks ``ldp``, ``ld2``/``ld3``/``ld4``, ``stp`` and the rest into
micro-ops, one line each, with a per-micro-op effective address.  The tracer's
record is per ARCHITECTURAL instruction, so the micro-ops of one macro-op are
folded back together here.  Folding, rather than comparing per micro-op, is
deliberate: the question the aarch64 memop rows ask is how many accesses the
INSTRUCTION makes and where, and gem5's cracking is an answer to that question,
not a different question.

Author: Maccoy Merrell.
"""
import os
import re
import struct
import sys

# ``  <tick>: system.cpu: T0 : 0x4000b0[.  1] :   <disasm> : <OpClass> : ...``
_LINE = re.compile(
    r'^\s*\d+:\s+\S+:\s+(?:A\d+\s+)?(?:T(\d+)\s+:\s+)?'
    r'0x([0-9a-f]+)(?:\.\s*(\d+))?\s+:\s+(.*)$')

_D = re.compile(r'\sD=(0x[0-9a-fA-F]+|\S+)')
_A = re.compile(r'\sA=0x([0-9a-f]+)')
_S = re.compile(r'\sS=(\d+)')
_MF = re.compile(r'\sMF=0x([0-9a-f]+)')
_DR = re.compile(r'\sDR=\[([^\]]*)\]')
_FL = re.compile(r'\sflags=\(([^)]*)\)')
_RW = re.compile(r'\sRW=\[([^\]]*)\]')
_MD = re.compile(r'\sMD=0x([0-9a-f]+)')
_SR = re.compile(r'\sSR=\[([^\]]*)\]')

#: the three direction bits the patched gem5 sets on the request flags.
ARC3_READ = 0x4000000000000000
ARC3_WRITE = 0x8000000000000000
ARC3_AMO = 0x2000000000000000


class Insn(object):
    """One executed architectural instruction as gem5 recorded it."""

    #: ``length`` / ``rflags`` / ``rflags_mask`` / ``preserve_reads`` /
    #: ``syscall`` are filled by the x86_64 arm only.  gem5 prints no encoding
    #: and holds no RFLAGS register, so on a variable-length ISA the reference
    #: states a LENGTH (checked, not aligned on) and a RECONSTRUCTED flags word
    #: with a mask naming which bits it spoke about.  They are declared here,
    #: rather than in a subclass, so that one comparator reads one record type.
    __slots__ = ('pc', 'bits', 'nbytes', 'writes', 'loads', 'stores',
                 'uops', 'disas', 'srcs', 'unmapped', 'ctrl',
                 'length', 'rflags', 'rflags_mask', 'preserve_reads',
                 'syscall')

    def __init__(self, pc, bits, nbytes):
        self.pc = pc
        self.bits = bits
        self.nbytes = nbytes
        self.writes = []      # [(generic id, value, width_bytes)]
        self.srcs = []        # [(generic id)]
        self.loads = []       # [(addr, data, width_bytes)]
        self.stores = []      # [(addr, data, width_bytes)]
        self.uops = 0
        self.disas = ''
        self.unmapped = []    # gem5 reg ids no vocabulary rule reaches
        self.ctrl = False     # gem5 calls this a control transfer
        self.length = None    # x86_64 only: the length gem5 states, or None
        self.rflags = None    # x86_64 only: the reconstructed flags word
        self.rflags_mask = 0  # x86_64 only: which bits gem5 spoke about
        self.preserve_reads = set()   # x86_64 only: R7.1 preserve reads
        self.syscall = False

    def __repr__(self):
        return 'g5Insn(pc=0x%x uops=%d w=%r ld=%r st=%r)' % (
            self.pc, self.uops, self.writes, self.loads, self.stores)


# --------------------------------------------------------------- vocabulary
#
# gem5 names a register as class:index.  The tracer names it as a
# GenericRegId.  The mapping below is per ISA and is DELIBERATELY PARTIAL: an
# index no rule reaches is recorded on the instruction as `unmapped` and
# reported, never dropped and never folded into agreement.  A silent drop on
# the reference side is the failure mode that let a whole CSR population read
# as agreement on the riscv64 leg before it was caught.

# gem5 ArmISA int_reg enum (src/arch/arm/regs/int.hh).  R0..R15 occupy 0..15,
# the AArch32 banked registers 16..33, then Zero, Ureg0..2, Sp0..3 and Spx.
# AArch64 aliases X0..X30 onto 0..30, which is why 27..33 have two names.
_ARM_ZERO = 34
_ARM_UREG = (35, 36, 37)
_ARM_SP = (38, 39, 40, 41, 42)
_ARM_NUM_VEC_ELEM = 64          # MaxSveVecLenInBits(2048) / 32
_ARM_ARCH_VEC = 32              # NumVecV8ArchRegs

#: REGISTERS THAT ARE NOT ARCHITECTURAL STATE.
#
#  gem5 cracks macro-ops through registers the guest architecture does not
#  have -- micro-op scratch (Ureg0..2), the vector special/interleave file
#  above V31, and the exclusive-monitor and event bookkeeping it keeps in the
#  misc file.  A guest cannot name any of them, so the tracer correctly has no
#  id for them and their absence is not a dropped write.
#
#  They are dropped ON THE REFERENCE SIDE, where they come from, and every
#  drop is COUNTED: a named exclusion that stops matching anything is a
#  justification nobody can check (the riscv64 leg was caught by exactly that
#  before `NONARCH_DROPPED` was added there).
INTERNAL = 'INTERNAL'

_ARM_MISC_INTERNAL = frozenset((
    'lockaddr', 'lockflag', 'sev_mailbox', 'tlbi_needsync',
    'unknown', 'impldef_unimpl',
))

#: misc-register name -> GenericRegId.  Prefix rules, longest first.
_ARM_MISC_RULES = (
    ('nzcv', 'REG_FLAGS'), ('cpsr', 'REG_FLAGS'), ('spsr', 'REG_FLAGS'),
    ('daif', 'REG_FLAGS'), ('pan', 'REG_FLAGS'), ('uao', 'REG_FLAGS'),
    ('fpcr', 'REG_FCSR'), ('fpsr', 'REG_FCSR'), ('fpscr', 'REG_FCSR'),
    ('fpexc', 'REG_FCSR'),
    ('cpacr', 'REG_SYSFPEN'), ('cptr', 'REG_SYSFPEN'),
    ('tpidrro_el0', 'REG_TLS'), ('tpidr_el0', 'REG_TLS'),
    ('cntvct', 'REG_SYSTIMER'), ('cntpct', 'REG_SYSTIMER'),
    ('cntfrq', 'REG_SYSTIMER'), ('cntkctl', 'REG_SYSTIMER'),
    ('cntv', 'REG_SYSTIMER'), ('cntp', 'REG_SYSTIMER'),
    ('ctr_el0', 'REG_SYSID'), ('dczid', 'REG_SYSID'), ('midr', 'REG_SYSID'),
    ('mpidr', 'REG_SYSID'), ('revidr', 'REG_SYSID'), ('id_', 'REG_SYSID'),
    ('aidr', 'REG_SYSID'), ('ccsidr', 'REG_SYSID'), ('clidr', 'REG_SYSID'),
    ('csselr', 'REG_SYSCACHE'),
    ('esr', 'REG_SYSEXC'), ('far', 'REG_SYSEXC'), ('elr', 'REG_SYSEXC'),
    ('ttbr', 'REG_SYSMMU'), ('tcr', 'REG_SYSMMU'), ('mair', 'REG_SYSMMU'),
    ('pmc', 'REG_SYSPERF'), ('pmu', 'REG_SYSPERF'),
    ('dbg', 'REG_SYSDBG'), ('mdscr', 'REG_SYSDBG'),
)

#: filled by ``load_misc_names``; index -> gem5's own name for the register.
_ARM_MISC_NAMES = []

#: index -> name LEARNED from gem5's own disassembly of an `mrs`/`msr`.
#  The transcribed `miscRegName[]` table is not trustworthy on its own: read
#  out of the header it resolves index 819 to `icv_iar0_el1`, while gem5's
#  disassembly of the instruction that writes index 819 reads
#  `msr tpidr_el0, x3`.  Some of that array's entries are not plain string
#  literals, so a positional read of it drifts partway down.  Rather than
#  trust either source, every `mrs`/`msr` line teaches the map its own answer,
#  the taught answer WINS, and a disagreement with the table is COUNTED and
#  reported -- a silent wrong name would put a register in the wrong tracer
#  family and read as agreement.
_ARM_MISC_LEARNED = {}
_ARM_MISC_CONFLICTS = {}

_MRS = re.compile(r'^\s*mrs\s+\S+,\s*([A-Za-z0-9_]+)')
_MSR = re.compile(r'^\s*msr\s+([A-Za-z0-9_]+),')


def load_misc_names(gem5_dir):
    """Read gem5's ARM misc-register name table out of its own source.

    Derived rather than transcribed: a hand-copied table of a thousand names
    is a table that drifts silently at the next gem5 bump, and a misc index
    resolved to the WRONG name would put a register in the wrong tracer family
    and read as agreement.
    """
    del _ARM_MISC_NAMES[:]
    path = os.path.join(gem5_dir, 'src/arch/arm/regs/misc.hh')
    src = open(path).read()
    i = src.index('const char * const miscRegName[] = {')
    j = src.index('};', i)
    _ARM_MISC_NAMES.extend(re.findall(r'"([^"]*)"', src[i:j]))
    if not _ARM_MISC_NAMES:
        raise RuntimeError('miscRegName table empty in %s' % path)
    return len(_ARM_MISC_NAMES)


def _arm_misc(idx):
    if not _ARM_MISC_NAMES:
        return None
    if idx >= len(_ARM_MISC_NAMES):
        return None
    name = _ARM_MISC_LEARNED.get(idx) or _ARM_MISC_NAMES[idx]
    if name in _ARM_MISC_INTERNAL:
        return INTERNAL
    for pre, gid in _ARM_MISC_RULES:
        if name.startswith(pre):
            return gid
    # No rule reaches it.  Returned under gem5's own name so the row it
    # produces is a NAMED disagreement, never a silent agreement.
    return 'MISC:' + name


def _arm_reg(cls, idx):
    if cls == 'integer':
        if 0 <= idx <= 28:
            return 'REG_GPR%d' % idx
        if idx == 29:
            return 'REG_FP_REG'
        if idx == 30:
            return 'REG_LR'
        if idx == _ARM_ZERO:
            return 'REG_ZERO'
        if idx in _ARM_SP:
            return 'REG_SP'
        if idx in _ARM_UREG:
            return INTERNAL
        return None
    if cls == 'vector':
        return 'REG_VEC%d' % idx if 0 <= idx < _ARM_ARCH_VEC else INTERNAL
    if cls == 'vector_element':
        v = idx // _ARM_NUM_VEC_ELEM
        return 'REG_VEC%d' % v if v < _ARM_ARCH_VEC else INTERNAL
    if cls == 'vector_predicate':
        return 'REG_PRED%d' % idx if 0 <= idx < 32 else INTERNAL
    if cls == 'condition_code':
        # gem5 splits AArch64's NZCV into nz / c / v (and keeps ge, fp, sat
        # for AArch32).  The tracer names the whole word REG_FLAGS, so the
        # three fold onto one id -- a granularity difference recorded here
        # rather than left to look like a disagreement.
        return 'REG_FLAGS'
    if cls == 'miscellaneous':
        return _arm_misc(idx)
    if cls == 'invalid':
        return INTERNAL
    return None


# gem5 MipsISA: 32 int regs, 32 float regs; HI/LO live in the misc file.
_MIPS_MISC_RULES = (
    ('hi', 'REG_ACC0'), ('lo', 'REG_ACC1'),
    ('fcsr', 'REG_FCSR'), ('fir', 'REG_SYSID'), ('fccr', 'REG_FCSR'),
    ('fexr', 'REG_FCSR'), ('fenr', 'REG_FCSR'),
    ('llflag', INTERNAL), ('lladdr', INTERNAL),
)


# gem5 MipsISA int_reg (src/arch/mips/regs/int.hh): the architectural file is
# 0..31, then the DSP accumulator pairs, of which pair 0 IS the classic
# HI/LO -- `Lo = DspLo0 = intRegClass[32]`, `Hi = DspHi0 = intRegClass[33]`.
# The tracer names LO REG_ACC0 and HI REG_ACCHI0 (MIPS_REG_AC0 expands to the
# pair; MIPS_REG_HI0 -> REG_ACCHI0).
_MIPS_ACC = {32: 'REG_ACC0', 33: 'REG_ACCHI0',
             34: 'REG_ACC1', 35: 'REG_ACCHI1',
             36: 'REG_ACC2', 37: 'REG_ACCHI2',
             38: 'REG_ACC3', 39: 'REG_ACCHI3'}


def _mips_reg(cls, idx):
    if cls == 'integer':
        if idx == 0:
            return 'REG_ZERO'
        # The tracer gives MIPS $29/$30/$31 their role names, as it does on
        # aarch64 (champsim_tracer_mnemonics_mips.h).
        if idx == 29:
            return 'REG_SP'
        if idx == 30:
            return 'REG_FP_REG'
        if idx == 31:
            return 'REG_LR'
        if 1 <= idx < 32:
            return 'REG_GPR%d' % idx
        return _MIPS_ACC.get(idx)
    if cls == 'floating_point':
        if 0 <= idx < 32:
            return 'REG_FPR%d' % idx
        # gem5 MipsISA float_reg (src/arch/mips/regs/float.hh): the FP control
        # registers live above the architectural file -- _FirIdx == 32 (a
        # read-only implementation identification word) and _FcsrIdx == 36.
        if idx == 32:
            return 'REG_SYSID'
        if idx == 36:
            return 'REG_FCSR'
        return None
    if cls == 'invalid':
        return INTERNAL
    if cls == 'miscellaneous':
        return 'MISC:%d' % idx
    return None


#: The x86_64 vocabulary is NOT transcribed a second time here.  It lives in
#: ``wp/x86_vocab.py``, where the wrong-path leg also uses it, and a single
#: table is the only way the two legs cannot drift apart on which gem5 index
#: is which architectural register.  The wrapper exists because ``REGMAP`` is
#: the correct-path comparator's own prerequisite gate: an ISA absent from it
#: is REFUSED by name rather than scored with every register unmapped.
_WP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wp')
if _WP_DIR not in sys.path:
    sys.path.insert(0, _WP_DIR)
import x86_vocab as _x86v                                       # noqa: E402


def _x86_reg(cls, idx):
    return _x86v.to_generic(cls, idx)


REGMAP = {'aarch64': _arm_reg, 'mipsel': _mips_reg, 'x86_64': _x86_reg}


def exec_ranges(path):
    """Executable PT_LOAD ranges of an ELF, 32- or 64-bit little-endian."""
    with open(path, 'rb') as fh:
        data = fh.read()
    assert data[:4] == b'\x7fELF' and data[5] == 1, path
    is64 = data[4] == 2
    if is64:
        e_phoff, = struct.unpack_from('<Q', data, 0x20)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    else:
        e_phoff, = struct.unpack_from('<I', data, 0x1c)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x2a)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags = struct.unpack_from('<II', data, off)
            p_vaddr, = struct.unpack_from('<Q', data, off + 0x10)
            p_memsz, = struct.unpack_from('<Q', data, off + 0x28)
        else:
            p_type, = struct.unpack_from('<I', data, off)
            p_vaddr, = struct.unpack_from('<I', data, off + 0x08)
            p_memsz, = struct.unpack_from('<I', data, off + 0x14)
            p_flags, = struct.unpack_from('<I', data, off + 0x18)
        if p_type == 1 and (p_flags & 1):
            out.append((p_vaddr, p_vaddr + p_memsz))
    assert out, 'no executable PT_LOAD in %s' % path
    return out


def text_bytes(path):
    """{vaddr: 4 encoding bytes} over every executable PT_LOAD.

    The encoding is the alignment key, and gem5's log does not print it, so it
    is read from the file both simulators were handed.  Both ISAs on this leg
    are fixed-width 4-byte, which is why a flat map is enough.
    """
    with open(path, 'rb') as fh:
        data = fh.read()
    is64 = data[4] == 2
    if is64:
        e_phoff, = struct.unpack_from('<Q', data, 0x20)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    else:
        e_phoff, = struct.unpack_from('<I', data, 0x1c)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x2a)
    out = {}
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags = struct.unpack_from('<II', data, off)
            p_off, = struct.unpack_from('<Q', data, off + 0x08)
            p_vaddr, = struct.unpack_from('<Q', data, off + 0x10)
            p_filesz, = struct.unpack_from('<Q', data, off + 0x20)
        else:
            p_type, = struct.unpack_from('<I', data, off)
            p_off, = struct.unpack_from('<I', data, off + 0x04)
            p_vaddr, = struct.unpack_from('<I', data, off + 0x08)
            p_filesz, = struct.unpack_from('<I', data, off + 0x10)
            p_flags, = struct.unpack_from('<I', data, off + 0x18)
        if p_type != 1 or not (p_flags & 1):
            continue
        for a in range(p_vaddr, p_vaddr + p_filesz - 3, 4):
            o = p_off + (a - p_vaddr)
            out[a] = int.from_bytes(data[o:o + 4], 'little')
    return out


def _regs(field, mapper, sink, internal):
    out = []
    for tok in field.split(','):
        tok = tok.strip()
        if not tok:
            continue
        cls, _, idx = tok.rpartition(':')
        try:
            g = mapper(cls, int(idx))
        except ValueError:
            g = None
        if g is None:
            sink.append(tok)
        elif g is INTERNAL:
            internal[tok] = internal.get(tok, 0) + 1
        else:
            out.append(g)
    return out


def parse(logpath, elfpath, isa, gem5_dir=None, dropped=None, notes=None):
    """(gem5 exec log, the guest ELF, isa) -> [Insn] in execution order.

    Micro-ops are folded onto their macro-op.  A new architectural instruction
    starts when the line has no micro-PC, or when its micro-PC is not one more
    than the previous line's -- which is what a loop back to the same PC looks
    like, and is why the PC alone cannot delimit them.

    x86_64 is dispatched to ``gem5_x86_cp``, which adapts the WRONG-PATH leg's
    x86 reader rather than repeating it.  The five decisions that reader had to
    make -- the x87 stack through ``X87Top``, XMM as two halves, RFLAGS
    reconstruction, merge-read suppression and contiguous-access folding -- are
    the same on both paths, and a second implementation would be a second place
    for them to drift.  The import is local so the two modules can refer to
    each other without a cycle.
    """
    if isa == 'x86_64':
        import gem5_x86_cp
        return gem5_x86_cp.parse(logpath, elfpath, dropped=dropped,
                                 notes=notes)
    mapper = REGMAP[isa]
    if dropped is None:
        dropped = {}
    if isa == 'aarch64' and not _ARM_MISC_NAMES:
        if gem5_dir is None:
            raise RuntimeError('aarch64 needs gem5_dir to read miscRegName')
        load_misc_names(gem5_dir)
    code = text_bytes(elfpath)
    ranges = exec_ranges(elfpath)
    out = []
    cur = None
    prev_upc = None
    for line in open(logpath, 'r', errors='replace'):
        m = _LINE.match(line)
        if not m:
            continue
        pc = int(m.group(2), 16)
        upc = int(m.group(3)) if m.group(3) is not None else None
        rest = m.group(4)
        if not any(lo <= pc < hi for lo, hi in ranges):
            continue
        new = (cur is None or cur.pc != pc or upc is None or
               prev_upc is None or upc != prev_upc + 1)
        if new:
            cur = Insn(pc, code.get(pc, 0), 4)
            out.append(cur)
        prev_upc = upc
        cur.uops += 1
        cur.disas = rest.split(' : ')[0].strip() if not cur.disas else cur.disas

        mfl0 = _FL.search(rest)
        if mfl0 and 'IsControl' in mfl0.group(1).split('|'):
            cur.ctrl = True

        # ---- teach the misc map from gem5's own disassembly
        if isa == 'aarch64':
            dis = rest.split(' : ')[0]
            mm = _MRS.match(dis) or _MSR.match(dis)
            if mm:
                idxs = set()
                for pat in (_RW, _DR, _SR):
                    f = pat.search(rest)
                    if f:
                        for tok in f.group(1).split(','):
                            lhs = tok.strip().split('=')[0]
                            if lhs.startswith('miscellaneous:'):
                                idxs.add(int(lhs.split(':')[1]))
                # cpsr is a source of every system access; the register the
                # instruction NAMES is the other one, and only an unambiguous
                # single candidate teaches anything.
                idxs.discard(0)
                if len(idxs) == 1:
                    k = idxs.pop()
                    nm = mm.group(1).lower()
                    old = _ARM_MISC_NAMES[k] if k < len(_ARM_MISC_NAMES) \
                        else None
                    if old is not None and old != nm:
                        _ARM_MISC_CONFLICTS[k] = (old, nm)
                    _ARM_MISC_LEARNED[k] = nm

        # ---- destinations, with their values.
        #
        # RW= is the patched sidecar: EVERY destination the micro-op wrote,
        # each with its own value.  D= is gem5's stock single data word, whose
        # owner is whichever destination happened to write last -- pairing it
        # with a register is a guess, and a guess here reads as a tracer
        # defect.  RW= removes the guess; D= is not used for values at all.
        vals = []
        mrw = _RW.search(rest)
        if mrw:
            for tok in mrw.group(1).split(','):
                tok = tok.strip()
                if not tok:
                    continue
                lhs, _, rhs = tok.rpartition('=')
                cls, _, idx = lhs.rpartition(':')
                try:
                    g = mapper(cls, int(idx))
                except ValueError:
                    g = None
                if g is None:
                    cur.unmapped.append(lhs)
                    continue
                if g is INTERNAL:
                    dropped[lhs] = dropped.get(lhs, 0) + 1
                    continue
                if rhs == '?':
                    vals.append((g, 0, 0))     # named, content not captured
                else:
                    vals.append((g, int(rhs, 16), 8))
            cur.writes.extend(vals)

        ma, ms, mf = _A.search(rest), _S.search(rest), _MF.search(rest)
        if ma:
            addr = int(ma.group(1), 16)
            size = int(ms.group(1)) if ms else 0
            fl = int(mf.group(1), 16) if mf else 0
            mmd = _MD.search(rest)
            # DIRECTION.  Taken from the StaticInst flags gem5 prints, not
            # from the OpClass: a read-modify-write micro-op carries ONE
            # OpClass and performs BOTH halves, so an OpClass reading would
            # drop one of them without saying so.  ``IsAtomic`` is tested
            # first for exactly that reason.
            mfl = _FL.search(rest)
            fset = set(mfl.group(1).split('|')) if mfl else set()
            # STORE data comes from MD=, the bytes the store actually moved.
            # LOAD data is reconstructed from the destination register, and
            # ONLY when one valued destination accounts for the whole access:
            # a wider or multi-destination load leaves the datum UNKNOWN
            # (None) rather than guessing which register holds which bytes.
            valued = [v for v in vals if v[2]]
            sdata = int(mmd.group(1), 16) if mmd else None
            ldata = valued[0][1] if (len(valued) == 1 and 0 < size <= 8) \
                else None
            if 'IsAtomic' in fset:
                cur.loads.append((addr, ldata, size))
                cur.stores.append((addr, sdata, size))
            elif 'IsStore' in fset:
                cur.stores.append((addr, sdata, size))
            elif 'IsLoad' in fset:
                cur.loads.append((addr, ldata, size))
            elif fl & ARC3_WRITE:
                cur.stores.append((addr, sdata, size))
            elif fl & (ARC3_READ | ARC3_AMO):
                cur.loads.append((addr, ldata, size))
            else:
                # Neither the instruction flags nor a direction bit: the
                # access is recorded with its direction UNKNOWN and counted,
                # never guessed at.
                cur.loads.append((addr, ldata, size))
                cur.unmapped.append('MEMDIR?')

        msr = _SR.search(rest)
        if msr:
            cur.srcs.extend(_regs(msr.group(1), mapper, cur.unmapped, dropped))
    return out
