"""
The x86_64 register vocabulary shared by the two sides of the wrong-path leg.

gem5 names a register as ``class:index``; the tracer names it as a
GenericRegId.  This module holds BOTH directions:

  ``to_generic``   gem5's ``class:index`` -> the tracer's GenericRegId, for
                   reading the reference.
  ``install``      a GenericRegId -> where it lives in an x86-64 machine, for
                   writing the reconstructed state back INTO a simulator.

Keeping them in one file is deliberate.  A one-way table drifts silently: the
riscv64 leg keeps its two directions adjacent for the same reason, and a
divergence between them shows up there as a register that can be read but not
installed.

WHAT IS NOT ARCHITECTURAL STATE, AND WHY IT IS DROPPED ON THE REFERENCE SIDE
===========================================================================
gem5 cracks x86 macro-ops through registers the guest architecture does not
have, and models pieces of the machine the architecture fixes:

* ``integer:16..31``    the micro-op scratch file (``t0``..``t15``).  gem5's
                        ``JNZ_I`` is three micro-ops that pass the branch
                        target through ``t1``/``t2``; no guest can name them.
* ``integer:32..37``    ``Prodlow``/``Prodhi``/``Quotient``/``Remainder``/
                        ``Divisor``/``Doublebits`` -- the multiply and divide
                        micro-op plumbing.
* ``floating_point:40..47``  the micro-op FP scratch file.
* ``invalid:*``         gem5's placeholder for an unused operand slot.  Every
                        x86 micro-op prints a fixed-width operand list, so
                        these appear in quantity.
* ``miscellaneous:139..142`` and ``152..155``  the ES/CS/SS/DS segment bases
                        and effective bases.  In 64-bit mode the processor
                        FORCES these to zero (SDM Vol.3 3.4.2.1) and gem5's
                        address micro-op adds the zero anyway, so it reads a
                        register on every single memory reference.  That is a
                        gem5 modelling artefact, not an architectural
                        dependency, and recording it would violate R2.
                        ``FsEffBase``/``GsEffBase`` are NOT dropped: FSBASE
                        and GSBASE are real 64-bit-mode architectural state
                        and the tracer names them REG_SEG3 / REG_SEG4.

Every drop is COUNTED and printed.  A named exclusion that stops matching is
a justification nobody can check.

Author: Maccoy Merrell.
"""

#: sentinel: a reference register that is not guest-architectural state.
INTERNAL = 'INTERNAL'

# --------------------------------------------------------------- gem5 -> tracer
#
# gem5's x86 integer file is in ENCODING order (src/arch/x86/regs/int.hh:
# _RaxIdx, _RcxIdx, _RdxIdx, _RbxIdx, _RspIdx, _RbpIdx, _RsiIdx, _RdiIdx,
# R8..R15).  The tracer's table (champsim_tracer_mnemonics_x86.h) gives RSP and
# RBP their ROLE ids and packs the remaining fourteen densely, so the two
# orders are NOT the same and a positional read of either would be wrong.
_INT = {
    0: 'REG_GPR0',    # rax
    1: 'REG_GPR1',    # rcx
    2: 'REG_GPR2',    # rdx
    3: 'REG_GPR3',    # rbx
    4: 'REG_SP',      # rsp
    5: 'REG_FP_REG',  # rbp
    6: 'REG_GPR4',    # rsi
    7: 'REG_GPR5',    # rdi
    8: 'REG_GPR6',    # r8
    9: 'REG_GPR7',    # r9
    10: 'REG_GPR8',   # r10
    11: 'REG_GPR9',   # r11
    12: 'REG_GPR10',  # r12
    13: 'REG_GPR11',  # r13
    14: 'REG_GPR12',  # r14
    15: 'REG_GPR13',  # r15
}

#: gem5 x86 misc register indices, resolved from src/arch/x86/regs/misc.hh by
#: evaluating the enum (the traits constants NumCRegs=16, NumDRegs=8,
#: NumSegments=6 and segment_idx::NumIdxs=13 come from x86_traits.hh and
#: segment.hh).  Transcribed here with the value beside the name so a gem5
#: bump that renumbers them is caught by ``verify_misc_map`` rather than
#: silently reading a register as the wrong one.
MISC = {
    0: 'Cr0', 2: 'Cr2', 3: 'Cr3', 4: 'Cr4', 8: 'Cr8',
    16: 'Dr0', 17: 'Dr1', 18: 'Dr2', 19: 'Dr3',
    22: 'Dr6', 23: 'Dr7',
    24: 'Rflags', 26: 'Tsc',
    126: 'Es', 127: 'Cs', 128: 'Ss', 129: 'Ds', 130: 'Fs', 131: 'Gs',
    139: 'EsBase', 140: 'CsBase', 141: 'SsBase', 142: 'DsBase',
    143: 'FsBase', 144: 'GsBase',
    152: 'EsEffBase', 153: 'CsEffBase', 154: 'SsEffBase', 155: 'DsEffBase',
    156: 'FsEffBase', 157: 'GsEffBase',
    191: 'X87Top', 192: 'Mxcsr', 193: 'Fcw', 194: 'Fsw', 195: 'Ftw',
    196: 'Ftag', 201: 'Fop', 204: 'Xcr0',
}

#: the ES/CS/SS/DS bases: zero by architecture in 64-bit mode.
_SEG_BASE_INTERNAL = frozenset((139, 140, 141, 142, 152, 153, 154, 155))

_MISC_TO_GENERIC = {
    # gem5's misc file opens with the control and debug registers; the tracer
    # gives each of those its own id (REG_CTRL0..15 / REG_DEBUG0..15) because
    # they are architecturally distinct registers with unrelated roles.
    24: 'REG_FLAGS',
    26: 'REG_SYSTIMER',
    126: 'REG_SEG2', 127: 'REG_SEG0', 128: 'REG_SEG5',
    129: 'REG_SEG1', 130: 'REG_SEG3', 131: 'REG_SEG4',
    143: 'REG_SEG3', 144: 'REG_SEG4',
    156: 'REG_SEG3', 157: 'REG_SEG4',
    # The tracer maps X86_REG_FPSW onto REG_FCSR; gem5 splits the x87 control
    # and status words, and MXCSR is a third register again.  All three are
    # FP mode-and-status state and the tracer has ONE id for that role.
    192: 'REG_FCSR', 193: 'REG_FCSR', 194: 'REG_FCSR', 195: 'REG_FCSR',
    196: 'REG_FCSR', 201: 'REG_FCSR',
    204: 'REG_SYSFPEN',
    # gem5 keeps the x87 stack pointer in a misc register.  It is
    # architectural state (the TOP field of the status word) and folds onto
    # the same id the tracer gives the status word.
    191: 'REG_FCSR',
}


def verify_misc_map(gem5_dir):
    """Re-derive the misc indices from gem5's own header; -> [(idx, ours, its)].

    A gem5 bump that inserts a register renumbers everything after it, and a
    misc index read as the WRONG name puts a register in the wrong tracer
    family -- which reads as agreement, not as an error.  The caller prints
    every mismatch and treats a non-empty list as a hard failure.
    """
    import os
    import re
    path = os.path.join(gem5_dir, 'src/arch/x86/regs/misc.hh')
    src = open(path).read().splitlines()
    body = []
    for k in range(110, len(src)):
        body.append(src[k])
        if src[k].strip().startswith('};'):
            break
    txt = '\n'.join(body)
    txt = re.sub(r'//.*', '', txt)
    txt = re.sub(r'/\*.*?\*/', '', txt, flags=re.S)
    txt = txt[txt.index('{') + 1:txt.rindex('}')]
    txt = txt.replace('segment_idx::NumIdxs', '13')
    env = {'NumCRegs': 16, 'NumDRegs': 8, 'NumSegments': 6,
           'NumMicroFpRegs': 8}
    val, seen = 0, {}
    for tok in txt.split(','):
        tok = tok.strip()
        if not tok:
            continue
        if '=' in tok:
            n, e = tok.split('=', 1)
            n = n.strip()
            val = eval(e.strip(), {}, dict(env))
        else:
            n = tok
        env[n] = val
        seen.setdefault(val, []).append(n)
        val += 1
    # An index can carry several names -- gem5 opens each region with an alias
    # (``SegSelBase, Es``), so the FIRST name at an index is often the region
    # marker rather than the register.  Membership, not position, is the test.
    bad = []
    for idx, name in sorted(MISC.items()):
        got = seen.get(idx)
        if not got or name not in got:
            bad.append((idx, name, got))
    return bad


#: gem5 x86 float file (src/arch/x86/regs/float.hh):
#:   0..7    MMX / x87 physical registers
#:   8..39   XMM, two 64-bit halves per register (Low = 8+2i, High = 9+2i)
#:   40..47  micro-op FP scratch
#:   48..55  the STACK-RELATIVE x87 operands st(0)..st(7).  gem5 prints the
#:           UNFLATTENED operand (``si->destRegIdx``), and its flatten rule
#:           (src/arch/x86/regs/float.cc) is
#:           ``fpr((X87Top + (idx - NumRegs)) % 8)``.  The tracer's REG_FPR<n>
#:           is stack-relative too -- Capstone's ST(n) -- so the two line up
#:           WITHOUT consulting TOP, and physical indices 0..7 are the MMX
#:           view of the same file, which the tracer also names REG_FPR<n>.
#:           Measured: ``fldt`` prints ``floating_point:55`` for ``%st(7)``.
_XMM_BASE = 8
_MICROFP_BASE = 40
_FP_NUMREGS = 48
_X87_STACK_BASE = _FP_NUMREGS


def to_generic(cls, idx):
    """gem5 ``class``/``index`` -> GenericRegId, ``INTERNAL``, or None.

    ``None`` means NO RULE REACHES IT.  The caller records the token verbatim
    and reports it; it is never folded into agreement and never dropped.
    """
    if cls == 'integer':
        if idx in _INT:
            return _INT[idx]
        if 16 <= idx <= 37:
            return INTERNAL             # micro scratch + mul/div plumbing
        return None
    if cls == 'condition_code':
        # gem5 splits the flags word into Zaps / Cfof / Df / Ecf / Ezf; the
        # tracer names the whole word REG_FLAGS.  Ecf and Ezf carry no
        # architectural bit at all -- they are microcode-only predicates --
        # but they are still part of the same word's machinery, so folding
        # them here keeps the SET axis honest and the VALUE axis is scored
        # from the reconstructed word (see ``rflags_from_cc``).
        return 'REG_FLAGS' if 0 <= idx <= 4 else None
    if cls == 'floating_point':
        if 0 <= idx < 8:
            return 'REG_FPR%d' % idx
        if _XMM_BASE <= idx < _MICROFP_BASE:
            return 'REG_VEC%d' % ((idx - _XMM_BASE) // 2)
        if _MICROFP_BASE <= idx < _FP_NUMREGS:
            return INTERNAL
        if _X87_STACK_BASE <= idx < _X87_STACK_BASE + 8:
            return 'REG_FPR%d' % (idx - _X87_STACK_BASE)
        return None
    if cls == 'miscellaneous':
        if idx in _SEG_BASE_INTERNAL:
            return INTERNAL
        if 0 <= idx <= 15:
            return 'REG_CTRL%d' % idx
        if 16 <= idx <= 23:
            # Dr4/Dr5 are not separate registers: with CR4.DE clear they alias
            # Dr6/Dr7, which is why the tracer folds them there too.
            return 'REG_DEBUG%d' % ({20: 6, 21: 7}.get(idx - 16, idx - 16))
        if idx in _MISC_TO_GENERIC:
            return _MISC_TO_GENERIC[idx]
        return 'MISC:%s' % MISC.get(idx, idx)
    if cls == 'invalid':
        return INTERNAL
    return None


def xmm_half(cls, idx):
    """(vector id, 0 for the low half / 1 for the high half), or None."""
    if cls != 'floating_point' or not (_XMM_BASE <= idx < _MICROFP_BASE):
        return None
    return ('REG_VEC%d' % ((idx - _XMM_BASE) // 2), (idx - _XMM_BASE) % 2)


# ------------------------------------------------------------------- RFLAGS
#
# gem5 holds no RFLAGS word: ``Zaps`` carries SF/ZF/AF/PF in their RFLAGS bit
# positions, ``Cfof`` carries CF/OF in theirs, and ``Df`` carries DF.  A word
# can therefore be REBUILT from the three, and comparing that word against the
# tracer's REG_FLAGS is a real value check rather than a skipped axis.  Only
# the bits gem5 actually models are compared; bit 1 is the architecturally
# fixed 1.
RFLAGS_CF = 1 << 0
RFLAGS_PF = 1 << 2
RFLAGS_AF = 1 << 4
RFLAGS_ZF = 1 << 6
RFLAGS_SF = 1 << 7
RFLAGS_DF = 1 << 10
RFLAGS_OF = 1 << 11

#: the bits this leg compares.  Everything else in the word (IF, IOPL, the
#: system bits) is not modelled by gem5's cc registers and is excluded by
#: MASK rather than by silence.
RFLAGS_MASK = (RFLAGS_CF | RFLAGS_PF | RFLAGS_AF | RFLAGS_ZF |
               RFLAGS_SF | RFLAGS_DF | RFLAGS_OF)


def rflags_from_cc(cc):
    """{gem5 cc index: value} -> the RFLAGS bits those registers state.

    Returns ``(word, mask)``: the mask names WHICH bits the reference spoke
    about, so a comparison never credits a bit gem5 did not write.
    """
    word = 0
    mask = 0
    if 0 in cc:                     # Zaps: SF ZF AF PF, in place
        word |= cc[0] & (RFLAGS_SF | RFLAGS_ZF | RFLAGS_AF | RFLAGS_PF)
        mask |= RFLAGS_SF | RFLAGS_ZF | RFLAGS_AF | RFLAGS_PF
    if 1 in cc:                     # Cfof: CF OF, in place
        word |= cc[1] & (RFLAGS_CF | RFLAGS_OF)
        mask |= RFLAGS_CF | RFLAGS_OF
    if 2 in cc:                     # Df: gem5 stores 1 or -1, not the bit
        word |= RFLAGS_DF if (cc[2] & 0xffffffffffffffff) != 1 else 0
        mask |= RFLAGS_DF
    return word, mask


# --------------------------------------------------------- tracer -> machine
#
# The install direction.  A GenericRegId the wire states has to be put back
# into a machine, and on x86 that is done with instructions (see
# ``wp_seed_x86``).  This says WHERE each id lives; the code generator says
# how to get a value there.

#: GenericRegId -> the AT&T name of the 64-bit integer register.
GPR_NAME = {
    'REG_GPR0': 'rax', 'REG_GPR1': 'rcx', 'REG_GPR2': 'rdx',
    'REG_GPR3': 'rbx', 'REG_SP': 'rsp', 'REG_FP_REG': 'rbp',
    'REG_GPR4': 'rsi', 'REG_GPR5': 'rdi', 'REG_GPR6': 'r8',
    'REG_GPR7': 'r9', 'REG_GPR8': 'r10', 'REG_GPR9': 'r11',
    'REG_GPR10': 'r12', 'REG_GPR11': 'r13', 'REG_GPR12': 'r14',
    'REG_GPR13': 'r15',
}

#: every integer register an x86-64 guest can name, in the order the prologue
#: writes them.  The scratch register is not here: it is written last, by
#: name, so that the exclusion is a property of the generator rather than of
#: how many instructions it happened to emit.
INSTALLABLE_GPR = [g for g in GPR_NAME if g != 'REG_GPR0']

#: the scratch the prologue uses for everything else, and therefore the LAST
#: register it writes.
SCRATCH = 'REG_GPR0'


def install_class(name):
    """Where a GenericRegId lives -> 'gpr'|'vec'|'x87'|'flags'|'fcsr'|None.

    ``None`` is the answer for an id this leg cannot put back into a machine
    from user code, and the caller NAMES every one of them as a seed gap
    rather than silently zeroing it.  A silent zero agrees with the reference
    on every register that happens to be zero and manufactures a pass.
    """
    if name in GPR_NAME:
        return 'gpr'
    if name.startswith('REG_VEC'):
        n = int(name[7:])
        return 'vec' if n < 16 else None
    if name.startswith('REG_FPR'):
        n = int(name[7:])
        return 'x87' if n < 8 else None
    if name == 'REG_FLAGS':
        return 'flags'
    if name == 'REG_FCSR':
        return 'fcsr'
    return None


# ------------------------------------------------- gem5 micro-op operand text
#
# gem5 prints each micro-op as ``<op>   <dst>, <src>, ...``.  The DESTINATION
# is the first operand in every form this leg has observed (``ld r9b, DS:[..]``,
# ``sexti r12, r12, 0xf``, ``movi r13b, r13b, 0x1``, ``mov2int rbx,
# %xmm3_low, 0``, ``addi r9, r9, 0x1``), and the WIDTH of that operand is what
# says whether the write is partial.  That distinction is the whole of the
# merge-read adjudication, so it is derived from gem5's own text rather than
# guessed from the opcode.

#: every spelling of each x86-64 integer register, by gem5 index, with the
#: FULL-WIDTH name first.  gem5 prints the AMD64 numbered registers with a
#: b/w/d suffix and the legacy eight with their historical names.
INT_NAMES = {
    0:  ('rax', 'eax', 'ax', 'al', 'ah'),
    1:  ('rcx', 'ecx', 'cx', 'cl', 'ch'),
    2:  ('rdx', 'edx', 'dx', 'dl', 'dh'),
    3:  ('rbx', 'ebx', 'bx', 'bl', 'bh'),
    4:  ('rsp', 'esp', 'sp', 'spl'),
    5:  ('rbp', 'ebp', 'bp', 'bpl'),
    6:  ('rsi', 'esi', 'si', 'sil'),
    7:  ('rdi', 'edi', 'di', 'dil'),
}
for _i in range(8, 16):
    INT_NAMES[_i] = ('r%d' % _i, 'r%dd' % _i, 'r%dw' % _i, 'r%db' % _i)

#: index -> the 64-bit spelling, the only one that is a FULL write.
INT_FULL_NAME = dict((i, n[0]) for i, n in INT_NAMES.items())

#: name -> index, every spelling.
INT_NAME_INDEX = {}
for _i, _ns in INT_NAMES.items():
    for _n in _ns:
        INT_NAME_INDEX[_n] = _i
