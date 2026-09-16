"""
Install a reconstructed x86-64 architectural state into gem5.

The wrong-path leg needs the simulator to start at a PC the guest never
legitimately reached, holding the register file and the memory the TRACE says
held at that moment.  gem5 has no "set the register file" interface, so the
state is installed the only way a machine accepts state: AS INSTRUCTIONS.
This module emits a static ELF whose entry point is a prologue that
materialises every register the trace named and then transfers to the
excursion's first PC.

THE ORDER IS THE DESIGN
=======================
Everything the prologue does needs a scratch register, and on x86-64 several
things need a stack as well (``popfq`` has no immediate form).  So:

  1. point ``rsp`` at a scratch stack INSIDE the boot region;
  2. install RFLAGS through ``push`` / ``popfq``;
  3. install the x87 file with eight ``fldt``s from a table of raw 80-bit
     values -- pushed in REVERSE, so that after eight pushes TOP is back
     where ``fninit`` left it and ``st(i)`` holds what the wire said;
  4. install XMM0..15 with ``movups`` from a table;
  5. install every integer register except the scratch, ``rsp`` last of those;
  6. install the scratch, ``rax``, LAST of all;
  7. transfer with a direct ``jmp rel32`` -- an absolute-address ``jmp *%reg``
     would need a register the prologue has already committed.

THE PROLOGUE IS EXCLUDED BY ADDRESS, NEVER BY COUNT
===================================================
It lives at ``BOOT_BASE`` and the guest at its own link address, so the filter
is a property of the image rather than an assumption about how many
instructions the assembler emitted.  ``BOOT_BASE`` is chosen within
``jmp rel32`` reach of a conventional non-PIE link address so the transfer
needs no register.

REGISTERS THE WIRE CANNOT PUT BACK
==================================
Every register set here comes from the trace.  A register the trace never
stated, or that cannot be written from user code, is NAMED in ``gaps`` --
never silently zeroed, because a silent zero agrees with the reference on
every register that happens to be zero and manufactures a pass.  The sharp
cases on this ISA:

  * ``REG_FCSR`` folds the x87 control word, the x87 status word, the tag
    word and MXCSR onto one id.  A fold is not invertible, so neither
    rounding mode nor the x87 TOP field can be restored from the wire.
  * ``REG_SEG*``: the ES/CS/SS/DS bases are architecturally zero in 64-bit
    mode and cannot be written from CPL 3 at all; FSBASE/GSBASE could be, but
    only through ``wrfsbase``, which requires CR4.FSGSBASE.
  * ``REG_CTRL*`` / ``REG_DEBUG*``: CPL 0 state.  The wire carries CR0, CR2,
    CR3, CR4 and CR8 in the seed; nothing at CPL 3 can install them.

Author: Maccoy Merrell.
"""
import os
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import x86_vocab as V                                          # noqa: E402

PAGE = 0x1000
BOOT_BASE = 0x30000000
BOOT_ENTRY = BOOT_BASE
#: the scratch stack the prologue uses for ``popfq``.  It sits in the boot
#: region, so it can never be confused with the guest's own stack and a store
#: through it can never overwrite reconstructed guest memory.
BOOT_STACK = BOOT_BASE + 0x8000
XTAB = BOOT_BASE + 0x10000          # 16 x 16 bytes of XMM state
FTAB = BOOT_BASE + 0x10100          # 8 x 10 bytes of x87 state
BOOT_SIZE = 0x11000

#: architecturally fixed bit 1 of RFLAGS.  Installed so the word gem5 ends up
#: holding is a legal one; it is outside ``V.RFLAGS_MASK`` and never compared.
RFLAGS_FIXED = 0x2


def _u64(v):
    return v & 0xffffffffffffffff


class Seed(object):
    """What was installed, and -- as importantly -- what could not be."""

    __slots__ = ('elf', 'gaps', 'unmapped', 'flags_word', 'code_len',
                 'segments')

    def __init__(self):
        self.elf = None
        self.gaps = []
        self.unmapped = []
        self.flags_word = None
        self.code_len = 0
        self.segments = []


def _pieces(regs):
    """Split a reconstructed state into what the prologue can install.

    -> (gpr, xmm, x87, flags, gaps, unmapped).  ``gaps`` names every
    architectural register this leg could not put back, whether because the
    wire never stated it or because no CPL-3 instruction can write it.
    """
    gpr = dict((g, None) for g in V.GPR_NAME)
    xmm = dict((i, None) for i in range(16))
    x87 = dict((i, None) for i in range(8))
    flags = None
    unmapped, gaps = [], []
    for name, (val, _w) in regs.items():
        kind = V.install_class(name)
        if kind is None:
            unmapped.append(name)
            continue
        if kind == 'gpr':
            gpr[name] = val
        elif kind == 'vec':
            xmm[int(name[7:])] = val
        elif kind == 'x87':
            x87[int(name[7:])] = val
        elif kind == 'flags':
            flags = val
        elif kind == 'fcsr':
            # Present on the wire, but the id folds FCW, FSW, the tag word and
            # MXCSR together and the fold is not invertible.
            pass
    gaps += [g for g in sorted(gpr) if gpr[g] is None]
    gaps += ['xmm%d' % i for i in sorted(xmm) if xmm[i] is None]
    gaps += ['st%d' % i for i in sorted(x87) if x87[i] is None]
    if flags is None:
        gaps.append('rflags')
    gaps.append('x87 TOP/tag + FCW/MXCSR (REG_FCSR fold is not invertible)')
    gaps.append('segment bases (no CPL-3 instruction writes them)')
    return gpr, xmm, x87, flags, gaps, unmapped


def prologue_source(regs, target_pc):
    """The assembly that installs `regs`, up to but NOT including the jump.

    The transfer is emitted as raw bytes by ``build`` once the prologue's
    length is known, because a direct ``jmp`` needs a displacement and an
    indirect one would need a register the prologue has already committed.
    """
    gpr, xmm, x87, flags, gaps, unmapped = _pieces(regs)
    L = []
    a = L.append
    a('# GENERATED by wp_seed_x86.py -- ARC 3 x86_64 wrong-path injection')
    a('.text')
    a('.globl _start')
    a('_start:')
    # --- 1/2: a scratch stack, then RFLAGS.
    a('  movabs $0x%x, %%rsp' % BOOT_STACK)
    a('  movabs $0x%x, %%rax' % _u64((flags or 0) | RFLAGS_FIXED))
    a('  pushq %rax')
    a('  popfq')
    # --- 3: the x87 file, pushed in reverse so st(i) lands on v[i].
    a('  fninit')
    a('  movabs $0x%x, %%rax' % FTAB)
    for i in range(7, -1, -1):
        a('  fldt %d(%%rax)' % (i * 10))
    # --- 4: XMM.
    a('  movabs $0x%x, %%rax' % XTAB)
    for i in range(16):
        a('  movups %d(%%rax), %%xmm%d' % (i * 16, i))
    # --- 5: the integer file except the scratch; rsp last of those, because
    # the scratch stack is live until it is written.
    for g in sorted(V.INSTALLABLE_GPR, key=lambda k: (k == 'REG_SP', k)):
        a('  movabs $0x%x, %%%s' % (_u64(gpr[g] or 0), V.GPR_NAME[g]))
    # --- 6: the scratch itself, LAST.
    a('  movabs $0x%x, %%%s' % (_u64(gpr[V.SCRATCH] or 0),
                                V.GPR_NAME[V.SCRATCH]))
    return '\n'.join(L) + '\n', gpr, xmm, x87, flags, gaps, unmapped


def assemble(src, outdir, tag, cc='gcc'):
    """Assemble the prologue to a FLAT binary (no relocations by construction).

    Every operand is an absolute immediate or an offset from one, so the bytes
    are the same wherever they are placed.  The flat form is what lets this
    module write the ELF itself instead of driving a linker per excursion --
    and a per-excursion link is a per-excursion opportunity for the toolchain
    to relax an instruction the harness counted on.
    """
    s = os.path.join(outdir, tag + '.S')
    o = os.path.join(outdir, tag + '.o')
    b = os.path.join(outdir, tag + '.bin')
    with open(s, 'w') as fh:
        fh.write(src)
    for cmd in ([cc, '-c', '-o', o, s],
                ['objcopy', '-O', 'binary', o, b]):
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        if p.returncode != 0:
            raise RuntimeError('%s failed: %s'
                               % (cmd[0], p.stdout.decode('utf-8', 'replace')))
    with open(b, 'rb') as fh:
        return fh.read()


def _regions(mem, extra):
    """Sparse {addr: byte} + [(base, bytes)] -> merged page-aligned segments.

    Merged with a one-page tolerance: a wrong-path excursion reads addresses
    the correct path established a cache line apart, and one PT_LOAD per byte
    produces an ELF no loader will take.
    """
    spans = []
    if mem:
        addrs = sorted(mem)
        lo = hi = addrs[0]
        for x in addrs[1:]:
            if x <= hi + PAGE:
                hi = x
                continue
            spans.append((lo, hi + 1))
            lo = hi = x
        spans.append((lo, hi + 1))
    for base, blob in extra:
        spans.append((base, base + len(blob)))
    spans = sorted((s & ~(PAGE - 1), (e + PAGE - 1) & ~(PAGE - 1))
                   for s, e in spans)
    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    segs = []
    for s, e in merged:
        buf = bytearray(e - s)
        for x, v in mem.items():
            if s <= x < e:
                buf[x - s] = v
        for base, blob in extra:
            if s <= base < e:
                buf[base - s:base - s + len(blob)] = blob
        segs.append((s, bytes(buf)))
    return segs


def write_elf(path, segs, entry):
    """Emit a little-endian x86-64 ELF64 executable, one PT_LOAD per segment.

    Written here rather than driven through a linker because the segments sit
    at addresses chosen by the guest and by the trace, not by a link script.
    A two-entry section header table with a real ``.shstrtab`` is included:
    ELF readers that walk sections looking for a symbol table assert on
    ``e_shstrndx < e_shnum``, and an image that trips that assertion is an
    image the reference refuses rather than one it disagrees with.
    """
    ehsize, phentsize = 64, 56
    phoff = ehsize
    off = phoff + phentsize * len(segs)
    body, phdrs = bytearray(), bytearray()
    for base, blob in segs:
        off = (off + PAGE - 1) & ~(PAGE - 1)
        while len(body) < off - (phoff + phentsize * len(segs)):
            body.append(0)
        phdrs += struct.pack('<IIQQQQQQ', 1, 7, off, base, base,
                             len(blob), len(blob), PAGE)
        body += blob
        off += len(blob)
    strtab = b'\0.shstrtab\0'
    stroff = phoff + phentsize * len(segs) + len(body)
    shoff = stroff + len(strtab)
    sh = struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh += struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, stroff, len(strtab),
                      0, 0, 1, 0)
    eh = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
                     b'\x7fELF', 2, 1, 1, 0, 0,
                     2, 62, 1, entry, phoff, shoff, 0,
                     ehsize, phentsize, len(segs), 64, 2, 1)
    with open(path, 'wb') as fh:
        fh.write(eh)
        fh.write(phdrs)
        fh.write(body)
        fh.write(strtab)
        fh.write(sh)
    return [(b, len(d)) for b, d in segs]


def build(outdir, tag, excursion, cc='gcc'):
    """-> Seed.  The injected image for one excursion, and its named gaps."""
    src, gpr, xmm, x87, flags, gaps, unmapped = prologue_source(
        excursion.regs, excursion.start_pc)
    code = bytearray(assemble(src, outdir, tag, cc))
    # The transfer, as raw bytes: `jmp rel32` from the end of the prologue.
    end = BOOT_ENTRY + len(code) + 5
    disp = excursion.start_pc - end
    if not (-(1 << 31) <= disp < (1 << 31)):
        raise RuntimeError(
            'excursion PC 0x%x is out of jmp rel32 reach of the boot region '
            'at 0x%x; move BOOT_BASE' % (excursion.start_pc, BOOT_BASE))
    code += b'\xe9' + struct.pack('<i', disp)

    xtab = bytearray(16 * 16)
    for i in range(16):
        xtab[i * 16:(i + 1) * 16] = ((xmm[i] or 0) &
                                     ((1 << 128) - 1)).to_bytes(16, 'little')
    ftab = bytearray(8 * 10)
    for i in range(8):
        ftab[i * 10:(i + 1) * 10] = ((x87[i] or 0) &
                                     ((1 << 80) - 1)).to_bytes(10, 'little')

    boot = bytearray(BOOT_SIZE)
    boot[0:len(code)] = code
    boot[XTAB - BOOT_BASE:XTAB - BOOT_BASE + len(xtab)] = xtab
    boot[FTAB - BOOT_BASE:FTAB - BOOT_BASE + len(ftab)] = ftab

    segs = _regions(excursion.mem, [(BOOT_BASE, bytes(boot))])
    elf = os.path.join(outdir, tag + '.elf')
    seg_desc = write_elf(elf, segs, BOOT_ENTRY)

    s = Seed()
    s.elf = elf
    s.gaps = gaps
    s.unmapped = unmapped
    s.flags_word = ((flags or 0) | RFLAGS_FIXED) if flags is not None else None
    s.code_len = len(code)
    s.segments = seg_desc
    return s
