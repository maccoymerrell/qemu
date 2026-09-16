"""
Install a reconstructed aarch64 architectural state into gem5.

The wrong-path leg needs gem5 to start at a PC the guest never legitimately
reached, holding the register file and the memory the TRACE says held at that
moment.  gem5 has no "set the register file" interface any more than Spike
does, so the state is installed the only way a machine accepts state: as
instructions.  This module emits a static ELF whose entry point is a prologue
that materialises every register the trace named and then transfers to the
excursion's first PC.

WHY SE MODE, AND WHAT IT COSTS
==============================
gem5's syscall-emulation mode loads a plain static ELF and starts it at
``e_entry`` in EL0 -- which is exactly the privilege level a qemu-user trace
was recorded at, so unlike the riscv64 leg (which had to enter M-mode through
``mret`` because the proxy kernel owns the entry sequence) nothing about the
privilege level has to be traded away here.

The costs that ARE real:

  * SE mode has no page table of its own to populate.  Every address the
    excursion touches must be in a ``PT_LOAD`` of the injected image, so the
    reconstruction lays the guest image and every correct-path-established
    byte back down at its own address.  An address the wire never established
    is not in the image, gem5 raises its SE-mode page fault, and the leg
    reports that as evidence rather than as a datum.
  * ``FPSR`` has no source on the wire: Capstone's aarch64 register space has
    no ``FPSR`` at all, so the tracer's table cannot name it and no snapshot
    can carry it.  Named as a seed gap, never silently zeroed.
  * SVE.  The trace's ``REG_VEC`` values are the full Z registers (512 bits
    under this QEMU's ``vg=8``), and the predicate file arrives as
    ``REG_PRED0..16``.  The prologue installs the low 128 bits of each Z --
    the architectural V register -- with ``ldr q``.  The Z tail and the
    predicate file are named seed gaps.

THE TRANSFER NEEDS NO REGISTER
==============================
The last thing the prologue does is a direct ``B``, whose target is a
PC-relative immediate: no register is consumed, so every general register can
carry the value the trace stated.  ``x16``/``x17`` are the prologue's scratch
and are therefore written LAST, immediately before the branch.  The prologue
is excluded from the comparison BY ADDRESS -- it lives at its own base, the
guest at its own link address -- never by counting instructions.

Author: Maccoy Merrell.
"""
import os
import struct
import subprocess

BOOT_BASE = 0x300000            # the prologue; 1 MiB below a 0x400000 guest
VTAB_BASE = 0x310000            # the vector table the prologue loads from
PAGE = 0x1000
EM_AARCH64 = 183

#: B imm26 reaches +-128 MiB, which is what lets the transfer consume no
#: register.  Asserted rather than assumed: a guest linked outside that window
#: would silently truncate the branch offset.
B_RANGE = 1 << 27

_ROLE_X = {'REG_FP_REG': 29, 'REG_LR': 30}


def reg_to_a64(name):
    """A GenericRegId spelling -> ('x'|'v'|'sp'|'nzcv'|'fpcr', idx), or None.

    Inverted from ``champsim_tracer_mnemonics_aarch64.h``, which is the same
    table ``gem5_ref._arm_reg`` maps the other way, so the two directions
    cannot drift apart without one of them failing to round-trip.
    """
    if name in _ROLE_X:
        return ('x', _ROLE_X[name])
    if name.startswith('REG_GPR'):
        n = int(name[7:])
        return ('x', n) if 0 <= n <= 28 else None
    if name.startswith('REG_VEC'):
        n = int(name[7:])
        return ('v', n) if 0 <= n < 32 else None    # REG_VEC32 is ZT0, not a V
    if name == 'REG_SP':
        return ('sp', 0)
    if name == 'REG_FLAGS':
        return ('nzcv', 0)
    if name == 'REG_FCSR':
        return ('fpcr', 0)
    if name == 'REG_ZERO':
        return ('zero', 0)
    return None


def _pieces(regs):
    """(x values, v values, sp, nzcv, fpcr, gaps, unmapped) from a state."""
    xs = dict((i, None) for i in range(31))
    vs = dict((i, None) for i in range(32))
    sp = nzcv = fpcr = None
    unmapped = []
    for name, (val, _w) in regs.items():
        m = reg_to_a64(name)
        if m is None:
            unmapped.append(name)
            continue
        bank, idx = m
        if bank == 'x':
            xs[idx] = val
        elif bank == 'v':
            vs[idx] = val
        elif bank == 'sp':
            sp = val
        elif bank == 'nzcv':
            nzcv = val
        elif bank == 'fpcr':
            fpcr = val
    gaps = []
    gaps += ['x%d' % i for i in sorted(xs) if xs[i] is None]
    gaps += ['v%d' % i for i in sorted(vs) if vs[i] is None]
    if sp is None:
        gaps.append('sp')
    if nzcv is None:
        gaps.append('nzcv')
    if fpcr is None:
        gaps.append('fpcr')
    # FPSR has no Capstone aarch64 register id, so the tracer's table cannot
    # name it and nothing on the wire ever states it.  A fact about the
    # vocabulary, reported on every excursion rather than discovered later.
    gaps.append('fpsr (no AARCH64_REG_FPSR exists to map)')
    # The predicate file and the Z tail above 128 bits are on the wire but the
    # prologue cannot install them without agreeing an SVE vector length with
    # the reference; stated so the report never implies they were installed.
    gaps.append('p0-p15/ffr + Z[511:128] (SVE state is not installed)')
    return xs, vs, sp, nzcv, fpcr, gaps, unmapped


def prologue_source(regs):
    """The assembly that installs `regs`.  The transfer is appended later."""
    xs, vs, sp, nzcv, fpcr, gaps, unmapped = _pieces(regs)
    L = []
    a = L.append
    a('// GENERATED by wp_seed_a64.py -- ARC 3 aarch64 wrong-path injection')
    a('.text')
    a('.globl _start')
    a('_start:')

    def li(reg, val):
        val &= (1 << 64) - 1
        a('  movz %s, #0x%x' % (reg, val & 0xffff))
        for sh in (16, 32, 48):
            part = (val >> sh) & 0xffff
            if part:
                a('  movk %s, #0x%x, lsl #%d' % (reg, part, sh))

    # --- the vector file, from a table.  x16 is the base and is reclaimed by
    #     the integer pass below.
    li('x16', VTAB_BASE)
    for i in range(32):
        a('  ldr q%d, [x16, #%d]' % (i, i * 16))
    # --- FPCR, then NZCV, then SP: all three need a scratch, and all three
    #     are installed before the integer pass takes its registers back.
    li('x17', (fpcr or 0) & 0xffffffff)
    a('  msr fpcr, x17')
    li('x17', ((nzcv or 0) >> 28) & 0xf)
    a('  lsl x17, x17, #28')
    a('  msr nzcv, x17')
    li('x17', (sp or 0))
    a('  mov sp, x17')
    # --- the integer file.  x16 and x17 are the scratch every step above
    #     used, so they are written LAST and the transfer consumes no
    #     register at all.
    for i in sorted(xs):
        if i in (16, 17):
            continue
        li('x%d' % i, xs[i] or 0)
    li('x16', xs[16] or 0)
    li('x17', xs[17] or 0)
    return '\n'.join(L) + '\n', gaps, unmapped, vs


def assemble(src, outdir, tag, cc='aarch64-linux-gnu-gcc'):
    """Assemble the prologue to a FLAT binary (no relocations by construction).

    Every operand is an absolute immediate, so the emitted bytes are the same
    wherever they are placed.  That is what lets this module write the ELF
    itself rather than drive a linker once per excursion -- and a per-excursion
    link is a per-excursion opportunity for the toolchain to rewrite an
    instruction the harness counted on.
    """
    s = os.path.join(outdir, tag + '.S')
    o = os.path.join(outdir, tag + '.o')
    b = os.path.join(outdir, tag + '.bin')
    with open(s, 'w') as fh:
        fh.write(src)
    for cmd in ([cc, '-march=armv8.4-a', '-c', '-o', o, s],
                [cc.replace('gcc', 'objcopy'), '-O', 'binary', o, b]):
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        if p.returncode != 0:
            raise RuntimeError('%s failed: %s'
                               % (cmd[0], p.stdout.decode('utf-8', 'replace')))
    with open(b, 'rb') as fh:
        return fh.read()


def branch_word(from_pc, to_pc):
    """The encoding of ``B <to_pc>`` placed at ``from_pc``.

    Emitted here rather than assembled because the assembler would need the
    prologue's final length to resolve the label, and that length is only
    known after assembly.  The range is CHECKED, not assumed.
    """
    delta = to_pc - from_pc
    if not (-B_RANGE <= delta < B_RANGE) or (delta & 3):
        raise RuntimeError(
            'the excursion entry 0x%x is %d bytes from the injection prologue '
            'at 0x%x; a direct B cannot reach it, and a register-consuming '
            'transfer would destroy the state this module exists to install'
            % (to_pc, delta, from_pc))
    return 0x14000000 | ((delta >> 2) & 0x03ffffff)


def _regions(mem, extra):
    """Sparse {addr: byte} + [(base, bytes)] -> merged page-aligned segments.

    Merged with a one-page tolerance: an excursion reads addresses the correct
    path established a cache line apart, and one PT_LOAD per byte produces an
    image no loader will take.
    """
    spans = []
    if mem:
        addrs = sorted(mem)
        lo = hi = addrs[0]
        for a in addrs[1:]:
            if a <= hi + PAGE:
                hi = a
                continue
            spans.append((lo, hi + 1))
            lo = hi = a
        spans.append((lo, hi + 1))
    for base, blob in extra:
        spans.append((base, base + len(blob)))
    spans = sorted((s & ~(PAGE - 1), (e + PAGE - 1) & ~(PAGE - 1))
                   for s, e in spans)
    out = []
    for s, e in spans:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    segs = []
    for s, e in out:
        buf = bytearray(e - s)
        for a, v in mem.items():
            if s <= a < e:
                buf[a - s] = v
        for base, blob in extra:
            if s <= base < e:
                buf[base - s:base - s + len(blob)] = blob
        segs.append((s, bytes(buf)))
    return segs


def write_elf(path, segs, entry):
    """A little-endian ELF64 AArch64 executable, one PT_LOAD per segment.

    Every segment is RWX.  gem5's SE-mode loader maps what the program headers
    say and the excursion is executing bytes that the traced guest held as
    data as often as it holds them as code -- a permission split here would
    turn a wrong-path fetch into a harness artefact.
    """
    ehsize, phentsize = 64, 56
    phoff = ehsize
    off = phoff + phentsize * len(segs)
    body, phdrs = bytearray(), bytearray()
    base_off = off
    for base, blob in segs:
        off = (off + PAGE - 1) & ~(PAGE - 1)
        while len(body) < off - base_off:
            body.append(0)
        phdrs += struct.pack('<IIQQQQQQ', 1, 7, off, base, base,
                             len(blob), len(blob), PAGE)
        body += blob
        off += len(blob)
    # A section header table with a real .shstrtab is not optional: every
    # ELF reader that walks sections for symbols asserts both
    # `e_shstrndx < e_shnum` and `sh_name < shstrtab size`.  Two entries
    # satisfy both for an image that has no sections of its own.
    strtab = b'\0.shstrtab\0'
    stroff = base_off + len(body)
    shoff = stroff + len(strtab)
    sh = struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh += struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, stroff, len(strtab),
                      0, 0, 1, 0)
    eh = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
                     b'\x7fELF', 2, 1, 1, 0, 0,
                     2, EM_AARCH64, 1, entry, phoff, shoff, 0,
                     ehsize, phentsize, len(segs), 64, 2, 1)
    with open(path, 'wb') as fh:
        fh.write(eh)
        fh.write(phdrs)
        fh.write(body)
        fh.write(strtab)
        fh.write(sh)
    return [(b, len(d)) for b, d in segs]


def build(outdir, tag, excursion, cc='aarch64-linux-gnu-gcc'):
    """-> (elf path, gaps, unmapped ids, prologue byte length)."""
    src, gaps, unmapped, vs = prologue_source(excursion.regs)
    code = assemble(src, outdir, tag, cc)
    code += struct.pack('<I', branch_word(BOOT_BASE + len(code),
                                          excursion.start_pc))
    vtab = bytearray(32 * 16)
    for i in range(32):
        v = vs[i] or 0
        vtab[i * 16:(i + 1) * 16] = (v & ((1 << 128) - 1)).to_bytes(16,
                                                                   'little')
    segs = _regions(excursion.mem, [(BOOT_BASE, code),
                                    (VTAB_BASE, bytes(vtab))])
    elf = os.path.join(outdir, tag + '.elf')
    write_elf(elf, segs, BOOT_BASE)
    return elf, gaps, unmapped, len(code)
