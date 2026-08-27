"""
Install a reconstructed mipsel architectural state into gem5.

The wrong-path leg needs the reference to start at a PC the guest never
legitimately reached, holding the register file and the memory the TRACE says
held at that moment.  gem5 has no "set the register file" interface -- in
syscall-emulation mode it loads an ELF and starts at ``e_entry`` -- so the
state is installed the only way a machine accepts state: AS INSTRUCTIONS.
This module emits an ELF32 whose entry point is a prologue that materialises
every register the trace named and then jumps to the excursion's first PC.

WHAT IT COSTS, STATED RATHER THAN HIDDEN
=======================================
  * The prologue itself retires, and is EXCLUDED BY ADDRESS, never by count:
    it lives at ``BOOT_BASE`` and the guest at its own link address, so the
    filter is a property of the image rather than an assumption about how many
    instructions the assembler emitted.
  * ``$at`` (``$1``) is the prologue's scratch -- every FP, HI/LO and FCSR
    store goes through it -- so it is written LAST, and the transfer is a
    J-type ``j``, which needs no register at all.  ``j`` takes its top four
    address bits from the delay slot's PC, so the prologue and the excursion
    must lie in the same 256 MB region; ``build`` REFUSES rather than emitting
    a jump to a silently different address.
  * The excursion runs in gem5's user mode, which is where the traced
    instructions ran, so no privilege level is being faked.

REGISTERS THE WIRE CANNOT STATE
===============================
Every register set here comes from the trace.  A register the trace never
stated is set to zero AND NAMED in ``gaps`` -- never silently zeroed, because
a silent zero agrees with the reference on every register that happens to be
zero and manufactures a pass.  The sharp cases on this ISA:

  * the FP condition code rides on ``REG_PRED0``, which the tracer publishes
    with WIDTH 0 -- a name with no value, so it cannot be installed;
  * ``REG_SYSID`` (FIR) and ``REG_SYSEXC`` are read-only implementation state
    a user-mode prologue cannot write;
  * the DSP accumulator pairs ``REG_ACC1..3``/``REG_ACCHI1..3`` need the DSP
    ASE, which the probe set does not build for.

Author: Maccoy Merrell.
"""
import os
import struct
import subprocess

BOOT_BASE = 0x00300000          # the prologue
FPTAB_BASE = 0x00310000         # 32 x 4 bytes, read by the prologue
PAGE = 0x1000
EM_MIPS = 8

#: GenericRegId -> MIPS GPR number, for the three registers the tracer names
#: by role (champsim_tracer_mnemonics_mips.h).
_ROLE_GPR = {'REG_ZERO': 0, 'REG_SP': 29, 'REG_FP_REG': 30, 'REG_LR': 31}


def reg_to_mips(name):
    """A GenericRegId spelling -> ('gpr'|'fpr'|'hi'|'lo'|'fcsr'|'pc', idx).

    Inverted from ``champsim_tracer_mnemonics_mips.h``, the same table
    ``gem5_ref._mips_reg`` maps the other way, so the two directions cannot
    drift apart silently.  A name this function does not reach is reported as
    an unmappable id, never installed as a zero.
    """
    if name in _ROLE_GPR:
        return ('gpr', _ROLE_GPR[name])
    if name.startswith('REG_GPR'):
        n = int(name[7:])
        return ('gpr', n) if 1 <= n <= 28 else None
    if name.startswith('REG_FPR'):
        n = int(name[7:])
        return ('fpr', n) if 0 <= n < 32 else None
    if name == 'REG_ACC0':
        return ('lo', 0)
    if name == 'REG_ACCHI0':
        return ('hi', 0)
    if name == 'REG_FCSR':
        return ('fcsr', 0)
    if name == 'REG_PC':
        return ('pc', 0)
    return None


def _pieces(regs):
    """(gpr, fpr, hi, lo, fcsr, gaps, unmapped) from a reconstructed state."""
    gpr = dict((i, None) for i in range(1, 32))
    fpr = dict((i, None) for i in range(32))
    hi = lo = fcsr = None
    unmapped = []
    for name, (val, _w) in regs.items():
        m = reg_to_mips(name)
        if m is None:
            unmapped.append(name)
            continue
        bank, idx = m
        if bank == 'gpr':
            if idx:
                gpr[idx] = val & 0xffffffff
        elif bank == 'fpr':
            fpr[idx] = val & 0xffffffff
        elif bank == 'hi':
            hi = val & 0xffffffff
        elif bank == 'lo':
            lo = val & 0xffffffff
        elif bank == 'fcsr':
            fcsr = val & 0xffffffff
        # 'pc' is installed by the transfer itself.
    gaps = []
    gaps += ['$%d' % i for i in sorted(gpr) if gpr[i] is None]
    gaps += ['$f%d' % i for i in sorted(fpr) if fpr[i] is None]
    if hi is None:
        gaps.append('hi')
    if lo is None:
        gaps.append('lo')
    if fcsr is None:
        gaps.append('fcsr')
    # The FP condition code is published with WIDTH 0 -- a name and no value --
    # so it cannot be installed whether or not REG_PRED0 was present.  Stated
    # on every excursion, because its presence does not make it recoverable.
    gaps.append('fcc (REG_PRED0 is published with width 0)')
    return gpr, fpr, hi, lo, fcsr, gaps, unmapped


def _li(reg, val):
    """Materialise a 32-bit constant using ONLY the target register.

    Written as an explicit ``lui``/``ori`` pair rather than the ``li`` macro:
    the macro's expansion depends on the constant, so the prologue's
    instruction count -- which bounds the injected run -- would depend on the
    values the trace happened to carry.
    """
    val &= 0xffffffff
    return ['  lui  $%s, 0x%04x' % (reg, (val >> 16) & 0xffff),
            '  ori  $%s, $%s, 0x%04x' % (reg, reg, val & 0xffff)]


def prologue_source(regs, target_pc):
    """The assembly that installs `regs` and jumps to `target_pc`."""
    gpr, fpr, hi, lo, fcsr, gaps, unmapped = _pieces(regs)
    L = ['# GENERATED by wp_seed_mipsel.py -- ARC 3 mipsel wrong-path state '
         'injection',
         '.set noreorder',
         '.set noat',
         '.set nomacro',
         '.text',
         '.globl _start',
         '_start:']
    a = L.append
    # --- the FP file, from a table, through $1.
    L += _li('1', FPTAB_BASE)
    for i in range(32):
        # lwc1, not ldc1: the tracer publishes every REG_FPR with WIDTH 4, so
        # a 32-bit move is the exact width the wire states.  A 64-bit move
        # would install eight bytes where the wire supplied four and invent
        # the other four.
        a('  lwc1 $f%d, %d($1)' % (i, 4 * i))
    L += _li('1', fcsr or 0)
    a('  ctc1 $1, $31')
    L += _li('1', hi or 0)
    a('  mthi $1')
    L += _li('1', lo or 0)
    a('  mtlo $1')
    # --- the integer file.  $1 is the scratch every step above used, so it is
    # written LAST and the transfer is `j`, which needs no register.
    for i in range(2, 32):
        L += _li('%d' % i, gpr[i] or 0)
    L += _li('1', gpr[1] or 0)
    a('  j 0x%x' % (target_pc & 0xffffffff))
    a('  nop')
    return '\n'.join(L) + '\n', gaps, unmapped, fpr


def assemble(src, outdir, tag, cc='mipsel-linux-gnu-gcc'):
    """Assemble the prologue to a FLAT binary (no relocations by construction).

    Every operand is an absolute immediate, so the emitted bytes are the same
    wherever they are placed; the flat form is what lets this module write the
    ELF itself instead of driving a linker per excursion -- and a per-excursion
    link is a per-excursion opportunity for the toolchain to reorder or relax
    an instruction the harness counted on.
    """
    s = os.path.join(outdir, tag + '.S')
    o = os.path.join(outdir, tag + '.o')
    b = os.path.join(outdir, tag + '.bin')
    with open(s, 'w') as fh:
        fh.write(src)
    for cmd in ([cc, '-EL', '-march=mips32r2', '-mfp32', '-mno-abicalls',
                 '-fno-pic', '-c', '-o', o, s],
                # `-j .text` is not optional.  A MIPS `.o` carries
                # `.reginfo`, `.MIPS.abiflags` and `.pdr` alongside the
                # code, ALL at VMA 0, and a bare `objcopy -O binary`
                # emitted `.reginfo`'s 24 bytes INSTEAD of the
                # instructions -- gem5 fetched them and died with
                # `src/arch/mips/faults.cc:139: panic: Fault Reserved
                # Instruction Fault` at tick 0, before a single line of
                # trace.  Naming the section makes the extraction a
                # statement rather than a coincidence of section order.
                [cc.replace('gcc', 'objcopy'), '-O', 'binary',
                 '-j', '.text', o, b]):
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        if p.returncode != 0:
            raise RuntimeError('%s failed: %s'
                               % (cmd[0], p.stdout.decode('utf-8', 'replace')))
    with open(b, 'rb') as fh:
        code = fh.read()
    if len(code) % 4:
        raise RuntimeError('prologue is %d bytes, not a whole number of '
                           'MIPS instructions' % len(code))
    return code


def _regions(mem, extra):
    """Sparse {addr: byte} + [(base, bytes)] -> merged page-aligned segments.

    Merged with a one-page tolerance: a wrong-path excursion reads addresses
    the correct path established a cache line apart, and one PT_LOAD per byte
    would produce an ELF no loader accepts.
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
    out = []
    for s, e in spans:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    segs = []
    for s, e in out:
        buf = bytearray(e - s)
        for x, v in mem.items():
            if s <= x < e:
                buf[x - s] = v
        for base, blob in extra:
            if s <= base < e:
                buf[base - s:base - s + len(blob)] = blob
        segs.append((s, bytes(buf)))
    return segs


def write_elf32(path, segs, entry):
    """Emit a little-endian ELF32 MIPS executable, one PT_LOAD per segment.

    Written here rather than driven through a linker because the segments sit
    at addresses chosen by the guest and by the trace, not by a link script.

    EVERY segment is marked R+W+X.  That is not laziness: ``gem5_ref.parse``
    filters the reference stream to the executable ranges of the ELF it is
    handed, and the excursion may reach an address the guest's own link put in
    a non-executable segment.  Marking the injected image uniformly, and then
    excluding the prologue BY ADDRESS, keeps that filter from silently
    deleting reference instructions and making a real divergence look like the
    reference's silence.
    """
    ehsize, phentsize = 52, 32
    phoff = ehsize
    off = phoff + phentsize * len(segs)
    body, phdrs = bytearray(), bytearray()
    base_off = off
    for base, blob in segs:
        off = (off + PAGE - 1) & ~(PAGE - 1)
        while len(body) < off - base_off:
            body.append(0)
        phdrs += struct.pack('<IIIIIIII', 1, off, base, base,
                             len(blob), len(blob), 7, PAGE)
        body += blob
        off += len(blob)
    strtab = b'\0.shstrtab\0'
    stroff = base_off + len(body)
    shoff = stroff + len(strtab)
    sh = struct.pack('<IIIIIIIIII', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh += struct.pack('<IIIIIIIIII', 1, 3, 0, 0, stroff, len(strtab),
                      0, 0, 1, 0)
    # e_flags: EF_MIPS_NOREORDER | EF_MIPS_CPIC | ABI O32 | ARCH_32R2
    e_flags = 0x00001001 | 0x70000000
    eh = struct.pack('<4sBBBBB7xHHIIIIIHHHHHH',
                     b'\x7fELF', 1, 1, 1, 0, 0,
                     2, EM_MIPS, 1, entry, phoff, shoff, e_flags,
                     ehsize, phentsize, len(segs), 40, 2, 1)
    with open(path, 'wb') as fh:
        fh.write(eh)
        fh.write(phdrs)
        fh.write(body)
        fh.write(strtab)
        fh.write(sh)
    return [(b, len(d)) for b, d in segs]


class SameRegionRefused(Exception):
    """The prologue and the excursion are not in one J-type region."""


def build(outdir, tag, excursion, extra_pages=(),
          cc='mipsel-linux-gnu-gcc'):
    """-> (elf path, prologue instruction count, gaps, unmapped, boot span).

    ``extra_pages`` names addresses the excursion is KNOWN to touch that the
    reconstruction never established.  They are mapped as zero so the run can
    proceed and the divergence can be attributed, and the caller keeps the
    same set as evidence for the RECONSTRUCTION-GAP verdict; they are not a
    claim that the wire established anything.
    """
    target = excursion.start_pc & 0xffffffff
    if (target >> 28) != ((BOOT_BASE + 4) >> 28):
        raise SameRegionRefused(
            'the excursion starts at 0x%x, which is not in the same 256 MB '
            'J-type region as the prologue at 0x%x.  A `j` would transfer to '
            'a DIFFERENT address than the trace names, so nothing is built.'
            % (target, BOOT_BASE))
    src, gaps, unmapped, fpr = prologue_source(excursion.regs, target)
    code = assemble(src, outdir, tag, cc)
    fptab = bytearray(32 * 4)
    for i in range(32):
        fptab[i * 4:(i + 1) * 4] = ((fpr[i] or 0) & 0xffffffff).to_bytes(
            4, 'little')
    mem = dict(excursion.mem)
    for a in extra_pages:
        mem.setdefault(a, 0)
    segs = _regions(mem, [(BOOT_BASE, code), (FPTAB_BASE, bytes(fptab))])
    elf = os.path.join(outdir, tag + '.elf')
    write_elf32(elf, segs, BOOT_BASE)
    return (elf, len(code) // 4, gaps, unmapped,
            (BOOT_BASE, BOOT_BASE + len(code)))
