"""
Install a reconstructed architectural state into a real simulator.

The wrong-path leg needs Spike to start at a PC the guest never legitimately
reached, holding the register file and the memory the TRACE says held at that
moment.  Spike has no "set the register file" interface, so the state is
installed the only way a machine accepts state: as instructions.  This module
emits a bare-metal ELF whose entry point is a prologue that materialises every
register the trace named, points ``mepc`` at the excursion's first PC and
``mret``s into it.

WHY BARE METAL, AND WHAT IT COSTS
=================================
Under the proxy kernel the excursion's PC is unreachable -- pk owns the entry
sequence and there is no way in.  Bare metal starts wherever ``--pc`` says,
with ``satp`` zero, so a guest virtual address IS the physical address and the
image can be laid down at the addresses the trace names.  The cost is stated
rather than hidden:

  * the excursion retires in M-mode, not U-mode.  Every instruction the WP
    arm emits on this ISA is an unprivileged one, so the privilege level
    changes no result -- but it does mean this leg cannot check a privilege
    fault, and it says so instead of scoring one.
  * the prologue itself retires, and is EXCLUDED BY ADDRESS, never by count:
    it lives at 0x40000000 and the guest at its own link address, so the
    filter is a property of the image rather than an assumption about how
    many instructions the assembler emitted.

REGISTERS THE WIRE CANNOT STATE
===============================
Every register set here comes from the trace.  A register the trace never
stated is set to zero AND NAMED in ``gaps`` -- never silently zeroed, because
a silent zero agrees with the reference on every register that happens to be
zero and manufactures a pass.  ``REG_VCTRL`` is the sharp case: the tracer
folds ``vstart``/``vxsat``/``vxrm``/``vcsr``/``vl``/``vtype``/``vlenb`` onto
one id, and a fold is not invertible, so ``vl`` and ``vtype`` cannot be
restored from the wire at all.  That is a fact about the format and it is
reported as one.

Author: Maccoy Merrell.
"""
import os
import struct
import subprocess

BOOT_BASE = 0x40000000          # trap handler at +0, prologue at +0x40
BOOT_ENTRY = BOOT_BASE + 0x40
VTAB_BASE = 0x40100000          # the vector-register table the prologue reads
PAGE = 0x1000

#: mstatus: FS=3 (14:13), MPP=3 (12:11), VS=3 (10:9).  FS and VS must be
#: non-zero before an f or v register can be written at all; MPP=3 keeps the
#: excursion in M-mode, which is what makes the guest's own addresses
#: physical addresses.
MSTATUS = (3 << 13) | (3 << 11) | (3 << 9)

_ROLE_X = {'REG_ZERO': 0, 'REG_LR': 1, 'REG_SP': 2, 'REG_FP_REG': 8}


def reg_to_riscv(name):
    """A GenericRegId spelling -> ('x'|'f'|'v'|'csr', index|name), or None.

    Inverted from champsim_tracer_mnemonics_riscv.h, the same table
    ``spike_ref.to_generic`` maps the other way, so the two directions cannot
    drift apart silently.
    """
    if name in _ROLE_X:
        return ('x', _ROLE_X[name])
    if name.startswith('REG_GPR'):
        return ('x', int(name[7:]))
    if name.startswith('REG_FPR'):
        return ('f', int(name[7:]))
    if name.startswith('REG_VEC'):
        return ('v', int(name[7:]))
    if name == 'REG_FCSR':
        return ('csr', 'fcsr')
    return None


def _pieces(regs):
    """(x values, f values, v values, fcsr, gaps) from a reconstructed state.

    ``gaps`` names every architectural register the trace did not state.  It
    is the deliverable of this module as much as the ELF is: a wrong-path
    excursion that cannot be rebuilt is a hole in the wire format.
    """
    xs = dict((i, None) for i in range(1, 32))
    fs = dict((i, None) for i in range(32))
    vs = dict((i, None) for i in range(32))
    fcsr = None
    unmapped = []
    for name, (val, _w) in regs.items():
        m = reg_to_riscv(name)
        if m is None:
            unmapped.append(name)
            continue
        bank, idx = m
        if bank == 'x' and idx:
            xs[idx] = val
        elif bank == 'f':
            fs[idx] = val
        elif bank == 'v':
            vs[idx] = val
        elif bank == 'csr':
            fcsr = val & 0xff
    gaps = []
    gaps += ['x%d' % i for i in sorted(xs) if xs[i] is None]
    gaps += ['f%d' % i for i in sorted(fs) if fs[i] is None]
    gaps += ['v%d' % i for i in sorted(vs) if vs[i] is None]
    if fcsr is None:
        gaps.append('fcsr')
    # vl/vtype are folded onto REG_VCTRL with five other CSRs and cannot be
    # recovered from the fold.  Stated as a gap whether or not REG_VCTRL was
    # present, because its presence does not make the fold invertible.
    gaps.append('vl/vtype (REG_VCTRL fold is not invertible)')
    return xs, fs, vs, fcsr, gaps, unmapped


def prologue_source(regs, target_pc):
    """The assembly that installs `regs` and jumps to `target_pc`."""
    xs, fs, vs, fcsr, gaps, unmapped = _pieces(regs)
    L = []
    a = L.append
    a('# GENERATED by wp_seed.py -- ARC 3 riscv64 wrong-path state injection')
    a('.option norelax')
    a('.text')
    a('.globl _start')
    a('trap_entry:')
    a('  j trap_entry')            # a trap leaves a PC the harness recognises
    a('.org 0x40')
    a('_start:')
    a('  li t0, %d' % MSTATUS)
    a('  csrw mstatus, t0')
    a('  li t0, %d' % BOOT_BASE)
    a('  csrw mtvec, t0')          # direct mode: base is 4-byte aligned
    a('  csrw mscratch, zero')
    # --- vector file, from a table, before the GPR pass claims t0.
    a('  li t0, %d' % VTAB_BASE)
    a('  vsetvli t1, zero, e8, m1, ta, ma')
    for i in range(32):
        a('  vle8.v v%d, (t0)' % i)
        a('  addi t0, t0, 16')
    # --- FP file
    for i in range(32):
        a('  li t0, %d' % ((fs[i] or 0) & 0xffffffffffffffff))
        a('  fmv.d.x f%d, t0' % i)
    a('  li t0, %d' % ((fcsr or 0) & 0xff))
    a('  csrw fcsr, t0')
    # --- where we are going
    a('  li t0, %d' % (target_pc & 0xffffffffffffffff))
    a('  csrw mepc, t0')
    # --- the integer file.  t0 (x5) is the scratch every step above used, so
    # it is written LAST and the transfer is `mret`, which needs no register.
    for i in sorted(xs):
        if i == 5:
            continue
        a('  li x%d, %d' % (i, (xs[i] or 0) & 0xffffffffffffffff))
    a('  li x5, %d' % ((xs[5] or 0) & 0xffffffffffffffff))
    a('  mret')
    return '\n'.join(L) + '\n', gaps, unmapped, vs


def assemble(src, outdir, tag, cc='riscv64-linux-gnu-gcc'):
    """Assemble the prologue to a FLAT binary (no relocations by construction).

    Every operand is an absolute immediate, so the emitted bytes are the same
    wherever they are placed; the flat form is what lets this module write the
    ELF itself instead of driving a linker per excursion.
    """
    s = os.path.join(outdir, tag + '.S')
    o = os.path.join(outdir, tag + '.o')
    b = os.path.join(outdir, tag + '.bin')
    with open(s, 'w') as fh:
        fh.write(src)
    for cmd in ([cc, '-march=rv64gcv', '-mabi=lp64d', '-c', '-o', o, s],
                [cc.replace('gcc', 'objcopy'), '-O', 'binary', o, b]):
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
    the correct path established one cache line apart, and one PT_LOAD per
    byte would produce an ELF spike refuses to load.
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
    # page-align and merge again
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
    """Emit a little-endian ELF64 RISC-V executable with one PT_LOAD per seg.

    Written here rather than driven through a linker because the segments are
    at addresses chosen by the guest and by the trace, not by a link script,
    and because a per-excursion link is a per-excursion opportunity for the
    toolchain to relax an instruction the harness counted on.
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
    # fesvr's load_elf walks the SECTION table to find symbols and asserts
    # both `e_shstrndx < e_shnum` and `sh_name < shstrtab size`, so a section
    # header table with a real .shstrtab is not optional even for an image
    # that has no sections of its own.  Two entries satisfy both invariants.
    strtab = b'\0.shstrtab\0'
    stroff = phoff + phentsize * len(segs) + len(body)
    shoff = stroff + len(strtab)
    sh = struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh += struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, stroff, len(strtab),
                      0, 0, 1, 0)
    eh = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
                     b'\x7fELF', 2, 1, 1, 0, 0,
                     2, 243, 1, entry, phoff, shoff, 0,
                     ehsize, phentsize, len(segs), 64, 2, 1)
    with open(path, 'wb') as fh:
        fh.write(eh)
        fh.write(phdrs)
        fh.write(body)
        fh.write(strtab)
        fh.write(sh)
    return [(b, len(d)) for b, d in segs]


def build(outdir, tag, excursion, cc='riscv64-linux-gnu-gcc'):
    """-> (elf path, spike -m string, gaps, unmapped register names)."""
    src, gaps, unmapped, vs = prologue_source(excursion.regs,
                                              excursion.start_pc)
    code = assemble(src, outdir, tag, cc)
    vtab = bytearray(32 * 16)
    for i in range(32):
        v = vs[i] or 0
        vtab[i * 16:(i + 1) * 16] = (v & ((1 << 128) - 1)).to_bytes(16,
                                                                   'little')
    segs = _regions(excursion.mem, [(BOOT_BASE, code),
                                    (VTAB_BASE, bytes(vtab))])
    elf = os.path.join(outdir, tag + '.elf')
    write_elf(elf, segs, BOOT_ENTRY)
    m = ','.join('0x%x:0x%x' % (b, len(d)) for b, d in segs)
    return elf, m, gaps, unmapped
