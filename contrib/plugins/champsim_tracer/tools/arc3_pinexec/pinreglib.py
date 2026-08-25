#!/usr/bin/env python3
"""Reader for the register execution reference written by
`champsim_reg_pintool.cpp`.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

The record is fixed-size and self-describing: the pintool writes a
`<out>.regnames` sidecar naming every XED and PIN register enumerator the
run actually emitted, together with the three capacities.  Nothing here
hard-codes either enum -- a hard-coded copy is a second place for the
mapping to be wrong in, and the 2026-08-23 pass already lost rows to one.

Record (1152 bytes at nsrc=16 / ndst=12 / vbytes=32):

      0..7    ip
      8       is_branch
      9       branch_taken
     10       instruction length (1..15)
     11       decode_ok            -- XED decoded this encoding
     12       n_src                -- TRUE count of named source registers
     13       n_dst                -- TRUE count of named destinations
     14       src_rec              -- how many the record actually holds
     15       dst_rec
     16..31   raw encoding, zero-padded
     32..     src[nsrc] entries, then dst[ndst] entries

  entry (40 bytes at vbytes=32):
      0..1    PIN REG enum, full-width (0 = unmapped)
      2..3    xed_reg_enum_t as decoded (NOT widened)
      4       full register width in bytes (0 = unknown)
      5       value bytes actually placed
      6       flags
      7       pad
      8..     value, little-endian, `got` bytes valid
"""
import numpy as np

RF_EXPLICIT = 0x01
RF_IMPLICIT = 0x02
RF_MEMADDR = 0x04
RF_RFLAGS = 0x08
RF_NOVALUE = 0x10
RF_TRUNC = 0x20

# XED pseudo-registers that stand for the stack memory operand of push/pop.
# They are not architectural registers and no reference should score them.
PSEUDO = {'STACKPUSH', 'STACKPOP'}


class RegNames:
    """The `<out>.regnames` sidecar: capacities plus both enum maps."""

    def __init__(self, path):
        self.xed = {}
        self.pin = {}
        self.recsize = None
        self.nsrc = self.ndst = self.vbytes = None
        with open(path) as f:
            for line in f:
                t = line.split()
                if not t:
                    continue
                if t[0] == '#':
                    if t[1] == 'recsize':
                        self.recsize = int(t[2])
                    elif t[1] == 'nsrc':
                        self.nsrc, self.ndst, self.vbytes = (
                            int(t[2]), int(t[4]), int(t[6]))
                    continue
                if t[0] == 'xed':
                    self.xed[int(t[1])] = t[2]
                elif t[0] == 'pin':
                    self.pin[int(t[1])] = t[2]
        if self.recsize is None or self.nsrc is None:
            raise ValueError('%s: no capacity header' % path)


def entry_dtype(vbytes):
    return np.dtype([('pin_reg', '<u2'), ('xed_reg', '<u2'), ('width', 'u1'),
                     ('got', 'u1'), ('flags', 'u1'), ('pad', 'u1'),
                     ('val', 'u1', vbytes)])


def rec_dtype(nsrc, ndst, vbytes):
    e = entry_dtype(vbytes)
    return np.dtype([('ip', '<u8'), ('is_branch', 'u1'), ('taken', 'u1'),
                     ('len', 'u1'), ('decode_ok', 'u1'), ('n_src', 'u1'),
                     ('n_dst', 'u1'), ('src_rec', 'u1'), ('dst_rec', 'u1'),
                     ('bytes', 'u1', 16), ('src', e, nsrc), ('dst', e, ndst)])


def read(path, names=None, nrec=None):
    """Memory-map the reference.  A file whose size is not a whole number of
    records is a REFUSAL, not a truncation: silently reading the tail as a
    short record would produce garbage that looks like data."""
    if names is None:
        names = RegNames(path + '.regnames')
    dt = rec_dtype(names.nsrc, names.ndst, names.vbytes)
    if dt.itemsize != names.recsize:
        raise ValueError('%s: sidecar says recsize=%d, layout computes %d'
                         % (path, names.recsize, dt.itemsize))
    a = np.memmap(path, dtype=dt, mode='r')
    return a[:nrec] if nrec else a, names


def raw_bytes(a):
    """Per-record raw instruction bytes as a list of `bytes`."""
    bs = np.asarray(a['bytes'])
    ln = np.asarray(a['len'])
    return [bs[i, :ln[i]].tobytes() for i in range(len(a))]


def canon(names, e):
    """Entry -> canonical full-width architectural register name, or None
    when the entry names nothing a reference should score.

    PIN's own `REG_StringShort` is preferred because the pintool already
    widened the register (`REG_FullRegName`); the XED name is the fallback
    for registers PIN has no exact map for (`ssp`, control registers), and
    is lower-cased so both sides speak one vocabulary."""
    p = int(e['pin_reg'])
    if p:
        n = names.pin.get(p)
        if n:
            return n
    x = names.xed.get(int(e['xed_reg']))
    if x is None or x in PSEUDO:
        return None
    return x.lower()


def value(e):
    """Entry value as an int, or None when nothing was captured."""
    g = int(e['got'])
    if not g:
        return None
    return int.from_bytes(bytes(np.asarray(e['val'])[:g]), 'little')


# ---------------------------------------------------------------------------
# One vocabulary for both instruments.
#
# The tracer names registers by GENERIC role (`%gp4`, `%sp`, `%flags`); PIN
# and XED name them architecturally (`rsi`, `rsp`, `rflags`).  Both are
# folded to a single canonical name here so that a disagreement is about
# WHICH REGISTER, never about which spelling.
# ---------------------------------------------------------------------------
import re as _re

_GPR = ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
_SEG = ['cs', 'ds', 'es', 'fs', 'gs', 'ss']

_RE_VEC = _re.compile(r'^[xyz]mm(\d+)$')


def norm(n):
    """Fold one architectural register name into the shared vocabulary."""
    if n is None:
        return None
    n = n.lower()
    if n in ('rflags', 'eflags', 'flags', 'gflags', 'status_flags'):
        return 'flags'
    if n in ('rip', 'eip', 'ip'):
        return 'rip'
    m = _RE_VEC.match(n)
    if m:
        return 'vec%d' % int(m.group(1))
    return n


def q_canon(ref):
    """champsim_tracer generic register ref -> shared vocabulary.

    From `champsim_tracer_mnemonics_x86.h`: GPR0..GPR13 = rax rcx rdx rbx
    rsi rdi r8..r15, SP = rsp, FP_REG = rbp, IP = rip, FLAGS = eflags,
    VECn = xmm_n, PREDn = k_n, FPRn = st_n, SEG0..5 = cs ds es fs gs ss.
    Returns None for refs with no architectural meaning."""
    if not ref.startswith('%'):
        return None
    b = ref[1:]
    if b.startswith('gp'):
        i = int(b[2:])
        return _GPR[i] if i < len(_GPR) else 'gpr%d' % i
    if b.startswith('v') and b[1:].isdigit():
        return 'vec%s' % b[1:]
    if b.startswith('seg'):
        i = int(b[3:])
        return _SEG[i] if i < len(_SEG) else 'seg%d' % i
    if b.startswith('p') and b[1:].isdigit():
        return 'k%s' % b[1:]
    if b.startswith('f') and b[1:].isdigit():
        return 'st%s' % b[1:]
    return {'sp': 'rsp', 'fpr': 'rbp', 'ip': 'rip', 'flags': 'flags',
            'mflags': None, 'zero': None, 'lr': None,
            'fcsr': 'mxcsr', 'vctrl': 'mxcsr'}.get(b, b)
