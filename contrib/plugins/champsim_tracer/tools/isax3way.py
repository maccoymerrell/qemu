#!/usr/bin/env python3
"""isax3way — three-way decoder tripwire: boundary vs LLVM vs GNU binutils.

Author: Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
`isaxcheck` is the per-commit decode gate.  It compares the tracer's decode
boundary — `cap_disas_raw_detail()` in disas/capstone.c, Capstone plus every
correction the boundary applies — against the LLVM MC layer, exhaustively.

Those two opinions are not fully independent.  Capstone's AArch64 / Mips /
RISCV instruction tables are auto-synced from LLVM TableGen, so a defect the
two share is structurally invisible to any comparison between them.  GNU
binutils/opcodes is a third decoder with its own hand-maintained opcode
tables, and it breaks that tie.

This tool is that third opinion, and it is a PERIODIC TRIPWIRE, not a gate.
It is run when a decoder version moves — a Capstone bump, an LLVM bump, a
binutils bump — and its output is compared against the previous run's.  It is
deliberately not wired into the per-commit path, for two reasons:

  - binutils yields disassembly *text* only.  No access metadata, no def/use
    sets.  So it can rule on encoding validity, instruction length, mnemonic
    identity and the registers named in the explicit operand text, and on
    nothing else — which is a strict subset of what `isaxcheck` already
    checks every commit.
  - the question it uniquely answers is a version question.  When the
    boundary decodes an encoding LLVM rejects, the LLVM subtarget in
    isaxcheck's kIsaTable may be NARROWER than the Capstone mode the tracer
    runs in, or Capstone may be over-accepting an encoding the architecture
    reserves.  `V-accept=cs` — binutils rejecting alongside LLVM — is
    unambiguously the second.  `V-accept=csgnu` puts the encoding beyond
    Capstone's word alone and points at the first, subject to the caveat
    that two decoders can share a leniency (see docs/troubleshooting.rst).
    The per-commit gate now measures the size of that gap directly and
    reports it as `subtarget_gap=` on its summary line, so the standing need
    is not to re-derive the interpretation every commit but to confirm it
    still holds after a decoder moves underneath it.

x86_64 is out of scope on purpose.  Capstone's x86 tables are hand-maintained
and independent of LLVM's, so the shared-blind-spot argument does not apply,
and x86 already has Intel PIN cross-validation.

POPULATIONS
-----------
The sweep is not exhaustive.  Two populations are used:

  representatives  Checked in under `isax3way_pop/<isa>_rep.hex`.  Generated
                   by `--gen-rep` (see below) from the same structured
                   opcode-space sweep `isaxcheck` walks, decimated to at most
                   `--rep-keep` encodings per distinct THREE-WAY ANSWER.  So
                   every bucket the exhaustive sweep produces survives into
                   the representative population; only the counts are capped.

  executed         Optional, supplied with `--hex`: the encodings a real
                   workload actually retired, from a trace.  `--weights`
                   attaches the dynamic execution count, which is what turns
                   a bucket from "reachable" into "reached N times a second".

Exhaustive is not merely slow here, it is unavailable: binutils 2.42's
AArch64 disassembler ABORTS on an assertion when swept exhaustively —

    aarch64-linux-gnu-objdump: ../../opcodes/aarch64-dis.c:251:
    get_sreg_qualifier_from_value: Assertion `value <= 0x4 &&
    aarch64_get_qualifier_standard_value (qualifier) == value' failed.

and the abort is reachable only in sequence: the same encoding disassembled
on its own decodes cleanly as `.inst ... ; undefined`.  binutils carries
decoder state across instructions (the MOVPRFX sequence constraint), so it is
the *adjacency* an exhaustive sweep creates that trips it, and no
single-encoding test finds it.  Measured here: the 4194304-encoding AArch64
sweep dies with SIGABRT at encoding 1531836 (`0x5d7ef022`), and the aborts
come in dense storms — six 4096-encoding regions in which very nearly every
encoding aborts.  A crash must not lose the rest of the batch, so the run is
resumed past the offending slot (see `_run_binary` for the backoff that makes
crossing a storm affordable) and the quarantined slots are answered
`(gnu-internal-error)`, which is a reportable binutils defect rather than a
decode opinion.  Representatives keep the storms bounded to begin with.

BUCKETS
-------
  V-*   validity vote  (which of the three accepted the encoding)
  L-*   length vote
  M-*   mnemonic vote
  X-*   explicit-operand register-name vote

Each name records who agreed with whom, so `M-cs=llvm!=gnu` is the
shared-blind-spot signal and `M-gnu=llvm!=cs` says binutils broke the tie
against the boundary.  The names are stable across versions of this tool on
purpose: a bucket-by-bucket diff against the previous run is the whole
deliverable.

USAGE
-----
    contrib/plugins/champsim_tracer/tools/isax3way.py \
        --isaxcheck build/contrib/plugins/isaxcheck

runs all three ISAs on the checked-in representatives.  Add executed
populations with `--hex aarch64=run/aarch64.hex --weights aarch64=...`.
`--out DIR` writes one `<isa>.3way` report per ISA alongside stdout.

To regenerate the checked-in representatives after a decoder bump:

    ... isax3way.py --isa aarch64 --gen-rep --isaxcheck <path>

which walks the full structured sweep once (minutes, not seconds) and
rewrites `isax3way_pop/aarch64_rep.hex`.
"""
import argparse
import bisect
import collections
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
POPDIR = os.path.join(HERE, 'isax3way_pop')

# ---------------------------------------------------------------------------
# ISA description
#
# Two binutils backends, because binutils cannot select a RISC-V extension set
# from the command line (`-M arch=` does not exist; the RISC-V disassembler
# takes its subset from the object's `.riscv.attributes`):
#
#   binary : aarch64, mipsel — objdump -D -b binary.  binutils decodes the
#            full AArch64 feature set (SVE included) unconditionally, so no
#            configuration is needed.
#   asm    : riscv64 — emit `.insn N, VALUE` through `as -march=...` so the
#            object carries the attribute, then objdump -d.  `.byte` cannot be
#            used: `as` marks it as data with a `$d` mapping symbol and
#            objdump then refuses to disassemble it.
# ---------------------------------------------------------------------------

ISA = {
    'aarch64': dict(backend='binary', slot=4,
                    objdump='aarch64-linux-gnu-objdump',
                    args=['-m', 'aarch64', '-EL'], fill=0x00),
    'mipsel':  dict(backend='binary', slot=4,
                    objdump='mipsel-linux-gnu-objdump',
                    args=['-m', 'mips:isa32r2', '-EL'], fill=0x00),
    'riscv64': dict(backend='asm', slot=8,
                    objdump='riscv64-linux-gnu-objdump',
                    asm='riscv64-linux-gnu-as',
                    march='rv64gcv_zba_zbb_zbs_zbc_zbkb_zbkc_zbkx_zfh'
                          '_zfhmin_zcb',
                    args=[]),
}
ISA_ORDER = ['aarch64', 'riscv64', 'mipsel']

# "   0:\td65f03c0 \tret"  |  "   0:\t00 00 \tadd ..."
LINE = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2,8} ?)+)\s*\t(.*)$')


# ---------------------------------------------------------------------------
# The binutils leg
# ---------------------------------------------------------------------------

def _clean(text):
    text = re.split(r'\s+//|\s+#|\s+<', text)[0].strip()
    return re.sub(r'[\s]+', ' ', text.replace('\t', ' ')).strip()


def _tok_bytes(raw_tokens):
    """objdump prints either space-separated bytes or one packed word."""
    return sum(len(t) // 2 for t in raw_tokens)


ICE_QUARANTINE_MAX = 4096       # slots retired per restart at full backoff


def _run_binary(cfg, order, scratch):
    """Disassemble one packed blob, surviving objdump internal errors.

    One fork for a million encodings instead of a million forks: every
    encoding under test is packed into a fixed-size slot and the whole batch
    goes through a single objdump invocation.

    binutils 2.42's AArch64 disassembler aborts on an assertion for some
    encoding sequences (see the module docstring), and the aborts come in
    dense storms — measured here, six 4096-slot regions of the AArch64
    opcode space in which very nearly every slot aborts.  Resuming one slot
    at a time across a storm costs one objdump fork per slot and does not
    finish.  So the resume distance BACKS OFF exponentially: each consecutive
    abort quarantines twice as many slots as the last, which crosses a
    4096-slot storm in about a dozen restarts, and the distance resets as
    soon as a run makes real progress again.  Quarantined slots are answered
    `(gnu-internal-error)` — a reportable binutils defect, not a decode
    opinion.
    """
    slot = cfg['slot']
    blob = bytearray()
    for h in order:
        b = bytes.fromhex(h)
        blob += b + bytes([cfg['fill']]) * (slot - len(b))
    path = os.path.join(scratch, '.blob.bin')
    with open(path, 'wb') as f:
        f.write(blob)
    base = [cfg['objdump'], '-D', '-b', 'binary'] + cfg['args']

    text = []
    ices = []
    start = 0
    quarantine = 1
    while start < len(order):
        p = subprocess.run(base + ['--start-address=%d' % (start * slot),
                                   path], capture_output=True, text=True)
        text.append(p.stdout)
        if p.returncode == 0:
            break
        last = -1
        for line in reversed(p.stdout.splitlines()):
            m = LINE.match(line)
            if m:
                last = int(m.group(1), 16) // slot
                break
        nxt = (last + 1) if last >= 0 else start
        if nxt - start > 8 * quarantine:
            quarantine = 1      # out of the storm; back to one at a time
        ices += order[nxt:nxt + quarantine]
        start = nxt + quarantine
        quarantine = min(quarantine * 2, ICE_QUARANTINE_MAX)
    return '\n'.join(text), {h: '(gnu-internal-error)' for h in ices}


def _run_asm(cfg, order, scratch):
    """Assemble one `.insn` per slot, then disassemble.

    Two things have to be handled or the whole batch is lost:

    - RISC-V encodes its own length in the low bits.  `.insn 4, V` with
      `V & 3 != 3` is rejected by `as` because the word says "this is a 16-bit
      instruction".  Those are not 4-byte encodings at all, so they are
      answered `(gnu-len-reject)` without being offered to the assembler.
    - `as` still rejects a residue (e.g. the 48/64-bit length prefixes).  Its
      diagnostics carry source line numbers, so the offending slots are
      replaced with padding and the assembly retried; each dropped slot is
      answered `(gnu-reject)`.
    """
    slot = cfg['slot']
    spath = os.path.join(scratch, '.blob.s')
    opath = os.path.join(scratch, '.blob.o')
    pad = ['\t.insn 2, 0x1'] * (slot // 2)

    rejected = {}
    body = []                       # one list of source lines per slot
    for h in order:
        raw = bytes.fromhex(h)
        # RISC-V encodes its own length in the low bits of the first
        # halfword.  A caller sweeping fixed 4-byte words will hand us words
        # whose low bits say "16-bit"; the boundary and LLVM both decode
        # those as a 2-byte compressed instruction and report size=2, so
        # binutils must be given the same 2 bytes or the third opinion is
        # answering a different question.
        n = 4 if (raw[0] & 3) == 3 else 2
        if n > len(raw):
            rejected[h] = '(gnu-len-reject)'
            body.append(list(pad))
            continue
        val = int.from_bytes(raw[:n], 'little')
        body.append(['\t.insn %d, 0x%x' % (n, val)]
                    + ['\t.insn 2, 0x1'] * ((slot - n) // 2))

    header = ['\t.text', '\t.option arch, %s' % cfg['march']]
    for _ in range(8):
        lines = list(header)
        line_of_slot = []
        for b in body:
            line_of_slot.append(len(lines) + 1)   # 1-based
            lines += b
        with open(spath, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        p = subprocess.run([cfg['asm'], '-march=' + cfg['march'], '-o', opath,
                            spath], capture_output=True, text=True)
        if p.returncode == 0:
            break
        bad = set()
        for m in re.finditer(re.escape(os.path.basename(spath)) + r':(\d+):',
                             p.stderr):
            bad.add(int(m.group(1)))
        if not bad:
            sys.stderr.write(p.stderr[:2000])
            raise SystemExit('%s: assembly failed with no line numbers'
                             % cfg['asm'])
        for ln in bad:
            i = bisect.bisect_right(line_of_slot, ln) - 1
            if 0 <= i < len(order):
                rejected[order[i]] = '(gnu-reject)'
                body[i] = list(pad)
    q = subprocess.run([cfg['objdump'], '-d'] + cfg['args'] + [opath],
                       capture_output=True, text=True)
    if q.returncode != 0:
        sys.stderr.write(q.stderr[:4000])
        raise SystemExit('%s failed' % cfg['objdump'])
    return q.stdout, rejected


def gnu_run(isa, hexes, scratch):
    """Return {hexstring: (n_bytes_decoded, 'mnem op,op')}."""
    cfg = ISA[isa]
    slot = cfg['slot']
    order = [h for h in hexes if len(h) // 2 <= slot]
    if not order:
        return {}, 0
    fn = _run_binary if cfg['backend'] == 'binary' else _run_asm
    stdout, refused = fn(cfg, order, scratch)

    out = {h: (0, why) for h, why in refused.items()}
    n_ice = sum(1 for w in refused.values() if w == '(gnu-internal-error)')
    for line in stdout.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if addr % slot:
            continue                      # padding, not a probe slot
        idx = addr // slot
        if idx >= len(order) or order[idx] in out:
            # A slot answered '(gnu-reject)' holds padding now, so its
            # disassembly must not overwrite the verdict already recorded.
            continue
        out[order[idx]] = (_tok_bytes(m.group(2).split()), _clean(m.group(3)))
    return out, n_ice


def gnu_version(isa):
    p = subprocess.run([ISA[isa]['objdump'], '--version'],
                       capture_output=True, text=True)
    return p.stdout.splitlines()[0].strip() if p.returncode == 0 else '?'


# ---------------------------------------------------------------------------
# Text canonicalisation.  The three printers differ cosmetically and spell the
# same architectural register three ways; fold the cosmetics out so that a
# residual difference means a real difference.  Width is dropped (the tracer
# models the architectural register), but the register *class* is kept so an
# integer/vector confusion still surfaces.
# ---------------------------------------------------------------------------

_MIPS_ABI = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
             't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
             's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
             't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']
_RV_ABI = ['zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
           's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
           's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11',
           't3', 't4', 't5', 't6']
_RV_FABI = ['ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7',
            'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5',
            'fa6', 'fa7', 'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7',
            'fs8', 'fs9', 'fs10', 'fs11', 'ft8', 'ft9', 'ft10', 'ft11']


def _mk(names, prefix, extra=()):
    m = {n: prefix + str(i) for i, n in enumerate(names)}
    m.update(extra)
    return m


REGMAP = {
    'mipsel': _mk(_MIPS_ABI, 'r', {'s8': 'r30', 'fp': 'r30'}),
    'riscv64': dict(list(_mk(_RV_ABI, 'r').items())
                    + list(_mk(_RV_FABI, 'f').items())),
    'aarch64': {'lr': 'r30', 'fp': 'r29', 'sp': 'sp', 'wsp': 'sp',
                'xzr': 'zr', 'wzr': 'zr'},
}

REGTOK = {
    'aarch64': re.compile(r'(?<![a-z0-9_.])'
                          r'([xw]\d{1,2}|[qdshb]\d{1,2}|v\d{1,2}|z\d{1,2}'
                          r'|p\d{1,2}|sp|wsp|xzr|wzr|lr|fp)'
                          r'(?![a-z0-9_])'),
    'riscv64': re.compile(r'(?<![a-z0-9_.])'
                          r'(x\d{1,2}|v\d{1,2}|f\d{1,2}'
                          r'|zero|ra|sp|gp|tp|t[0-6]|s(?:1[01]|[0-9])'
                          r'|a[0-7]|ft(?:1[01]|[0-9])|fa[0-7]'
                          r'|fs(?:1[01]|[0-9]))'
                          r'(?![a-z0-9_])'),
    'mipsel':  re.compile(r'(?<![a-z0-9_.])'
                          r'(\$\d{1,2}|zero|at|v[01]|a[0-3]|t[0-9]'
                          r'|s[0-8]|k[01]|gp|sp|fp|ra|f\d{1,2}|w\d{1,2}'
                          r'|ac[0-3])'
                          r'(?![a-z0-9_])'),
}


def canon_reg(isa, tok):
    tok = tok.lstrip('$%')
    m = REGMAP[isa]
    if tok in m:
        return m[tok]
    if isa == 'mipsel' and tok.isdigit():
        return 'r' + tok
    if isa == 'aarch64' and tok and tok[0] in 'xw' and tok[1:].isdigit():
        return 'r' + tok[1:]
    if isa == 'aarch64' and tok and tok[0] in 'qdshb' and tok[1:].isdigit():
        return 'v' + tok[1:]
    if isa == 'riscv64' and tok.startswith('x') and tok[1:].isdigit():
        return 'r' + tok[1:]
    if isa == 'riscv64' and tok.startswith('f') and tok[1:].isdigit():
        return 'f' + tok[1:]
    return tok


def canon_text(isa, t):
    t = t.strip().lower()
    if not t:
        return '', ''
    t = t.replace('\t', ' ')
    t = re.sub(r'\s*,\s*', ',', t)
    t = re.sub(r'\s+', ' ', t)
    parts = t.split(' ', 1)
    mnem = parts[0]
    ops = parts[1] if len(parts) > 1 else ''
    # Sigils only one printer emits.  '$' is KEPT: LLVM's MIPS printer spells
    # registers '$4', and the sigil is what tells that apart from an
    # immediate.
    ops = ops.replace('%', '')

    def _num(m):
        try:
            return str(int(m.group(0), 0))
        except ValueError:
            return m.group(0)
    ops = re.sub(r'(?<![a-z0-9_])-?0x[0-9a-f]+'
                 r'|(?<![a-z0-9_.])-?\d+(?![a-z0-9_])', _num, ops)
    return mnem, ops


def regset(isa, ops):
    """Registers named in the *explicit* operand text, canonicalised.

    Branch displacements are stripped first: the three printers render the
    target as an absolute address, a signed byte offset and a
    section-relative address respectively, and a bare `a02` from one of those
    forms would otherwise be mistaken for register a0.
    """
    toks = set()

    def _take(m):
        toks.add(canon_reg(isa, m.group(0)))
        return ' '

    if isa == 'mipsel':
        # LLVM's MIPS printer uses '$4'; consume those before the immediate
        # strip below removes the digits.
        ops = re.sub(r'\$\d{1,2}(?![0-9])', _take, ops)
    ops = re.sub(r'(?<![a-z0-9_$])-?\d+(?![a-z0-9_])', ' ', ops)
    # binutils renders a branch target as a bare section-relative hex address
    # with no 0x prefix ("beqz a5,a02"); three or more hex digits that are not
    # a register name is an address, not an operand.
    ops = re.sub(r'(?<![a-z0-9_$])[0-9a-f]{3,16}(?![a-z0-9_])',
                 lambda m: (m.group(0) if m.group(0) in REGMAP[isa] else ' '),
                 ops)
    for m in REGTOK[isa].finditer(ops):
        toks.add(canon_reg(isa, m.group(0)))
    return frozenset(toks)


def invalid(ok, text):
    if not ok:
        return True
    t = text.strip().lower()
    return (t.startswith('.inst') or t.startswith('.word')
            or t.startswith('.insn') or t.startswith('.byte')
            or t.startswith('(nodecode)') or 'undefined' in t
            or t.startswith('bad') or t == 'unimp')


# ---------------------------------------------------------------------------
# The boundary + LLVM legs, through `isaxcheck --batch`
# ---------------------------------------------------------------------------

def _speaks_batch(path):
    """True if this binary has `--batch` and answers with the joinable TSV.

    A QEMU tree routinely carries half a dozen build directories of differing
    ages, so "the first isaxcheck found" is not good enough: an older one
    predates `--batch` and would fail with a usage message that looks nothing
    like a decode problem.  Ask the binary instead of guessing.
    """
    try:
        p = subprocess.run([path, '--isa=aarch64', '--batch'], input='',
                           capture_output=True, text=True)
    except OSError:
        return False
    return p.returncode == 0 and p.stdout.startswith('hex\t')


def find_isaxcheck(explicit):
    """Locate the gate binary: --isaxcheck, then $ISAXCHECK, then build dirs.

    The batch row carries both decoders' views and echoes the input bytes
    back in a `hex` column, which is what this tool joins binutils onto.  The
    row is read by header name, not by position, so a column added upstream
    (`b_unmodelled` was) does not silently shift the join.
    """
    cands = []
    if explicit:
        cands.append(explicit)
    if os.environ.get('ISAXCHECK'):
        cands.append(os.environ['ISAXCHECK'])
    root = os.path.abspath(os.path.join(HERE, '..', '..', '..', '..'))
    builds = []
    try:
        for d in os.listdir(root):
            if d == 'build' or d.startswith('build-') or d.startswith('build'):
                p = os.path.join(root, d, 'contrib', 'plugins', 'isaxcheck')
                if os.path.isfile(p):
                    builds.append((os.path.getmtime(p), p))
    except OSError:
        pass
    # Newest first: in a multi-build tree the one just rebuilt is the one
    # meant, and an ancient build directory should never win by alphabet.
    cands += [p for _, p in sorted(builds, reverse=True)]

    tried = []
    for c in cands:
        if not (c and os.path.isfile(c) and os.access(c, os.X_OK)):
            tried.append('%s (missing)' % c)
            continue
        if not _speaks_batch(c):
            tried.append('%s (no --batch)' % c)
            continue
        sys.stderr.write('isax3way: using %s\n' % c)
        return c
    raise SystemExit('isax3way: no usable isaxcheck; pass --isaxcheck PATH '
                     '(tried: %s)' % ', '.join(tried or ['(nothing)']))


def batch_rows(isaxcheck, isa, hexes, scratch):
    """Yield one dict per encoding from `isaxcheck --batch`.

    No `--mattr`: the LLVM subtarget under test is the one the gate ships in
    its kIsaTable, and overriding it here would make the tripwire measure a
    subtarget nobody runs.
    """
    inp = os.path.join(scratch, '.hexlist')
    with open(inp, 'w') as f:
        f.write('\n'.join(hexes) + '\n')
    with open(inp) as fin:
        p = subprocess.run([isaxcheck, '--isa=' + isa, '--batch'], stdin=fin,
                           capture_output=True, text=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr[:4000])
        raise SystemExit('isaxcheck --batch failed for %s' % isa)
    lines = p.stdout.splitlines()
    hdr = lines[0].split('\t')
    for ln in lines[1:]:
        yield dict(zip(hdr, ln.split('\t')))


# ---------------------------------------------------------------------------
# The three-way vote
# ---------------------------------------------------------------------------

class Report:
    def __init__(self, isa, samples):
        self.isa = isa
        self.samples = samples
        self.buckets = collections.defaultdict(
            lambda: dict(n=0, w=0, samples=[]))
        self.tried = 0
        self.ices = 0

    def add(self, name, hexv, detail, w):
        b = self.buckets[name]
        b['n'] += 1
        b['w'] += w
        if len(b['samples']) < self.samples:
            b['samples'].append('%s | %s' % (hexv, detail))

    def text(self, extra_comments=()):
        out = ['#isa\t%s' % self.isa, '#tried\t%d' % self.tried]
        out += ['#%s\t%s' % kv for kv in extra_comments]
        if self.ices:
            out.append('#gnu-internal-errors\t%d' % self.ices)
        out.append('#bucket\tn\tdynweight\tsamples')
        for k, v in sorted(self.buckets.items(),
                           key=lambda kv: (-kv[1]['w'], -kv[1]['n'])):
            out.append('%s\t%d\t%d\t%s'
                       % (k, v['n'], v['w'], ' ;; '.join(v['samples'])))
        return '\n'.join(out) + '\n'


def vote(isa, isaxcheck, hexes, weights, scratch, samples, chunk):
    rep = Report(isa, samples)
    for i in range(0, len(hexes), chunk):
        part = hexes[i:i + chunk]
        gnu, n_ice = gnu_run(isa, part, scratch)
        rep.ices += n_ice
        for row in batch_rows(isaxcheck, isa, part, scratch):
            h = row['hex']
            rep.tried += 1
            gsz, gtext = gnu.get(h, (0, '(nodecode)'))
            b_ok = row['b_ok'] == '1'
            l_ok = row['l_ok'] == '1'
            b_text = (row['b_mnem'] + ' ' + row['b_ops']).strip()
            l_text = row['l_text']
            bi = invalid(b_ok, b_text)
            li = invalid(l_ok, l_text)
            gi = invalid(True, gtext) or gsz == 0
            w = weights.get(h, 0)

            # --- validity vote ---------------------------------------------
            if not (bi == li == gi):
                who = ''.join(['cs' if not bi else '',
                               'llvm' if not li else '',
                               'gnu' if not gi else '']) or 'none'
                rep.add('V-accept=%s' % who, h,
                        'cs=%s | llvm=%s | gnu=%s'
                        % (b_text or '(rej)', l_text or '(rej)', gtext), w)
            if bi or li or gi:
                continue    # text comparison is meaningless if anyone rejected

            # --- length vote -----------------------------------------------
            bsz, lsz = int(row['b_sz']), int(row['l_sz'])
            if not (bsz == lsz == gsz):
                rep.add('L-cs=%d,llvm=%d,gnu=%d' % (bsz, lsz, gsz), h,
                        '%s | %s | %s' % (b_text, l_text, gtext), w)

            bm, bo = canon_text(isa, b_text)
            lm, lo = canon_text(isa, l_text)
            gm, go = canon_text(isa, gtext)

            # --- mnemonic vote ---------------------------------------------
            if not (bm == lm == gm):
                if bm == lm:
                    tag = 'M-cs=llvm!=gnu'          # shared blind spot signal
                elif lm == gm:
                    tag = 'M-gnu=llvm!=cs'          # gnu breaks tie vs cs
                elif bm == gm:
                    tag = 'M-cs=gnu!=llvm'          # gnu breaks tie vs llvm
                else:
                    tag = 'M-all-differ'
                rep.add('%s [%s/%s/%s]' % (tag, bm, lm, gm), h,
                        '%s | %s | %s' % (b_text, l_text, gtext), w)
                continue

            # --- explicit-operand register vote ----------------------------
            br, lr, gr = (regset(isa, bo), regset(isa, lo), regset(isa, go))
            if not (br == lr == gr):
                if br == lr:
                    tag = 'X-cs=llvm!=gnu'
                elif lr == gr:
                    tag = 'X-gnu=llvm!=cs'
                elif br == gr:
                    tag = 'X-cs=gnu!=llvm'
                else:
                    tag = 'X-all-differ'
                rep.add('%s [%s]' % (tag, bm), h,
                        '%s | %s | %s' % (b_text, l_text, gtext), w)
    return rep


# ---------------------------------------------------------------------------
# Representative population
#
# The structured sweep is the same shape `isaxcheck` walks: the opcode-bearing
# bit space exhaustively, with the register fields FILLED, so an encoding that
# overloads a register field as an opcode extension is still reached.  One
# filling per ISA is enough here — none of the three decoders' opinion about
# instruction FORM varies with the register number.
#
# Decimation keeps at most `--rep-keep` encodings per distinct three-way
# ANSWER — (boundary verdict + mnemonic, LLVM verdict + mnemonic, binutils
# verdict + mnemonic).  That is the right unit because it is exactly what the
# third opinion can rule on: binutils yields text, so validity, length and
# mnemonic identity are the whole of its testimony.  Every V-, M- and X-
# bucket the exhaustive sweep produces therefore survives into the
# representative population by construction; what is lost is bucket
# MAGNITUDE, and magnitude that matters is what the executed population
# supplied with --hex carries.  Keeping more than one per answer is what
# leaves a decoder bump somewhere to land: a class that answers uniformly
# today may split tomorrow, and 24 members of it give that split 24 chances
# to be seen instead of one.
# ---------------------------------------------------------------------------

def _w32(v):
    return '%02x%02x%02x%02x' % (v & 0xff, (v >> 8) & 0xff,
                                 (v >> 16) & 0xff, (v >> 24) & 0xff)


def sweep_aarch64():
    # bits [31:10] exhaustive; Rn = x1, Rd = x2  (bits 9:5 = Rn, 4:0 = Rd)
    for hi in range(1 << 22):
        yield _w32((hi << 10) | (1 << 5) | 2)


def sweep_mipsel():
    # {op[31:26], rs[25:21], rt[20:16], funct[5:0]} exhaustive; rd = $3, sa = 0
    for v in range(1 << 22):
        op, rs, rt, fn = ((v >> 16) & 0x3f, (v >> 11) & 0x1f,
                          (v >> 6) & 0x1f, v & 0x3f)
        yield _w32((op << 26) | (rs << 21) | (rt << 16) | (3 << 11) | fn)


def sweep_riscv64():
    # {[31:20], [14:12], [6:0]} exhaustive; rs1 = x1, rd = x2
    for v in range(1 << 22):
        top, f3, op = (v >> 10) & 0xfff, (v >> 7) & 0x7, v & 0x7f
        yield _w32((top << 20) | (1 << 15) | (f3 << 12) | (2 << 7) | op)
    for v in range(1 << 16):        # every 16-bit compressed encoding
        yield '%02x%02x' % (v & 0xff, (v >> 8) & 0xff)


SWEEP = {'aarch64': sweep_aarch64, 'riscv64': sweep_riscv64,
         'mipsel': sweep_mipsel}


def gen_rep(isa, isaxcheck, scratch, keep, chunk, out_path):
    seen = collections.Counter()
    kept = []
    t0 = time.time()
    it = SWEEP[isa]()
    n = 0
    while True:
        part = []
        for h in it:
            part.append(h)
            if len(part) >= chunk:
                break
        if not part:
            break
        gnu, _ = gnu_run(isa, part, scratch)
        for row in batch_rows(isaxcheck, isa, part, scratch):
            h = row['hex']
            n += 1
            gsz, gtext = gnu.get(h, (0, '(nodecode)'))
            b_text = (row['b_mnem'] + ' ' + row['b_ops']).strip()
            key = (invalid(row['b_ok'] == '1', b_text), row['b_mnem'],
                   invalid(row['l_ok'] == '1', row['l_text']),
                   canon_text(isa, row['l_text'])[0],
                   invalid(True, gtext) or gsz == 0,
                   canon_text(isa, gtext)[0])
            if seen[key] < keep:
                seen[key] += 1
                kept.append(h)
        sys.stderr.write('\r  %s: %d swept, %d forms, %d kept, %.0fs'
                         % (isa, n, len(seen), len(kept), time.time() - t0))
        sys.stderr.flush()
    sys.stderr.write('\n')
    kept.sort()
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        f.write('\n'.join(kept) + '\n')
    sys.stderr.write('  -> %s (%d encodings from %d swept, %d distinct '
                     '3-way answers)\n' % (out_path, len(kept), n, len(seen)))


# ---------------------------------------------------------------------------

def read_hexlist(path):
    out = []
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith('#'):
                out.append(ln.split()[0].lower())
    return out


def read_weights(path):
    w = {}
    with open(path) as f:
        for ln in f:
            fld = ln.rstrip('\n').split('\t')
            if len(fld) >= 2 and fld[0] != 'hex':
                try:
                    w[fld[0].lower()] = int(fld[1])
                except ValueError:
                    pass
    return w


def split_isa_arg(val, isas):
    """`aarch64=path` -> ('aarch64', 'path'); a bare path needs one --isa."""
    if '=' in val:
        isa, path = val.split('=', 1)
        if isa not in ISA:
            raise SystemExit('isax3way: unknown isa %r in %r' % (isa, val))
        return isa, path
    if len(isas) != 1:
        raise SystemExit('isax3way: %r needs an ISA prefix (isa=path) when '
                         'more than one ISA is selected' % val)
    return isas[0], val


def main():
    ap = argparse.ArgumentParser(
        description='three-way decoder tripwire (boundary / LLVM / binutils)')
    ap.add_argument('--isa', action='append', choices=ISA_ORDER,
                    help='ISA to check; repeatable, default all three')
    ap.add_argument('--isaxcheck', default=None,
                    help='path to the isaxcheck binary')
    ap.add_argument('--hex', action='append', default=[], metavar='[ISA=]FILE',
                    help='executed-population hex list, one encoding per line')
    ap.add_argument('--weights', action='append', default=[],
                    metavar='[ISA=]FILE',
                    help='TSV hex<TAB>exec_count for the executed population')
    ap.add_argument('--pop', default=None, metavar='DIR',
                    help='directory holding <isa>.hex and optional '
                         '<isa>.weights.tsv')
    ap.add_argument('--no-rep', action='store_true',
                    help='skip the checked-in representative population')
    ap.add_argument('--out', default=None, metavar='DIR',
                    help='also write <isa>.3way reports here')
    ap.add_argument('--scratch', default=None,
                    help='scratch directory for the objdump blobs')
    ap.add_argument('--samples', type=int, default=3,
                    help='samples recorded per bucket (default 3)')
    ap.add_argument('--chunk', type=int, default=250000)
    ap.add_argument('--gen-rep', action='store_true',
                    help='regenerate the checked-in representative lists '
                         'from the full structured sweep and exit')
    ap.add_argument('--rep-keep', type=int, default=24,
                    help='--gen-rep: encodings kept per distinct three-way '
                         'answer (default 24)')
    a = ap.parse_args()

    isas = a.isa or list(ISA_ORDER)
    isaxcheck = find_isaxcheck(a.isaxcheck)
    # Deliberately not $TMPDIR: the objdump blobs run to tens of megabytes
    # under --gen-rep and this project keeps bulk output off the OS disk.
    # Alongside the reports when there are reports, else the working
    # directory — which is why a run from a source tree does not leave a
    # stray directory in it.  Point --scratch wherever the space is.
    scratch = a.scratch or os.path.join(a.out or os.getcwd(), '.isax3way')
    os.makedirs(scratch, exist_ok=True)
    if a.out:
        os.makedirs(a.out, exist_ok=True)

    if a.gen_rep:
        for isa in isas:
            gen_rep(isa, isaxcheck, scratch, a.rep_keep, a.chunk,
                    os.path.join(POPDIR, '%s_rep.hex' % isa))
        return 0

    extra_hex = collections.defaultdict(list)
    extra_w = collections.defaultdict(dict)
    if a.pop:
        for isa in isas:
            p = os.path.join(a.pop, '%s.hex' % isa)
            if os.path.exists(p):
                extra_hex[isa].append(p)
            p = os.path.join(a.pop, '%s.weights.tsv' % isa)
            if os.path.exists(p):
                extra_w[isa].update(read_weights(p))
    for v in a.hex:
        isa, path = split_isa_arg(v, isas)
        extra_hex[isa].append(path)
    for v in a.weights:
        isa, path = split_isa_arg(v, isas)
        extra_w[isa].update(read_weights(path))

    rc = 0
    t_all = time.time()
    for isa in isas:
        hexes, order = [], set()
        srcs = []
        rep = os.path.join(POPDIR, '%s_rep.hex' % isa)
        if not a.no_rep:
            if not os.path.exists(rep):
                raise SystemExit('isax3way: missing %s; run --gen-rep' % rep)
            srcs.append(('rep', rep))
        srcs += [('exec', p) for p in extra_hex[isa]]
        for _, p in srcs:
            for h in read_hexlist(p):
                if h not in order:
                    order.add(h)
                    hexes.append(h)
        t0 = time.time()
        r = vote(isa, isaxcheck, hexes, extra_w[isa], scratch, a.samples,
                 a.chunk)
        dt = time.time() - t0
        comments = [('binutils', gnu_version(isa)),
                    ('population', ' '.join('%s=%s' % (k, os.path.basename(p))
                                            for k, p in srcs)),
                    ('seconds', '%.1f' % dt)]
        body = r.text(comments)
        sys.stdout.write(body)
        sys.stdout.flush()
        if a.out:
            with open(os.path.join(a.out, '%s.3way' % isa), 'w') as f:
                f.write(body)
        gap = sum(v['n'] for k, v in r.buckets.items()
                  if k.startswith('V-accept=csgnu'))
        sys.stderr.write('%-8s %7d encodings  %2d buckets  '
                         'V-accept=csgnu=%d  %.1fs\n'
                         % (isa, r.tried, len(r.buckets), gap, dt))
    sys.stderr.write('total %.1fs\n' % (time.time() - t_all))
    return rc


if __name__ == '__main__':
    sys.exit(main())
