#!/usr/bin/env python3
"""Register cross-check of a champsim_tracer (.cst) correct-path stream
against the PIN register execution reference (`champsim_reg_pintool.cpp`).

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

  usage: cmp_reg.py --pin reg.bin --qemu q.jsonl [--anchor N] [--out FILE]

FOUR AXES, and what each one is worth
-------------------------------------
  src set     Which registers the instruction READS.  The reference is XED's
              FULL template operand list, EXPLICIT and SUPPRESSED alike, so
              its SILENCE is evidence: a register the list does not carry is
              a register the instruction does not name.  That is the whole
              reason this tool exists -- `INS_RegR` reported explicit
              operands only, so the previous reference could convict a
              subset and never a superset.
  dst set     Which registers it WRITES, same list, same both-directions
              property.
  dst VALUE   What the destination register HELD after the instruction, read
              out of the CONTEXT of the following instruction.  This is the
              axis that read NONE on x86_64 in the 2026-08-23 facet table.
  src VALUE   What each source register held BEFORE it.  The tracer's wire
              carries destination values only, so the tracer side of this
              axis is RECONSTRUCTED: a shadow register file replayed from
              the tracer's own published destination writes.  A source read
              is then scored against the value the TRACER ITSELF last said
              that register was given.  A register with no producer on the
              compared path is UNWITNESSED and is reported as such, never as
              agreement.

CROSS-RUN VALUES, and the constraint that keeps the model honest
----------------------------------------------------------------
The two runs are different processes.  Their images load identically (the
guest is static and non-PIE) but their stacks, environment blocks and
mappings do not, so a register holding a pointer differs between them by a
constant per region.  Accepting any FREQUENT delta as explained would let a
systematic register error mint its own explanation.  So a delta is
ESTABLISHED only if it has at least --minsupport witnesses AND the range of
QEMU values it covers is disjoint from every stronger delta's range -- the
piecewise-constant map a set of relocated mappings actually produces.
Deltas rejected for overlap are scored UNACCOUNTED, not absorbed.

DIRECTIONS
----------
  TRACER-SUPERSET  we carry something true the reference omits   OK, named
  TRACER-SUBSET    the reference carries something we drop       DEFECT
  ORTHOGONAL       different vocabulary for the same fact        OK, named
  UNACCOUNTED      not yet interrogated                          must be 0
"""
import argparse
import collections
import json
import sys

import pinreglib

AP = argparse.ArgumentParser()
AP.add_argument('--pin', required=True)
AP.add_argument('--qemu', required=True)
AP.add_argument('--anchor', type=int, default=None)
AP.add_argument('--qskip', type=int, default=None,
                help='QEMU instructions to drop before anchoring.  PIN\'s '
                     'skip gate consumes one instruction before it arms, so '
                     'the reference normally starts one guest instruction '
                     'late; left unset this is SEARCHED and reported, never '
                     'assumed')
AP.add_argument('--fp', type=int, default=20000)
AP.add_argument('--searchrec', type=int, default=4000000)
AP.add_argument('--out', default=None)
AP.add_argument('--maxreport', type=int, default=9999)
AP.add_argument('--kgram', type=int, default=16)
AP.add_argument('--window', type=int, default=20000)
AP.add_argument('--minsupport', type=int, default=8)
AP.add_argument('--mutate', default=None,
                help='negative control: inject one named defect into the '
                     'QEMU side -- dropsrc | extrasrc | dropdst | dstvalue | '
                     'srcvalue')
AP.add_argument('--mutate-every', type=int, default=997)
AP.add_argument('--witness', default=None,
                help='comma-separated ENCODINGS (as printed in the report, '
                     'e.g. 0f05).  For every disagreeing VALUE row on one of '
                     'those encodings, print ONE LINE PER INSTANCE to stderr: '
                     'position, pc, register, both values, and the category '
                     'the classifier reached.  Diagnostics only -- it reads '
                     'the same decisions the report is built from and cannot '
                     'change a count, and the report on stdout/--out is '
                     'byte-identical with and without it.  It exists because '
                     'an aggregated row cannot say WHICH instance survived: '
                     '#281 left 2 of 13 syscall r11 rows standing and the '
                     'residue could not be named without opening them.')
AP.add_argument('--summary', default=None,
                help='APPEND one machine-parsable CONTROL SUMMARY line, '
                     'carrying EVERY axis, to this file.  A negative control '
                     'that does not report the axis it exists to convict '
                     'proves nothing about that axis.')
A = AP.parse_args()

OUT = open(A.out, 'w') if A.out else sys.stdout


def say(*a):
    print(*a, file=OUT)
    OUT.flush()


NORM = pinreglib.norm
QC = pinreglib.q_canon

# Architectural names the tracer deliberately FOLDS into a coarser generic
# role.  A fold is a vocabulary difference, not a missing register, and it
# is listed here so it is visible rather than silently equated.
VOCAB_FOLD = {
    'xcr0': 'sys',      # REG_SYS carries the extended-control registers
}

# ---------------------------------------------------------------- load QEMU
Q = []
with open(A.qemu) as f:
    for line in f:
        j = json.loads(line)
        j['_b'] = bytes.fromhex(j['b'])
        j['_s'] = frozenset(x for x in (NORM(QC(r)) for r in j['s']) if x)
        j['_d'] = frozenset(x for x in (NORM(QC(r)) for r in j['d']) if x)
        dv = {}
        for ref, (val, w) in j.get('dv', {}).items():
            c = NORM(QC(ref))
            # Width 0 is the wire's "not captured": the plugin publishes a
            # destination whose register QEMU does not expose with w=0, and
            # the renderer prints `%r[0x0]`.  Reading that as the VALUE zero
            # would score a gap as agreement whenever the truth is zero --
            # exactly the defect 75838869cd was landed to remove.
            if c and w:
                dv[c] = (int(val, 16), w)
        j['_dv'] = dv
        # The SAME dict serves two different consumers: the destination-VALUE
        # comparison (`_dv`) and the publication into the shadow register
        # file that the SOURCE-VALUE axis reads back (`_sv`).  They are one
        # object in the unmutated stream -- a tracer that published a wrong
        # write is wrong on both -- and are split only so a control can
        # corrupt ONE of them.
        j['_sv'] = dv
        Q.append(j)
NQ = len(Q)
qb = [j['_b'] for j in Q]
say("QEMU correct-path instructions loaded: %d" % NQ)

# ------------------------------------------------------- negative control
N_MUT = 0
if A.mutate:
    n_mut = 0
    for k in range(0, NQ, A.mutate_every):
        j = Q[k]
        if A.mutate == 'dropsrc' and j['_s']:
            j['_s'] = frozenset(sorted(j['_s'])[1:])
        elif A.mutate == 'extrasrc':
            j['_s'] = frozenset(set(j['_s']) | {'r15'})
        elif A.mutate == 'dropdst' and j['_d']:
            j['_d'] = frozenset(sorted(j['_d'])[1:])
        elif A.mutate == 'dstvalue' and j['_dv']:
            # A wrong published write: wrong where it is compared AND wrong
            # everywhere it is later read, so both consumers see it.
            r = sorted(j['_dv'])[0]
            v, w = j['_dv'][r]
            j['_dv'] = dict(j['_dv'])
            j['_dv'][r] = (v ^ 0x8, w)
            j['_sv'] = j['_dv']
        elif A.mutate == 'srcvalue' and j['_dv']:
            # ISOLATING the source-value axis.  Corrupt ONLY the value that
            # reaches the shadow register file, leaving the destination
            # comparison at this instruction untouched.  The dst-VALUE
            # columns must then be BYTE-IDENTICAL to baseline while the
            # src-VALUE columns move -- which is the only shape that
            # convicts the shadow-regfile propagation rather than the
            # destination comparison it was riding on.  Before this split
            # `srcvalue` and `dstvalue` mutated the same field and differed
            # only in XOR mask, so neither could speak for this axis alone.
            r = sorted(j['_dv'])[0]
            v, w = j['_dv'][r]
            j['_sv'] = dict(j['_dv'])
            j['_sv'][r] = (v ^ 0x4000, w)
        else:
            continue
        n_mut += 1
    say("NEGATIVE CONTROL: mutation '%s' applied at %d QEMU instructions "
        "(every %d)" % (A.mutate, n_mut, A.mutate_every))
    N_MUT = n_mut
    if n_mut == 0:
        say("FATAL: the mutation never fired -- it proves nothing")
        raise SystemExit(3)

# ---------------------------------------------------------------- load PIN
P, NAMES = pinreglib.read(A.pin)
NP = len(P)
say("PIN records loaded: %d   (nsrc=%d ndst=%d vbytes=%d)"
    % (NP, NAMES.nsrc, NAMES.ndst, NAMES.vbytes))
pb = pinreglib.raw_bytes(P)


def p_side(r, which):
    """PIN record -> {canonical name: (value or None, flags)}."""
    out = {}
    n = int(r['src_rec'] if which == 'src' else r['dst_rec'])
    arr = r[which]
    for k in range(n):
        e = arr[k]
        c = NORM(pinreglib.canon(NAMES, e))
        if not c:
            continue
        v = pinreglib.value(e)
        prev = out.get(c)
        if prev is None or (prev[0] is None and v is not None):
            out[c] = (v, int(e['flags']), int(e['got']))
    return out


# ---------------------------------------------------------------- 1. anchor
SEP = b'\xff\xfe'
lim = min(NP, A.searchrec)
starts = {}
acc = 0
parts = []
for i in range(lim):
    starts[acc] = i
    parts.append(pb[i])
    acc += len(pb[i]) + len(SEP)
blob = SEP.join(parts) + SEP


def anchor_at(qskip, F):
    pat = SEP.join(qb[qskip:qskip + F]) + SEP
    hits = []
    pos = 0
    while True:
        k = blob.find(pat, pos)
        if k < 0:
            break
        if k in starts:
            hits.append(starts[k])
        pos = k + 1
    return hits


if A.anchor is not None and A.qskip is not None:
    k0, q0 = A.anchor, A.qskip
    say("anchor: forced to PIN record %d / QEMU record %d" % (k0, q0))
else:
    F = min(A.fp, NQ)
    q0 = k0 = None
    tried = []
    for qs in ([A.qskip] if A.qskip is not None else range(0, 17)):
        hits = anchor_at(qs, F)
        tried.append((qs, len(hits)))
        if hits:
            q0, k0 = qs, hits[0]
            break
    say("anchor: %d-instruction fingerprint searched over QEMU leads %s "
        "(lead, hits)" % (F, tried))
    if k0 is None:
        say("FATAL: no anchor; the pair is not aligned")
        raise SystemExit(2)
del blob, parts, starts
say("anchor: PIN record %d  <->  QEMU record %d  (QEMU lead %d: PIN's skip "
    "gate consumes one instruction before arming)" % (k0, q0, q0))

# ---------------------------------------------------------------- 2. walk
K, W = A.kgram, A.window


def kg(seq, i, n):
    if i + K > n:
        return None
    return b'|'.join(seq[i + t] for t in range(K))


i, j = k0, q0
pairs = []
regions = []
n_ident = 0
while i < NP and j < NQ:
    if pb[i] == qb[j]:
        pairs.append((i, j))
        n_ident += 1
        i += 1
        j += 1
        continue
    idx = {}
    for t in range(i, min(NP - K, i + W)):
        g = kg(pb, t, NP)
        if g is not None and g not in idx:
            idx[g] = t
    best = None
    for t in range(j, min(NQ - K, j + W)):
        g = kg(qb, t, NQ)
        if g is None:
            break
        u = idx.get(g)
        if u is not None:
            cost = (u - i) + (t - j)
            if best is None or cost < best[0]:
                best = (cost, u, t)
            if cost == 0:
                break
    if best is None:
        regions.append((i, j, NP - i, NQ - j, 'UNRESYNCED'))
        break
    _, ni, nj = best
    regions.append((i, j, ni - i, nj - j, ''))
    i, j = ni, nj

span_q = (pairs[-1][1] - pairs[0][1] + 1) if pairs else 0
say("lockstep walk: %d byte-identical pairs, %d divergent regions"
    % (n_ident, len(regions)))
say("compared span: QEMU [%d..%d] = %d instructions; byte-identical %d "
    "(%.6f%%)" % (pairs[0][1] if pairs else 0, pairs[-1][1] if pairs else 0,
                  span_q, n_ident, 100.0 * n_ident / max(1, span_q)))

# The boundaries of the divergent regions: a shadow register file cannot be
# carried across one, because registers were written inside it that this
# comparison never saw.
region_start_q = set(r[1] for r in regions)

# ------------------------------------------------- 3. the pointer delta map
PTR_LO, PTR_HI = 0x400000, 0x800000000000

# The PIN-QEMU CODE delta, measured over the pairing itself: the guest is a
# static non-PIE image, so it is expected to be 0, but an expectation is not
# a measurement.
code_hist = collections.Counter()
for (pi, qj) in pairs:
    code_hist[int(P[pi]['ip']) - int(Q[qj]['pc'], 16)] += 1
CODE_DELTAS = set(d for d, c in code_hist.items()
                  if c >= A.minsupport or d == 0)

PAGE = 12   # mappings relocate as whole pages, so a delta's DOMAIN is a
            # set of pages, not a min/max hull.  A hull over a sparse
            # sample swallows the pages between its witnesses and then
            # convicts every value in them of a "wrong delta".

delta_hist = collections.Counter()
dpages = collections.defaultdict(set)
drange = collections.defaultdict(lambda: [None, None])
for (pi, qj) in pairs:
    pd = p_side(P[pi], 'dst')
    for c, (pv, _f, _g) in pd.items():
        if pv is None or c not in Q[qj]['_dv']:
            continue
        qv, qw = Q[qj]['_dv'][c]
        w = min(qw or 8, 8)
        m = (1 << (8 * w)) - 1
        a, b = qv & m, pv & m
        # Only values that could BE pointers enter the delta map.  A delta
        # is a property of a relocated MAPPING, and a register holding a
        # small integer is in no mapping: letting `rax = 0` vs `rax = 4`
        # contribute a "+4 delta" would give delta 0 a range covering the
        # whole 64-bit space and reject every real mapping delta for
        # overlap -- which is exactly what happened before this constraint.
        if w != 8 or not (PTR_LO <= a < PTR_HI and PTR_LO <= b < PTR_HI):
            continue
        delta_hist[b - a] += 1
        dpages[b - a].add(a >> PAGE)
        rg = drange[b - a]
        rg[0] = a if rg[0] is None else min(rg[0], a)
        rg[1] = a if rg[1] is None else max(rg[1], a)

ESTAB = set()
PAGE_DELTA = {}
rejected = []
for d, c in sorted(delta_hist.items(), key=lambda kv: (-kv[1], kv[0])):
    if c < A.minsupport and d != 0:
        continue
    if any(pg in PAGE_DELTA for pg in dpages[d]):
        rejected.append((d, c) + tuple(drange[d]))
        continue
    ESTAB.add(d)
    for pg in dpages[d]:
        PAGE_DELTA[pg] = d
ESTAB.add(0)

say("")
say("=== PIN-QEMU register-value deltas measured over the paired "
    "destinations ===")
say("  distinct deltas seen: %d;  ESTABLISHED (>= %d witnesses AND covering "
    "a PAGE DOMAIN disjoint from every stronger delta): %d"
    % (len(delta_hist), A.minsupport, len(ESTAB)))
for d, c in delta_hist.most_common(12):
    lo, hi = drange[d]
    why = ('ESTABLISHED' if d in ESTAB else
           'below support' if c < A.minsupport else
           'REJECTED: page domain overlaps a stronger delta')
    say("  %+#20x  %9d  [%#14x .. %#14x]  %s" % (d, c, lo, hi, why))
if rejected:
    say("  deltas rejected for page-domain overlap: %d  (their registers are "
        "scored UNACCOUNTED, not absorbed)" % len(rejected))

def value_agrees(qv, pv, w):
    """Exact, or the same pointer under an ESTABLISHED delta."""
    m = (1 << (8 * w)) - 1
    a, b = qv & m, pv & m
    if a == b:
        return 'exact'
    if w == 8 and (b - a) in ESTAB:
        return 'pointer'
    return None


# ---------------------------------------------------------------- 4. score
st = collections.Counter()
setsig = collections.defaultdict(collections.Counter)
valsig = collections.defaultdict(collections.Counter)
sample = {}


def note(book, kind, sig, qj):
    book[kind][sig] += 1
    sample.setdefault((kind, sig), qj)


WITNESS_ENC = set(x.strip().lower()
                  for x in (A.witness or '').split(',') if x.strip())


def witness(axis, q, pos, reg, qv, pv, w, cat, direction):
    """Per-INSTANCE trace of one disagreeing value row, to stderr.

    Off unless --witness names this encoding.  It prints what the classifier
    decided and the two values it decided on, so a surviving row in an
    aggregated count can be opened and named instead of guessed at."""
    if not WITNESS_ENC or q['b'].lower() not in WITNESS_ENC:
        return
    m = (1 << (8 * w)) - 1
    print('WITNESS %-7s pos=%-8d pc=%-12s %-6s qemu=%#018x ref=%#018x '
          'w=%d  %s / %s'
          % (axis, pos, q.get('pc'), reg, qv & m, pv & m, w, cat, direction),
          file=sys.stderr)


# The identically-placed mapping: the range of QEMU pointer values whose
# PIN counterpart was the SAME value.  A load from outside it reads a cell
# the two processes placed differently, so its content is process-private
# and any value derived from it may legitimately differ.
IMG_LO, IMG_HI = drange[0] if 0 in drange and drange[0][0] is not None \
    else (None, None)
say("  identically-placed value range (delta 0): %s"
    % ('none measured' if IMG_LO is None else '[%#x .. %#x]' % (IMG_LO, IMG_HI)))


def process_private_load(q):
    """True when this instruction read memory the two runs place
    differently, so anything it computed may legitimately differ."""
    if IMG_LO is None:
        return False
    for a in q.get('la', ()):
        if not (IMG_LO <= a <= IMG_HI):
            return True
    return False


def mapping_of(a):
    """The ESTABLISHED delta whose page domain contains @a, or None."""
    return PAGE_DELTA.get(a >> PAGE)


# Encodings whose result is a property of the MACHINE, not of the program.
# PIN runs them on this host's CPU; the tracer runs them on QEMU's emulated
# one.  Their destinations cannot agree and their difference is not a tracer
# fact -- it is which CPU answered.
HOST_SPECIFIC = {
    '0fa2': 'cpuid',
    '0f01d0': 'xgetbv',
    '0f31': 'rdtsc',
    '0f01f9': 'rdtscp',
    '0fc7f8': 'rdpid',
}
SYSCALL_ENC = '0f05'


def is_host_specific(enc):
    for k in HOST_SPECIFIC:
        if enc == k or enc.endswith(k):
            return HOST_SPECIFIC[k]
    return None


def has_seg_prefix(enc):
    """An fs/gs-prefixed access reads thread-local storage, which the two
    processes place independently."""
    return enc.startswith('64') or enc.startswith('65')


#: Registers the KERNEL wrote across a syscall and no instruction published.
#: qemu-user performs the write in the CPU loop, outside the translated
#: instruction stream, so the tracer has no observation point for it and the
#: comparison's shadow register file cannot learn the new value.  Emptied as
#: soon as an instruction publishes the register again.
kernel_written = set()
#: what cpu_loop.c's EXCP_SYSCALL arm writes back that no instruction does.
SYSCALL_KERNEL_WRITES = ('rax',)

#: THE SYSCALL REGISTER-EFFECT VERDICT for the pair currently being scored.
#: Empty for every encoding but 0f05.  Filled by syscall_effects() below and
#: read by classify_value(); a dict rather than an argument because the same
#: verdict decides three different registers on the same instruction and
#: recomputing it per register would let the three disagree.
SYSFX = {}
#: One row per syscall instance whose rcx/r11/flags disagreed, with both
#: sides' numbers.  An aggregated report cannot say WHICH instance survived
#: (#281 left 2 of 13 standing and they could not be named without opening
#: them), so the adjudication is printed per instance, always, not behind a
#: diagnostic flag.
sys_rows = []


def syscall_effects(rec, q, pd):
    """Did BOTH sides perform SYSCALL's architectural register effects?

    SYSCALL's whole register footprint is three writes: RCX <- the address of
    the next instruction, R11 <- RFLAGS, RIP <- LSTAR.  Whether an instrument
    performed the first two is a fact each side states ABOUT ITSELF -- rcx
    against its own next-instruction address, r11 against its own rflags --
    so it is decidable without comparing the two sides at all.

    That is exactly what the question needs.  A value disagreement on
    rcx/r11/flags means the CLOBBER IS MISSING only if some side did not
    perform it.  If both performed it, the disagreement is in the flags word
    that ARRIVED, and R11-equals-RFLAGS on each side also proves RFLAGS is
    unchanged across the instruction -- the hardware answer, measured
    natively under #281.  Naming that a missing clobber is a false
    justification, which is what #293 filed.

    Returns a dict with 'performed' and, when it is False, a 'why' naming the
    check that failed.  A missing record on either side is NOT performed: a
    check that cannot find its subject fails."""
    def ref(c):
        e = pd.get(c)
        return None if e is None else e[0]

    def trc(c):
        e = q['_dv'].get(c)
        return None if e is None else e[0]

    ref_next = int(rec['ip']) + int(rec['len'])
    trc_next = int(q['pc'], 16) + len(q['_b'])
    out = {'ref_rcx': ref('rcx'), 'ref_r11': ref('r11'),
           'ref_flags': ref('flags'), 'ref_next': ref_next,
           'trc_rcx': trc('rcx'), 'trc_r11': trc('r11'),
           'trc_flags': trc('flags'), 'trc_next': trc_next}
    for k in ('ref_rcx', 'ref_r11', 'ref_flags',
              'trc_rcx', 'trc_r11', 'trc_flags'):
        if out[k] is None:
            out['performed'] = False
            out['why'] = 'no-' + k.replace('_', '-')
            return out
    if out['ref_r11'] != out['ref_flags']:
        out['performed'] = False
        out['why'] = 'reference-r11-is-not-its-own-rflags'
    elif out['trc_r11'] != out['trc_flags']:
        out['performed'] = False
        out['why'] = 'tracer-r11-is-not-its-own-rflags'
    elif out['ref_rcx'] != out['ref_next']:
        out['performed'] = False
        out['why'] = 'reference-rcx-is-not-its-own-next-ip'
    elif out['trc_rcx'] != out['trc_next']:
        out['performed'] = False
        out['why'] = 'tracer-rcx-is-not-its-own-next-pc'
    else:
        out['performed'] = True
        out['why'] = ''
    return out


def classify_value(reg, qv, pv, w, inherited, enc):
    """Name the mechanism behind a cross-run register-value difference.

    Every rule is decided from measured evidence in these two streams: an
    ESTABLISHED mapping delta, a value that is a pointer on both sides, an
    input this comparison already SAW differ legitimately.  A difference no
    rule explains is UNACCOUNTED and is adjudicated by hand, never
    absorbed."""
    m = (1 << (8 * w)) - 1
    a, b = qv & m, pv & m
    if w == 8 and (b - a) in ESTAB:
        return ('MAPPING-POINTER', 'ORTHOGONAL')
    if enc == SYSCALL_ENC and reg in ('rcx', 'r11', 'flags'):
        # THE CLOBBER IS TESTED, NOT ASSUMED FROM THE ENCODING  (#281, #293).
        #
        # SYSCALL performs three register effects -- RCX <- RIP-of-next,
        # R11 <- RFLAGS, RFLAGS <- RFLAGS & ~IA32_FMASK, the last undone by
        # the kernel's SYSRET.  qemu-user performs the first two on the
        # correct path since #281 (target/i386/tcg/user/seg_helper.c, long
        # mode).  The third is deliberately not emulated and MUST NOT BE:
        # measured natively under #281, one static binary run on real
        # hardware observes RFLAGS UNCHANGED across a syscall, and qemu-user
        # produces the identical answer.
        #
        # THIS RULE USED TO CONVICT ON THE ENCODING ALONE.  Two rules did:
        # `QEMU-USER-SYSCALL-NO-RCX-R11-CLOBBER` and
        # `QEMU-USER-SYSCALL-NO-RFLAGS-CLOBBER`.  After the fix they still
        # claimed 4 rows, and the witness showed none of them was this class:
        # at pc 0x418ea0 and 0x418efc the tracer read r11 = flags = 0x206 and
        # the reference read r11 = flags = 0x202, differing in bit 2 (PF)
        # alone.  Both sides had performed the clobber correctly; the
        # difference was entirely in the flags word that arrived -- the
        # pointer-placement class adjudicated under #272.
        #
        # syscall_effects() now decides it from the record: each side's r11
        # against ITS OWN rflags and each side's rcx against ITS OWN next
        # instruction address.  That keeps the regression tripwire -- an
        # emulator that stops writing r11 fails `tracer-r11-is-not-its-own-
        # rflags` and is convicted TRACER-SUBSET, per instance, by name --
        # while refusing to call an input difference a missing write.  The
        # per-instance numbers are printed in the report's SYSCALL section,
        # unconditionally.
        SYSFX.setdefault('_regs', []).append(reg)
        if not SYSFX.get('performed'):
            return ('QEMU-USER-SYSCALL-CLOBBER-NOT-PERFORMED:'
                    + (SYSFX.get('why') or 'no-record'), 'TRACER-SUBSET')
        if reg == 'rcx':
            # Both sides put their own next-instruction address in rcx, so a
            # remaining difference is where the CODE sits, and only a delta
            # the pairing itself measured may explain it.
            if w == 8 and (b - a) in CODE_DELTAS:
                return ('SYSCALL-NEXT-IP-UNDER-A-MEASURED-CODE-DELTA',
                        'ORTHOGONAL')
            return ('SYSCALL-NEXT-IP-CODE-DELTA-UNESTABLISHED', 'UNACCOUNTED')
        # r11 and flags: r11 == rflags on BOTH sides, so this register's
        # disagreement IS the flags word's disagreement, and the equality
        # also says rflags did not change here.  The difference came in.
        return ('SYSCALL-INHERITED-FLAGS-INPUT', 'ORTHOGONAL')
    hs = is_host_specific(enc)
    if hs:
        return ('HOST-VS-EMULATED-CPU:' + hs, 'ORTHOGONAL')
    if reg == 'rip' and (b - a) in CODE_DELTAS and (b - a) != 0:
        # The two runs resolved an IFUNC to different twins of the same
        # function, so control transfers to a different -- but paired --
        # address.  The delta is one the PAIRING itself measured.
        return ('TWIN-FUNCTION-SELECTION', 'ORTHOGONAL')
    if has_seg_prefix(enc):
        return ('TLS-SEGMENT-READ', 'ORTHOGONAL')
    if inherited:
        # Measured evidence beats shape: this instruction consumed a value
        # this comparison ALREADY saw differ legitimately, so its result may
        # differ however it likes.  Checked before the pointer rules because
        # "the input differed" explains a pointer result too.
        return ('INHERITED-DIFFERING-INPUT', 'ORTHOGONAL')
    if w == 8 and PTR_LO <= a < PTR_HI and PTR_LO <= b < PTR_HI:
        # A pointer difference is explained by the MAPPING it points into,
        # never by "both look like pointers".  If the QEMU value lies inside
        # a mapping this comparison measured, the only admissible difference
        # is that mapping's own delta -- and value_agrees() already accepted
        # that above, so arriving here means the delta is WRONG.  Absorbing
        # it would let any pointer-shaped corruption explain itself: the
        # `dstvalue` negative control is precisely that shape.
        if mapping_of(a) is not None:
            return ('IN-MAPPING-WRONG-DELTA', 'UNACCOUNTED')
        return ('POINTER-OUTSIDE-EVERY-MEASURED-MAPPING', 'ORTHOGONAL')
    if reg in kernel_written:
        # THE SAME BOUNDARY, THE OTHER DIRECTION, AND ALSO UPSTREAM QEMU'S.
        # cpu_loop.c DOES write the syscall's result: env->regs[R_EAX] = ret,
        # at linux-user/i386/cpu_loop.c:257 -- but it does it in the CPU
        # LOOP, outside any translated instruction, so no plugin instruction
        # callback ever observes it and the value never reaches the wire.
        # A consumer replaying this trace therefore has a stale RAX after
        # every syscall: OBSERVED at 0x404387, where `test %eax,%eax` read
        # the 0x9e that `movl $0x9e,%eax` had written for the syscall NUMBER
        # while the reference had already seen the return value 0.
        #
        # COUNTED, not forgiven.  The dependency edge a consumer would build
        # from this trace is wrong, which makes it a trace fact even though
        # its cause is a missing QEMU observation point rather than anything
        # the plugin decides.  The fix is upstream: qemu-user must make the
        # cpu_loop syscall write-back visible to plugins (or the tracer must
        # snapshot the destination after the exception returns), and until
        # it does, this row is a defect with a named owner.
        return ('QEMU-USER-SYSCALL-RESULT-WRITTEN-OUTSIDE-THE-INSN-STREAM',
                'TRACER-SUBSET')
    return ('UNACCOUNTED', 'UNACCOUNTED')


# ------------------------------------------------------- PROVENANCE
#
# WHY THIS IS SEPARATE FROM `tainted`, AND MUST STAY SEPARATE.
#
# `tainted` records a difference this comparison has EXPLAINED, and it feeds
# `inherited`, which downgrades a later row to ORTHOGONAL.  An UNACCOUNTED
# difference deliberately does NOT enter it: if it did, one real defect would
# launder every value derived from it and the criterion would fall to zero
# for the wrong reason.  That rule is right and is not touched here.
#
# But it leaves the residue unreadable.  A single unexplained root produces a
# fan-out of unexplained descendants, and the report showed all of them as
# peers -- 274 rows with no way to tell the one difference that arose here
# from the two hundred that only carried it forward.  `unexplained` is the
# missing half: it records where an UNACCOUNTED difference AROSE, so a later
# row can NAME its ancestor without being FORGIVEN by it.  Nothing in here
# ever reaches `inherited`, and no row's DIRECTION changes because of it --
# only the mechanism it is reported under.
#
#   reg -> (enc, mnem, reg, pc)   the row that first left this register
#                                 differing with no rule to explain it
unexplained = {}
#   page -> (enc, mnem, reg, pc)  a store whose DATA was such a register, so
#                                 the cell it wrote now differs too, and the
#                                 next load of it inherits through MEMORY --
#                                 which this arm has no reference for.
unexplained_mem = {}
#: every ROOT, keyed by the (enc, reg) whose difference arose with nothing
#: upstream of it, carrying how many rows are charged to it.
root_census = collections.OrderedDict()
MEMPAGE = 6          # 64-byte granule: a store and the load that reads it back

#: prov_of()'s third answer.  Not a root (the difference came from outside)
#: and not a known root either (this arm has no reference for the carrier).
UNPAIRED = object()


def prov_of(q, ps, c, unwitnessed):
    """Where an UNACCOUNTED difference on @c at this instruction CAME FROM.

    Returns (suffix, ancestor).  The suffix names the mechanism; the
    ancestor is the root tuple to charge this row to, None when the row IS a
    root, or UNPAIRED when the carrier is real but unnamed.

    A row is a ROOT only when EVERY register input was COMPARED and AGREED
    and no memory was read.  That is the only shape that can be a tracer
    defect rather than a difference between two processes -- and it is why
    @unwitnessed is a separate answer rather than folded into agreement: a
    source the shadow file never held was never compared, so calling the row
    a root would be claiming an agreement that was never measured.  That is
    this project's dominant failure wearing this instrument's hat.
    """
    # The register itself already differed before this instruction ran.
    src = unexplained.get(c)
    if src is None:
        for k in ps:
            if k in unexplained:
                src = unexplained[k]
                break
    if src is not None:
        return ('-VIA-REG:' + src[0] + '/' + src[2], src)
    # If it read a cell a differing store wrote, the difference travelled
    # through MEMORY, which the REGISTER arm has no reference for --
    # cmp_memop.py is the instrument that compares memory.
    for a in q.get('la', ()):
        m = unexplained_mem.get(a >> MEMPAGE)
        if m is not None:
            return ('-VIA-MEM:' + m[0] + '/' + m[2], m)
    if unwitnessed:
        return ('-VIA-REG:UNWITNESSED:' + ','.join(sorted(unwitnessed)),
                UNPAIRED)
    if q.get('nl'):
        return ('-VIA-MEM:UNWITNESSED-CELL', UNPAIRED)
    return ('-ROOT', None)


def prov_charge(root, q, c, axis=None, qv=None, pv=None, w=None):
    """Book one row against its ancestor, or open a new root.

    A root carries its WITNESS -- the axis, and both sides' value -- because
    a root is the only class in this residue that could be a tracer defect,
    and a defect claim with no observed value behind it is a table row.
    """
    if root is UNPAIRED:
        return None
    if root is None:
        key = (q['b'], c)
        r = root_census.get(key)
        if r is None:
            r = root_census[key] = {'enc': q['b'], 'mnem': q['c'], 'reg': c,
                                    'pc': q['pc'], 'n': 0, 'desc': 0,
                                    'w': []}
        r['n'] += 1
        if len(r['w']) < 4:
            m = (1 << (8 * (w or 8))) - 1
            r['w'].append('%s @%s %s trc=%#x ref=%#x w=%d'
                          % (axis, q['pc'], c, (qv or 0) & m, (pv or 0) & m,
                             w or 8))
        return (q['b'], q['c'], c, q['pc'])
    key = (root[0], root[2])
    r = root_census.get(key)
    if r is not None:
        r['desc'] += 1
    return root


# The tracer's own shadow register file, replayed from the destination
# values the tracer published.  It is the tracer side of the source-value
# axis; it is cleared at every divergent region because a register written
# inside one was never observed here.
shadow = {}
# Registers whose cross-run value difference this comparison has ALREADY
# explained.  Only an EXPLAINED difference taints -- an UNACCOUNTED one
# must not become the excuse for its own successors, or a single real
# defect would launder every value derived from it.
tainted = set()
prev_qj = None
repnext = set()
for t in range(len(pairs) - 1):
    if P[pairs[t][0]]['ip'] == P[pairs[t + 1][0]]['ip'] and \
            pb[pairs[t][0]] == pb[pairs[t + 1][0]]:
        repnext.add(t)

for pos, (pi, qj) in enumerate(pairs):
    r = P[pi]
    q = Q[qj]
    if prev_qj is not None and qj != prev_qj + 1:
        shadow.clear()
        tainted.clear()
        unexplained.clear()
        unexplained_mem.clear()
        kernel_written.clear()
        st['shadow_cleared'] += 1
    prev_qj = qj
    st['pairs'] += 1

    ps = p_side(r, 'src')
    pd = p_side(r, 'dst')
    pset = frozenset(ps)
    dset = frozenset(pd)

    # The syscall register-effect verdict for THIS pair, decided once and
    # read by every register the rule covers (#293).
    SYSFX.clear()
    if q['b'] == SYSCALL_ENC:
        SYSFX.update(syscall_effects(r, q, pd))

    if int(r['decode_ok']) == 0:
        st['ref_decode_fail'] += 1
        note(setsig, 'refdecode', (q['b'], q['m'], q['c']), qj)
        continue
    if int(r['n_src']) > int(r['src_rec']) or int(r['n_dst']) > int(r['dst_rec']):
        st['ref_overcapacity'] += 1
        note(setsig, 'refcap', (q['b'], q['m'], q['c']), qj)
        continue

    # ---- axis 1/2: the two SETS -----------------------------------------
    for axis, pv_set, qv_set in (('srcset', pset, q['_s']),
                                 ('dstset', dset, q['_d'])):
        if pv_set == qv_set:
            st[axis + '_match'] += 1
            continue
        st[axis + '_mismatch'] += 1
        only_p = sorted(pv_set - qv_set)
        only_q = sorted(qv_set - pv_set)
        if all(VOCAB_FOLD.get(x) in qv_set for x in only_p) and \
                all(x in set(VOCAB_FOLD.get(y) for y in only_p) for x in only_q) \
                and only_p:
            direction = 'ORTHOGONAL'
        elif only_p and not only_q:
            direction = 'TRACER-SUBSET'
        elif only_q and not only_p:
            direction = 'TRACER-SUPERSET'
        else:
            direction = 'UNACCOUNTED'
        note(setsig, axis,
             (q['b'], q['c'], 'ref_only=' + ','.join(only_p),
              'tracer_only=' + ','.join(only_q), direction), qj)

    # ---- axis 4: SOURCE VALUES, against the tracer's own shadow file ----
    # Scored FIRST: whether this instruction's inputs already differed
    # legitimately is what decides how a destination difference is read.
    inherited = process_private_load(q) or is_host_specific(q['b']) is not None \
        or has_seg_prefix(q['b'])
    # Sources this comparison could not compare at all: the shadow file never
    # held them, so their agreement is unmeasured and must not be assumed.
    # Computed BEFORE the source loop, not accumulated during it: a row
    # scored early would otherwise be told about only the registers the loop
    # had reached, and would call itself a root on the strength of a set that
    # was still being built.
    unwitnessed = set(c for c, (pv, _f, _g) in ps.items()
                      if c != 'rip' and pv is not None and c not in shadow)
    for c, (pv, flags, got) in ps.items():
        if pv is None:
            st['srcval_ref_absent'] += 1
            continue
        if c == 'rip':
            # rip is not a shadow-file register.  Its SOURCE value is the
            # address of the instruction itself, which the tracer never
            # publishes as a value and never needs to: the pairing already
            # carries it as the record's own pc.  Scoring it against the
            # last %ip DESTINATION -- a branch target -- would compare two
            # different facts and then absorb the difference as "both are
            # pointers", which is laundering.  It gets its own axis.
            st['ripsrc_probed'] += 1
            pin_ip = int(r['ip'])
            q_pc = int(q['pc'], 16)
            if pv != pin_ip:
                st['ripsrc_ref_inconsistent'] += 1
                note(valsig, 'ripsrc', (q['b'], q['c'], 'rip',
                                        'REFERENCE-SELF-INCONSISTENT',
                                        'UNACCOUNTED'), qj)
            elif (pin_ip - q_pc) in CODE_DELTAS:
                st['ripsrc_exact'] += 1
            else:
                st['ripsrc_mismatch'] += 1
                note(valsig, 'ripsrc', (q['b'], q['c'], 'rip',
                                        'CODE-DELTA-UNESTABLISHED',
                                        'UNACCOUNTED'), qj)
            continue
        if c in tainted:
            inherited = True
        if c not in shadow:
            st['srcval_unwitnessed'] += 1
            continue
        qv, qw = shadow[c]
        w = min(qw or 8, got, 8) or 8
        st['srcval_probed'] += 1
        how = value_agrees(qv, pv, w)
        if how == 'exact':
            st['srcval_exact'] += 1
        elif how == 'pointer':
            st['srcval_pointer'] += 1
            inherited = True
            tainted.add(c)
        else:
            st['srcval_mismatch'] += 1
            cat, direction = classify_value(c, qv, pv, w, inherited, q['b'])
            witness('srcval', q, pos, c, qv, pv, w, cat, direction)
            if direction == 'ORTHOGONAL':
                tainted.add(c)
                inherited = True
            elif direction == 'UNACCOUNTED':
                suf, root = prov_of(q, ps, c, unwitnessed)
                cat += suf
                anc = prov_charge(root, q, c, 'srcval', qv, pv, w)
                if anc is not None:
                    unexplained.setdefault(c, anc)
            note(valsig, 'srcval', (q['b'], q['c'], c, cat, direction), qj)

    # ---- axis 3: DESTINATION VALUES -------------------------------------
    is_rep_iteration = pos in repnext
    for c, (pv, flags, got) in pd.items():
        if pv is None:
            st['dstval_ref_absent'] += 1
            continue
        if c not in q['_dv']:
            if is_rep_iteration:
                # The tracer's settled REP contract (3205d7c1cc, format.rst):
                # a self-looping instruction publishes its destination writes
                # ONCE, on the entry that COMPLETES it; iterations 1..N-1
                # carry no write, and ABSENCE means "not produced yet".  PIN
                # emits one record per iteration, so the reference has a
                # per-iteration value the wire deliberately does not.
                st['dstval_rep_deferred'] += 1
                note(valsig, 'dstval_rep', (q['b'], q['c'], c,
                                            'REP-DEFERRED-WRITE',
                                            'ORTHOGONAL'), qj)
            else:
                st['dstval_tracer_absent'] += 1
                note(valsig, 'dstval_absent', (q['b'], q['c'], c), qj)
            continue
        qv, qw = q['_dv'][c]
        w = min(qw or 8, got, 8) or 8
        st['dstval_probed'] += 1
        how = value_agrees(qv, pv, w)
        if how == 'exact':
            st['dstval_exact'] += 1
        elif how == 'pointer':
            st['dstval_pointer'] += 1
            tainted.add(c)
        else:
            st['dstval_mismatch'] += 1
            cat, direction = classify_value(c, qv, pv, w, inherited, q['b'])
            witness('dstval', q, pos, c, qv, pv, w, cat, direction)
            if direction == 'ORTHOGONAL':
                tainted.add(c)
            elif direction == 'UNACCOUNTED':
                suf, root = prov_of(q, ps, c, unwitnessed)
                cat += suf
                anc = prov_charge(root, q, c, 'dstval', qv, pv, w)
                # This destination now differs with no rule to explain it,
                # whether the difference arose here or arrived through an
                # input.  Either way the NEXT reader of this register is a
                # descendant, not a second independent finding -- and it is
                # charged to the ORIGINAL root, not to this row.
                unexplained[c] = anc or (q['b'], q['c'], c, q['pc'])
                # ... and so is the next reader of any cell this instruction
                # stores it into.
                for a in q.get('sa', ()):
                    unexplained_mem[a >> MEMPAGE] = unexplained[c]
            note(valsig, 'dstval', (q['b'], q['c'], c, cat, direction), qj)

    if SYSFX.get('_regs'):
        sys_rows.append({'pos': pos, 'pc': q['pc'],
                         'regs': ','.join(sorted(set(SYSFX['_regs']))),
                         'performed': SYSFX['performed'],
                         'why': SYSFX['why'],
                         'ref_rcx': SYSFX['ref_rcx'], 'ref_r11': SYSFX['ref_r11'],
                         'ref_flags': SYSFX['ref_flags'],
                         'ref_next': SYSFX['ref_next'],
                         'trc_rcx': SYSFX['trc_rcx'], 'trc_r11': SYSFX['trc_r11'],
                         'trc_flags': SYSFX['trc_flags'],
                         'trc_next': SYSFX['trc_next']})

    # publish this instruction's destination writes into the shadow file
    for c, (qv, qw) in q['_sv'].items():
        shadow[c] = (qv, qw)
        kernel_written.discard(c)
        if inherited:
            tainted.add(c)
        # A destination the two runs AGREED on is no longer differing, so it
        # must stop being named as an ancestor -- otherwise one root would
        # be charged with every later row that happens to touch the register
        # it once passed through, which is the opposite failure to the one
        # this instrument exists to fix.
        if c in unexplained and c in pd and c in q['_dv']:
            pvv = pd[c][0]
            if pvv is not None:
                gw = min(qw or 8, pd[c][2], 8) or 8
                if value_agrees(q['_dv'][c][0], pvv, gw):
                    del unexplained[c]
    # a destination the tracer named WITHOUT a value invalidates the shadow
    # entry: the register changed and we do not know to what.
    for c in q['_d']:
        if c not in q['_sv']:
            shadow.pop(c, None)
            tainted.discard(c)
            unexplained.pop(c, None)
    # A syscall's result is written by the CPU loop, not by this or any
    # instruction, so nothing above can have published it.  Mark it, so the
    # next reader of that register is named rather than left unexplained.
    if q['b'] == SYSCALL_ENC:
        kernel_written.update(SYSCALL_KERNEL_WRITES)

# ---------------------------------------------------------------- 5. report
say("")
say("=== PIN ip - QEMU pc, measured over the pairing ===")
for d, c in code_hist.most_common(6):
    say("  %+#14x  %9d  %s" % (d, c, 'ESTABLISHED' if d in CODE_DELTAS
                               else 'below support'))

say("")
say("=== per-axis agreement over %d byte-identical instruction pairs ==="
    % st['pairs'])


def line(name, m, x, extra=''):
    tot = m + x
    say("  %-24s matched %10d  mismatched %8d  (%.5f%%)  %s"
        % (name, m, x, 100.0 * m / tot if tot else 0.0, extra))


line('src register set', st['srcset_match'], st['srcset_mismatch'])
line('dst register set', st['dstset_match'], st['dstset_mismatch'])
say("")
say("  dst register VALUE       probed %10d  exact %10d  same pointer under "
    "an ESTABLISHED delta %8d  mismatched %6d"
    % (st['dstval_probed'], st['dstval_exact'], st['dstval_pointer'],
       st['dstval_mismatch']))
say("  src register VALUE       probed %10d  exact %10d  same pointer under "
    "an ESTABLISHED delta %8d  mismatched %6d"
    % (st['srcval_probed'], st['srcval_exact'], st['srcval_pointer'],
       st['srcval_mismatch']))
say("  rip as a SOURCE          probed %10d  the instruction's own pc under "
    "an ESTABLISHED code delta %8d  mismatched %6d  reference "
    "self-inconsistent %d"
    % (st['ripsrc_probed'], st['ripsrc_exact'], st['ripsrc_mismatch'],
       st['ripsrc_ref_inconsistent']))
say("")
say("  not probed, and why (never counted as agreement):")
say("    reference named the register but captured no value : %d src / %d dst"
    % (st['srcval_ref_absent'], st['dstval_ref_absent']))
say("    tracer named the destination without a value       : %d"
    % st['dstval_tracer_absent'])
say("    REP iteration 1..N-1, write deferred by contract    : %d"
    % st['dstval_rep_deferred'])
say("    source had no producer on the compared path        : %d"
    % st['srcval_unwitnessed'])
say("    reference record over capacity (excluded whole)    : %d"
    % st['ref_overcapacity'])
say("    reference could not decode the encoding            : %d"
    % st['ref_decode_fail'])
say("    shadow register file cleared at a divergent region : %d times"
    % st['shadow_cleared'])

say("")
say("=== every disagreeing SET row, with a DIRECTION ===")
roll = collections.Counter()
for kind in ('srcset', 'dstset'):
    if not setsig[kind]:
        continue
    say("  -- %s --" % kind)
    for sig, n in setsig[kind].most_common(A.maxreport):
        enc, cap, only_p, only_q, direction = sig
        roll[direction] += n
        say("    %-18s %-10s %-34s %-34s %-16s %8d"
            % (enc[:18], cap[:10], only_p[:34], only_q[:34], direction, n))
for kind in ('refdecode', 'refcap'):
    for sig, n in setsig[kind].most_common(A.maxreport):
        say("    %-18s %-10s %s  %8d" % (sig[0][:18], sig[2][:10], kind, n))

say("")
say("=== every disagreeing VALUE row, with a CATEGORY and a DIRECTION ===")
vroll = collections.Counter()
for kind in ('dstval', 'srcval', 'ripsrc', 'dstval_rep'):
    if not valsig[kind]:
        continue
    say("  -- %s --" % kind)
    for sig, n in valsig[kind].most_common(A.maxreport):
        enc, cap, reg, cat, direction = sig
        vroll[direction] += n
        say("    %-18s %-10s %-10s %-46s %-14s %8d"
            % (enc[:18], cap[:10], reg, cat, direction, n))
for sig, n in valsig['dstval_absent'].most_common(A.maxreport):
    say("    %-18s %-10s %-10s reference has a value, tracer has none %8d"
        % (sig[0][:18], sig[1][:10], sig[2], n))

say("")
say("=== SYSCALL REGISTER EFFECTS, PER INSTANCE ===")
say("  Every syscall whose rcx / r11 / rflags disagreed, with the numbers the")
say("  verdict was taken from.  PERFORMED means each side's r11 equals ITS OWN")
say("  rflags and each side's rcx equals ITS OWN next-instruction address, so")
say("  both instruments carried out the write and the remaining difference")
say("  came IN.  NOT-PERFORMED names the check that failed and is counted as")
say("  TRACER-SUBSET.  Printed unconditionally: an aggregated row cannot say")
say("  which instance survived (#281 left two standing and #293 could not name")
say("  them without opening them).")
if not sys_rows:
    say("  (no syscall register disagreement in this pairing)")
for w in sys_rows:
    say("  pos=%-8d pc=%s  regs=%-12s %s%s"
        % (w['pos'], w['pc'], w['regs'],
           'PERFORMED' if w['performed'] else 'NOT-PERFORMED',
           '' if w['performed'] else ': ' + w['why']))
    say("      reference  rcx=%#x next-ip=%#x  r11=%#x rflags=%#x  r11==rflags %s"
        % (w['ref_rcx'] or 0, w['ref_next'], w['ref_r11'] or 0,
           w['ref_flags'] or 0, w['ref_r11'] == w['ref_flags']))
    say("      tracer     rcx=%#x next-pc=%#x  r11=%#x rflags=%#x  r11==rflags %s"
        % (w['trc_rcx'] or 0, w['trc_next'], w['trc_r11'] or 0,
           w['trc_flags'] or 0, w['trc_r11'] == w['trc_flags']))

say("")
say("=== THE UNACCOUNTED RESIDUE, RESOLVED TO ITS ROOTS ===")
say("  An UNACCOUNTED difference does not TAINT -- that rule stands, and is")
say("  what stops one defect from laundering everything downstream of it.")
say("  But it left the residue unreadable: a root and the two hundred rows")
say("  that only carried it forward were reported as peers.  Every")
say("  UNACCOUNTED row now names where its difference AROSE.  Its DIRECTION")
say("  is unchanged and it is still counted in the criterion.")
say("")
_desc = sum(r['desc'] for r in root_census.values())
_roots = sum(r['n'] for r in root_census.values())
say("  roots %d (over %d distinct (encoding, register) sites) "
    "| rows charged to a root %d" % (_roots, len(root_census), _desc))
say("")
say("  %-18s %-10s %-8s %-14s %8s %8s"
    % ('ROOT ENCODING', 'MNEMONIC', 'REG', 'FIRST PC', 'ROOTS', 'DESCEND'))
for key, r in sorted(root_census.items(),
                     key=lambda kv: (-(kv[1]['n'] + kv[1]['desc']), kv[0])):
    say("  %-18s %-10s %-8s %-14s %8d %8d"
        % (r['enc'][:18], r['mnem'][:10], r['reg'], r['pc'], r['n'],
           r['desc']))
    for wline in r.get('w', ()):
        say("        %s" % wline)
if not root_census:
    say("  (none)")

say("")
say("=== ROLL-UP ===")
say("  SET rows:   " + '  '.join("%s %d" % (k, v) for k, v in
                                 sorted(roll.items())) or "  SET rows: none")
say("  VALUE rows: " + '  '.join("%s %d" % (k, v) for k, v in
                                 sorted(vroll.items())) or "  VALUE rows: none")
bad = roll['UNACCOUNTED'] + roll['TRACER-SUBSET'] + \
    vroll['UNACCOUNTED'] + vroll['TRACER-SUBSET'] + st['dstval_tracer_absent']
say("  SUBSET + UNACCOUNTED (the criterion; must be 0): %d" % bad)

# ------------------------------------------------- 6. the CONTROL SUMMARY
# One line, every axis, machine-parsable.  A negative control is only
# evidence for the axis it REPORTS: a summary that omits `src register
# VALUE` cannot convict the src-VALUE axis no matter which field the
# mutation touched, because the propagation from the corrupted producer
# into the shadow register file is exactly what is unproven.  So every
# axis appears in every row, control and baseline alike.
SUMMARY = ("CONTROL SUMMARY  mutation=%-9s n_mut=%-7d pairs=%d"
           " | src-set matched=%d mismatched=%d"
           " | dst-set matched=%d mismatched=%d"
           " | dst-VALUE probed=%d exact=%d pointer=%d mismatched=%d"
           " | src-VALUE probed=%d exact=%d pointer=%d mismatched=%d"
           " | rip-src probed=%d exact=%d mismatched=%d"
           " | criterion=%d") % (
    A.mutate or 'baseline', N_MUT, st['pairs'],
    st['srcset_match'], st['srcset_mismatch'],
    st['dstset_match'], st['dstset_mismatch'],
    st['dstval_probed'], st['dstval_exact'], st['dstval_pointer'],
    st['dstval_mismatch'],
    st['srcval_probed'], st['srcval_exact'], st['srcval_pointer'],
    st['srcval_mismatch'],
    st['ripsrc_probed'], st['ripsrc_exact'], st['ripsrc_mismatch'],
    bad)
say("")
say(SUMMARY)
if A.summary:
    # Append-and-close per run: the previous artifact was truncated
    # mid-word because one long-lived handle held every row.
    with open(A.summary, 'a') as _f:
        _f.write(SUMMARY + '\n')
