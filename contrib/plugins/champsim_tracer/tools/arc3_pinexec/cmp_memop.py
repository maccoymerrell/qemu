#!/usr/bin/env python3
"""Memop cross-check: a champsim_tracer (.cst) correct-path stream against an
Intel PIN EXECUTION reference of the same program point.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

  usage: cmp_memop.py --pin memop.bin --qemu q.jsonl [--anchor N] [--out F]

The register arm (`compare.py`, the widened ChampSim `input_instr`) could
score memop COUNT and, as a per-region constant delta, memop ADDRESS.  It
carried no width and no value, so memop DATA -- the value actually read or
written -- was never scored against execution at all.  This scores all four:

    COUNT    loads and stores separately, against PIN's TRUE per-instruction
             counts (uncapped; the capacity of the record is carried in the
             record so an over-capacity instruction is visible, not silent)
    WIDTH    the access size in bytes
    ADDRESS  the effective address of each access
    DATA     the bytes read or written, as the little-endian integer of the
             accessed bytes -- the same encoding cst_decode prints for
             `ld=0x<value>/w<size>`

TWO MODELLED DIFFERENCES, both named rather than counted as disagreement:

  * TCG lowers a >16-byte vector access into 16-byte halves, so QEMU records
    two contiguous memops where PIN records one.  Contiguous equal-width QEMU
    memops are coalesced -- addresses, widths and VALUES all -- before the
    comparison, and the coalescing count is reported.

  * The two processes are different executions.  Their images load at the
    same addresses (a non-PIE static guest) but their stacks, environment
    blocks and mappings do not, so a pointer -- whether used as an address or
    stored as a VALUE -- differs by a constant per region.  Deltas are
    measured, not assumed: a delta is ESTABLISHED only if it has at least
    --minsupport witnesses, and anything else is reported as UNACCOUNTED with
    samples, never absorbed.

Every disagreement is reported with a direction:
    TRACER-SUPERSET   we record something true the reference omits
    TRACER-SUBSET     the reference records something we drop   (a DEFECT)
    ORTHOGONAL        different vocabulary for the same fact
    UNACCOUNTED       not yet interrogated                      (must be 0)
"""
import argparse
import collections
import json
import sys

import pinmemlib

AP = argparse.ArgumentParser()
AP.add_argument('--pin', required=True)
AP.add_argument('--qemu', required=True)
AP.add_argument('--pinrec', type=int, default=None)
AP.add_argument('--anchor', type=int, default=0)
AP.add_argument('--out', default=None)
AP.add_argument('--samples', default=None)
AP.add_argument('--kgram', type=int, default=16)
AP.add_argument('--window', type=int, default=20000)
AP.add_argument('--maxreport', type=int, default=25)
AP.add_argument('--minsupport', type=int, default=8,
                help='witnesses a PIN-QEMU pointer delta needs before it is '
                     'ESTABLISHED; below this the pair is UNACCOUNTED')
A = AP.parse_args()

OUT = open(A.out, 'w') if A.out else sys.stdout


def say(*a):
    print(*a, file=OUT)
    OUT.flush()


# ---------------------------------------------------------------- load QEMU
Q = []
with open(A.qemu) as f:
    for line in f:
        j = json.loads(line)
        j['_b'] = bytes.fromhex(j['b'])
        Q.append(j)
NQ = len(Q)
qb = [j['_b'] for j in Q]
say("QEMU correct-path instructions loaded: %d" % NQ)

P = pinmemlib.read_memop(A.pin, nrec=A.pinrec)
NP = len(P)
say("PIN memop records loaded: %d  (record %d bytes, capacity %d memops/dir, "
    "%d value bytes)" % (NP, pinmemlib.REC, pinmemlib.NMEM, pinmemlib.DBYTES))
pb = pinmemlib.rec_bytes(P)

over = int((P['n_ld'] > P['ld_rec']).sum() + (P['n_st'] > P['st_rec']).sum())
say("PIN records whose memops exceeded the record capacity: %d  "
    "(these are EXCLUDED from the per-memop tables and counted, never "
    "scored as agreement)" % over)

# ------------------------------------------------------------------- 1. walk
K, W = A.kgram, A.window


def kg(seq, i, n):
    if i + K > n:
        return None
    return b'|'.join(seq[i + t] for t in range(K))


i, j = A.anchor, 0
pairs = []
regions = []
while i < NP and j < NQ:
    if pb[i] == qb[j]:
        pairs.append((i, j))
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
        regions.append((i, j, NP - i, NQ - j))
        break
    _, ni, nj = best
    regions.append((i, j, ni - i, nj - j))
    i, j = ni, nj

say("lockstep walk: %d byte-identical pairs, %d divergent regions"
    % (len(pairs), len(regions)))
span_q = (pairs[-1][1] - pairs[0][1] + 1) if pairs else 0
say("compared span: QEMU %d instructions; byte-identical %d (%.6f%%)"
    % (span_q, len(pairs), 100.0 * len(pairs) / max(1, span_q)))

# ------------------------------------------------- 2. build the memop lists
def coalesce_q(addrs, widths, vals):
    """Fold TCG's 16-byte halves of one wide access back into one memop.

    Returns (list of (addr, width, value), n_merged).  The value of a merged
    pair is the little-endian integer of the concatenated bytes, which is
    exactly what the single wide access read or wrote."""
    trip = sorted(zip(addrs, widths, vals))
    out = []
    merged = 0
    for a, w, v in trip:
        if out:
            pa, pw, pv = out[-1]
            if a == pa + pw and w == pw:
                out[-1] = (pa, pw + w, pv | (v << (8 * pw)))
                merged += 1
                continue
            if a == pa and w == pw and v == pv:
                merged += 1          # the renderer printed one memop twice
                continue
        out.append((a, w, v))
    return out, merged


def q_memops(q, tag):
    """(addr, width, value) triples for one direction, in address order.

    The wire's dyn-param count is authoritative for HOW MANY memops there
    are; the operand renderer prints an address once per micro-operation
    group, so `la` can repeat an address that is one memop."""
    addrs = q['la'] if tag == 'ld' else q['sa']
    widths = q['lw'] if tag == 'ld' else q['sw']
    vals = q['lv'] if tag == 'ld' else q['sv']
    n = len(widths)
    ua = list(dict.fromkeys(addrs))     # order-preserving unique
    if len(ua) != n or len(vals) != n:
        return None, 0                  # cannot pair address to value
    return coalesce_q(ua, widths, vals)


def p_memops(r, tag):
    n = int(r['ld_rec'] if tag == 'ld' else r['st_rec'])
    ea = r['ld_ea'] if tag == 'ld' else r['st_ea']
    sz = r['ld_sz'] if tag == 'ld' else r['st_sz']
    dat = r['ld_data'] if tag == 'ld' else r['st_data']
    got = r['ld_got'] if tag == 'ld' else r['st_got']
    out = [(int(ea[k]), int(sz[k]), pinmemlib.memop_value(dat[k], int(got[k])))
           for k in range(n)]
    out.sort()
    return out


# ---- pass 1: measure the pointer deltas the two processes differ by -------
delta_hist = collections.Counter()
for (pi, qj) in pairs:
    r = P[pi]
    q = Q[qj]
    for tag in ('ld', 'st'):
        qm, _ = q_memops(q, tag)
        pm = p_memops(r, tag)
        if qm is None or len(qm) != len(pm):
            continue
        for (qa, qw, qv), (pa, pw, pv) in zip(qm, pm):
            delta_hist[pa - qa] += 1

# A delta is not established merely by being frequent.  The two processes
# differ by a PIECEWISE-CONSTANT map: each mapping (image, stack, environment
# block, vDSO, brk) moved as a whole, so the address ranges that distinct
# deltas cover must be DISJOINT.  Accepting any frequent delta instead lets a
# systematic address error establish itself -- a tracer that shifted every
# stack access by 8 bytes would mint its own "established" delta and score
# 100%.  That is not a hypothetical: it is what the `addr` negative control
# measured before this constraint existed.
#
# So: sort deltas by witness count, and accept one only if the QEMU address
# range it covers does not overlap a range already accepted.  Delta 0 is
# always accepted -- it is the identically-placed mapping.
drange = collections.defaultdict(lambda: [None, None])
for (pi, qj) in pairs:
    r = P[pi]
    q = Q[qj]
    for tag in ('ld', 'st'):
        qm, _ = q_memops(q, tag)
        pm = p_memops(r, tag)
        if qm is None or len(qm) != len(pm):
            continue
        for (qa, _w, _v), (pa, _pw, _pv) in zip(qm, pm):
            rg = drange[pa - qa]
            rg[0] = qa if rg[0] is None else min(rg[0], qa)
            rg[1] = qa if rg[1] is None else max(rg[1], qa)

ESTAB = set()
accepted_ranges = []
rejected = []
for d, c in sorted(delta_hist.items(), key=lambda kv: (-kv[1], kv[0])):
    if c < A.minsupport and d != 0:
        continue
    lo, hi = drange[d]
    if any(not (hi < alo or lo > ahi) for alo, ahi in accepted_ranges):
        rejected.append((d, c, lo, hi))
        continue
    ESTAB.add(d)
    accepted_ranges.append((lo, hi))
if 0 not in ESTAB:
    ESTAB.add(0)

say("")
say("=== PIN-QEMU pointer deltas measured over the paired memops ===")
say("  distinct deltas seen: %d;  ESTABLISHED (>= %d witnesses AND covering "
    "an address range disjoint from every stronger delta): %d"
    % (len(delta_hist), A.minsupport, len(ESTAB)))
for d, c in delta_hist.most_common(14):
    lo, hi = drange[d]
    if d in ESTAB:
        why = 'ESTABLISHED'
    elif c < A.minsupport:
        why = 'below support'
    else:
        why = 'REJECTED: range overlaps a stronger delta'
    say("  %+#20x  %8d  [%#14x .. %#14x]  %s" % (d, c, lo, hi, why))
if rejected:
    say("  deltas rejected for range overlap: %d  (their memops are scored "
        "UNACCOUNTED, not absorbed)" % len(rejected))

# ---- the regions the two runs share, measured from the address evidence ---
# An address whose PIN-QEMU delta is 0 is in a mapping both runs placed
# identically -- for a non-PIE static guest that is the image.  Anything with
# a nonzero delta is in a per-process mapping (stack, environment block,
# vDSO, brk), whose CONTENT is per-process by construction.
img_lo = img_hi = None
for (pi, qj) in pairs:
    r = P[pi]
    q = Q[qj]
    for tag in ('ld', 'st'):
        qm, _ = q_memops(q, tag)
        pm = p_memops(r, tag)
        if qm is None or len(qm) != len(pm):
            continue
        for (qa, _w, _v), (pa, _pw, _pv) in zip(qm, pm):
            if pa - qa == 0:
                img_lo = qa if img_lo is None else min(img_lo, qa)
                img_hi = qa if img_hi is None else max(img_hi, qa)
pc_lo = min(int(q['pc'], 16) for q in Q)
pc_hi = max(int(q['pc'], 16) for q in Q)
say("")
say("=== regions measured from the evidence ===")
say("  identically-placed (delta 0) data addresses: [%#x .. %#x]"
    % (img_lo or 0, img_hi or 0))
say("  executed PC range (a value in here is a CODE POINTER): [%#x .. %#x]"
    % (pc_lo, pc_hi))

FS28 = '64488b042528000000'
PTR_LO = 0x7f0000000000          # every per-process mapping in this run
PTR_HI = 1 << 48

# Byte addresses, in the identically-placed image, whose CONTENT the two runs
# have already been SEEN to differ at.  A later read of such a byte inherits
# the difference; that is propagation of a process-state difference, not a
# fresh disagreement.  Populated as the scoring pass walks the stream in
# order, so a cell can only explain reads that come AFTER the write.
diff_cells = set()

# Byte addresses the compared span has been SEEN to write on the
# byte-identical path SINCE THE LAST DIVERGENT REGION.  Crossing a divergence
# means instructions ran that this comparison did not observe, so every
# witness is void from that point: a cell that agreed before a divergence may
# have been rewritten differently inside it.  The set is therefore cleared at
# every region boundary.
witnessed_cells = set()


def touches_diff(a, w):
    return any((a + k) in diff_cells for k in range(w))


def witnessed(a, w):
    return all((a + k) in witnessed_cells for k in range(w))


def classify(tag, enc, qa, pa, qw, qv, pv, loads_agreed, qloads):
    """Name the mechanism behind a cross-run value difference.

    Every rule is decided from measured evidence in these two streams -- an
    address the runs place differently, a value that is a pointer into a
    differently-placed mapping, a cell whose content the runs were already
    seen to differ at.  A difference no rule explains is UNACCOUNTED and is
    adjudicated by hand rather than absorbed."""
    if FS28 in enc:
        return ('TLS-CANARY', 'ORTHOGONAL')
    if pa != qa:
        return ('PROCESS-PRIVATE-REGION', 'ORTHOGONAL')
    if img_lo is not None and img_lo <= qa <= img_hi:
        if pc_lo <= qv <= pc_hi and pc_lo <= pv <= pc_hi:
            return ('GOT-IFUNC', 'ORTHOGONAL')
    if qw == 8 and (pv - qv) in ESTAB and pv != qv:
        return ('MAPPING-POINTER', 'ORTHOGONAL')
    if qw == 8 and PTR_LO <= qv < PTR_HI and PTR_LO <= pv < PTR_HI:
        return ('POINTER-VALUED', 'ORTHOGONAL')
    # Propagation: this access reads, or this store was computed from, a cell
    # the two runs were already seen to hold different bytes in.
    if tag == 'ld' and touches_diff(qa, qw):
        return ('INHERITED-DIFFERING-CELL', 'ORTHOGONAL')
    if tag == 'ld' and not witnessed(qa, qw):
        # Nothing on the compared path produced these bytes: they were written
        # before the window opened, or inside a divergent region.  Their
        # content is process state this comparison never watched being made,
        # and reading it faithfully is what a tracer is supposed to do.
        return ('UNWITNESSED-CELL', 'ORTHOGONAL')
    if tag == 'st':
        if any(touches_diff(a_, w_) for a_, w_ in qloads):
            return ('INHERITED-DIFFERING-CELL', 'ORTHOGONAL')
        if any(not witnessed(a_, w_) for a_, w_ in qloads):
            return ('UNWITNESSED-CELL', 'ORTHOGONAL')
        if loads_agreed:
            # Either the instruction read no memory at all, or every byte it
            # read AGREED with the reference.  The memop layer therefore had
            # nothing to get wrong: the stored value came from a register, and
            # the difference is upstream of memop attribution -- it belongs to
            # the register arm, where CPUID / auxv / environment enter.
            return ('REGISTER-SOURCED', 'ORTHOGONAL')
    return ('UNACCOUNTED', 'UNACCOUNTED')


# ---- pass 2: score ------------------------------------------------------
st = collections.Counter()
dataclass = collections.Counter()
addrclass = collections.Counter()
mism = collections.defaultdict(collections.Counter)
sample = {}
CAPB = 8 * pinmemlib.DBYTES


def note(kind, sig, qj):
    mism[kind][sig] += 1
    sample.setdefault((kind, sig), qj)


def value_agrees(qv, pv, w):
    """Exact, or the same pointer under an established delta.

    A stored pointer is the same architectural fact in both runs; it differs
    by exactly the delta the two processes' mappings differ by.  Only deltas
    that the ADDRESS evidence already established are admitted, so this
    cannot launder an arbitrary value difference."""
    if qv == pv:
        return 'exact'
    if w == 8 and (pv - qv) in ESTAB:
        return 'pointer'
    return None


prev_qj = None
for (pi, qj) in pairs:
    r = P[pi]
    q = Q[qj]
    st['pairs'] += 1
    if r['n_ld'] > r['ld_rec'] or r['n_st'] > r['st_rec']:
        st['overcapacity_excluded'] += 1
        continue
    if prev_qj is not None and qj != prev_qj + 1:
        # A divergent region was crossed: unobserved instructions ran, so no
        # cell's provenance is witnessed any more.
        witnessed_cells.clear()
        st['witness_resets'] += 1
    prev_qj = qj
    _lm, _ = q_memops(q, 'ld')
    insn_loads = [(a_, w_) for a_, w_, _v in (_lm or [])]
    insn_load_ok = True
    for tag, qn in (('ld', 'nl'), ('st', 'ns')):
        qm, nmerged = q_memops(q, tag)
        pm = p_memops(r, tag)
        pn = int(r['n_ld'] if tag == 'ld' else r['n_st'])
        if qm is None:
            st[tag + '_unpairable'] += 1
            note(tag + '_unpairable', (q['b'], q['m'], q['c'],
                 'dyn=%d addrs=%d vals=%d' % (len(q['lw' if tag == 'ld' else 'sw']),
                                              len(set(q['la' if tag == 'ld' else 'sa'])),
                                              len(q['lv' if tag == 'ld' else 'sv']))), qj)
            continue
        if nmerged:
            st[tag + '_coalesced'] += nmerged
        # ---------------- COUNT ----------------
        if len(qm) == pn:
            st[tag + '_count_match'] += 1
        else:
            st[tag + '_count_mismatch'] += 1
            note(tag + '_count', (q['b'], q['m'], q['c'],
                 'pin=%d qemu=%d(raw %d, coalesced %d)'
                 % (pn, len(qm), q[qn], nmerged)), qj)
            continue
        # ------- ADDRESS / WIDTH / DATA, memop by memop -------
        for (qa, qw, qv), (pa, pw, pv) in zip(qm, pm):
            d = pa - qa
            if d == 0:
                st[tag + '_addr_exact'] += 1
            elif d in ESTAB:
                st[tag + '_addr_shifted'] += 1
            else:
                st[tag + '_addr_unaccounted'] += 1
                if img_lo is None or not (img_lo <= qa <= img_hi):
                    acls = 'PROCESS-PRIVATE-REGION'
                elif (PTR_LO <= qv < PTR_HI and PTR_LO <= pv < PTR_HI):
                    # An identically-placed array indexed by a value the two
                    # runs derived from differently-placed mappings: the slot
                    # written differs because the INDEX does.
                    acls = 'PROCESS-DERIVED-INDEX'
                else:
                    acls = 'UNACCOUNTED'
                addrclass[(tag, acls)] += 1
                note(tag + '_addr', (q['b'], q['m'], q['c'],
                     'delta=%+#x' % d, acls), qj)
            if qw == pw:
                st[tag + '_width_match'] += 1
            else:
                st[tag + '_width_mismatch'] += 1
                note(tag + '_width', (q['b'], q['m'], q['c'],
                     'pin=%d qemu=%d' % (pw, qw)), qj)
                continue
            if tag == 'st' and pa == qa:
                for _k in range(qw):
                    witnessed_cells.add(qa + _k)
            if qw > pinmemlib.DBYTES:
                st[tag + '_data_uncaptured'] += 1
                continue
            v = value_agrees(qv, pv, qw)
            if v is not None and pa == qa:
                # Seen to hold the SAME bytes now: it is no longer a cell the
                # two runs differ at.
                for _k in range(qw):
                    diff_cells.discard(qa + _k)
            if v == 'exact':
                st[tag + '_data_exact'] += 1
            elif v == 'pointer':
                st[tag + '_data_pointer'] += 1
            else:
                st[tag + '_data_mismatch'] += 1
                if tag == 'ld':
                    insn_load_ok = False
                cls, direction = classify(tag, q['b'], qa, pa, qw, qv, pv,
                                          insn_load_ok, insn_loads)
                # A cell the two runs were seen to hold different bytes in --
                # from either direction -- explains every later read of it.
                if pa == qa:
                    for _k in range(qw):
                        diff_cells.add(qa + _k)
                dataclass[(tag, cls, direction)] += 1
                note(tag + '_data', (q['b'], q['m'], q['c'],
                     'w=%d' % qw, cls), qj)

# ------------------------------------------------------------------ report
say("")
say("=== memop agreement over %d byte-identical instruction pairs ==="
    % st['pairs'])
say("  over-capacity instructions excluded: %d" % st['overcapacity_excluded'])


def line(name, m, x):
    t = m + x
    say("  %-30s matched %10d  mismatched %8d  (%9.5f%%)"
        % (name, m, x, 100.0 * m / max(1, t)))


for tag, human in (('ld', 'load'), ('st', 'store')):
    say("")
    line('%s memop COUNT (per insn)' % human,
         st[tag + '_count_match'], st[tag + '_count_mismatch'])
    say("      QEMU 16B halves coalesced into one wide access: %d"
        % st[tag + '_coalesced'])
    say("      instructions whose address/value lists could not be paired: %d"
        % st[tag + '_unpairable'])
    nadr = st[tag + '_addr_exact'] + st[tag + '_addr_shifted']
    line('%s memop ADDRESS' % human, nadr, st[tag + '_addr_unaccounted'])
    say("      exact (same address in both runs): %d;  shifted by an "
        "ESTABLISHED delta: %d" % (st[tag + '_addr_exact'],
                                   st[tag + '_addr_shifted']))
    line('%s memop WIDTH' % human,
         st[tag + '_width_match'], st[tag + '_width_mismatch'])
    ndat = st[tag + '_data_exact'] + st[tag + '_data_pointer']
    line('%s memop DATA' % human, ndat, st[tag + '_data_mismatch'])
    say("      exact bytes: %d;  same pointer under an ESTABLISHED delta: %d;"
        "  wider than the reference captured: %d"
        % (st[tag + '_data_exact'], st[tag + '_data_pointer'],
           st[tag + '_data_uncaptured']))

say("")
say("=== every disagreeing memop, with a CATEGORY and a DIRECTION ===")
say("  %-6s %-24s %-16s %8s" % ('kind', 'category', 'direction', 'memops'))
tot_unacc = 0
for (tag, cls, direction), c in sorted(dataclass.items(),
                                      key=lambda kv: -kv[1]):
    say("  %-6s %-24s %-16s %8d" % (tag + ' DATA', cls, direction, c))
    if direction == 'UNACCOUNTED':
        tot_unacc += c
for (tag, cls), c in sorted(addrclass.items(), key=lambda kv: -kv[1]):
    d = 'UNACCOUNTED' if cls == 'UNACCOUNTED' else 'ORTHOGONAL'
    say("  %-6s %-24s %-16s %8d" % (tag + ' ADDR', cls, d, c))
    if d == 'UNACCOUNTED':
        tot_unacc += c
say("")
say("  UNACCOUNTED memops: %d   (the acceptance bar for this phase is 0)"
    % tot_unacc)
say("  TRACER-SUBSET (a fact the reference has and we drop): %d"
    % (st['ld_count_mismatch'] + st['st_count_mismatch']
       + st['ld_width_mismatch'] + st['st_width_mismatch']))

if A.samples:
    with open(A.samples, 'w') as fh:
        for (kind, sig), qj in sample.items():
            rec = {k: v for k, v in Q[qj].items() if not k.startswith('_')}
            fh.write(json.dumps({'kind': kind, 'sig': list(map(str, sig)),
                                 'q': qj, 'rec': rec}) + '\n')

for kind in sorted(mism):
    tot = sum(mism[kind].values())
    say("")
    say("=== mismatch signatures: %s (%d distinct, %d memops/instructions) ==="
        % (kind, len(mism[kind]), tot))
    for sig, c in mism[kind].most_common(A.maxreport):
        say("  %8d  q=%-9d %s" % (c, sample[(kind, sig)], sig))
    if len(mism[kind]) > A.maxreport:
        say("  ... %d more signatures" % (len(mism[kind]) - A.maxreport))
