#!/usr/bin/env python3
"""
ARC 3 -- does one OPCODE ROW stand for encodings that DISAGREE about dataflow?

THE QUESTION, AND WHY IT DECIDES WHETHER THE DENOMINATOR IS RIGHT
=================================================================
The four-ISA denominator is 14,847 OPCODE rows, not encodings, and every row
was proven with ONE representative encoding.  A row therefore stands in for a
much larger encoding space, and the claim it carries -- "the tracer captures
this instruction's operands" -- is only as good as the assumption that every
encoding under the row behaves the same way.

That assumption is measurable, and this measures it:

  1.  BIT-FLIP PROBE.  Flip each bit of the representative encoding, one at a
      time, and decode.  A bit whose flip keeps the same mnemonic AND the same
      instruction length is a FREE bit of the row -- an operand, an immediate,
      a register selector.  A bit whose flip changes the mnemonic, changes the
      length or stops decoding is FIXED.  This is an OBSERVED decode, not a
      table lookup, and it needs no per-ISA mask table -- which matters,
      because three of the four denominators do not carry one.

  2.  MULTIPLICITY.  2^(free bits) is how many encodings the row covers, and
      the extremes of that distribution are what "the denominator is opcodes,
      not encodings" costs.  It is a BOUND, not an exact count: bits interact,
      and on a variable-length ISA the length constraint hides every encoding
      of the same instruction that is spelled with a different prefix or
      addressing mode.  Both directions are stated with the number.

  3.  DATAFLOW INVARIANCE.  Sample K encodings that vary only the free bits,
      keep those that still decode as the same mnemonic at the same length,
      and compare their STRUCTURAL dataflow signature -- the tracer's generic
      opcode, its branch class, its atomicity, its load and store counts, its
      lane-mask kind, and the register CLASSES it reads and writes.  Register
      IDENTITY is deliberately not in the signature: `add x1, x2, x3` and
      `add x4, x5, x6` are the same dataflow and a signature that separated
      them would report every row as disagreeing.

A row whose accepted samples produce MORE THAN ONE signature is a row whose
encodings disagree about dataflow -- and for that row the denominator is the
wrong unit, because one probe of it validated one behaviour out of several.

CONTROL
=======
``--falsify=OPCODE_ID`` corrupts the fields view of one sampled encoding of
that row -- one extra load -- and the run FAILS unless that row is then
reported as DISAGREE.  A disagreement detector nobody has watched fire
vouches for nothing, which is this project's dominant failure mode.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import random
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

#: the denominator of each ISA, and the columns that carry the row id, the
#: mnemonic and the representative encoding.  The four tables were written
#: independently and spell their columns differently; that is all this records.
_TABLES = {
    'x86_64':  ('x86_64/attrib.tsv',  '#opcode_id', 'mnemonic',
                'encoding_hex'),
    'aarch64': ('aarch64/attrib.tsv', 'opcode_id', 'mnemonic', 'hex'),
    'riscv64': ('riscv64/attrib.tsv', 'opcode_id', 'mnemonic', 'hex'),
    'mipsel':  ('mipsel/attrib.tsv',  '#opcode_id', 'mnemonic',
                'encoding_hex_le'),
}

_DIGITS = re.compile(r'\d+$')

#: The ONLY fold: the members of one register FILE onto the file.  Stripping
#: the trailing digits already does that for `REG_GPR13`, `REG_FPR2`,
#: `REG_VEC7` and every other indexed family; this table adds the five
#: architectural ALIASES the integer file is also spelled with, because
#: `add $t0,$t1,$sp` and `add $t0,$t1,$t2` read the same file and differ only
#: in which register of it they name.  That is operand identity, resolved
#: dynamically per instruction, and treating it as a dataflow disagreement
#: would report every row of every ISA as disagreeing while saying nothing.
#:
#: NOTHING ELSE IS FOLDED.  `REG_SYS`, `REG_SYSMMU`, `REG_SYSDBG`, `REG_FCSR`
#: and the rest are SEPARATE architectural state with separate generic ids, so
#: an encoding that reaches one where its row's representative reached another
#: really is touching different state -- which is precisely what this
#: measurement is for.
_FILE = {
    'REG_ZERO': 'REG_GPR', 'REG_SP': 'REG_GPR', 'REG_LR': 'REG_GPR',
    'REG_FP_REG': 'REG_GPR',
}


def reg_file(name):
    """REG_GPR13 -> REG_GPR.  The register FILE, never the register."""
    base = _DIGITS.sub('', name)
    return _FILE.get(base, base)


def signature(row):
    """TIER-1: the dataflow signature that operand identity cannot move.

    Everything here is a property of the INSTRUCTION -- what it is, whether
    it branches, whether it is atomic, how many memory accesses it makes,
    which lane-mask model applies, and which register FILES it reads and
    writes.  Nothing here changes because a different register was named.
    """
    src = tuple(sorted(set(
        reg_file(x) for x in row['f_src'].split(',') if x and x != '-')))
    dst = tuple(sorted(set(
        reg_file(x) for x in row['f_dst'].split(',') if x and x != '-')))
    return (row['f_opcode'], row['f_branch'], row['f_cond'], row['f_atomic'],
            row['f_loads'], row['f_stores'], row['f_lanekind'], src, dst)


def arity(row):
    """TIER-2: how many operand slots survived, per file.

    Reported apart from TIER-1 and never as a defect on its own: when two
    operand fields name the SAME register the dependency set holds one
    element instead of two, so this moves for a reason that is correct
    behaviour rather than a disagreement about what the instruction does.
    """
    src = tuple(sorted(collections.Counter(
        reg_file(x) for x in row['f_src'].split(',') if x and x != '-'
    ).items()))
    dst = tuple(sorted(collections.Counter(
        reg_file(x) for x in row['f_dst'].split(',') if x and x != '-'
    ).items()))
    return (src, dst)


def batch(isaxcheck, isa, encodings):
    """{hex: {column: value}} for every encoding, one process for the lot."""
    if not encodings:
        return {}
    p = subprocess.run([isaxcheck, '--isa=' + isa, '--batch'],
                       input=''.join(h + '\n' for h in encodings).encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise SystemExit('isaxcheck --batch exit %d: %s'
                         % (p.returncode,
                            p.stderr.decode('utf-8', 'replace')[-600:]))
    lines = p.stdout.decode('utf-8', 'replace').splitlines()
    hdr = lines[0].split('\t')
    out = {}
    for line in lines[1:]:
        f = line.split('\t')
        if len(f) < len(hdr):
            continue
        out[f[0]] = dict(zip(hdr, f))
    return out


def flip(h, bit):
    b = bytearray.fromhex(h)
    b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b).hex()


def vary(h, freebits, rng):
    b = bytearray.fromhex(h)
    for bit in freebits:
        if rng.getrandbits(1):
            b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b).hex()


def load_rows(cov, isa, limit):
    path, idc, mnc, hxc = _TABLES[isa]
    full = os.path.join(cov, path)
    if not os.path.exists(full):
        raise SystemExit('no denominator at %s' % full)
    rows = []
    with open(full) as fh:
        hdr = fh.readline().rstrip('\n').split('\t')
        for c in (idc, mnc, hxc):
            if c not in hdr:
                raise SystemExit('%s has no %r column; the table changed and '
                                 'this measurement would read the wrong field'
                                 % (path, c))
        i, m, x = hdr.index(idc), hdr.index(mnc), hdr.index(hxc)
        for line in fh:
            f = line.rstrip('\n').split('\t')
            if len(f) <= max(i, m, x) or not f[x]:
                continue
            try:
                bytearray.fromhex(f[x])
            except ValueError:
                continue
            rows.append((f[i], f[m], f[x]))
    if limit:
        rows = rows[:limit]
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True, choices=sorted(_TABLES))
    ap.add_argument('--isaxcheck', required=True)
    ap.add_argument('--cov', default='/mnt/md0/QEMU/cst_runs/_arc3_cov')
    ap.add_argument('--samples', type=int, default=24,
                    help='encodings sampled per row, over its free bits')
    ap.add_argument('--seed', type=int, default=4242)
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--tsv')
    ap.add_argument('--falsify', help='opcode id whose sample is corrupted; '
                                      'the run FAILS if that row is not then '
                                      'reported DISAGREE')
    a = ap.parse_args()
    rng = random.Random(a.seed)

    rows = load_rows(a.cov, a.isa, a.limit)
    if not rows:
        raise SystemExit('the denominator produced no usable rows')

    # ---- stage 0: the representative encodings themselves.
    base = batch(a.isaxcheck, a.isa, sorted(set(h for _i, _m, h in rows)))

    # ---- stage 1: the bit-flip probe.
    probes, owner = [], {}
    for rid, _mn, h in rows:
        nb = len(h) // 2
        for bit in range(8 * nb):
            e = flip(h, bit)
            probes.append(e)
            owner.setdefault(e, []).append((rid, h, bit))
    flips = batch(a.isaxcheck, a.isa, sorted(set(probes)))

    free = collections.defaultdict(list)
    for rid, _mn, h in rows:
        b0 = base.get(h)
        if not b0 or b0['b_ok'] != '1':
            continue
        for bit in range(8 * (len(h) // 2)):
            r = flips.get(flip(h, bit))
            if (r and r['b_ok'] == '1' and r['b_mnem'] == b0['b_mnem']
                    and r['b_sz'] == b0['b_sz']):
                free[rid].append(bit)

    # ---- stage 2: sample the free space and compare signatures.
    samples, sowner = [], collections.defaultdict(list)
    for rid, _mn, h in rows:
        fb = free.get(rid) or []
        if not fb:
            continue
        seen = set()
        for _k in range(a.samples):
            e = vary(h, fb, rng)
            if e in seen:
                continue
            seen.add(e)
            samples.append(e)
            sowner[rid].append(e)
    got = batch(a.isaxcheck, a.isa, sorted(set(samples)))

    # ---- stage 3: sibling membership.
    #
    # A sampled encoding varies only the row's OWN free bits, so it always
    # satisfies that row's fixed pattern -- but the denominator may carry a
    # SECOND row, of the same mnemonic, whose fixed pattern it ALSO satisfies.
    # When it does, the behaviour it exhibits is one the denominator already
    # separated, and the row is not too coarse: the encoding simply belongs to
    # the sibling.  `abs` on aarch64 is the case that forced this to be
    # mechanical rather than argued -- ABS_asisdmisc_R and ABS_asimdmisc_R are
    # both rows, the Q bit is free by the flip probe, and a sample that flips
    # it lands in the sibling with the sibling's lane-mask kind.
    #
    # A disagreeing sample that satisfies NO other row's pattern is the real
    # finding: nothing in the denominator stands for what it does.
    # Keyed by the DECODED mnemonic, never by the table's own spelling: XED
    # calls it `MOV` and Capstone calls it `movq`, and a sibling lookup that
    # used the table column found no siblings at all on x86_64 while finding
    # them on the three ISAs whose tables happen to agree with Capstone.
    bymnem = collections.defaultdict(list)
    for rid, _mn, h in rows:
        b0 = base.get(h)
        if b0 and b0['b_ok'] == '1':
            bymnem[b0['b_mnem']].append(rid)
    fixedpat = {}
    for rid, _mn, h in rows:
        nbits = 8 * (len(h) // 2)
        fb = set(free.get(rid) or ())
        val = int.from_bytes(bytearray.fromhex(h), 'little')
        mask = 0
        for b in range(nbits):
            if b not in fb:
                mask |= 1 << b
        fixedpat[rid] = (mask, val & mask, nbits)

    def sibling_of(rid, mnem, enc):
        """Another row of the same mnemonic whose fixed pattern ``enc`` fits."""
        v = int.from_bytes(bytearray.fromhex(enc), 'little')
        for other in bymnem.get(mnem, ()):
            if other == rid or other not in fixedpat:
                continue
            mask, want, nbits = fixedpat[other]
            if nbits != 8 * (len(enc) // 2):
                continue
            if (v & mask) == want:
                return other
        return None

    # ``--falsify=auto`` picks the subject rather than making the caller
    # guess one.  A row is usable only if it has an accepted sample the
    # SIBLING RULE cannot explain away -- on aarch64 every sample of `abs`
    # fits one of its four sibling rows, so naming that row by hand stages a
    # control that cannot possibly fire and reads as a blind detector.
    if a.falsify == 'auto':
        a.falsify = None
        for rid, _mn, h in rows:
            b0 = base.get(h)
            if not b0 or b0['f_ok'] != '1':
                continue
            cand = [e for e in sowner.get(rid, ())
                    if (got.get(e, {}).get('b_ok') == '1'
                        and got[e].get('f_ok') == '1'
                        and got[e]['b_mnem'] == b0['b_mnem']
                        and got[e]['b_sz'] == b0['b_sz']
                        and sibling_of(rid, b0['b_mnem'], e) is None)]
            if len(cand) >= 2:
                a.falsify = rid
                break
        if a.falsify is None:
            sys.stderr.write('REFUSING: no row on this ISA can carry the '
                             'falsifier, so the detector cannot be watched '
                             'fire and its zero means nothing\n')
            return 2

    fals_fired = False
    disagree, crossed, per_row = [], [], {}
    for rid, _mn, h in rows:
        b0 = base.get(h)
        if not b0 or b0['f_ok'] != '1':
            continue
        sigs = collections.defaultdict(list)
        ars = set()
        sigs[signature(b0)].append(h)
        ars.add(arity(b0))
        # The falsifier must land on a sample the SIBLING RULE cannot explain
        # away, or the control proves nothing about the detector: a corrupted
        # encoding that also fits a sibling row's fixed pattern is filed as
        # CROSSED, which is exactly the correct behaviour and exactly not a
        # demonstration that DISAGREE can be reported.
        fals_target = None
        if a.falsify and rid == a.falsify:
            for e in sowner.get(rid, ()):
                r = got.get(e)
                if not (r and r['b_ok'] == '1' and r['f_ok'] == '1'
                        and r['b_mnem'] == b0['b_mnem']
                        and r['b_sz'] == b0['b_sz']):
                    continue
                if sibling_of(rid, b0['b_mnem'], e) is None:
                    fals_target = e
                    break
        for e in sowner.get(rid, ()):
            r = got.get(e)
            if not (r and r['b_ok'] == '1' and r['f_ok'] == '1'
                    and r['b_mnem'] == b0['b_mnem']
                    and r['b_sz'] == b0['b_sz']):
                continue
            if e == fals_target and not fals_fired:
                r = dict(r)
                r['f_loads'] = str(int(r['f_loads']) + 1)
                fals_fired = True
            sigs[signature(r)].append(e)
            ars.add(arity(r))
        per_row[rid] = (len(free.get(rid) or []),
                        sum(len(v) for v in sigs.values()), len(sigs),
                        len(ars))
        if len(sigs) > 1:
            # The row's OWN signature is the one its representative produced.
            own = signature(b0)
            unexplained = {}
            for sig, encs in sigs.items():
                if sig == own:
                    continue
                rest = [e for e in encs
                        if sibling_of(rid, b0['b_mnem'], e) is None]
                if rest:
                    unexplained[sig] = rest
            if unexplained:
                unexplained[own] = sigs[own]
                disagree.append((rid, b0['b_mnem'], unexplained))
            else:
                crossed.append((rid, b0['b_mnem'], len(sigs) - 1))

    # ---------------------------------------------------------------- report
    out, w = [], None
    w = out.append
    w('=' * 74)
    w('ARC 3 -- ENCODINGS PER OPCODE ROW, AND WHETHER THEY AGREE  --  %s'
      % a.isa)
    w('=' * 74)
    w('')
    w('rows in the denominator                     %d' % len(rows))
    w('rows whose representative encoding decodes  %d'
      % sum(1 for _i, _m, h in rows
            if base.get(h, {}).get('b_ok') == '1'))
    w('rows the fields layer produced              %d' % len(per_row))
    w('bit-flip probes decoded                     %d' % len(flips))
    w('sampled encodings decoded                   %d' % len(got))
    w('')
    mult = sorted((n, rid) for rid, (n, _s, _g, _a) in per_row.items())
    w('FREE BITS PER ROW -- the size of the encoding space one row stands for.')
    w('An encoding count is 2^(free bits) and is a BOUND: bits interact, and')
    w('on a variable-length ISA every spelling of the same instruction at a')
    w('DIFFERENT length is excluded by construction, so the true space is')
    w('larger than this on x86_64 and close to exact on the fixed-width ISAs.')
    w('')
    if mult:
        q = [mult[int(len(mult) * f)][0] for f in (0.0, 0.25, 0.5, 0.75)]
        w('  minimum      %2d free bits   -> %d encoding(s)   e.g. %s'
          % (mult[0][0], 2 ** mult[0][0], mult[0][1]))
        w('  quartiles    %d / %d / %d free bits' % (q[1], q[2], q[3]))
        w('  maximum      %2d free bits   -> 2^%d encodings    e.g. %s'
          % (mult[-1][0], mult[-1][0], mult[-1][1]))
        tot = sum(2 ** n for n, _r in mult)
        w('')
        w('  SUM over every row: %d encodings stand behind %d opcode rows'
          % (tot, len(mult)))
        w('  -- a factor of %.0f between the denominator and what it covers.'
          % (float(tot) / max(len(mult), 1)))
    w('')
    hist = collections.Counter(n for n, _r in mult)
    w('  free-bit histogram')
    for k in sorted(hist):
        w('    %2d bits  %6d rows' % (k, hist[k]))
    w('')
    w('DATAFLOW INVARIANCE.  A row is DISAGREEING when two encodings that')
    w('decode to the same mnemonic at the same length produce different')
    w('structural dataflow -- different generic opcode, branch class,')
    w('atomicity, load or store count, lane-mask kind, or a different')
    w('multiset of register CLASSES read or written.  Register IDENTITY is')
    w('not in the signature: two encodings of one instruction naming')
    w('different registers are the same dataflow.')
    w('')
    w('  rows sampled                    %d' % len(per_row))
    w('  rows with >1 accepted encoding  %d'
      % sum(1 for _r, (_f, s, _g, _a) in per_row.items() if s > 1))
    w('  rows with >1 signature          %d'
      % (len(disagree) + len(crossed)))
    w('  ... explained by a SIBLING row  %d'
      % len(crossed))
    w('  ROWS WHOSE ENCODINGS DISAGREE   %d' % len(disagree))
    w('      -- and no other row of the denominator stands for what the')
    w('         disagreeing encoding does, so for these rows the opcode')
    w('         denominator is the wrong unit.')
    w('')
    w('  TIER-2, reported apart and NOT a defect: rows whose operand ARITY')
    w('  moves because two fields named the same register, so a dependency')
    w('  SET holds one element instead of two.')
    w('    rows with >1 arity            %d'
      % sum(1 for _r, (_f, _s, _g, ar) in per_row.items() if ar > 1))
    w('')
    if disagree:
        w('EVERY DISAGREEING ROW, with the signatures it produced:')
        for rid, mnem, sigs in disagree[:80]:
            w('  %-40s %s   %d signatures' % (rid, mnem, len(sigs)))
            for sig, encs in sorted(sigs.items(), key=lambda kv: -len(kv[1])):
                w('      n=%-4d %s' % (len(encs), sig))
                w('             e.g. %s' % encs[0])
        if len(disagree) > 80:
            w('  ... %d more; --tsv carries all of them'
              % (len(disagree) - 80))
        w('')
    w('CONTROL')
    if a.falsify:
        hit = any(rid == a.falsify for rid, _m, _s in disagree)
        w('  falsifier on %-30s %s'
          % (a.falsify, 'FIRED -- the row is reported DISAGREE' if hit
             else 'DID NOT FIRE -- the detector is blind'))
    else:
        w('  no falsifier requested; run once with --falsify=<opcode_id> '
          'before quoting a zero')
    w('')
    sys.stdout.write('\n'.join(out) + '\n')

    if a.tsv:
        with open(a.tsv, 'w') as fh:
            fh.write('opcode_id\tmnemonic\tfree_bits\tencodings_bound\t'
                     'accepted\tsignatures\tarities\tverdict\n')
            for rid, mn, _h in rows:
                if rid not in per_row:
                    continue
                fb, acc, sg, ar = per_row[rid]
                fh.write('%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n'
                         % (rid, mn, fb, 2 ** fb, acc, sg, ar,
                            'DISAGREE' if sg > 1 else 'invariant'))

    if a.falsify:
        if not fals_fired:
            sys.stderr.write('REFUSING: --falsify=%s has no accepted sample '
                             'that the sibling rule leaves unexplained, so '
                             'the control could not be staged; choose another '
                             'row\n' % a.falsify)
            return 2
        if not any(rid == a.falsify for rid, _m, _s in disagree):
            sys.stderr.write('REFUSING: the falsified row was not reported '
                             'DISAGREE; the detector is blind\n')
            return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
