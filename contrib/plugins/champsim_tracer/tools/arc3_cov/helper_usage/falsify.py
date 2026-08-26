#!/usr/bin/env python3
"""Falsify the CP-H usage table against QEMU's OWN statement about the helper.

The table is read out of helper bodies.  TCGHelperInfo::flags is QEMU saying
the same thing from the other side, and the register allocator ACTS on it:
tcg_liveness_analysis() does la_global_kill() when neither NO_WG nor NO_RWG is
set, la_global_sync() when only NO_WG is, and nothing when NO_RWG is
(tcg/tcg.c).  So a helper declared TCG_CALL_NO_RWG that this table says
touches a TCG global is a CONTRADICTION -- one of the two accounts is wrong,
and either way the row must not ship.

The check runs in the direction that catches a WRONG row.  It cannot catch a
SHORT one: a helper declared without NO_RWG is permitted to touch nothing, so
a row that misses an access contradicts no flag.  That limit is stated here
rather than left for a reader to discover.
"""
import json, re, sys, argparse

def globals_of(dump):
    out = []
    for line in open(dump):
        if line.startswith('G '):
            _, off, size, name = line.split(None, 3)
            out.append((int(off), int(size), name.strip()))
    return out

def offsets_of(inc):
    """(field -> (off,size)) is not in the .inc; re-probe is the caller's."""
    raise NotImplementedError

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True)
    ap.add_argument('--derived', required=True)
    ap.add_argument('--census', required=True)
    ap.add_argument('--dump', required=True)
    ap.add_argument('--offsets', required=True, help='field->off,size json')
    ap.add_argument('--extra', help='hand rows json -- checked the same way')
    a = ap.parse_args()

    glob = globals_of(a.dump)
    offs = json.load(open(a.offsets))
    der = json.load(open(a.derived))['rows']
    if a.extra:
        for k, v in json.load(open(a.extra)).get(a.isa, {}).items():
            der[k] = dict(v, status='OK')
    cen = json.load(open(a.census))[a.isa]

    NO_RWG, NO_WG = 1, 2
    bad, checked, notouch = [], 0, 0
    for name, v in sorted(der.items()):
        if v['status'] != 'OK' or name not in cen:
            continue
        flags = cen[name]['flags']
        checked += 1
        touched_r, touched_w = [], []
        for f, d in v['env'].items():
            if f not in offs:
                continue
            fo, fs = offs[f]
            for go, gs, gn in glob:
                if fo < go + gs and go < fo + fs:
                    if d & 1:
                        touched_r.append(gn)
                    if d & 2:
                        touched_w.append(gn)
        if flags & NO_RWG:
            if touched_r or touched_w:
                bad.append((name, 'declared NO_RWG but the row touches '
                            'globals: r=%s w=%s'
                            % (sorted(set(touched_r)), sorted(set(touched_w)))))
        elif flags & NO_WG:
            if touched_w:
                bad.append((name, 'declared NO_WG but the row WRITES globals: '
                            '%s' % sorted(set(touched_w))))
        if not touched_r and not touched_w:
            notouch += 1
    touching = checked - notouch
    print('%s: %d rows checked against their own TCG call flags; %d of them '
          'overlap a TCG global and are therefore the check\'s actual '
          'subject; %d contradictions' % (a.isa, checked, touching, len(bad)))
    if touching == 0:
        print('  REFUSING: no row overlapped any TCG global, so this check '
              'had NO SUBJECT.  A pass here would report success without '
              'verifying anything.')
        return 2
    for n, w in bad:
        print('  CONTRADICTION %-24s %s' % (n, w))
    return 1 if bad else 0

if __name__ == '__main__':
    sys.exit(main())
