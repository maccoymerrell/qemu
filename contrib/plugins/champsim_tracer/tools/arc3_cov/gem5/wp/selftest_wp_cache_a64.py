"""
NEGATIVE CONTROL for the aarch64 cache-maintenance adjudication rules.

``selftest_wp_a64.py`` proves every AXIS can go red, but it mutates only pairs
whose baseline is CLEAN on the axis it targets -- and every cache-maintenance
row is dirty by construction.  So the axis control says nothing at all about
the four rules that account for those rows:

    MAINT-EXTENT-IS-CACHE-GEOMETRY   REF-NO-CACHE-MAINT-DEST
    HINT-MEMOP-REF-SILENT            CACHE-MAINT-DEST-SPELLING

A rule nobody has watched refuse is a rule that might be laundering a defect,
and four rules that between them turned 54 UNACCOUNTED rows green is exactly
where that would hide.  This control breaks the TRACER's cache records in the
ways a real defect would break them and requires each rule to REFUSE -- the
row must come back WP-DEFECT or UNACCOUNTED, never carrying the rule's name.

It also names, out loud, the two facts this reference CANNOT check.  A
mutation that provably cannot fire is reported as UNCHECKABLE with its reason
and is never counted as a pass.

Exit codes are the tool's own, taken from the process:
    0  every mutation that CAN fire did
    1  a mutation did not fire -- a rule is too broad
    3  REFUSED: no maintenance instruction to mutate, or gem5 did not run

Author: Maccoy Merrell.
"""
import argparse
import copy
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..', 'riscv64', 'spike', 'wp'))

import elfimage                                              # noqa: E402
import gem5_env                                              # noqa: E402
import wp_trace                                              # noqa: E402
import wp_seed_a64                                           # noqa: E402
import compare_wp_a64 as C                                   # noqa: E402

RED = (C.WP_DEFECT, C.RECON_GAP, C.UNACCOUNTED)

#: the rule names this control exists to interrogate
WATCHED = ('MAINT-EXTENT-IS-CACHE-GEOMETRY', 'REF-NO-CACHE-MAINT-DEST',
           'HINT-MEMOP-REF-SILENT', 'CACHE-MAINT-DEST-SPELLING')


def maint_indices(ex):
    """Indices of instructions the TRACE itself calls cache maintenance.

    Read off the record's write list, not off a disassembly (R8.7).
    """
    return [i for i, ins in enumerate(ex.insns)
            if any(n == C.MAINT_DEST for n, _v, _w in ins.writes)]


def ref_silent_at(refrows, i):
    """True when the reference performed no access at all for index ``i``."""
    if i >= len(refrows):
        return False
    r = refrows[i][0]
    return not r.loads and not r.stores


def mutations(ex, refrows):
    """[(name, rule, axis, index, description, mutated excursion)].

    The INDEX matters and is carried: an excursion holds several maintenance
    instructions, and the rows of the ones this mutation did not touch are
    legitimately labelled and legitimately not red.  Scoring them would have
    called every rule too broad -- the first run of this control did exactly
    that, and the scoping is why its result is now a measurement.

    Every mutation is applied to an instruction the TRACE calls maintenance,
    and each one is the shape of a REAL defect: a wrong line, a claimed width
    the operation cannot have, a dropped destination, a destination renamed.
    """
    out = []
    idx = maint_indices(ex)
    if not idx:
        return out

    sized = [i for i in idx if not ref_silent_at(refrows, i)]
    silent = [i for i in idx if ref_silent_at(refrows, i)]

    def clone():
        return copy.deepcopy(ex)

    # ---- MAINT-EXTENT-IS-CACHE-GEOMETRY: the containment guard -------------
    for i in sized[:1]:
        m = clone()
        a, d, sz = m.insns[i].loads[0]
        m.insns[i].loads[0] = (a + 0x1000, d, sz)
        out.append(('wrong-page', 'MAINT-EXTENT-IS-CACHE-GEOMETRY',
                    'memop-addr', i,
                    'name a line a page away from the one gem5 cleaned', m))

        # The subtle one.  A defect that missed by ONE LINE is the defect a
        # containment test exists to catch; an off-by-a-page mutation would
        # pass a rule that only checked the page.
        m = clone()
        r0 = refrows[i][0]
        span = max(sz2 or 0 for _a2, _d2, sz2 in r0.loads + r0.stores) or 64
        a, d, sz = m.insns[i].loads[0]
        m.insns[i].loads[0] = (a + span, d, sz)
        out.append(('next-line', 'MAINT-EXTENT-IS-CACHE-GEOMETRY',
                    'memop-addr', i,
                    'name the NEXT line (+%d) instead of the cleaned one'
                    % span, m))

        # ---- the address-only gate.  A maintenance memop that claims to
        # carry data is not the record docs/format.rst 5.2 describes, and the
        # rule that says "the extent belongs to the cache" must not cover it.
        m = clone()
        a, d, sz = m.insns[i].loads[0]
        m.insns[i].loads[0] = (a, d, 8)
        out.append(('claims-width', 'MAINT-EXTENT-IS-CACHE-GEOMETRY',
                    'memop-width', i,
                    'claim an 8-byte access for a line operation', m))

    # ---- HINT-MEMOP-REF-SILENT: same address-only gate, silent reference ---
    for i in silent[:1]:
        if ex.insns[i].loads:
            m = clone()
            a, d, sz = m.insns[i].loads[0]
            m.insns[i].loads[0] = (a, d, 8)
            out.append(('silent-claims-width', 'HINT-MEMOP-REF-SILENT',
                        'memop-width', i,
                        'claim an 8-byte access where the reference issues '
                        'none', m))

    # ---- the destination rules --------------------------------------------
    # Dropping the destination is only VISIBLE where the reference names one.
    for i in idx:
        rw = frozenset(n for n, _v, _w in refrows[i][0].writes) \
            if i < len(refrows) else frozenset()
        m = clone()
        m.insns[i].writes = [w for w in m.insns[i].writes
                             if w[0] != C.MAINT_DEST]
        name = 'drop the REG_SYSCACHE destination of insn %d' % i
        if rw:
            out.append(('drop-dest', 'CACHE-MAINT-DEST-SPELLING',
                        'fpsr-dst-set', i, name, m))
        else:
            out.append(('drop-dest-blind', 'REF-NO-CACHE-MAINT-DEST',
                        'fpsr-dst-set', i, name, None))

        m = clone()
        m.insns[i].writes = [(('REG_GPR9' if n == C.MAINT_DEST else n), v, w)
                             for n, v, w in m.insns[i].writes]
        out.append(('rename-dest',
                    'CACHE-MAINT-DEST-SPELLING' if rw
                    else 'REF-NO-CACHE-MAINT-DEST',
                    'fpsr-dst-set', i,
                    'name REG_GPR9 where the operation writes the cache', m))
        if len(out) > 10:
            break
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--wpdepth', type=int, default=32)
    ap.add_argument('--python-home')
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('guest', nargs='+')
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    try:
        binary, cfg, env, _notes = C.prereqs(args.gem5_dir, args.outdir,
                                             args.python_home)
    except gem5_env.MissingPrerequisite as exc:
        sys.stderr.write('%s\n' % exc)
        return 3

    print('=' * 74)
    print('NEGATIVE CONTROL -- the aarch64 cache-maintenance RULES')
    print('=' * 74)
    print()
    print('The axis control mutates only pairs whose baseline is clean on the')
    print('axis it targets, and every cache-maintenance row is dirty by')
    print('construction -- so it says nothing about the rules that account')
    print('for them.  Each rule below is required to REFUSE a broken record.')
    print()

    lines, bad, uncheckable, subjects = [], 0, [], 0
    for guest in args.guest:
        image, _xr, _e = elfimage.load(guest)
        stem = os.path.join(args.outdir, os.path.basename(guest))
        trace = C.run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
        exc, _cp, _st = wp_trace.build(args.decode, trace, image)
        for k, ex in enumerate(exc):
            if not maint_indices(ex):
                continue
            tag = '%s.mc%04d' % (os.path.basename(guest), k)
            elf, _g, _u, plen = wp_seed_a64.build(args.outdir, tag, ex)
            log, reason, _p = C.run_gem5(binary, cfg, env, elf, args.outdir,
                                         tag, plen // 4 + len(ex.insns) + 16)
            refrows = C.parse_ref(log, elf, args.gem5_dir, C.not_prologue(plen))
            if len(refrows) < len(maint_indices(ex)):
                continue
            gi = C.excursion_gaps(ex, [])
            base = C.compare_excursion(guest, ex, refrows, gi, reason)[0]
            if any(r.verdict in RED for r in base):
                continue          # a dirty baseline proves nothing
            named = set()
            for r in base:
                for w in WATCHED:
                    if w in (r.detail or ''):
                        named.add(w)
            if not named:
                continue
            subjects += 1
            print('SUBJECT  %s excursion %d -- baseline is clean and carries: '
                  '%s' % (os.path.basename(guest), k, ', '.join(sorted(named))))
            print()
            for name, rule, axis, at, what, m in mutations(ex, refrows):
                if m is None:
                    uncheckable.append((name, rule, what))
                    continue
                rows = C.compare_excursion(guest, m, refrows,
                                           C.excursion_gaps(m, []), reason)[0]
                # SCOPED TO THE MUTATED INSTRUCTION, and to every axis of
                # it.  Two scoping decisions, both learned from a red run of
                # this control:
                #   * rows of the maintenance instructions this mutation did
                #     not touch are correctly labelled and correctly not red;
                #     counting them called every rule too broad.
                #   * the mutation need not surface on the axis it targets.
                #     Renaming REG_SYSCACHE to REG_GPR9 moves the write into
                #     the ARCHITECTURAL partition, so it lands on
                #     reg-dst-set; demanding fpsr-dst-set would have reported
                #     a caught defect as an uncaught one.  The baseline at
                #     this index is clean on every axis, so any red row here
                #     is the mutation's.
                mine = [r for r in rows if r.idx == at]
                hit = [r for r in mine if r.verdict in RED]
                laundered = [r for r in mine
                             if rule in (r.detail or '')
                             and r.verdict not in RED]
                ok = bool(hit) and not laundered
                bad += 0 if ok else 1
                lines.append('  %-22s %-32s %-13s %s'
                             % (name, rule, axis,
                                'REFUSED' if ok else 'RULE COVERED IT'))
            break
        if subjects:
            break

    if not subjects:
        sys.stderr.write('REFUSED: no clean excursion carrying a '
                         'cache-maintenance rule was found to mutate.\n')
        return 3

    print('MUTATION                RULE UNDER TEST                  AXIS'
          '          RESULT')
    for l in lines:
        print(l)
    print()

    if uncheckable:
        print('UNCHECKABLE AGAINST THIS REFERENCE -- reported, never counted')
        print('as a pass:')
        for name, rule, what in uncheckable:
            print('  %-22s %-32s %s' % (name, rule, what))
        print('  gem5 names NO destination for a DC clean, so the trace')
        print('  dropping REG_SYSCACHE there produces two empty sets and no')
        print('  row at all.  The same blind spot covers the ADDRESS of an')
        print('  IC IVAU memop: the reference issues no request, so any')
        print('  address compares equal to nothing.  Both are properties of')
        print('  the reference, not of the trace, and neither is closed by')
        print('  this leg.')
        print()

    print('MUTATIONS THAT MUST REFUSE: %d,  refused %d'
          % (len(lines), len(lines) - bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
