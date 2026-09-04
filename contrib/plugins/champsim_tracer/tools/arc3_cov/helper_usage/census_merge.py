#!/usr/bin/env python3
"""Sum the CP-H census part files a run left behind into one census json.

QEMU writes the census as a FULL REWRITE of one file per process (there is no
at-exit hook in qemu-user that survives _exit), so a run that is cut into
chunks -- one QEMU per chunk -- leaves one part per process, named
``<path>.<pid>``.  Reading only ``<path>`` reads no chunk at all, and reading
the newest part reads the last chunk as though it were the run.  This reads
every part and states what it summed, so a missing chunk is a number that
does not match rather than a census that quietly got shorter.

Counters and bitsets merge differently and the difference matters:

  calls, unknown_pairs   SUM      -- how often, over the whole run
  reasons, *_args        UNION    -- a bit set in any chunk is set for the run

``nargs`` and ``flags`` are properties of the helper's declaration, not of a
call, so they must agree across parts; a disagreement is reported rather than
resolved, because a helper whose declaration differs between two processes of
one run means the parts are not from one build.

Usage:
    census_merge.py --isa x86_64 <path-or-dir> [--isa aarch64 <...>] -o m.json
"""
import argparse, glob, json, os, sys

FIELDS = ('calls', 'nargs', 'flags', 'reasons', 'ptr_args', 'env_args',
          'unknown_args', 'stated_args', 'unknown_pairs')
# The json key each TSV column is published under (derive.py/falsify.py read
# these names).
OUT = {'calls': 'calls', 'nargs': 'nargs', 'flags': 'flags',
       'reasons': 'reasons', 'ptr_args': 'ptr', 'env_args': 'env',
       'unknown_args': 'unk', 'stated_args': 'stated',
       'unknown_pairs': 'upairs'}
SUMMED = ('calls', 'unknown_pairs')
UNIONED = ('reasons', 'ptr_args', 'env_args', 'unknown_args', 'stated_args')
DECLARED = ('nargs', 'flags')


def parts_for(spec):
    """Every part file named by @spec: a directory, a base path, or a part.

    AN EMPTY PART IS A REFUSAL, not something to skip.  A part exists because
    a process created it, and QEMU writes each one by rename(2) from a
    complete temporary -- so a zero-byte part cannot be a process that
    reached no helper (that one would still carry the header).  It is a
    process that died mid-write under an older build, or a truncated file,
    and the chunk it stands for is GONE.  Skipping it merges the survivors
    and reports a total, which is precisely the silent shortfall this whole
    tool exists to prevent.  Measured: four aarch64 parts, all zero bytes,
    from chunk processes stopped by a host stall.

    `.tmp` files are ignored rather than refused -- those are the in-flight
    half of the rename and belong to a process that is still running.
    """
    if os.path.isdir(spec):
        cand = sorted(glob.glob(os.path.join(spec, '*_helpers.tsv.*')) +
                      glob.glob(os.path.join(spec, '*_helpers.tsv')))
    else:
        cand = sorted(set(glob.glob(spec + '.*')) | ({spec}
                      if os.path.exists(spec) else set()))
    cand = [c for c in cand if os.path.isfile(c) and not c.endswith('.tmp')]
    empty = [c for c in cand if not os.path.getsize(c)]
    if empty:
        raise SystemExit(
            'census_merge: %d part(s) named by %s are EMPTY -- REFUSING.\n'
            '  %s\n'
            '  A part is written by rename(2) from a complete temporary, so '
            'an empty one is\n  a chunk whose census was lost, not a chunk '
            'that reached no helper.  Merging\n  the rest would report a '
            'total that is short by however many chunks these were.'
            % (len(empty), spec, '\n  '.join(empty)))
    return cand


def read_part(path):
    """-> (target, overflow, {name: {field: int}}).  Refuses a truncated part."""
    rows, target, overflow, cols = {}, None, False, None
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if line.startswith('#'):
                if line.startswith('# target='):
                    target = line.split('=', 1)[1]
                elif line.startswith('# overflow='):
                    body = line[2:].split()
                    overflow = body[0].split('=')[1] != '0'
                elif line.startswith('# name\t'):
                    cols = line[2:].split('\t')
                continue
            if not line:
                continue
            v = line.split('\t')
            if cols is None:
                raise SystemExit('census_merge: %s has rows before its column '
                                 'header -- REFUSING (the column order is not '
                                 'known, so the numbers cannot be named)'
                                 % path)
            if len(v) != len(cols):
                raise SystemExit('census_merge: %s row %r has %d field(s), the '
                                 'header names %d -- REFUSING (a part written '
                                 'while the process died is a SHORT part, and '
                                 'a short part read as whole is a census that '
                                 'lost calls)' % (path, v[0], len(v), len(cols)))
            rows[v[0]] = {k: int(x, 0) for k, x in zip(cols[1:], v[1:])}
    return target, overflow, rows


def merge(specs):
    acc, target, overflow, seen, conflicts = {}, None, False, [], []
    for spec in specs:
        ps = parts_for(spec)
        if not ps:
            raise SystemExit('census_merge: %s names no non-empty census part '
                             '-- REFUSING.  An absent census and an empty one '
                             'are not the same answer, and only one of them '
                             'is honest about it.' % spec)
        for p in ps:
            t, ov, rows = read_part(p)
            if target is None:
                target = t
            elif t != target:
                raise SystemExit('census_merge: part %s is target %s, the '
                                 'others are %s -- REFUSING' % (p, t, target))
            overflow = overflow or ov
            seen.append((p, len(rows)))
            for name, r in rows.items():
                fresh = name not in acc
                cur = acc.setdefault(name, dict.fromkeys(FIELDS, 0))
                for k in SUMMED:
                    cur[k] += r.get(k, 0)
                for k in UNIONED:
                    cur[k] |= r.get(k, 0)
                for k in DECLARED:
                    # Checked on EVERY part after the first, including the
                    # parts whose value is zero: `flags == 0` is a real
                    # declaration (no TCG_CALL_NO_* bit at all), so guarding
                    # the comparison on truthiness would make the commonest
                    # flags value the one disagreement nobody can see.
                    if not fresh and cur[k] != r.get(k, 0):
                        conflicts.append((name, k, cur[k], r.get(k, 0), p))
                    cur[k] = r.get(k, 0)
    return target, overflow, acc, seen, conflicts


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', action='append', required=True, nargs='+',
                    metavar=('ISA', 'PART'),
                    help='ISA followed by its part path(s)/dir(s)')
    ap.add_argument('-o', required=True)
    a = ap.parse_args()

    out, bad = {}, False
    for spec in a.isa:
        isa, specs = spec[0], spec[1:]
        if not specs:
            raise SystemExit('census_merge: --isa %s names no part' % isa)
        target, overflow, acc, seen, conflicts = merge(specs)
        out[isa] = {n: {OUT[k]: v[k] for k in FIELDS} for n, v in acc.items()}
        calls = sum(v['calls'] for v in acc.values())
        print('%s (target=%s): %d part(s), %d helper(s), %d call(s)%s'
              % (isa, target, len(seen), len(acc), calls,
                 '  OVERFLOW' if overflow else ''))
        for p, n in seen:
            print('    %6d rows  %s' % (n, os.path.basename(p)))
        for c in conflicts:
            bad = True
            print('    CONFLICT %s.%s: %d vs %d in %s' % c)
        if overflow:
            bad = True
            print('    a part overflowed DF_CENSUS_MAX -- the census is a '
                  'PREFIX of the helpers reached, not the set')
    json.dump(out, open(a.o, 'w'), indent=1)
    if bad:
        sys.exit(2)
