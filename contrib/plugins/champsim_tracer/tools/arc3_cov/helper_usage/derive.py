#!/usr/bin/env python3
"""Derive the CP-H per-helper usage table from QEMU's own source.

Input  : the CP-H census (which helpers a run actually reached -- a
         MEASUREMENT, not a recollection) and the target's preprocessed
         translation units.
Output : one row per helper it can bound completely, and a named refusal for
         every one it cannot.

The two rules from the table's own comment are enforced here rather than
trusted:  a row carries the file:line it was read from, and a helper whose
footprint the reader could not close gets NO ROW at all.
"""
import argparse, json, os, subprocess, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canalyze as C
from preprocess import entries_for, preprocess

TARGETS = {
    'x86_64':  ('x86_64-linux-user',  '/target/i386/',  'CPUX86State'),
    'aarch64': ('aarch64-linux-user', '/target/arm/',   'CPUARMState'),
    'riscv64': ('riscv64-linux-user', '/target/riscv/', 'CPURISCVState'),
    'mipsel':  ('mipsel-linux-user',  '/target/mips/',  'CPUMIPSState'),
}
# TUs outside target/ that define helpers the four targets call.
EXTRA = ['/accel/tcg/cpu-exec.c', '/accel/tcg/tcg-runtime.c', '/accel/tcg/tcg-runtime-gvec.c',
         '/accel/tcg/cputlb.c', '/accel/tcg/user-exec.c',
         '/fpu/softfloat.c', '/tcg/tcg-op-gvec.c']


def units_for(isa, ppdir, verbose=False):
    lib, tdir, envty = TARGETS[isa]
    os.makedirs(ppdir, exist_ok=True)
    sel = entries_for(lib, lambda f: tdir in f or any(e in f for e in EXTRA))
    units, failed = [], []
    seen = set()
    for e in sel:
        if e['file'] in seen:
            continue
        seen.add(e['file'])
        try:
            ip = preprocess(e, ppdir)
        except Exception as ex:
            failed.append((e['file'], str(ex)[:200]))
            continue
        try:
            units.append(C.Unit(ip))
        except Exception as ex:
            failed.append((e['file'], 'tokenize: ' + str(ex)[:200]))
    return units, failed, envty


def roots_of(params, envty):
    """Map parameter index -> root id, from the DEFINITION's own signature."""
    roots = {}
    for i, (nm, star, nmi, text) in enumerate(params):
        if not nm:
            continue
        if star and (envty in text or 'CPUArchState' in text):
            roots[i] = 'env'
        elif star:
            roots[i] = i
    return roots


def _pointee(params):
    """Parameter index -> the type text with ONE pointer level removed.

    Read off the DEFINITION's own signature and returned as text; whether it
    is a type the target's headers can size is the generator's question, and
    it asks the compiler.  Nothing here computes a size.
    """
    out = {}
    for i, (nm, star, nmi, text) in enumerate(params):
        if not star or not nm:
            continue
        t = text
        if nm and t.endswith(nm):
            t = t[:-len(nm)]
        t = t.replace('*', ' ', 1).strip()
        t = ' '.join(t.split())
        if t and '*' not in t and '[' not in t:
            out[i] = t
    return out


def derive(isa, helpers, ppdir, verbose=False):
    units, failed, envty = units_for(isa, ppdir, verbose)
    index = {}
    for u in units:
        for k in u.funcs:
            index.setdefault(k, u)
    out = {}
    for h in sorted(helpers):
        fn = 'helper_' + h
        u = index.get(fn)
        if u is None:
            out[h] = dict(status='NO-DEFINITION',
                          why='helper_%s is defined in no preprocessed unit' % h)
            continue
        params, brace, end, loc = u.funcs[fn]
        roots = roots_of(params, envty)
        a = C.Analysis(u, [x for x in units if x is not u])
        try:
            a.run(fn, roots)
        except C.Refusal as e:
            out[h] = dict(status='REFUSED', why=e.why, where=str(e.where),
                          defined_at='%s:%d' % loc)
            continue
        except RecursionError:
            out[h] = dict(status='REFUSED', why='recursion', defined_at='%s:%d' % loc)
            continue
        argdir = {}
        for i, (nm, star, nmi, text) in enumerate(params):
            if roots.get(i) == 'env':
                argdir[i] = 'env'
            elif star:
                argdir[i] = a.arg_dir.get(i, 0)
        out[h] = dict(status='OK',
                      escapes=sorted(set(a.cpu_escapes)),
                      defined_at='%s:%d' % loc,
                      params=[(t[0], t[3]) for t in params],
                      argdir=argdir,
                      env={k: v for k, v in sorted(a.env_fields.items())},
                      env_where=a.where,
                      # Members whose ARRAY INDEX the reader could not read
                      # off the source: the range is the whole file and names
                      # no element of it.  See Analysis._note_env().
                      env_unbounded=sorted(a.env_unbounded),
                      # The POINTEE TYPE of each pointer parameter, as the
                      # definition declares it.  It is what states the EXTENT
                      # of the state a pointer argument reaches -- the fact
                      # the gvec constructors supply for their operands and
                      # nothing supplied for anyone else, so every non-gvec
                      # pointer argument arrived at the consumer with extent
                      # 0 and could not be resolved to a register.
                      argtype={i: t for i, t in _pointee(params).items()},
                      # CP1: the GUEST MEMORY the helper reaches itself, which
                      # no qemu_ld/st op names because there is none -- the
                      # access happens inside the call.
                      mem=sorted(a.mem_acc.values(),
                                 key=lambda m: (m['dir'],
                                                -1 if m['addr'] is None
                                                else m['addr'])),
                      has_env='env' in roots.values())
    return out, failed


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True)
    ap.add_argument('--census', required=True, help='merged census json')
    ap.add_argument('--ppdir', required=True)
    ap.add_argument('-o', required=True)
    args = ap.parse_args()
    cen = json.load(open(args.census))
    helpers = list(cen[args.isa].keys())
    res, failed = derive(args.isa, helpers, args.ppdir)
    json.dump(dict(isa=args.isa, rows=res, pp_failed=failed),
              open(args.o, 'w'), indent=1)
    ok = sum(1 for v in res.values() if v['status'] == 'OK')
    print('%s: %d helpers, %d bounded, %d refused/undefined, %d TUs failed to '
          'preprocess' % (args.isa, len(res), ok, len(res) - ok, len(failed)))
