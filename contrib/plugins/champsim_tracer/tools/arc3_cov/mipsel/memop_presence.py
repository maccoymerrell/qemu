#!/usr/bin/env python3
"""mipsel MEMOP presence: the tracer's static claim vs binutils' own flags.

Author: Maccoy Merrell.

Registers were the first half of ARC 3 because they needed building.  They are
not the scope.  COUNT, ADDRESS and DATA for every load and store are the other
half, and on mipsel nothing compared any of them: the register harness reads
`f_src` / `f_dst` out of `isaxcheck --batch` and has never once read `f_loads`
or `f_stores` sitting in the same row.

This is the presence arm.  For every opcode in the mipsel denominator it asks
whether the tracer's InsnFields claim a load, a store, both or neither, and
puts that against `INSN_LOAD_MEMORY` / `INSN_STORE_MEMORY` -- the flags
binutils itself carries on the entry the encoding came from.  Both sides
therefore come from the same enumeration this directory already produces; no
new reference is introduced, and none is needed to answer "does this
instruction touch memory at all".

WHAT IT IS NOT.  binutils is a STATIC decoder.  It knows that `lw` reads
memory; it has never run one.  mipsel has NO execution reference, and a result
from this harness must never be quoted as though execution had validated it.
It also says nothing about ADDRESS or DATA, and nothing about the runtime
memop count -- only about what the template CLAIMS, which is what sizes the
dependency lane mask.

HOW A DISAGREEMENT IS REPORTED.  A bare disagree count is not a result: it is
equally consistent with the project's goal (we record MORE) and with its one
disqualifying failure (we record LESS).  So each disagreeing row carries a
DIRECTION measured from the two claims and a CATEGORY naming the mechanism,
and the headline is TRACER-SUBSET + UNACCOUNTED, never the agreement rate.

Usage:
    python memop_presence.py [--raw DIR] [--opcodes FILE] [--isaxcheck BIN]
                             [--show CLASS ...]

`--raw` is the directory holding the enumerator's `raw_v0..3.tsv`
(`mips_enum --variant=$v`, see METHOD.md); `--opcodes` is the denominator
table `opcodes.tsv` that the register harness already uses.
"""
import os
import sys
import csv
import json
import argparse
import subprocess
import collections

# binutils-2.42 include/opcode/mips.h.  Taken from the header rather than
# guessed: a wrong bit here would silently reclassify the whole reference.
INSN_LOAD_MEMORY = 0x00000800          # mips.h:1050
INSN_STORE_MEMORY = 0x00800000         # mips.h:1075

_D = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.environ.get(
    'CST_ARC3_TOOLS',
    '/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/arc3_cov')
for _p in (_D, os.path.dirname(_D), _TOOLS):
    if os.path.exists(os.path.join(_p, 'arc3_taxonomy.py')):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break

DEFAULT_COV = '/mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel'
DEFAULT_ISAX = '/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck'

#: direction x category for each outcome.  A row whose mechanism is not named
#: stays UNACCOUNTED -- a row nobody has interrogated has no direction anyone
#: is entitled to claim.
CLASSES = {
    'AGREE':            ('-',               '-'),
    'LD-MISSING':       ('TRACER-SUBSET',   'tracer-defect'),
    'ST-MISSING':       ('TRACER-SUBSET',   'tracer-defect'),
    'LD-EXTRA':         ('TRACER-SUPERSET', 'reference-gap'),
    'ST-EXTRA':         ('TRACER-SUPERSET', 'reference-gap'),
}

#: The two DIRECTION-SWAP outcomes are deliberately absent from CLASSES, so a
#: row that lands in one stays UNACCOUNTED until a mechanism is named for it.
#: They used to be there, mapped to ORTHOGONAL / vocabulary-difference, and
#: they were wrong twice over.
#:
#: They were DEAD: the classifier composes its key in the fixed order
#: LD-MISSING, LD-EXTRA, ST-MISSING, ST-EXTRA, so the key it can actually
#: build for "reference says store, tracer says load" is `LD-EXTRA+ST-MISSING`
#: -- and the table spelled it `ST-MISSING+LD-EXTRA`, which nothing can ever
#: produce.  No row had reached either entry, so nothing had exercised them.
#:
#: And had they been reachable they would have laundered a real defect.  A
#: store recorded as a load is exactly the shape AArch64 `stzgm` had until
#: 2026-08-25, where Capstone reported the written block READ; that was a
#: decoder bug fixed at the boundary, not a difference of vocabulary.  A
#: blanket ORTHOGONAL on the swap classes would have scored it as agreement in
#: a different dialect.  The docstring above already stated the rule -- a row
#: whose mechanism is not named has no direction anyone is entitled to claim
#: -- and these two entries contradicted it.
SWAP_CLASSES = {'LD-EXTRA+ST-MISSING', 'LD-MISSING+ST-EXTRA'}

#: The hint / cache-maintenance class.  These instructions DO mint a runtime
#: memop (decode_synthetic_ea), so the wire is not empty.  Since 2026-08-25
#: the STATIC claim matches it -- the template allocates the load slot the
#: synthetic EA fills -- so `pref` and `cache` now AGREE and only the
#: DIRECTION of `synci` still separates the two sides.
STATIC_DYNAMIC_SPLIT = {'pref', 'prefe', 'synci', 'cache', 'cachee'}

#: ADDRESS-ONLY CACHE MAINTENANCE, and the direction question settled.
#:
#: binutils flags `synci` INSN_STORE_MEMORY -- "Instruction stores value into
#: memory" -- and has since 1993.  The tracer records one address-only memop
#: for it, load-shaped, carrying no data.  That is the whole of the remaining
#: disagreement: both sides say ONE access at the same effective address, and
#: they name its direction differently.
#:
#: It is adjudicated from QEMU, which is this arc's ground truth, and not from
#: the flag:
#:
#:   * QEMU emits NOTHING for `synci`.  Every regime lowers it to a bare
#:     `ctx->base.is_jmp = DISAS_STOP` -- target/mips/tcg/translate.c:14403,
#:     micromips_translate.c.inc:2420 and :2456, nanomips_translate.c.inc:3991
#:     -- with no TCG memory op, no helper and no address computation.  There
#:     is no store for the tracer to have dropped.
#:   * LLVM MC, the rank-1 mipsel reference and this directory's naming
#:     authority, reports mayLoad=0 mayStore=0 for the same encoding
#:     (`isaxcheck --isa=mipsel --hex=00009f04`, the `llvm` line).
#:   * binutils is not self-consistent across the construct: for three MIPS
#:     operations that all name an effective address and all move no
#:     architectural data, `pref` carries LM, `cache` carries neither flag,
#:     and `synci` carries SM.
#:
#: So the reference's own flag is the outlier, and the surviving difference is
#: a difference of vocabulary in a wire format that has two directions and
#: needs a third.  The record is load-shaped because that is what
#: MemAccessRecorder::record_synthetic_load() mints and what `prfm` / `pref`
#: have always published; the information the consumer is owed -- WHICH LINE
#: -- is present, and nothing is dropped.  Membership is by name, so a future
#: row that merely happens to swap direction cannot inherit this ruling.
CACHE_MAINT_ADDRESS_ONLY = {'synci', 'cache', 'cachee', 'pref', 'prefe'}

#: The store-conditional family.  QEMU lowers `sc` / `scd` / `sce` onto
#: `tcg_gen_atomic_cmpxchg_tl` (target/mips/tcg/translate.c:2219-2244), which
#: performs a REAL load before the store, and the memop callback delivers it.
#: binutils is right that the ARCHITECTURE only stores; the tracer is right
#: about what the guest RAN.  That is not a gap in the reference -- it models
#: the instruction correctly -- so the row is charged to `emulation-artefact`
#: rather than to `reference-gap`, which is where an unlabelled LD-EXTRA
#: would land it.  Decided the same way #177 decided the identical AArch64
#: case and applied to riscv64's `sc.d` in the same pass.
QEMU_CMPXCHG_SC = {'sc', 'scd', 'sce'}


def read_pinfo(rawdir):
    """Two indexes over the enumerator's rows: by ENCODING and by NAME.

    The name index is what this harness started with, and it has a hole the
    denominator falls straight into.  binutils spells the SPECIAL/funct=2
    rotate `ror` (mips-opc.c row `{"ror", "d,w,<", 0x00200002, ...}`); the
    denominator, which takes its subject names from the disassembler, spells
    the same encoding `rotr`.  Under the name key `rotr` resolves only to the
    two `mips_macros` pseudo-op rows, which carry no `pinfo` at all, so the
    subject scored REF-UNPROBED while its reference row sat in the table with
    `pinfo=0x9`.

    The encoding is the thing both sides actually agree on, so it is tried
    first -- but ONLY when it is unambiguous.  Aliases share encodings
    (`0000a47c` is both `ext` and the R5900 `sq`), and OR-ing their flags
    would manufacture a store on an instruction that has none.  A colliding
    encoding falls back to the name chain rather than being merged.
    """
    pin = collections.defaultdict(int)
    enc = collections.defaultdict(int)
    enc_names = collections.defaultdict(set)
    seen_any = False
    for v in '0123':
        path = os.path.join(rawdir, 'raw_v%s.tsv' % v)
        if not os.path.exists(path):
            continue
        with open(path, newline='') as f:
            for r in csv.DictReader(f, delimiter='\t'):
                flags = r.get('flags') or ''
                if 'pinfo=' not in flags:
                    continue
                seen_any = True
                p = int(flags.split('pinfo=')[1].split(',')[0], 16)
                pin[r['name']] |= p
                h = (r.get('enc_bytes_le') or '').strip()
                if h:
                    enc[h] |= p
                    enc_names[h].add(r['name'])
    if not seen_any:
        sys.exit('no pinfo= column found under %s -- re-run mips_enum '
                 '(see METHOD.md); a reference that cannot be read must FAIL, '
                 'not score everything as agreement' % rawdir)
    enc = {h: v for h, v in enc.items() if len(enc_names[h]) == 1}
    return pin, enc


def read_opcodes(path):
    """[(opcode_id, mnemonic, hex)] from the denominator table."""
    rows = []
    with open(path, newline='') as f:
        rd = csv.reader(f, delimiter='\t')
        for r in rd:
            if not r or r[0].startswith('#'):
                continue
            rows.append((r[0], r[1], r[2]))
    return rows


def tracer_batch(isax, hexes):
    p = subprocess.run([isax, '--isa=mipsel', '--batch'],
                       input='\n'.join(hexes) + '\n',
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit('isaxcheck --batch failed rc=%d: %s'
                 % (p.returncode, p.stderr[-2000:]))
    return {r['hex']: r for r in csv.DictReader(p.stdout.splitlines(),
                                                delimiter='\t')}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', default=os.path.join(DEFAULT_COV, 'work'))
    ap.add_argument('--opcodes', default=os.path.join(DEFAULT_COV,
                                                      'opcodes.tsv'))
    ap.add_argument('--isaxcheck', default=DEFAULT_ISAX)
    ap.add_argument('--out', default=None, help='write the per-row TSV here')
    ap.add_argument('--show', nargs='*', default=[],
                    help='print every row of these classes')
    A = ap.parse_args()

    pin, enc = read_pinfo(A.raw)
    opc = read_opcodes(A.opcodes)
    trc = tracer_batch(A.isaxcheck, [h for _, _, h in opc])

    cat = collections.Counter()
    #: (class, direction, category) -> count.  The headline is computed from
    #: THIS, not from `cat`: the per-row overrides below (the SC family, the
    #: address-only cache-maintenance ruling) are the whole point of the
    #: taxonomy, and a headline summed over bare classes could not see any of
    #: them.  It could not see `synci` in particular -- the row's direction
    #: was being read out of a table keyed by a string the classifier never
    #: builds.
    adj = collections.Counter()
    rows = collections.defaultdict(list)
    out = []
    for oid, mnem, hx in opc:
        T = trc.get(hx)
        # The ENCODING is the key both sides share, so it is tried first --
        # only for encodings the enumerator names exactly once (see
        # read_pinfo).  Everything else falls back to the name chain: the
        # enumerator keys on the bare mnemonic while the denominator keys on
        # "mipsel.<mnemonic>" and disambiguates same-named entries by
        # appending the encoding ("mipsel.rddsp.7c0004b8"), so both forms are
        # tried, and the mnemonic column is the last resort.
        p = enc.get(hx)
        if p is None:
            key = oid.split('.', 1)[1] if oid.startswith('mipsel.') else oid
            p = pin.get(key)
            if p is None and '.' in key:
                p = pin.get(key.rsplit('.', 1)[0])
            if p is None:
                p = pin.get(mnem)
        if T is None or p is None:
            cat['REF-UNPROBED'] += 1
            rows['REF-UNPROBED'].append((oid, mnem, hx, None, None, None, None))
            continue
        refl = bool(p & INSN_LOAD_MEMORY)
        refs = bool(p & INSN_STORE_MEMORY)
        fl, fs = int(T['f_loads']), int(T['f_stores'])
        d = []
        if refl and fl == 0:
            d.append('LD-MISSING')
        if not refl and fl > 0:
            d.append('LD-EXTRA')
        if refs and fs == 0:
            d.append('ST-MISSING')
        if not refs and fs > 0:
            d.append('ST-EXTRA')
        k = '+'.join(d) if d else 'AGREE'
        direction, category = CLASSES.get(k, ('UNACCOUNTED', 'unaccounted'))
        if k in SWAP_CLASSES and mnem in CACHE_MAINT_ADDRESS_ONLY:
            direction, category = ('ORTHOGONAL', 'cache-maintenance-direction')
        elif k != 'AGREE' and mnem in STATIC_DYNAMIC_SPLIT:
            category = 'static-dynamic-split'
        if k == 'LD-EXTRA' and mnem in QEMU_CMPXCHG_SC:
            category = 'emulation-artefact'
        cat[k] += 1
        adj[(k, direction, category)] += 1
        rows[k].append((oid, mnem, hx, refl, refs, fl, fs))
        out.append({'opcode_id': oid, 'mnemonic': mnem, 'hex': hx,
                    'ref_load': int(refl), 'ref_store': int(refs),
                    'trc_loads': fl, 'trc_stores': fs,
                    'verdict': 'AGREE' if k == 'AGREE' else 'DISAGREE',
                    'class': k, 'direction': direction,
                    'category': category})

    tot = sum(cat.values())
    sub = sum(c for (_, d, _), c in adj.items() if d == 'TRACER-SUBSET')
    una = sum(c for (_, d, _), c in adj.items() if d == 'UNACCOUNTED')

    print('=' * 78)
    print('mipsel MEMOP PRESENCE -- tracer static claim vs binutils pinfo')
    print('=' * 78)
    print('reference:  binutils INSN_LOAD_MEMORY / INSN_STORE_MEMORY, STATIC.')
    print('            mipsel has NO execution reference; this result must not')
    print('            be quoted as if execution had validated it.')
    print('scope:      PRESENCE only.  Not count, not address, not data.')
    print()
    print('THE NUMBER THAT MATTERS:  TRACER-SUBSET %d  +  UNACCOUNTED %d  =  %d'
          % (sub, una, sub + una))
    print()
    print('  subjects %d   agree %d   unprobed %d'
          % (tot, cat['AGREE'], cat['REF-UNPROBED']))
    print()
    print('  %-24s %6s  %-16s %s' % ('class', 'count', 'direction', 'category'))
    print('  ' + '-' * 74)
    if cat['REF-UNPROBED']:
        print('  %-24s %6d  %-16s %s'
              % ('REF-UNPROBED', cat['REF-UNPROBED'], 'NONE', 'not-compared'))
    for (k, direction, category), v in sorted(adj.items(),
                                              key=lambda kv: -kv[1]):
        print('  %-24s %6d  %-16s %s' % (k, v, direction, category))

    for k in cat:
        if k in ('AGREE', 'REF-UNPROBED') or k in A.show:
            continue
        print('\n  ## %s' % k)
        for oid, mnem, hx, rl, rs, fl, fs in rows[k]:
            print('     %-28s %-10s %s  ref(ld=%s,st=%s) tracer(ld=%s,st=%s)%s'
                  % (oid, mnem, hx, int(rl), int(rs), fl, fs,
                     '   [static/dynamic split: a runtime memop IS minted]'
                     if mnem in STATIC_DYNAMIC_SPLIT else ''))

    for k in A.show:
        print('\n  ## %s (full)' % k)
        for r in rows[k]:
            print('     %s' % (r,))

    if A.out:
        cols = ['opcode_id', 'mnemonic', 'hex', 'ref_load', 'ref_store',
                'trc_loads', 'trc_stores', 'verdict', 'class', 'direction',
                'category']
        with open(A.out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=cols, delimiter='\t')
            w.writeheader()
            for r in out:
                w.writerow(r)

    return 1 if (sub + una) else 0


if __name__ == '__main__':
    sys.exit(main())
