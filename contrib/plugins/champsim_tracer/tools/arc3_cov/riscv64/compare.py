#!/usr/bin/env python3
"""riscv64 register-attribution cross-check: Sail-RISCV reference vs the
tracer's own InsnFields (isaxcheck --layer=fields)."""
import os, re, sys, json, csv, subprocess, collections
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import sail_effects as S
import zcmp_profile as ZC

# The two-axis taxonomy is shared by all four ISA harnesses.  A harness runs
# from a working copy beside its evidence, so look there first and fall back to
# the tree, which is the source of truth.
_TOOLS = os.environ.get(
    'CST_ARC3_TOOLS',
    '/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/arc3_cov')
for _p in (HERE, ROOT, os.path.dirname(ROOT), _TOOLS):
    if os.path.exists(os.path.join(_p, 'arc3_taxonomy.py')):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break
else:
    sys.exit('arc3_taxonomy.py not found (set CST_ARC3_TOOLS)')
import arc3_taxonomy as tax
import arc3_rules as taxrules

QEMU = '/mnt/md0/QEMU/qemu'
ISAX = os.path.join(QEMU, 'build/contrib/plugins/isaxcheck')
SAIL = os.path.join(ROOT, 'ref/sail-riscv')

# ------------------------------------------------- canonical register naming
# The tracer's GenericRegId space is deliberately coarse (see
# champsim_tracer_generic_ids.h): a whole CSR population folds onto REG_SYS,
# the FP status/rounding word onto REG_FCSR and the vector control words onto
# REG_VCTRL.  The reference is canonicalised the same way (R4).
CSR_NUM_FOLD = {
    0x001: 'REG_FCSR',   # fflags
    0x002: 'REG_FCSR',   # frm
    0x003: 'REG_FCSR',   # fcsr
    0x008: 'REG_VCTRL',  # vstart
    0x009: 'REG_FCSR',   # vxsat
    0x00A: 'REG_FCSR',   # vxrm
    0x00F: 'REG_FCSR',   # vcsr
    0xC20: 'REG_VCTRL',  # vl
    0xC21: 'REG_VCTRL',  # vtype
    0xC22: 'REG_SYSID',  # vlenb (read-only implementation constant)
}
CSR_NAME_FOLD = {
    'fcsr': 'REG_FCSR', 'fflags': 'REG_FCSR', 'frm': 'REG_FCSR',
    'vcsr': 'REG_FCSR', 'vxsat': 'REG_FCSR', 'vxrm': 'REG_FCSR',
    'vstart': 'REG_VCTRL', 'vl': 'REG_VCTRL', 'vtype': 'REG_VCTRL',
    'vlenb': 'REG_SYSID',
    # the Zicfiss shadow-stack pointer has an ID of its own
    # (champsim_tracer_mnemonics_riscv.h: RISCV_REG_SSP -> REG_SSP)
    'ssp': 'REG_SSP',
}

def expand_group(eff, nf, nreg):
    """Register groups whose size the ENCODING fixes.

    `nf`   (whole-register and segment load/store): Sail indexes the group with
           `vregidx_offset(base, <loop var>)`, which the scan reports as a group
           base; the group is nf registers wide.
    `nreg` (vmv<nr>r.v): EMUL comes straight from the encoded nreg and Sail
           indexes through read_vreg/write_vreg, so every vector operand of the
           instruction is an nreg-wide group."""
    out = set()
    for role, cls, key in eff:
        if isinstance(key, tuple) and key and key[0] == 'grp':
            for k in range(max(1, nf)): out.add((role, cls, key[1] + k))
        elif nreg > 1 and cls == 'VEC' and isinstance(key, int):
            for k in range(nreg): out.add((role, cls, key + k))
        else:
            out.add((role, cls, key))
    return out

# ------------------------------------------------- adjudicated disagreements
# Every residual disagreement is adjudicated here, with the reason, rather
# than dropped: the row stays DISAGREE and carries the verdict in its
# adjudication column.  Keyed by (Sail node, regex over one signature part);
# a row is adjudicated only when EVERY part of its signature matches an entry.
#
# REF-ARTIFACT   the reference performs a read the ISA does not make this
#                encoding depend on at all.
# (GATE-READ)    RETIRED.  This class held the reads that decide whether an
#                instruction TRAPS -- vector FP frm, WFI's mstatus.TW, the
#                Zicbom/Zicboz/Zicfiss envcfg enable bits -- on the argument
#                that InsnFields has no legality axis.  R7.4 settled it the
#                other way: a pending write to such a CSR must resolve before
#                the instruction may proceed, which is an edge a renaming
#                regfile has to respect, so it is a source.  The tracer
#                records all 23 and they agree; there is no adjudication left
#                to make and the entries are gone rather than left to match
#                nothing.
# SCOPE-XLATE    address translation, PMP/PMA and platform state: an
#                enumerated scope exclusion (see SCOPE EXCLUSIONS above) that
#                the tracer applies on its side.  The reference leaks it when
#                the read is INLINE in the execute clause instead of behind
#                one of the blacklisted helpers.
# REF-UNDERREAD  Sail writes only a SUB-RANGE of the destination (the loop is
#                bounded by vstart / vl / eg_len), so the elements outside it
#                keep their previous values -- a preserve the accessor scan
#                cannot see, because no read accessor is called.  The tracer
#                names the register as a source, which is what the
#                architecture says.
ADJUDICATED = [
    (('VSETVL', 'VSETVLI'), r'^SRC-missing:REG_VCTRL$', 'REF-ARTIFACT',
     'execute_vsetvl_type computes lmul_sew_ratio from the OLD vtype '
     'unconditionally but uses it only when requires_fixed_vlmax '
     '(rd==x0 && rs1==x0), which this encoding is not'),

    (('HLVTYPE', 'HSV'), r'^SRC-missing:REG_SYS$', 'SCOPE-XLATE',
     'hgatp/satp/vsatp/vsstatus/mstatus/hstatus/pma_regions -- the '
     'hypervisor load-store selects an effective privilege and translates '
     'through the guest tables; every CSR named is address-translation, '
     'privilege or physical-memory state'),
    (('SFENCE_VMA', 'SINVAL_VMA', 'HFENCE_GVMA', 'HFENCE_VVMA',
      'HINVAL_GVMA', 'HINVAL_VVMA'), r'^SRC-missing:REG_SYS$', 'SCOPE-XLATE',
     'mstatus.TVM / hstatus / hgatp -- the privilege gate and the VMID that '
     'scopes a TLB maintenance operation, both address-translation state'),
    (('ZICBOP',), r'^SRC-missing:REG_SYS$', 'SCOPE-XLATE',
     'mstatus and pma_regions: privilege and physical-memory attributes'),

    (('VLRETYPE', 'VSM3ME_VV', 'VSM4K_VI'), r'^SRC-extra:REG_VEC<n>(x\d+)?$',
     'REF-UNDERREAD',
     'the write loop starts at vstart (VLRETYPE: `cur_elem = start_element`) '
     'or runs over element groups eg_start..eg_len-1 (Zvk), so elements '
     'outside that range keep their previous values; Sail calls no read '
     'accessor for them, but the register is architecturally preserved and '
     'therefore read'),
]


def adjudicate_part(node, part):
    for nodes, rx, kind, note in ADJUDICATED:
        if node in nodes and re.match(rx, part):
            return kind, note
    return None, None


def canon(role, cls, key):
    if cls == 'GPR':
        if key is None: return None
        if key == 0:
            # a write to x0 changes no architectural state (Sail wX: `0 => ()`)
            return None if role == 'W' else 'REG_ZERO'
        # the tracer names three GPRs by architectural role rather than number
        # (champsim_tracer_mnemonics_riscv.h); that is a naming fold, not a
        # different register (R4).
        return {1: 'REG_LR', 2: 'REG_SP', 8: 'REG_FP_REG'}.get(key, 'REG_GPR%d' % key)
    if cls == 'FPR':
        return None if key is None else 'REG_FPR%d' % key
    if cls == 'VEC':
        return None if key is None else 'REG_VEC%d' % key
    if cls == 'CSRNUM':
        if key is None: return 'REG_SYS'
        return CSR_NUM_FOLD.get(key, 'REG_SYS')
    if cls == 'CSR':
        return CSR_NAME_FOLD.get(key, 'REG_SYS')
    return None

# ------------------------------------------------------------ opcode rows
def opcode_id(r):
    m = re.match(r'^mapping clause encdec(?:_compressed)?\s*=\s*\w+\s*\((.*?)\)\s*<->',
                 r['text'])
    lits = []
    if m:
        for p in S.split_args(m.group(1)):
            if re.match(r'^[A-Z]\w*$', p.strip()): lits.append(p.strip())
    bits = ['SAIL:' + r['node']]
    if lits: bits.append(','.join(lits))
    c = ','.join('%s=%s' % (k, v) for k, v in sorted(r['combo'].items()))
    if c: bits.append(c)
    return ':'.join(bits)

def batch(hexes, extra):
    argv = [ISAX, '--isa=riscv64', '--layer=fields', '--batch'] + extra
    fals = os.environ.get('CST_FALSIFY')
    if fals: argv.append('--falsify=' + fals)
    proc = subprocess.run(argv, input='\n'.join(hexes) + '\n',
                          capture_output=True, text=True)
    tr = {}
    for row in csv.DictReader(proc.stdout.splitlines(), delimiter='\t'):
        tr[row['hex']] = row
    sys.stderr.write('isaxcheck %s rows=%d rc=%d\n'
                     % (' '.join(extra) or 'base', len(tr), proc.returncode))
    return tr


def main():
    inscope = {}
    with open(os.path.join(ROOT, 'opcodes.tsv')) as f:
        for row in csv.DictReader(f, delimiter='\t'):
            inscope[row['opcode_id']] = row
    # The Zcmp/Zcmt profile is a SEPARATE enumeration pass, not eight more rows
    # of this one: its encodings are c.fsdsp in the base decoder configuration
    # and the two configurations cannot coexist (zcmp_profile.py has the
    # measurement and QEMU's own refusal to build a CPU with both).  Its rows
    # are joined to a QEMU-truth reference rather than to Sail, which has no
    # clause for either extension.
    zc_ref = {z['opcode_id']: z for z in ZC.ROWS}
    base = {k: v for k, v in inscope.items()
            if v.get('profile', ZC.BASE_PROFILE) != ZC.PROFILE}
    zcmp = {k: v for k, v in inscope.items()
            if v.get('profile') == ZC.PROFILE}
    unref = [k for k in zcmp if k not in zc_ref]
    assert not unref, ('%s-profile rows with no reference: %r' % (ZC.PROFILE, unref))

    rows = json.load(open(os.path.join(HERE, 'rows_vals.json')))
    byid = {}
    for r in rows: byid.setdefault(opcode_id(r), r)
    missing = [k for k in base if k not in byid]
    assert not missing, ('unjoined opcode rows: %d %r' % (len(missing), missing[:5]))

    model = S.Model(SAIL)
    an = S.Analyzer(model)

    # ---- tracer side, one --batch pass per profile
    tr = batch([base[k]['hex'] for k in base], [])
    tr_zc = batch([zcmp[k]['hex'] for k in zcmp],
                  ['--cs-mode-add=' + ZC.CS_MODE_ADD, '--mattr=' + ZC.LLVM_MATTR]) \
            if zcmp else {}

    out = []
    for oid, meta in sorted(zcmp.items()):
        z = zc_ref[oid]
        rec = {'opcode_id': oid, 'mnemonic': meta['mnemonic'], 'hex': meta['hex'],
               'node': z['opcode_id'].split(':')[1], 'ext': z['ext'],
               'family': z['family'], 'profile': ZC.PROFILE,
               'ref_status': 'ok', 'ref_src': ','.join(sorted(z['ref_src'], key=regkey)),
               'ref_dst': ','.join(sorted(z['ref_dst'], key=regkey))}
        t = tr_zc.get(meta['hex'])
        if t is None or t['f_ok'] != '1':
            rec['trc_status'] = 'no-fields'
            rec['trc_src'] = rec['trc_dst'] = ''
        else:
            rec['trc_status'] = 'ok'
            rec['trc_src'] = '' if t['f_src'] == '-' else t['f_src']
            rec['trc_dst'] = '' if t['f_dst'] == '-' else t['f_dst']
            rec['opcode'] = t['f_opcode']
        out.append(rec)

    for oid, meta in sorted(base.items()):
        r = byid[oid]
        node = r['node']
        # positional env: encdec clause parameter i carries the fixed value the
        # representative encoding gives it; the execute clause takes the same
        # union constructor, hence the same positional signature.
        posval = []
        plit = {int(k): v for k, v in r['plit'].items()}
        for i, p in enumerate(r['params']):
            if i in plit: posval.append(plit[i]); continue
            nm = re.match(r'^([a-z_]\w*)', p.strip())
            posval.append(r['fieldvals'].get(nm.group(1)) if nm else None)
        rec = {'opcode_id': oid, 'mnemonic': meta['mnemonic'], 'hex': meta['hex'],
               'node': node, 'ext': meta.get('ext', ''), 'family': meta.get('family', ''),
               'profile': meta.get('profile', ZC.BASE_PROFILE)}
        # ---- reference
        if node not in model.exec_clauses:
            rec['ref_status'] = 'no-execute-clause'
            rec['ref_src'] = rec['ref_dst'] = ''
        else:
            ps, _body = an.pick_arm(node, posval)
            env = {}
            for i, pn in enumerate(ps):
                if i < len(posval) and posval[i] is not None:
                    v = posval[i]
                    if isinstance(v, str) and re.match(r'^-?\d+$', v): v = int(v)
                    env[pn] = v
            eff = an.exec_summary(node, env, posval)
            nfv = r['fieldvals'].get('nf', 1)
            try: nf = int(nfv)
            except Exception: nf = 1
            try: nreg = int(r['fieldvals'].get('nreg', 1))
            except Exception: nreg = 1
            eff = expand_group(eff, nf, nreg)
            src, dst, unk = set(), set(), []
            for role, cls, key in eff:
                c = canon(role, cls, key)
                if c is None:
                    if key is None: unk.append('%s:%s' % (role, cls))
                    continue
                (src if role == 'R' else dst).add(c)
            rec['ref_status'] = 'ok' if not unk else 'ok-partial:' + ','.join(sorted(set(unk)))
            rec['ref_src'] = ','.join(sorted(src, key=regkey))
            rec['ref_dst'] = ','.join(sorted(dst, key=regkey))
        # ---- tracer
        t = tr.get(meta['hex'])
        if t is None or t['f_ok'] != '1':
            rec['trc_status'] = 'no-fields'
            rec['trc_src'] = rec['trc_dst'] = ''
        else:
            rec['trc_status'] = 'ok'
            rec['trc_src'] = '' if t['f_src'] == '-' else t['f_src']
            rec['trc_dst'] = '' if t['f_dst'] == '-' else t['f_dst']
            rec['opcode'] = t['f_opcode']
        out.append(rec)

    # ---- verdicts
    for rec in out:
        if rec['ref_status'].startswith('no-') or rec['trc_status'] != 'ok':
            rec['verdict'] = 'UNPROBED'
            rec['sig'] = rec['ref_status'] if rec['ref_status'].startswith('no-') \
                         else 'tracer:' + rec['trc_status']
            continue
        rs = set(filter(None, rec['ref_src'].split(',')))
        rd = set(filter(None, rec['ref_dst'].split(',')))
        ts = set(filter(None, rec['trc_src'].split(',')))
        td = set(filter(None, rec['trc_dst'].split(',')))
        parts = []
        for tag, ref, trc in (('SRC', rs, ts), ('DST', rd, td)):
            for kind, diff in (('missing', ref - trc), ('extra', trc - ref)):
                c = collections.Counter(gen(m) for m in diff)
                for g in sorted(c, key=regkey):
                    parts.append('%s-%s:%s%s' % (tag, kind, g,
                                                 '' if c[g] == 1 else 'x%d' % c[g]))
        rec['verdict'] = 'AGREE' if not parts else 'DISAGREE'
        rec['sig'] = ';'.join(parts)
        # ---- the two axes.  DIRECTION is measured from the very sets the
        # verdict was taken from, so it cannot drift from it.
        rec['set_relation'] = tax.set_relation(rs, rd, ts, td)
        adj = [adjudicate_part(rec['node'], p) for p in parts]
        done = [a for a in adj if a[0]]
        if not parts:
            rec['adjudication'] = ''
        elif len(done) == len(parts):
            kinds = []
            for k, _ in done:
                if k not in kinds: kinds.append(k)
            rec['adjudication'] = '+'.join(kinds)
            rec['adjudication_note'] = ' | '.join(
                dict.fromkeys(n for _, n in done))
        else:
            miss = any(p.startswith(('SRC-missing', 'DST-missing')) for p in parts)
            extra = any(p.startswith(('SRC-extra', 'DST-extra')) for p in parts)
            rec['adjudication'] = ('MIXED' if miss and extra else
                                   'TRACER-GAP' if miss else 'TRACER-EXTRA')
            # A derived fallback restates which way the sets differ; it names
            # no mechanism, so it accounts for nothing (arc3_rules.RISCV).

            if done:
                rec['adjudication'] += '+' + '+'.join(
                    dict.fromkeys(k for k, _ in done))
                rec['adjudication_note'] = ' | '.join(
                    dict.fromkeys(n for _, n in done))
    return out

def gen(name):
    """generalise a concrete register to its class for signature grouping"""
    m = re.match(r'^REG_(GPR|FPR|VEC|PRED)\d+$', name)
    return 'REG_' + m.group(1) + '<n>' if m else name

def regkey(n):
    m = re.match(r'^REG_([A-Z_]+?)(\d+)$', n)
    return (m.group(1), int(m.group(2))) if m else (n, -1)

if __name__ == '__main__':
    out = main()
    # ---- the two axes, applied to every disagreeing row
    tax_rows, tax_labels = [], collections.Counter()
    for r in out:
        if r['verdict'] != 'DISAGREE':
            r.setdefault('set_relation', tax.EQUAL if r['verdict'] == 'AGREE'
                         else 'NOT-COMPARED')
            r['direction'] = '-' if r['verdict'] == 'AGREE' else 'NOT-COMPARED'
            r['category'] = '-' if r['verdict'] == 'AGREE' else 'reference-gap'
            r['accounted'] = '-'
            continue
        lab = r.get('adjudication', '')
        tax_labels[lab] += 1
        t = tax.classify(r['opcode_id'], r['mnemonic'], lab,
                         r['set_relation'], taxrules.riscv_rule(lab))
        tax_rows.append(t)
        r['direction'] = t.direction
        r['category'] = t.category
        r['accounted'] = '1' if t.accounted else '0'

    cols = ['opcode_id', 'mnemonic', 'hex', 'profile', 'node', 'opcode',
            'ref_status', 'ref_src', 'ref_dst', 'trc_status', 'trc_src', 'trc_dst',
            'verdict', 'adjudication', 'sig', 'adjudication_note',
            'set_relation', 'direction', 'category', 'accounted']
    dest = os.path.join(ROOT, os.environ.get('CST_OUT', 'attrib.tsv'))
    with open(dest, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols, delimiter='\t', extrasaction='ignore')
        w.writeheader()
        for r in out: w.writerow(r)
    c = collections.Counter(r['verdict'] for r in out)
    adj = collections.Counter(r.get('adjudication', '') for r in out
                              if r['verdict'] == 'DISAGREE')
    sigs = collections.Counter(r['sig'] for r in out if r['verdict'] == 'DISAGREE')
    lines = []
    # A disagreement count on its own hides the whole criterion: every
    # disagreeing row is classified on DIRECTION (measured from the sets) and
    # CATEGORY (the mechanism), and the cross-tabulation comes first.
    lines.append('=' * 78)
    lines.append('TWO-AXIS CLASSIFICATION OF THE %d DISAGREEING ROWS' % c['DISAGREE'])
    lines.append('=' * 78)
    lines.append('')
    for d in tax.DIRECTIONS:
        lines.append('  %-16s %s' % (d, tax.DIRECTION_VERDICT[d]))
    lines.append('')
    lines.append(tax.render_crosstab(tax_rows,
                                     'CROSS-TABULATION  direction x category'))
    lines.append('')
    lines.append(tax.render_conflicts(tax_rows))
    lines.append(tax.render_unaccounted(tax_rows))
    lines.append('LABELS WITH NO RULE  (an adjudication the taxonomy does not map')
    lines.append('is not an explanation; its rows are UNACCOUNTED above)')
    _nr = [(k, n) for k, n in tax_labels.most_common()
           if taxrules.riscv_rule(k) is None]
    for k, n in _nr:
        lines.append('  %6d  %s' % (n, k or '(empty)'))
    if not _nr:
        lines.append('  (none)')
    lines.append('')
    lines.append('MEMOP ATTRIBUTION  (count / address / data for every load and')
    lines.append('store) is HALF the deliverable and this harness measures none of')
    lines.append('it: the Sail effect analysis carries the memory clauses and the')
    lines.append('comparison never reads them.  Reported as a hole, not implied to')
    lines.append('be covered by the register numbers below.')
    lines.append('')
    lines.append('riscv64 register attribution: Sail-RISCV reference vs tracer InsnFields')
    lines.append('')
    lines.append('METHOD')
    lines.append('  reference   sail-riscv @ ac2a585506aa (ranked #1 for riscv64).  An')
    lines.append('              interprocedural, value-aware effect analysis over the')
    lines.append('              `function clause execute` bodies: operand values fixed by the')
    lines.append('              representative encoding are propagated so match/if arms the')
    lines.append('              encoding cannot reach are pruned, not unioned.  Leaf accessors')
    lines.append('              (rX/wX, rF*/wF*, rV/wV, read_vreg/write_vreg, read_vmask,')
    lines.append('              read_CSR/write_CSR) carry the register identity; everything')
    lines.append('              else is derived by call-graph propagation.')
    lines.append('  tracer      build/contrib/plugins/isaxcheck --isa=riscv64 --layer=fields')
    lines.append('              --batch, columns f_src / f_dst (the tracer\'s own InsnFields')
    lines.append('              via decode_detail_to_generic).')
    lines.append('  comparison  as SETS, after canonicalising the reference onto the tracer\'s')
    lines.append('              GenericRegId space (R4): x1/x2/x8 -> REG_LR/REG_SP/REG_FP_REG,')
    lines.append('              x0 -> REG_ZERO, fcsr|fflags|frm|vcsr|vxrm|vxsat -> REG_FCSR,')
    lines.append('              vstart|vl|vtype -> REG_VCTRL, every other CSR -> REG_SYS.')
    lines.append('              A write to x0 is not a destination (Sail wX: `0 => ()`).')
    lines.append('')
    lines.append('SCOPE EXCLUSIONS (enumerated, both sides, in sail_effects.BLACKLIST)')
    lines.append('  - address translation, PMP, physical memory and the platform devices')
    lines.append('    (a load\'s satp/mstatus/pmpcfg traffic is memory-system state, not an')
    lines.append('    operand).  The tracer excludes them too, so the comparison stays even.')
    lines.append('  - trap entry.  ECALL/EBREAK therefore compare as empty on both sides')
    lines.append('    (3 rows); their mepc/mcause/mstatus footprint is out of scope here.')
    lines.append('  - CSR access-permission gates (privilege, *stateen): Zicsr fixes the')
    lines.append('    read/write footprint by the (op, rd, rs1) table, not by the gate.')
    lines.append('  - extension dirty-state bookkeeping (mstatus/vsstatus .FS/.VS/.SD).')
    lines.append('')
    lines.append('POWER (the comparison is shown to be able to fail)')
    lines.append('  isaxcheck --falsify=drop-src:<mnem> damages the dependency model')
    lines.append('  after isax_fields_decode(), where a real defect would sit.  Replayed')
    lines.append('  through this comparison:')
    lines.append('    drop-src:ctz      1 row  flips AGREE->DISAGREE (ctz)')
    lines.append('    drop-src:vadd.vv  1 row  flips, signature')
    lines.append('                      SRC-missing:REG_VCTRL;SRC-missing:REG_VEC<n>x3')
    lines.append('    add-dst:fadd.s    1 row  flips, DST-extra:REG_FPR<n>')
    lines.append('  and nothing else moves in any of the three, so an agreement here is')
    lines.append('  a measured agreement.  vadd.vv is the interesting one: it carries')
    lines.append('  the vd-as-source and vl/vtype/vstart terms this pass added, so the')
    lines.append('  new agreements are covered by the falsification and not just the')
    lines.append('  old scalar ones.')
    lines.append('  Reproduce: CST_FALSIFY=drop-src:ctz CST_OUT=fals.tsv python compare.py')
    lines.append('')
    lines.append('SHARED ASSUMPTION (not a disagreement, disclosed)')
    lines.append('  For vector operands whose register-group width comes from LMUL/EMUL in')
    lines.append('  vtype, the group size is a RUNTIME value, so no static attribution can')
    lines.append('  be exact (R1).  Both sides name one register per such operand.  Where')
    lines.append('  the ENCODING fixes the group -- nf (whole-register / segment forms) and')
    lines.append('  nreg (vmv<nr>r.v) -- BOTH sides expand the full group and the')
    lines.append('  comparison is exact.')
    lines.append('')
    prof = collections.Counter(r.get('profile', ZC.BASE_PROFILE) for r in out)
    lines.append('denominator  %d opcodes (opcodes.tsv): %s' % (
        len(out), ', '.join('%s %d' % kv for kv in sorted(prof.items()))))
    lines.append('  the %s profile is a second enumeration pass, not a subset of' % ZC.PROFILE)
    lines.append('  the first: Zcmp/Zcmt displace the compressed FP-store encodings, so')
    lines.append('  its representative encodings decode as c.fsdsp under the base')
    lines.append('  decoder configuration.  Reference for those rows is QEMU\'s own')
    lines.append('  translation (R6) -- Sail has no clause for either extension and')
    lines.append('  LLVM MC models none of their register traffic.')
    lines.append('verdicts     %s' % dict(c))
    lines.append('adjudication %s' % dict(adj))
    lines.append('')
    lines.append('%-6s %-14s %s' % ('count', 'adjudication', 'signature'))
    for sg, n in sigs.most_common():
        a = collections.Counter(r.get('adjudication', '') for r in out
                                if r['sig'] == sg and r['verdict'] == 'DISAGREE')
        lines.append('%-6d %-14s %s' % (n, a.most_common(1)[0][0], sg))
    lines.append('')
    lines.append('nodes per signature')
    for sg, n in sigs.most_common():
        nd = collections.Counter(r['node'] for r in out if r['sig'] == sg
                                 and r['verdict'] == 'DISAGREE')
        lines.append('  %-72s %s' % (sg[:72], ' '.join(
            '%s=%d' % (k, v) for k, v in nd.most_common(10))))
    txt = '\n'.join(lines) + '\n'
    if not os.environ.get('CST_FALSIFY'):
        open(os.path.join(ROOT, 'attrib_signatures.txt'), 'w').write(txt)
    print(txt[:4000])
