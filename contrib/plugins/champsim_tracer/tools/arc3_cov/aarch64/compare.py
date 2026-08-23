"""Compare the tracer's InsnFields register sets against the A64 reference."""
import csv, json, collections, re, sys

BASE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64'

# ---------------------------------------------------------- canonical names
def canon_gpr(n):
    if n == 31:
        return 'ZERO'
    if n == 30:
        return 'LR'
    if n == 29:
        return 'FP_REG'
    return 'GPR%d' % n


# The tracer's GenericRegId space is the thing being measured, so every
# mapping change has to land here too or the comparison reports the drift
# instead of the model.  cf574b77d4 split two AArch64 collisions:
#   FFR left REG_VCTRL (which now carries VG, the vector-granule count)
#        for REG_PRED16, the first slot past the architectural predicate
#        file -- FFR is predicate-shaped and predicate-addressed.
#   ZT0  left REG_MATRIX (which keeps the 33 overlapping VIEWS of the ZA
#        array, aliases by R8.2) for REG_VEC32.  ZT0 is the SME2
#        lookup-table register: separate state, not a view of ZA.
TRC_MAP = {
    'REG_FLAGS': 'FLAGS', 'REG_FCSR': 'FCSR', 'REG_SYS': 'SYS', 'REG_TLS': 'TLS',
    'REG_SP': 'SP', 'REG_LR': 'LR', 'REG_FP_REG': 'FP_REG', 'REG_ZERO': 'ZERO',
    'REG_IP': 'IP', 'REG_MATRIX': 'MATRIX', 'REG_VCTRL': 'VCTRL',
    'REG_PRED16': 'FFR', 'REG_VEC32': 'ZT0',
}


def trc_tok(t):
    t = t.strip()
    if not t or t == '-':
        return None
    if t in TRC_MAP:
        return TRC_MAP[t]
    m = re.fullmatch(r'REG_(GPR|VEC|PRED|FPR)(\d+)', t)
    if m:
        k, n = m.group(1), int(m.group(2))
        if k == 'GPR':
            return canon_gpr(n)
        if k in ('VEC', 'FPR'):
            return 'VEC%d' % n
        return 'PRED%d' % n
    return t


LLVM_MAP = {'nzcv': 'FLAGS', 'fpcr': 'FCSR', 'fpsr': 'FCSR', 'sp': 'SP',
            'zr': 'ZERO', 'ffr': 'FFR', 'zt0': 'ZT0', 'pc': 'IP'}


def llvm_tok(t):
    t = t.strip()
    if not t or t == '-':
        return None
    if t in LLVM_MAP:
        return LLVM_MAP[t]
    if t.startswith('za'):
        return 'MATRIX'
    m = re.fullmatch(r'([rvpq])(\d+)', t)
    if m:
        k, n = m.group(1), int(m.group(2))
        if k == 'r':
            return canon_gpr(n)
        if k in ('v', 'q'):
            return 'VEC%d' % n
        return 'PRED%d' % n
    return t


# reference token space is already canonical except PC
def ref_tok(t):
    return 'IP' if t == 'PC' else t


CLASS_RE = re.compile(r'^(GPR|VEC|PRED)\d+$')

# Tier B: architectural state that is EXECUTION CONTEXT rather than an
# operand -- the PSTATE mode bits (SM, EL, UAO, DIT, ...) and the program
# counter.  The tracer's generic register space has no class for any of
# them, so a difference here is a representational boundary, not an
# attribution error.  Counted and reported separately, never dropped.
def tier_b(t):
    return t == 'IP' or t.startswith('PSTATE.')


def split_tiers(s):
    return set(x for x in s if not tier_b(x)), set(x for x in s if tier_b(x))


def klass(t):
    m = CLASS_RE.match(t)
    return (m.group(1) + '#') if m else t


def signature(rs, rd, ts, td):
    items = []
    for lab, ref, trc in (('SRC', rs, ts), ('DST', rd, td)):
        for t in sorted(ref - trc):
            items.append('%s+ref:%s' % (lab, klass(t)))
        for t in sorted(trc - ref):
            items.append('%s+trc:%s' % (lab, klass(t)))
    return ' '.join(sorted(collections.Counter(items).elements()))


def parse_set(field, fn):
    if not field:
        return set()
    inner = field[field.index('{') + 1:field.rindex('}')] if '{' in field else field
    out = set()
    for t in inner.split(','):
        v = fn(t)
        if v:
            out.add(v)
    return out


def main():
    rows = list(csv.DictReader(open(BASE + '/opcodes.tsv'), delimiter='\t'))
    ref = json.load(open(BASE + '/ref_mra.json'))

    trc = {}
    for line in open(BASE + '/tracer_fields.tsv'):
        p = line.rstrip('\n').split('\t')
        if len(p) < 5:
            continue
        trc[p[0]] = (p[2], p[3], p[4])

    llvm = {}
    with open(BASE + '/fields_all.txt') as f:
        rd = csv.DictReader(f, delimiter='\t')
        for x in rd:
            llvm[x['hex']] = (x['l_rd'], x['l_wr'], x['l_ok'])

    out = open(BASE + '/attrib.tsv', 'w')
    cols = ['opcode_id', 'mnemonic', 'hex', 'disasm', 'instr_class', 'ref_rank',
            'ref_status', 'ref_src', 'ref_dst', 'trc_src', 'trc_dst',
            'verdict', 'signature', 'tierB_ref_only', 'llvm_src', 'llvm_dst',
            'mra_vs_llvm', 'notes']
    out.write('\t'.join(cols) + '\n')

    counts = collections.Counter()
    sigs = collections.Counter()
    sig_examples = collections.defaultdict(list)
    xcheck = collections.Counter()
    xsig = collections.Counter()

    for x in rows:
        h = x['hex']
        r = ref.get(h, {'status': 'missing', 'notes': ['no-ref-row']})
        t = trc.get(h)
        lv = llvm.get(h)
        ls = parse_set(lv[0], llvm_tok) if lv else set()
        ld = parse_set(lv[1], llvm_tok) if lv else set()

        if t is None:
            verdict, rank, rs, rd_, ts, td, sig = 'unprobed', '-', set(), set(), set(), set(), 'no-tracer-row'
            counts['unprobed'] += 1
        else:
            ts = parse_set(t[1], trc_tok)
            td = parse_set(t[2], trc_tok)
            if r['status'] == 'ok':
                rank = '1:MRA'
                rs = set(ref_tok(y) for y in r['src'])
                rd_ = set(ref_tok(y) for y in r['dst'])
            elif lv and lv[2] == '1':
                rank = '2:LLVM-MC'
                rs, rd_ = set(ls), set(ld)
            else:
                rank = '-'
                rs = rd_ = set()
            rsa, rsb = split_tiers(rs)
            rda, rdb = split_tiers(rd_)
            tsa, _ = split_tiers(ts)
            tda, _ = split_tiers(td)
            tierb = ','.join(sorted(rsb | rdb)) or '-'
            if rank == '2:LLVM-MC':
                tierb = '-'
            if rank == '-':
                verdict = 'unprobed'
                sig = 'no-reference'
                counts['unprobed'] += 1
            elif rsa == tsa and rda == tda:
                verdict = 'agree'
                sig = ''
                counts['agree'] += 1
                if rsb or rdb:
                    counts['agree_with_tierB_refonly'] += 1
            else:
                verdict = 'disagree'
                sig = signature(rsa, rda, tsa, tda)
                counts['disagree'] += 1
                sigs[sig] += 1
                if len(sig_examples[sig]) < 8:
                    sig_examples[sig].append('%s | %s | ref S{%s} D{%s} | trc S{%s} D{%s}' % (
                        x['opcode_id'], x['llvm_disasm'][:34],
                        ','.join(sorted(rsa)) or '-', ','.join(sorted(rda)) or '-',
                        ','.join(sorted(tsa)) or '-', ','.join(sorted(tda)) or '-'))
        # rank1-vs-rank2 cross-check on the reference itself
        mv = '-'
        if r['status'] == 'ok' and lv and lv[2] == '1':
            m1 = split_tiers(set(ref_tok(y) for y in r['src']))[0]
            m2 = split_tiers(set(ref_tok(y) for y in r['dst']))[0]
            if m1 == ls and m2 == ld:
                mv = 'same'
            else:
                mv = signature(m1, m2, ls, ld)
                xsig[mv] += 1
            xcheck[mv == 'same'] += 1

        out.write('\t'.join([
            x['opcode_id'], x['mnemonic'], h, x['llvm_disasm'], x['instr_class'],
            rank, r['status'],
            ','.join(sorted(rs)) or '-', ','.join(sorted(rd_)) or '-',
            ','.join(sorted(ts)) or '-', ','.join(sorted(td)) or '-',
            verdict, sig or '-', tierb if t is not None else '-',
            ','.join(sorted(ls)) or '-', ','.join(sorted(ld)) or '-',
            mv, ';'.join(r.get('notes', [])) or '-']) + '\n')
    out.close()

    with open(BASE + '/attrib_signatures.txt', 'w') as f:
        f.write('TOTALS %s\n\n' % dict(counts))
        f.write('DISAGREEMENT SIGNATURES (largest first)\n')
        for s, n in sigs.most_common():
            f.write('%6d  %s\n' % (n, s))
            for e in sig_examples[s]:
                f.write('        eg %s\n' % e)
        f.write('\nREFERENCE CROSS-CHECK rank1(MRA) vs rank2(LLVM MC): same=%d differ=%d\n'
                % (xcheck[True], xcheck[False]))
        for s, n in xsig.most_common(40):
            f.write('%6d  %s\n' % (n, s))
    print(dict(counts))
    print('distinct signatures', len(sigs))
    for s, n in sigs.most_common(25):
        print('%6d  %s' % (n, s))
    print('MRA vs LLVM: same=%d differ=%d' % (xcheck[True], xcheck[False]))


if __name__ == '__main__':
    main()
