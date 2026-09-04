"""Compare the tracer's InsnFields register sets against the A64 reference."""
import csv
import re, json, collections, re, sys, os

BASE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64'

# The two-axis taxonomy is shared by all four ISA harnesses.  A harness runs
# from a working copy beside its evidence, so look there first and fall back to
# the tree, which is the source of truth.
_D = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.environ.get(
    'CST_ARC3_TOOLS',
    '/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/arc3_cov')
for _p in (_D, os.path.dirname(_D), _TOOLS):
    if os.path.exists(os.path.join(_p, 'arc3_taxonomy.py')):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break
else:
    sys.exit('arc3_taxonomy.py not found (set CST_ARC3_TOOLS)')
if _D not in sys.path:
    sys.path.insert(0, _D)
import arc3_taxonomy as tax
import arc3_rules as taxrules
# The adjudication table lives with the adjudicator; the taxonomy translates it
# rather than restating it, so there is exactly one place a verdict is written.
from adjudicate import ADJ as _ADJ
TAXRULES = taxrules.aarch64_rules(_ADJ)

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
    # FPCR moved off REG_FCSR: it is the CONTROL word every FP instruction
    # reads, REG_FCSR is the STATUS word they write, and one id for both
    # manufactured a read-after-write edge between consecutive unrelated FP
    # instructions.  The reference's token space still spells both 'FCSR',
    # so both generic ids resolve to it here.
    'REG_FPCW': 'FCSR',
    'REG_SP': 'SP', 'REG_LR': 'LR', 'REG_FP_REG': 'FP_REG', 'REG_ZERO': 'ZERO',
    'REG_PC': 'PC', 'REG_MATRIX': 'MATRIX', 'REG_VCTRL': 'VCTRL',
    'REG_PRED16': 'FFR', 'REG_VEC32': 'ZT0',
    # The R8 split of the AArch64 system-register file (cap_aarch64_sysreg_class)
    # gives the privileged file one generic ID per DEPENDENCE-BEHAVIOUR group
    # instead of one for all 1,213 registers.  The reference's token space has
    # a single 'SYS' for the whole file -- it resolves NAMES, and the split is
    # a claim about GROUPS -- so every group folds back to 'SYS' here.  That
    # keeps a mapping change from being scored as an attribution change; it
    # also means this instrument is blind to the split, whose evidence is the
    # 1,213-encoding census, not this table.
    'REG_SYS': 'SYS', 'REG_SYSEXC': 'SYS', 'REG_SYSMMU': 'SYS',
    'REG_SYSTIMER': 'SYS', 'REG_SYSPERF': 'SYS', 'REG_SYSDBG': 'SYS',
    'REG_SYSCACHE': 'SYS', 'REG_SYSID': 'SYS', 'REG_COPROC0': 'SYS',
    'REG_COPROC1': 'SYS',
    # REG_SYSFPEN is the exception: R7.4's gate is the thing being measured,
    # so the reference was given the matching token (mra_ref.FPEN_REGS) and
    # the two are compared directly.
    'REG_SYSFPEN': 'SYSFPEN',
    # GCSPR_ELx is the AArch64 guarded-control-stack pointer, the same
    # register role as x86 CET SSP and RISC-V ssp.
    'REG_SSP': 'SSP',
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
            'zr': 'ZERO', 'ffr': 'FFR', 'zt0': 'ZT0', 'pc': 'PC'}


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


# reference token space is already canonical
def ref_tok(t):
    return t


CLASS_RE = re.compile(r'^(GPR|VEC|PRED)\d+$')

# Tier B: architectural state that is EXECUTION CONTEXT rather than an
# operand -- the PSTATE mode bits (SM, EL, UAO, DIT, ...) and the program
# counter.  The tracer's generic register space has no class for any of
# them, so a difference here is a representational boundary, not an
# attribution error.  Counted and reported separately, never dropped.
def tier_b(t):
    return t == 'PC' or t.startswith('PSTATE.')


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


REFFIX = collections.Counter()


def ref_correct(x, rs, rd_):
    """Corrections applied to the REFERENCE, each with a third witness.

    The project's settled policy for a proven reference defect is to CORRECT
    the reference, not to label the row (R7.1, R7.3, R7.7).  Every rule here
    is COUNTED: a rule whose count falls to zero has stopped reaching its
    subject and is a finding, not a pass.
    """
    mn = x['mnemonic']
    dis = x.get('llvm_disasm') or x.get('asm_template') or ''
    if not dis:
        # A rule that cannot find its subject must FAIL, not silently apply
        # to everything: without the disassembly RF-3 cannot tell a
        # register-less TLBI from `at s1e1r, x16`.
        raise SystemExit('opcodes.tsv carries no disassembly column; RF-3 '
                         'cannot decide whether a system instruction names '
                         'an Xt operand')

    # RF-1 (R7.1) -- MOVT writes 64 bits into the 512-byte ZT0 table and
    # leaves the rest alone.  The MRA's execute ASL spells that as
    # `result = ZT0; Elem[result, offset, 64] = X[t, 64]; ZT0[512] = result`,
    # so ZT0 reads as a source.  R7.1 is binding and says the opposite: a
    # narrow write does not make a register a source, because rename does
    # not know the data-width scope of the next reader.  The tracer is
    # right; this deletes the preserve-read the reference manufactured.
    # SCOPE IS THE CLASS, not the row: MOVT is the only ZT0 form that
    # writes PART of the table (LDR ZT0 writes all of it, STR ZT0 reads it).
    if mn == 'movt' and 'ZT0' in rs and 'ZT0' in rd_:
        rs.discard('ZT0')
        REFFIX['RF-1 R7.1: MOVT\'s partial ZT0 write is not a ZT0 read'] += 1

    # RF-2 -- the generic HINT subject's representative encoding is
    # `hint #35`, which is UNALLOCATED: llvm-mc -mattr=+all prints a bare
    # `hint #35` with no alias, Capstone prints `hint #0x23`, and QEMU's
    # translate-a64 has no case for it, so a guest executes a NOP.  The MRA
    # arm evaluates the HINT page's execute ASL, which covers the WHOLE hint
    # space, so CHKFEAT's X16 traffic and its system-register write arrive
    # on an encoding that performs neither.  The reference is describing a
    # different instruction.
    if x['opcode_id'] == 'HINT_HM_hints':
        if rs or rd_:
            REFFIX['RF-2 hint #35 is unallocated: a NOP, not CHKFEAT '
                   '(LLVM +all and QEMU over the MRA hint page)'] += 1
        rs, rd_ = set(), set()

    # RF-3 -- a TLBI form with no Xt operand.  TLBI VMALLE1IS takes no
    # register; the architecture requires Rt == 0b11111 in the encoding.
    # The representative encoding carries Rt = 28, which is malformed, and
    # the MRA arm reads the field anyway.  A reference reading an operand
    # the disassembly does not name is reading the representative encoding,
    # not the instruction.
    if mn in ('tlbi', 'dc', 'ic', 'at') and not re.search(r',\s*[xw]\d', dis):
        gp = set(y for y in rs if y.startswith('GPR'))
        if gp:
            rs -= gp
            REFFIX['RF-3 a register-less system instruction has no Xt: the '
                   'MRA read a RES1 encoding field'] += 1
    return rs, rd_


def reprobe_or_refuse():
    """The tracer arm is RE-DERIVED here, never trusted from disk.

    THE FAILURE THIS EXISTS FOR: an arm scored off a file is an arm nobody
    re-ran.  x86_64's attribution report published a verdict computed from a
    `tracer_batch.tsv` built four hours before the commits it claimed to
    measure, and this leg has the same shape -- `tracer_fields.tsv` is
    written by reprobe.py and then read by whoever runs next.  The probe
    costs well under a second over 3,920 encodings, so the file is checked
    against a live one and a mismatch stops the report.
    """
    fn = BASE + '/tracer_fields.tsv'
    try:
        import reprobe
    except ImportError:
        sys.exit('CANNOT RE-PROBE: reprobe.py is not importable beside '
                 'compare.py; the tracer arm cannot be verified and a check '
                 'that cannot find its subject must fail')
    fresh, _ = reprobe.render()
    try:
        have = open(fn).read()
    except OSError:
        sys.exit('NO TRACER ARM: %s does not exist.  Run reprobe.py.' % fn)
    if have == fresh:
        return
    a, b = have.splitlines(), fresh.splitlines()
    moved = sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
    sys.exit('STALE TRACER ARM -- %s does not match a fresh probe of the '
             'live binary: %d of %d rows differ.  The attribution numbers '
             'this report would print are not true at this tip; run '
             'reprobe.py and score again.' % (fn, moved, max(len(a), len(b))))


def main():
    reprobe_or_refuse()
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
    # ---- THE LLVM ARM IS A CACHE AND MUST COVER THE DENOMINATOR ----------
    #
    # fields_all.txt is an isaxcheck --batch dump over opcodes.tsv, kept on
    # disk.  Nothing re-derived it, so a representative that MOVED silently
    # lost its cross-check row and the `llvm_src` column simply read '-' --
    # the same shape as the tracer_fields.tsv staleness this harness already
    # has a guard for.  MEASURED: re-seating `movprfx_z_p_z_` at its merging
    # M bit orphaned exactly one row, and nothing said so.
    #
    # Missing rows are therefore counted and named.  A blank llvm_src is a
    # legitimate state for a row LLVM does not decode; it is not a legitimate
    # state for a row the cache was never asked about, and the two are
    # indistinguishable downstream, so the refusal is here.
    uncov = [x['hex'] for x in rows if x['hex'] not in llvm]
    if uncov:
        sys.exit('REFUSED: %d of %d opcodes.tsv encodings have no row in '
                 'fields_all.txt -- the LLVM cross-check cache does not cover '
                 'the denominator and those rows would read as "LLVM says '
                 'nothing" when nothing asked LLVM.  Re-derive it:\n'
                 "  cut -f3 opcodes.tsv | tail -n +2 | isaxcheck "
                 '--isa=aarch64 --batch > fields_all.txt\n  first missing: %s'
                 % (len(uncov), len(rows), ' '.join(uncov[:8])))

    out = open(BASE + '/attrib.tsv', 'w')
    cols = ['opcode_id', 'mnemonic', 'hex', 'disasm', 'instr_class', 'ref_rank',
            'ref_status', 'ref_src', 'ref_dst', 'trc_src', 'trc_dst',
            'verdict', 'signature', 'tierB_ref_only', 'llvm_src', 'llvm_dst',
            'mra_vs_llvm', 'notes',
            'set_relation', 'direction', 'category', 'accounted']
    out.write('\t'.join(cols) + '\n')

    counts = collections.Counter()
    sigs = collections.Counter()
    sig_examples = collections.defaultdict(list)
    xcheck = collections.Counter()
    xsig = collections.Counter()
    tax_rows = []                       # the two-axis classification per DISAGREE
    tax_sigs = collections.Counter()    # measured rows per adjudication key

    for x in rows:
        trow = None
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
                rs, rd_ = ref_correct(x, rs, rd_)
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
                # ---- the two axes.  DIRECTION is measured from the very sets
                # the verdict was taken from, so it cannot drift from it.
                rel = tax.set_relation(rsa, rda, tsa, tda)
                tax_sigs[sig] += 1
                tax_rows.append(tax.classify(x['opcode_id'], x['mnemonic'],
                                             sig, rel, TAXRULES.get(sig)))
                trow = tax_rows[-1]
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
            mv, ';'.join(r.get('notes', [])) or '-',
            trow.relation if trow else (tax.EQUAL if verdict == 'agree'
                                        else 'NOT-COMPARED'),
            trow.direction if trow else ('-' if verdict == 'agree'
                                         else 'NOT-COMPARED'),
            trow.category if trow else ('-' if verdict == 'agree'
                                        else 'reference-gap'),
            ('1' if trow.accounted else '0') if trow else '-']) + '\n')
    out.close()

    # ------------------------------------------------------------ two axes
    # A disagreement count on its own hides the whole criterion: every
    # disagreeing row is classified on DIRECTION (measured from the sets) and
    # CATEGORY (the mechanism), and the cross-tabulation is printed first.
    taxtxt = ['=' * 78,
              'TWO-AXIS CLASSIFICATION OF THE %d DISAGREEING ROWS'
              % counts['disagree'], '=' * 78, '']
    for d in tax.DIRECTIONS:
        taxtxt.append('  %-16s %s' % (d, tax.DIRECTION_VERDICT[d]))
    taxtxt += ['', tax.render_crosstab(
        tax_rows, 'CROSS-TABULATION  direction x category'), '',
        tax.render_conflicts(tax_rows), tax.render_unaccounted(tax_rows)]
    taxtxt.append('LABELS WITH NO RULE  (an adjudication the taxonomy does not')
    taxtxt.append('map is not an explanation; its rows are UNACCOUNTED above)')
    nr = [(k, n) for k, n in tax_sigs.most_common() if k not in TAXRULES]
    for k, n in nr:
        taxtxt.append('  %6d  %s' % (n, k))
    if not nr:
        taxtxt.append('  (none)')
    taxtxt.append('')
    # An adjudication whose prose states a row count is making a checkable
    # claim about the measurement.  When it stops matching, either the tree
    # moved under the adjudication or the adjudication was never right.
    bad = tax.check_stated(TAXRULES, tax_sigs)
    taxtxt.append('STATED-COUNT CHECK  (an adjudication that says "N rows." is '
                  'checked against')
    taxtxt.append('the measurement; a mismatch is a finding, not a rounding)')
    if bad:
        for k, st, got in bad:
            taxtxt.append('  MISMATCH  stated %-4d measured %-4d  %s'
                          % (st, got, k))
    else:
        taxtxt.append('  every stated row count matches the measurement')
    taxtxt.append('')
    taxtxt.append('MEMOP ATTRIBUTION  (count / address / data for every load '
                  'and store) is HALF')
    taxtxt.append('the deliverable and this harness measures none of it: the '
                  'reference carries')
    taxtxt.append('mem_r / mem_w per subject and the comparison never reads '
                  'them.  Reported as')
    taxtxt.append('a hole, not implied to be covered by the register numbers.')
    taxtxt = '\n'.join(taxtxt) + '\n'
    print(taxtxt)

    with open(BASE + '/attrib_signatures.txt', 'w') as f:
        f.write(taxtxt + '\n')
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
    print('REFERENCE CORRECTIONS (a rule that reaches nothing is a finding):')
    for k, n in sorted(REFFIX.items()):
        print('%6d  %s' % (n, k))
    for k in ('RF-1', 'RF-2', 'RF-3'):
        if not any(x.startswith(k) for x in REFFIX):
            print('       0  %s -- INERT, it no longer reaches its subject'
                  % k)


if __name__ == '__main__':
    main()
