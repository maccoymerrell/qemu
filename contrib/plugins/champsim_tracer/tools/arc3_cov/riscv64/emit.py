#!/usr/bin/env python3
"""Emit the riscv64 opcode-space denominator files.

THE DECODE STATUS IS RE-MEASURED HERE, EVERY RUN, and rows.json is written
back.  It used to be read out of rows.json as a frozen fact, and a frozen
fact goes stale silently: `ssamoswap.w` / `ssamoswap.d` sat in excluded.tsv
under "neither decoder in the tracer boundary decodes this encoding" for as
long as it took CS_MODE_RISCV_ZICFISS to be switched on, after which the
sentence was simply false and the denominator was two opcodes short with no
signal that anything had changed.  That is the dead-allowlist-row shape this
project keeps finding, so the classification is derived from a probe of the
tool as it stands, not from a snapshot of how it once behaved -- and every
exclusion reason must match at least one row or this script fails.
"""
import json, re, collections, os, sys, csv, subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'attrib'))
import zcmp_profile as ZC

rows = json.load(open(os.path.join(ROOT, 'rows.json')))
SAIL_SHA = 'ac2a585506aad46b088b3594e56b8c21c52e297e'
ISAX = os.environ.get('CST_ISAXCHECK',
                      '/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck')


def reprobe(rows):
    """Re-decode every representative encoding with the tool as it is now.

    Returns the list of rows whose decode status moved since rows.json, which
    the caller prints: a silent refresh would replace one invisible staleness
    with another."""
    inp = '\n'.join(r['hex'] for r in rows) + '\n'
    seen = {}
    for layer in ('boundary', 'fields'):
        p = subprocess.run([ISAX, '--isa=riscv64', '--layer=' + layer, '--batch'],
                           input=inp, capture_output=True, text=True)
        if p.returncode != 0:
            raise SystemExit('isaxcheck --layer=%s failed rc=%d\n%s'
                             % (layer, p.returncode, p.stderr[-2000:]))
        for row in csv.DictReader(p.stdout.splitlines(), delimiter='\t'):
            seen.setdefault(row['hex'], {}).update(row)
    moved = []
    for r in rows:
        d = seen.get(r['hex'])
        if d is None:
            raise SystemExit('isaxcheck returned no row for %s' % r['hex'])
        was = (int(bool(r['b_ok'])), int(bool(r['l_ok'])), int(r['fields_ok']))
        now = (1 if d['b_ok'] == '1' else 0,
               1 if d['l_ok'] == '1' else 0,
               1 if d.get('f_ok') == '1' else 0)
        if was != now:
            moved.append((r['node'], r['mnemonic'], r['hex'], was, now,
                          d['b_mnem'], d['l_text']))
        r['b_ok'] = bool(now[0]); r['l_ok'] = bool(now[1])
        r['hex_ok'] = now[0]; r['fields_ok'] = now[2]
        r['hex_sz'] = int(d['b_sz'] or 0)
        r['b_mnem'] = d['b_mnem']; r['l_text'] = d['l_text']
        if d.get('b_ops'):
            r['b_ops'] = d['b_ops']
    return moved


VM_FIELD = re.compile(r'(?<![A-Za-z0-9_])vm(?![A-Za-z0-9_])')
VM_BIT = 25


def reseat_vm(rows):
    """Move every RVV representative off the value where the mask is inert.

    THE RULE THIS IS AN INSTANCE OF is mkprobe.py's, stated in its opening
    paragraph for x86: "an EVEX opcode carrying a mask slot is re-probed with
    aaa=001 so the mask operand is actually exercised (C3)".  A probe encoding
    whose field sits at the value where the modelled effect DOES NOT HAPPEN is
    not a probe of that effect.  Every RVV representative here seats `vm = 1`
    -- UNMASKED -- so `v0` is never read and the tracer answer the comparison
    scores is the answer for an instruction that has no mask operand.
    exec106's probe-degeneracy audit measured 586 opcodes in that state
    (probedeg/ADJUDICATION.md).

    WHY IT IS THE SAME SUBJECT AND NOT A NEW ONE.  The Sail encdec clause
    names `vm` as a field OF THE CLAUSE -- `encdec_vvfunct6(funct6) @ vm @
    ...` -- so both values are one opcode by the reference's own
    construction, exactly as `LDR_32_ldst_pos` and `_immpre` are two by
    aarch64's.  Re-seating changes the ENCODING probed and never the OPCODE
    measured.

    THE ACCEPTANCE RULE IS WHAT EXCLUDES THE COMBINATIONS RVV RESERVES.
    `vmv`, `vadc`/`vmadc` and friends FIX `vm`, so their bit-25 variants
    decode to a different instruction or to nothing at all; the variant is
    taken only when LLVM reads it as the SAME MNEMONIC at the SAME LENGTH.
    That is `mkprobe.py`'s own `same_opcode` rule expressed in fixed-width
    terms, and it is the reference deciding, not this file.

    Returns the rows that moved, for printing.  A row that does not move is
    not an error: most of the space has no `vm` field at all.
    """
    cand = [r for r in rows
            if r['bytes'] == 4 and VM_FIELD.search(r['text'])
            and (r['word'] >> VM_BIT) & 1]
    if not cand:
        return [], []
    want = [(r, r['word'] & ~(1 << VM_BIT)) for r in cand]
    inp = '\n'.join(w.to_bytes(4, 'little').hex() for _, w in want) + '\n'
    p = subprocess.run([ISAX, '--isa=riscv64', '--layer=boundary', '--batch'],
                       input=inp, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit('isaxcheck refused the vm re-seat batch rc=%d\n%s'
                         % (p.returncode, p.stderr[-2000:]))
    got = {row['hex']: row
           for row in csv.DictReader(p.stdout.splitlines(), delimiter='\t')}
    moved, refused = [], []
    for r, w in want:
        h = w.to_bytes(4, 'little').hex()
        d = got.get(h)
        if d is None:
            raise SystemExit('isaxcheck returned no row for %s' % h)
        same = (d['l_ok'] == '1'
                and d['l_text'].split()[:1] == r['l_text'].split()[:1]
                and int(d['l_sz'] or 0) == 4)
        if not same:
            refused.append((r['node'], r['mnemonic'], h,
                            d['l_text'] or '(no LLVM decode)'))
            continue
        r['word'] = w
        r['hex'] = h
        moved.append((r['node'], r['mnemonic'], r['hex'], d['l_text']))
    return moved, refused


VM_MOVED, VM_REFUSED = reseat_vm(rows)
print('vm re-seat: %d representative(s) moved to the MASKED encoding, '
      '%d refused by the reference' % (len(VM_MOVED), len(VM_REFUSED)))
for m in VM_REFUSED[:20]:
    print('  refused %-14s %-14s %s  LLVM: %s' % m)
MOVED = reprobe(rows)
print('re-probed %d rows against %s' % (len(rows), ISAX))
if MOVED:
    print('DECODE STATUS MOVED SINCE rows.json -- %d row(s):' % len(MOVED))
    for m in MOVED:
        print('  %-14s %-14s %s  (b,l,f) %s -> %s   %s / %s' % m)
    json.dump(rows, open(os.path.join(ROOT, 'rows.json'), 'w'), indent=1)
    print('rows.json rewritten with the current status')
else:
    print('decode status unchanged since rows.json')

def ext_of(r):
    e = sorted(set(re.findall(r'Ext_(\w+)', r['guard'])))
    if e: return '+'.join(e)
    d = r['file'].split('/')
    # ref/sail-riscv/model/extensions/<EXT>/<file>.sail
    if 'extensions' in d: return d[d.index('extensions') + 1]
    if 'mops' in d: return d[d.index('mops') + 1]
    return 'I'

def family_of(r):
    d = r['file'].split('/')
    if 'extensions' in d: return d[d.index('extensions') + 1]
    if 'mops' in d: return d[d.index('mops') + 1]
    if 'core' in d or 'sys' in d: return 'privileged'
    return 'I'

def combo_str(r):
    if not r['combo']: return ''
    return ','.join('%s=%s' % (k, v) for k, v in sorted(r['combo'].items()))

def lhs_literals(r):
    """enum arms fixed positionally in the clause head, e.g. RTYPE(rs2,rs1,rd,ADD)"""
    m = re.match(r'^mapping clause encdec(?:_compressed)?\s*=\s*\w+\s*\((.*?)\)\s*<->', r['text'])
    if not m: return []
    depth = 0; cur = ''; parts = []
    for ch in m.group(1):
        if ch in '([{': depth += 1
        elif ch in ')]}': depth -= 1
        if depth == 0 and ch == ',': parts.append(cur); cur = ''; continue
        cur += ch
    parts.append(cur)
    return [p.strip() for p in parts if re.match(r'^[A-Z]\w*$', p.strip())]

def opcode_id(r):
    bits = ['SAIL:' + r['node']]
    lits = lhs_literals(r)
    if lits: bits.append(','.join(lits))
    c = combo_str(r)
    if c: bits.append(c)
    return ':'.join(bits)

def shape(r):
    """operand shape: the decoder-visible operand list of the representative"""
    return r['b_ops'] if r.get('b_ops') else ''

# ------------------------------------------------------------ classification
ZCF = {'C_FLW', 'C_FSW', 'C_FLWSP', 'C_FSWSP'}
# Every exclusion reason is a claim about the decode boundary as it is TODAY.
# A claim that matches no row is a claim nobody can check, and the SSAMOSWAP
# entry that used to sit here is what that looks like when it goes wrong: it
# outlived the decoder change that falsified it and cost the denominator two
# opcodes.  So each reason carries a tag, the tags are counted, and a tag that
# fires zero times ends the run.
RCOUNT = collections.Counter()
def excluded(r, tag, reason):
    RCOUNT[tag] += 1
    r['xreason'] = reason
    r['xtag'] = tag
    return r

incl, excl = [], []
for r in rows:
    if r['node'] in ZCF:
        excl.append(excluded(r, 'zcf',
                    'RV32-only extension Zcf: on RV64 this encoding space IS '
                    'c.ld/c.sd (decoders confirm: decodes as ld/sd)')); continue
    if not r['hex_ok']:
        e = ext_of(r)
        if 'Zabha' in e or (r['node'] == 'AMO'):
            excl.append(excluded(r, 'zabha',
                        'Zabha (byte/halfword AMO): QEMU implements it '
                        '(target/riscv/insn_trans/trans_rvzabha.c.inc) but neither the '
                        'Capstone 6.0.0-Alpha7 RISCV mode set nor the LLVM-18 mattr list '
                        'in isaxcheck carries Zabha -- decode-boundary gap, not an ISA gap'))
        elif 'Zvabd' in e:
            excl.append(excluded(r, 'zvabd',
                        'Zvabd (draft vector abs-diff): not in QEMU, not in either decoder'))
        elif 'Zibi' in e:
            excl.append(excluded(r, 'zibi',
                        'Zibi (draft branch-with-immediate): not in QEMU, not in either decoder'))
        else:
            excl.append(excluded(r, 'nodecode',
                        'does not decode in the tracer decode boundary'))
        continue
    incl.append(r)

# The NAMED reasons -- each one asserts something specific about a specific
# extension -- must every one of them match a row.  `nodecode` is the residual
# and is allowed to be empty; when it is not, its rows are printed, because an
# opcode excluded with no reason beyond "it did not decode" is a reason nobody
# has written yet.
NAMED_TAGS = ('zcf', 'zabha', 'zvabd', 'zibi')
dead = [t for t in NAMED_TAGS if not RCOUNT[t]]
if dead:
    raise SystemExit(
        'DEAD EXCLUSION REASON(S): %s matched no row.  The decode boundary has '
        'moved under this script: either the opcodes now decode and belong in '
        'opcodes.tsv, or the reason is describing something that no longer '
        'exists.  Do not delete the tag without saying which.' % ', '.join(dead))
if RCOUNT['nodecode']:
    print('UNNAMED no-decode rows (%d) -- each needs a reason of its own:'
          % RCOUNT['nodecode'])
    for r in excl:
        if r.get('xtag') == 'nodecode':
            print('  %-16s %-20s %s' % (r['node'], r['mnemonic'], r['hex']))

# --------------------------------------------------------------- opcodes.tsv
# The `profile` column names the decoder configuration a row's representative
# encoding was enumerated under.  It exists because the riscv64 opcode space
# is not enumerable in one configuration: Zcmp/Zcmt displace the compressed
# FP-store space that RV64GC occupies, so the two profiles are alternatives,
# not layers (zcmp_profile.py carries the measurement and the QEMU citation).
with open(os.path.join(ROOT, 'opcodes.tsv'), 'w') as fh:
    fh.write('opcode_id\tmnemonic\thex\tsource_table\tprofile\n')
    for r in incl:
        fh.write('%s\t%s\t%s\t%s\t%s\n' % (
            opcode_id(r), r['mnemonic'], r['hex'],
            'sail-riscv@%s:%s' % (SAIL_SHA[:12], r['file'].replace('ref/sail-riscv/', '')),
            ZC.BASE_PROFILE))
    for z in ZC.ROWS:
        fh.write('%s\t%s\t%s\t%s\t%s\n' % (
            z['opcode_id'], z['mnemonic'], z['hex'],
            'QEMU target/riscv (R6) + RISC-V Zc spec', ZC.PROFILE))

with open(os.path.join(ROOT, 'opcodes_full.tsv'), 'w') as fh:
    fh.write('opcode_id\tmnemonic\thex\tsource_table\textension\tsail_node\t'
             'decoded_size\tcapstone_mnemonic\tllvm_text\tfields_layer_ok\tfamily\t'
             'profile\tnote\n')
    for r in incl:
        note = ''
        if r['b_mnem'].strip().lower() != r['mnemonic'].lower():
            note = 'decoder prints alias/base form'
        if r['node'] in ('SSPUSH', 'SSPOPCHK', 'SSRDP', 'C_SSPUSH', 'C_SSPOPCHK'):
            note = ('decode boundary resolves this to its Zimop/Zcmop base encoding: '
                    'Zicfiss is not enabled in the Capstone mode set / LLVM mattr list')
        if r['node'] in ('ZIMOP_MOP_R', 'ZIMOP_MOP_RR', 'ZCMOP'):
            note = 'hint-number field is generic (C3): one row covers all mop numbers'
        fh.write('%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s\t%s\t%s\n' % (
            opcode_id(r), r['mnemonic'], r['hex'],
            'sail-riscv@%s:%s' % (SAIL_SHA[:12], r['file'].replace('ref/sail-riscv/', '')),
            ext_of(r), r['node'], r['hex_sz'], r['b_mnem'], r['l_text'],
            r['fields_ok'], family_of(r), ZC.BASE_PROFILE, note))
    for z in ZC.ROWS:
        fh.write('%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s\t%s\t%s\n' % (
            z['opcode_id'], z['mnemonic'], z['hex'],
            'QEMU target/riscv (R6) + RISC-V Zc spec', z['ext'], '-', 2,
            z['mnemonic'], z['asm'], 1, z['family'], ZC.PROFILE,
            'enumerated in the ' + ZC.PROFILE + ' profile: Zcmp/Zcmt are '
            'EXCLUSIVE with the Zcd that C+D implies, so this encoding is '
            'c.fsdsp in the ' + ZC.BASE_PROFILE + ' profile'))

# -------------------------------------------------------------- excluded.tsv
rv32 = json.load(open(os.path.join(ROOT, 'rv32_only.json')))
RV64_ALSO = {'rev8', 'zext.h'}
with open(os.path.join(ROOT, 'excluded.tsv'), 'w') as fh:
    fh.write('opcode_id\tmnemonic\thex\tsource_table\tclass\treason\n')
    for r in excl:
        fh.write('%s\t%s\t%s\t%s\t%s\t%s\n' % (
            opcode_id(r), r['mnemonic'], r['hex'],
            'sail-riscv@%s:%s' % (SAIL_SHA[:12], r['file'].replace('ref/sail-riscv/', '')),
            'no-decode' if not r['hex_ok'] else 'rv32-only', r['xreason']))
    for node, mn in sorted(rv32, key=lambda x: x[1]):
        if mn in RV64_ALSO:
            reason = ('RV32 encoding of an opcode that also exists on RV64 (the RV64 '
                      'encoding IS in opcodes.tsv); not a separate RV64 opcode')
        else:
            reason = 'RV32-only opcode (Sail guard xlen == 32 / in32BitMode()); absent from RV64'
        fh.write('SAIL:%s\t%s\t-\t%s\t%s\t%s\n' % (node, mn, 'sail-riscv@' + SAIL_SHA[:12],
                                                   'rv32-only', reason))
    for node, why in [
        ('ILLEGAL', 'Sail wildcard catch-all for undefined 32-bit encodings; not an opcode'),
        ('C_ILLEGAL', 'Sail wildcard catch-all for undefined 16-bit encodings; not an opcode'),
        ('STOP_FETCHING', 'rmem concurrency-model pseudo-instruction (0xfade...); not RISC-V'),
        ('THREAD_START', 'rmem concurrency-model pseudo-instruction (0xc0de...); not RISC-V')]:
        fh.write('SAIL:%s\t-\t-\tsail-riscv@%s\tnon-instruction\t%s\n' % (node, SAIL_SHA[:12], why))

# ------------------------------------------------------------- manifest.json
man = {
    'isa': 'riscv64',
    'reference': {'name': 'Sail-RISCV (riscv/sail-riscv)', 'sha': SAIL_SHA,
                  'date': '2026-08-20', 'path': 'ref/sail-riscv',
                  'rank': 'ranked #1 for riscv64; LLVM MC used only as a decode cross-check'},
    'encdec_clauses_total': 464,
    'clauses_parsed': 462,
    'opcodes_in_scope': len(incl) + len(ZC.ROWS),
    'opcodes_in_scope_by_profile': {ZC.BASE_PROFILE: len(incl), ZC.PROFILE: len(ZC.ROWS)},
    'opcodes_excluded_rows': len(excl),
    'exclusion_reason_counts': dict(RCOUNT),
    'profiles': {
        ZC.BASE_PROFILE: {'cs_mode_add': None, 'llvm_mattr': 'kIsaTable riscv64 row',
                          'reference': 'Sail-RISCV'},
        ZC.PROFILE: {'cs_mode_add': ZC.CS_MODE_ADD, 'llvm_mattr': ZC.LLVM_MATTR,
                     'reference': 'QEMU target/riscv translation (R6); Sail has '
                                  'no clause for Zcmp/Zcmt and LLVM MC models no '
                                  'register traffic for them'},
    },
    'rv32_only_clauses': len(rv32),
    'verification': 'isaxcheck --isa=riscv64 --hex=<bytes> run once per row, plus --batch',
    'ext_histogram': dict(collections.Counter(ext_of(r) for r in incl).most_common()),
    'family_histogram': dict(collections.Counter(family_of(r) for r in incl).most_common()),
}
json.dump(man, open(os.path.join(ROOT, 'manifest.json'), 'w'), indent=1)
print('in scope', len(incl) + len(ZC.ROWS),
      '(%s %d + %s %d)' % (ZC.BASE_PROFILE, len(incl), ZC.PROFILE, len(ZC.ROWS)),
      'excluded rows', len(excl))
print('exclusion reasons', dict(RCOUNT))
for k, v in collections.Counter(family_of(r) for r in incl).most_common(): print('  %-16s %d' % (k, v))
