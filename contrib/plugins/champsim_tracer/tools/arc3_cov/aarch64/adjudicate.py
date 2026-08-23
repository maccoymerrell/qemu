"""Adjudicated summary of the aarch64 register-attribution measurement."""
import csv, collections

BASE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64'

# signature -> (who is right, why)
ADJ = {
 'SRC+ref:FCSR': ('TRACER MISSES A READ',
    'FPCR is an input: BF16 (FPCR.EBF) on bfdot/bfmmla/bfmlal, the rounding '
    'mode on fixed-point fcvtz*/scvtf/ucvtf, and FPCR.NEP merging on the '
    'fmov register-file moves.  13 of these rows are fmov, where the MRA '
    'block reads FPCR unconditionally but the value reaches no result on '
    'the FtoI direction -- those are reference-side over-reports.'),
 'SRC+trc:FCSR': ('TRACER INVENTS A READ',
    'fabs/fneg are sign-bit operations and the integer saturating ops '
    '(sqabs/sqadd/sqshl...) consult no control word; the MRA execute ASL '
    'contains no FPCR read on any path.'),
 'DST+ref:FCSR': ('TRACER MISSES A WRITE',
    'the cumulative FP exception bits (FPSR.IXC/IOC/OFC/UFC/IDC) and the '
    'saturation bit FPSR.QC are written.  R5 governs: the write is '
    'conditional on the operation raising the condition, and an inert '
    'write is still a write.'),
 'DST+ref:FCSR SRC+ref:FCSR': ('TRACER MISSES BOTH',
    'same class, on ops that both read FPCR and write FPSR.'),
 'DST+ref:FCSR SRC+trc:FCSR': ('TRACER HAS THE DIRECTION BACKWARDS',
    'integer saturating arithmetic writes FPSR.QC and reads nothing; the '
    'tracer records the status word as a SOURCE and omits the write.'),
 'SRC+ref:SYS': ('TRACER MISSES A READ',
    'the pointer-authentication key registers (APIAKey_EL1 / APIBKey_EL1 / '
    'APDAKey_EL1 / APDBKey_EL1 / APGAKey_EL1) are inputs to pac*/aut*/'
    'blra*/braa*, and GCR_EL1 is an input to addg/subg/irg.'),
 'SRC+ref:SYS SRC+ref:ZERO': ('TRACER MISSES TWO READS',
    'the PAC key, plus the xzr modifier operand of the *Z forms.'),
 'SRC+ref:VEC#': ('TRACER MISSES A READ',
    'ldff1* is a read-modify-write of its destination: elements not loaded '
    'because the first-fault check stopped the access keep their previous '
    'value (Elem[result,e] = Elem[orig,e] in the execute ASL).'),
 'SRC+ref:FLAGS': ('TRACER MISSES A READ',
    'the MOPS prologue instructions test PSTATE.C to detect a wrong-option '
    'restart (cpyp.xml lines 87/93); NZCV is a genuine input.'),
 'SRC+ref:FLAGS SRC+ref:SYS': ('TRACER MISSES TWO READS',
    'MOPS prologue NZCV plus GCR_EL1 on the tag-setting setgp* forms.'),
 'SRC+ref:ZERO': ('TRACER MISSES A READ',
    'the encoded operand is xzr/wzr (mov=orr Rn=31, mneg=msub Ra=31, '
    'cset=csinc Rn=Rm=31).  The tracer CAN name it -- it emits REG_ZERO '
    'elsewhere, and --keep-zero does not change the answer -- so this is '
    'an omission, not a fold.  LLVM MC agrees with the reference.'),
 'SRC+trc:ZERO': ('TRACER INVENTS A READ', 'see the fcmp #0.0 class.'),
 'DST+ref:FCSR SRC+trc:ZERO': ('TRACER INVENTS A READ AND MISSES A WRITE',
    'fcmp/fcmpe against #0.0: the zero is an IMMEDIATE, not the zero '
    'register, and the FPSR exception write is absent.'),
 'DST+trc:ZERO': ('TRACER INVENTS A WRITE',
    'a write to xzr is architecturally discarded (casp with an xzr pair).'),
 'SRC+trc:MATRIX': ('TRACER INVENTS A READ',
    'these SME2 forms are write-only into ZA: the execute ASL computes the '
    'result from the Z operands alone and stores it (ZAvector[vec,VL] = '
    'result).  The accumulating forms -- add_za_zw, the *_za_zzi group -- '
    'do read ZA, and there the tracer agrees, so the model is not simply '
    'always-read.'),
 'SRC+ref:MATRIX': ('TRACER MISSES A READ',
    'movt zt0[8], x2 writes one slice of ZT0 and preserves the rest.'),
 'DST+ref:MATRIX SRC+trc:MATRIX': ('TRACER HAS THE DIRECTION BACKWARDS',
    'zero {za0.d} writes ZA; the tracer records a read and no write.'),
 'DST+ref:SYS': ('TRACER MISSES A WRITE',
    'the sys-instruction group produces architectural results: at -> '
    'PAR_EL1, the gcs push/pop forms -> GCSPR_ELx.'),
 'DST+ref:SYS SRC+ref:ZERO': ('TRACER MISSES A WRITE AND A READ', 'as above.'),
 'DST+ref:SYS SRC+ref:SYS': ('TRACER MISSES BOTH',
    'esb reads and writes DISR_EL1; irg reads and writes RGSR_EL1/GCR_EL1.'),
 'SRC+ref:SYS SRC+trc:LR': ('TRACER NAMES THE WRONG REGISTER',
    'eretaa/eretab authenticate ELR_EL1, a system register.  The tracer '
    'records x30 (REG_LR), which the instruction does not touch.'),
 'SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:SYS':
    ('TRACER MISSES SEVEN READS',
     'st64b/st64bv0 send a 512-bit payload held in eight consecutive X '
     'registers; the tracer records two.'),
 'SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:SYS':
    ('TRACER MISSES SIX READS', 'st64bv, same class.'),
 'DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# SRC+ref:SYS':
    ('TRACER MISSES SEVEN WRITES',
     'ld64b returns 512 bits into eight consecutive X registers; the '
     'tracer records one destination.'),
 'DST+ref:GPR# DST+ref:SYS SRC+ref:GPR# SRC+ref:SYS': ('TRACER MISSES EVERYTHING',
    'hint #35 is chkfeat x16: it reads and writes x16 and reads the '
    'feature registers.  The tracer records no operand at all.'),
 'DST+trc:GPR# SRC+ref:SYS': ('TRACER INVENTS A WRITE AND MISSES A READ',
    'ldg has no base-register writeback; the tracer records one.'),
 'SRC+ref:GPR#': ('TRACER MISSES A READ',
    'psel takes the slice index from w12; the tracer omits the GPR.'),
 'SRC+trc:VEC#': ('TRACER INVENTS A READ',
    'pmov Zd, Pn.B writes the whole destination.'),
 'SRC+trc:FLAGS': ('REFERENCE-SIDE FOLD, TRACER RIGHT -- now resolved',
    'kept for the record: rmif/setf8/setf16 update a SUBSET of NZCV, so a '
    'model that folds the four flags onto one register must call the '
    'destination a source.  The reference now applies that rule (R5) and '
    'these rows agree.'),
 'SRC+trc:GPR# SRC+trc:GPR#': ('REFERENCE GAP -- NOT A TRACER DEFECT',
    'sysp/tlbip are the 128-bit system-instruction pair form, whose '
    'execute ASL bottoms out in an operation this extractor does not '
    'model.  The tracer names the two X registers, which is right.'),
 'DST+trc:GPR# DST+trc:GPR# SRC+trc:SYS': ('REFERENCE GAP -- NOT A TRACER DEFECT',
    'mrrs, the 128-bit system-register read pair; same modelling gap.'),
 'DST+trc:SYS SRC+trc:GPR# SRC+trc:GPR#': ('REFERENCE GAP -- NOT A TRACER DEFECT',
    'msrr, same.'),
 'DST+trc:SYS SRC+trc:ZERO': ('REFERENCE GAP -- NOT A TRACER DEFECT',
    'msr <pstatefield>, #imm; the extractor produced no effect for it.'),
 'DST+ref:SYS SRC+ref:GPR#': ('REPRESENTATIVE ARTIFACT',
    'tlbi vmalle1is: the chosen representative encoding carries Rt=28 in a '
    'field the alias requires to be 0b11111, so the reference reads an X '
    'register the real encoding does not have.'),
 'DST+ref:GPR# SRC+ref:SYS SRC+trc:GPR#': ('MIXED',
    'sysl writes its result into Xt from a system register; the tracer has '
    'the direction of Xt inverted.'),
}


def main():
    rows = list(csv.DictReader(open(BASE + '/attrib.tsv'), delimiter='\t'))
    sig = collections.Counter()
    for r in rows:
        if r['verdict'] == 'disagree':
            sig[r['signature']] += 1
    verd = collections.Counter(r['verdict'] for r in rows)
    rank = collections.Counter((r['ref_rank'], r['verdict']) for r in rows)
    tierb = collections.Counter()
    for r in rows:
        for t in r['tierB_ref_only'].split(','):
            if t and t != '-':
                tierb[t] += 1
    cls = collections.Counter()
    for r in rows:
        cls[(r['instr_class'], r['verdict'])] += 1

    bucket = collections.Counter()
    for s, n in sig.items():
        who = ADJ.get(s, ('UNADJUDICATED', ''))[0]
        bucket[who] += n

    out = open(BASE + '/attrib_adjudication.txt', 'w')
    w = out.write
    w('AARCH64 REGISTER ATTRIBUTION -- ADJUDICATED SUMMARY\n')
    w('=' * 62 + '\n\n')
    w('denominator          %d opcode subjects (opcodes.tsv)\n' % len(rows))
    w('probed               %d\n' % (verd['agree'] + verd['disagree']))
    w('unprobed             %d\n' % verd['unprobed'])
    w('agree                %d\n' % verd['agree'])
    w('disagree             %d\n\n' % verd['disagree'])
    w('BY REFERENCE RANK\n')
    for (rk, v), n in sorted(rank.items()):
        w('  %-12s %-9s %d\n' % (rk, v, n))
    w('\nADJUDICATION OF THE %d DISAGREEING ROWS\n' % verd['disagree'])
    for who, n in bucket.most_common():
        w('  %5d  %s\n' % (n, who))
    w('\nSIGNATURES, LARGEST FIRST\n')
    for s, n in sig.most_common():
        who, why = ADJ.get(s, ('UNADJUDICATED', ''))
        w('\n%6d  %s\n' % (n, s))
        w('        verdict: %s\n' % who)
        if why:
            for line in _wrap(why, 68):
                w('        %s\n' % line)
    w('\nTIER B -- architectural state outside the tracer\'s register space\n')
    w('(execution-context PSTATE bits and the PC; excluded from the verdict\n')
    w(' above, counted here so nothing is hidden)\n')
    for t, n in tierb.most_common():
        w('  %-16s %d rows\n' % (t, n))
    w('\nBY INSTRUCTION CLASS\n')
    names = sorted(set(k[0] for k in cls))
    for c in names:
        a, d = cls[(c, 'agree')], cls[(c, 'disagree')]
        tot = a + d + cls[(c, 'unprobed')]
        w('  %-12s %5d rows  agree %5d (%5.1f%%)  disagree %5d\n'
          % (c or '(none)', tot, a, 100.0 * a / tot if tot else 0, d))
    out.close()
    print(open(BASE + '/attrib_adjudication.txt').read())


def _wrap(s, n):
    words, line, out = s.split(), '', []
    for x in words:
        if len(line) + len(x) + 1 > n:
            out.append(line)
            line = x
        else:
            line = (line + ' ' + x).strip()
    if line:
        out.append(line)
    return out


if __name__ == '__main__':
    main()
