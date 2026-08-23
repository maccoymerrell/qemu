"""Adjudicated summary of the aarch64 register-attribution measurement."""
import csv, collections

BASE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64'

# signature -> (who is right, why)
#
# Every entry is adjudicated against the rank-1 reference read as
# PSEUDOCODE -- the named .xml page is quoted -- with QEMU's own
# translator as a second, independent reading wherever the architecture
# leaves a choice.  A verdict of REFERENCE DEFECT is never asserted from
# plausibility: it names the mechanism in the extractor that produced the
# wrong answer.
ADJ = {
 # ---------------------------------------------------------- open, tracer
 'SRC+ref:VEC#': ('TRACER RIGHT -- REFERENCE DEFECT (CONSTRAINED UNPREDICTABLE)',
    'ldff1*/ldnf1* after a suppressed access.  ldff1b_z_p_br.xml offers '
    'three behaviours for the elements past the fault -- '
    'ConstrainUnpredictableBool(Unpredictable_SVELDNFDATA) keeps the data, '
    'Unpredictable_SVELDNFZERO zeroes, and the final else MERGES from '
    '`bits(VL) orig = Z[t, VL]`.  The extractor answers FALSE to every '
    'ConstrainUnpredictableBool, which lands on the merge arm and makes the '
    'destination a source.  That is an extractor default, not an '
    'architectural requirement: QEMU picks the ZERO arm -- sve_ldnfff1_r() '
    'in target/arm/tcg/sve_helper.c, "After any fault, zero the other '
    'elements", swap_memzero(vd, reg_off).  R6/R7: the tracer records the '
    'implementation it traces, so no Zt read.  76 rows.'),
 'SRC+ref:ZERO': ('TRACER DEFECT -- OPEN',
    'the encoded operand is xzr/wzr and the printed alias hides it '
    '(mov = orr Rn=31, mul = madd Ra=31, neg = sub Rn=31, cset = csinc '
    'Rn=Rm=31, and the pac*Z/aut*Z/ldraa modifier).  The tracer names '
    'REG_ZERO whenever Capstone prints it -- 33 rows do -- so this is the '
    'ret-alias loss again, on the operand rather than the implicit list, '
    'and it is an inconsistency in the tracer rather than a modelling '
    'choice.  Not fixed here: it needs the alias-to-base-form mapping '
    'Capstone exposes only through cs_regs_access(), whose staleness '
    'across decodes is already documented at AARCH64_INS_ALIAS_RET.  '
    '46 rows.'),
 'SRC+ref:FLAGS': ('TRACER RIGHT -- REFERENCE DEFECT (LIVENESS)',
    'the MOPS PROLOGUE (cpyfp/cpyp/setp/setgp and variants).  cpyfp.xml '
    'reads `bits(4) nzcv = PSTATE.<N,Z,C,V>` at the top and then, in the '
    'prologue branch, overwrites it on BOTH arms -- `nzcv = \'0000\'` when '
    'CPYFOptionA() and `nzcv = \'0010\'` when not -- before any use.  The '
    '`if nzcv<1> == \'1\' // PSTATE.C` wrong-option test is in the ELSE '
    'branch, which is the Main and Epilogue stages.  The measurement '
    'confirms the split exactly: all 40 Main and all 40 Epilogue rows '
    'AGREE, with the tracer naming FLAGS; only the 40 prologue rows '
    'disagree.  The extractor\'s liveness rule missed a local rebound on '
    'both arms of an if/else.  42 rows.'),
 'DST+trc:FCSR SRC+trc:FCSR': ('REFERENCE GAP -- RANK 2 HAS NO FP STATUS MODEL',
    'the post-2022-12 FP8 and FAMINMAX additions (f1cvt/f2cvt/bf1cvt/'
    'bf2cvt families, famax/famin, fmlall*, fcvtnb, fvdotb) and the SVE2 '
    'quadword reductions, probed against LLVM MC because the 2022-12 MRA '
    'does not name them.  LLVM MC models no FPSR at all and reports FPCR '
    'on no FP instruction, so it cannot adjudicate either half of the FP '
    'status/control contract.  51 rows, all rank 2.'),
 'DST+trc:FCSR': ('MIXED -- 10 RANK-2 GAP, 5 REFERENCE DEFECT',
    'famax/famin are rank-2 rows (see above).  The five frecpe rows are '
    'rank 1 and are a reference under-report: FPRecipEstimate is one of '
    'the shared functions the extractor cannot parse, named in its own '
    'LIMITATIONS, and FRECPE does raise IDC/IOC/DZC.  15 rows.'),
 'DST+ref:SYS': ('TRACER DEFECT -- OPEN',
    'the system-instruction group produces architectural results the '
    'tracer does not record: AT -> PAR_EL1, the GCS push/pop forms -> '
    'GCSPR_ELx, TRCIT, the DC/CFP/CPP/DVP/COSP context operations.  '
    'Capstone models these as AARCH64_OP_SYSALIAS with no register at '
    'all, so naming the result needs an encoding->register table the '
    'boundary does not yet carry.  12 rows.'),
 'SRC+trc:FCSR': ('TRACER DEFECT -- OPEN (3 rows) / REFERENCE (9)',
    'after the FP status/control contract landed, what remains is fmov '
    'immediate forms (`fmov d2, #2.125`), where the tracer applies the '
    'scalar-merge rule and the reference reports no read because the '
    'immediate path never consults FPCR, and rank-2 rows.  12 rows.'),
 'SRC+ref:SYS': ('MIXED -- 8 TRACER DEFECT, 2 SUBSUMED',
    'what survives the removal of the enabling-condition and translation-'
    'configuration leak (see METHOD): GCR_EL1 on addg/subg, GMID_EL1 on '
    'ldgm/stgm, DCZID_EL0 on stzgm, ELR_ELx/SPSR_ELx on eret/eretaa/'
    'eretab, GCSPR_ELx on gcspopm/gcsss2.  Those are genuine operands the '
    'tracer does not name.  NOT the pointer-authentication keys: AddPACIA '
    'does read APIAKeyHi_EL1:APIAKeyLo_EL1, but the extractor never '
    'reports them, so this measurement is silent about that read on both '
    'sides -- a blind spot, recorded rather than scored.  10 rows.'),
 'SRC+trc:MATRIX': ('TRACER DEFECT -- OPEN',
    'the SME2 ADD/SUB "array results" forms (add_za_zzv / add_za_zzw and '
    'the SUB twins).  add_za_zzv.xml computes from the Z operands alone '
    'and stores -- `ZAvector[vec, VL] = result` -- with no read.  The '
    'ACCUMULATE form add_za_zw does read ZA and there the tracer agrees.  '
    'Capstone reports both with the same operand types and the same '
    'READ|WRITE access on the tile, and a count-based discriminator '
    'collides (a 4x4 accumulate and a 2x2 results form both carry four Z '
    'registers), so this waits for ARC 3\'s QEMU-derived dataflow.  '
    '8 rows.'),
 'DST+ref:SYS SRC+ref:ZERO': ('TRACER DEFECT -- OPEN',
    'the GCS push/pop forms: the sysalias result register (see '
    'DST+ref:SYS) plus the hidden xzr operand (see SRC+ref:ZERO).  '
    '4 rows.'),
 'SRC+ref:FCSR': ('TRACER DEFECT -- OPEN',
    'two fmov element forms (`fmov v2.d[1], x1`, `fmov x2, v1.d[1]`), '
    'where the scalar-merge rule is scoped off by the arrangement '
    'specifier the element syntax carries.  2 rows.'),
 'SRC+ref:MATRIX': ('TRACER DEFECT -- OPEN',
    'movt zt0[8], x2 writes one slice of ZT0 and preserves the rest, so '
    'the destination is also a source.  1 row.'),
 'SRC+ref:GPR#': ('TRACER DEFECT -- OPEN',
    'psel takes its slice index from w12; Capstone reports the operand '
    'as AARCH64_OP_PRED with the vector-select register in '
    'pred.vec_select, which the operand walk does not read.  1 row.'),
 'SRC+trc:VEC#': ('TRACER DEFECT -- OPEN',
    'pmov Zd, Pn.B with imm == 0 writes the whole destination -- '
    'pmov_z_pi.xml takes `result = Zeros(VL)` on that path and '
    '`result = Z[d, VL]` only when imm != 0.  1 row.'),
 'DST+ref:GPR# SRC+ref:SYS SRC+trc:GPR#': ('TRACER DEFECT -- OPEN',
    'sysl reads a system register into Xt; the tracer has the direction '
    'of Xt inverted.  1 row.'),
 'DST+trc:GPR#': ('TRACER DEFECT -- OPEN',
    'ldg has no base-register writeback; the tracer records one.  1 row.'),
 'DST+ref:SYS SRC+ref:SYS': ('TRACER DEFECT -- OPEN',
    'esb reads and writes DISR_EL1; irg reads and writes '
    'RGSR_EL1/GCR_EL1.  1 row.'),
 'DST+ref:GPR# DST+ref:SYS SRC+ref:GPR#': ('TRACER DEFECT -- OPEN',
    'hint #35 is chkfeat x16: it reads and writes x16 and reads the '
    'feature registers.  The tracer records no operand at all.  1 row.'),
 'SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:SYS':
    ('TRACER DEFECT -- OPEN',
     'st64b/st64bv0 send a 512-bit payload held in eight consecutive X '
     'registers; the tracer records two.  1 row.'),
 'SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR#':
    ('TRACER DEFECT -- OPEN', 'st64bv, same class.  1 row.'),
 'SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR# SRC+ref:GPR#':
    ('TRACER DEFECT -- OPEN', 'st64bv0 variant, same class.  1 row.'),
 'DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR# DST+ref:GPR#':
    ('TRACER DEFECT -- OPEN',
     'ld64b returns 512 bits into eight consecutive X registers; the '
     'tracer records one destination.  1 row.'),
 # ------------------------------------------------------- reference-side
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
 # ------------------------------------------------ closed by this session
 'DST+ref:FCSR': ('CLOSED -- TRACER FIXED',
    'the FPSR cumulative-exception write, absent from every FP '
    'instruction.  Added by the FP status/control contract in '
    'disas/capstone.c.  405 rows at the start of this session.'),
 'DST+ref:FCSR SRC+ref:FCSR': ('CLOSED -- TRACER FIXED',
    'same class, on the forms that also read FPCR.  233 rows.'),
 'DST+ref:FCSR SRC+trc:FCSR': ('CLOSED -- TRACER FIXED',
    'integer saturating arithmetic: FPSR.QC written, nothing read.  The '
    'tracer had the direction backwards.  72 rows.'),
 'SRC+trc:ZERO': ('CLOSED -- TRACER FIXED',
    'fcmp/fcmpe against #0.0: the zero is an IMMEDIATE, not the zero '
    'register.  6 rows.'),
 'DST+trc:ZERO': ('NEEDS RULING -- DO NOT FIX UNILATERALLY',
    'a write to the zero register is architecturally discarded (AArch64 '
    'XZR/WZR, RISC-V x0, MIPS $zero all read as zero however they are '
    'written), and the reference discards it -- mra_ref.to_sets() does '
    '`dst.discard(\'ZERO\')`.  Recorded, it is a producer for a value no '
    'consumer can receive, and every later reader of the zero register '
    'waits on it.  BUT the current behaviour is author-declared, not '
    'accidental: the validator generates a block class literally named '
    'probe_zero_reg whose expected_insns entry is '
    '`{"src": ["REG_GPR5","REG_GPR6"], "dst": ["REG_ZERO"]}`, and '
    'dropping the write turns that probe RED on riscv64 and mipsel.  '
    'THE QUESTION FOR THE MAINTAINER, in one sentence: should a write to '
    'the architectural zero register be recorded as a destination, or '
    'discarded as the architecture discards it -- and if discarded, does '
    'probe_zero_reg change to assert the absence?  3 rows.'),
 'SRC+ref:SYS SRC+trc:LR': ('CLOSED -- TRACER FIXED',
    'eretaa/eretab do not touch x30.  2 rows; what remains on those rows '
    'is the ELR_ELx read, counted under SRC+ref:SYS.'),
 'DST+ref:MATRIX SRC+trc:MATRIX': ('CLOSED -- TRACER FIXED',
    'zero {za0.d} writes ZA; the tracer recorded a read and no write.  '
    '1 row.'),
 'SRC+trc:FLAGS': ('CLOSED -- REFERENCE FIXED',
    'rmif/setf8/setf16 update a SUBSET of NZCV, so a model that folds the '
    'four flags onto one register must call the destination a source.  '
    'The reference applies that rule (R5) and these rows agree.'),
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
