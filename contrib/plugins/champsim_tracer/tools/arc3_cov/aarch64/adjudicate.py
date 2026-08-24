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
 'SRC+ref:VEC#': ('CLOSED -- REFERENCE FIXED (ruling A)',
    'ldff1*/ldnf1* after a suppressed access.  ldff1b_z_p_br.xml offers '
    'three behaviours for the elements past the fault -- '
    'ConstrainUnpredictableBool(Unpredictable_SVELDNFDATA) keeps the data, '
    'Unpredictable_SVELDNFZERO zeroes, and the final else MERGES from '
    '`bits(VL) orig = Z[t, VL]`.  The extractor answered FALSE to every '
    'ConstrainUnpredictableBool, which lands on the merge arm and makes the '
    'destination a source.  That was an extractor default, not an '
    'architectural requirement: QEMU picks the ZERO arm -- sve_ldnfff1_r() '
    'in target/arm/tcg/sve_helper.c, "After any fault, zero the other '
    'elements", swap_memzero(vd, reg_off).  Ruling A: a label does not move '
    'a row, so the REFERENCE was corrected rather than annotated -- '
    'aslinterp.UNPREDICTABLE_CHOICE resolves each CONSTRAINED UNPREDICTABLE '
    'choice the way the traced implementation resolves it, with the '
    'citation beside it, and answers no choice silently: an enum with no '
    'entry is recorded as cu-unmodelled:<enum> in the subject notes.  These '
    '76 rows AGREE.  76 rows at the start.'),
 'SRC+ref:ZERO': ('CLOSED -- TRACER FIXED',
    'the hidden xzr/wzr operand behind a printed alias (mov = orr '
    'Rn=31, mul = madd Ra=31, neg = sub Rn=31, cset = csinc Rn=Rm=31, '
    'the pac*Z / aut*Z / ldraa modifier). 46 rows at the start.'),
 'SRC+ref:FLAGS': ('CLOSED -- REFERENCE FIXED (ruling A), then TRACER FIXED',
    'was the MOPS PROLOGUE (cpyfp/cpyp/setp/setgp and variants), 40 rows.  '
    'cpyfp.xml reads `bits(4) nzcv = PSTATE.<N,Z,C,V>` at the top and '
    'then, in the prologue branch, overwrites it on BOTH arms -- '
    '`nzcv = \'0000\'` when CPYFOptionA() and `nzcv = \'0010\'` when not -- '
    'before any use, so the read reaches nothing.  `used` could not see '
    'that: it answers whether the NAME was evaluated, and the prologue '
    'does evaluate nzcv, at the bottom, in `PSTATE.<N,Z,C,V> = nzcv`.  '
    'Ruling A: the reference was corrected rather than labelled.  '
    'aslinterp now tracks value flow per variable (var_reads), kills a '
    'read when the container is rebound, and only counts a kill where '
    'EVERY path to the join performs it.  All 40 prologue rows agree; '
    'Main and Epilogue keep their FLAGS read.  The 2 rows that survived '
    'were a different mechanism -- ctermeq/ctermne, whose PSTATE.V is '
    'computed from PSTATE.C -- and are fixed on the TRACER side at the '
    'Capstone boundary.  0 rows.'),
 # -------------------------- state the tracer names and the reference does not
 'SRC+trc:SSP': ('REFERENCE GAP -- THE EXTRACTOR STOPS AT THE SYSINSTR CALL',
    'gcspopcx / gcspopx / gcspushx / gcspushm / gcsss1.  The guarded '
    'control stack operations read GCSPR_ELx to find the stack before '
    'they can move it, and the tracer records that read; the reference\'s '
    'execute ASL bottoms out in AArch64.SysInstr, which the extractor '
    'models as a single write and never as a read.  5 rows.'),
 'DST+trc:SSP': ('REFERENCE GAP -- THE EXTRACTOR STOPS AT THE SYSINSTR CALL',
    'gcspopm / gcsss2, the SYSL-format half of the same class: the '
    'reference records the GCSPR read and not the write back.  2 rows.'),
 'DST+trc:VCTRL SRC+trc:VCTRL': ('REFERENCE GAP -- SVCR SPELT AS A PSTATE BIT',
    'smstart / smstop.  The tracer names SVCR, the architectural '
    'register whose two bits ARE PSTATE.SM and PSTATE.ZA, and records '
    'the read (SetPSTATE_SM zeroes the vector state only when the mode '
    'CHANGES) and the write.  The reference spells the same state as '
    'PSTATE.SM, which this harness classifies Tier B -- execution '
    'context the comparison excludes -- so on the Tier-A axis the '
    'tracer strictly adds.  The same fact, named on one side only; the '
    'reference is not corrected to match because PSTATE.SM is Tier B on '
    '2,779 OTHER subjects where the tracer has no counterpart, and '
    'moving the whole class to Tier A to close two rows would open '
    'those.  2 rows.'),
 # ------------------------------------------------- rank 2, the LLVM leg
 # The 2022-12 MRA does not name the post-2022-12 encodings, so 106
 # subjects are scored against LLVM MC instead.  LLVM MC is an ASSEMBLER
 # model: it has no FPSR at all, reports FPCR on no FP instruction, and
 # has no legality axis whatever, so it can express neither half of the
 # FP status/control contract nor the R7.4 enable gate.  Every row below
 # measures TRACER-SUPERSET -- state the tracer records and the reference
 # cannot -- which is the direction that is never a defect.  These four
 # keys replace the single 'DST+trc:FCSR SRC+trc:FCSR' that predates the
 # REG_SYSFPEN token and no longer reaches any row.
 'DST+trc:FCSR SRC+trc:FCSR SRC+trc:SYSFPEN':
    ('REFERENCE GAP -- RANK 2 MODELS NEITHER FP STATUS NOR LEGALITY',
     'the post-2022-12 FP8 and FAMINMAX additions (f1cvt/f2cvt/bf1cvt/'
     'bf2cvt, fmlall*, fcvtnb, fvdotb) and the SVE2 quadword reductions.  '
     'The tracer names the FPCR read, the FPSR cumulative-exception '
     'write and the CPACR/CPTR enable gate; LLVM MC names none of the '
     'three.  51 rows, all rank 2.'),
 'DST+trc:FCSR SRC+trc:SYSFPEN':
    ('REFERENCE GAP -- RANK 2 MODELS NEITHER FP STATUS NOR LEGALITY',
     'famax/famin: an FPSR write and the enable gate, with no FPCR read '
     'because the maximum-of-absolute-values forms consult no rounding '
     'mode.  10 rows, all rank 2.'),
 'SRC+trc:FCSR SRC+trc:SYSFPEN':
    ('REFERENCE GAP -- RANK 2 MODELS NEITHER FP STATUS NOR LEGALITY',
     'fmlall and the FP8 dot products: an FPCR read and the enable gate.  '
     '9 rows, all rank 2.'),
 'SRC+trc:SYSFPEN':
    ('REFERENCE GAP -- RANK 2 HAS NO LEGALITY AXIS',
     'the SVE forms of the FEAT_CPA checked-pointer-arithmetic '
     'instructions -- addpt/subpt/madpt/mlapt on z registers.  They are '
     'integer operations, so no FP status word is involved, but they are '
     'SVE encodings and go through CheckSVEEnabled, which R7.4 makes a '
     'real source.  Measured, not assumed: the SCALAR forms of the same '
     'four mnemonics (addpt x0, sp, x0 and its ten siblings) carry no '
     'gate on either side and agree, so the gate is attached to the SVE '
     'encodings and not to the mnemonic.  6 rows, all rank 2.'),
 'DST+trc:FCSR': ('REFERENCE GAP -- SHARED FUNCTION THE EXTRACTOR CANNOT PARSE',
    'no longer MIXED: the famax/famin half of this signature moved to '
    'DST+trc:FCSR SRC+trc:SYSFPEN when the enable gate was given its own '
    'token, leaving one mechanism.  All five surviving rows are frecpe, '
    'rank 1, and the reference under-reports: FPRecipEstimate is one of '
    'the shared functions aslparse cannot parse -- it is in the '
    'extractor\'s own LIMITATIONS -- so the FPSR write it performs never '
    'reaches the reference, while FRECPE does raise IDC/IOC/DZC.  The '
    'tracer is right and records more; the fix path is the extractor, '
    'not the tracer.  5 rows.'),
 'DST+ref:SYS': ('CLOSED -- TRACER FIXED',
    'the system-instruction group. AT -> PAR_EL1, the GCS push/pop '
    'forms -> GCSPR_ELx, TRCIT, BRB, the DC/CFP/CPP/DVP/COSP context '
    'operations and the bare SYS. Closed by '
    'cap_aarch64_sysinstr_contract, which reads the SYS/SYSL encoding '
    'directly instead of waiting for the encoding-to-register table '
    'keyed on Capstone alias ids that this entry used to ask for: one '
    'fixed pattern covers every alias. 12 rows at the start.'),
 'SRC+trc:FCSR': ('CLOSED -- TRACER FIXED',
    'the fmov immediate forms. Closed before this session; the key no '
    'longer reaches a row. 12 rows at the start.'),
 'SRC+ref:SYS': ('CLOSED -- TRACER FIXED',
    'the implicit system-register operands: GCR_EL1 on addg/subg, '
    'GMID_EL1 on ldgm/stgm, DCZID_EL0 on stzgm, ELR_ELx/SPSR_ELx on '
    'eret/eretaa/eretab, GCSPR_ELx on gcspopm/gcsss2. Closed by '
    'cap_aarch64_implicit_sysregs and the SYS/SYSL contract, each row '
    'citing the MRA page that states it. The pointer-authentication '
    'keys remain a blind spot on BOTH sides -- AddPACIA does read the '
    'APIAKey pair and the extractor never reports it -- so nothing '
    'here scores that read either way. 10 rows at the start.'),
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
 'DST+ref:SYS SRC+ref:ZERO': ('CLOSED -- TRACER FIXED',
    'the GCS push/pop forms: the sysalias result register plus the '
    'hidden xzr operand, both closed with the SYS/SYSL contract -- Rt '
    '== 31 on a SYS-format encoding is the zero register the execute '
    'ASL reads, not an absent operand. 4 rows at the start.'),
 'SRC+ref:FCSR': ('TRACER RIGHT -- REFERENCE OVER-READS (LIVENESS, OPEN)',
    'the FMOV integer-to-FP and FP-to-integer moves (fmov w2, s1 and '
    'its nine siblings), no longer the two element forms the earlier '
    'count named. fmov_float_gen.xml does FPCRType fpcr = FPCR[]; '
    'boolean merge = IsMerging(fpcr); unconditionally, but merge '
    'reaches no result on the MOV forms: integer fsize = if op == '
    'FPConvOp_CVT_ItoF && merge then 128 else fltsize short-circuits '
    'on the op test, and neither the MOV_FtoI nor the MOV_ItoF arm of '
    'the case mentions merge. So FPCR is read into a value nothing '
    'consumes, and the tracer is right to name no FPCR source -- the '
    'same shape the liveness fix already closed for fmov d0, d1, '
    'where the && short-circuits BEFORE the call and the read never '
    'happens. WHAT IS MISSING, exactly: the value-flow tracker '
    'consumes a read at the CALL SITE, when the argument is '
    'evaluated, instead of letting it flow through the callee return '
    'value; a pure inlined function argument read reaches a result '
    'only if the result does. MEASUREMENT that sizes it: 10 rows, all '
    'rank 1, every one an FMOV_*_float2int, and the change is '
    'confined to argument evaluation in _call_inner. 10 rows.'),
 'SRC+ref:MATRIX': ('CLOSED -- TRACER FIXED',
    'movt zt0[8], x2. Superseded by SRC+ref:ZT0 once ZT0 was split '
    'off REG_MATRIX; the surviving row is adjudicated there under '
    'R7.1. 1 row at the start.'),
 'SRC+ref:GPR#': ('TRACER DEFECT -- OPEN',
    'psel takes its slice index from w12; Capstone reports the '
    'operand as AARCH64_OP_PRED with the vector-select register in '
    'pred.vec_select, which the operand walk does not read -- the gap '
    'docs/limitations.rst already records. The second row is st64bv, '
    'whose Xs payload register list is adjudicated with the other '
    'LS64 forms. 2 rows.'),
 'SRC+trc:VEC#': ('TRACER DEFECT -- OPEN',
    'pmov Zd, Pn.B with imm == 0 writes the whole destination -- '
    'pmov_z_pi.xml takes `result = Zeros(VL)` on that path and '
    '`result = Z[d, VL]` only when imm != 0.  1 row.'),
 'DST+ref:GPR# SRC+ref:SYS SRC+trc:GPR#': ('CLOSED -- TRACER FIXED',
    'sysl reads a system register into Xt and the tracer had the '
    'direction of Xt inverted -- because Capstone reports it inverted '
    'too (cstool -d aarch64 852329d5: operands[0] x5 access READ, '
    'Registers read: x5, nothing modified), and so does LLVM MC. The '
    'boundary takes the direction from the Rt field instead. 1 row at '
    'the start.'),
 'DST+trc:GPR#': ('TRACER DEFECT -- OPEN',
    'ldg has no base-register writeback; the tracer records one.  1 row.'),
 'DST+ref:SYS SRC+ref:SYS': ('CLOSED -- TRACER FIXED',
    'esb reads and writes DISR_EL1 (cap_aarch64_hint_contract, keyed '
    'on the HINT immediate read off the encoding); irg reads GCR_EL1 '
    'and reads and writes RGSR_EL1, the random-allocation seed. 1 row '
    'at the start.'),
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
 'DST+trc:ZERO': ('CLOSED -- REFERENCE FIXED (R7.3)',
    'subps/sbfiz/caspl writing xzr.  The tracer named REG_ZERO and the '
    'reference dropped it -- mra_ref.to_sets() did `dst.discard(\'ZERO\')` '
    'on the argument that the architecture discards the value.  R7.3: '
    '"REG_ZERO exists, so it should be specified.  We should not be '
    'dropping reg zero."  Attribution is a regfile-dependency question, '
    'not a value question, so the discard was the reference measuring its '
    'own convention.  The line is gone; these 3 rows AGREE.  The '
    'author-declared validator probe probe_zero_reg '
    '(`{"src": ["REG_GPR5","REG_GPR6"], "dst": ["REG_ZERO"]}`) is '
    'unchanged and stays green.  3 rows.'),
 'SRC+ref:ZT0': ('TRACER RIGHT -- REFERENCE-SIDE (R7.1)',
    '`movt zt0[8], x2` writes 64 bits of the 512-bit SME2 lookup-table '
    'register, so the reference makes the destination a source to model '
    'the preserve of the other 448.  R7.1 settles exactly this shape: a '
    'write narrower than the register does not acquire a source, because '
    'rename does not know the data-width-scope of the next reader and '
    'width is carried at execution rather than in the static set.  A '
    'register is a source when the INSTRUCTION takes it as one, and movt '
    'does not.  Surfaced only when ZT0 was split off REG_MATRIX: while it '
    'shared an ID with the ZA array the read and the write cancelled into '
    'one token and the row could not be seen.  1 row.'),
 'DST+ref:ZERO': ('CLOSED -- TRACER FIXED',
    'the DESTINATION half of the same alias loss: cmp = subs Rd=31, '
    'cmn = adds Rd=31, tst = ands Rd=31. 16 rows at the start.'),
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
