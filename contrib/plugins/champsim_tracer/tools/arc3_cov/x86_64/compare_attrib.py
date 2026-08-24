#!/usr/bin/env python3
"""
ARC 3 -- x86_64 REGISTER ATTRIBUTION over the whole opcode space.

For every one of the 8880 opcodes in the x86_64 denominator, compare the
register SOURCE and DESTINATION sets the ChampSim Tracer records (its own
InsnFields, via isaxcheck --layer=fields) against the ranked x86_64
reference: Intel XED (primary) with iced-x86 and LLVM MC available for
adjudication.

Comparison happens in the tracer's GenericRegId vocabulary: each reference
register name is translated through the tracer's OWN x86 register table
(champsim_tracer_mnemonics_x86.h).  A reference register with no row in
that table is reported as UNMAPPED -- a tracer vocabulary gap, never a
silent agreement.

Rulings applied: R4 (canonical full width on both sides -- the reference
side is already largest-enclosing), R5 (a conditional form names every
candidate; a preserving conditional write is also a source), R3 (an idiom
reads its source -- neither side special-cases idioms), R9 (branch class
is not a register question -- RIP/REG_IP is dropped on both sides).

Author: Maccoy Merrell.
"""
import sys, os, re, json, collections

D = os.path.dirname(os.path.abspath(__file__))
COV = os.path.dirname(D)

# The two-axis taxonomy is shared by all four ISA harnesses.  A harness runs
# from a working copy beside its evidence, so look there first and fall back to
# the tree, which is the source of truth.
_TOOLS = os.environ.get(
    'CST_ARC3_TOOLS',
    '/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/arc3_cov')
for _p in (D, os.path.dirname(D), _TOOLS):
    if os.path.exists(os.path.join(_p, 'arc3_taxonomy.py')):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break
else:
    sys.exit('arc3_taxonomy.py not found (set CST_ARC3_TOOLS)')
import arc3_taxonomy as tax
import qemu_tcg_scope as tcgscope
import arc3_rules as taxrules

# ---------------------------------------------------------------- vocabulary
# The tracer's declared x86 register vocabulary, parsed from its own table.
TRACER_REG = {}
hdr = '/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/champsim_tracer_mnemonics_x86.h'
for line in open(hdr):
    m = re.match(r'\s+\[X86_REG_([A-Z0-9_]+)\]\s*=\s*\{\s*\.reg_id\s*=\s*(REG_[A-Z0-9_]+)', line)
    if m:
        TRACER_REG[m.group(1)] = m.group(2)

# Reference-name -> tracer-table-name, where the two spell the same
# architectural register differently.
ALIAS = {
    'RFLAGS':   'EFLAGS',  # XED's 64-bit spelling of the tracer's EFLAGS row
    'X87PUSH':  'FPSW',    # TOP field of the x87 status word
    'X87POP':   'FPSW',
    'X87POP2':  'FPSW',
    'X87STATUS':'FPSW',
    # The tracer's vocabulary has one id per segment and no separate base
    # register, so the segment base resolves to the segment it belongs to.
    'FSBASE':   'FS',
    'GSBASE':   'GS',
}
# Registers the tracer maps at the disas/capstone.c BOUNDARY rather than in
# its register table, because Capstone's x86 register enum has no id for
# them (checked: none of these has an X86_REG_ entry).  They reach the
# dependency model as QEMU_PLUGIN_OP_SYSREG operands whose architectural
# ROLE the boundary resolves, so the vocabulary is real and this table is
# where the reference side learns it -- exactly the map the header parse
# above builds for the registers Capstone CAN name.
#
# UIF and IA32_KERNEL_GS_BASE are deliberately absent: their instructions
# (CLUI / STUI / ERETU) are not decoded by this Capstone at all -- it
# ignores the F3 prefix and returns rdpkru / wrpkru / clac -- so the
# tracer cannot reach those registers and they stay UNMAPPED, which is
# the honest report.
BOUNDARY_REG = {
    'GDTR':       'REG_SYSMMU',
    'IDTR':       'REG_SYSMMU',
    'LDTR':       'REG_SYSMMU',
    'TR':         'REG_SYSMMU',
    'MXCSR':      'REG_FCSR',
    'X87CONTROL': 'REG_FCSR',
    'X87TAG':     'REG_FCSR',
    'MSRS':       'REG_SYS',
    'TSCAUX':     'REG_SYS',
    'XCR0':       'REG_SYS',
    'TSC':        'REG_SYSTIMER',
    'SSP':        'REG_SSP',
}

# Dropped on BOTH sides, with the reason.
#   CS/DS/ES/SS : segment bases are forced to zero in 64-bit mode -> no dataflow
#   RIP         : R9 -- control flow travels the branch taxonomy, and the
#                 tracer drops REG_IP by construction (isax_generic_reg_dropped)
#   STACKPUSH/POP: XED pseudo-operands, redundant with RSP which XED names
#                 separately in the very same operand list
DROP_REF = {'CS', 'DS', 'ES', 'SS', 'RIP', 'STACKPUSH', 'STACKPOP'}
DROP_TRACER = {'REG_IP', 'REG_ZERO', 'REG_NONE', 'REG_SEG0', 'REG_SEG1',
               'REG_SEG2', 'REG_SEG5'}   # SEG0=cs SEG1=ds SEG2=es SEG5=ss

# Many-to-one collapses in the tracer vocabulary: agreement on these rows is
# agreement modulo a reduction, and is counted separately.
COLLAPSE = {}
_byid = collections.defaultdict(set)
for n, g in TRACER_REG.items():
    _byid[g].add(n)
for g, names in _byid.items():
    # distinct ARCHITECTURAL registers sharing one generic id (sub-register
    # spellings of one register do not count -- that is R4 and is correct)
    pass

def ref_token(name):
    """Reference register name -> tracer generic token, or None if dropped."""
    if name in DROP_REF:
        return None
    key = ALIAS.get(name, name)
    if key in TRACER_REG:
        return TRACER_REG[key]
    if key in BOUNDARY_REG:
        return BOUNDARY_REG[key]
    return 'UNMAPPED:' + name

def parse_set(s):
    if not s or s == '-':
        return set()
    return set(s.split(','))

# ---------------------------------------------------------------- inputs
def load_tool(path):
    d = {}
    with open(path) as f:
        next(f)
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) < 8:
                continue
            hexs, tool, ok, ln, mn, src, dst, mem = p[:8]
            # column 9 (XED only) says WHY RFLAGS is a source; see xl3.cc.
            why = p[8] if len(p) > 8 else '-'
            d.setdefault(hexs, {})[tool] = dict(
                ok=(ok == '1'), len=int(ln), mn=mn,
                src=parse_set(src), dst=parse_set(dst), mem=mem, why=why)
    return d

REF = load_tool(os.path.join(D, 'xl3.tsv'))
for h, rec in load_tool(os.path.join(D, 'iced.tsv')).items():
    REF.setdefault(h, {}).update(rec)

# The encoding actually probed for each opcode.  For an EVEX opcode whose
# iform carries a mask slot, the denominator's representative encoding has
# aaa=000 -- which architecturally means UNMASKED, so the mask operand is
# never exercised.  C3 requires showing the operand is captured FOR THAT
# OPCODE TYPE, so those opcodes are probed with aaa=001 instead, accepted
# only when XED still decodes the variant to the same iform at the same
# length.  probe_map.json records the choice per opcode.
PROBE = json.load(open(os.path.join(D, 'probe_map.json')))

# ------------------------------------------------------------ adjudication
# XED is the ranked primary for x86_64.  Where iced-x86 AND LLVM MC both
# contradict it and the architecture agrees with them, the correction is
# applied here -- explicitly, enumerably, and counted.  Nothing is averaged.
ADJ = collections.Counter()

def adjudicate(hexs, xsrc, xdst):
    """XED sets -> adjudicated reference sets, in XED's own vocabulary."""
    iced = REF.get(hexs, {}).get('ICED')
    src, dst = set(xsrc), set(xdst)
    # ADJ-1: EVEX aaa=000 is 'no masking', not 'reads k0'.  XED names the
    # mask operand slot regardless; iced resolves it to no mask at all and
    # LLVM reports no mask register.  Charging k0 as a source would invent
    # a dependency the hardware does not have.
    if 'K0' in src and iced and iced['ok'] and not any(
            re.fullmatch(r'K[0-7]', r) for r in iced['src']):
        src.discard('K0')
        ADJ['ADJ-1 EVEX aaa=000 k0 is no-mask (iced+LLVM over XED)'] += 1
    # ADJ-2: R7.1-NARROW removed the sub-width preserve-read from all three
    # elaborators.  On a few iforms XED's own operand ACTION is wrong -- it
    # marks a read-modify operand write-only -- and the preserve rule had
    # been silently standing in for the real read, so removing it exposed the
    # defect rather than causing one.  EXTRQ_XMMq_IMMb_IMMb is the case: the
    # instruction EXTRACTS a bitfield FROM the register it then writes, so
    # the register is genuinely a source.  Where iced-x86 AND LLVM MC both
    # name a register XED writes as a source, the two independent references
    # win -- the same protocol as ADJ-1, in the other direction.
    llvm = REF.get(hexs, {}).get('LLVM')
    if iced and iced['ok'] and llvm and llvm['ok']:
        for r in sorted(dst - src):
            if r in iced['src'] and r in llvm['src']:
                src.add(r)
                ADJ['ADJ-2 XED marks a read-modify operand write-only '
                    '(iced+LLVM over XED)'] += 1
                # ADJ-2b: the same two references settle the OTHER half.
                # Where neither of them names the register as a
                # destination either, XED did not merely lose the read --
                # it has the operand's ROLE inverted, and leaving the
                # write standing would keep a result the instruction does
                # not produce.  LLWPCB is the case: the register holds the
                # ADDRESS of the control block the instruction loads.
                if r not in iced['dst'] and r not in llvm['dst']:
                    dst.discard(r)
                    ADJ['ADJ-2b XED has the operand role INVERTED, not '
                        'merely lost (iced+LLVM over XED)'] += 1
    # -------------------------------------------------------------- x87
    # XED models the x87 escapes with a BLANKET "writes X87STATUS, writes
    # ST(0)" that is right for the arithmetic and wrong for four families.
    # Each correction below is checked against the other two references AND
    # against QEMU's own implementation, and each is COUNTED: a rule whose
    # count falls to zero has stopped reaching its subject and is a finding,
    # not a pass.
    #
    # iced-x86 cannot arbitrate the STATUS half on its own -- it prints
    # RFLAGS where XED prints X87STATUS on EVERY x87 row (compare d800:
    # XED `ST0,X87STATUS`, iced `RFLAGS,ST0`) -- so its RFLAGS is read as
    # the status word, never as EFLAGS, and only its ST(n) evidence counts.
    xmn = REF.get(hexs, {}).get('XED', {}).get('mn', '')
    # ADJ-3: FTST compares ST(0) with 0.0 and writes only the condition
    # codes.  iced (dst = status only) and LLVM MC (dst = X87STATUS) both
    # contradict XED's ST0 destination.
    if xmn == 'FTST' and 'ST0' in dst:
        dst.discard('ST0')
        ADJ['ADJ-3 FTST does not write ST(0) (iced+LLVM over XED)'] += 1
    # ADJ-4: the non-waiting STORES of the control and status words only
    # read them.  XED and LLVM MC both name X87STATUS a destination; QEMU
    # settles it -- helper_fnstcw() returns env->fpuc and helper_fnstsw()
    # returns a rearrangement of env->fpus, and neither assigns anything
    # (target/i386/tcg/fpu_helper.c).  Following the reference here would
    # plant a write the guest does not perform, which is the worse defect:
    # a wrong dependency reads as agreement.
    if xmn in ('FNSTCW', 'FNSTSW') and 'X87STATUS' in dst:
        dst.discard('X87STATUS')
        ADJ['ADJ-4 FNSTCW/FNSTSW read the status word and do not write it '
            '(QEMU helper over XED+LLVM)'] += 1
    # ADJ-5: FCMOVcc TESTS CF/ZF/PF and writes no flag.  XED declares its
    # RFLAGS operand rw; LLVM MC names no flags at all, and iced's dst
    # RFLAGS is the status-word rendering above rather than a claim about
    # EFLAGS -- so no reference actually asserts an EFLAGS write.
    if xmn.startswith('FCMOV') and 'RFLAGS' in dst:
        dst.discard('RFLAGS')
        ADJ['ADJ-5 FCMOVcc tests the flags and does not write them '
            '(LLVM over XED)'] += 1
    # ADJ-6: 3DNow! (0F 0F /r imm8).  Every operation in the map writes
    # BOTH packed elements of its MMX destination, so no part of the old
    # value survives and the register is not a source; XED declares the
    # operand rw anyway.  iced-x86 and LLVM MC both name only the memory
    # or register operand, which is the ADJ-2 protocol run in reverse and
    # is scoped to this one escape rather than applied generally.
    # ADJ-7: QEMU's group-7 decoder is PREFIX-BLIND on 0F 01 CA / CB, so
    # F2 0F 01 CA -- which XED reads as FRED's ERETS -- is executed by the
    # guest as CLAC, exactly as pre-FRED hardware executes it
    # (target/i386/tcg/translate.c case 0xca / 0xcb take no prefix test,
    # and QEMU has no FRED at all: no CPUID bit, no decode entry).  The
    # reference is describing a machine this guest is not.  Replacing it
    # with QEMU's own reading is the only honest comparison; the tracer
    # follows the guest, and Capstone reads these bytes the same way.
    if xmn in ('ERETS', 'ERETU') and _is_group7_prefixed(hexs):
        src, dst = set(), {'RFLAGS'}
        ADJ['ADJ-7 QEMU executes F2/F3 0F 01 CA as CLAC (it has no FRED); '
            'the reference decodes a different machine'] += 1
    # ADJ-8 is deliberately unused: VMFUNC's ECX is carried as a NAMED
    # SUPERSET of XED in disas/capstone.c rather than adjudicated here,
    # the same disposition MWAITX's RBX already has.
    # ADJ-9: VIA PadLock XSTORE.  EDX carries the quality factor INTO the
    # instruction and is not a result; ECX is the REP form's counter and
    # the single-shot form has none.  XED alone says otherwise on both
    # counts and iced-x86 and LLVM MC both contradict it.
    if xmn in ('XSTORE', 'REP_XSTORE'):
        if 'RDX' in dst:
            dst.discard('RDX')
            ADJ['ADJ-9 XSTORE reads the quality factor in EDX and does not '
                'write it (iced+LLVM over XED)'] += 1
        if xmn == 'XSTORE' and 'RCX' in src:
            src.discard('RCX')
            ADJ['ADJ-9 the single-shot XSTORE has no ECX counter '
                '(iced+LLVM over XED)'] += 1
    # ADJ-10: FFREEP tags ST(i) empty and pops.  It reads no data from the
    # register it names, which is why disas/capstone.c drops the operand
    # (cap_x86_is_x87_tag_only).  XED and LLVM MC both name it anyway
    # because it is spelled as an operand; the dependency a renaming
    # machine must respect is the tag word, and that is recorded.
    if xmn == 'FFREEP':
        for r in sorted(src):
            if re.fullmatch(r'ST[0-7]', r):
                src.discard(r)
                ADJ['ADJ-10 FFREEP names a tag entry, not a value '
                    '(the operand is not read)'] += 1
    if _is_3dnow(hexs) and iced and iced['ok'] and llvm and llvm['ok']:
        for r in sorted(src & dst):
            if not re.fullmatch(r'MM[0-7]', r):
                continue
            if r in iced['src'] or r in llvm['src']:
                continue
            src.discard(r)
            ADJ['ADJ-6 3DNow! writes its whole MMX destination, so it is '
                'not also a source (iced+LLVM over XED)'] += 1
    return src, dst


def _is_group7_prefixed(hexs):
    """True for 66/F2/F3 0F 01 /r -- the group-7 code points QEMU decodes
    without looking at the mandatory prefix at all."""
    b = [int(hexs[i:i + 2], 16) for i in range(0, len(hexs) - 1, 2)]
    i = 0
    pfx = False
    while i < len(b) and b[i] in (0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36,
                                  0x3e, 0x26, 0x64, 0x65):
        pfx = pfx or b[i] in (0x66, 0xf2, 0xf3)
        i += 1
    if i < len(b) and (b[i] & 0xf0) == 0x40:
        i += 1
    return pfx and b[i:i + 2] == [0x0f, 0x01]


def _is_3dnow(hexs):
    """True for the 0F 0F escape, past any legacy prefix / REX run."""
    b = [int(hexs[i:i + 2], 16) for i in range(0, len(hexs) - 1, 2)]
    i = 0
    while i < len(b) and b[i] in (0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36,
                                 0x3e, 0x26, 0x64, 0x65):
        i += 1
    if i < len(b) and (b[i] & 0xf0) == 0x40:
        i += 1
    return b[i:i + 2] == [0x0f, 0x0f]

TR = {}
with open(os.path.join(D, 'tracer_batch.tsv')) as f:
    cols = next(f).rstrip('\n').split('\t')
    ix = {c: i for i, c in enumerate(cols)}
    for line in f:
        p = line.rstrip('\n').split('\t')
        if len(p) < len(cols):
            continue
        TR[p[ix['hex']]] = dict(
            ok=(p[ix['f_ok']] == '1'),
            b_ok=(p[ix['b_ok']] == '1'),
            b_mnem=p[ix['b_mnem']],
            opcode=p[ix['f_opcode']],
            src=parse_set(p[ix['f_src']]),
            dst=parse_set(p[ix['f_dst']]),
            loads=int(p[ix['f_loads']]), stores=int(p[ix['f_stores']]))

META = {}
with open(os.path.join(COV, 'opcodes_meta.tsv')) as f:
    next(f)
    for line in f:
        p = line.rstrip('\n').split('\t')
        if len(p) >= 5:
            META[p[0]] = dict(iclass=p[1], isa_set=p[2], ext=p[3], cat=p[4])

# ------------------------------------------------------------ reachability
# Whether a QEMU x86_64 guest can execute an encoding decides whether a
# tracer decode gap there costs anything, so it is MEASURED, not named:
# reach.tsv carries the verdict of running each encoding under
# qemu-x86_64 (reach_probe.c, driven by REPRODUCE.sh).
#
# The name test below is kept, but only as a CROSS-CHECK that is required
# to disagree out loud.  It used to BE the answer, and it was wrong by 128
# rows: XED keeps a promoted instruction's original extension (BMI1, BMI2,
# ADOX_ADCX, LZCNT, MOVBE, RAO, USER_MSR) and carries APX only in the
# isa-set, so `ext.startswith('APX')` called every APX form of an
# ordinary instruction reachable.  QEMU TCG has no APX and SIGILLs all of
# them, which is exactly what the measurement says and the name did not.
def name_guess_unreachable(ext, isa_set):
    return (ext.startswith('AVX512') or ext.startswith('AVX10') or
            ext.startswith('APX') or isa_set.startswith('APX') or
            ext.startswith('AMX') or ext == 'ACE')

REACH = {}
_reach_path = os.path.join(D, 'reach.tsv')
if os.path.exists(_reach_path):
    with open(_reach_path) as f:
        next(f)
        for line in f:
            q = line.rstrip('\n').split('\t')
            if len(q) >= 2:
                REACH[q[0]] = (q[1] == 'yes')
# A check that cannot find its subject must fail rather than quietly fall
# back to the guess it replaced.
if not REACH:
    sys.exit('reach.tsv missing or empty: reachability is measured, not '
             'assumed.  Run REPRODUCE.sh, which builds reach_probe.c and '
             'executes every encoding under qemu-x86_64.')

# The execution probe is fed the encodings the TRACER could not decode
# (REPRODUCE.sh), and at CPL3 a SIGILL from a privileged opcode says
# "privilege", not "unimplemented".  Neither leg is independent of the
# decoder on its own, so every exclusion must ALSO carry a citation derived
# from QEMU's own source; qemu_tcg_scope re-asserts those citations here and
# a stale one stops the report rather than quietly excusing 2,000 rows.
_stale = tcgscope.selfcheck()
if _stale:
    for _s in _stale:
        sys.stderr.write('STALE SCOPE CITATION: %s\n' % _s)
    sys.exit('the QEMU-derived scope model no longer matches the tree: the '
             'unreachable rows are unjustified until it is repaired')

reach_conflicts = []          # measurement and name test disagree
reach_unmeasured = set()      # no execution verdict; the name test stood in

def unreachable(ext, isa_set, hexs=None):
    """True when no QEMU x86_64 guest can execute these bytes.

    The execution probe only runs the encodings the tracer could not decode
    (REPRODUCE.sh), so most rows have no verdict.  Those fall back to the
    QEMU-derived scope model, NOT to the extension-name guess: the name guess
    is kept only to be contradicted out loud, and standing in for a
    measurement is exactly the job it was found unfit for.

    Measured 2026-08-23 on the 16 rows where the two fallbacks disagreed --
    CET (WRSS/WRUSS/INCSSP/RSTORSSP/SAVEPREVSSP/SETSSBSY/CLRSSBSY), UINTR
    (CLUI/STUI), TDX (SEAMCALL) and MOVDIR (MOVDIRI/MOVDIR64B): every one
    SIGILLs under qemu-x86_64 -cpu max, so the scope model is right and the
    name guess called all 16 reachable.  Controls in the same run ran clean
    (endbr64, IBHF, prefetch, add), so the probe was not simply refusing.
    """
    guess_unreach = name_guess_unreachable(ext, isa_set)
    ran = REACH.get(hexs)
    if ran is None:
        reach_unmeasured.add(hexs)
        return tcgscope.classify(hexs, ext, isa_set) is not None
    if guess_unreach == ran:
        reach_conflicts.append((hexs, ext, isa_set, guess_unreach, ran))
    return not ran

def classtok(t):
    """Collapse register NUMBER so signatures group across the bank (C3:
    the denominator is the opcode space, not the field permutations)."""
    return re.sub(r'\d+', '#', t)

def sigset(s):
    return ','.join(sorted({classtok(x) for x in s})) or '-'

# ------------------------------------------------------- mechanism roll-up
# 83 raw signatures collapse to a handful of causes.  Each row is charged to
# exactly one mechanism, most specific first, so the counts sum to n_dis.
def mechanism(mnem, ext, smiss, sextra, dmiss, dextra, refd, trd, flagwhy):
    sm, se = {classtok(x) for x in smiss}, {classtok(x) for x in sextra}
    dm, de = {classtok(x) for x in dmiss}, {classtok(x) for x in dextra}
    allt = sm | se | dm | de
    if 'REG_PRED#' in de and 'REG_VEC#' in dm:
        return ('M2 EVEX mask lands in the DESTINATION set and the vector '
                'destination is lost')
    if allt and allt <= {'REG_PRED#'}:
        if sm == {'REG_PRED#'} and not (se or dm or de):
            return 'M1 EVEX mask register not recorded as a source'
        return 'M1b EVEX mask register misplaced or missing (k-dest forms)'
    if 'REG_PRED#' in sm:
        return 'M1c EVEX mask source missing, alongside another gap'
    if any(x.startswith('UNMAPPED:') for x in allt):
        return 'M6 register outside the tracer vocabulary (system / model state)'
    if 'REG_FPR#' in allt or mnem.startswith('F'):
        return 'M5 x87: implicit ST(0) / status-word dependency missing'
    if sm == {'REG_FLAGS'} and not (se or dm or de):
        # R7.1 removed the preserve-read on the reference side, so an RFLAGS
        # source that SURVIVES here is a real edge and this is a tracer gap.
        # xl3.cc reports which edge, and the split is measured, not assumed.
        if 'CW' in flagwhy.split(','):
            return ('M3c tracer misses the R4 source of a CONDITIONAL flag '
                    'write (shift by CL: count 0 leaves the old flags)')
        return ('M3 tracer misses a REAL RFLAGS read (flag tested, or an '
                'explicit read-modify RFLAGS operand)')
    if 'REG_FLAGS' in allt:
        return 'M3b flag dependency wrong in another shape'
    if se or de:
        return 'M7 tracer names a register the reference does not (phantom)'
    return 'M8 other missing register'

# ---------------------------------------------------------------- compare
rows = []
sig_count = collections.Counter()
sig_example = {}
n_agree = n_dis = n_unprobed_tracer = n_unprobed_ref = 0
corro_count = collections.Counter()
sig_corro = collections.defaultdict(collections.Counter)
mech_count = collections.Counter()
mech_corro = collections.defaultdict(collections.Counter)
mech_reach = collections.defaultdict(collections.Counter)
mech_regs = collections.defaultdict(set)
tax_rows = []                       # the two-axis classification, one per DISAGREE
tax_labels = collections.Counter()  # every mechanism label seen, for rule coverage
n_collapse_dependent = 0
unprobed_by_reach = collections.Counter()

with open(os.path.join(COV, 'opcodes.tsv')) as f:
    next(f)
    opcodes = [l.rstrip('\n').split('\t') for l in f]

for opid, mnem, enc_hex, srctab in opcodes:
    hexs = PROBE.get(opid, enc_hex)
    md = META.get(opid, dict(iclass=mnem, isa_set='?', ext='?', cat='?'))
    r = REF.get(hexs, {})
    xed = r.get('XED')
    t = TR.get(hexs)
    reach = 'no' if unreachable(md['ext'], md['isa_set'], hexs) else 'yes'

    if t is None or not t['ok']:
        n_unprobed_tracer += 1
        unprobed_by_reach[('tracer_decode_fail', reach)] += 1
        rows.append((opid, mnem, enc_hex, md['ext'], hexs, reach, 'UNPROBED',
                     'tracer: decoder does not decode these bytes '
                     '(no InsnFields produced)', '', '', '', '', 'na',
                     'tracer-decode-gap', 'NOT-COMPARED', 'NOT-COMPARED',
                     'tracer-defect', '0'))
        continue
    if xed is None or not xed['ok']:
        n_unprobed_ref += 1
        unprobed_by_reach[('reference_decode_fail', reach)] += 1
        rows.append((opid, mnem, enc_hex, md['ext'], hexs, reach, 'UNPROBED',
                     'reference: XED does not decode these bytes', '', '',
                     ','.join(sorted(t['src'])) or '-',
                     ','.join(sorted(t['dst'])) or '-', 'na',
                     'reference-decode-gap', 'NOT-COMPARED', 'NOT-COMPARED',
                     'reference-gap', '0'))
        continue

    axsrc, axdst = adjudicate(hexs, xed['src'], xed['dst'])
    rsrc = set(); rdst = set()
    for n in axsrc:
        v = ref_token(n)
        if v: rsrc.add(v)
    for n in axdst:
        v = ref_token(n)
        if v: rdst.add(v)
    tsrc = {x for x in t['src'] if x not in DROP_TRACER}
    tdst = {x for x in t['dst'] if x not in DROP_TRACER}
    rsrc = {x for x in rsrc if x not in DROP_TRACER}
    rdst = {x for x in rdst if x not in DROP_TRACER}

    smiss, sextra = rsrc - tsrc, tsrc - rsrc
    dmiss, dextra = rdst - tdst, tdst - rdst

    refs = ','.join(sorted(rsrc)) or '-'
    refd = ','.join(sorted(rdst)) or '-'
    trs = ','.join(sorted(tsrc)) or '-'
    trd = ','.join(sorted(tdst)) or '-'

    if not (smiss or sextra or dmiss or dextra):
        n_agree += 1
        rows.append((opid, mnem, enc_hex, md['ext'], hexs, reach, 'AGREE', '',
                     refs, refd, trs, trd, 'agree',
                     '-', tax.EQUAL, '-', '-', '-'))
        continue

    n_dis += 1
    sig = 'SRC-MISS{%s} SRC-EXTRA{%s} DST-MISS{%s} DST-EXTRA{%s}' % (
        sigset(smiss), sigset(sextra), sigset(dmiss), sigset(dextra))
    sig_count[sig] += 1
    # Adjudicate: does the SECOND-ranked reference back XED, or the tracer?
    # A disagreement two independent references agree on is a finding; one
    # only XED reports is a candidate XED idiosyncrasy and is marked so.
    corro = 'na'
    iced = REF.get(hexs, {}).get('ICED')
    if iced and iced['ok']:
        isrc = {v for v in (ref_token(n) for n in iced['src']) if v}
        idst = {v for v in (ref_token(n) for n in iced['dst']) if v}
        isrc = {x for x in isrc if x not in DROP_TRACER}
        idst = {x for x in idst if x not in DROP_TRACER}
        if (isrc, idst) == (rsrc, rdst):
            corro = 'ref'          # iced == XED: disagreement corroborated
        elif (isrc, idst) == (tsrc, tdst):
            corro = 'tracer'       # iced == tracer: XED is the outlier
        else:
            corro = 'third'        # all three differ
    corro_count[corro] += 1
    sig_corro[sig][corro] += 1
    mech = mechanism(mnem, md['ext'], smiss, sextra, dmiss, dextra, refd, trd,
                     xed.get('why', '-'))
    mech_count[mech] += 1
    mech_corro[mech][corro] += 1
    mech_reach[mech][reach] += 1
    for x in ({classtok(y) for y in smiss} | {classtok(y) for y in sextra} |
              {classtok(y) for y in dmiss} | {classtok(y) for y in dextra}):
        if x.startswith('UNMAPPED:'):
            mech_regs[mech].add(x)
    sig_example.setdefault(sig, (opid, mnem, hexs, refs, refd, trs, trd))

    # ---- the two axes.  DIRECTION is measured from the sets the verdict was
    # taken from -- the same four -- so it cannot drift from the verdict.
    rel = tax.set_relation(rsrc, rdst, tsrc, tdst)
    key = taxrules.x86_key(mech)
    tax_labels[key] += 1
    tax_rows.append(tax.classify(opid, mnem, mech, rel,
                                 taxrules.X86.get(key)))
    trow = tax_rows[-1]
    rows.append((opid, mnem, enc_hex, md['ext'], hexs, reach, 'DISAGREE', sig,
                 refs, refd, trs, trd, corro,
                 mech, rel, trow.direction, trow.category,
                 '1' if trow.accounted else '0'))

# ---------------------------------------------------------------- outputs
with open(os.path.join(COV, 'attrib.tsv'), 'w') as f:
    f.write('#opcode_id\tmnemonic\tencoding_hex\textension\t'
            'probe_hex\tqemu_tcg_reachable\tverdict\tsignature\t'
            'ref_src\tref_dst\ttracer_src\ttracer_dst\ticed_backs\t'
            'mechanism\tset_relation\tdirection\tcategory\taccounted\n')
    for r in rows:
        f.write('\t'.join(r) + '\n')

out = []
w = out.append
w('ChampSim Tracer / ARC 3 -- x86_64 REGISTER ATTRIBUTION, whole opcode space')
w('reference: Intel XED External Release v2026.07.15 (primary), with')
w('           iced-x86 1.21.0 and LLVM MC 18.1.3 loaded for adjudication')
w('tracer   : isaxcheck --isa=x86_64 --layer=fields  (the plugin\'s own InsnFields')
w('           via decode_detail_to_generic(), i.e. what the TRACE records)')
w('repo     : /mnt/md0/QEMU/qemu @ champsim-trace')
w('')
w('DENOMINATOR   x86_64 opcode space                 : %d' % len(opcodes))
w('  ATTEMPTED   (a reference AND a tracer set exist): %d' % (n_agree + n_dis))
w('  AGREE       (sets identical, both directions)   : %d' % n_agree)
w('  DISAGREE                                        : %d' % n_dis)
# The unprobed TOTAL is never printed on its own.  It sat frozen at 2713
# across three reports while its composition moved 2479/234 -> 2363/349
# reachable: the constant hid a 50% growth in the coverage hole.  Both
# components are printed on the same line, always, so the next change cannot
# hide inside a sum.
_unp_unreach = sum(v for (_why, rc), v in unprobed_by_reach.items() if rc == 'no')
_unp_reach = sum(v for (_why, rc), v in unprobed_by_reach.items() if rc == 'yes')
_unp_hole = sum(v for (why, rc), v in unprobed_by_reach.items()
                if why == 'tracer_decode_fail' and rc == 'yes')
w('  UNPROBED  = out-of-scope + REACHABLE HOLE     : %d = %d + %d'
  % (_unp_unreach + _unp_reach, _unp_unreach, _unp_reach))
w('')
w('UNPROBED BREAKDOWN  (an opcode that could not be probed is NOT an opcode')
w('that agreed; it is reported here and counted nowhere else)')
for (why, reach), n in sorted(unprobed_by_reach.items(), key=lambda kv: -kv[1]):
    w('  %-22s  qemu-tcg-reachable=%-3s : %5d' % (why, reach, n))
w('')

# ---------------------------------------------- the exclusion, from QEMU
# Every unreachable row is charged to a mechanism read out of QEMU's own
# source, not out of the tracer's failure to decode it, and not out of an
# extension NAME.  A row this model cannot charge is an unjustified
# exclusion and stops the report.
_scope_mech = collections.Counter()
_scope_cite = {}
_uncited = []
for r in rows:
    if r[6] != 'UNPROBED' or r[5] != 'no':
        continue
    _sc = tcgscope.classify(r[4], r[3], META.get(r[0], {}).get('isa_set', ''))
    if _sc is None:
        _uncited.append(r)
    else:
        _scope_mech[_sc.mechanism] += 1
        _scope_cite[_sc.mechanism] = _sc
w('WHY THE %d OUT-OF-SCOPE ROWS ARE OUT OF SCOPE  (derived from the QEMU tree,'
  % _unp_unreach)
w('re-asserted at every run by qemu_tcg_scope.selfcheck; NOT from the tracer')
w('failing to decode them and NOT from an XED extension name)')
w('')
for _m, _n in _scope_mech.most_common():
    _sc = _scope_cite[_m]
    w('  %-28s %5d' % (_m, _n))
    w('      cite   : %s' % _sc.citation)
    w('      reach  : %s' % _sc.remedy)
w('')
if _uncited:
    w('  *** %d UNREACHABLE ROWS WITH NO QEMU CITATION ***' % len(_uncited))
    for r in _uncited[:20]:
        w('      %-14s %-18s %s' % (r[4], r[1], r[3]))
w('')
w('The %d REACHABLE unprobed rows are the coverage hole: a QEMU x86_64 guest'
  % _unp_reach)
w('runs them, and for the %d of those the TRACER rejects, the trace carries no'
  % _unp_hole)
w('register sets at all -- the most severe form of dropped information there')
w('is.  By XED extension:')
unp_ext = collections.Counter()
for r in rows:
    if r[6] == 'UNPROBED' and r[5] == 'yes' and 'tracer' in r[7]:
        unp_ext[r[3]] += 1
for e, v in unp_ext.most_common():
    w('  %-22s %4d' % (e, v))
w('')
pct = lambda a, b: (100.0 * a / b) if b else 0.0
w('ADJUDICATIONS APPLIED TO THE REFERENCE (XED primary; a correction is')
w('listed only where iced-x86 and LLVM MC both contradict XED)')
for k, v in ADJ.most_common():
    w('  %6d  %s' % (v, k))
if not ADJ:
    w('  (none)')
w('')
w('PROBE ENCODINGS')
w('  opcodes probed with the denominator encoding    : %d' %
  sum(1 for o, m2, h, s2 in opcodes if PROBE.get(o, h) == h))
w('  opcodes re-probed with aaa=001 to exercise the')
w('  EVEX mask operand (same iform, same length)     : %d' %
  sum(1 for o, m2, h, s2 in opcodes if PROBE.get(o, h) != h))
w('')
w('AGREEMENT RATE over what was actually probed      : %d/%d = %.2f%%' %
  (n_agree, n_agree + n_dis, pct(n_agree, n_agree + n_dis)))
w('AGREEMENT RATE over the whole opcode space        : %d/%d = %.2f%%' %
  (n_agree, len(opcodes), pct(n_agree, len(opcodes))))
w('')
# ------------------------------------------------------------- the two axes
# A disagreement count on its own hides the whole criterion.  Every disagreeing
# row is classified on DIRECTION (measured from the sets) and CATEGORY (the
# mechanism), and the cross-tabulation is printed before anything else.
w('=' * 78)
w('TWO-AXIS CLASSIFICATION OF THE %d DISAGREEING ROWS' % n_dis)
w('=' * 78)
w('')
for d in tax.DIRECTIONS:
    w('  %-16s %s' % (d, tax.DIRECTION_VERDICT[d]))
w('')
w(tax.render_crosstab(tax_rows,
                      'CROSS-TABULATION  direction x category'))
w('')
w(tax.render_conflicts(tax_rows))
w(tax.render_unaccounted(tax_rows))
w('LABELS WITH NO RULE  (a mechanism label the taxonomy does not map is not')
w('an explanation; its rows are UNACCOUNTED and are listed above)')
_nr = [(k, n) for k, n in tax_labels.most_common() if k not in taxrules.X86]
for k, n in _nr:
    w('  %6d  %s' % (n, k))
if not _nr:
    w('  (none -- every mechanism label the harness emits maps onto the taxonomy)')
w('')
w('NOT COMPARED AT ALL  (an opcode with no comparison has no direction; it is')
w('the most complete form of dropped information and is counted here, never')
w('inside the cross-tabulation above)')
w('  tracer decoder rejects the bytes, qemu-tcg reachable : %d' %
  sum(v for (why, rc), v in unprobed_by_reach.items()
      if why == 'tracer_decode_fail' and rc == 'yes'))
w('  tracer decoder rejects the bytes, not reachable      : %d' %
  sum(v for (why, rc), v in unprobed_by_reach.items()
      if why == 'tracer_decode_fail' and rc == 'no'))
w('  reference decoder rejects the bytes                  : %d' %
  sum(v for (why, rc), v in unprobed_by_reach.items()
      if why == 'reference_decode_fail'))
w('')
w('')
w('  the two legs of the exclusion, and neither is the decoder\'s opinion:')
w('    executed under qemu-x86_64 -cpu max, SIGILL           : %d' % _unp_unreach)
w('    charged to a QEMU source citation (qemu_tcg_scope)    : %d'
  % sum(_scope_mech.values()))
w('    unreachable rows with NO citation (must be 0)         : %d' % len(_uncited))
w('')
w('  reachability is MEASURED: every encoding above was executed under')
w('  qemu-x86_64 -cpu max and SIGILL is QEMU\'s TCG front end refusing it')
w('  (reach_probe.c).  A name test on XED\'s extension / isa-set is kept')
w('  only to be contradicted out loud.')
w('    encodings with an execution verdict     : %d' % len(REACH))
w('    encodings the name test stood in for    : %d' % len(reach_unmeasured))
w('    name test contradicted by the run       : %d' % len(reach_conflicts))
for hx, ext, iset, guess, ran in reach_conflicts[:12]:
    w('      %-16s %-16s %-18s name=%s run=%s' %
      (hx, ext, iset, 'unreachable' if guess else 'reachable',
       'ran' if ran else 'SIGILL'))
if len(reach_conflicts) > 12:
    w('      ... and %d more' % (len(reach_conflicts) - 12))
w('')
w('MEMOP ATTRIBUTION  (count / address / data for every load and store) is')
w('HALF the deliverable and this harness does not measure any of it: the')
w('tracer arm reads f_loads / f_stores and the reference arm carries XED\'s')
w('memop column, and neither is compared.  Reported as a hole, not implied')
w('to be covered by the register numbers above.')
w('')
w('MECHANISM ROLL-UP  (every disagreement charged to exactly one cause;')
w('these sum to the %d disagreements above)' % n_dis)
w('')
# Maintainer adjudications, per mechanism.  A mechanism whose verdict is
# REFERENCE-side is not a tracer defect and must not be read as one; the
# count stays in the DISAGREE total because the two sets really do differ,
# and hiding it would make the total mean something else.
#
# R7.1 (2026-08-23), verbatim: "Things like narrow writes into registers
# are irrelevant (rename doesn't care, because it doesn't know the
# data-width-scope of the next reader). I know for a fact that during
# execution we track register-data-width, so the fact that a register's
# upper contents may not be modified does not imply it is a source AND a
# destination for the instruction unless the instruction specifically
# takes it as a source."  That kills the preserve-read argument for BOTH
# M3 (a partial flag write) and M4 (a sub-width vector write), which are
# the same argument in two register banks.  XED and iced model the
# hardware preserve, which is a different question from the one the wire
# answers.
#
# M3b is NOT covered by it and must not be swept in: those rows are the
# tracer recording NOTHING where the reference records a write (`cli`
# writes IF), which is a Capstone access-flag gap, not a preserve-read.
# NOTHING is charged to R7.1 any more, and that is the point: R7.1 was
# applied by CORRECTING THE REFERENCE (xl3.cc / icedtsv.py), not by labelling
# rows.  A label cannot change set identity, so a labelled row can never
# leave the disagree column; a corrected reference moves it to AGREE.  The
# rule fires on every sweep and prints its suppression counts, so the class
# is still visible -- see the R7.1-NARROW / R7.1-SCALAR lines on stderr.
MECH_VERDICT = {}

for m, n in mech_count.most_common():
    cc = mech_corro[m]
    verdict = next((v for k, v in MECH_VERDICT.items() if m.startswith(k)),
                   None)
    if verdict:
        w('%6d  %s' % (n, m))
        w('        VERDICT: %s' % verdict)
        w('        corroborated by iced-x86: %d   XED-only: %d   3-way split: %d'
          % (cc['ref'], cc['tracer'], cc['third']))
        w('        qemu-tcg reachable: yes=%d no=%d'
          % (mech_reach[m]['yes'], mech_reach[m]['no']))
        continue
    if m.startswith('M6'):
        regs = sorted({x[9:] for x in mech_regs[m]})
        w('%6d  %s' % (n, m))
        w('        registers: %s' % ', '.join(regs))
        w('        corroborated by iced-x86: %d   XED-only: %d   3-way split: %d'
          % (cc['ref'], cc['tracer'], cc['third']))
        w('        qemu-tcg reachable: yes=%d no=%d'
          % (mech_reach[m]['yes'], mech_reach[m]['no']))
        continue
    w('%6d  %s' % (n, m))
    w('        corroborated by iced-x86: %d   XED-only: %d   3-way split: %d'
      % (cc['ref'], cc['tracer'], cc['third']))
    w('        qemu-tcg reachable: yes=%d no=%d'
      % (mech_reach[m]['yes'], mech_reach[m]['no']))
adj_n = sum(n for m, n in mech_count.items()
            if any(m.startswith(k) for k in MECH_VERDICT))
w('')
w('CHARGED TO A REFERENCE-SIDE VERDICT                : %d of the %d'
  % (adj_n, n_dis))
w('  R7.1 is applied by CORRECTING the reference, not by labelling rows, so')
w('  its rows are AGREE above rather than adjudicated here.  Remaining')
w('  disagreements that are still the tracer\'s              : %d' % (n_dis - adj_n))
w('')
w('DISAGREEMENT SIGNATURES  (%d distinct), largest first' % len(sig_count))
w('  MISS  = the reference names it, the tracer does not')
w('  EXTRA = the tracer names it, the reference does not')
w('  register numbers collapsed to # so a signature groups across the bank')
w('')
for sig, n in sig_count.most_common():
    opid, mnem, hexs, refs, refd, trs, trd = sig_example[sig]
    cc = sig_corro[sig]
    w('%6d  %s' % (n, sig))
    w('        iced-x86 backs: reference=%d tracer=%d neither=%d n/a=%d'
      % (cc['ref'], cc['tracer'], cc['third'], cc['na']))
    w('        e.g. %s  %s  [%s]' % (opid, mnem, hexs))
    w('             ref    SRC{%s} DST{%s}' % (refs, refd))
    w('             tracer SRC{%s} DST{%s}' % (trs, trd))
w('')
# reachability split of the disagreements
dis_reach = collections.Counter()
for r in rows:
    if r[6] == 'DISAGREE':
        dis_reach[r[5]] += 1
w('SECOND-REFERENCE ADJUDICATION OF THE %d DISAGREEMENTS' % n_dis)
w('  (iced-x86 elaborated independently, mapped through the same vocabulary)')
w('  iced backs the REFERENCE (disagreement corroborated) : %5d' % corro_count['ref'])
w('  iced backs the TRACER    (XED is the outlier)        : %5d' % corro_count['tracer'])
w('  all three differ                                     : %5d' % corro_count['third'])
w('  iced could not decode                                : %5d' % corro_count['na'])
w('')
w('DISAGREEMENTS BY QEMU-TCG REACHABILITY')
for k, v in sorted(dis_reach.items()):
    w('  reachable=%-3s : %5d' % (k, v))
w('')
ext_dis = collections.Counter()
ext_tot = collections.Counter()
for r in rows:
    ext_tot[r[3]] += 1
    if r[6] == 'DISAGREE':
        ext_dis[r[3]] += 1
w('DISAGREEMENTS BY XED EXTENSION (top 25 by count)')
for e, v in ext_dis.most_common(25):
    w('  %-22s %5d / %5d in the denominator' % (e, v, ext_tot[e]))

w('')
w('ROOT CAUSE OF M1/M1b/M1c/M2 (the EVEX mask classes, %d rows)'
  % sum(v for m, v in mech_count.items() if m.startswith('M1') or m.startswith('M2')))
w('The tracer\'s operand walker contributes a register by its ACCESS FLAG.')
w('Capstone 6.0-Alpha7 hands over the EVEX mask operand with access == 0 --')
w('neither read nor write -- so the walker drops it and the mask never')
w('reaches InsnFields.  isaxcheck reports that condition as b_unkreg.')
w('Correlation over this sweep:')
mrows = [r for r in rows if r[6] == 'DISAGREE' and 'REG_PRED' in r[7]]
arows = [r for r in rows if r[6] == 'AGREE']
unk = {}
with open(os.path.join(D, 'tracer_batch.tsv')) as f:
    c2 = next(f).rstrip('\n').split('\t'); j = {c: i for i, c in enumerate(c2)}
    for line in f:
        q = line.rstrip('\n').split('\t')
        if len(q) >= len(c2):
            unk[q[j['hex']]] = q[j['b_unkreg']]
mu = collections.Counter(unk.get(r[4]) for r in mrows)
au = collections.Counter(unk.get(r[4]) for r in arows)
w('  mask-loss rows with a Capstone access==0 REG operand : %d / %d'
  % (mu['1'], len(mrows)))
w('  agreeing rows with a Capstone access==0 REG operand  : %d / %d'
  % (au['1'], len(arows)))
w('This is an upstream Capstone defect of the same family as the PEXTR and')
w('MSA access-flag bugs already worked around at the boundary in')
w('disas/capstone.c.  Under R8 the fix belongs on the fork, at that same')
w('boundary; it is NOT a tracer limitation to be documented away.')
w('')
w('LOSSY POINTS IN THE TRACER VOCABULARY ITSELF (independent of any sweep')
w('row above): distinct architectural registers sharing one GenericRegId.')
coll = collections.defaultdict(set)
for nme, g in TRACER_REG.items():
    coll[g].add(nme)
for g in ('REG_FLAGS', 'REG_CTRL', 'REG_DEBUG'):
    names = sorted(coll.get(g, ()))
    if len(names) > 1:
        w('  %-12s <- %d distinct architectural registers: %s'
          % (g, len(names), ', '.join(names)))
w('  REG_VEC<n>   <- XMM<n>, YMM<n>, ZMM<n> (true aliases, correct per R4)')
w('                  AND MM<n>, which in hardware aliases ST(<n>), not XMM')

txt = '\n'.join(out) + '\n'
open(os.path.join(COV, 'attrib_signatures.txt'), 'w').write(txt)
print(txt)

# An exclusion that nothing in QEMU justifies is not an exclusion.  This is
# the only place the report refuses: the rows it would otherwise drop are the
# ones that cost EVERYTHING for their instruction.
if _uncited:
    sys.exit('%d unreachable rows carry no QEMU citation; they are '
             'unjustified exclusions, not out-of-scope rows' % len(_uncited))
