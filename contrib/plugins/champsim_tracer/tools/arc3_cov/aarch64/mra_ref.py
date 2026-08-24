"""Reference operand sets for A64 encodings, from the Arm MRA pseudocode."""
import os, re, sys
import mraxml, aslparse, aslinterp
from aslinterp import Interp, Bits, UNK, Effects, Undefined, Budget

XMLDIR = mraxml.XMLDIR
BASE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64'

# ---------------------------------------------------------------- sysregs
def load_sysregs():
    by_name = {}
    by_enc = {}
    path = os.path.join(BASE, 'sysreg_accessors.tsv')
    if os.path.exists(path):
        with open(path) as f:
            hdr = f.readline().rstrip('\n').split('\t')
            col = {n: i for i, n in enumerate(hdr)}
            for line in f:
                p = line.rstrip('\n').split('\t')
                nm = p[col.get('reg', 0)] if 'reg' in col else p[0]
                by_name[nm.upper()] = nm
    return by_name, by_enc


SYSREG_NAMES = set()
def _init_sysreg_names():
    """Every AArch64 system register name in the rank-1 SysReg XML."""
    d = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64/_ref/sysreg/SysReg_xml_A_profile-2022-12'
    if not os.path.isdir(d):
        return
    for fn in os.listdir(d):
        if fn.endswith('.xml'):
            SYSREG_NAMES.add(fn[:-4].upper())
_init_sysreg_names()

TLS_REGS = {'TPIDR_EL0', 'TPIDRRO_EL0'}

# The FP/SIMD/SVE/SME execution-enable gate.  R7.4 rules the read real
# and the tracer now records it on its own generic ID (REG_SYSFPEN), so
# the reference needs the matching token: folded into 'SYS' the
# comparison would score the gate against every other system register
# and could not tell a correct gate read from a wrong one.
FPEN_REGS = {'CPACR_EL1', 'CPTR_EL2', 'CPTR_EL3'}

# Vector configuration.  ZCR_ELx and SMCR_ELx carry the SVE / streaming
# vector length, and SMCR_ELx.EZT0 is the second gate CheckSMEZT0Enabled
# reads on the ZT0 forms.  The tracer's generic space has carried a
# vector-configuration ID (REG_VCTRL) since before this arc -- it is what
# RISC-V vl/vtype/vstart map to -- and cap_aarch64_sysreg_class now puts
# these there, so the reference names the same role rather than folding
# them into the residual.
VCTRL_REGS = {'ZCR_EL1', 'ZCR_EL2', 'ZCR_EL3', 'ZCR_EL12',
              'SMCR_EL1', 'SMCR_EL2', 'SMCR_EL3', 'SMCR_EL12', 'SVCR'}

# The guarded control stack pointer.  GCSPR_ELx is a shadow-stack
# pointer, which is a role the tracer's generic space has named for as
# long as it has had x86 CET SSP and RISC-V ssp in it (REG_SSP), and
# cap_aarch64_sysreg_class puts GCSPR_ELx there for the same reason.
# Folded into 'SYS' here, the comparison would score every GCS push and
# pop against the whole privileged file and could not tell a
# shadow-stack dependency from any other system-register dependency.
# The fourth role carve-out, on the same footing as TLS, SYSFPEN and
# VCTRL and for the same reason: the reference names a role the tracer
# names, so a naming difference is never scored as an attribution one.
SSP_REGS = {'GCSPR_EL0', 'GCSPR_EL1', 'GCSPR_EL2', 'GCSPR_EL3',
            'GCSPR_EL12'}

# The enabling-condition and translation-configuration registers.
#
# METHOD declares the exception-delivery, address-translation, debug,
# profiling and trap-check families cut, and CUT_PREFIXES / CUT_EXACT cut
# them wherever they are reached through a named function.  They are not
# always reached that way: AddPACIA writes its own trap check inline
# (`Enable = SCTLR_EL1.EnIA; TrapEL3 = ... SCR_EL3.API ...`), and
# CalculateBottomPACBit reaches the stage-1 walk parameters -- TCR, TTBR,
# MAIR, PIR -- to find how many pointer bits the translation regime
# leaves for the PAC.  A name-keyed cut cannot see either.
#
# These registers are never an operand of the instruction under any
# reading.  They say whether the instruction is ENABLED and how the
# address space is CONFIGURED.  Measured before this filter: 395 of the
# 426 rows carrying a system-register read carried SCTLR_EL{1,2,3}, 355
# carried TCR_EL3 -- read by the tag-check enable predicate on every
# atomic and by the PAC bit-width computation, not by the instruction.
#
# HALF OF THAT IS A BLIND SPOT AND NOT A CUT, and the half is the ENABLE
# registers.  This filter used to justify itself with "recording them
# makes every branch, every atomic and every tagged store depend on
# whatever system register was written last".  R7.4 rules the dependency
# REAL -- "if a write to the CSR would block that instruction due to a
# dependency, it should be recorded" -- and R8.1 rules the objection a
# MAPPING defect rather than a reason to drop the fact.  So CPACR_EL1 and
# CPTR_EL{2,3} stay filtered ONLY because the tracer does not record them
# yet, which keeps the two arms comparable; the filter is aligned to the
# tracer here, not to the architecture, and that is the one place in this
# reference where those differ.
#
# SIZE OF THE BLIND SPOT, measured 2026-08-23 by lifting the filter and
# CUT_EXACT's FP/SVE/SME enable family together: 2,803 of the 3,810
# probed subjects gain a SYS source -- 771 distinct mnemonics across
# advsimd 696, sve 788, sve2 455, mortlach/mortlach2 555, float 218,
# fpsimd 89, system 2 -- and NOT ONE of them already carries a SYS
# source, so every one would be a new edge.  All 2,803 land on REG_SYS,
# which on AArch64 is the whole system-register file bar NZCV, FPCR,
# FPSR, FPMR, TPIDR and the 23 REG_SYSID constants.  That is R8.5's
# shape at 280x the riscv64 scale, and R8.5 is why it is not implemented:
# the file must be split before the ruling can be honoured without
# manufacturing the edge R8.1 forbids.  Lift both filters to re-measure.
#
# Registers that ARE operands stay: GCR_EL1 (the tag exclusion mask ADDG
# and IRG compute from), RGSR_EL1, GMID_EL1, DCZID_EL0, ELR_ELx / SPSR_ELx
# (what ERET resumes from), DISR_EL1, ACCDATA_EL1, PAR_EL1, GCSPR_ELx.
CONFIG_REGS = re.compile(
    r'^('
    r'SCTLR2?_EL[123]'
    r'|SCR_EL3'
    r'|HCRX?_EL2'
    r'|TCR2?_EL[123]'
    r'|TTBR[01]_EL[123]'
    r'|MAIR2?_EL[123]'
    r'|PIR_EL[123]|PIRE0_EL[12]'
    r'|GCSCR_EL[123]|GCSCRE0_EL1'
    r')$')


def sysreg_lookup(name=None, enc=None):
    if name is not None:
        u = name.upper()
        if CONFIG_REGS.match(u):
            return None
        if u in FPEN_REGS:
            return 'SYSFPEN'
        if u in VCTRL_REGS:
            return 'VCTRL'
        if u in SSP_REGS:
            return 'SSP'
        if u in SYSREG_NAMES or re.match(r'^[A-Z][A-Z0-9]*_EL[0-3]', u):
            return 'TLS' if u in TLS_REGS else 'SYS'
        return None
    # Reached from AArch64.SysInstr / SysInstrWithResult, where the
    # operation is named by its ENCODING and there is no register name to
    # look up.  The guarded-control-stack operations -- GCSPUSHM/X,
    # GCSPOPM/X/CX, GCSSS1/2, all op0 = 1, CRn = 7, CRm = 7 -- move
    # GCSPR_ELx, so they carry the shadow-stack role rather than the
    # residual, exactly as the named lookup above gives GCSPR_ELx.
    if enc is not None:
        op0, op1, crn, crm, op2 = enc
        if op0 == 1 and crn == 7 and crm == 7:
            return 'SSP'
    return 'SYS'


# ------------------------------------------------------- encoding matching
class EncTable:
    def __init__(self, idx):
        self.idx = idx
        self.cache = {}

    def file_entries(self, base):
        if base in self.cache:
            return self.cache[base]
        out = []
        f = self.idx['files'].get(base)
        if f is None:
            self.cache[base] = out
            return out
        for ci, ic in enumerate(f['iclasses']):
            mask, val, fields = 0, 0, {}
            for b in ic['boxes']:
                lo = b['hibit'] - b['width'] + 1
                cells = b['cells']
                if b.get('name'):
                    fields.setdefault(b['name'], []).append((b['hibit'], b['width']))
                if len(cells) == b['width']:
                    for k, c in enumerate(cells):
                        if c in ('0', '1'):
                            bit = b['hibit'] - k
                            mask |= 1 << bit
                            val |= int(c) << bit
                elif b['width'] == 1 and cells and cells[0] in ('0', '1'):
                    mask |= 1 << b['hibit']
                    val |= int(cells[0]) << b['hibit']
            for ei, e in enumerate(ic['encs']):
                em, ev = mask, val
                for b in e['boxes']:
                    cells = b['cells']
                    if len(cells) == b['width']:
                        for k, c in enumerate(cells):
                            if c in ('0', '1'):
                                bit = b['hibit'] - k
                                em |= 1 << bit
                                ev = (ev & ~(1 << bit)) | (int(c) << bit)
                out.append({'ci': ci, 'ei': ei, 'mask': em, 'val': ev,
                            'fields': fields, 'name': e['name'], 'iclass': ic})
        self.cache[base] = out
        return out

    def match(self, base, word, prefer=None):
        ents = self.file_entries(base)
        hits = [e for e in ents if (word & e['mask']) == e['val']]
        if prefer:
            for e in hits:
                if e['name'] == prefer:
                    return e
            for e in ents:
                if e['name'] == prefer:
                    return e
        if len(hits) == 1:
            return hits[0]
        if hits:
            return max(hits, key=lambda e: bin(e['mask']).count('1'))
        return None


ALIASTO = {}
def alias_target(base):
    if base in ALIASTO:
        return ALIASTO[base]
    p = os.path.join(XMLDIR, base)
    tgt = None
    if os.path.exists(p):
        d = open(p, encoding='utf-8', errors='replace').read()
        m = re.search(r'<aliasto refiform="([^"]+)"', d)
        if m:
            tgt = m.group(1)
    ALIASTO[base] = tgt
    return tgt


# ---------------------------------------------------------------- the cut
CUT_PREFIXES = (
    'AArch32.', 'AArch64.Abort', 'AArch64.Take', 'AArch64.DataAbort',
    'AArch64.InstructionAbort', 'AArch64.Undefined', 'AArch64.SystemAccessTrap',
    'AArch64.Breakpoint', 'AArch64.Watchpoint', 'AArch64.VectorCatch',
    'AArch64.SoftwareBreakpoint', 'AArch64.SPAlignmentFault', 'AArch64.RaiseTagCheckFault',
    'AArch64.WFxTrap', 'AArch64.CallSupervisor', 'AArch64.CallHypervisor',
    'AArch64.CallSecureMonitor', 'AArch64.FPTrappedException', 'AArch64.vESBOperation',
    'AArch64.GenerateDebugExceptions', 'AArch64.CheckFor', 'AArch64.MaybeZero',
    'AArch64.TranslateAddress', 'AArch64.MemSingle', 'AArch64.CheckAlignment',
    'AArch64.AccessIsTagChecked', 'AArch64.ExclusiveMonitor',
    'BRBE', 'CountPMUEvents', 'Halt', 'DCPSInstruction', 'DRPSInstruction',
    'CheckExceptionCatch', 'UpdateEDSCRFields', 'FailTransaction',
    'TakeTransactionCheckpoint', 'RestoreTransactionCheckpoint',
    'TransactionStartTrap', 'GenMPAM', 'ReportAsGPCException',
    'SVEAccessTrap', 'SMEAccessTrap', 'IllegalExceptionReturn',
    'Hint_WF', 'InterruptPending', 'ResetSVEState', 'ResetSMEState',
    'CheckGCSSTRTrap', 'AlignmentEnforced', 'DebugRestorePSR',
    'DebugExceptionReturnSS', 'SSAdvance', 'AArch64.CheckSystemAccess',
    'AArch64.SysRegAccess', 'AArch64.SetExclusiveMonitors',
    'AArch64.MarkExclusive', 'AArch64.IsExclusive', 'ExclusiveMonitorsStatus',
    'SPEBranch', 'Hint_Branch', 'AArch64.BranchAddr', 'ProfilingBufferEnabled',
)
CUT_EXACT = {
    # The FP/SIMD/SVE/SME enable checks -- CheckFPAdvSIMDEnabled,
    # CheckFPEnabled, CheckSVEEnabled and the streaming/ZA/ZT0 variants
    # -- USED TO BE CUT HERE, and the METHOD file called that the one
    # place this reference followed the tracer instead of the
    # architecture.  It no longer does: the tracer records the gate
    # (R7.4), so the checks are inlined and their CPACR_EL1 /
    # CPTR_EL{2,3} reads are scored.  What still keeps the inlining
    # bounded is CONFIG_REGS above, which drops SCTLR / HCR / SCR and
    # the translation configuration those functions also touch, and
    # IsSVEEnabled / IsInHost / ELStateUsingAArch32K, still cut below.
    'CheckMOPSEnabled', 'CheckLDST64BEnabled',
    'CheckST64BV0Enabled', 'CheckST64BVEnabled', 'CheckSPAlignment',
    'BTypeCompatible_BTI', 'BTypeCompatible_PACIXSP', 'BigEndian',
    'IsFullA64Enabled', 'IsTMEEnabled', 'IsSVEEnabled', 'IsInHost',
    'UsingAArch32', 'ELStateUsingAArch32K', 'CurrentSecurityState',
    'CurrentInstrSet', 'NewAccDesc', 'StoreOnlyTagCheckingEnabled',
    'GetCurrentEXLOCKEN', 'SetPSTATEFromPSR', 'AddGCSRecord',
    'SetCurrentGCSPointer', 'GetCurrentGCSPointer', 'LoadCheckGCSRecord',
}


def inline_ok(name):
    if name in CUT_EXACT:
        return False
    for p in CUT_PREFIXES:
        if name.startswith(p):
            return False
    return True


# ---------------------------------------------------------------- driver
class Ref:
    def __init__(self):
        self.idx = mraxml.load_index()
        self.sh = mraxml.load_shared()
        self.tab = EncTable(self.idx)
        self.pcache = {}

    def parse_cached(self, key, text):
        if key not in self.pcache:
            try:
                self.pcache[key] = aslparse.parse_stmts(text)
            except Exception as e:
                self.pcache[key] = ('ERR', str(e))
        v = self.pcache[key]
        if isinstance(v, tuple) and v and v[0] == 'ERR':
            raise aslparse.AslError(v[1])
        return v

    def field_env(self, ent, word):
        env = {}
        for nm, boxes in ent['fields'].items():
            boxes = sorted(boxes, key=lambda b: -b[0])
            val = 0
            wid = 0
            for hibit, w in boxes:
                lo = hibit - w + 1
                piece = (word >> lo) & ((1 << w) - 1)
                val = (val << w) | piece
                wid += w
            env[nm] = Bits(wid, val)
        return env

    def run(self, opid, word, xml_file):
        """Return (effects, notes, status)."""
        base = xml_file
        prefer = opid
        tgt = alias_target(base)
        if tgt:
            base, prefer = tgt, None
        ent = self.tab.match(base, word, prefer)
        if ent is None and tgt is None:
            t2 = None
        if ent is None:
            return None, ['no-encoding-match'], 'unprobed'
        f = self.idx['files'][base]
        ic = ent['iclass']
        dec = [p['text'] for p in ic['ps'] if p['sect'] == 'decode']
        post = [p['text'] for p in f['top_ps'] if p['sect'] == 'postdecode']
        ex = [p['text'] for p in f['top_ps'] if p['sect'] == 'execute']
        if not ex:
            return None, ['no-execute-section'], 'unprobed'
        ip = Interp(self.sh, inline_ok, sysreg_lookup, budget=4000000)
        ip.ef = Effects()
        env = self.field_env(ent, word)
        env['InGuardedPage'] = False
        try:
            ip.phase = 'decode'
            for i, t in enumerate(dec):
                ip.run(self.parse_cached((base, ent['ci'], 'd', i), t), env)
            for i, t in enumerate(post):
                ip.run(self.parse_cached((base, 'p', i), t), env)
            ip.ef_decode_only = False
            ip.run(self.parse_cached((base, 'x', 0), ex[0]), env)
        except Undefined:
            return ip.ef, sorted(ip.notes) + ['undefined-path'], 'ok'
        except Budget:
            return ip.ef, sorted(ip.notes) + ['budget'], 'partial'
        except aslparse.AslError as e:
            return None, ['parse:' + str(e)[:60]], 'unprobed'
        except RecursionError:
            return None, ['recursion'], 'unprobed'
        except Exception as e:
            return None, ['interp:' + type(e).__name__ + ':' + str(e)[:60]], 'unprobed'
        live, dead = ip.live_reads()
        ip.ef.r = live
        # R5: a write that updates only SOME condition flags preserves the
        # rest, so in a model that folds NZCV onto one register the
        # destination is also a source.  SETF8/SETF16/RMIF are the class.
        if 0 < len(ip.flags_written) < 4:
            ip.ef.r.add(('FLAGS', None))
            ip.notes.add('partial-flag-write')
        if dead:
            ip.notes.add('dead-reads:%d' % len(dead))
        if ip.ef.unresolved:
            return ip.ef, sorted(ip.notes), 'unresolved'
        return ip.ef, sorted(ip.notes), 'ok'


# ---------------------------------------------------------------- naming
def tok(kind, idx):
    if kind == 'GPR':
        if idx == 31:
            return 'ZERO'
        if idx == 30:
            return 'LR'
        if idx == 29:
            return 'FP_REG'
        return 'GPR%d' % idx
    if kind == 'SP':
        return 'SP'
    if kind == 'VEC':
        return 'VEC%d' % idx
    if kind == 'PRED':
        return 'PRED%d' % idx
    if kind == 'ZA':
        return 'MATRIX'
    if kind == 'ZT0':
        return 'ZT0'
    if kind == 'FFR':
        return 'FFR'
    if kind == 'PC':
        return 'PC'
    if kind == 'FLAGS':
        return 'FLAGS'
    if kind == 'FCSR':
        return 'FCSR'
    if kind == 'SYS':
        # sysreg_lookup put the ROLE in idx: the thread pointer, the
        # FP/SIMD/SVE/SME enable gate and the vector configuration are
        # the roles the tracer's generic space names separately, so the
        # reference names them too rather than folding them into SYS.
        if idx in ('TLS', 'SYSFPEN', 'VCTRL', 'SSP'):
            return idx
        return 'SYS'
    if kind == 'PSTATE':
        return 'PSTATE.%s' % idx
    return '%s?%s' % (kind, idx)


def to_sets(ef):
    src = set(tok(k, i) for k, i in ef.r)
    dst = set(tok(k, i) for k, i in ef.w)
    # R7.3: the write to XZR is RECORDED.  The architecture discards the
    # value, but the regfile-dependency question is a different one -- the
    # generic space has REG_ZERO and the tracer names it, so a reference
    # that dropped it was measuring its own convention, not the tracer.
    return src, dst
