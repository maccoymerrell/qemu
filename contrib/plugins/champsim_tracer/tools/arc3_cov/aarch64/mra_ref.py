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


def sysreg_lookup(name=None, enc=None):
    if name is not None:
        u = name.upper()
        if u in SYSREG_NAMES or re.match(r'^[A-Z][A-Z0-9]*_EL[0-3]', u):
            return 'TLS' if u in TLS_REGS else 'SYS'
        return None
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
    'CheckSVEEnabled', 'CheckStreamingSVEEnabled', 'CheckNonStreamingSVEEnabled',
    'CheckStreamingSVEAndZAEnabled', 'CheckOriginalSVEEnabled', 'CheckSMEEnabled',
    'CheckSMEAndZAEnabled', 'CheckSMEZT0Enabled', 'CheckSMEAccess',
    'AArch64.CheckFPAdvSIMDEnabled64', 'AArch64.CheckFPEnabled64',
    'CheckFPAdvSIMDEnabled64', 'CheckFPEnabled64',
    'AArch64.CheckFPAdvSIMDEnabled', 'AArch64.CheckFPEnabled',
    'AArch64.CheckFPAdvSIMDTrap', 'CheckMOPSEnabled', 'CheckLDST64BEnabled',
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
    if kind == 'FFR':
        return 'FFR'
    if kind == 'PC':
        return 'PC'
    if kind == 'FLAGS':
        return 'FLAGS'
    if kind == 'FCSR':
        return 'FCSR'
    if kind == 'SYS':
        return 'TLS' if idx == 'TLS' else 'SYS'
    if kind == 'PSTATE':
        return 'PSTATE.%s' % idx
    return '%s?%s' % (kind, idx)


def to_sets(ef):
    src = set(tok(k, i) for k, i in ef.r)
    dst = set(tok(k, i) for k, i in ef.w)
    # a write to XZR is architecturally discarded
    dst.discard('ZERO')
    return src, dst
