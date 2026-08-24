#!/usr/bin/env python3
"""Interprocedural register-effect extraction from the Sail-RISCV model.

For every `function clause execute NODE(...)` this computes the set of
architectural register reads and writes the instruction performs.  The scan is
value-aware: parameters whose value is fixed by the encoding (enum arms, widths,
register numbers) are propagated so that `match`/`if` arms that cannot be taken
are pruned rather than unioned.  Without that pruning the reference would
over-approximate (e.g. every AMO would appear to touch a register pair).
"""
import re, os, sys, json, collections

# ---------------------------------------------------------------- lexing
def strip_comments(s):
    out = []; i = 0; n = len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n:
                if s[j] == '\\': j += 2; continue
                if s[j] == '"': j += 1; break
                j += 1
            out.append(s[i:j]); i = j; continue
        if s.startswith('//', i):
            j = s.find('\n', i)
            if j < 0: j = n
            out.append(' ' * (j - i)); i = j; continue
        if s.startswith('/*', i):
            j = s.find('*/', i)
            j = n if j < 0 else j + 2
            out.append(re.sub(r'[^\n]', ' ', s[i:j])); i = j; continue
        out.append(c); i += 1
    return ''.join(out)

TOPKW = re.compile(r'^(private\s+function|scattered\s+function|function|val|register|'
                   r'mapping|union|enum|struct|type|let|var|overload|bitfield|infix|'
                   r'infixl|infixr|default|scattered|end|instantiation|outcome|impl|'
                   r'import|\$\w+)\b')

def chunks(text):
    lines = text.split('\n')
    starts = [i for i, L in enumerate(lines) if TOPKW.match(L)]
    out = []
    for k, i in enumerate(starts):
        j = starts[k + 1] if k + 1 < len(starts) else len(lines)
        out.append('\n'.join(lines[i:j]))
    return out

def split_top(s, seps=','):
    parts = []; depth = 0; cur = ''; i = 0; n = len(s)
    while i < n:
        ch = s[i]
        if ch == '"':
            j = i + 1
            while j < n:
                if s[j] == '\\': j += 2; continue
                if s[j] == '"': j += 1; break
                j += 1
            cur += s[i:j]; i = j; continue
        if ch in '([{': depth += 1
        elif ch in ')]}': depth -= 1
        if ch in seps and depth == 0:
            parts.append(cur); cur = ''; i += 1; continue
        cur += ch; i += 1
    parts.append(cur)
    return parts

def split_args(s):
    return [p.strip() for p in split_top(s)] if s.strip() else []

def match_bracket(s, i):
    """s[i] is one of ([{ ; return index just past the matching close"""
    open_c = s[i]; close_c = {'(': ')', '[': ']', '{': '}'}[open_c]
    depth = 0; n = len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n:
                if s[j] == '\\': j += 2; continue
                if s[j] == '"': j += 1; break
                j += 1
            i = j; continue
        if c in '([{': depth += 1
        elif c in ')]}':
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    return -1

def skip_ws(s, i):
    while i < len(s) and s[i] in ' \t\n\r': i += 1
    return i

# ------------------------------------------------------------ model load
class Model:
    def __init__(self, root):
        self.root = root
        self.registers = set()
        self.overloads = collections.defaultdict(list)
        self.funcs = {}              # name -> (params, body)
        self.func_file = {}
        self.exec_clauses = {}       # node -> (params, body, file)  [best arm]
        self.exec_arms = collections.defaultdict(list)  # node -> [(raw, names, body)]
        self.letconst = {}
        self.files = []
        self._load()

    def _load(self):
        for dirpath, _, names in os.walk(os.path.join(self.root, 'model')):
            for nm in sorted(names):
                if not nm.endswith('.sail'): continue
                p = os.path.join(dirpath, nm)
                self.files.append(p)
                self._scan(strip_comments(open(p, errors='replace').read()), p)

    def _scan(self, text, path):
        for ch in chunks(text):
            m = re.match(r'^register\s+(\w+)\s*:', ch)
            if m: self.registers.add(m.group(1)); continue
            m = re.match(r'^overload\s+([\w\s]+?)\s*=\s*\{(.*?)\}', ch, re.S)
            if m:
                nm = m.group(1).strip()
                if re.match(r'^\w+$', nm):
                    self.overloads[nm] += [x.strip() for x in m.group(2).split(',') if x.strip()]
                continue
            m = re.match(r'^let\s+(\w+)\s*:\s*(?:c?[xfv]?regidx|regidx|cregidx|fregidx|'
                         r'vregidx|regno)\s*=(.*)', ch, re.S)
            if m:
                lit = re.search(r'0b([01_]+)|0x([0-9a-fA-F_]+)|\b(\d+)\b', m.group(2))
                if lit:
                    v = (int(lit.group(1).replace('_', ''), 2) if lit.group(1) else
                         int(lit.group(2).replace('_', ''), 16) if lit.group(2) else
                         int(lit.group(3)))
                    self.letconst[m.group(1)] = v
                continue
            mm = re.match(r'^(?:private\s+)?function\b', ch)
            if not mm: continue
            self._func(ch[mm.end():], path)

    def _func(self, rest, path):
        r = rest.lstrip()
        isclause = False
        if r.startswith('clause'):
            isclause = True; r = r[len('clause'):].lstrip()
        m2 = re.match(r'^(\w+)', r)
        if not m2: return
        name = m2.group(1); r = r[m2.end():].lstrip()
        if isclause and name == 'execute':
            paren = r.startswith('(')
            if paren: r = r[1:].lstrip()
            m3 = re.match(r'^(\w+)', r)
            if not m3: return
            node = m3.group(1); r = r[m3.end():].lstrip()
            if r.startswith('('):
                e = match_bracket(r, 0); params = split_args(r[1:e - 1]); r = r[e:]
            else:
                params = []
            r = r.lstrip()
            if paren and r.startswith(')'): r = r[1:]
            body = self._after_eq(r)
            self.exec_arms[node].append((params, self._pnames(params), body))
            if node not in self.exec_clauses:
                self.exec_clauses[node] = (self._pnames(params), body, path)
            return
        if isclause: return
        if r.startswith('('):
            e = match_bracket(r, 0); params = split_args(r[1:e - 1]); r = r[e:]
        else:
            params = []
        body = self._after_eq(r)
        if name not in self.funcs:
            self.funcs[name] = (self._pnames(params), body)
            self.func_file[name] = path

    @staticmethod
    def _after_eq(r):
        depth = 0; k = 0
        while k < len(r):
            c = r[k]
            if c in '([{': depth += 1
            elif c in ')]}': depth -= 1
            elif c == '=' and depth == 0 and r[k:k + 2] != '==' and \
                 (k == 0 or r[k - 1] not in '=<>!+-*/&|^'):
                return r[k + 1:]
            k += 1
        return ''

    @staticmethod
    def _pnames(params):
        out = []
        for p in params:
            p = p.strip()
            m = re.match(r'^(?:\w+\s*\(\s*)?([a-zA-Z_]\w*)', p)
            out.append(m.group(1) if m else '_')
        return out

# ------------------------------------------------------------- effects
# effect = (role, cls, key)     role 'R'/'W'
#   cls 'GPR'/'FPR'/'VEC' -> key is an int register number or None (unknown)
#   cls 'CSR'             -> key is the Sail register name
LEAF = {
    'rX': ('R', 'GPR', 0, 0), 'wX': ('W', 'GPR', 0, 0),
    'rX_bits': ('R', 'GPR', 0, 0), 'wX_bits': ('W', 'GPR', 0, 0),
    'rX_pair_bits': ('R', 'GPRPAIR', 0, 0), 'wX_pair_bits': ('W', 'GPRPAIR', 0, 0),
    'rF': ('R', 'FPR', 0, 0), 'wF': ('W', 'FPR', 0, 0),
    'rF_bits': ('R', 'FPR', 0, 0), 'wF_bits': ('W', 'FPR', 0, 0),
    'rF_BF16': ('R', 'FPR', 0, 0), 'wF_BF16': ('W', 'FPR', 0, 0),
    'rF_H': ('R', 'FPR', 0, 0), 'wF_H': ('W', 'FPR', 0, 0),
    'rF_S': ('R', 'FPR', 0, 0), 'wF_S': ('W', 'FPR', 0, 0),
    'rF_D': ('R', 'FPR', 0, 0), 'wF_D': ('W', 'FPR', 0, 0),
    'rF_or_X_H': ('R', 'FPR', 0, 0), 'wF_or_X_H': ('W', 'FPR', 0, 0),
    'rF_or_X_S': ('R', 'FPR', 0, 0), 'wF_or_X_S': ('W', 'FPR', 0, 0),
    'rF_or_X_D': ('R', 'FPR', 0, 0), 'wF_or_X_D': ('W', 'FPR', 0, 0),
    'rV': ('R', 'VEC', 0, 0), 'wV': ('W', 'VEC', 0, 0),
    'rV_bits': ('R', 'VEC', 0, 0), 'wV_bits': ('W', 'VEC', 0, 0),
    'read_vreg': ('R', 'VEC', 3, 2), 'write_vreg': ('W', 'VEC', 3, 2),
    'read_single_element': ('R', 'VEC', 2, None),
    'write_single_element': ('W', 'VEC', 2, None),
    # read_vreg_seg is a GROUP read: its body is
    #   `foreach (j from 0 to (nf - 1)) { vreg_list[j] =
    #      read_vreg(.., vregidx_offset(vrid, j * LMUL_reg)) }`
    # (model/extensions/V/vext_utils_insts.sail:571-573), so a segment
    # load reads all nf fields of the destination group, not just the
    # base.  Reported as a group key so expand_group() widens it by nf,
    # exactly as the write side is widened by the vregidx_offset the
    # write_single_element calls carry.
    'read_vreg_seg': ('R', 'VEC', 4, 'grp'),
    'write_vmask': ('W', 'VEC', 1, None),
    # scattered CSR dispatch: 254 `function clause read_CSR/write_CSR` arms
    # keyed by CSR number; the number itself is the register identity.
    'read_CSR': ('R', 'CSRNUM', 0, None), 'write_CSR': ('W', 'CSRNUM', 0, None),
}
# vector mask reads are suppressed when vm == 1 (unmasked encoding)
MASKED = {'read_vmask': (1, 2), 'read_vmask_carry': (1, 2)}

# Trap / platform / memory-system machinery.  An instruction's architectural
# register footprint is its effect on the visible register file; the CSR
# traffic of address translation, PMP, the platform devices and the trap
# handler is memory-system and exception state, not an operand of the
# instruction.  Enumerated here rather than filtered downstream so the
# exclusion is auditable.
BLACKLIST = {
    # trap / exception
    'handle_exception', 'handle_mem_exception', 'handle_interrupt', 'trap',
    'exception_handler', 'trap_handler', 'exception_delegatee', 'memory_exception',
    'prepare_trap_vector', 'handle_trap_extension', 'handle_illegal',
    'handle_illegal_vtype', 'Illegal_Instruction', 'internal_error',
    # address translation / PMP / physical memory / platform devices
    'vmem_read_addr', 'vmem_write_addr', 'mem_read', 'mem_write_value',
    'mem_write_ea', 'translateAddr', 'translate_addr', 'pmpCheck',
    'phys_mem_read', 'phys_mem_write', 'checked_mem_read', 'checked_mem_write',
    'transform_effective_address', 'transform_hlsv_address',
    'is_aligned_addr', 'plat_misaligned_exception',
    'within_phys_mem', 'pmpCheckPerms', 'pmpAddrMatch', 'pmpMatchAddr',
    'legalize_pmpcfg', 'pmpWriteCfgReg', 'pmpWriteAddrReg',
    # extension dirty-state bookkeeping (mstatus.FS/VS/SD, vsstatus.FS/VS/SD)
    'dirty_fd_context', 'dirty_fd_context_if_present', 'dirty_v_context',
    # diagnostics / init / harness
    'assert', 'print', 'print_endline', 'print_reg', 'print_mem_access',
    'print_platform', 'print_dbg', 'print_insn', 'dec_str', 'hex_str', 'bits_str',
    'not_implemented', 'reset_sys', 'init_sys', 'init_vregs', 'init_regs',
    'init_base_regs', 'init_fdext_regs', 'csr_name_map', 'csr_write_callback',
    'long_csr_write_callback', 'csr_id_write_callback', 'sail_barrier',
    'cancel_reservation', 'match_reservation', 'load_reservation',
    'ext_check_xret_priv', 'ext_fail_xret_priv', 'rvfi_write', 'rvfi_read',
    # CSR access-permission checking: Zicsr defines the read/write footprint
    # by the (op, rd, rs1) table above; the privilege/stateen gate is access
    # control, not an operand of the instruction.
    'check_CSR_result', 'check_CSR', 'ext_check_CSR', 'csr_read_callback',
    'is_CSR_defined', 'csr_priv_ok', 'check_Counteren', 'check_TVM_SATP',
    'check_seed_CSR', 'virtual_instruction_exception',
}

# Calls that ARE the enumerated scope exclusion, argument list included.
#
# BLACKLIST silences a call's BODY; it does not silence the expressions the
# call is handed, and for these three the address-translation state arrives as
# an ARGUMENT.  `effectivePrivilege(access, mstatus, cur_privilege)` puts the
# bare register name in the argument list, so `prefetch.i` -- an instruction
# every arm of whose translation is a no-op, which therefore cannot trap and
# whose result does not depend on any CSR -- reported a REG_SYS source that
# came entirely from translating its own operand.  `phys_access_check` reads
# `pma_regions` in its body and is reached the same way.
#
# THE LINE, and it is the same one the tracer draws at the decode boundary: a
# CSR the instruction's OWN semantics consult -- including the gate that
# decides whether it traps -- is a source; a CSR consulted only by the
# translation or physical-memory check of its memory operand is excluded, on
# both sides.  `sfence.vma` reads mstatus.TVM in its clause head and keeps it;
# `prefetch.i` reads mstatus only here and loses it.
#
# This cannot silence a legality gate by accident: `feature_enabled_for_priv`,
# which is how the Zicbom/Zicboz and Zicfiss enable bits are read, is a
# separate call and is not listed.
SKIP_XLATE_ARGS = {
    'effectivePrivilege', 'phys_access_check', 'pmaMatch',
}

# calls whose arguments are pure reporting and must not be scanned as reads
SKIP_WHOLE = {
    'csr_write_callback', 'long_csr_write_callback', 'csr_read_callback',
    'csr_id_write_callback', 'print', 'print_endline', 'print_reg',
    'print_mem_access', 'print_platform', 'print_dbg', 'print_insn',
    'dec_str', 'hex_str', 'bits_str', 'assert', 'rvfi_write', 'rvfi_read',
    'sail_barrier',
}

NON_ARCH_REGS = {
    'PC', 'nextPC', 'instbits', 'cur_privilege', 'cur_inst',
    'htif_tohost', 'htif_fromhost', 'htif_done', 'htif_exit_code',
    'htif_cmd_write', 'htif_payload_writes', 'tlb',
    'float_result', 'float_fflags', 'fp_eq_flag', 'fp_lt_flag',
    'reservation', 'reservation_valid',
}
REGFILE_CELL = re.compile(r'^(x|f|vr)\d+$')

BUILTIN_CONST = {'xlen': 64, 'xlen_bytes': 8, 'flen': 64, 'zreg': 0, 'zvreg': 0,
                 'log2_xlen': 6, 'xlen_max_unsigned': None}

# ----------------------------------------------------------- value pruning
def prune(body, env):
    """Textually remove `match`/`if` branches that the fixed operand values of
    this encoding cannot reach.  `env` maps identifier -> concrete value."""
    for _ in range(6):
        nb = _prune_match(body, env)
        nb = _prune_if(nb, env)
        if nb == body: return body
        body = nb
    return body

def _lookup(env, tok):
    tok = tok.strip()
    if tok in env:
        v = env[tok]
        return v if isinstance(v, (int, str)) else None
    if tok in BUILTIN_CONST: return BUILTIN_CONST[tok]
    m = re.match(r'^0b([01_]+)$', tok)
    if m: return int(m.group(1).replace('_', ''), 2)
    m = re.match(r'^0x([0-9a-fA-F_]+)$', tok)
    if m: return int(m.group(1).replace('_', ''), 16)
    m = re.match(r'^-?\d+$', tok)
    if m: return int(tok)
    m = re.match(r'^zeros\(\)$', tok)
    if m: return 0
    if re.match(r'^[A-Z][A-Za-z0-9_]*$', tok): return tok
    return None

def _eval_cond(cond, env):
    """return True/False if the condition is decidable, else None"""
    cond = cond.strip()
    while cond.startswith('(') and match_bracket(cond, 0) == len(cond):
        cond = cond[1:-1].strip()
    parts = split_top(cond, '&')
    if len(parts) > 1:
        vs = [_eval_cond(p, env) for p in parts]
        if any(v is False for v in vs): return False
        if all(v is True for v in vs): return True
        return None
    parts = split_top(cond, '|')
    if len(parts) > 1:
        vs = [_eval_cond(p, env) for p in parts]
        if any(v is True for v in vs): return True
        if all(v is False for v in vs): return False
        return None
    m = re.match(r'^not\s*\((.*)\)$', cond, re.S)
    if m:
        v = _eval_cond(m.group(1), env)
        return None if v is None else (not v)
    m = re.match(r'^(.+?)\s*(==|!=|<=|>=|<_s|<_u|>_s|>_u|<|>)\s*(.+)$', cond, re.S)
    if not m: return None
    a = _lookup(env, m.group(1)); b = _lookup(env, m.group(3)); op = m.group(2)
    if a is None or b is None: return None
    if op == '==': return a == b
    if op == '!=': return a != b
    if isinstance(a, str) or isinstance(b, str): return None
    return {'<=': a <= b, '>=': a >= b, '<': a < b, '>': a > b,
            '<_s': a < b, '<_u': a < b, '>_s': a > b, '>_u': a > b}[op]

def _pat_matches(pat, val):
    pat = pat.strip()
    if pat in ('_', '()'): return True
    if val is None: return None
    lv = _lookup({}, pat)
    if lv is None: return None
    return lv == val

def _prune_match(s, env):
    out = []; i = 0; n = len(s)
    while i < n:
        m = re.compile(r'\bmatch\b').search(s, i)
        if not m: out.append(s[i:]); break
        out.append(s[i:m.start()])
        j = skip_ws(s, m.end())
        k = j
        while k < n and (s[k].isalnum() or s[k] == '_'): k += 1
        scrut = s[j:k]
        k2 = skip_ws(s, k)
        if not scrut or k2 >= n or s[k2] != '{':
            out.append(s[m.start():m.end()]); i = m.end(); continue
        val = _lookup(env, scrut)
        e = match_bracket(s, k2)
        if e < 0 or val is None or isinstance(val, str) and scrut not in env:
            out.append(s[m.start():m.end()]); i = m.end(); continue
        arms = split_top(s[k2 + 1:e - 1])
        kept = None; undecided = False
        for arm in arms:
            if '=>' not in arm: continue
            pat, rhs = arm.split('=>', 1)
            r = _pat_matches(pat, val)
            if r is None: undecided = True; break
            if r: kept = rhs; break
        if undecided or kept is None:
            out.append(s[m.start():m.end()]); i = m.end(); continue
        out.append(' ( ' + kept + ' ) ')
        i = e
    return ''.join(out)

def _branch_extent(s, i):
    """extent of a `then`/`else` branch starting at i"""
    i = skip_ws(s, i)
    if i >= len(s): return i, i
    if s[i] in '({':
        e = match_bracket(s, i)
        return i, (e if e > 0 else len(s))
    depth = 0; j = i; n = len(s)
    while j < n:
        c = s[j]
        if c == '"':
            k = j + 1
            while k < n:
                if s[k] == '\\': k += 2; continue
                if s[k] == '"': k += 1; break
                k += 1
            j = k; continue
        if c in '([{': depth += 1
        elif c in ')]}':
            if depth == 0: break
            depth -= 1
        elif depth == 0:
            if c in ';,': break
            if re.match(r'\belse\b', s[j:]): break
        j += 1
    return i, j

def _prune_if(s, env):
    out = []; i = 0; n = len(s)
    while i < n:
        m = re.compile(r'\bif\b').search(s, i)
        if not m: out.append(s[i:]); break
        out.append(s[i:m.start()])
        j = skip_ws(s, m.end())
        # condition runs to the matching `then`
        depth = 0; k = j
        while k < n:
            c = s[k]
            if c in '([{': depth += 1
            elif c in ')]}': depth -= 1
            elif depth == 0 and re.match(r'\bthen\b', s[k:]): break
            k += 1
        if k >= n:
            out.append(s[m.start():m.end()]); i = m.end(); continue
        cond = s[j:k]
        v = _eval_cond(cond, env)
        if v is None:
            out.append(s[m.start():m.end()]); i = m.end(); continue
        ts, te = _branch_extent(s, k + 4)
        p = skip_ws(s, te)
        has_else = bool(re.match(r'\belse\b', s[p:]))
        if has_else:
            es, ee = _branch_extent(s, p + 4)
        else:
            es = ee = te
        keep = s[ts:te] if v else (s[es:ee] if has_else else ' () ')
        out.append(' ( ' + keep + ' ) ')
        i = ee if has_else else te
    return ''.join(out)

# ---------------------------------------------------------------- analyzer
class Analyzer:
    def __init__(self, model):
        self.m = model
        self.reg_names = {r for r in model.registers
                          if r not in NON_ARCH_REGS and not REGFILE_CELL.match(r)}
        self.cache = {}
        self.unresolved = collections.Counter()
        self.depth_hits = collections.Counter()

    # ---- resolve an argument expression to a concrete value, if possible
    def val(self, expr, env):
        e = expr.strip()
        while e.startswith('(') and match_bracket(e, 0) == len(e): e = e[1:-1].strip()
        m = re.match(r'^\w+\s*\(\s*(.*?)\s*\)$', e, re.S)
        mo = re.match(r'^vregidx_offset\s*\((.*)\)$', e, re.S)
        if mo:
            sub = split_args(mo.group(1))
            if len(sub) == 2:
                b = self.val(sub[0], env); o = self.val(sub[1], env)
                if isinstance(b, tuple): b = b[1]
                if b is None: return None
                if isinstance(o, int): return b + o
                return ('grp', b)            # group base; size known to the caller
        if m and re.match(r'^(creg2reg_idx|cregidx_to_regidx|creg2reg|'
                          r'cregidx_to_fregidx|cfregidx_to_fregidx|cfreg2freg_idx)\b', e):
            v = self.val(m.group(1), env)
            return None if v is None else 8 + v
        if m and re.match(r'^(Regidx|Regno|Fregidx|Fregno|Vregidx|Vregno|Cregidx|'
                          r'vregidx_bits|unsigned|bits_of|trunc|sign_extend|'
                          r'zero_extend|to_bits|not_implemented)\b', e):
            return self.val(m.group(1), env)
        # a register-group base: `vrid + reg_in_group`
        head = split_top(e, '+')[0].strip()
        if head != e: return self.val(head, env)
        if e in env and isinstance(env[e], tuple): return env[e]
        v = _lookup(env, e)
        if v is None and e in self.m.letconst: v = self.m.letconst[e]
        return v

    def apply_lets(self, body, env):
        """sequentially fold `let`/`var` bindings whose value is computable, and
        DROP any binding that shadows a known name with an unknown value"""
        env = dict(env)
        for m in re.finditer(r'\b(?:let|var)\s+\'?([a-zA-Z_]\w*)\s*(?::[^=;]*)?=', body):
            nm = m.group(1)
            rest = body[m.end():]
            expr = split_top(rest, ';')[0]
            v = self.val(expr, env)
            if v is None: env.pop(nm, None)
            else: env[nm] = v
        return env

    def scan(self, params, body, env, depth):
        eff = set()
        env = self.apply_lets(body, env)
        s = prune(body, env)
        i = 0; n = len(s)
        while i < n:
            c = s[i]
            if c == '"':
                j = i + 1
                while j < n:
                    if s[j] == '\\': j += 2; continue
                    if s[j] == '"': j += 1; break
                    j += 1
                i = j; continue
            if not (c.isalpha() or c == '_'):
                i += 1; continue
            if i > 0 and (s[i - 1].isalnum() or s[i - 1] in '_.'):
                i += 1; continue
            j = i
            while j < n and (s[j].isalnum() or s[j] == '_'): j += 1
            word = s[i:j]
            k = skip_ws(s, j)
            if k < n and s[k] == '(':
                e = match_bracket(s, k)
                if e < 0: i = j; continue
                args = split_args(s[k + 1:e - 1])
                t = skip_ws(s, e)
                if t < n and s[t] == '[':
                    t2 = match_bracket(s, t)
                    if t2 > 0: t = skip_ws(s, t2)
                iswrite = (t < n and s[t] == '=' and s[t:t + 2] != '==' and
                           (t == 0 or s[t - 1] not in '=<>!'))
                if word in SKIP_WHOLE or word in SKIP_XLATE_ARGS:
                    i = e; continue
                eff |= self.call(word, args, env, iswrite, depth)
                i = j; continue
            if word in self.reg_names:
                t = k
                rmw = False
                if t < n and s[t] == '[':
                    t2 = match_bracket(s, t)
                    if t2 > 0: t = skip_ws(s, t2); rmw = True
                if t < n and s[t] == '=' and s[t:t + 2] != '==':
                    eff.add(('W', 'CSR', word))
                    if rmw: eff.add(('R', 'CSR', word))
                else:
                    eff.add(('R', 'CSR', word))
                i = j; continue
            i = j
        return eff

    def call(self, name, args, env, iswrite, depth):
        if name in ('ExecuteAs', 'execute') and len(args) == 1:
            a = args[0].strip()
            mm = re.match(r'^(\w+)\s*\((.*)\)$', a, re.S)
            if mm and mm.group(1) in self.m.exec_clauses:
                node = mm.group(1); sub = split_args(mm.group(2))
                ps, body, _ = self.m.exec_clauses[node]
                se = {}
                for i, pn in enumerate(ps):
                    if i < len(sub):
                        v = self.val(sub[i], env)
                        if v is None:
                            t = sub[i].strip()
                            if re.match(r'^[A-Z]\w*$', t): v = t
                        if isinstance(v, (int, str)): se[pn] = v
                if depth > 8: return set()
                return self.scan(ps, body, se, depth + 1)
            mm2 = re.match(r'^(\w+)$', a)
            if mm2 and mm2.group(1) in self.m.exec_clauses:
                ps, body, _ = self.m.exec_clauses[mm2.group(1)]
                if depth > 8: return set()
                return self.scan(ps, body, {}, depth + 1)
            return set()
        if name in self.m.overloads:
            mem = self.m.overloads[name]
            pick = [x for x in mem if x.startswith('w')] if iswrite else \
                   [x for x in mem if x.startswith('r')]
            if not pick: pick = mem
            out = set()
            for p in pick: out |= self.call(p, args, env, False, depth)
            return out
        if name in MASKED:
            vmi, ri = MASKED[name]
            if vmi < len(args):
                vm = self.val(args[vmi], env)
                if vm == 1: return set()
            if ri < len(args):
                return {('R', 'VEC', self.val(args[ri], env))}
            return set()
        if name in LEAF:
            role, cls, ai, grp = LEAF[name]
            if ai >= len(args): return set()
            v = self.val(args[ai], env)
            if grp == 'grp' and isinstance(v, int):
                return {(role, cls, ('grp', v))}
            if cls == 'CSRNUM':
                return {(role, 'CSRNUM', v)}
            if cls == 'GPRPAIR':
                if v is None: return {(role, 'GPR', None)}
                return {(role, 'GPR', v), (role, 'GPR', v + 1)}
            return {(role, cls, v)}
        if name in BLACKLIST: return set()
        if name in ('if', 'match', 'foreach', 'while', 'return', 'let', 'var',
                    'then', 'else', 'in', 'and', 'or', 'not', 'sizeof', 'struct'):
            return set()
        if name not in self.m.funcs: return set()
        if depth > 20:
            self.depth_hits[name] += 1
            return set()
        params, body = self.m.funcs[name]
        sub_env = {}
        for idx, p in enumerate(params):
            if idx < len(args):
                v = self.val(args[idx], env)
                if isinstance(v, (int, str)): sub_env[p] = v
        key = (name, tuple(sorted(sub_env.items(), key=str)))
        if key in self.cache: return self.cache[key]
        self.cache[key] = set()
        r = self.scan(params, body, sub_env, depth + 1)
        self.cache[key] = r
        return r

    def pick_arm(self, node, posval):
        """20 nodes carry several `function clause execute` arms distinguished by
        an enum literal in the pattern; select the arm this encoding selects."""
        arms = self.m.exec_arms[node]
        best = None; best_score = -1
        for raw, names, body in arms:
            score = 0; ok = True
            for i, p in enumerate(raw):
                p = p.strip()
                if re.match(r'^[A-Z]\w*$', p):
                    if i >= len(posval) or posval[i] != p: ok = False; break
                    score += 1
            if ok and score > best_score:
                best = (names, body); best_score = score
        if best is None:
            names, body, _ = self.m.exec_clauses[node]
            return names, body
        return best

    def exec_summary(self, node, env, posval=None):
        if posval is not None:
            params, body = self.pick_arm(node, posval)
        else:
            params, body, _ = self.m.exec_clauses[node]
        return self.scan(params, body, env, 0)
