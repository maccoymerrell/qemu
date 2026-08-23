#!/usr/bin/env python3
"""Expand parsed Sail encdec clauses into concrete opcode rows."""
import json, re, os, sys, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_opcodes import (MAPS, build, Fail, split_top, split_args, repr_reg,
                         bits_val, ROOT, D, UNIONS)

# --------------------------------------------------------------- assembly db
ASM = {}
for a in D.get('assembly', []):
    t = a['text']
    m = re.match(r'^mapping clause assembly\s*=\s*(\w+)\s*(?:\((.*?)\))?\s*<->\s*(.*)$', t)
    if not m: continue
    node = m.group(1); params = split_args(m.group(2)) if m.group(2) else []
    ASM.setdefault(node, []).append((params, m.group(3).strip()))

def eval_mnemonic(node, posval):
    """posval: positional index -> symbolic value (enum arm name / number / None)"""
    for params, expr in ASM.get(node, []):
        # positional literal constants in the assembly pattern must match
        okmatch = True
        binding = {}
        for i, p in enumerate(params):
            v = posval.get(i)
            if re.match(r'^[A-Z]\w*$', p):
                if v != p: okmatch = False; break
            elif re.match(r'^[a-z_]\w*$', p):
                binding[p] = v
        if not okmatch: continue
        out = []
        for term in [x.strip() for x in expr.split('^')]:
            if term.startswith('spc()') or term == 'spc()': break
            mm = re.match(r'^"(.*)"$', term)
            if mm: out.append(mm.group(1)); continue
            mm = re.match(r'^(\w+)\s*\((.*)\)$', term)
            if mm:
                fn, arg = mm.group(1), mm.group(2).strip()
                info = MAPS.get(fn)
                if info is None or info['kind'] != 'to_str': return None
                args = [a.strip() for a in arg.split(',')]
                vs = [binding.get(a, a) for a in args]
                if any(v is None for v in vs): return None
                key = str(vs[0]) if len(vs) == 1 else '(' + ', '.join(str(v) for v in vs) + ')'
                hit = [v for k, v in info['table'] if k == key]
                if not hit: return None
                out.append(hit[0].strip('"'))
                continue
            return None
        if out: return ''.join(out)
    return None

# ------------------------------------------------------------- guard machine
def tokenize(g):
    """'&', '|', '(', ')' and atoms; ident(...) with balanced parens is ONE atom"""
    toks = []; i = 0; n = len(g); cur = ''
    while i < n:
        c = g[i]
        if c.isalnum() or c in '_':
            j = i
            while j < n and (g[j].isalnum() or g[j] in '_.'): j += 1
            word = g[i:j]
            if j < n and g[j] == '(':
                depth = 0; k = j
                while k < n:
                    if g[k] == '(': depth += 1
                    elif g[k] == ')':
                        depth -= 1
                        if depth == 0: k += 1; break
                    k += 1
                cur += g[i:k]; i = k; continue
            cur += word; i = j; continue
        if c in '&|()':
            if cur.strip(): toks.append(cur.strip())
            cur = ''
            toks.append(c); i += 1; continue
        cur += c; i += 1
    if cur.strip(): toks.append(cur.strip())
    return toks

def eval_guard(g, vals):
    if not g.strip(): return True
    toks = tokenize(g)
    pos = [0]
    def expr():
        v = term()
        while pos[0] < len(toks) and toks[pos[0]] == '|':
            pos[0] += 1; v = term() | v
        return v
    def term():
        v = fact()
        while pos[0] < len(toks) and toks[pos[0]] == '&':
            pos[0] += 1; v = fact() & v
        return v
    def fact():
        t = toks[pos[0]]
        if t == '(':
            pos[0] += 1; v = expr()
            if pos[0] < len(toks) and toks[pos[0]] == ')': pos[0] += 1
            return v
        pos[0] += 1
        return atom(t.strip())
    return expr()

def numval(v):
    try: return int(str(v))
    except Exception: return None

CUR = {}
def atom(a):
    a = a.strip()
    if a in ('', ')'): return True
    if a.startswith('not'): return True
    if re.match(r'^xlen\s*==\s*32$', a) or re.match(r'^xlen\s*<=\s*32$', a): return False
    if a == 'in32BitMode()': return False
    if re.match(r'^xlen\s*(==|>=)\s*64$', a): return True
    v = CUR
    m = re.match(r'^valid_load_encdec\((\w+),\s*(\w+)\)$', a)
    if m:
        w = numval(v.get(m.group(1))); u = v.get(m.group(2)) == 'true'
        if w is None: return True
        return (w < 8) or ((not u) and w <= 8)
    m = re.match(r'^lrsc_width_valid\((\w+)\)$', a)
    if m:
        w = numval(v.get(m.group(1)));  return True if w is None else w in (4, 8)
    m = re.match(r'^float_load_store_width_supported\((\w+)\)$', a)
    if m:
        w = numval(v.get(m.group(1)));  return True if w is None else w in (2, 4, 8)
    m = re.match(r'^amo_encoding_valid\((\w+),\s*(\w+),.*\)$', a)
    if m:
        w = numval(v.get(m.group(1))); op = v.get(m.group(2))
        if w is None: return True
        if w == 16: return op == 'AMOCAS'
        return w in (1, 2, 4, 8)
    m = re.match(r'^(\w+)\s*<=\s*xlen_bytes$', a)
    if m:
        w = numval(v.get(m.group(1)));  return True if w is None else w <= 8
    m = re.match(r'^(\w+)\s*(==|!=)\s*(0b[01_]+)$', a)
    if m:
        raw = v.get(m.group(1))
        if raw is None: return True
        lb = bits_val(str(raw)); rb = bits_val(m.group(3))
        if lb is None or rb is None: return True
        return (lb[0] == rb[0]) if m.group(2) == '==' else (lb[0] != rb[0])
    m = re.match(r'^(\w+)\s*(==|!=|<|<=|>|>=)\s*(\d+)$', a)
    if m:
        w = numval(v.get(m.group(1)))
        if w is None: return True
        n = int(m.group(3)); op = m.group(2)
        return {'==': w == n, '!=': w != n, '<': w < n, '<=': w <= n,
                '>': w > n, '>=': w >= n}[op]
    return True

def mnemonic_prefix_terms(node):
    out = []
    for params, expr in ASM.get(node, []):
        for term in [x.strip() for x in expr.split('^')]:
            if term.startswith('spc()'): break
            m = re.match(r'^(\w+)\s*\(([a-z_]\w*)\)$', term)
            if m: out.append((m.group(1), m.group(2)))
    return out

def bitkey_choices(node, var, width):
    """mnemonic-bearing bare bit field -> the finite key set it selects over"""
    for fn, arg in mnemonic_prefix_terms(node):
        if arg != var: continue
        info = MAPS.get(fn)
        if not info or info['kind'] != 'to_str': continue
        keys = [k for k, _ in info['table']]
        bvs = [bits_val(k) for k in keys]
        if all(b is not None and b[1] == width for b in bvs):
            return list(zip(keys, [b[0] for b in bvs]))
    return None

MANUAL_MNEMONIC = {
    'FENCE': 'fence', 'FENCEI': 'fence.i', 'ZCMOP': 'c.mop.n',
    'ZIMOP_MOP_R': 'mop.r.n', 'ZIMOP_MOP_RR': 'mop.rr.n',
}

# --------------------------------------------------------------- expansion
SKIP_NODES = {'ILLEGAL', 'C_ILLEGAL', 'STOP_FETCHING', 'THREAD_START'}
# enum fields that do NOT change the mnemonic or the operand set
FIX_CHOICE = {'encdec_rounding_mode': 'RM_RNE'}
FIX_BOOLVAR = {'aq': 'false', 'rl': 'false'}
# representative values forced by guards that our evaluator records as free
VAR_OVERRIDE = {
    ('SSPUSH', 'rs2'): 1, ('SSPOPCHK', 'rs1'): 1, ('C_SSPUSH', 'rs2'): 1,
    ('C_SSPOPCHK', 'rs1'): 1, ('AES64KS1I', 'rnum'): 1,
    # architecturally reserved must-be-zero fields (not operand fields)
    ('FENCE', 'fm'): 0, ('FENCE', 'pred'): 15, ('FENCE', 'succ'): 15,
    ('FENCE', 'rs'): 0, ('FENCE', 'rd'): 0,
    ('FENCEI', 'imm'): 0, ('FENCEI', 'rs'): 0, ('FENCEI', 'rd'): 0,
    # a CSR number that is not one of the F-extension aliases (fflags/frm/fcsr)
    ('CSRReg', 'csr'): 0x340, ('CSRImm', 'csr'): 0x340,
}

IMM_DEFAULT = 3   # 3, not 1: an immediate of 1 turns sltiu into the seqz alias
def imm_value(node, var, width):
    if (node, var) in VAR_OVERRIDE: return VAR_OVERRIDE[(node, var)]
    return IMM_DEFAULT if width >= 2 else 1

def expand(c):
    node = c['node']
    if node in SKIP_NODES: return []
    fields = c['fields']
    # choice fields
    choices = []
    for f in fields:
        if f['k'] != 'choice': continue
        info = MAPS[f['map']]
        var = f['var']
        # bound to a literal enum constant in the LHS?
        lit = None
        for i, p in enumerate(c['params']):
            if p == var and i in c['plit']: lit = c['plit'][i]
        if lit is not None:
            choices.append((f, [lit])); continue
        if f['map'] in FIX_CHOICE:
            choices.append((f, [FIX_CHOICE[f['map']]])); continue
        if f['map'] == 'bool_bit' and var in FIX_BOOLVAR:
            choices.append((f, [FIX_BOOLVAR[var]])); continue
        choices.append((f, [k for k, _ in info['table']]))
    # bare bit fields that select the mnemonic are opcode-bearing too
    bitkeys = []
    for f in fields:
        if f['k'] != 'free' or f.get('rk') != 'imm' or 'slice' in f: continue
        bk = bitkey_choices(node, f['var'], f['w'])
        if bk: bitkeys.append((f, bk))
    rows = []
    keys = [ch[0] for ch in choices]
    bkeys = [b[0] for b in bitkeys]
    for combo_all in itertools.product(*([ch[1] for ch in choices] +
                                         [[k for k, _ in b[1]] for b in bitkeys])):
        combo = combo_all[:len(choices)]
        bcombo = combo_all[len(choices):]
        vals = {}
        for f, val in zip(keys, combo): vals[f['var']] = val
        bitval = {}
        for f, sel in zip(bkeys, bcombo):
            vals[f['var']] = sel
            bitval[f['var']] = dict(bitkey_choices(node, f['var'], f['w']))[sel]
        # positional literals also carry enum values
        for i, p in enumerate(c['params']):
            if i in c['plit']: vals.setdefault(c['plit'][i], c['plit'][i])
        CUR.clear(); CUR.update(vals)
        if not eval_guard(c['guard'], vals): continue
        # ---- build the bit vector
        bits = []
        varvals = {}
        for f in fields:
            if f['k'] == 'lit':
                bits.append((f['v'], f['w']))
            elif f['k'] == 'choice':
                info = MAPS[f['map']]
                sel = vals[f['var']]
                hit = [b for k, b in info['table'] if k == sel]
                bv = bits_val(hit[0])
                if bv is None: raise Fail('choice bits %r' % hit)
                bits.append((bv[0], f['w']))
            else:
                rk = f.get('rk')
                if rk in ('gpr', 'fpr', 'vec', 'cgpr', 'cfpr'):
                    v = VAR_OVERRIDE.get((node, f['var']))
                    if v is None: v = repr_reg(rk, f['var'])
                elif f['var'] in bitval and 'slice' not in f:
                    v = bitval[f['var']]
                else:
                    base = varvals.get(f['var'])
                    if base is None:
                        base = imm_value(node, f['var'], f['w']); varvals[f['var']] = base
                    if 'slice' in f:
                        hi, lo = f['slice']; v = (base >> lo) & ((1 << (hi - lo + 1)) - 1)
                    else:
                        v = base
                bits.append((v & ((1 << f['w']) - 1), f['w']))
        word = 0
        for v, w in bits: word = (word << w) | v
        fieldvals = {}
        for f in fields:
            if f['k'] == 'lit': continue
            if f['k'] == 'choice': fieldvals[f['var']] = vals[f['var']]; continue
            rk = f.get('rk')
            if rk in ('gpr', 'fpr', 'vec', 'cgpr', 'cfpr'):
                v = VAR_OVERRIDE.get((node, f['var']))
                if v is None: v = repr_reg(rk, f['var'])
                fieldvals[f['var']] = v
            elif f['var'] in bitval and 'slice' not in f:
                fieldvals[f['var']] = bitval[f['var']]
            else:
                fieldvals[f['var']] = varvals.get(f['var'], imm_value(node, f['var'], f['w']))
        # positional symbolic values for mnemonic evaluation
        posval = {}
        for i, p in enumerate(c['params']):
            if i in c['plit']: posval[i] = c['plit'][i]
            else:
                nm = re.match(r'^([a-z_]\w*)', p)
                posval[i] = vals.get(nm.group(1)) if nm else None
        mn = eval_mnemonic(node, posval) or MANUAL_MNEMONIC.get(node)
        rows.append({'node': node,
                     'combo': dict(zip([f['var'] for f in keys] +
                                       [f['var'] for f in bkeys], combo_all)),
                     'word': word, 'bytes': c['total'] // 8, 'mnemonic': mn,
                     'file': c['file'], 'guard': c['guard'], 'text': c['text'],
                     'fieldvals': fieldvals, 'params': c['params'], 'plit': c['plit']})
    return rows

if __name__ == '__main__':
    clauses = json.load(open(os.path.join(ROOT, 'clauses.json')))
    for c in clauses: c['plit'] = {int(k): v for k, v in c['plit'].items()}
    allrows = []; nomn = 0
    for c in clauses:
        if 'xlen == 32' in [x.strip() for x in re.split(r'&', c['guard'])]: continue
        try:
            rs = expand(c)
        except Fail as e:
            print('EXPAND FAIL', c['node'], e); continue
        allrows += rs
    for r in allrows:
        if not r['mnemonic']: nomn += 1
    print('rows', len(allrows), 'without sail mnemonic', nomn)
    json.dump(allrows, open(os.path.join(ROOT, 'attrib', 'rows_vals.json'), 'w'), indent=1)
    import collections
    c = collections.Counter(r['node'] for r in allrows if not r['mnemonic'])
    for k, v in c.most_common(25): print('  nomn', k, v)
