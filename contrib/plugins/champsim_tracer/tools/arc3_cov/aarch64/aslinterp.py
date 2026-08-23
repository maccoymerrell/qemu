"""Partial-evaluating ASL interpreter for A64 register attribution.

Given an encoding's concrete field bits, the decode ASL is evaluated
exactly; the execute ASL is then evaluated with register and memory
contents held UNKNOWN.  A branch on an unknown condition executes BOTH
arms and unions their effects, which is exactly ruling R5: a conditional
form names every candidate operand and an inert write is still a write.
"""
import re
import aslparse

class Undefined(Exception):
    pass

class Budget(Exception):
    pass

class Unresolved(Exception):
    """A register index that could not be resolved to a number."""

class ReturnSig(Exception):
    def __init__(self, val):
        self.val = val


class Unk:
    _inst = None
    def __new__(cls):
        if cls._inst is None:
            cls._inst = super().__new__(cls)
        return cls._inst
    def __repr__(self):
        return 'UNK'

UNK = Unk()


class Bits:
    __slots__ = ('w', 'v')
    def __init__(self, w, v):
        self.w = w
        self.v = None if v is None else (v & ((1 << w) - 1) if w > 0 else 0)
    def __repr__(self):
        return 'Bits(%s,%s)' % (self.w, self.v)
    def __eq__(self, o):
        return isinstance(o, Bits) and o.w == self.w and o.v == self.v
    def __hash__(self):
        return hash((self.w, self.v))


class Enum:
    __slots__ = ('name',)
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return 'Enum(%s)' % self.name
    def __eq__(self, o):
        return isinstance(o, Enum) and o.name == self.name
    def __hash__(self):
        return hash(self.name)


class Rec:
    """An ASL structure value; fields resolve lazily to UNK."""
    __slots__ = ('f',)
    def __init__(self):
        self.f = {}


# --------------------------------------------------------------- effects
# kind: GPR SP VEC PRED PC FFR ZA SYS FCSR FLAGS PSTATE MEM
class Effects:
    def __init__(self):
        self.r = set()
        self.w = set()
        self.unresolved = set()
        self.mem_r = 0
        self.mem_w = 0
        self.reads = {}          # read_id -> (kind, idx)
        self._next = 0
    def add(self, rw, kind, idx=None):
        if rw == 'r':
            self.r.add((kind, idx))
            self._next += 1
            self.reads[self._next] = (kind, idx)
            return self._next
        self.w.add((kind, idx))
        return None


CONSTS = {
    'TRUE': True, 'FALSE': False,
    'EL0': Bits(2, 0), 'EL1': Bits(2, 1), 'EL2': Bits(2, 2), 'EL3': Bits(2, 3),
    'M32_User': Bits(5, 0x10), 'HIGH_VA': UNK,
    # The vector length is a runtime property, not an encoding field.  It is
    # pinned to the architectural minimum so element loops have a concrete
    # trip count; no register INDEX in the A64 pseudocode depends on it.
    'CurrentVL': 512, 'CurrentSVL': 512,
}

# PSTATE fields that are the condition flags
NZCV = {'N', 'Z', 'C', 'V'}

REG_ACCESSORS = {
    'X': 'GPR', 'SP': 'SP', 'V': 'VEC', 'Vpart': 'VEC', 'Z': 'VEC', 'P': 'PRED',
    'PC': 'PC', 'FFR': 'FFR', 'ElemFFR': 'FFR', 'ZAvector': 'ZA', 'ZAtile': 'ZA',
    'ZAslice': 'ZA', 'ZAhslice': 'ZA', 'ZAvslice': 'ZA', 'ZT0': 'ZA',
    'D': 'VEC', 'S': 'VEC', 'H': 'VEC', 'B': 'VEC', 'Q': 'VEC',
    '_R': 'GPR', '_Z': 'VEC', '_P': 'PRED',
}
# accessors whose FIRST argument is the register number
IDX_ARG = {'X': 0, 'V': 0, 'Vpart': 0, 'Z': 0, 'P': 0, 'ZAvector': 0, 'ZAtile': 0,
           'ZAslice': 0, 'ZAhslice': 0, 'ZAvslice': 0, 'D': 0, 'S': 0, 'H': 0,
           'B': 0, 'Q': 0, '_R': 0, '_Z': 0, '_P': 0}

MEM_ACCESSORS = {'Mem', 'MemNF', 'MemAtomic', 'MemAtomicRCW', 'MemLoad64B',
                 'MemStore64B', 'MemStore64BWithRet', 'MemSingle', 'AArch64.MemSingle'}

SYSREG_RE = re.compile(r'^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$')


class Interp:
    def __init__(self, shared, inline_ok, sysreg_lookup=None, budget=400000,
                 unroll_cap=256):
        self.shared = shared
        self.inline_ok = inline_ok
        self.sysreg_lookup = sysreg_lookup or (lambda *a: None)
        self.budget = budget
        self.unroll_cap = unroll_cap
        self.ef = None
        self.steps = 0
        self.depth = 0
        self.notes = set()
        self.frames = []
        # liveness bookkeeping for the ASL's scratch-register idiom
        self.certain = 0          # >0 while inside an unknown-condition path
        self.origin = {}          # var -> (read_id, kind, idx)
        self.cover = {}           # var -> set of covered bit ranges
        self.used = set()         # vars whose value was consumed
        self.wb = {}              # (kind, idx) -> [width, covered set, read_ids]
        self.suppress_use = 0
        self.last_read_id = None
        self.read_var = {}
        self.flags_written = set()

    # -------------------------------------------------- entry points
    def run(self, stmts, env):
        self.exec_block(stmts, env)
        return env

    def tick(self):
        self.steps += 1
        if self.steps > self.budget:
            raise Budget()

    # -------------------------------------------------- statements
    def exec_block(self, stmts, env):
        for s in stmts:
            self.exec_stmt(s, env)

    def exec_stmt(self, s, env):
        self.tick()
        k = s[0]
        if k == 'assign':
            lhs, rhs = s[1], s[2]
            if (lhs[0] == 'index' and lhs[1][0] == 'var'
                    and lhs[1][1] in REG_ACCESSORS and rhs[0] == 'var'):
                self.suppress_use += 1
                try:
                    val = self.eval(rhs, env)
                finally:
                    self.suppress_use -= 1
                self.writeback(lhs, rhs[1], env)
                return
            self.last_read_id = None
            val = self.eval(rhs, env)
            if lhs[0] == 'var':
                self.note_origin(lhs[1], rhs)
            self.assign(lhs, val, env)
        elif k == 'decl':
            self.last_read_id = None
            val = self.eval(s[3], env) if s[3] is not None else UNK
            if s[2]:
                if len(s[2]) == 1:
                    env[s[2][0]] = val
                    if s[3] is not None:
                        self.note_origin(s[2][0], s[3])
                    else:
                        self.origin.pop(s[2][0], None)
                        self.cover.pop(s[2][0], None)
                else:
                    for nm in s[2]:
                        env[nm] = UNK
                        self.origin.pop(nm, None)
                        self.cover.pop(nm, None)
        elif k == 'if':
            self.exec_if(s, env)
        elif k == 'for':
            self.exec_for(s, env)
        elif k == 'while':
            self.exec_loop_unknown(s[2], env)
        elif k == 'repeat':
            self.exec_loop_unknown(s[1], env)
        elif k == 'case':
            self.exec_case(s, env)
        elif k == 'call':
            self.eval(s[1], env)
        elif k == 'return':
            raise ReturnSig(self.eval(s[1], env) if s[1] is not None else None)
        elif k == 'undefined':
            raise Undefined()
        elif k in ('unpred', 'see', 'nop', 'assert'):
            pass
        else:
            raise AssertionError('stmt %r' % (k,))

    def note_origin(self, var, rhs):
        self.origin.pop(var, None)
        self.cover.pop(var, None)
        if (rhs[0] == 'index' and rhs[1][0] == 'var'
                and rhs[1][1] in REG_ACCESSORS and self.last_read_id is not None):
            self.origin[var] = self.last_read_id
            self.read_var[self.last_read_id] = var

    # ---------------------------------------------------- liveness
    def live_reads(self):
        """Register reads whose value can reach an architectural result.

        The A64 pseudocode routinely reads a destination register into a
        scratch variable, overwrites it element by element and writes it
        back.  Where every bit is overwritten on a path that certainly
        executes, that read carries nothing -- LD1 {V4.4S} does not depend
        on V4.  Where it does not (merging predication, a single-lane
        load), the read stays.
        """
        dead = set()
        wb_ids = set()
        for w, cov, rids in self.wb.values():
            wb_ids |= rids
        for rid, var in self.read_var.items():
            if var not in self.used and rid not in wb_ids:
                dead.add(rid)
        for w, cov, rids in self.wb.values():
            if not (w and _covers(cov, w)):
                continue
            for rid in rids:
                if self.read_var.get(rid) not in self.used:
                    dead.add(rid)
        return set(v for rid, v in self.ef.reads.items() if rid not in dead), dead

    def writeback(self, lhs, var, env):
        """REG[n, w] = var  -- the scratch read-modify-write idiom."""
        args = lhs[2]
        name = lhs[1][1]
        kind = REG_ACCESSORS[name]
        vals = [self.eval(a, env) for a in args]
        pos = IDX_ARG.get(name, 0)
        n = as_int(vals[pos]) if pos < len(vals) else None
        w = as_int(vals[1]) if len(vals) > 1 else None
        if n is None and kind in ('ZA', 'FFR'):
            n = None
        elif n is None:
            self.ef.unresolved.add((kind, 'w'))
            self.notes.add('unresolved-index:' + kind)
            return
        self.ef.add('w', kind, n)
        rid = self.origin.get(var)
        if rid is None:
            return
        key = (kind, n)
        if self.ef.reads.get(rid) != key:
            self.used.add(var)
            return
        ent = self.wb.setdefault(key, [w, set(), set()])
        if w is not None:
            ent[0] = max(ent[0] or 0, w)
        ent[1] |= self.cover.get(var, set())
        ent[2].add(rid)

    def exec_if(self, s, env):
        arms, els = s[1], s[2]
        pending = None
        for cond, body in arms:
            c = self.eval(cond, env)
            if c is True:
                self.exec_block(body, env)
                return
            if c is False:
                continue
            # unknown: union this arm with the rest
            self.certain += 1
            e1 = dict(env)
            fin1 = self._try(body, e1)
            rest = ('if', arms[arms.index((cond, body)) + 1:], els)
            e2 = dict(env)
            fin2 = self._try_stmt(rest, e2) if (rest[1] or rest[2]) else True
            self.certain -= 1
            self._join(env, e1 if fin1 else None, e2 if fin2 else None)
            return
        self.exec_block(els, env)

    def _try(self, body, env):
        try:
            self.exec_block(body, env)
            return True
        except ReturnSig as r:
            if self.frames:
                self.frames[-1].append(r.val)
            return False
        except Undefined:
            return False

    def _try_stmt(self, st, env):
        try:
            self.exec_stmt(st, env)
            return True
        except ReturnSig as r:
            if self.frames:
                self.frames[-1].append(r.val)
            return False
        except Undefined:
            return False

    def _join(self, env, e1, e2):
        if e1 is None and e2 is None:
            raise Undefined()
        if e1 is None:
            env.clear(); env.update(e2); return
        if e2 is None:
            env.clear(); env.update(e1); return
        keys = set(e1) | set(e2)
        env.clear()
        for k in keys:
            a, b = e1.get(k, UNK), e2.get(k, UNK)
            env[k] = a if (a is b or a == b) else UNK

    def exec_for(self, s, env):
        _, var, lo_e, hi_e, step, body = s
        lo, hi = self.eval(lo_e, env), self.eval(hi_e, env)
        lo, hi = as_int(lo), as_int(hi)
        if lo is None or hi is None:
            env[var] = UNK
            self.notes.add('unbounded-loop')
            self.certain += 1
            self._try(body, env)
            self.certain -= 1
            return
        n = (hi - lo + 1) if step > 0 else (lo - hi + 1)
        if n <= 0:
            return
        if n > self.unroll_cap:
            self.certain += 1
            # the register footprint of a data loop does not grow with the
            # element count; run the ends and mark it
            self.notes.add('loop-capped')
            idxs = list(range(lo, lo + self.unroll_cap // 2, step)) + \
                   [hi] if step > 0 else list(range(lo, lo - self.unroll_cap // 2, -1)) + [hi]
        else:
            idxs = list(range(lo, hi + 1)) if step > 0 else list(range(lo, hi - 1, -1))
        for i in idxs:
            env[var] = i
            self._try(body, env)
        if n > self.unroll_cap:
            self.certain -= 1
        env[var] = UNK

    def exec_loop_unknown(self, body, env):
        self.certain += 1
        e1 = dict(env)
        self._try(body, e1)
        self.certain -= 1
        self._join(env, dict(env), e1)

    def exec_case(self, s, env):
        subj = self.eval(s[1], env)
        matched_any = False
        unknown_arms = []
        for vals, body in s[2]:
            r = self.case_match(subj, vals, env)
            if r is True:
                self.exec_block(body, env)
                return
            if r is None:
                unknown_arms.append(body)
        if not unknown_arms:
            self.exec_block(s[3], env)
            return
        envs = []
        self.certain += 1
        for body in unknown_arms + ([s[3]] if s[3] else []):
            e = dict(env)
            if self._try(body, e):
                envs.append(e)
        self.certain -= 1
        if not envs:
            raise Undefined()
        acc = envs[0]
        for e in envs[1:]:
            merged = dict(acc)
            self._join(merged, acc, e)
            acc = merged
        env.clear(); env.update(acc)

    def case_match(self, subj, vals, env):
        any_unknown = False
        for v in vals:
            if v[0] == 'bits':
                pat = v[1]
                if not isinstance(subj, Bits) or subj.v is None:
                    any_unknown = True
                    continue
                if bits_match(subj, pat):
                    return True
            else:
                x = self.eval(v, env)
                if x is UNK or subj is UNK:
                    any_unknown = True
                    continue
                if eq_vals(subj, x):
                    return True
        return None if any_unknown else False

    # -------------------------------------------------- assignment
    def assign(self, lhs, val, env):
        k = lhs[0]
        if k == 'var':
            n = lhs[1]
            if '.' in n:
                root, _, tail = n.partition('.')
                if root == 'PSTATE':
                    self.pstate([('one', ('var', tail.split('.')[0]))], 'w', env)
                    return
                if root not in env:
                    self.maybe_sysreg(root, 'w')
                    return
                env[root] = UNK
                return
            if n == '_PC':
                self.ef.add('w', 'PC', None)
                return
            if n not in env and SYSREG_RE.match(n):
                self.maybe_sysreg(n, 'w')
                return
            env[n] = val
        elif k == 'discard':
            pass
        elif k == 'tuple':
            for t in lhs[1]:
                self.assign(t, UNK, env)
        elif k == 'index':
            self.access(lhs, env, 'w')
        elif k == 'slice':
            base = lhs[1]
            if base[0] == 'var' and base[1] == 'PSTATE':
                self.pstate(lhs[2], 'w', env)
            elif base[0] == 'index':
                self.access(base, env, 'w')
            elif base[0] == 'var':
                if base[1] in env:
                    env[base[1]] = UNK
                else:
                    self.maybe_sysreg(base[1], 'w')
            elif base[0] == 'field':
                self.assign(base, UNK, env)
        elif k == 'field':
            base = lhs[1]
            if base[0] == 'var' and base[1] == 'PSTATE':
                self.pstate([('one', ('var', lhs[2]))], 'w', env)
            elif base[0] == 'var':
                if base[1] in env:
                    env[base[1]] = UNK
                else:
                    self.maybe_sysreg(base[1], 'w')
            elif base[0] == 'index':
                self.access(base, env, 'w')
            else:
                self.assign(base, UNK, env)
        elif k == 'call':
            self.eval(lhs, env)
        else:
            raise AssertionError('lhs %r' % (k,))

    # -------------------------------------------------- expressions
    def eval(self, e, env):
        self.tick()
        k = e[0]
        if k == 'num':
            return e[1]
        if k == 'bits':
            s = e[1]
            if not s:
                return Bits(0, 0)
            if 'x' in s or 'X' in s:
                return Bits(len(s), None)
            return Bits(len(s), int(s, 2))
        if k == 'str':
            return Enum(e[1])
        if k == 'unknown':
            return UNK
        if k == 'var':
            n = e[1]
            if n in env:
                if not self.suppress_use:
                    self.used.add(n)
                return env[n]
            if n == '_PC':
                self.ef.add('r', 'PC', None)
                return UNK
            if n in CONSTS:
                return CONSTS[n]
            if '.' in n:
                root, _, tail = n.partition('.')
                if root == 'PSTATE':
                    self.pstate([('one', ('var', tail.split('.')[0]))], 'r', env)
                    return UNK
                if root in env:
                    return UNK
                self.maybe_sysreg(root, 'r')
                return UNK
            self.maybe_sysreg(n, 'r')
            return UNK if not is_enumlike(n) else Enum(n)
        if k == 'tuple':
            for x in e[1]:
                self.eval(x, env)
            return UNK
        if k == 'set':
            return [self.eval(x, env) if x[0] != 'rangeval' else UNK for x in e[1]]
        if k == 'cond':
            c = self.eval(e[1], env)
            if c is True:
                return self.eval(e[2], env)
            if c is False:
                return self.eval(e[3], env)
            a = self.eval(e[2], env)
            b = self.eval(e[3], env)
            return a if (a is b or a == b) else UNK
        if k == 'un':
            return self.unop(e[1], self.eval(e[2], env))
        if k == 'bin':
            return self.binop(e[1], e[2], e[3], env)
        if k == 'field':
            base = e[1]
            if base[0] == 'var' and base[1] == 'PSTATE':
                self.pstate([('one', ('var', e[2]))], 'r', env)
                return UNK
            self.eval(base, env)
            return UNK
        if k == 'slice':
            base = e[1]
            if base[0] == 'var' and base[1] == 'PSTATE':
                self.pstate(e[2], 'r', env)
                return UNK
            b = self.eval(base, env)
            return self.do_slice(b, e[2], env)
        if k == 'index':
            return self.access(e, env, 'r')
        if k == 'call':
            return self.call(e, env)
        raise AssertionError('expr %r' % (k,))

    def do_slice(self, b, parts, env):
        if len(parts) == 1 and parts[0][0] in ('range', 'one'):
            p = parts[0]
            if p[0] == 'one':
                hi = lo = as_int(self.eval(p[1], env))
            else:
                hi = as_int(self.eval(p[1], env))
                lo = as_int(self.eval(p[2], env))
            if hi is None or lo is None:
                return UNK
            w = hi - lo + 1
            if isinstance(b, Bits) and b.v is not None and w > 0:
                return Bits(w, b.v >> lo)
            return Bits(w, None) if w > 0 else UNK
        tot = 0
        for p in parts:
            if p[0] == 'one':
                tot += 1
            elif p[0] == 'range':
                hi = as_int(self.eval(p[1], env))
                lo = as_int(self.eval(p[2], env))
                if hi is None or lo is None:
                    return UNK
                tot += hi - lo + 1
            else:
                n = as_int(self.eval(p[2], env))
                if n is None:
                    return UNK
                tot += n
        return Bits(tot, None)

    def unop(self, op, v):
        if op == '-':
            return -v if isinstance(v, int) and not isinstance(v, bool) else UNK
        if op in ('!',):
            return (not v) if isinstance(v, bool) else UNK
        if op == 'NOT':
            if isinstance(v, Bits):
                return Bits(v.w, None if v.v is None else ~v.v)
            if isinstance(v, bool):
                return not v
            return UNK
        if op == '~':
            return UNK
        return UNK

    def binop(self, op, le, re_, env):
        if op == '&&':
            a = self.eval(le, env)
            if a is False:
                return False
            b = self.eval(re_, env)
            if a is True:
                return b
            return False if b is False else UNK
        if op == '||':
            a = self.eval(le, env)
            if a is True:
                return True
            b = self.eval(re_, env)
            if a is False:
                return b
            return True if b is True else UNK
        a = self.eval(le, env)
        b = self.eval(re_, env)
        if op == ':':
            if isinstance(a, Bits) and isinstance(b, Bits):
                if a.v is None or b.v is None:
                    return Bits(a.w + b.w, None)
                return Bits(a.w + b.w, (a.v << b.w) | b.v)
            return UNK
        if op in ('==', '!='):
            r = eq_vals(a, b)
            if r is None:
                return UNK
            return r if op == '==' else (not r)
        if op == 'IN':
            if isinstance(b, list):
                if any(x is UNK for x in b) or a is UNK:
                    return UNK
                res = [eq_vals(a, x) for x in b]
                if any(x is True for x in res):
                    return True
                if all(x is False for x in res):
                    return False
                return UNK
            if isinstance(b, Bits) and isinstance(a, Bits):
                return eq_vals(a, b)
            return UNK
        ai, bi = as_int(a), as_int(b)
        if op in ('+', '-', '*', 'DIV', 'MOD', '<<', '>>', 'QUOT', 'REM', '/', '^'):
            if ai is None or bi is None:
                if op in ('+', '-') and isinstance(a, Bits):
                    return Bits(a.w, None)
                return UNK
            try:
                if op == '+':
                    r = ai + bi
                elif op == '-':
                    r = ai - bi
                elif op == '*':
                    r = ai * bi
                elif op in ('DIV', 'QUOT'):
                    r = ai // bi if bi else 0
                elif op in ('MOD', 'REM'):
                    r = ai % bi if bi else 0
                elif op == '/':
                    r = ai / bi if bi else 0
                elif op == '^':
                    r = ai ** bi if 0 <= bi < 64 else 0
                elif op == '<<':
                    r = ai << bi if 0 <= bi < 4096 else 0
                else:
                    r = ai >> bi if bi >= 0 else 0
            except (ValueError, OverflowError, ZeroDivisionError):
                return UNK
            if isinstance(a, Bits) and op in ('+', '-'):
                return Bits(a.w, r)
            return r
        if op in ('<', '>', '<=', '>='):
            if ai is None or bi is None:
                return UNK
            return {'<': ai < bi, '>': ai > bi, '<=': ai <= bi, '>=': ai >= bi}[op]
        if op in ('AND', 'OR', 'EOR'):
            if isinstance(a, bool) and isinstance(b, bool):
                return {'AND': a and b, 'OR': a or b, 'EOR': a != b}[op]
            if isinstance(a, Bits) and isinstance(b, Bits):
                if a.v is None or b.v is None:
                    return Bits(max(a.w, b.w), None)
                return Bits(max(a.w, b.w),
                            {'AND': a.v & b.v, 'OR': a.v | b.v, 'EOR': a.v ^ b.v}[op])
            return UNK
        return UNK

    # -------------------------------------------------- register access
    def access(self, e, env, rw):
        base = e[1]
        args = e[2]
        name = base[1] if base[0] == 'var' else None
        if name is None:
            for a in args:
                self.eval(a, env)
            return UNK
        if name == 'Elem':
            if rw == 'w' and args and args[0][0] == 'var':
                base_var = args[0][1]
                idxv = self.eval(args[1], env) if len(args) > 1 else UNK
                szv = self.eval(args[2], env) if len(args) > 2 else UNK
                ei, sz = as_int(idxv), as_int(szv)
                if self.certain == 0 and ei is not None and sz is not None:
                    self.cover.setdefault(base_var, set()).add((ei * sz, sz))
                env[base_var] = UNK
                return UNK
            for a in args:
                self.eval(a, env)
            return UNK
        if name in MEM_ACCESSORS:
            for a in args:
                self.eval(a, env)
            if rw == 'r':
                self.ef.mem_r += 1
            else:
                self.ef.mem_w += 1
            return UNK
        if name in REG_ACCESSORS:
            kind = REG_ACCESSORS[name]
            vals = [self.eval(a, env) for a in args]
            if name in ('SP', 'PC', 'FFR', 'ZT0', 'ElemFFR'):
                self.last_read_id = self.ef.add(rw, kind, None)
                return UNK
            pos = IDX_ARG.get(name, 0)
            n = as_int(vals[pos]) if pos < len(vals) else None
            if n is None:
                if kind in ('ZA', 'FFR'):
                    self.last_read_id = self.ef.add(rw, kind, None)
                    self.notes.add('index-runtime:' + kind)
                else:
                    self.ef.unresolved.add((kind, rw))
                    self.notes.add('unresolved-index:' + kind)
            else:
                self.last_read_id = self.ef.add(rw, kind, n)
            return UNK
        # a call written with brackets: FPCR[], SCTLR[], ...
        return self.call(('call', name, args, base), env, bracket=True)

    def pstate(self, parts, rw, env):
        names = []
        for p in parts:
            if p[0] == 'one' and p[1][0] == 'var':
                names.append(p[1][1])
            else:
                names.append('?')
        for nm in names:
            if nm in NZCV:
                if rw == 'w':
                    self.flags_written.add(nm)
                self.ef.add(rw, 'FLAGS', None)
            elif nm == '?':
                self.ef.add(rw, 'PSTATE', '?')
            else:
                self.ef.add(rw, 'PSTATE', nm)

    def maybe_sysreg(self, name, rw):
        if name in ('FPCR', 'FPSR', 'FPCRType', 'FPSCR'):
            self.ef.add(rw, 'FCSR', None)
            return
        if name == 'NZCV':
            self.ef.add(rw, 'FLAGS', None)
            return
        if name in ('SP_EL0', 'SP_EL1', 'SP_EL2', 'SP_EL3'):
            self.ef.add(rw, 'SP', None)
            return
        if SYSREG_RE.match(name) and self.sysreg_lookup(name) is not None:
            self.ef.add(rw, 'SYS', self.sysreg_lookup(name))

    # -------------------------------------------------- calls
    def call(self, e, env, bracket=False):
        name, args = e[1], e[2]
        if name is None:
            self.eval(e[3], env)
            for a in args:
                self.eval(a, env)
            return UNK
        vals = [self.eval(a, env) for a in args]
        b = _dispatch_feature(name)
        if b is not None:
            return b(self, vals, env)
        if name in ('FPCR', 'FPSR'):
            self.ef.add('r', 'FCSR', None)
            return UNK
        if name == 'AArch64.SysRegRead':
            self.sysreg_op(vals, 'r')
            return UNK
        if name == 'AArch64.SysRegWrite':
            self.sysreg_op(vals, 'w')
            return UNK
        if name in ('AArch64.SysInstr', 'AArch64.SysInstrWithResult'):
            self.sysreg_op(vals, 'r' if 'Result' in name else 'w')
            return UNK
        if name in REG_ACCESSORS and bracket:
            return UNK
        # inline a shared function when it is in the allowed set
        if self.inline_ok(name) and self.depth < 12:
            body = self.lookup(name, len(args))
            if body is not None:
                params, stmts = body
                sub = dict(zip(params, vals))
                self.depth += 1
                self.frames.append([])
                definite = []
                try:
                    self.exec_block(stmts, sub)
                except ReturnSig as r:
                    definite.append(r.val)
                except Undefined:
                    pass
                finally:
                    self.depth -= 1
                    seen = self.frames.pop() + definite
                if not seen:
                    return UNK
                first = seen[0]
                for v in seen[1:]:
                    if not (v is first or v == first):
                        return UNK
                return first
        return UNK

    def lookup(self, name, nargs):
        for key in ((name, nargs, 'func'), (name, nargs, 'get'), (name, nargs, 'set')):
            v = self.shared.get(key)
            if v is not None:
                params, text = v
                stmts = self.parsed(key, text)
                if stmts is not None:
                    return params, stmts
        return None

    _pcache = {}
    def parsed(self, key, text):
        if key in self._pcache:
            return self._pcache[key]
        try:
            st = aslparse.parse_stmts(text)
        except Exception:
            st = None
        self._pcache[key] = st
        return st

    def sysreg_op(self, vals, rw):
        op0, op1, crn, crm, op2 = [as_int(v) for v in vals[:5]]
        t = as_int(vals[5]) if len(vals) > 5 else None
        nm = self.sysreg_lookup(None, (op0, op1, crn, crm, op2))
        if rw == 'r':
            self.ef.add('r', 'SYS', nm)
            if t is None:
                self.ef.unresolved.add(('GPR', 'w'))
            else:
                self.ef.add('w', 'GPR', t)
        else:
            self.ef.add('w', 'SYS', nm)
            if t is None:
                self.ef.unresolved.add(('GPR', 'r'))
            else:
                self.ef.add('r', 'GPR', t)


# --------------------------------------------------------------- helpers
def _covers(ranges, width):
    if not ranges:
        return False
    iv = sorted((o, o + sz) for o, sz in ranges)
    end = 0
    for lo, hi in iv:
        if lo > end:
            return False
        end = max(end, hi)
    return end >= width


def as_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, Bits):
        return v.v
    return None


def eq_vals(a, b):
    if a is UNK or b is UNK:
        return None
    if isinstance(a, Enum) or isinstance(b, Enum):
        if isinstance(a, Enum) and isinstance(b, Enum):
            return a.name == b.name
        return None
    if isinstance(a, Bits) and isinstance(b, Bits):
        if a.v is None or b.v is None:
            return None
        return a.v == b.v
    ai, bi = as_int(a), as_int(b)
    if isinstance(a, bool) and isinstance(b, bool):
        return a == b
    if ai is None or bi is None:
        return None
    return ai == bi


def bits_match(v, pat):
    if v.v is None:
        return None
    n = len(pat)
    for i, ch in enumerate(pat):
        if ch in 'xX':
            continue
        bit = (v.v >> (n - 1 - i)) & 1
        if bit != int(ch):
            return False
    return True


def is_enumlike(n):
    return bool(re.match(r'^[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+$', n))


# --------------------------------------------------------------- builtins
def _b_uint(ip, v, env):
    x = v[0]
    if isinstance(x, Bits):
        return x.v
    return as_int(x)

def _b_sint(ip, v, env):
    x = v[0]
    if isinstance(x, Bits) and x.v is not None:
        s = x.v
        if s >> (x.w - 1):
            s -= 1 << x.w
        return s
    return None if not isinstance(x, int) else x

def _b_zeros(ip, v, env):
    n = as_int(v[0]) if v else None
    return Bits(n, 0) if n else UNK

def _b_ones(ip, v, env):
    n = as_int(v[0]) if v else None
    return Bits(n, (1 << n) - 1) if n else UNK

def _b_ext(ip, v, env):
    n = as_int(v[1]) if len(v) > 1 else None
    x = v[0]
    if n is None:
        return UNK
    if isinstance(x, Bits) and x.v is not None:
        return Bits(n, x.v)
    return Bits(n, None)

def _b_sext(ip, v, env):
    n = as_int(v[1]) if len(v) > 1 else None
    x = v[0]
    if n is None or not isinstance(x, Bits):
        return UNK
    if x.v is None:
        return Bits(n, None)
    s = x.v
    if s >> (x.w - 1):
        s -= 1 << x.w
    return Bits(n, s)

def _b_lsl(ip, v, env):
    x, n = v[0], as_int(v[1]) if len(v) > 1 else None
    if isinstance(x, Bits) and x.v is not None and n is not None:
        return Bits(x.w, x.v << n)
    return UNK

def _b_int(ip, v, env):
    return _b_uint(ip, v, env)

def _b_len(ip, v, env):
    x = v[0]
    return x.w if isinstance(x, Bits) else None

def _b_replicate(ip, v, env):
    return UNK

def _b_currentvl(ip, v, env):
    return 512

def _b_false(ip, v, env):
    return False

def _b_true(ip, v, env):
    return True

def _b_unk(ip, v, env):
    return UNK

FEATURE_OFF = {
    # Optional SUBSYSTEMS that attach state to OTHER instructions (branch
    # records, profiling buffers, virtualization redirection).  Instruction
    # EXISTENCE features are never switched off here -- switching one off
    # would make its own encoding UNDEFINED and silently empty its row.
    'HaveBRBExt', 'HaveStatisticalProfiling', 'HaveSPE',
    'HaveSelfHostedTrace', 'HaveTraceExt', 'HaveRME',
    'HaveMPAMExt', 'HaveNV2Ext', 'HaveNVExt', 'HaveVirtHostExt',
    'EL2Enabled', 'HaveAArch32', 'HaveAArch32EL', 'HaveDoubleLock',
    'HaveTrapLoadStoreMultipleDeviceExt', 'HaveHPMN0Ext',
    'InGuardedPage', 'ProfilingBufferEnabled',
}


def _b_feature(ip, v, env):
    return True


def _b_featoff(ip, v, env):
    return False


BUILTIN = {
    'UInt': _b_uint, 'SInt': _b_sint, 'Int': _b_int,
    'Zeros': _b_zeros, 'Ones': _b_ones,
    'ZeroExtend': _b_ext, 'SignExtend': _b_sext, 'Extend': _b_ext,
    'LSL': _b_lsl, 'Len': _b_len, 'Replicate': _b_replicate,
    'CurrentVL': _b_currentvl, 'CurrentSVL': _b_currentvl,
    'HaveSVE': _b_true, 'HaveSME': _b_true,
    'ConstrainUnpredictableBool': _b_false,
    'IsFeatureImplemented': _b_true,
    'BigEndian': _b_false,
    'InGuardedPage': _b_false,
    'UsingAArch32': _b_false, 'ELUsingAArch32': _b_false,
    'ELUsingAArch32K': _b_false, 'IsSecure': _b_false,
    'HaveFP16Ext': _b_true, 'HaveAltFP': _b_false,
}
for _f in FEATURE_OFF:
    BUILTIN[_f] = _b_featoff


def _dispatch_feature(name):
    if name in BUILTIN:
        return BUILTIN[name]
    if name.startswith('Have') and name.endswith(('Ext', 'Extension')):
        return _b_feature
    if name.startswith('Have'):
        return _b_feature
    if name.startswith('IsFeatureImplemented'):
        return _b_feature
    return None
