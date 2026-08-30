#!/usr/bin/env python3
"""A refusing reader of preprocessed C, for CP-H's per-helper usage facts.

What it answers, for one helper:

  * the DIRECTION of each pointer parameter -- read, written, or both;
  * the FOOTPRINT through `env` -- which members of CPUArchState it reaches,
    and in which direction.

What it refuses to answer, and says so rather than guessing:

  * a helper that hands `env` itself (or any pointer cast from it) to a
    function this unit does not define.  The footprint is then whatever that
    function does and nothing here bounds it.
  * a helper that reaches state through a pointer whose provenance it cannot
    follow.

The refusal is the point.  An absent row costs precision; a wrong row costs
correctness, and a missing dependency is the error direction this project
treats as disqualifying.  So every uncertainty widens the answer (an escaped
address is read AND written, an indexed array member is the whole array) or
refuses outright.
"""
import re, sys

TOK = re.compile(r"""
    (?P<ws>\s+)
  | (?P<line>\#[^\n]*)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<chr>'(?:[^'\\]|\\.)*')
  | (?P<id>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<num>(?:0[xX][0-9a-fA-F]+|\d+)[uUlLfF]*|\.\d+\w*)
  | (?P<punc>\.\.\.|<<=|>>=|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\^=|\|=|\#\#|.)
""", re.X)

LINEMARK = re.compile(r'^#\s+(\d+)\s+"([^"]*)"')


class Unit:
    """One preprocessed translation unit, tokenized and indexed by function."""

    def __init__(self, path):
        self.toks = []      # (kind, text)
        self.loc = []       # (file, line) for each token
        src = open(path, errors='replace').read()
        cur_file, cur_line = path, 1
        pos = 0
        for m in TOK.finditer(src):
            kind = m.lastgroup
            text = m.group()
            if kind == 'line':
                lm = LINEMARK.match(text)
                if lm:
                    cur_line = int(lm.group(1))
                    cur_file = lm.group(2)
                continue
            if kind == 'ws':
                cur_line += text.count('\n')
                continue
            self.toks.append((kind, text))
            self.loc.append((cur_file, cur_line))
        self.funcs = {}
        self._index_functions()
        self.enums = {}
        self._index_enums()

    # -- function indexing ------------------------------------------------
    def _match_back(self, i, open_t, close_t):
        """@i is the index of close_t; return index of its opener."""
        d = 0
        while i >= 0:
            t = self.toks[i][1]
            if t == close_t:
                d += 1
            elif t == open_t:
                d -= 1
                if d == 0:
                    return i
            i -= 1
        return -1

    def _match_fwd(self, i, open_t, close_t):
        d = 0
        n = len(self.toks)
        while i < n:
            t = self.toks[i][1]
            if t == open_t:
                d += 1
            elif t == close_t:
                d -= 1
                if d == 0:
                    return i
            i += 1
        return -1

    def _index_enums(self):
        """Bind enumeration constants to the integers QEMU gave them.

        `env->regs[R_EAX]` is an access to ONE register and the source says
        which: target/i386/cpu.h writes `R_EAX = 0`.  R_EAX is an ENUMERATOR,
        not a macro, so the preprocessor leaves the identifier standing and a
        reader that only accepts a numeric token sees a subscript it cannot
        read -- which widened cpuid's four destinations to the whole 128-byte
        `regs` array and lost every one of them a name.  Per R5 the
        information is in the source; this reads it.

        NOTHING IS EVALUATED.  A binding is taken only when the enumerator is
        written as a plain integer literal, or is the implicit successor of
        one already bound.  An initializer that is an expression stops the
        run: that enumerator and every implicit one after it in the same
        block stay unbound, so a name this reader is unsure of is a name it
        does not have rather than one it computed.

        A name bound to two different values in two blocks is DROPPED, since
        an ambiguous constant would decide a subscript by which header the
        reader happened to see first.
        """
        toks, n = self.toks, len(self.toks)
        i = 0
        seen = {}
        while i < n:
            if toks[i][1] != 'enum':
                i += 1
                continue
            j = i + 1
            if j < n and toks[j][0] == 'id':
                j += 1            # a tag
            if j >= n or toks[j][1] != '{':
                i += 1
                continue
            close = self._match_fwd(j, '{', '}')
            if close < 0:
                i = j + 1
                continue
            self._read_enum_body(j + 1, close, seen)
            i = close + 1
        self.enums = {k: v for k, v in seen.items() if v is not None}

    def _read_enum_body(self, lo, hi, seen):
        toks = self.toks
        nxt = 0                  # the next implicit value, None once lost
        k = lo
        while k < hi:
            if toks[k][0] != 'id':
                k += 1
                continue
            name = toks[k][1]
            k += 1
            val = nxt
            if k < hi and toks[k][1] == '=':
                k += 1
                if k < hi and toks[k][0] == 'num' and \
                        (k + 1 >= hi or toks[k + 1][1] == ','):
                    txt = toks[k][1].rstrip('uUlL')
                    val = int(txt, 0) if txt[:2].lower() == '0x' \
                        else (int(txt) if txt.isdigit() else None)
                    k += 1
                else:
                    val = None
                # An expression initializer: this name and every implicit
                # successor after it are unreadable.
            nxt = None if val is None else val + 1
            if val is not None:
                if name in seen and seen[name] != val:
                    seen[name] = None       # ambiguous: no binding at all
                elif name not in seen:
                    seen[name] = val
            while k < hi and toks[k][1] != ',':
                k += 1
            k += 1

    def _index_functions(self):
        n = len(self.toks)
        i = 0
        depth = 0
        while i < n:
            t = self.toks[i][1]
            if t == '{':
                if depth == 0:
                    end = self._match_fwd(i, '{', '}')
                    if end < 0:
                        break
                    self._try_function(i, end)
                    i = end + 1
                    continue
                depth += 1
            elif t == '}':
                depth -= 1
            i += 1

    def _try_function(self, brace, end):
        # walk back over __attribute__((...)) and similar
        j = brace - 1
        while j >= 0 and self.toks[j][1] == ')':
            op = self._match_back(j, '(', ')')
            if op < 0:
                return
            name_i = op - 1
            if name_i < 0 or self.toks[name_i][0] != 'id':
                # __attribute__((...)) -- the ident before is a keyword
                j = name_i - 1 if name_i >= 0 else -1
                continue
            if self.toks[name_i][1] == '__attribute__':
                j = name_i - 1
                continue
            # a declarator: IDENT ( params ) {
            name = self.toks[name_i][1]
            if name_i - 1 >= 0 and self.toks[name_i - 1][1] in (',', '(', '='):
                return          # an initializer or a call, not a definition
            params = self._split_params(op, j)
            if name not in self.funcs:
                self.funcs[name] = (params, brace, end, self.loc[name_i])
            return
        return

    def _split_params(self, op, cp):
        """Return [(name_or_None, is_pointer)] for the parameter list."""
        out = []
        d = 0
        cur = []
        for k in range(op + 1, cp):
            t = self.toks[k][1]
            if t in '([{':
                d += 1
            elif t in ')]}':
                d -= 1
            if t == ',' and d == 0:
                out.append(cur); cur = []
            else:
                cur.append((k, self.toks[k]))
        if cur:
            out.append(cur)
        res = []
        for grp in out:
            if not grp:
                continue
            texts = [g[1][1] for g in grp]
            if texts == ['void']:
                continue
            star = '*' in texts
            # the parameter name is the last identifier that is not a type kw
            nm, nmi = None, None
            for k, (kind, txt) in reversed(grp):
                if kind == 'id':
                    nm, nmi = txt, k
                    break
            res.append((nm, star, nmi, ' '.join(texts)))
        return res


# ---------------------------------------------------------------------------
RD, WR = 1, 2

ASSIGN_OPS = {'=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>='}

#
# QEMU's own accessors between one CPU's three views of itself.  These are the
# ONE derived form this reader follows rather than refuses, and it follows
# them because they are not arithmetic on a pointer -- they are QEMU stating
# an identity.  env_cpu() is `(CPUState *)((uintptr_t)env - sizeof(CPUState))`
# and env_archcpu() the same with the concrete type; cpu_env() goes back.
#
# The direction matters for what the footprint MEANS.  This model's universe
# is CPUArchState, because a field record is an ENV OFFSET and nothing else
# can be published; CPUState's own members (halted, exception_index, the
# TLB) have no env offset and are outside it in either account.  So a value
# reached through the CPUState view is not a miss in the published model --
# it is a member of a struct the model does not describe -- and only a return
# to the CPUArchState view puts it back in scope.
#
ENV_TO_CPU = {'env_cpu', 'env_cpu_const', 'env_archcpu', 'env_archcpu_const'}
CPU_TO_ENV = {'cpu_env', 'cpu_env_const'}

#
# A struct member named `env` is the env view, in both of the two shapes QEMU
# writes it: `ArchCPU::env` is the CPUArchState embedded in the CPU object --
# `cpu_env()` is literally `&cpu->env` -- and a carrier struct such as
# target/i386's `X86Access` holds a `CPUX86State *env` so that the do_*()
# worker can recover it (`CPUX86State *env = ac->env;`,
# target/i386/tcg/fpu_helper.c:2534).  Without this the x87 environment
# helpers came out with an EMPTY footprint.
#
ENV_MEMBER = 'env'


# ---------------------------------------------------------------------------
# CP1 -- the guest memory accesses a helper performs itself.
#
# QEMU's helpers reach guest memory through exactly one family of entry
# points, declared in include/exec/cpu_ldst.h and spelled
# cpu_<dir><width>[_<endian>]_<how>[_ra].  They all take the CPU state
# pointer first and the guest ADDRESS second, and the store forms take the
# VALUE third.  That shape is what makes the address argument nameable at
# all; it is CHECKED here (argument 0 must be the env root) rather than
# assumed, and a call that does not have it is not recorded.
#
# _code is excluded on purpose: an instruction fetch is not in the model on
# any instruction -- no instruction records reading its own encoding -- so
# recording one here would be an exception made for helpers alone.
ACC_PREFIX = ('cpu_ld', 'cpu_st', 'cpu_atomic_')
ACC_WIDTH = [
    ('16', 16), ('ub', 1), ('sb', 1), ('uw', 2), ('sw', 2),
    ('ul', 4), ('sl', 4), ('b', 1), ('w', 2), ('l', 4), ('q', 8), ('o', 16),
]


def _acc_of(name):
    """(direction, width) for a guest-access primitive, or None.

    The width is read off the name; a form this reader does not recognise
    gets width 0, which the table publishes as "not stated" rather than as a
    guess -- the count of bytes is not the fact the SHAPE gate needs, and
    inventing one would put a number on the wire that nothing measured.
    """
    if '_code' in name:
        return None
    if name.startswith('cpu_atomic_'):
        return (RD | WR, 0)
    if name.startswith('cpu_ld'):
        d, rest = RD, name[len('cpu_ld'):]
    elif name.startswith('cpu_st'):
        d, rest = WR, name[len('cpu_st'):]
    else:
        return None
    for pfx, sz in ACC_WIDTH:
        if rest.startswith(pfx):
            return (d, sz)
    return (d, 0)


class Refusal(Exception):
    def __init__(self, why, where):
        super().__init__(why)
        self.why = why
        self.where = where


class Analysis:
    """Footprints of one helper, derived from the expansion of its body."""

    MAX_DEPTH = 24

    def __init__(self, unit, extra_units=()):
        self.u = unit
        self.units = [unit] + list(extra_units)
        self.reset()

    def reset(self):
        self.env_fields = {}    # field -> dir
        self.arg_dir = {}       # root id -> dir
        self.refusals = []
        self.seen = set()
        self.where = {}         # field -> "file:line"
        self.pending_derived = {}
        # Fields whose ARRAY INDEX was not a constant: the recorded range is
        # the whole file and no element of it can be named.  Kept apart from
        # env_fields so a row can state which of its members it narrowed.
        self.env_unbounded = set()
        # SUBSCRIPT EXPRESSIONS a path walk stepped over, as (open, close)
        # token indices, waiting to be scanned in their own right.  See
        # _path_end()'s `[` arm and _drain_subs().
        self._pending_subs = []
        self.cpu_escapes = []   # unresolved callees reached via the CPU view
        # CP1.  Guest memory accesses the helper performs ITSELF, keyed by
        # (direction, address argument) -- see _guest_access().  The value
        # carries the access width, whether the count is bounded, and the
        # file:line it was read from.
        self.mem_acc = {}
        self._sframe = [{}]     # scalar parameter name -> argument index
        self._pending_sroots = None
        self._in_acc = 0        # depth inside an access primitive's own body
        # A CALLEE handed over as an argument.
        #
        # aarch64's MOPS set helpers reach their guest stores through one:
        # HELPER(setp) is `do_setp(env, syndrome, mtedesc, set_step, false,
        # GETPC())` and do_setp() calls `stepfn(env, ...)`.  Read literally,
        # `stepfn` is defined in no unit, the env root reaches it, and the
        # helper is REFUSED -- which is this reader's limit written down as
        # the machine's, the shape R5 rules out.
        #
        # It is bounded and it is derived: the binding exists only when the
        # ACTUAL argument at the call site is the NAME of a function these
        # units define, so the concrete callee is read off QEMU's own source
        # at the site that chose it.  A call through a STRUCT MEMBER --
        # `ri->accessfn`, whose table has hundreds of entries -- has no such
        # site and stays refused.
        self._fnframe = [{}]    # parameter name -> concrete function name
        self._pending_fnroots = None

    def lookup(self, name):
        for u in self.units:
            if name in u.funcs:
                return u, u.funcs[name]
        return None, None

    # -- the walk ---------------------------------------------------------
    def run(self, helper, roots):
        """@roots maps parameter index -> root id ('env' or an int)."""
        self.reset()
        u, f = self.lookup(helper)
        if f is None:
            raise Refusal('no definition in the preprocessed units', helper)
        self._walk(u, helper, roots, 0)
        return self

    def _walk(self, u, fname, roots, depth):
        fnr = self._pending_fnroots
        self._pending_fnroots = None
        # The function-pointer binding is part of the walk's IDENTITY, not a
        # decoration on it: do_setp(..., set_step, ...) and
        # do_setp(..., set_step_tags, ...) are the same function reached with
        # the same roots and they touch different state.  Leaving it out of
        # the key memoises the first and silently gives the second its answer.
        key = (id(u), fname, tuple(sorted(roots.items())),
               tuple(sorted((fnr or {}).items())))
        if key in self.seen:
            return
        if depth > self.MAX_DEPTH:
            raise Refusal('call depth limit', fname)
        self.seen.add(key)
        params, brace, end, loc = u.funcs[fname]
        # local name -> root
        taint = {}
        for pi, root in roots.items():
            if pi < len(params) and params[pi][0]:
                taint[params[pi][0]] = (root, None)
        # CP1's SCALAR frame, kept strictly beside the pointer taint above and
        # never merged into it.  A guest address arrives in a helper as a
        # target_ulong -- helper_swr(env, arg1, arg2, mem_idx) addresses
        # through arg2 -- and roots_of() gives a root only to POINTER
        # parameters, so the pointer taint cannot name it.  Merging the two
        # would put a scalar into arg_dir[] and change the argument-direction
        # column this pass must leave byte-identical, so they stay apart.
        sr = self._pending_sroots
        self._pending_sroots = None
        if depth == 0:
            # The helper's own signature IS the naming: every parameter that
            # is not a pointer root is a candidate address or data argument,
            # under the same index the usage table's argdir[] uses.
            sr = {pi: pi for pi in range(len(params)) if pi not in roots}
        sframe = {}
        for pi, root in (sr or {}).items():
            if pi < len(params) and params[pi][0]:
                sframe[params[pi][0]] = root
        fnframe = {}
        for pi, callee in (fnr or {}).items():
            if pi < len(params) and params[pi][0]:
                fnframe[params[pi][0]] = callee
        self._sframe.append(sframe)
        self._fnframe.append(fnframe)
        try:
            self._scan(u, brace, end, taint, depth, fname)
        finally:
            self._sframe.pop()
            self._fnframe.pop()

    def _scan(self, u, brace, end, taint, depth, fname):
        toks, loc = u.toks, u.loc
        i = brace + 1
        while i < end:
            kind, txt = toks[i]
            if kind != 'id':
                i += 1
                continue
            # `<anything>->env` / `<anything>.env` -- the env view again.
            if txt == ENV_MEMBER and i > 0 and toks[i - 1][1] in ('->', '.') \
                    and txt not in taint:
                base = i - 2
                while base > 0 and toks[base - 1][1] in ('->', '.'):
                    base -= 2
                i = self._derived(u, max(base, 0), i + 1, end, taint, 'env',
                                  fname)
                self._drain_subs(u, taint, depth, fname)
                continue
            # An accessor between the env and CPUState views of one CPU.
            if (txt in ENV_TO_CPU or txt in CPU_TO_ENV) and \
                    i + 1 < end and toks[i + 1][1] == '(':
                cp = u._match_fwd(i + 1, '(', ')')
                inner = [k for k in range(i + 2, cp)]
                if cp > 0 and len(inner) == 1 and toks[inner[0]][1] in taint:
                    src = taint[toks[inner[0]][1]][0]
                    want = 'env' if txt in ENV_TO_CPU else 'cpu'
                    if (want == 'env' and src == 'env') or \
                            (want == 'cpu' and src == 'cpu'):
                        newroot = 'cpu' if txt in ENV_TO_CPU else 'env'
                        i = self._derived(u, i, cp + 1, end, taint, newroot,
                                          fname)
                        self._drain_subs(u, taint, depth, fname)
                        continue
            # a call?
            if i + 1 < end and toks[i + 1][1] == '(' and txt not in (
                    'if', 'for', 'while', 'switch', 'return', 'sizeof',
                    'do', '__builtin_expect'):
                cp = u._match_fwd(i + 1, '(', ')')
                if cp > 0 and cp < end:
                    self._call(u, i, cp, taint, depth, fname)
                    i += 1
                    continue
            if txt in taint and (i == 0 or toks[i - 1][1] not in ('->', '.')):
                i = self._access(u, i, end, taint, fname)
                self._drain_subs(u, taint, depth, fname)
                continue
            i += 1

    def _drain_subs(self, u, taint, depth, fname):
        """Scan the subscript expressions _path_end() stepped over.

        A subscript is an rvalue context, so an access found inside one is
        classified by the same rules that classify any other -- no direction
        is assumed here.  Draining in a loop rather than a for: a nested
        subscript pushes while this runs.
        """
        while self._pending_subs:
            opn, cl = self._pending_subs.pop()
            self._scan(u, opn, cl, taint, depth, fname)

    def _path_end(self, u, i, end):
        """Consume root [-> . [ ] ]* and return (index past it, first member,
        full access path, index-not-stated).

        THE WHOLE PATH IS THE NAME, and a CONSTANT SUBSCRIPT is part of it.

        `env->regs[R_EAX] = eax` is a write to ONE register and
        `env->cp15.tpidr_el[0] = x` is a write to one system register.  Both
        are valid offsetof designators, so the generator can hand each to the
        compiler and get the element's own offset and width.  Recording only
        the first member instead produced `regs` (128 bytes over sixteen
        registers) and `cp15` (2,416 bytes over the whole system file) -- and
        a range that reaches past a register is REFUSED downstream rather
        than named, which is exactly why QEMU's write list came out short of
        the machine's and cpuid's four destinations reached the wire with no
        row behind them.

        Enumerators are resolved because they are QEMU's own binding, not an
        evaluation: see Unit._index_enums().

        THE PATH STOPS WHERE THE READER STOPS BEING SURE:

          a VARIABLE subscript -- `env->xregs[mops_destreg(syn)]` -- ends the
          path at the array and reports index-not-stated, so the range is the
          whole file and the caller knows it names no element of it.  Guessing
          one is the error direction this file treats as disqualifying;

          a `->` after the first step is a POINTER member, and what it reaches
          is not inside CPUArchState at all, so the path ends at the pointer.

        The FIRST member is still returned beside the path: the carrier-struct
        rule (`ac->env`) keys on that name and must not see a path.
        """
        toks = u.toks
        j = i + 1
        first = None
        path = None
        var_index = False
        step = 0
        while j < end:
            t = toks[j][1]
            if t in ('->', '.') and j + 1 < end and toks[j + 1][0] == 'id':
                if step > 0 and t == '->':
                    break       # a pointer member: outside CPUArchState
                nm = toks[j + 1][1]
                if first is None:
                    first, path = nm, nm
                elif path is not None:
                    path = '%s.%s' % (path, nm)
                step += 1
                j += 2
            elif t == '[':
                cl = u._match_fwd(j, '[', ']')
                if cl < 0:
                    break
                lit = self._const_index(u, j, cl)
                if lit is None:
                    # A SUBSCRIPT THE READER CANNOT NAME IS STILL AN
                    # EXPRESSION, AND WHAT IT READS IS READ.
                    #
                    # `ST(n)` expands to `env->fpregs[(env->fpstt + (n)) & 7]`
                    # and names TWO members: the array, which this walk
                    # reports, and `fpstt`, which the subscript states.  The
                    # walk resumes past the `]`, so without this the
                    # subscript's own reads were dropped whole and
                    # helper_fxchg_ST0_STN came out reading fpregs alone --
                    # a missing dependency published as though the footprint
                    # were complete.
                    self._pending_subs.append((j, cl))
                    if path is not None:
                        var_index = True
                        path = None   # the path stops being nameable here
                elif path is not None:
                    path = '%s[%s]' % (path, lit)
                j = cl + 1
            else:
                break
        if path is None:
            path = first
        return j, first, path, var_index

    @staticmethod
    def _const_index(u, opn, cl):
        """The integer between [ and ], as written, or None.

        Accepted ONLY when the whole subscript is a single integer token --
        the shape a macro constant leaves behind after expansion.  An
        expression, even a constant-folding one, is not read: this reader
        does not evaluate C, and a subscript it computed itself would be a
        number nothing in the source states.
        """
        if cl != opn + 2:
            return None
        kind, text = u.toks[opn + 1]
        if kind == 'id':
            v = u.enums.get(text)
            return None if v is None else str(v)
        if kind != 'num':
            return None
        text = text.rstrip('uUlL')
        if not text.isdigit():
            return None
        return text

    def _derived(self, u, lo, j, end, taint, newroot, fname):
        """An accessor expression spanning [lo, j) evaluates to @newroot."""
        toks = u.toks
        prev = toks[lo - 1][1] if lo > 0 else ''
        nxt = toks[j][1] if j < end else ''
        # `CPUState *cs = env_cpu(env);`
        if prev == '=' and nxt == ';' and lo - 2 >= 0 and \
                toks[lo - 2][0] == 'id':
            taint[toks[lo - 2][1]] = (newroot, None)
            return j
        # `f(env_cpu(env), ...)` -- the call's own handling maps it.
        if prev in ('(', ',') and nxt in (')', ','):
            self.pending_derived[lo] = newroot
            return j
        # `&cpu->env` -- the address of the embedded CPUArchState IS env.
        if prev == '&' and newroot == 'env' and nxt in (')', ',', ';'):
            if nxt in (')', ','):
                self.pending_derived[lo - 1] = newroot
            return j
        # `ac->env = <the env root>` -- storing the view back into a carrier.
        if nxt == '=' and newroot == 'env':
            k = j + 1
            if k < end and toks[k][0] == 'id' and toks[k][1] in taint and \
                    taint[toks[k][1]][0] == 'env':
                return j
        # `cpu->env.features[i]` -- the env view followed by a member path,
        # which is an ordinary CPUArchState access and must be recorded as
        # one.  x86_cpu_xsave_xcr0_components() reads the feature words that
        # way and nothing else in helper_cpuid reaches them.
        if newroot == 'env' and nxt in ('->', '.'):
            k, _first, field, var_index = self._path_end(u, j - 1, end)
            prev2 = toks[lo - 1][1] if lo > 0 else ''
            nxt2 = toks[k][1] if k < end else ''
            if nxt2 == '=':
                d = WR
            elif nxt2 in ASSIGN_OPS or nxt2 in ('++', '--') or \
                    prev2 in ('++', '--'):
                d = RD | WR
            else:
                d = RD
            if prev2 == '&':
                d = RD | WR
            if field:
                self._note_env(field, d, '%s:%d' % u.loc[j - 1], var_index)
            return k
        # `env_cpu(env)->field` -- a CPUState member, outside this model.
        if nxt in ('->', '.'):
            k, _first, field, _var = self._path_end(u, j - 1, end)
            return k
        if newroot == 'env':
            raise Refusal('the env view escapes into an expression this '
                          'reader does not follow', fname)
        return j

    def _access(self, u, i, end, taint, fname):
        toks, loc = u.toks, u.loc
        root, off = taint[toks[i][1]]
        j, first, field, var_index = self._path_end(u, i, end)
        lo = i
        # A macro that parenthesises its result -- x86's CC_SRC expands to
        # (env->cc_src) -- puts the assignment operator OUTSIDE the paren, so
        # a write reads as a read unless the wrapper is peeled.  Peel only a
        # paren that is not a call's: `f(env->x)` has the same token shape and
        # the paren there belongs to f.
        while (lo > 0 and toks[lo - 1][1] == '(' and j < end
               and toks[j][1] == ')'
               and not (lo - 2 >= 0 and (toks[lo - 2][0] == 'id'
                                         or toks[lo - 2][1] in (')', ']')))):
            lo -= 1
            j += 1
            if j < end and toks[j][1] in ('->', '.', '['):
                j2, fi2, f2, v2 = self._path_end(u, j - 1, end)
                if field is None:
                    field = f2
                    first = fi2
                    var_index = v2
                j = j2
        prev = toks[lo - 1][1] if lo > 0 else ''
        nxt = toks[j][1] if j < end else ''

        # `p = <something>` -- an assignment to the tainted local itself.
        if field is None and j == i + 1 and nxt == '=':
            if root == 'env':
                raise Refusal('env reassigned', fname)
            taint.pop(toks[i][1], None)
            return j + 1

        # &root->field ... : the address escapes; it is read AND written
        # unless it is inside sizeof.
        escaped = (prev == '&')
        d = 0
        if nxt in ASSIGN_OPS and nxt != '==':
            d = WR if nxt == '=' else (RD | WR)
        elif nxt in ('++', '--') or prev in ('++', '--'):
            d = RD | WR
        else:
            d = RD
        if escaped:
            d = RD | WR

        # `ac->env` reached through a TAINTED base.  _scan hits the base
        # first, so the ENV_MEMBER rule never sees the member; without this
        # the carrier's env member was consumed as an ordinary member of a
        # struct outside the model, and do_fldenv()'s whole footprint was
        # dropped on the floor.
        if first == ENV_MEMBER and root != 'env':
            # Hand _derived the span that ends AT the env member, not at the
            # end of the whole path: `cpu->env.features[i]` continues past it
            # and _derived must see the `.` to know the access is an ordinary
            # CPUArchState one.
            m = lo
            while m < j and toks[m][1] not in ('->', '.'):
                m += 1
            return self._derived(u, lo, m + 2, end, taint, 'env', fname)

        if field is None:
            # The ROOT itself, not a member of it.
            #
            # Exactly one context is safe: the root standing alone as a call
            # argument, which _call resolves by walking into the callee.
            # EVERY other use is the pointer escaping into an expression this
            # reader does not follow -- a cast (`env_cpu(env)` is
            # `(CPUState *)((uintptr_t)env - sizeof(CPUState))`), an
            # assignment into a struct member, a return.  The first cut
            # returned silently from those and produced an EMPTY footprint for
            # helper_fldenv, which loads the whole x87 environment: a missed
            # dependency, published as though it were an exact one.
            bare_arg = prev in ('(', ',') and nxt in (')', ',')
            if bare_arg:
                return j
            # `CPUX86State *e = env;` -- a plain alias, and the only derived
            # form worth following rather than refusing.
            if prev == '=' and nxt == ';' and lo - 2 >= 0 and \
                    toks[lo - 2][0] == 'id' and \
                    (lo - 3 < 0 or toks[lo - 3][1] not in ('->', '.')):
                taint[toks[lo - 2][1]] = (root, None)
                return j
            # `ac->env = env` -- stored into a member that IS the env view.
            # Benign: any later read of that member is recognised as the env
            # root in its own right (ENV_MEMBER below).  The first cut let
            # this fall into the alias rule above, because the member name is
            # itself `env`, and silently produced an EMPTY footprint for
            # helper_fldenv -- which loads the entire x87 environment.
            if root == 'env' and prev == '=' and lo - 2 >= 0 and \
                    toks[lo - 2][1] == ENV_MEMBER and \
                    lo - 3 >= 0 and toks[lo - 3][1] in ('->', '.'):
                return j
            if root == 'env':
                raise Refusal('env escapes into an expression this reader '
                              'does not follow (prev=%r next=%r)'
                              % (prev, nxt), fname)
            if root in ('cpu', 'carrier'):
                return j
            self.arg_dir[root] = self.arg_dir.get(root, 0) | (RD | WR)
            return j
        if root == 'env':
            self._note_env(field, d, '%s:%d' % loc[i], var_index)
        elif root in ('cpu', 'carrier'):
            pass            # not a CPUArchState member: outside the universe
        else:
            self.arg_dir[root] = self.arg_dir.get(root, 0) | d
        return j

    def _note_env(self, field, d, where, var_index=False):
        """Record one CPUArchState access, at the one place they are recorded.

        @field is either a member name or `member[N]` with N the constant the
        source wrote.  @var_index says the subscript was NOT a constant, so
        the range recorded is the WHOLE array and the reader could not narrow
        it -- that fact is kept, because a consumer replacing its own list
        with this one has to know the difference between "these registers"
        and "somewhere in this file".
        """
        self.env_fields[field] = self.env_fields.get(field, 0) | d
        self.where.setdefault(field, where)
        if var_index:
            self.env_unbounded.add(field)

    def _scalar_roots(self, u, args):
        """Actual arguments that are a bare scalar this frame can name."""
        toks = u.toks
        out = {}
        cur = self._sframe[-1]
        for ai, grp in enumerate(args):
            if len(grp) == 1:
                t = toks[grp[0]]
                if t[0] == 'id' and t[1] in cur:
                    out[ai] = cur[t[1]]
        return out

    def _addr_root(self, u, grp):
        """The one helper argument the address expression is built from.

        `arg2` names it directly and `arg2 + 1 * dir` names it through
        arithmetic; both are the same argument and both are accepted.  An
        expression naming NO argument -- a MOPS helper addresses through
        env->xregs[], not through anything it was passed -- and one naming
        TWO are both reported as UNSTATED rather than resolved by preference,
        because the wrong register in an address mask is worse than none.
        """
        cur = self._sframe[-1]
        found = set()
        for k in grp:
            kind, txt = u.toks[k]
            if kind == 'id' and txt in cur:
                found.add(cur[txt])
        return found.pop() if len(found) == 1 else None

    def _guest_access(self, u, i, acc, args, fname):
        d, size = acc
        if self._in_acc:
            # Already inside an access primitive's own body: the same access,
            # seen a second time one level down.  Recording it again would
            # turn one access into two.
            return
        addr = self._addr_root(u, args[1]) if len(args) > 1 else None
        data = None
        if (d & WR) and len(args) > 2:
            data = self._addr_root(u, args[2])
        key = (d, addr)
        prev = self.mem_acc.get(key)
        if prev is None:
            self.mem_acc[key] = dict(dir=d, addr=addr, data=data, size=size,
                                     unbounded=False, n=1,
                                     where='%s:%d' % u.loc[i])
        else:
            # A second site of the same direction through the same argument.
            # The number of accesses is then not one, and this reader does not
            # try to count it: helper_swr stores one to four bytes depending
            # on the address's alignment, and a count read off the static
            # sites would be a number nothing measured.
            prev['n'] += 1
            prev['unbounded'] = True
            if prev['size'] != size:
                prev['size'] = 0
            if prev['data'] != data:
                prev['data'] = None

    def _fn_roots(self, u, args, taint):
        """Actual arguments that NAME a function these units define.

        The binding is only ever read off a call site that wrote the name
        down, which is what makes it a derivation rather than a guess: a
        `ri->stepfn` has no such site and gets none.  A parameter already
        bound in the CALLER's frame is forwarded, so a pointer handed two
        levels down keeps its concrete callee.
        """
        out = {}
        for ai, grp in enumerate(args):
            if len(grp) != 1:
                continue
            kind, txt = u.toks[grp[0]]
            if kind != 'id' or txt in taint:
                continue
            fwd = self._fnframe[-1].get(txt)
            if fwd is not None:
                out[ai] = fwd
            elif self.lookup(txt)[1] is not None:
                out[ai] = txt
        return out

    def _call(self, u, i, cp, taint, depth, fname):
        toks = u.toks
        callee = toks[i][1]
        # A call through a parameter the caller bound to a named function is
        # a call to that function.  Substituted before anything else looks at
        # the name, so lookup(), the access-primitive table and the refusal
        # all see the concrete callee.
        callee = self._fnframe[-1].get(callee, callee)
        # split the actual arguments
        args, cur, d = [], [], 0
        for k in range(i + 2, cp):
            t = toks[k][1]
            if t in '([{':
                d += 1
            elif t in ')]}':
                d -= 1
            if t == ',' and d == 0:
                args.append(cur); cur = []
            else:
                cur.append(k)
        if cur:
            args.append(cur)

        cu, cf = self.lookup(callee)
        pass_roots = {}
        acc = _acc_of(callee)
        for ai, grp in enumerate(args):
            if not grp:
                continue
            texts = [toks[k][1] for k in grp]
            # a bare tainted root passed straight through
            if len(texts) == 1 and texts[0] in taint:
                pass_roots[ai] = taint[texts[0]][0]
                continue
            if grp[0] in self.pending_derived:
                pass_roots[ai] = self.pending_derived[grp[0]]
                continue
            if len(grp) > 1 and grp[0] in self.pending_derived:
                pass_roots[ai] = self.pending_derived[grp[0]]
                continue
            # Anything else -- a value read through the pointer, an address
            # of one of its members, the pointer inside a cast -- is left to
            # _scan's own walk into these same tokens, which classifies each
            # occurrence in its own context.  Deciding it a second time here
            # is how the first cut recorded every SOURCE of every SSE helper
            # as read-and-written: a fabricated write on every such
            # instruction.
        # `access_prepare(&ac, env, ...)` -- a local whose ADDRESS is handed
        # to the same call that receives the env root becomes an env CARRIER.
        # target/i386 writes the whole x87 memory-environment family this way:
        # helper_fldenv() fills an X86Access on its stack and then calls
        # do_fldenv(&ac, ...), which recovers the env as `ac->env`.  Without
        # following the carrier, do_fldenv() is never walked at all and
        # helper_fldenv -- which loads fpuc, fpus, fpstt and all eight
        # fptags -- comes out with an EMPTY footprint that the row would then
        # publish as EXACT.  Following it can only widen the answer or make
        # this reader refuse, never narrow it.
        if 'env' in pass_roots.values():
            for grp in args:
                if len(grp) == 2 and toks[grp[0]][1] == '&' and \
                        toks[grp[1]][0] == 'id':
                    taint.setdefault(toks[grp[1]][1], ('carrier', None))
        for ai, grp in enumerate(args):
            if ai in pass_roots:
                continue
            if len(grp) == 2 and toks[grp[0]][1] == '&' and \
                    toks[grp[1]][0] == 'id' and \
                    taint.get(toks[grp[1]][1], (None,))[0] == 'carrier':
                pass_roots[ai] = 'carrier'
        if acc and pass_roots.get(0) == 'env':
            self._guest_access(u, i, acc, args, fname)
        if pass_roots:
            if cf is None:
                if 'env' in pass_roots.values():
                    raise Refusal('env passed to %s(), not defined in this '
                                  'unit' % callee, fname)
                if 'carrier' in pass_roots.values():
                    self.cpu_escapes.append((callee, '%s:%d' % u.loc[i]))
                if 'cpu' in pass_roots.values():
                    # The CPUState view reached a function this unit does not
                    # define.  Not a refusal on its own -- CPUState is outside
                    # the model -- but that function CAN come back through
                    # cpu_env(), so the callee is NAMED and adjudicated by
                    # hand rather than assumed harmless.
                    self.cpu_escapes.append((callee, '%s:%d' % u.loc[i]))
                for r in pass_roots.values():
                    if r not in ('env', 'cpu', 'carrier'):
                        self.arg_dir[r] = self.arg_dir.get(r, 0) | (RD | WR)
                return
            self._pending_sroots = self._scalar_roots(u, args)
            self._pending_fnroots = self._fn_roots(u, args, taint)
            if acc:
                self._in_acc += 1
            try:
                self._walk(cu, callee, pass_roots, depth + 1)
            finally:
                self._pending_sroots = None
                if acc:
                    self._in_acc -= 1
