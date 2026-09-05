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
import os, re, sys

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
        self._guard = None
        self._has_goto = None

    # -- CONTROL, and the one question asked of it ------------------------
    #
    # THE ONLY THING THIS ANSWERS is "does this token stand on the function's
    # straight line, or under a condition".  It is asked of WRITES and of
    # nothing else, because the fact it supports is a DOMINATING write -- a
    # store that every path through the body performs before the read that
    # follows it.  A read needs no such property: a read is recorded wherever
    # it appears.
    #
    # It answers CONSERVATIVELY IN THE DIRECTION THAT KEEPS SOURCES.  Every
    # construct that can skip a statement marks the statement guarded, and a
    # construct this reader does not recognise leaves the token unmarked ONLY
    # when nothing in the scan could have put it under one -- `goto` and
    # labels defeat that reasoning entirely, so a body containing either is
    # reported and the dominance question is refused for the whole walk.
    # Losing a dominating write costs a source that is inert; inventing one
    # deletes a real dependency, which is the error direction this file
    # treats as disqualifying.
    def _stmt_end(self, k, n):
        """Index of the last token of the statement beginning at @k."""
        if k >= n:
            return n - 1
        if self.toks[k][1] == '{':
            m = self._match_fwd(k, '{', '}')
            return m if m >= 0 else n - 1
        d = 0
        while k < n:
            t = self.toks[k][1]
            if t in '([{':
                d += 1
            elif t in ')]}':
                if d == 0:
                    return k - 1
                d -= 1
            elif t == ';' and d == 0:
                return k
            k += 1
        return n - 1

    def _expr_end(self, k, n):
        """Index of the last token of the expression @k stands in."""
        d = 0
        while k < n:
            t = self.toks[k][1]
            if t in '([{':
                d += 1
            elif t in ')]}':
                if d == 0:
                    return k - 1
                d -= 1
            elif t == ';' and d == 0:
                return k
            k += 1
        return n - 1

    def _build_guard(self):
        toks = self.toks
        n = len(toks)
        marks = [0] * (n + 1)

        def mark(lo, hi):
            if lo <= hi and lo < n:
                marks[max(lo, 0)] += 1
                marks[min(hi + 1, n)] -= 1

        i = 0
        while i < n:
            t = toks[i][1]
            if t in ('if', 'while', 'for', 'switch') and \
                    i + 1 < n and toks[i + 1][1] == '(':
                cp = self._match_fwd(i + 1, '(', ')')
                if cp > 0:
                    se = self._stmt_end(cp + 1, n)
                    mark(cp + 1, se)
                    # ... and the `else` clause of an `if`, which is guarded
                    # by the negation of the same condition.
                    k = se + 1
                    if k < n and toks[k][1] == 'else':
                        mark(k, self._stmt_end(k + 1, n))
                    # AND KEEP SCANNING THE CONDITION ITSELF.  Jumping past
                    # the closing paren skipped every `&&`, `||` and `?:`
                    # inside a control expression, so a write in a
                    # short-circuit right-hand side -- `if (g() && (env->fpuc
                    # = 5))` -- was left unmarked and read as unconditional.
                    # Marks are counted, so a nested construct marking the
                    # same span again is harmless.
                    i += 1
                    continue
            if t == 'do':
                # The body runs at least once, but the reader does not follow
                # `continue`, so it is marked like any other controlled
                # statement.  Conservative in the keeping direction.
                mark(i + 1, self._stmt_end(i + 1, n))
            elif t == '?' or t == '&&' or t == '||':
                # The right-hand side of a short-circuit, and both arms of a
                # conditional expression, are evaluated conditionally.
                mark(i, self._expr_end(i, n))
            i += 1
        run = 0
        g = [False] * n
        for k in range(n):
            run += marks[k]
            g[k] = run > 0
        self._guard = g

    def stmt_end_from(self, i):
        """Index of the last token of the statement token @i is inside."""
        return self._stmt_end(i, len(self.toks))

    def guarded(self, i):
        if self._guard is None:
            self._build_guard()
        return self._guard[i] if 0 <= i < len(self._guard) else True

    def has_goto(self, fname):
        """A body with a `goto` or a label: the straight line is not one."""
        if self._has_goto is None:
            self._has_goto = {}
        if fname in self._has_goto:
            return self._has_goto[fname]
        _params, brace, end, _loc = self.funcs[fname]
        toks = self.toks
        bad = False
        for k in range(brace + 1, end):
            if toks[k][1] == 'goto':
                bad = True
                break
            # `name :` at statement position is a label.  A `case`/`default`
            # colon and the `?:` colon are excluded by their own keywords and
            # by the preceding token.
            if toks[k][1] == ':' and k > brace + 1 and toks[k - 1][0] == 'id' \
                    and toks[k - 2][1] in (';', '{', '}', ':') \
                    and toks[k - 1][1] not in ('default',):
                bad = True
                break
        self._has_goto[fname] = bad
        return bad

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

    def _match_bwd(self, i, open_t, close_t):
        """Index of the OPENING token matching the closer at @i, or -1."""
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


#
# THE THREE STANDARD FUNCTIONS WHOSE POINTER DIRECTIONS ARE WRITTEN DOWN.
#
# An undefined callee makes this reader widen every pointer it was handed to
# READ AND WRITTEN, because it cannot see what the callee does.  For memset,
# memcpy and memmove it does not have to see: C 7.24.6 states the direction
# of each parameter, and the statement is as much a fact about the source as
# a definition would be.  QEMU's own SVE predicate writer is the reason this
# is not a convenience --
#
#     static uint32_t do_zero(ARMPredicateReg *d, intptr_t oprsz)
#     { memset(d, 0, sizeof(ARMPredicateReg)); return PREDTEST_INIT; }
#
# -- so every helper that begins by zeroing its destination predicate had
# that destination widened to a READ by the widening alone, and HELPER(sve_
# whilel) then published the register it overwrites as one of its sources.
# The widening is this reader saying it does not know; here it does.
#
# NOTHING ELSE IS ADDED.  A function whose direction is not stated by the
# standard keeps the widening, which is the safe answer.
# AND IT IS DECIDED BY THE NAME, BEFORE ANY BODY IS LOOKED UP.  On a host
# with _FORTIFY_SOURCE the preprocessed unit CARRIES a body for memset --
# /usr/include/.../bits/string_fortified.h:58 --
#
#     memset(void *__dest, int __ch, size_t __len)
#     { return __builtin___memset_chk(__dest, __ch, __len,
#                                     __builtin_dynamic_object_size(__dest, 0)); }
#
# and walking it hands __dest to two undefined builtins, which widens the
# pointer straight back to READ AND WRITTEN.  That body is the HOST's libc
# headers, not QEMU's source, and following it puts the build machine's
# fortify implementation into the emulator's dataflow model.  The standard's
# statement is the fact; the wrapper is not.
MEM_PRIM = {
    'memset':  {0: WR},
    'memcpy':  {0: WR, 1: RD},
    'memmove': {0: WR, 1: RD},
    '__builtin_memset':  {0: WR},
    '__builtin_memcpy':  {0: WR, 1: RD},
    '__builtin_memmove': {0: WR, 1: RD},
    '__builtin___memset_chk':  {0: WR},
    '__builtin___memcpy_chk':  {0: WR, 1: RD},
    '__builtin___memmove_chk': {0: WR, 1: RD},
    # Neither a load nor a store: these ask how large the object a pointer
    # designates is, which is answered from the pointer's provenance.
    '__builtin_object_size':         {0: 0},
    '__builtin_dynamic_object_size': {0: 0},
}


#
# THE DIRECTION A FUNCTION'S OWN BODY STATES, WRITTEN DOWN AT THE SITE.
#
# MEM_PRIM above is the same idea with the C standard as its authority.  This
# table's authority is QEMU's source, quoted: an entry names the function, the
# parameter, the direction, and the LINES that state it, and it is accepted
# only where the mechanical walk already reached a SUPERSET of it.  It can
# therefore delete an over-approximation and can never invent an access.
#
# It exists because two shapes defeat a reader that works one token at a time,
# and both of them assemble a WHOLE-REGISTER WRITE OUT OF PIECES:
#
#   HELPER(sve_whileg) writes its predicate with three loops that between
#   them cover every word of it, and predtest_ones() then reads it whole.  No
#   single store states an extent, so the read cannot be recognised as a read
#   of what this same call just wrote, and WHILEGE published Pd as a source of
#   itself.
#
#   sve_ldff1_z writes its destination on every path before it returns -- the
#   all-false predicate path memsets the register whole; every other path
#   loads one element and swap_memzero()s the prefix and the suffix around it
#   -- but the memset is inside an `if`, and a conditional whole-pointee write
#   keeps its widening for the reason MEM_PRIM's own comment gives.
#
# In both the register is a DESTINATION and nothing else, which is what the
# architecture says too: SVE first-fault gather loads are ZEROING-predicated,
# so the inactive elements of Zt are zeroed rather than preserved and no value
# of Zt can reach the result.  QEMU's helper reads the POINTER (the `vd == vm`
# overlap check) and never the pointee.
#
# A STATEMENT THAT CHANGES NOTHING IS REPORTED, NOT KEPT QUIETLY.  If the walk
# already derived exactly what the entry states, the entry is DEAD -- either
# the defect it was written for is gone or it never fired -- and it is named
# in the row and counted by the caller, which is the same treatment the
# allowlists' dead-rule detector gives.
_INDEX = (
    {0: WR},
    '../target/arm/tcg/sve_helper.c:2385-2423',
    'The whole body is `for (i = 0; i < opr_sz; i += 1) d[H1(i)] = start + '
    'i * incr;` over the destination\'s own element type, so every element '
    'of Zd is assigned and none of them is read.  INDEX is unpredicated.')

SITE_DIR = {
    'sve_ldff1_z': (
        {1: WR},
        '../target/arm/tcg/sve_helper.c:6946-6976',
        'Every path through the body writes the whole of vd before it '
        'returns: the empty-predicate path memsets reg_max bytes, and on '
        'every other path tlb_fn() writes the first active element while '
        'swap_memzero() zeroes the prefix below it and the suffix above it. '
        'The only use of vd that is not a write is the pointer comparison '
        '`vd == vm`, which reads the pointer and not the register.'),
    'helper_sve_whileg': (
        {0: WR},
        '../target/arm/tcg/sve_helper.c:4177-4199',
        'count == 0 zeroes the predicate whole; otherwise the three loops '
        'cover every word of it -- `for (i = (oprsz-1)/8; i > invcount/64; '
        '--i)`, the single word at i, and `while (--i >= 0)` -- so the '
        'predtest_ones() that follows reads only what this call just wrote.'),
    'helper_sve_index_b': _INDEX, 'helper_sve_index_h': _INDEX,
    'helper_sve_index_s': _INDEX, 'helper_sve_index_d': _INDEX,
}


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
        # THE SELF-RELOAD LEDGER.  One entry per recorded access, in the
        # order the walk reached it, keyed by the same name the footprint is
        # keyed by: ('env', field) or ('arg', root).  See _dominated_writes().
        self._seq = 0
        self.order = {}
        # A frame reached under a condition: everything it records is
        # conditional, whatever the callee's own body looks like.
        self._fguard = [False]
        # WRITES WAITING FOR THEIR OWN RIGHT-HAND SIDE.  See _defer_write().
        self._defer = [[]]
        # Set when any body in the walk carries a `goto` or a label, which
        # makes "before" a statement about token order and not about
        # execution.  The whole dominance question is then refused.
        self.order_refused = False
        self._pending_fnroots = None
        # SITE_DIR's ledger: what fired, and what fired but changed nothing.
        self.stated = []
        self.stated_dead = []

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
        self._defer.append([])
        # A STATED DIRECTION IS SCOPED TO THE FRAME IT IS A STATEMENT ABOUT.
        # What the root already carried when the walk entered here is kept,
        # so an access made somewhere else in the helper is never deleted by
        # a statement about this body.
        stated = SITE_DIR.get(fname)
        before = {}
        if stated:
            for pi in stated[0]:
                r = roots.get(pi)
                if r is not None and r not in ('env', 'cpu', 'carrier'):
                    before[pi] = (r, self.arg_dir.get(r, 0))
        try:
            self._scan(u, brace, end, taint, depth, fname)
        finally:
            self._flush_defer(len(u.toks) + 1)
            self._defer.pop()
            self._sframe.pop()
            self._fnframe.pop()
        if stated:
            self._apply_stated(fname, stated, before)

    def _apply_stated(self, fname, stated, before):
        dirs, where, why = stated
        for pi, (r, prior) in sorted(before.items()):
            got = self.arg_dir.get(r, 0)
            reached = got & ~prior
            want = dirs[pi]
            if want & ~reached:
                # The entry claims an access the walk never reached.  It is
                # not a narrowing of a measurement, it is an assertion over
                # one, and this reader does not make those.
                raise Refusal('SITE_DIR %s param %d states %d, which the walk '
                              'did not reach (%d)' % (fname, pi, want, reached),
                              fname)
            self.arg_dir[r] = prior | want
            tag = '%s:%d=%d @%s' % (fname, pi, want, where)
            if reached == want:
                self.stated_dead.append(tag)
            else:
                self.stated.append(tag)

    def _scan(self, u, brace, end, taint, depth, fname):
        toks, loc = u.toks, u.loc
        i = brace + 1
        while i < end:
            self._flush_defer(i)
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
            self._rebind(taint, toks[lo - 2][1], newroot, u, lo, fname)
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
                self._note_env(field, d, '%s:%d' % u.loc[j - 1], var_index,
                               self._uncond(u, j - 1, fname), u, j - 1, fname)
            return k
        # `env_cpu(env)->field` -- a CPUState member, outside this model.
        if nxt in ('->', '.'):
            k, _first, field, _var = self._path_end(u, j - 1, end)
            return k
        if newroot == 'env':
            raise Refusal('the env view escapes into an expression this '
                          'reader does not follow', fname)
        return j

    def _cast_deref(self, u, lo, j):
        """`*(T *)root` and `*(T *)(root + off)` -- an ACCESS OF THE POINTEE.

        Returns the index just past the whole dereference, or None.

        THE POINTER IS NOT WHAT IS BEING ASSIGNED.  `*(uint64_t *)vd = l` has
        the token shape of `vd = l` once the cast is skipped, and the rule
        that ends a taint on `p = ...` claimed it: HELPER(sve_rev_p) reassigns
        nothing and writes its whole destination predicate through that line
        (../target/arm/tcg/sve_helper.c:3325), and the row came out with NO
        ACCESS TO vd AT ALL -- a destination deleted, silently, by a rule
        meant for a different statement.

        The offset form is how QEMU writes one element of a vector register:
        `*(TYPEE *)(vd + H(reg_off)) = val` is the body of every SVE load
        primitive (../target/arm/tcg/sve_ldst_internal.h:44), and reading it
        as an escape widened the destination of every one of them to a source
        as well.
        """
        toks = u.toks
        # * ( T * ) root
        if lo > 0 and toks[lo - 1][1] == ')':
            m = u._match_bwd(lo - 1, '(', ')')
            if m > 0 and toks[m - 1][1] == '*':
                return j
        # * ( T * ) ( root <op> ... )   -- the root inside the operand.
        # Walked OUTWARD through the nesting, because H1_4(x) expands to (x)
        # and puts a second pair of parentheses between the cast and the root.
        at = lo
        for _ in range(4):
            k, d = at - 1, 0
            while k >= 0:
                t = toks[k][1]
                if t in (';', '{', '}', ','):
                    return None
                if t == ')':
                    d += 1
                elif t == '(':
                    if d == 0:
                        break
                    d -= 1
                k -= 1
            if k < 1:
                return None
            if toks[k - 1][1] == ')':
                m = u._match_bwd(k - 1, '(', ')')
                if m > 0 and toks[m - 1][1] == '*':
                    cl = u._match_fwd(k, '(', ')')
                    if cl > 0:
                        return cl + 1
                return None
            if toks[k - 1][1] != '(':
                return None
            at = k
        return None

    def _rebind(self, taint, name, newroot, u, i, fname):
        """`x = <root>` -- x designates @newroot from here on.

        A NAME THAT MAY STILL DESIGNATE THE ROOT IT HELD IS NOT FOLLOWED.
        The taint map gives a name one root, so a CONDITIONAL rebinding --

            if (unlikely(vd == vn0)) {
                vn0 = memcpy(&scratch, vn0, oprsz);
                if (vd == vn1) { vn1 = vn0; }
            }

        at ../target/arm/tcg/sve_helper.c:3008 -- cannot be represented: on
        the path that did not take it, `vn1` is still the second table
        register, and every access do_tb_b() then makes through that name was
        being recorded against the FIRST one alone.  The root that may still
        be there is widened to read-and-written, which is this reader saying
        it does not know, and is the direction it says it in everywhere else.
        """
        old = taint.get(name)
        if old is not None and old[0] != newroot and \
                not self._uncond(u, i, fname):
            r = old[0]
            if r not in ('env', 'cpu', 'carrier'):
                self.arg_dir[r] = self.arg_dir.get(r, 0) | (RD | WR)
                self._note_order(('arg', r), RD | WR, False)
        taint[name] = (newroot, None)

    def _access(self, u, i, end, taint, fname):
        toks, loc = u.toks, u.loc
        root, off = taint[toks[i][1]]
        if root == 'env' and off is not None:
            return self._env_ptr_access(u, i, end, taint, off, fname)
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

        # `*(T *)p = v` / `x = *(T *)(p + off)` -- through the pointer, and
        # therefore an access of what it designates.  Checked BEFORE the
        # reassignment rule below, whose token shape it otherwise matches.
        cd = None
        if field is None and root not in ('env', 'cpu', 'carrier'):
            cd = self._cast_deref(u, lo, j)
        if cd is not None:
            nx = toks[cd][1] if cd < end else ''
            if nx == '=':
                dd = WR
            elif nx in ASSIGN_OPS and nx != '==' or nx in ('++', '--'):
                dd = RD | WR
            else:
                dd = RD
            if prev == '&':
                dd = RD | WR
            if dd & WR:
                # A PREDICATED OR NARROWING STORE LEAVES THE REGISTER
                # STANDING: every SVE merging form is
                # `if (pg & 1) *(TYPE *)(vd + H(i)) = ...` and the elements
                # the predicate did not select keep the value Zd had, which is
                # a read of it.  Same reason as the subscript form above.
                dd = RD | WR
            self.arg_dir[root] = self.arg_dir.get(root, 0) | dd
            # ONE ELEMENT OF A REGISTER: it names no extent, so it does not
            # dominate, for the same reason the member form does not.
            self._note_order(('arg', root), dd, False)
            return j

        # `p = <something>` -- an assignment to the tainted local itself.
        if field is None and j == i + 1 and nxt == '=':
            if root == 'env':
                raise Refusal('env reassigned', fname)
            # ONLY AN UNCONDITIONAL REASSIGNMENT ENDS THE TAINT.  On a path
            # that does not take the assignment the name still designates the
            # root, so dropping it there loses every access made through it
            # afterwards.  SVE's gather loads are the shape:
            #
            #     if (unlikely(vd == vm)) { vm = memcpy(&scratch, vm, reg_max); }
            #     ...
            #     addr = base + (off_fn(vm, reg_off) << scale);
            #
            # -- and with the taint dropped at the `vm =` the INDEX VECTOR's
            # own reads, every one of them after that line, were recorded
            # against nothing.  Keeping it is also the over-approximating
            # direction: where the assignment did happen the name designates
            # a copy of the same bytes.
            if self._uncond(u, i, fname):
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

        if field is None and root not in ('env', 'cpu', 'carrier') \
                and j > i + 1 and toks[i + 1][1] == '[':
            # `d[i] = v` -- A SUBSCRIPT OF THE ROOT IS AN ACCESS OF THE ROOT.
            #
            # _path_end() consumes the subscript and reports no member, which
            # is right -- there is no member -- and the escape rule below then
            # read the absence of a name as "this reader does not know what
            # happened".  It does know: `d[i]` designates bytes of the
            # pointee, exactly as `d->p[i]` does, and the operator that
            # follows states the direction the same way.  Reading it as an
            # escape widened every one of them to READ AND WRITTEN, and
            # HELPER(sve_index_b) -- whose whole body is
            #
            #     uint8_t *d = vd;
            #     for (i = 0; i < opr_sz; i += 1) { d[H1(i)] = start + i * incr; }
            #
            # -- published the register it fills as one of its own sources.
            # The subscript's own reads are already recorded by _path_end();
            # what is added here is the access through it.
            #
            # THE WRITE STILL DOES NOT DOMINATE.  It names one element and the
            # key is the pointer, which is the reason the member form carries
            # the same False below.
            if d & WR:
                # A STORE THROUGH THE POINTER KEEPS ITS WIDENING.  It names
                # bytes, not a register, and nothing here measures how many:
                # `d[H1(i)] = v` under a loop may cover the register and
                # `*(TYPEN *)(vd + HN(i + sizeof(TYPEN)))` -- SVE2's narrowing
                # TOP forms, ../target/arm/tcg/sve_helper.c:2280 -- covers
                # exactly half of it and leaves the other half standing.  The
                # reader cannot tell the two apart, so the write stays a read
                # as well and the difference is stated per site by SITE_DIR.
                d = RD | WR
            self.arg_dir[root] = self.arg_dir.get(root, 0) | d
            self._note_order(('arg', root), d, False)
            return j

        if field is None and not escaped and root != 'env' \
                and (nxt in ('==', '!=') or prev in ('==', '!=')):
            # `if (vd == vm)` -- A POINTER COMPARISON IS NOT AN ACCESS.
            #
            # It reads the POINTER, which is a value the caller passed by
            # register, and never the pointee.  The escape rule below counted
            # it as both a read and a write of the register the pointer
            # designates, and SVE's overlap check --
            # `if (unlikely(vd == vm)) { vm = memcpy(&scratch, vm, reg_max); }`
            # at ../target/arm/tcg/sve_helper.c:6958 -- put the destination of
            # every first-fault gather load on its own source list.
            return j

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
                self._rebind(taint, toks[lo - 2][1], root, u, lo, fname)
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
            self._note_order(('arg', root), RD | WR, False)
            return j
        if root == 'env':
            # `uint64_t *ffr = env->vfp.pregs[16].p;` -- A LOCAL POINTER BOUND
            # TO AN ENV MEMBER STILL DESIGNATES THAT MEMBER.
            #
            # abff4724d4 taught this reader `d[i]` for a helper PARAMETER and
            # left the same subscript unread when the pointer is a LOCAL bound
            # here.  record_fault() (../target/arm/tcg/sve_helper.c:6160) is
            # the worked example and it is not a corner:
            #
            #     uint64_t *ffr = env->vfp.pregs[FFR_PRED_NUM].p;   <- 6162
            #     ffr[i / 64] &= MAKE_64BIT_MASK(0, i & 63);        <- RMW
            #     ffr[i / 64] = 0;                                  <- WRITE
            #
            # The binding line is the only one the reader saw, it is a READ,
            # and so 38 rows over eleven SVE first-fault and non-fault load
            # mnemonics stated the FFR READ-ONLY -- while the wire correctly
            # published it as a destination of every one of them.  8,448
            # encodings were scored as walk-only cost against a write list
            # that was missing the write.
            #
            # THE BINDING LINE'S OWN READ IS KEPT.  For an ARRAY member the
            # expression yields an address and reads nothing, but for a
            # POINTER member it reads the pointer, and this reader has no
            # types to tell them apart; the read is the over-approximating
            # direction and it is the one taken everywhere else here.
            #
            # SCOPED TO A DECLARATION.  `T *name = env-><path>;` and nothing
            # else: a bare assignment to an existing name cannot be told from
            # an integer one without types, and a name that already designates
            # something is what _rebind() is for.
            if d == RD and field and prev == '=' and nxt == ';' and \
                    lo - 4 >= 0 and toks[lo - 2][0] == 'id' and \
                    toks[lo - 3][1] == '*' and toks[lo - 4][0] == 'id':
                taint[toks[lo - 2][1]] = ('env', field)
            self._note_env(field, d, '%s:%d' % loc[i], var_index,
                           self._uncond(u, i, fname), u, i, fname)
        elif root in ('cpu', 'carrier'):
            pass            # not a CPUArchState member: outside the universe
        else:
            self.arg_dir[root] = self.arg_dir.get(root, 0) | d
            # A WRITE THROUGH A POINTER MEMBER NEVER DOMINATES.  An env field
            # is keyed by its whole path, so a write and a read under the same
            # key are the same bytes; a pointer argument is keyed by the
            # POINTER, and `d->p[i] = bits` writes one element of a register
            # that predtest_ones() then reads whole.  HELPER(sve_whileg) is
            # exactly that shape and would come out written-only on the
            # strength of a single-element store.  Only a call that states an
            # EXTENT can cover the pointee, which is what MEM_PRIM does and
            # nothing here does.
            self._note_order(('arg', root), d, False)
        return j

    def _env_ptr_access(self, u, i, end, taint, field, fname):
        """A use of a local pointer that designates the env member @field.

        Same vocabulary as the parameter case in _access(), keyed on the
        MEMBER instead of on the pointer, because the member is what the
        wire publishes.  The directions are the same ones and for the same
        reasons:

          `p[x] = v`    a store through a pointer names bytes and no extent,
                        so it stays a read as well and does not dominate --
                        the reason SITE_DIR exists for the parameter form.
          `p == q`      a pointer comparison reads the pointer, never the
                        pointee, and is not an access at all.
          `p = ...`     an UNCONDITIONAL reassignment ends the binding; a
                        conditional one leaves the name possibly designating
                        the member still, so it is kept.
          anything else the pointer escapes into an expression this reader
                        does not follow, and an escape is read AND written.

        The index is a variable at every site this reaches, so the write is
        recorded as not covering: `ffr[i / 64] = 0` under a loop may cover
        the predicate and the reader cannot say that it does.
        """
        toks = u.toks
        j, _first, _f, var_index = self._path_end(u, i, end)
        prev = toks[i - 1][1] if i > 0 else ''
        nxt = toks[j][1] if j < end else ''
        bare = (j == i + 1)

        if bare and nxt == '=':
            if self._uncond(u, i, fname):
                taint.pop(toks[i][1], None)
            return j + 1
        if bare and prev != '&' and (nxt in ('==', '!=')
                                     or prev in ('==', '!=')):
            return j

        if nxt in ASSIGN_OPS and nxt != '==':
            d = WR if nxt == '=' else (RD | WR)
        elif nxt in ('++', '--') or prev in ('++', '--'):
            d = RD | WR
        else:
            d = RD
        if prev == '&' or bare:
            d = RD | WR
            var_index = True
        if d & WR:
            # A WRITE THROUGH A POINTER NAMES ONE ELEMENT AND NO EXTENT, so
            # it stays a read as well and it may not cover the member --
            # `ffr[i / 64] = 0` under a loop might and the reader cannot say
            # that it does.  Same reason the parameter form does not dominate.
            d = RD | WR
            var_index = True
        # A READ KEEPS THE INDEX THE PATH STATED.  `cr[1]` in
        # sve_vqm1_for_el_sm() is a constant subscript and forcing it unstated
        # would widen four vfp.zcr_el rows for no reason this rule has.
        self._note_env(field, d, '%s:%d' % u.loc[i], var_index,
                       self._uncond(u, i, fname), u, i, fname)
        return j

    def _uncond(self, u, i, fname):
        """Does this access stand on the straight line of the whole walk?"""
        if self._fguard[-1]:
            return False
        if u.has_goto(fname):
            self.order_refused = True
            return False
        return not u.guarded(i)

    def _defer_write(self, u, i, key, uncond, fname):
        """Sequence an assignment's WRITE after its own right-hand side.

        THE ORDER THE TOKENS ARE IN IS NOT THE ORDER THEY RUN IN.  A scan
        reaches the destination of `env->fpstt = (env->fpstt - 1) & 7` first
        and the source second, and C evaluates them the other way round.
        Recording the write at the token it appears on therefore made it
        DOMINATE a read that in fact happens before it, and the dominance
        rule then deleted a real dependency: FDECSTP, FINCSTP and fpush()
        each read the x87 stack-top pointer to step it, and each came out
        write-only.  That is the error direction this reader treats as
        disqualifying, and it was caught by the whole-table A/B rather than
        by inspection, which is why the check is here and not in a comment.

        So the entry is held until the scan has passed the end of the
        statement, and it is held PER FRAME: the callee a right-hand side
        calls runs before the assignment completes, and its own accesses
        must land first.
        """
        self._defer[-1].append((u.stmt_end_from(i), key, uncond))

    def _flush_defer(self, upto):
        lst = self._defer[-1]
        if not lst:
            return
        keep = []
        for end, key, uncond in lst:
            if end < upto:
                self._note_order(key, WR, uncond)
            else:
                keep.append((end, key, uncond))
        self._defer[-1] = keep

    def _note_order(self, key, d, uncond):
        """One access, in walk order, for the dominance question.

        @uncond says the access stands on the straight line of every body
        that leads to it.  It is meaningful only for a WRITE; a read is
        recorded wherever it appears and its own guard is irrelevant.
        """
        self.order.setdefault(key, []).append((self._seq, d, bool(uncond)))
        self._seq += 1

    def _note_env(self, field, d, where, var_index=False, uncond=False,
                  u=None, i=None, fname=None):
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
        key = ('env', field)
        cover = uncond and not var_index
        if (d & WR) and u is not None:
            # The read half lands now; the write half waits for the
            # right-hand side it is the destination of.
            if d & RD:
                self._note_order(key, RD, False)
            self._defer_write(u, i, key, cover, fname)
        else:
            self._note_order(key, d, cover)

    def self_reloaded(self):
        """The names whose every READ is of bytes this call already WROTE.

        A published source is a claim that the instruction's result can be
        changed by changing that register.  It cannot be, when every read of
        the register in the closed body is preceded on every path by a write
        of the same bytes by the same call: overwrite the register with
        anything and the helper's answer is identical, because the value it
        reads is the one it just stored.  QEMU writes exactly that shape in
        two independent places --

            cpu_set_fpuc(): `env->fpuc = fpuc` and then update_fp_status(),
            which re-derives the softfloat rounding mode by READING
            env->fpuc (target/i386/cpu.h:2730-2731);

            cpu_set_fpus(): `env->fpus = fpus & ~0x3800 & ~FPUS_B` and then
            `env->fpus |= env->fpus & FPUS_SE ? FPUS_B : 0`
            (target/i386/tcg/fpu_helper.c:2519-2520)

        -- and both put a register on the wire as a source of an instruction
        that overwrites it: FLDCW, FLDENV, LDMXCSR, VLDMXCSR.

        THE RULE IS ORDER PLUS DOMINANCE, and both halves are load-bearing.
        The dominating write must stand on the straight line of every body
        that led to it (see Unit.guarded and the frame guard), and it must
        come BEFORE the read in walk order -- a write after a read does not
        dominate it, and a write inside a loop whose read precedes it does
        not either.

        REFUSED WHOLESALE when any body in the walk carries a `goto` or a
        label: "before" is then a fact about tokens and not about execution.
        An unbounded array write is not a dominating write either -- it names
        no element, so it cannot be said to cover the element that is read.
        """
        if self.order_refused:
            return set()
        out = set()
        for key, entries in self.order.items():
            dom = None
            for seq, d, uncond in entries:
                if (d & WR) and uncond:
                    dom = seq
                    break
            if dom is None:
                continue
            if all(seq > dom for seq, d, _u in entries if d & RD):
                out.add(key)
        return out

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

        prim = MEM_PRIM.get(callee)
        cu, cf = self.lookup(callee)
        pass_roots = {}
        acc = _acc_of(callee)
        for ai, grp in enumerate(args):
            if not grp:
                continue
            texts = [toks[k][1] for k in grp]
            # a bare tainted root passed straight through
            if len(texts) == 1 and texts[0] in taint:
                # A LOCAL BOUND TO AN ENV MEMBER IS NOT THE ENV VIEW.  Its
                # taint says 'env' so the member can be named, but what is
                # passed here is a pointer to some bytes of one member, not
                # the whole CPUArchState -- and handing it on as the env root
                # reaches the refusal written for the view and aborts the
                # whole helper.  Left to _scan's own walk, which reads the
                # bare occurrence as an escape and widens the member.
                if taint[texts[0]][1] is not None:
                    continue
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
        # A STATED DIRECTION SETTLES THE CALL.  Checked before the callee's
        # body, for the reason MEM_PRIM's own comment gives -- and never for
        # the env view, whose whole-struct footprint the name does not bound,
        # so that case falls through to the refusal it already had.
        # AND ONLY WHERE THE CALL ITSELF IS UNCONDITIONAL.  A memset the body
        # performs on ONE PATH says the bytes are written on that path; it
        # says nothing about the others, and on those the pointee keeps the
        # value it had -- which is a read of it.  HELPER(sve_brkn) is the
        # whole argument:
        #
        #     if (!last_active_pred(vn, vg, oprsz)) { do_zero(vd, oprsz); }
        #
        # BRKN zeroes its destination or LEAVES IT STANDING, and R17 states
        # what that is: "a merging form writes its destination whether or not
        # the governing predicate selects any element, because the
        # architecture defines the unselected elements as retaining their
        # previous value, which is a read-modify-write of the same register
        # and not an absence of one."  Narrowing it to write-only deleted
        # that dependency, and eight SVE gather loads whose every memset is
        # inside an `if` went the same way.  A conditional primitive
        # therefore keeps the widening it would otherwise replace.
        if prim is not None and pass_roots and \
                'env' not in pass_roots.values():
            uncond = self._uncond(u, i, fname)
            for ai, r in pass_roots.items():
                if r in ('cpu', 'carrier'):
                    continue
                d = prim.get(ai)
                if d is None:
                    self.arg_dir[r] = self.arg_dir.get(r, 0) | (RD | WR)
                    self._note_order(('arg', r), RD | WR, False)
                    continue
                if (d & WR) and not uncond:
                    # A CONDITIONAL WRITE DOES NOT COVER THE POINTEE, which is
                    # the whole of the argument above: on the path that did
                    # not take it the register keeps the value it had, and
                    # that is a read of it.
                    self.arg_dir[r] = self.arg_dir.get(r, 0) | (RD | WR)
                    self._note_order(('arg', r), RD | WR, False)
                    continue
                if d:
                    # A CONDITIONAL READ IS STILL ONLY A READ.  The argument
                    # for widening is about a register whose old value
                    # survives the call; it has nothing to say about a
                    # parameter the standard declares READ-ONLY, where not
                    # taking the branch means the call did not happen and no
                    # value was written by anyone.  Widening those made the
                    # SOURCE of every conditional memcpy a destination too --
                    # `if (unlikely(vd == vm)) { vm = memcpy(&scratch, vm,
                    # reg_max); }` at ../target/arm/tcg/sve_helper.c:6959 put
                    # the INDEX VECTOR of every SVE first-fault gather load on
                    # its own destination list.
                    self.arg_dir[r] = self.arg_dir.get(r, 0) | d
                    self._note_order(('arg', r), d, bool(d & WR) and uncond)
            return
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
                    if r in ('env', 'cpu', 'carrier'):
                        continue
                    self.arg_dir[r] = self.arg_dir.get(r, 0) | (RD | WR)
                    # An ESCAPE is not a stated direction.  The widening
                    # above is this reader saying it does not know, so it can
                    # neither dominate a later read nor be dominated by an
                    # earlier write: it is recorded conditional and carries a
                    # read, which keeps the source.
                    self._note_order(('arg', r), RD | WR, False)
                return
            self._pending_sroots = self._scalar_roots(u, args)
            self._pending_fnroots = self._fn_roots(u, args, taint)
            if acc:
                self._in_acc += 1
            # A CALL UNDER A CONDITION MAKES ITS WHOLE BODY CONDITIONAL.
            # cpu_set_fpuc() writes env->fpuc on its straight line and then
            # calls update_fp_status() from inside `if (tcg_enabled())`; the
            # reads in that callee are conditional even though they sit on
            # the callee's own straight line, and a write there could not
            # dominate anything.  The guard travels with the frame.
            self._fguard.append(self._fguard[-1] or u.guarded(i)
                                or u.has_goto(fname))
            try:
                self._walk(cu, callee, pass_roots, depth + 1)
            finally:
                self._fguard.pop()
                self._pending_sroots = None
                if acc:
                    self._in_acc -= 1


# ---------------------------------------------------------------------------
# SELFTEST -- the dominance rule, on bodies whose answer is written down.
#
# The rule deletes published sources, so every arm below states the shape and
# the answer it must give, and the SHAPES THAT MUST NOT NARROW outnumber the
# ones that must.  Two of them are here because the first cut got them wrong:
# `x = x - 1` (an assignment's destination is scanned BEFORE its source and
# runs after it -- FDECSTP, FINCSTP and fpush() each came out write-only) and
# a write through a pointer member (one element of a register does not cover
# the register HELPER(sve_whileg) then reads whole).
# ---------------------------------------------------------------------------
_SELFTEST = [
    # (name, body, expected env dirs, expected arg dirs)
    ('write_then_read_same_body',
     'void helper_t(CPUArchState *env) { env->fpuc = 5; f(env->fpuc); }',
     {'fpuc': WR}, {}),
    ('read_on_own_rhs',
     'void helper_t(CPUArchState *env) { env->fpstt = (env->fpstt - 1) & 7; }',
     {'fpstt': RD | WR}, {}),
    ('read_before_write',
     'void helper_t(CPUArchState *env) { f(env->fpuc); env->fpuc = 5; }',
     {'fpuc': RD | WR}, {}),
    ('write_guarded_by_if',
     'void helper_t(CPUArchState *env) { if (g()) { env->fpuc = 5; } '
     'f(env->fpuc); }',
     {'fpuc': RD | WR}, {}),
    ('read_guarded_after_write',
     'void helper_t(CPUArchState *env) { env->fpuc = 5; if (g()) '
     '{ f(env->fpuc); } }',
     {'fpuc': WR}, {}),
    ('write_in_else',
     'void helper_t(CPUArchState *env) { if (g()) h(); else env->fpuc = 5; '
     'f(env->fpuc); }',
     {'fpuc': RD | WR}, {}),
    ('write_in_loop',
     'void helper_t(CPUArchState *env) { for (i = 0; i < 4; i++) '
     '{ env->fpuc = 5; } f(env->fpuc); }',
     {'fpuc': RD | WR}, {}),
    ('write_in_shortcircuit_rhs',
     'void helper_t(CPUArchState *env) { if (g() && (env->fpuc = 5)) h(); '
     'f(env->fpuc); }',
     {'fpuc': RD | WR}, {}),
    ('write_in_conditional_arm',
     'void helper_t(CPUArchState *env) { x = g() ? (env->fpuc = 5) : 0; '
     'f(env->fpuc); }',
     {'fpuc': RD | WR}, {}),
    ('write_then_read_across_call',
     'static void inner(CPUArchState *e) { f(e->fpuc); }\n'
     'void helper_t(CPUArchState *env) { env->fpuc = 5; inner(env); }',
     {'fpuc': WR}, {}),
    ('write_then_guarded_call_reads',
     'static void inner(CPUArchState *e) { f(e->fpuc); }\n'
     'void helper_t(CPUArchState *env) { env->fpuc = 5; if (g()) inner(env); }',
     {'fpuc': WR}, {}),
    ('call_under_if_writes',
     'static void inner(CPUArchState *e) { e->fpuc = 5; }\n'
     'void helper_t(CPUArchState *env) { if (g()) inner(env); '
     'f(env->fpuc); }',
     {'fpuc': RD | WR}, {}),
    ('goto_refuses',
     'void helper_t(CPUArchState *env) { env->fpuc = 5; goto out; out: '
     'f(env->fpuc); }',
     {'fpuc': RD | WR}, {}),
    ('unbounded_index_does_not_cover',
     'void helper_t(CPUArchState *env) { env->fptags[i] = 0; '
     'f(env->fptags[j]); }',
     {'fptags': RD | WR}, {}),
    ('rmw_alone',
     'void helper_t(CPUArchState *env) { env->fpuc |= 1; }',
     {'fpuc': RD | WR}, {}),
    ('memset_arg_is_write_only',
     'static void z(P *d) { memset(d, 0, sizeof(P)); }\n'
     'void helper_t(void *vd) { P *d = vd; z(d); f(d->p[0]); }',
     {}, {0: WR}),
    ('memset_under_if_does_not_cover',
     'static void z(P *d) { memset(d, 0, sizeof(P)); }\n'
     'void helper_t(void *vd) { P *d = vd; if (g()) z(d); f(d->p[0]); }',
     {}, {0: RD | WR}),
    # HELPER(sve_brkn): the ONLY write is conditional and there is no read
    # after it, so nothing else can put the read back.  The unwritten path
    # leaves the register standing, which is a read of it.
    ('conditional_memset_only_keeps_the_read',
     'static void z(P *d) { memset(d, 0, sizeof(P)); }\n'
     'void helper_t(void *vd) { if (g()) z(vd); }',
     {}, {0: RD | WR}),
    ('conditional_memset_in_else_keeps_the_read',
     'static void z(P *d) { memset(d, 0, sizeof(P)); }\n'
     'void helper_t(void *vd) { if (g()) h(); else z(vd); }',
     {}, {0: RD | WR}),
    ('member_write_does_not_cover_pointee',
     'void helper_t(void *vd) { P *d = vd; d->p[i] = 1; f(d->p[j]); }',
     {}, {0: RD | WR}),
    ('memcpy_directions',
     'void helper_t(void *vd, void *vs) { memcpy(vd, vs, 8); }',
     {}, {0: WR, 1: RD}),
    ('undefined_callee_still_widens',
     'void helper_t(void *vd) { P *d = vd; opaque(d); f(d->p[0]); }',
     {}, {0: RD | WR}),
    # -- the pointer's own vocabulary -----------------------------------
    ('subscript_read_of_the_root_is_a_read',
     'void helper_t(void *vd) { unsigned char *d = vd; f(d[0]); }',
     {}, {0: RD}),
    ('subscript_write_of_the_root_keeps_the_widening',
     'void helper_t(void *vd) { unsigned char *d = vd; d[0] = 1; }',
     {}, {0: RD | WR}),
    ('store_through_a_cast_is_not_a_reassignment',
     'void helper_t(void *vd) { *(unsigned long *)vd = 1; }',
     {}, {0: RD | WR}),
    ('cast_deref_read_at_an_offset_is_a_read',
     'void helper_t(void *vn) { f(*(unsigned long *)(vn + 8)); }',
     {}, {0: RD}),
    ('pointer_comparison_is_not_an_access',
     'void helper_t(void *vd, void *vm) { if (vd == vm) { f(); } }',
     {}, {}),
    ('conditional_reassignment_keeps_the_taint',
     'void helper_t(void *vm) { char s[8]; if (g()) { vm = memcpy(s, vm, 8); }'
     ' f(*(unsigned long *)vm); }',
     {}, {0: RD}),
    ('conditional_rebind_widens_the_root_it_may_still_be',
     'void helper_t(void *vn0, void *vn1) { if (g()) { vn1 = vn0; }'
     ' f(*(unsigned long *)vn1); }',
     {}, {0: RD, 1: RD | WR}),
    ('conditional_read_only_primitive_is_still_a_read',
     'void helper_t(void *vs) { char s[8]; if (g()) { memcpy(s, vs, 8); } }',
     {}, {0: RD}),
    # -- SITE_DIR -------------------------------------------------------
    ('site_direction_narrows_what_the_walk_reached',
     'static void w(void *d) { opaque(d); }\n'
     'void helper_t(void *vd) { w(vd); }',
     {}, {0: WR}, {'w': ({0: WR}, 'test', 'test')}),
    ('site_direction_is_scoped_to_its_own_frame',
     'static void w(void *d) { opaque(d); }\n'
     'void helper_t(void *vd) { P *d = vd; f(d->p[0]); w(vd); }',
     {}, {0: RD | WR}, {'w': ({0: WR}, 'test', 'test')}),
    ('site_direction_cannot_invent_an_access',
     'static void w(void *d) { f(*(unsigned long *)d); }\n'
     'void helper_t(void *vd) { w(vd); }',
     {}, 'REFUSED', {'w': ({0: WR}, 'test', 'test')}),
    # -- a local pointer bound to an env member -------------------------
    # record_fault(), ../target/arm/tcg/sve_helper.c:6160, reduced.
    ('env_member_pointer_carries_its_writes',
     'void helper_t(CPUArchState *env) { unsigned long *p = env->fptags; '
     'p[i] = 0; }',
     {'fptags': RD | WR}, {}),
    ('env_member_pointer_rmw',
     'void helper_t(CPUArchState *env) { unsigned long *p = env->fptags; '
     'p[i] &= m; }',
     {'fptags': RD | WR}, {}),
    ('env_member_pointer_read_only_stays_a_read',
     'void helper_t(CPUArchState *env) { unsigned long *p = env->fptags; '
     'f(p[i]); }',
     {'fptags': RD}, {}),
    # NEGATIVE: a value assignment is not a binding, or every scalar read
    # into a local would become a write of the member.
    ('env_member_value_is_not_a_pointer_binding',
     'void helper_t(CPUArchState *env) { unsigned long v = env->fpuc; '
     'v = 3; f(v); }',
     {'fpuc': RD}, {}),
    # NEGATIVE: the reader has no types, so only a DECLARATION binds.
    ('env_member_bare_assignment_does_not_bind',
     'void helper_t(CPUArchState *env) { p = env->fptags; p[i] = 0; }',
     {'fptags': RD}, {}),
    # The pointer escaping is read AND written, the direction this reader
    # uses for everything it does not follow.
    ('env_member_pointer_escape_widens',
     'void helper_t(CPUArchState *env) { unsigned long *p = env->fptags; '
     'opaque(p); }',
     {'fptags': RD | WR}, {}),
    ('env_member_pointer_comparison_is_not_an_access',
     'void helper_t(CPUArchState *env) { unsigned long *p = env->fptags; '
     'if (p == q) { f(); } }',
     {'fptags': RD}, {}),
    # An UNCONDITIONAL reassignment ends the binding; the access after it
    # belongs to whatever the name designates then, which is not the member.
    ('env_member_pointer_reassignment_ends_the_binding',
     'void helper_t(CPUArchState *env) { unsigned long *p = env->fptags; '
     'p = other; p[i] = 0; }',
     {'fptags': RD}, {}),
]


def _selftest():
    import tempfile
    bad = 0
    for arm in _SELFTEST:
        name, body, want_env, want_arg = arm[:4]
        site = arm[4] if len(arm) > 4 else None
        with tempfile.NamedTemporaryFile('w', suffix='.i', delete=False) as fh:
            fh.write(body + '\n')
            path = fh.name
        try:
            u = Unit(path)
            params = u.funcs['helper_t'][0]
            roots = {}
            for k, (nm, star, _ni, text) in enumerate(params):
                if star:
                    roots[k] = 'env' if 'CPUArchState' in text else k
            a = Analysis(u)
            if site:
                SITE_DIR.update(site)
            try:
                a.run('helper_t', roots)
            except Refusal as e:
                if want_arg == 'REFUSED':
                    print('ok   %s' % name)
                    continue
                raise
            finally:
                for k in (site or ()):
                    SITE_DIR.pop(k, None)
            if want_arg == 'REFUSED':
                bad += 1
                print('FAIL %-36s expected a refusal' % name)
                continue
            rel = a.self_reloaded()
            got_env = {}
            for f, d in a.env_fields.items():
                got_env[f] = d & ~RD if ('env', f) in rel else d
            got_arg = {}
            for r, d in a.arg_dir.items():
                got_arg[r] = d & ~RD if ('arg', r) in rel else d
            ok = got_env == want_env and got_arg == want_arg
            if not ok:
                bad += 1
                print('FAIL %-36s env=%s want=%s  arg=%s want=%s'
                      % (name, got_env, want_env, got_arg, want_arg))
            else:
                print('ok   %s' % name)
        except Exception as e:                    # noqa: BLE001
            bad += 1
            print('FAIL %-36s raised %s: %s' % (name, type(e).__name__, e))
        finally:
            os.unlink(path)
    print('%d arm(s), %d failure(s)' % (len(_SELFTEST), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    import os
    if '--selftest' in sys.argv:
        sys.exit(_selftest())
    sys.exit('usage: canalyze.py --selftest')
