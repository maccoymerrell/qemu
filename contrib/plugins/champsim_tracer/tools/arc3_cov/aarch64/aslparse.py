"""Minimal ASL (Arm Specification Language) lexer + parser.

Covers the subset used by the A64 instruction pseudocode in the Arm MRA
release: decode / postdecode / execute sections and the shared function
library.  Anything outside the subset raises AslError, which the driver
counts rather than swallows.
"""
import re

class AslError(Exception):
    pass

KEYWORDS = {
    'if','then','else','elsif','for','to','downto','while','do','repeat','until',
    'case','of','when','otherwise','return','assert','constant','enumeration',
    'array','is','DIV','MOD','AND','OR','EOR','NOT','IN','UNKNOWN','UNDEFINED',
    'UNPREDICTABLE','SEE','IMPLEMENTATION_DEFINED','QUOT','REM','DIVIDE',
}

TYPES = {
    'integer','boolean','bits','bit','real','string','char','signal','type',
}

# ---------------------------------------------------------------- lexer

TOK_RE = re.compile(r"""
    (?P<ws>[ \t]+)
  | (?P<comment>//[^\n]*)
  | (?P<bitlit>'[^'\n]*')
  | (?P<str>"[^"\n]*")
  | (?P<hex>0x[0-9A-Fa-f_]+)
  | (?P<num>[0-9][0-9_]*(?:\.[0-9]+)?)
  | (?P<name>[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*)
  | (?P<op><<|>>|==|!=|<=|>=|&&|\|\||\+:|-:|[-+*/<>=!&|^~,;:.\[\]{}()])
""", re.X)


class Tok:
    __slots__ = ('kind', 'val', 'pos')
    def __init__(self, kind, val, pos):
        self.kind, self.val, self.pos = kind, val, pos
    def __repr__(self):
        return 'Tok(%s,%r)' % (self.kind, self.val)


def lex(text):
    """Tokenise one logical line.  Slice brackets are disambiguated here.

    `<` opens a bit-slice when it is glued to the preceding primary
    (`x<7:0>`, `PSTATE.<N,Z,C,V>`) and is a comparison otherwise
    (`n < 31`).  The matching `>` is found by scanning, so the parser
    never has to guess.
    """
    toks = []
    i, n = 0, len(text)
    slice_close = set()          # byte offsets of '>' that close a slice
    while i < n:
        m = TOK_RE.match(text, i)
        if not m:
            raise AslError('lex: %r at %d' % (text[i:i+20], i))
        kind = m.lastgroup
        val = m.group()
        if kind in ('ws', 'comment'):
            i = m.end()
            continue
        if kind == 'op' and val == '<':
            glued = (i > 0 and text[i-1] not in ' \t(,[=<>+-*/:')
            prev_ok = toks and (toks[-1].kind in ('name', 'num', 'hex', 'bitlit')
                                or toks[-1].val in (']', ')', '>', '.'))
            nxt = text[i+1] if i + 1 < n else ''
            if glued and prev_ok and nxt not in ' =':
                j = _match_angle(text, i)
                if j is not None:
                    slice_close.add(j)
                    toks.append(Tok('sopen', '<', i))
                    i = m.end()
                    continue
        if kind == 'op' and val == '>' and i in slice_close:
            toks.append(Tok('sclose', '>', i))
            i = m.end()
            continue
        toks.append(Tok(kind, val, i))
        i = m.end()
    return toks


def _match_angle(text, i):
    """Offset of the '>' matching the '<' at i, or None."""
    depth = 0
    j = i
    n = len(text)
    while j < n:
        c = text[j]
        if c == "'":
            k = text.find("'", j + 1)
            j = n if k < 0 else k + 1
            continue
        if c in '([':
            depth += 1
        elif c in ')]':
            if depth == 0:
                return None
            depth -= 1
        elif c == '<' and depth == 0:
            if j == i:
                pass
            else:
                # nested slice open only if glued
                if text[j-1] not in ' \t(,[=<>+-*/:':
                    k = _match_angle(text, j)
                    if k is None:
                        return None
                    j = k + 1
                    continue
        elif c == '>' and depth == 0:
            return j
        j += 1
    return None


# ---------------------------------------------------------------- AST
# Expressions are tuples: (op, ...)
#   ('num', int) ('bits', str) ('str', s) ('var', name)
#   ('bin', op, l, r) ('un', op, e) ('call', name, [args])
#   ('index', base, [args])            -- X[n, 64], Elem[v,e,s]
#   ('slice', base, [(hi,lo)|('range',e,e)|('plus',e,e)])
#   ('field', base, name)              -- a.b
#   ('cond', c, t, f)  ('tuple', [..])  ('unknown', typ)  ('set', [..])
#   ('concat', l, r)

class Parser:
    def __init__(self, toks):
        self.t = toks
        self.i = 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else Tok('eof', '', -1)

    def next(self):
        tk = self.peek()
        self.i += 1
        return tk

    def at(self, val):
        return self.peek().val == val and self.peek().kind in ('op', 'name', 'sopen', 'sclose')

    def eat(self, val):
        if not self.at(val):
            raise AslError('expected %r got %r' % (val, self.peek()))
        return self.next()

    def opt(self, val):
        if self.at(val):
            self.next()
            return True
        return False

    def done(self):
        return self.i >= len(self.t)

    # -- expressions, precedence climbing
    PREC = [
        ('||',), ('&&',), ('OR',), ('EOR',), ('AND',),
        ('==', '!='), ('<', '>', '<=', '>=', 'IN'),
        (':',),
        ('<<', '>>'),
        ('+', '-'),
        ('*', '/', 'DIV', 'MOD', 'QUOT', 'REM'),
        ('^',),
    ]

    def expr(self):
        if self.at('if'):
            self.next()
            c = self.expr()
            self.eat('then')
            a = self.expr()
            self.eat('else')
            b = self.expr()
            return ('cond', c, a, b)
        return self.binary(0)

    def binary(self, lvl):
        if lvl >= len(self.PREC):
            return self.unary()
        lhs = self.binary(lvl + 1)
        ops = self.PREC[lvl]
        while True:
            tk = self.peek()
            if tk.kind in ('op', 'name') and tk.val in ops:
                # ':' is concatenation; guard against the ':' inside slices
                self.next()
                rhs = self.binary(lvl + 1)
                lhs = ('bin', tk.val, lhs, rhs)
            else:
                return lhs

    def unary(self):
        tk = self.peek()
        if tk.val in ('-', '!', 'NOT', '~') and tk.kind in ('op', 'name'):
            self.next()
            return ('un', tk.val, self.unary())
        return self.postfix(self.primary())

    def primary(self):
        tk = self.next()
        if tk.kind == 'num':
            v = tk.val.replace('_', '')
            return ('num', float(v)) if '.' in v else ('num', int(v))
        if tk.kind == 'hex':
            return ('num', int(tk.val.replace('_', ''), 16))
        if tk.kind == 'bitlit':
            return ('bits', tk.val[1:-1].replace(' ', ''))
        if tk.kind == 'str':
            return ('str', tk.val[1:-1])
        if tk.val == '(':
            items = [self.expr()]
            while self.opt(','):
                items.append(self.expr())
            self.eat(')')
            return items[0] if len(items) == 1 else ('tuple', items)
        if tk.val == '{':
            items = []
            if not self.at('}'):
                items.append(self.rangeitem())
                while self.opt(','):
                    items.append(self.rangeitem())
            self.eat('}')
            return ('set', items)
        if tk.kind == 'name':
            if tk.val == 'UNKNOWN':
                return ('unknown', None)
            return ('var', tk.val)
        raise AslError('primary: %r' % (tk,))

    def rangeitem(self):
        e = self.expr()
        if self.at('..'):
            self.next()
            return ('rangeval', e, self.expr())
        return e

    def postfix(self, e):
        while True:
            nx = self.peek()
            if nx.kind == 'name' and nx.val in ('UNKNOWN', 'IMPLEMENTATION_DEFINED'):
                self.next()
                if self.peek().kind == 'str':
                    self.next()
                return ('unknown', None)
            tk = self.peek()
            if tk.val == '(' and tk.kind == 'op':
                self.next()
                args = []
                if not self.at(')'):
                    args.append(self.expr())
                    while self.opt(','):
                        args.append(self.expr())
                self.eat(')')
                name = e[1] if e[0] == 'var' else None
                e = ('call', name, args, e)
            elif tk.val == '[' and tk.kind == 'op':
                self.next()
                args = []
                if not self.at(']'):
                    args.append(self.expr())
                    while self.opt(','):
                        args.append(self.expr())
                self.eat(']')
                e = ('index', e, args)
            elif tk.kind == 'sopen':
                self.next()
                parts = []
                while True:
                    parts.append(self.sliceitem())
                    if not self.opt(','):
                        break
                if self.peek().kind != 'sclose':
                    raise AslError('slice not closed near %r' % (self.peek(),))
                self.next()
                e = ('slice', e, parts)
            elif tk.val == '.' and tk.kind == 'op':
                if self.peek(1).kind == 'sopen':
                    self.next()
                    continue
                self.next()
                nm = self.next()
                e = ('field', e, nm.val)
            else:
                return e

    def sliceitem(self):
        a = self.binary(0)
        if self.at(':'):
            # already consumed by ':' concat precedence?  binary() swallows ':'
            pass
        if a[0] == 'bin' and a[1] == ':':
            return ('range', a[2], a[3])
        if self.at('+:') or self.at('-:'):
            op = self.next().val
            b = self.binary(0)
            return ('plus' if op == '+:' else 'minus', a, b)
        return ('one', a)


# ---------------------------------------------------------------- statements
# ('assign', lhs, rhs) ('decl', typ, [names], rhs|None) ('if', [(c,body)], else)
# ('for', var, lo, hi, step, body) ('while', c, body) ('repeat', body, c)
# ('case', e, [(vals, body)], otherwise) ('call', expr) ('return', e|None)
# ('undefined',) ('unpred',) ('nop',) ('assert', e) ('see',)

ASSIGN_SPLIT = re.compile(r'(?<![=!<>+\-*/])=(?!=)')


def _depth(s):
    d, inq = 0, False
    for ch in s:
        if ch == "'":
            inq = not inq
            continue
        if inq:
            continue
        if ch in '([{':
            d += 1
        elif ch in ')]}':
            d -= 1
    return d


CONT_TAIL = ('&&', '||', '+', '-', '*', ',', ':', '==', '!=', '<', '>', '=')


def split_lines(text):
    out = []
    for raw in text.split('\n'):
        line = raw.rstrip()
        s = line.lstrip(' ')
        indent = len(line) - len(s)
        c = s.find('//')
        if c >= 0:
            s = s[:c].rstrip()
        if not s:
            continue
        if out:
            prev_i, prev_s = out[-1]
            if _depth(prev_s) > 0 or prev_s.endswith(CONT_TAIL):
                out[-1] = (prev_i, prev_s + ' ' + s)
                continue
        out.append((indent, s))
    return out


class StmtParser:
    def __init__(self, lines):
        self.lines = lines
        self.i = 0

    def parse_block(self, indent):
        body = []
        if self.i < len(self.lines) and self.lines[self.i][0] > indent:
            indent = self.lines[self.i][0]
        while self.i < len(self.lines):
            ind, txt = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent and body:
                raise AslError('unexpected indent: %r' % txt)
            body.extend(self.parse_stmt(ind))
        return body

    def sub_block(self, parent_indent):
        if self.i >= len(self.lines):
            return []
        ind = self.lines[self.i][0]
        if ind <= parent_indent:
            return []
        return self.parse_block(ind)

    def parse_stmt(self, indent):
        ind, txt = self.lines[self.i]
        self.i += 1
        return self._stmt_text(txt, indent)

    def _stmt_text(self, txt, indent):
        t = txt.strip()
        if t.endswith(';'):
            t = t[:-1].rstrip()
        if not t:
            return []
        w = t.split(None, 1)
        head = w[0]
        if head not in ('if', 'for', 'while', 'repeat', 'case', 'elsif', 'else'):
            pieces = [x for x in _split_semis(t) if x.strip()]
            if len(pieces) > 1:
                out = []
                for pc in pieces:
                    out.extend(self._stmt_text(pc.strip(), indent))
                return out
        rest = w[1] if len(w) > 1 else ''

        if head == 'if':
            return [self._if(t, indent)]
        if head == 'for':
            return [self._for(t, indent)]
        if head == 'while':
            c = rest
            if c.endswith('do'):
                c = c[:-2]
            return [('while', parse_expr(c), self.sub_block(indent))]
        if head == 'repeat':
            body = self.sub_block(indent)
            cond = None
            if self.i < len(self.lines) and self.lines[self.i][1].startswith('until'):
                cond = parse_expr(self.lines[self.i][1][5:].rstrip(';'))
                self.i += 1
            return [('repeat', body, cond)]
        if head == 'case':
            return [self._case(t, indent)]
        if head == 'return':
            return [('return', parse_expr(rest) if rest else None)]
        if head == 'assert':
            return [('assert', None)]
        if t in ('UNDEFINED',):
            return [('undefined',)]
        if t in ('UNPREDICTABLE',):
            return [('unpred',)]
        if head == 'SEE' or t.startswith('SEE('):
            return [('see',)]
        if t in ('EndOfInstruction()', 'EndOfInstruction'):
            return [('nop',)]
        if head in ('enumeration', 'type', 'array'):
            return [('nop',)]
        m = TYPE_RE.match(t)
        if m and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*(\s*,\s*[A-Za-z_][A-Za-z_0-9]*)*',
                              m.group(3).strip()):
            return [('decl', m.group(2), [x.strip() for x in m.group(3).split(',')], None)]
        return [self._simple(t)]

    def _if(self, t, indent):
        arms = []
        els = []
        cur = t
        while True:
            body_txt = None
            if cur.startswith('if ') or cur.startswith('elsif '):
                kw = 'if' if cur.startswith('if ') else 'elsif'
                after = cur[len(kw):].strip()
                # split on the LAST ' then' at depth 0
                idx = _find_then(after)
                if idx is None:
                    raise AslError('if without then: %r' % t)
                cond = after[:idx]
                body_txt = after[idx + 5:].strip()
                tail_else = None
                if body_txt:
                    body_txt, tail_else = _split_inline_else(body_txt)
                    body = self._inline(body_txt, indent)
                else:
                    body = self.sub_block(indent)
                arms.append((parse_expr(cond), body))
                if tail_else is not None:
                    if tail_else.startswith('elsif '):
                        cur = tail_else
                        continue
                    els = self._inline(tail_else, indent)
                    return ('if', arms, els)
            # look ahead for elsif/else at this indent
            if self.i < len(self.lines):
                nind, ntxt = self.lines[self.i]
                if nind == indent and ntxt.startswith('elsif '):
                    self.i += 1
                    cur = ntxt.rstrip(';')
                    continue
                if nind == indent and (ntxt == 'else' or ntxt.startswith('else ')):
                    self.i += 1
                    tail = ntxt[4:].strip().rstrip(';')
                    els = self._inline(tail, indent) if tail else self.sub_block(indent)
            break
        return ('if', arms, els)

    def _inline(self, txt, indent):
        # inline body may itself hold several ';'-separated statements
        out = []
        for piece in _split_semis(txt):
            piece = piece.strip()
            if piece:
                out.extend(self._stmt_text(piece, indent))
        return out

    def _for(self, t, indent):
        body_txt = t[3:].strip()
        m = re.match(r'([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(.*)$', body_txt)
        if not m:
            raise AslError('for: %r' % t)
        var = m.group(1)
        rng = m.group(2)
        step = 1
        if ' downto ' in rng:
            lo_s, hi_s = rng.split(' downto ', 1)
            step = -1
        elif ' to ' in rng:
            lo_s, hi_s = rng.split(' to ', 1)
        else:
            raise AslError('for range: %r' % t)
        body = self.sub_block(indent)
        return ('for', var, parse_expr(lo_s), parse_expr(hi_s), step, body)

    def _case(self, t, indent):
        subj = t[4:].strip()
        if subj.endswith(' of'):
            subj = subj[:-3]
        arms = []
        other = []
        if self.i >= len(self.lines):
            return ('case', parse_expr(subj), arms, other)
        cind = self.lines[self.i][0]
        if cind <= indent:
            return ('case', parse_expr(subj), arms, other)
        while self.i < len(self.lines):
            ind, txt = self.lines[self.i]
            if ind < cind:
                break
            if ind > cind:
                raise AslError('case arm indent: %r' % txt)
            if txt.startswith('when '):
                self.i += 1
                after = txt[5:].strip()
                vals, tail = _split_when(after)
                body = self._inline(tail, cind) if tail else self.sub_block(cind)
                arms.append((vals, body))
            elif txt.startswith('otherwise'):
                self.i += 1
                tail = txt[9:].strip().rstrip(';')
                other = self._inline(tail, cind) if tail else self.sub_block(cind)
            else:
                break
        return ('case', parse_expr(subj), arms, other)

    def _simple(self, t):
        m = _find_assign(t)
        if m is None:
            e = parse_expr(t)
            return ('call', e)
        lhs_txt, rhs_txt = t[:m].rstrip(), t[m+1:].strip()
        rhs = parse_expr(rhs_txt)
        typ, names, lhs = _parse_lhs(lhs_txt)
        if typ is not None:
            return ('decl', typ, names, rhs)
        return ('assign', lhs, rhs)


def _split_semis(txt):
    out, depth, cur = [], 0, ''
    inq = False
    for ch in txt:
        if ch == "'":
            inq = not inq
        if not inq:
            if ch in '([':
                depth += 1
            elif ch in ')]':
                depth -= 1
            elif ch == ';' and depth == 0:
                out.append(cur)
                cur = ''
                continue
        cur += ch
    out.append(cur)
    return out


def _split_inline_else(txt):
    depth, inq, i = 0, False, 0
    while i < len(txt):
        ch = txt[i]
        if ch == "'":
            inq = not inq
            i += 1
            continue
        if not inq:
            if ch in '([':
                depth += 1
            elif ch in ')]':
                depth -= 1
            elif depth == 0:
                for kw in ('else ', 'elsif '):
                    if txt.startswith(kw, i) and (i == 0 or not txt[i-1].isalnum()):
                        head = txt[:i].rstrip().rstrip(';')
                        return head, txt[i:].strip() if kw == 'elsif ' else txt[i+5:].strip()
        i += 1
    return txt, None


def _find_then(s):
    depth, inq = 0, False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "'":
            inq = not inq
        if not inq:
            if ch in '([':
                depth += 1
            elif ch in ')]':
                depth -= 1
            elif depth == 0 and s.startswith(' then', i) and (i + 5 >= len(s) or not s[i+5].isalnum()):
                return i
        i += 1
    return None


def _split_when(after):
    """`when '0x' body` / `when EL0, EL1` / `when '00'`."""
    depth, inq = 0, False
    i = 0
    while i < len(after):
        ch = after[i]
        if ch == "'":
            inq = not inq
            i += 1
            continue
        if not inq:
            if ch in '([':
                depth += 1
            elif ch in ')]':
                depth -= 1
            elif ch == ' ' and depth == 0:
                # end of the value list if what follows is not a continuation
                head = after[:i].rstrip()
                if not head.endswith(','):
                    return [parse_expr(v) for v in _split_commas(head)], after[i+1:].strip().rstrip(';')
        i += 1
    return [parse_expr(v) for v in _split_commas(after.rstrip(';'))], ''


def _split_commas(s):
    out, depth, cur, inq = [], 0, '', False
    for ch in s:
        if ch == "'":
            inq = not inq
        if not inq:
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
            elif ch == ',' and depth == 0:
                out.append(cur)
                cur = ''
                continue
        cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _find_assign(t):
    """Offset of the top-level '=' that is an assignment, or None."""
    depth, inq, ang = 0, False, 0
    i = 0
    while i < len(t):
        ch = t[i]
        if ch == "'":
            inq = not inq
            i += 1
            continue
        if inq:
            i += 1
            continue
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        elif ch == '<' and i > 0 and t[i-1] not in ' \t(,[=<>+-*/:':
            j = _match_angle(t, i)
            if j is not None:
                i = j + 1
                continue
        elif ch == '=' and depth == 0:
            if t[i-1] in '=!<>+-*/' or (i + 1 < len(t) and t[i+1] == '='):
                i += 1
                continue
            return i
        i += 1
    return None


TYPE_RE = re.compile(r'^(constant\s+)?(bits\s*\([^()]*(?:\([^()]*\)[^()]*)*\)|bit|integer|boolean|real|string|'
                     r'[A-Z][A-Za-z_0-9]*(?:Type)?)\s+([A-Za-z_].*)$')


def _parse_lhs(s):
    s = s.strip()
    if s.startswith('<') and s.endswith('>'):
        inner = _split_commas(s[1:-1])
        return None, None, ('tuple', [_parse_lhs(x)[2] for x in inner])
    if s.startswith('(') and s.endswith(')'):
        inner = _split_commas(s[1:-1])
        return None, None, ('tuple', [('discard',) if x.strip() == '-'
                                      else _parse_lhs(x)[2] for x in inner])
    m = TYPE_RE.match(s)
    if m:
        tail = m.group(3).strip()
        # a declaration only if the tail is a bare name list
        if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*(\s*,\s*[A-Za-z_][A-Za-z_0-9]*)*', tail):
            return m.group(2), [x.strip() for x in tail.split(',')], None
    return None, None, parse_expr(s)


def parse_expr(s):
    p = Parser(lex(s.strip()))
    e = p.expr()
    if not p.done():
        raise AslError('trailing %r in %r' % (p.peek(), s))
    return e


def parse_stmts(text):
    return StmtParser(split_lines(text)).parse_block(0)
