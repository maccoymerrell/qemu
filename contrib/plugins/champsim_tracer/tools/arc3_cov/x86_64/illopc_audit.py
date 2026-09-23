#!/usr/bin/env python3
"""
ARC 3 -- audit the UNREACHABLE rows QEMU refused at NO-TABLE-ENTRY(ILLOPC).

An UNREACHABLE verdict on such a row asserts two things at once, and each one
has its own way of being false:

  (a) THE BYTES ARE THE INSTRUCTION THE ROW NAMES.  A byte string no decoder
      accepts raises #UD whatever QEMU implements, and would be counted as
      "QEMU cannot run this instruction" when the truth is "this is not that
      instruction".  That defect was already found once in this arc: the
      denominator's encoding for XED_IFORM_UD0 was a two-byte `0fff` that
      XED's own decoder rejected.  This leg re-decodes every probe under XED,
      LLVM MC, iced-x86 and binutils objdump and requires the intended
      mnemonic AT THE PROBE'S OWN LENGTH from at least two of them.  A decoder
      that names a DIFFERENT instruction, or the same one at a different
      length, is a BROKEN PROBE and is fatal.  A decoder that simply does not
      know the opcode is not evidence either way and is counted separately.

  (b) QEMU REALLY HAS NO TABLE ENTRY.  "grep found nothing" is not a citation.
      This leg walks the probe's own prefix/map/opcode/ModRM shape through
      `target/i386/tcg/decode-new.c.inc` AS IT IS ON DISK and names the table,
      the slot, and what occupies it.  A slot that turns out to be OCCUPIED is
      fatal: QEMU has learnt to decode the bytes and the row must be re-probed
      rather than re-explained.

      A root or 0F slot is often not the answer but a POINTER: `X86_OP_GROUP1(
      group3, E,b)` hands the probe to a second table indexed by ModRM.reg,
      and whether QEMU decodes the bytes is decided there.  So the walk
      DESCENDS: it reads the group's own decoder out of the same file,
      evaluates its dispatch for this probe's ModRM, opcode bit and prefixes,
      and reports the SLOT, not the pointer.  A group decoder written in a
      shape the walk cannot read is REFUSED and fatal -- never resolved to the
      permissive answer, which is what reporting the pointer amounted to.

Both legs carry a control, because an instrument nobody has watched fail
vouches for nothing (R8.7).  Leg (a) is fired at a deliberately corrupted
probe and must report CONTRADICTED; leg (b) is fired at an encoding whose slot
IS occupied and must report OCCUPIED.  The controls run every time and their
failure is fatal.

The single-decoder case is real and is not swept up: an instruction so recent
that only the rank-1 reference knows it has one observation, not two.  Those
rows must be named in an --allow-single-source file, one `hex  reason` per
line, or the audit is RED.  The file is an admission of evidence strength, not
a waiver of the verdict.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import os
import re
import csv
import sys
import shutil
import argparse
import tempfile
import subprocess
import collections

QEMU_ROOT = os.environ.get('CST_QEMU_ROOT', '/mnt/md0/QEMU/qemu')
_DECODE = 'target/i386/tcg/decode-new.c.inc'
ILLOPC = 'NO-TABLE-ENTRY(ILLOPC)'

_LEGACY = {'66', '67', 'f0', 'f2', 'f3',
           '2e', '36', '3e', '26', '64', '65'}


# ------------------------------------------------------------- the encoding
def shape(hexs):
    """The prefix/map/opcode/ModRM shape QEMU's decoder dispatches on."""
    b = [hexs[i:i + 2].lower() for i in range(0, len(hexs), 2)]
    pre, i = set(), 0
    while i < len(b) and b[i] in _LEGACY:
        pre.add(b[i])
        i += 1
    rex = None
    if i < len(b) and 0x40 <= int(b[i], 16) <= 0x4f:
        rex = int(b[i], 16)
        i += 1
    d = {'pre': pre, 'rex': rex, 'kind': 'legacy'}

    def at(k):
        return int(b[k], 16) if k < len(b) else None

    if b[i] == 'c4':                                   # 3-byte VEX
        v2, v3 = at(i + 1), at(i + 2)
        d.update(kind='vex', map=v2 & 0x1f, W=(v3 >> 7) & 1,
                 vvvv=(~v3 >> 3) & 0xf, L=(v3 >> 2) & 1, pp=v3 & 3,
                 op=at(i + 3), modrm=at(i + 4))
    elif b[i] == 'c5':                                 # 2-byte VEX
        v2 = at(i + 1)
        d.update(kind='vex', map=1, W=None, vvvv=(~v2 >> 3) & 0xf,
                 L=(v2 >> 2) & 1, pp=v2 & 3, op=at(i + 2), modrm=at(i + 3))
    elif b[i] == '8f':                                 # XOP, or POP group 1A
        d.update(kind='xop', op=at(i + 1), modrm=at(i + 2))
    elif b[i] == '62':
        d.update(kind='evex', op=at(i + 4), modrm=at(i + 5))
    elif b[i] == '0f':
        if b[i + 1] in ('38', '3a'):
            d.update(map=2 if b[i + 1] == '38' else 3,
                     op=at(i + 2), modrm=at(i + 3))
        else:
            d.update(map=1, op=at(i + 1), modrm=at(i + 2))
    else:
        d.update(map=0, op=at(i), modrm=at(i + 1))
    return d


# --------------------------------------------- leg (b): the ModRM.reg groups
class GroupRefused(Exception):
    """The group walk met a construct in decode-new.c.inc it cannot read.

    This is FATAL and never a quiet fallback.  The defect it exists to make
    impossible is the one this walk replaced: the citation used to stop at the
    ROOT entry, report `X86_OP_GROUP1(group3, E,b)` as OCCUPIED, and never look
    at the slot the group dispatches the probe's ModRM.reg to.  Seven rows were
    convicted that way, all seven at group slots that are empty.  A walk that
    cannot read a group must say so, not guess the permissive answer.
    """


class Group(object):
    """One `decode_<name>()` in decode-new.c.inc, read as a slot table.

    The question this answers is narrow and is the only question leg (b) asks:
    for a probe's ModRM.reg (and the mod bits, the opcode's low bit and the
    legacy prefixes it carries), does QEMU's group dispatch reach an entry with
    a generator, or does it reach `UNKNOWN_OPCODE`, a `{}` array slot or
    `entry->gen = NULL`?

    The body is interpreted over a DELIBERATELY SMALL grammar -- the local int
    declarations, the if/else chain, the assignments to `*entry` and
    `entry->gen`, and the static tables those read.  Anything outside it raises
    GroupRefused.  The alternative, falling through to "occupied", is exactly
    the false positive this replaced.
    """

    #: `entry->` members that do not decide whether the slot exists.  A member
    #: NOT on this list raises rather than being skipped: `gen` is what decides
    #: existence today, and a future member that also decided it would be
    #: silently ignored by a blanket skip.
    _IGNORED_MEMBERS = ('op0', 'op1', 'op2', 's0', 's1', 's2',
                        'special', 'word', 'flags')
    #: Whole statements with no bearing on whether the slot exists.
    _IGNORED_CALLS = ('X86_DF_SET', 'X86_DF_PICK', 'assert', 'g_assert')

    def __init__(self, name, line, body):
        self.name = name
        self.line = line
        self.body = _strip_comments(body)
        self.arrays = {}          # name -> (line, {index: text}, designated)
        self.scalars = {}         # name -> (line, text)
        self.stmts = _statements(self._take_statics())

    # ---------------------------------------------------------- the tables
    def _take_statics(self):
        """Pull the `static ... = { ... };` declarations out of the body."""
        out, i, txt = [], 0, self.body
        pat = re.compile(r'static\s+(?:const\s+)?'
                         r'(X86OpEntry|X86GenFunc|X86DfIdent)\s+'
                         r'(\w+)\s*(?:\[\s*\d*\s*\])?\s*=\s*')
        while True:
            m = pat.search(txt, i)
            if not m:
                out.append(txt[i:])
                break
            out.append(txt[i:m.start()])
            j = _end_of_initialiser(txt, m.end())
            self._record(m.group(1), m.group(2),
                         txt[m.end():j].strip(),
                         self.line + txt.count('\n', 0, m.start()))
            i = txt.index(';', j) + 1
        return ''.join(out)

    def _record(self, kind, name, init, line):
        if kind == 'X86DfIdent':
            return                       # names a dataflow row, not existence
        if not init.startswith('{'):
            self.scalars[name] = (line, init)
            return
        elems = _split_top(init[1:init.rindex('}')])
        des = re.compile(r'^\[\s*([0-9a-fA-Fx]+)\s*\]\s*=\s*(.*)$', re.S)
        slots, designated = {}, False
        for pos, e in enumerate(elems):
            m = des.match(e.strip())
            if m:
                designated = True
                slots[int(m.group(1), 0)] = m.group(2).strip()
            else:
                slots[pos] = e.strip()
        if designated:
            # A designated initialiser leaves every index it does not name at
            # the array default `{}` -- that is the whole point of reading it.
            slots = {k: v for k, v in slots.items() if v}
        self.arrays[name] = (line, slots, designated)

    # ------------------------------------------------------------ the walk
    def slot(self, ctx):
        """-> ('FILLED'|'EMPTY', citation).  Raises GroupRefused."""
        env = {}
        r = self._run(self.stmts, ctx, env)
        if r is None:
            raise GroupRefused(
                'decode_%s (%s:%d) assigned neither *entry nor entry->gen on '
                'the path this probe takes' % (self.name, _DECODE, self.line))
        return r

    def _run(self, stmts, ctx, env):
        out = None
        for st in stmts:
            if st[0] == 'if':
                _, cond, then, els = st
                took = then if _cond(cond, ctx, env) else els
                r = self._run(took, ctx, env) if took else None
            else:
                r = self._stmt(st[1], ctx, env)
            if r is not None:
                out = r
        return out

    def _stmt(self, text, ctx, env):
        text = text.strip()
        if not text:
            return None
        m = re.match(r'^(?:int|unsigned|uint\d+_t|bool)\s+(\w+)\s*=\s*(.*)$',
                     text, re.S)
        if m:
            env[m.group(1)] = _val(m.group(2), ctx, env)
            return None
        m = re.match(r'^\*\s*entry\s*=\s*(.*)$', text, re.S)
        if m:
            return self._entry_rhs(m.group(1), ctx, env)
        m = re.match(r'^entry\s*->\s*(\w+)\s*=\s*(.*)$', text, re.S)
        if m:
            if m.group(1) == 'gen':
                return self._gen_rhs(m.group(2), ctx, env)
            if m.group(1) in self._IGNORED_MEMBERS:
                return None
            raise GroupRefused(
                'decode_%s (%s:%d) assigns entry->%s, which this walk has no '
                'rule for: it may or may not decide whether the slot exists'
                % (self.name, _DECODE, self.line, m.group(1)))
        head = text.split('(')[0].strip()
        if head in self._IGNORED_CALLS:
            return None
        if 'entry' in text:
            raise GroupRefused(
                'decode_%s (%s:%d) has a statement this walk cannot read and '
                'that mentions `entry`: %r' % (self.name, _DECODE, self.line,
                                               text[:90]))
        return None                       # s->popl_esp_hack and friends

    # -------------------------------------------------------- the two RHSs
    def _entry_rhs(self, rhs, ctx, env):
        rhs = rhs.strip()
        t = _ternary(rhs)
        if t:
            c, a, b = t
            return self._entry_rhs(a if _cond(c, ctx, env) else b, ctx, env)
        if rhs == 'UNKNOWN_OPCODE':
            return ('EMPTY', 'decode_%s (%s:%d) assigns `*entry = '
                             'UNKNOWN_OPCODE` for this ModRM.reg'
                    % (self.name, _DECODE, self.line))
        m = re.match(r'^\*\s*decode_by_prefix\s*\(\s*s\s*,\s*(\w+)\s*\)$', rhs)
        if m:
            return self._lookup(m.group(1), _prefix_column(ctx), 'prefix '
                                'column %d' % _prefix_column(ctx))
        m = re.match(r'^(\w+)\s*\[(.*)\]$', rhs, re.S)
        if m:
            i = _val(m.group(2), ctx, env)
            return self._lookup(m.group(1), i, 'index %d' % i)
        if rhs in self.scalars:
            line, init = self.scalars[rhs]
            if init.strip() in ('{}', ''):
                return ('EMPTY', '%s (%s:%d) is `{}`' % (rhs, _DECODE, line))
            return ('FILLED', '%s (%s:%d) = %s'
                    % (rhs, _DECODE, line, _one_line(init)))
        raise GroupRefused('decode_%s (%s:%d): `*entry = %s` is a form this '
                           'walk has no rule for'
                           % (self.name, _DECODE, self.line, _one_line(rhs)))

    def _gen_rhs(self, rhs, ctx, env):
        rhs = rhs.strip()
        t = _ternary(rhs)
        if t:
            c, a, b = t
            return self._gen_rhs(a if _cond(c, ctx, env) else b, ctx, env)
        if rhs == 'NULL':
            return ('EMPTY', 'decode_%s (%s:%d) assigns `entry->gen = NULL` '
                             'for this probe' % (self.name, _DECODE, self.line))
        m = re.match(r'^(\w+)\s*\[(.*)\]$', rhs, re.S)
        if m:
            i = _val(m.group(2), ctx, env)
            return self._lookup(m.group(1), i, 'index %d' % i)
        if re.match(r'^gen_\w+$', rhs):
            return ('FILLED', 'decode_%s (%s:%d) assigns `entry->gen = %s`'
                    % (self.name, _DECODE, self.line, rhs))
        raise GroupRefused('decode_%s (%s:%d): `entry->gen = %s` is a form '
                           'this walk has no rule for'
                           % (self.name, _DECODE, self.line, _one_line(rhs)))

    def _lookup(self, tbl, idx, where):
        if tbl not in self.arrays:
            raise GroupRefused('decode_%s (%s:%d) indexes %s, which this walk '
                               'did not parse as a table'
                               % (self.name, _DECODE, self.line, tbl))
        line, slots, _ = self.arrays[tbl]
        e = slots.get(idx)
        if e is None or e.strip() in ('{}', 'NULL', ''):
            return ('EMPTY',
                    '%s (table at %s:%d) at %s is %s: decode_%s hands '
                    'translate.c an entry with no generator and it reaches '
                    '`goto unknown_op`'
                    % (tbl, _DECODE, line, where,
                       '`%s`' % e.strip() if e else 'the array default {}',
                       self.name))
        return ('FILLED', '%s (table at %s:%d) at %s = %s'
                % (tbl, _DECODE, line, where, _one_line(e)))


# ------------------------------------------------------- the tiny C reader
def _strip_comments(t):
    t = re.sub(r'/\*.*?\*/', ' ', t, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', t)


def _one_line(t):
    return ' '.join(t.split())[:120]


def _end_of_initialiser(txt, i):
    """Index just past the balanced {...} (or the bare expression) at @i."""
    while i < len(txt) and txt[i].isspace():
        i += 1
    if txt[i] != '{':
        return txt.index(';', i)
    d = 0
    for j in range(i, len(txt)):
        d += (txt[j] == '{') - (txt[j] == '}')
        if d == 0:
            return j + 1
    raise GroupRefused('unbalanced initialiser in %s' % _DECODE)


def _split_top(s):
    out, d, cur = [], 0, ''
    for ch in s:
        d += ch in '({[' and 1 or (-1 if ch in ')}]' else 0)
        if ch == ',' and d == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _balanced(txt, i):
    """@i is at '('; -> (inside, index just past ')')."""
    d = 0
    for j in range(i, len(txt)):
        d += (txt[j] == '(') - (txt[j] == ')')
        if d == 0:
            return txt[i + 1:j], j + 1
    raise GroupRefused('unbalanced parenthesis in %s' % _DECODE)


def _statements(body):
    """A statement list: ('stmt', text) and ('if', cond, then, else)."""
    out, i, n = [], 0, len(body)
    while i < n:
        while i < n and body[i] in ' \t\n\r;':
            i += 1
        if i >= n:
            break
        if body.startswith('{', i):
            j = _end_of_initialiser(body, i)
            out.extend(_statements(body[i + 1:j - 1]))
            i = j
            continue
        m = re.compile(r'if\s*\(').match(body, i)
        if m:
            cond, j = _balanced(body, body.index('(', i))
            then, j = _block(body, j)
            els = None
            k = j
            while k < n and body[k] in ' \t\n\r':
                k += 1
            if body.startswith('else', k) and not body[k + 4:k + 5].isalnum():
                els, j = _block(body, k + 4)
            out.append(('if', cond, then, els))
            i = j
            continue
        j = _to_semicolon(body, i)
        out.append(('stmt', body[i:j]))
        i = j + 1
    return out


def _block(body, i):
    """A `{...}` or a single statement at @i -> (statements, index past it)."""
    while i < len(body) and body[i] in ' \t\n\r':
        i += 1
    if body.startswith('{', i):
        j = _end_of_initialiser(body, i)
        return _statements(body[i + 1:j - 1]), j
    if re.compile(r'if\s*\(').match(body, i):
        st = _statements(body[i:])
        return st[:1], len(body)
    j = _to_semicolon(body, i)
    return [('stmt', body[i:j])], j + 1


def _to_semicolon(body, i):
    d = 0
    for j in range(i, len(body)):
        d += body[j] in '({[' and 1 or (-1 if body[j] in ')}]' else 0)
        if body[j] == ';' and d == 0:
            return j
    return len(body)


_PREFIX_BIT = {'PREFIX_DATA': '66', 'PREFIX_REPZ': 'f3', 'PREFIX_REPNZ': 'f2',
               'PREFIX_LOCK': 'f0', 'PREFIX_ADR': '67'}


def _prefix_column(ctx):
    """decode_by_prefix()'s column: REPNZ 3, REPZ 2, DATA 1, else 0."""
    if 'f2' in ctx['pre']:
        return 3
    if 'f3' in ctx['pre']:
        return 2
    if '66' in ctx['pre']:
        return 1
    return 0


def _strip_parens(s):
    s = s.strip()
    while s.startswith('(') and _balanced(s, 0)[1] == len(s):
        s = s[1:-1].strip()
    return s


def _split_op(s, op):
    """Split @s on top-level @op, or None."""
    out, d, cur, i = [], 0, '', 0
    while i < len(s):
        d += s[i] in '({[' and 1 or (-1 if s[i] in ')}]' else 0)
        if d == 0 and s.startswith(op, i):
            out.append(cur)
            cur = ''
            i += len(op)
            continue
        cur += s[i]
        i += 1
    if not out:
        return None
    out.append(cur)
    return out


def _ternary(s):
    s = s.strip()
    d, q = 0, None
    for i, ch in enumerate(s):
        d += ch in '({[' and 1 or (-1 if ch in ')}]' else 0)
        if d == 0 and ch == '?':
            q = i
            break
    if q is None:
        return None
    d = 0
    for i in range(q + 1, len(s)):
        d += s[i] in '({[' and 1 or (-1 if s[i] in ')}]' else 0)
        if d == 0 and s[i] == ':':
            return s[:q], s[q + 1:i], s[i + 1:]
    raise GroupRefused('a `?` with no `:` in %s' % _DECODE)


def _val(e, ctx, env):
    """An integer-valued expression in a group decoder."""
    e = _strip_parens(e)
    m = _split_op(e, '|')
    if m:
        v = 0
        for p in m:
            v |= _val(p, ctx, env)
        return v
    m = re.match(r'^(.*)>>\s*(\d+)\s*&\s*(0x[0-9a-fA-F]+|\d+)$', e)
    if m:
        return (_val(m.group(1), ctx, env) >> int(m.group(2))) \
            & int(m.group(3), 0)
    m = _split_op(e, '&')
    if m:
        v = -1
        for p in m:
            v &= _val(p, ctx, env)
        return v
    m = _split_op(e, '>>')
    if m and len(m) == 2:
        return _val(m[0], ctx, env) >> _val(m[1], ctx, env)
    m = _split_op(e, '<<')
    if m and len(m) == 2:
        return _val(m[0], ctx, env) << _val(m[1], ctx, env)
    e = e.strip()
    if re.match(r'^get_modrm\s*\(\s*s\s*,\s*env\s*\)$', e):
        if ctx['modrm'] is None:
            raise GroupRefused('the probe carries no ModRM byte and the group '
                               'dispatch needs one')
        return ctx['modrm']
    if e == '*b':
        return ctx['op']
    if re.match(r'^(0x[0-9a-fA-F]+|\d+)$', e):
        return int(e, 0)
    if e in env:
        return env[e]
    raise GroupRefused('`%s` is not an expression this walk can evaluate'
                       % _one_line(e))


def _split_cmp(e):
    """Split @e at a top-level comparison -> (lhs, op, rhs), or None.

    `->` and `>>` are NOT comparisons, and a naive scan for '>' splits
    `s->prefix & PREFIX_DATA` after the `-`.
    """
    d, i, n = 0, 0, len(e)
    while i < n:
        d += e[i] in '({[' and 1 or (-1 if e[i] in ')}]' else 0)
        if d == 0:
            two = e[i:i + 2]
            if two in ('==', '!=', '>=', '<='):
                return e[:i], two, e[i + 2:]
            if two in ('->', '>>', '<<'):
                i += 2
                continue
            if e[i] in '<>':
                return e[:i], e[i], e[i + 1:]
        i += 1
    return None


def _cond(e, ctx, env):
    e = _strip_parens(e)
    m = _split_op(e, '||')
    if m:
        return any(_cond(p, ctx, env) for p in m)
    m = _split_op(e, '&&')
    if m:
        return all(_cond(p, ctx, env) for p in m)
    if e.startswith('!'):
        return not _cond(e[1:], ctx, env)
    m = re.match(r'^s\s*->\s*prefix\s*&\s*(PREFIX_\w+)$', e.strip())
    if m:
        if m.group(1) not in _PREFIX_BIT:
            raise GroupRefused('%s is a prefix this walk does not map'
                               % m.group(1))
        return _PREFIX_BIT[m.group(1)] in ctx['pre']
    s = e.strip()
    if s == 'REX_W(s)':
        return bool(ctx['rex'] is not None and (ctx['rex'] >> 3) & 1)
    if s == 'REX_B(s)':
        return bool(ctx['rex'] is not None and ctx['rex'] & 1)
    if s == 'REX_R(s)':
        return bool(ctx['rex'] is not None and (ctx['rex'] >> 2) & 1)
    if s in ('CODE64(s)', 'LMA(s)'):
        return True                       # the matrix is x86-64 throughout
    m = _split_cmp(e)
    if m:
        lhs, op, rhs = m
        a, b = _val(lhs, ctx, env), _val(rhs, ctx, env)
        return {'==': a == b, '!=': a != b, '>=': a >= b,
                '<=': a <= b, '>': a > b, '<': a < b}[op]
    raise GroupRefused('`%s` is not a condition this walk can evaluate'
                       % _one_line(e))


# ------------------------------------------------- leg (b): the QEMU tables
class Tables(object):
    """decode-new.c.inc, parsed from the tree on every run."""

    #: The initialiser of a table slot that hands the probe to a ModRM.reg
    #: group: `X86_OP_GROUP0(group15)`, `X86_OP_GROUP1(group3, E,b)`, ...
    _GROUP_RE = re.compile(r'X86_OP_GROUP[0-9wr]*\s*\(\s*([A-Za-z0-9_]+)')

    def __init__(self, root=QEMU_ROOT):
        p = os.path.join(root, _DECODE)
        if not os.path.exists(p):
            sys.exit('%s is not in the QEMU tree at %s: the citation cannot '
                     'be derived and must not be guessed' % (_DECODE, root))
        self.path = p
        self.txt = open(p).read()
        self.root_t, self.root_l = self._one('opcodes_root[256]')
        self.t0f, self.l0f = self._one('opcodes_0F[256]')
        self.t38, self.l38 = self._one('opcodes_0F38_00toEF[240]')
        self.t3a, self.l3a = self._one('opcodes_0F3A[256]')
        self.tf0, self.lf0 = self._f0toff()
        self.groups = self._groups()
        if len(self.groups) < 8:
            sys.exit('only %d decode_*() group function(s) were parsed out of '
                     '%s: the group walk has lost its subject and every slot '
                     'it would call empty is worthless' % (len(self.groups),
                                                           _DECODE))
        # A parser that finds nothing would call every slot empty and every
        # row unreachable.  Refuse to run rather than produce that.
        for name, tab in (('opcodes_root', self.root_t),
                          ('opcodes_0F', self.t0f),
                          ('opcodes_0F38_00toEF', self.t38),
                          ('opcodes_0F3A', self.t3a)):
            if len(tab) < 32:
                sys.exit('%s parsed to %d entries: the table parser has lost '
                         'its subject and every "slot empty" it would print '
                         'is worthless' % (name, len(tab)))

    def _line(self, off):
        return self.txt.count('\n', 0, off) + 1

    def _body(self, decl):
        i = self.txt.index('static const X86OpEntry %s = {' % decl)
        return i, self.txt[i:self.txt.index('\n};', i)]

    def _one(self, decl):
        i0, body = self._body(decl)
        out = {}
        for m in re.finditer(r'^\s*\[(0x[0-9a-fA-F]+)\]\s*=\s*(.*?),?\s*$',
                             body, re.M):
            out[int(m.group(1), 16)] = (self._line(i0 + m.start()),
                                        m.group(2).rstrip(','))
        return out, self._line(i0)

    def _groups(self):
        """Every `static void decode_<name>(...)` in the file, as a Group."""
        out = {}
        for m in re.finditer(r'^static void decode_([A-Za-z0-9_]+)\s*\(',
                             self.txt, re.M):
            i = self.txt.index('{', m.end())
            j = self.txt.index('\n}\n', i)
            out[m.group(1)] = Group(m.group(1), self._line(m.start()),
                                    self.txt[i + 1:j])
        return out

    def _group_of(self, entry_text):
        """The group `decode_*` this table entry dispatches to, or None."""
        m = self._GROUP_RE.search(entry_text)
        if m and m.group(1) in self.groups:
            return self.groups[m.group(1)]
        return None

    def _descend(self, tbl_name, slot, e, d, where):
        """Follow a table entry that names a ModRM.reg group.

        -> (verdict, class, citation), or None when the entry is not a group.

        THIS IS WHAT THE CITATION USED TO SKIP.  `opcodes_root[0xF6]` IS
        occupied -- by `X86_OP_GROUP1(group3, E,b)`, which is a POINTER at a
        second table.  Reporting the pointer as the answer convicted seven rows
        whose ModRM.reg lands in a slot decode_group3/group11/group15 leaves
        empty.  The slot the probe actually reaches is the fact.
        """
        g = self._group_of(e[1])
        if g is None:
            return None
        ctx = {'modrm': d['modrm'], 'op': d['op'], 'pre': d['pre'],
               'rex': d['rex']}
        state, why = g.slot(ctx)
        head = ('%s[0x%02x] (%s:%d) = %s dispatches on ModRM.reg; '
                % (tbl_name, slot, _DECODE, e[0], _one_line(e[1])))
        if state == 'EMPTY':
            return ('ABSENT', 'GROUP(%s)-SLOT-EMPTY' % g.name,
                    head + why + '.  The ROOT slot is occupied by the group '
                    'pointer; the slot this probe reaches is not.')
        return ('OCCUPIED', 'GROUP(%s)-SLOT-OCCUPIED' % g.name, head + why)

    def _f0toff(self):
        i0, body = self._body('opcodes_0F38_F0toFF[16][5]')
        rows = {}
        for m in re.finditer(r'\[(\d+)\]\s*=\s*\{(.*?)\n    \}', body, re.S):
            cols, depth, cur = [], 0, ''
            for ch in m.group(2):
                depth += (ch == '(') - (ch == ')')
                if ch == ',' and depth == 0:
                    cols.append(cur.strip())
                    cur = ''
                else:
                    cur += ch
            if cur.strip():
                cols.append(cur.strip())
            rows[int(m.group(1))] = (self._line(i0 + m.start()),
                                     [c for c in cols if c])
        return rows, self._line(i0)

    # ------------------------------------------------------------- the cite
    def cite(self, hexs):
        """-> (verdict, class, citation).  verdict is ABSENT or OCCUPIED."""
        d = shape(hexs)
        if d['kind'] == 'evex':
            return ('ABSENT', 'EVEX-PREFIX-NOT-DECODED',
                    'the 0x62 EVEX prefix is not decoded by '
                    'decode-new.c.inc at all')
        if d['kind'] == 'vex' and d['map'] not in (1, 2, 3):
            return ('ABSENT', 'VEX-MAP-RESERVED',
                    'the 3-byte-VEX switch on (vex2 & 0x1f) in %s has cases '
                    '0x01/0x02/0x03 only; map 0x%02x takes `default: /* '
                    'Reserved for future use. */ goto unknown_op`.  QEMU has '
                    'no opcode table for VEX map %d.'
                    % (_DECODE, d['map'], d['map']))
        if d['kind'] == 'xop':
            # QEMU sees 0x8F as an opcode and the NEXT byte as its ModRM --
            # the byte XOP spends on RXB.map.  `shape()` calls that byte `op`
            # because it is XOP's opcode-map selector; for the group walk it is
            # the ModRM byte, and reading the one after it (XOP's own opcode)
            # would ask decode_group1A about the wrong reg field.  It happens
            # not to change the verdict on this corpus -- every XOP map leaves
            # ModRM.reg at 5 or 1, never 0 -- but the citation would be naming
            # a byte QEMU does not look at.
            e = self.root_t.get(0x8f)
            reg = (d['op'] >> 3) & 7
            ctx = {'modrm': d['op'], 'op': 0x8f, 'pre': d['pre'],
                   'rex': d['rex']}
            state, why = self.groups['group1A'].slot(ctx)
            if state == 'FILLED':
                return ('OCCUPIED', 'XOP-REG0-IS-POP',
                        'opcodes_root[0x8F] (%s:%d) -> group1A at ModRM.reg=%d '
                        ': %s' % (_DECODE, e[0], reg, why))
            return ('ABSENT', 'XOP-IS-POP-GROUP1A',
                    'opcodes_root[0x8F] (%s:%d) = %s; %s (here reg=%d, from '
                    'the byte after 0x8F, which XOP spends on RXB.map).  QEMU '
                    'never decodes the 0x8F XOP prefix.'
                    % (_DECODE, e[0], _one_line(e[1]), why, reg))

        op = d['op']
        vmap = d['map']
        if vmap == 2:
            if op < 0xf0:
                e = self.t38.get(op)
                if e is None:
                    return ('ABSENT', '0F38-SLOT-EMPTY',
                            'opcodes_0F38_00toEF[0x%02x] (table at %s:%d) has '
                            'no designated initializer: the slot is the array '
                            'default {}, decode_0F38 returns gen==NULL and '
                            'translate.c reaches `goto unknown_op`.'
                            % (op, _DECODE, self.l38))
                return ('OCCUPIED', '0F38-SLOT-OCCUPIED',
                        'opcodes_0F38_00toEF[0x%02x] IS occupied at %s:%d -> '
                        '%s' % (op, _DECODE, e[0], e[1]))
            row = (2 if 'f3' in d['pre']
                   else (3 if 'f2' in d['pre'] else 0)
                   + (1 if '66' in d['pre'] else 0))
            r = self.tf0.get(op & 15)
            if r is None:
                return ('ABSENT', '0F38F0-ROW-ABSENT',
                        'opcodes_0F38_F0toFF[0x%02x & 15 = %d] (table at '
                        '%s:%d) has no designated initializer at all: all '
                        'five prefix columns are {}.  decode_0F38 selects '
                        'column %d and returns gen==NULL -> `goto '
                        'unknown_op`.' % (op, op & 15, _DECODE, self.lf0, row))
            col = r[1][row] if row < len(r[1]) else '{}'
            if col.strip() in ('{}', ''):
                return ('ABSENT', '0F38F0-COL-EMPTY',
                        'opcodes_0F38_F0toFF[%d][%d] (row at %s:%d) is `{}` '
                        '-> gen==NULL -> `goto unknown_op`.'
                        % (op & 15, row, _DECODE, r[0]))
            return ('OCCUPIED', '0F38F0-COL-OCCUPIED',
                    'opcodes_0F38_F0toFF[%d][%d] = %s' % (op & 15, row, col))

        if vmap == 3:
            e = self.t3a.get(op)
            if e is None:
                return ('ABSENT', '0F3A-SLOT-EMPTY',
                        'opcodes_0F3A[0x%02x] (table at %s:%d) has no '
                        'designated initializer: the slot is {} -> `goto '
                        'unknown_op`.' % (op, _DECODE, self.l3a))
            return ('OCCUPIED', '0F3A-SLOT-OCCUPIED',
                    'opcodes_0F3A[0x%02x] IS occupied at %s:%d -> %s'
                    % (op, _DECODE, e[0], e[1]))

        if vmap == 1:
            e = self.t0f.get(op)
            if e is None:
                return ('ABSENT', '0F-SLOT-EMPTY',
                        'opcodes_0F[0x%02x] (table at %s:%d) has no '
                        'designated initializer: the slot is {} -> `goto '
                        'unknown_op`.' % (op, _DECODE, self.l0f))
            g = self._descend('opcodes_0F', op, e, d, 'map 1')
            if g:
                return g
            return ('OCCUPIED', '0F-SLOT-OCCUPIED',
                    'opcodes_0F[0x%02x] IS occupied at %s:%d -> %s'
                    % (op, _DECODE, e[0], e[1]))

        e = self.root_t.get(op)
        if e is None:
            return ('ABSENT', 'ROOT-SLOT-EMPTY',
                    'opcodes_root[0x%02x] (table at %s:%d) has no designated '
                    'initializer.' % (op, _DECODE, self.root_l))
        g = self._descend('opcodes_root', op, e, d, 'root')
        if g:
            return g
        return ('OCCUPIED', 'ROOT-SLOT-OCCUPIED',
                'opcodes_root[0x%02x] IS occupied at %s:%d -> %s'
                % (op, _DECODE, e[0], e[1]))


# ------------------------------------------------- leg (a): the decoders
_SKIP = {'{vex}', '{evex}', '{rex}', '{load}', '{store}', 'rep', 'repz',
         'repnz', 'lock', 'addr32', 'addr16', 'data16'}


def _norm(t):
    return t.replace('-', '').replace('_', '').lower()


def objdump_decode(binary, hexes):
    """-> {hex: (ok, length, text)} from one objdump per encoding."""
    out = {}
    d = tempfile.mkdtemp(prefix='illopc-')
    try:
        f = os.path.join(d, 'a.bin')
        for h in hexes:
            open(f, 'wb').write(bytes.fromhex(h))
            p = subprocess.run([binary, '-D', '-b', 'binary',
                                '-m', 'i386:x86-64', '-M', 'att',
                                '--insn-width=16', f],
                               capture_output=True, text=True)
            ln = [l for l in p.stdout.splitlines() if l.strip().startswith('0:')]
            if not ln:
                out[h] = (False, 0, '')
                continue
            parts = ln[0].split('\t')
            nb = len(parts[1].split()) if len(parts) > 1 else 0
            txt = ' '.join(parts[2:]).strip() if len(parts) > 2 else '(bad)'
            out[h] = ('(bad)' not in txt and bool(txt), nb, txt)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return out


def objdump_mnem(txt):
    for t in txt.split():
        if t.lower() in _SKIP:
            continue
        return t.lower().lstrip('*')
    return ''


def load_tool(path, tool):
    out = {}
    if not path or not os.path.exists(path):
        return out
    for r in csv.DictReader(open(path), delimiter='\t'):
        if tool and r.get('tool') != tool:
            continue
        out[r['hex']] = r
    return out


#: XOP VPCOM*/VPCOMU* imm8 -> the compare predicate it selects (AMD XOP, and
#: the suffix binutils spells into the mnemonic).  Values 8..255 are reserved,
#: so the rule below accepts only 0..7 -- a probe with a reserved imm8 is NOT
#: the same instruction under another name and must keep firing.
_XOP_PRED = {0: 'lt', 1: 'le', 2: 'gt', 3: 'ge',
             4: 'eq', 5: 'neq', 6: 'false', 7: 'true'}


def xop_predicate_suffix(mnem, name, hexs):
    """-> the predicate when @name is @mnem with the imm8's predicate spelled in.

    THE TWO SPELLINGS OF ONE ENCODING.  XED's iform keeps the family name --
    VPCOMB -- and carries the compare predicate as the immediate, which is
    where the encoding puts it.  binutils resolves the immediate at disassembly
    and spells the predicate into the mnemonic: `vpcomleb`.  Neither is wrong
    and they name THE SAME BYTES, so a row whose reference decoder took the
    second convention is not a broken probe.

    The rule is per row and checks the immediate, not the family: the suffix
    must be exactly the predicate THIS probe's imm8 selects, in front of the
    row's own type letters.  `vpcomltb` against a probe whose imm8 is 1 is a
    different instruction and still fires, and so does any other size.
    """
    m, n = _norm(mnem), _norm(name)
    if not (m.startswith('vpcom') and n.startswith('vpcom')):
        return None
    if len(hexs) < 2:
        return None
    imm = int(hexs[-2:], 16)
    pred = _XOP_PRED.get(imm)
    if pred is None:
        return None
    if n[5:] == pred + m[5:]:
        return pred
    return None


def judge(mnem, nbytes, ok, length, name, strip=(), hexs=None):
    """One decoder's opinion: OK / OKPRED / NAME:x / LEN:n / REFUSED."""
    if not ok:
        return 'REFUSED'
    if int(length) != nbytes:
        return 'LEN:%s' % length
    n = _norm(name)
    for p in strip:
        if n.startswith(p):
            n = n[len(p):]
            break
    if n.startswith(_norm(mnem)):
        return 'OK:' + name
    if hexs and xop_predicate_suffix(mnem, n, hexs):
        return 'OKPRED:' + name
    return 'NAME:' + name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--matrix', required=True)
    ap.add_argument('--xl3', required=True, help='xl3.tsv (XED + LLVM MC)')
    ap.add_argument('--iced', required=True, help='iced.tsv')
    ap.add_argument('--objdump', action='append', default=None,
                    help='objdump to consult; repeatable, and each one is '
                         'counted as an independent decoder -- passing the '
                         'same binary twice is REFUSED.  A DISTRIBUTION '
                         'objdump lags the newest ISA extensions by years, so '
                         'pass a recent one too rather than letting its '
                         'ignorance read as a single-source row.')
    ap.add_argument('--root', default=QEMU_ROOT)
    ap.add_argument('--allow-single-source',
                    help='rows only the rank-1 reference decodes: '
                         '"<hex>  <reason>" per line')
    ap.add_argument('-o', help='write the per-row audit here')
    a = ap.parse_args()

    tabs = Tables(a.root)
    xed = load_tool(a.xl3, 'XED')
    llvm = load_tool(a.xl3, 'LLVM')
    iced = load_tool(a.iced, None)
    if not xed or not llvm:
        sys.exit('%s carries no XED and/or no LLVM rows' % a.xl3)

    allow = {}
    if a.allow_single_source:
        for line in open(a.allow_single_source):
            line = line.split('#')[0].strip()
            if line:
                k, _, why = line.partition(' ')
                allow[k.strip()] = why.strip()

    rows = [r for r in csv.DictReader(open(a.matrix), delimiter='\t')
            if r['verdict'] == 'UNREACHABLE' and r['qemu_refusal'] == ILLOPC]
    if not rows:
        sys.exit('%s has no UNREACHABLE row refused at %s: this audit has '
                 'lost its subject' % (a.matrix, ILLOPC))

    objs = a.objdump or ([shutil.which('objdump')]
                         if shutil.which('objdump') else [])
    objs = [o for o in objs if o]
    if not objs:
        sys.exit('no objdump on PATH and none given: leg (a) would run on '
                 'three decoders where the brief asks for an independent '
                 'fourth, and a leg that cannot find its subject must fail')
    vers = [subprocess.run([o, '--version'], capture_output=True,
                           text=True).stdout.splitlines()[0] for o in objs]

    # A COLUMN THAT IS THE SAME DECODER TWICE IS NOT A COLUMN, and this audit
    # shipped one.  `--objdump "${CST_OBJDUMP_NEW:-objdump}" --objdump objdump`
    # with the variable unset resolved BOTH slots to the distribution binary,
    # so `len(opin)` counted five decoders while four ran, and the SINGLE-
    # SOURCE message printed the same version string twice -- which is how it
    # was eventually caught.  Ten rows were convicted on the strength of a
    # decoder that had been asked the same question twice.
    #
    # The fallback is deleted rather than deduplicated: silently collapsing
    # to four would keep the count honest and lose the fifth opinion without
    # saying so, and a leg that cannot reach its subject must FAIL.  Identity
    # is decided on the resolved path AND on the version banner, because two
    # different paths can be the same build (a symlink, a hardlink, a copy).
    seen = {}
    for o, v in zip(objs, vers):
        key = (os.path.realpath(shutil.which(o) or o), v)
        if key in seen:
            sys.exit('THE SAME objdump WAS PASSED TWICE (%s -> %s, %s).  Each '
                     '--objdump is counted as an independent decoder, so a '
                     'repeat inflates the decoder count and can convict a row '
                     'as SINGLE-SOURCE on four opinions while claiming five.  '
                     'Pass distinct binaries or pass one.'
                     % (o, key[0], v))
        seen[key] = o

    hexes = sorted({r['probe_hex'] for r in rows})
    # CONTROL for leg (a): the same pipeline, on a probe whose opcode byte has
    # been corrupted, must CONTRADICT the mnemonic the row claims.
    ctl_row = next(r for r in rows if len(r['probe_hex']) >= 6)
    ctl_hex = ctl_row['probe_hex']
    ctl_bad = ctl_hex[:-4] + ('%02x' % ((int(ctl_hex[-4:-2], 16) ^ 0x40) & 0xff)) \
        + ctl_hex[-2:]
    # CONTROL (a2): the BROKEN-PROBE branch itself.  A row is only fatal when
    # a decoder names a DIFFERENT instruction, so that branch has to be shown
    # reachable -- a control that only ever produces REFUSED proves the
    # pipeline is silent, not that it can speak.
    ctl_wrong = '660f38dc00'                 # 66 0F 38 DC = AESENC
    ods = [objdump_decode(o, hexes + [ctl_bad, ctl_wrong]) for o in objs]
    od = ods[0]

    out, tally = [], collections.Counter()
    fatal, adjudicated = [], []
    for r in rows:
        h, mn = r['probe_hex'], r['mnemonic']
        n = len(h) // 2
        x, l, i = xed.get(h), llvm.get(h), iced.get(h)
        o = od.get(h)
        vx = judge(mn, n, x and x['ok'] == '1', x['len'] if x else 0,
                   x['mnem'] if x else '', ('rep',), h) if x else 'REFUSED'
        vl = judge(mn, n, l and l['ok'] == '1', l['len'] if l else 0,
                   l['mnem'] if l else '', (), h) if l else 'REFUSED'
        vi = judge(mn, n, i and i['ok'] == '1', i['len'] if i else 0,
                   i['mnem'] if i else '',
                   ('vex', 'evex', 'xop', 'mvex'), h) if i else 'REFUSED'
        vos = []
        for t in ods:
            e = t.get(h)
            vos.append(judge(mn, n, e[0], e[1], objdump_mnem(e[2]), (), h)
                       if e else 'REFUSED')
        opin = (vx, vl, vi) + tuple(vos)
        nok = sum(1 for v in opin if v.startswith('OK'))
        bad = [v for v in opin if v.startswith(('NAME:', 'LEN:'))]
        # PER ROW, NOT PER FAMILY: name the probe's own imm8, the predicate it
        # selects and every decoder that spelled it in, so the adjudication can
        # be checked against the bytes rather than against a rule's name.
        pred = [v[7:] for v in opin if v.startswith('OKPRED:')]
        if pred:
            tally['XOP-IMM8-PREDICATE-SUFFIX'] += 1
            adjudicated.append(
                '%s %s imm8=0x%s pred=%s generic=%s spelled-in-by=%s'
                % (r['opcode_id'], h, h[-2:],
                   xop_predicate_suffix(mn, _norm(pred[0]), h), mn,
                   ','.join(sorted(set(pred)))))
        if bad:
            state = 'BROKEN-PROBE'
            fatal.append('%s %s: %s decodes to %s, not %s'
                         % (r['opcode_id'], h, 'a decoder', bad[0], mn))
        elif nok >= 2:
            state = 'CONFIRMED-%d' % nok
        elif nok == 1:
            state = ('SINGLE-SOURCE-ALLOWED' if h in allow
                     else 'SINGLE-SOURCE')
            if h not in allow:
                fatal.append('%s %s: only one of %d decoders names it (%s) '
                             'and it is not in --allow-single-source'
                             % (r['opcode_id'], h, len(opin),
                                ', '.join(vers)))
        else:
            state = 'NO-DECODER'
            fatal.append('%s %s: no decoder names it at all' %
                         (r['opcode_id'], h))
        try:
            verdict, cls, why = tabs.cite(h)
        except GroupRefused as ex:
            verdict, cls, why = 'REFUSED', 'GROUP-WALK-REFUSED', str(ex)
            fatal.append('%s %s: THE GROUP WALK CANNOT READ QEMU\'S DISPATCH '
                         '-- %s.  This row has no citation at all; it is not '
                         'an ABSENT one.' % (r['opcode_id'], h, ex))
        if verdict == 'OCCUPIED':
            fatal.append('%s %s: QEMU HAS A TABLE ENTRY -- %s' %
                         (r['opcode_id'], h, why))
        tally[state] += 1
        tally['cite:' + cls] += 1
        out.append((r['opcode_id'], mn, h, str(n), vx, vl, vi)
                   + tuple(vos) + (state, verdict, cls, why))

    # --------------------------------------------------------- the controls
    cx = xed.get(ctl_bad)
    co = od.get(ctl_bad)
    ctl_a = (judge(ctl_row['mnemonic'], len(ctl_bad) // 2,
                   cx and cx['ok'] == '1', cx['len'] if cx else 0,
                   cx['mnem'] if cx else '', ('rep',)) if cx
             else judge(ctl_row['mnemonic'], len(ctl_bad) // 2,
                        co[0], co[1], objdump_mnem(co[2])) if co else 'REFUSED')
    ctl_a_fires = not ctl_a.startswith('OK')
    # CONTROL for leg (b): an encoding whose slot IS occupied must say so.
    cw = od.get(ctl_wrong)
    ctl_a2 = (judge(ctl_row['mnemonic'], len(ctl_wrong) // 2, cw[0], cw[1],
                    objdump_mnem(cw[2])) if cw else 'REFUSED')
    ctl_a2_fires = ctl_a2.startswith('NAME:')
    ctl_b = tabs.cite(ctl_wrong)
    ctl_b_fires = ctl_b[0] == 'OCCUPIED'
    # CONTROLS FOR THE GROUP DESCENT, both directions.  A walk that always said
    # EMPTY would turn the seven false positives into seven silent passes and
    # would also excuse every row QEMU really does decode, so the OCCUPIED
    # direction is planted at a ModRM.reg the SAME group fills: `f6 c0 00` is
    # `test $0,%al`, opcodes_root[0xF6] -> group3 at index 0, which
    # decode_group3 initialises.  `f6 c8 01` is the same opcode at reg=1, the
    # undocumented second TEST encoding, which it does not.  One byte apart,
    # opposite answers, and both must be the ones printed here.
    ctl_g_full = tabs.cite('f6c000')
    ctl_g_empty = tabs.cite('f6c801')
    ctl_g_full_fires = ctl_g_full[0] == 'OCCUPIED'
    ctl_g_empty_fires = ctl_g_empty[0] == 'ABSENT'
    # CONTROL FOR THE PREDICATE-SUFFIX ADJUDICATION.  A rule that accepted any
    # vpcom* spelling would launder a genuinely different decode, so it is
    # fired at three pairs: the real one, one whose predicate is not the imm8's
    # (imm8=1 selects `le`, not `lt`) and one whose type letters differ.
    ctl_p_yes = xop_predicate_suffix('VPCOMB', 'vpcomleb', '8fe878ccc001')
    ctl_p_pred = xop_predicate_suffix('VPCOMB', 'vpcomltb', '8fe878ccc001')
    ctl_p_size = xop_predicate_suffix('VPCOMW', 'vpcomleb', '8fe878ccc001')
    ctl_p_fires = (ctl_p_yes == 'le' and ctl_p_pred is None
                   and ctl_p_size is None)

    for v in vers:
        print('objdump                     : %s' % v)
    print('rows refused at %s : %d' % (ILLOPC, len(rows)))
    for k in sorted(tally):
        if not k.startswith('cite:'):
            print('  %-24s %d' % (k, tally[k]))
    print('citations, by table slot:')
    for k in sorted(tally):
        if k.startswith('cite:'):
            print('  %-24s %d' % (k[5:], tally[k]))
    print('control (a) corrupted probe %s -> %s : %s'
          % (ctl_bad, ctl_a, 'FIRES' if ctl_a_fires else 'INERT'))
    print('control (a2) %s claimed as %-14s -> %s : %s'
          % (ctl_wrong, ctl_row['mnemonic'], ctl_a2,
             'FIRES' if ctl_a2_fires else 'INERT'))
    print('control (b) %s (AESENC) -> %s : %s'
          % (ctl_wrong, ctl_b[1], 'FIRES' if ctl_b_fires else 'INERT'))
    print('control (b2) f6c000 test $0,%%al  group3 reg=0 -> %s : %s'
          % (ctl_g_full[1], 'FIRES' if ctl_g_full_fires else 'INERT'))
    print('control (b3) f6c801 same opcode reg=1 -> %s : %s'
          % (ctl_g_empty[1], 'FIRES' if ctl_g_empty_fires else 'INERT'))
    print('control (p) vpcomleb=%s vpcomltb=%s vpcomleb-vs-VPCOMW=%s : %s'
          % (ctl_p_yes, ctl_p_pred, ctl_p_size,
             'FIRES' if ctl_p_fires else 'INERT'))
    for line in adjudicated:
        print('XOP-PREDICATE-ADJUDICATED %s' % line)

    if a.o:
        with open(a.o, 'w') as f:
            f.write('\t'.join(('opcode_id', 'mnemonic', 'probe_hex',
                               'nbytes', 'XED', 'LLVM_MC', 'iced_x86')
                              + tuple('objdump:' + v.split()[-1]
                                      for v in vers)
                              + ('probe_state', 'qemu_slot', 'cite_class',
                                 'citation')) + '\n')
            for row in out:
                f.write('\t'.join(row) + '\n')

    rc = 0
    if not ctl_a_fires:
        print('CONTROL (a) IS INERT: a corrupted probe was still accepted, so '
              'every "CONFIRMED" above vouches for nothing')
        rc = 1
    if not ctl_a2_fires:
        print('CONTROL (a2) IS INERT: a decode that names a DIFFERENT '
              'instruction was not reported as a contradiction, so the '
              'BROKEN-PROBE branch is unreachable and every "CONFIRMED" '
              'above vouches for nothing')
        rc = 1
    if not ctl_b_fires:
        print('CONTROL (b) IS INERT: an OCCUPIED slot was reported ABSENT, so '
              'every citation above vouches for nothing')
        rc = 1
    if not ctl_g_full_fires:
        print('CONTROL (b2) IS INERT: a ModRM.reg the group DOES fill was '
              'reported ABSENT, so every "the group slot is empty" above '
              'vouches for nothing')
        rc = 1
    if not ctl_g_empty_fires:
        print('CONTROL (b3) IS INERT: a ModRM.reg the group leaves empty was '
              'not reported ABSENT, so the group descent is not reaching the '
              'group at all')
        rc = 1
    if not ctl_p_fires:
        print('CONTROL (p) IS INERT: the XOP predicate-suffix rule either '
              'rejected the imm8 it does select or accepted one it does not, '
              'so every row it adjudicated vouches for nothing')
        rc = 1
    for m in fatal:
        print('RED: %s' % m)
        rc = 1
    dead = [h for h in allow if h not in hexes]
    if dead:
        print('RED: --allow-single-source names %d encoding(s) that are no '
              'longer ILLOPC rows: %s.  A rule that cannot reach its subject '
              'is not a rule.' % (len(dead), ' '.join(sorted(dead))))
        rc = 1
    print('AUDIT %s' % ('GREEN' if rc == 0 else 'RED'))
    return rc


if __name__ == '__main__':
    sys.exit(main())
