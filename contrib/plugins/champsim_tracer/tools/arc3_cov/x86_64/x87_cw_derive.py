#!/usr/bin/env python3
"""
ARC 3 -- DOES THIS x87 ENCODING READ THE x87 CONTROL WORD?

Answered from QEMU, in two halves that never consult the tracer:

  1. WHICH HELPERS the encoding runs.  Read off an OBSERVED TCG op dump
     (`qemu-x86_64 -one-insn-per-tb -d op`, x87_cw_probe.c), never off the
     switch in gen_x87() by eye.
  0. WHAT THE HELPER'S TEXT ACTUALLY SAYS.  QEMU addresses the x87 stack
     through the ST0 / ST1 / ST(n) macros, so `helper_fabs_ST0` reads
     `env->fpstt` -- the TOP field -- without the field appearing anywhere
     in its body.  Every macro whose expansion transitively mentions
     `env->` is expanded to a fixed point BEFORE any of the questions
     below is asked.  Nothing here may be answered off unexpanded text.

  2. WHETHER A NAMED HELPER READS THE CONTROL WORD.  Answered by walking
     the call graph of target/i386/tcg/fpu_helper.c (plus cc_helper.c and
     the cpu.h inlines) to a fixed point.

A function reads the control word when either route reaches it:

  (a) it evaluates `env->fpuc`, and the evaluation is not DOMINATED by a
      DEFINITION of the control word.  The kill is ordinary def-kill
      dataflow and it is what R7 asks.  `cpu_set_fpuc()` stores its
      argument into `env->fpuc` and only then calls `update_fp_status()`,
      which re-reads what was just stored in order to decode it
      (target/i386/cpu.h); nothing a PRIOR writer of the control word
      produced is an input, so `fldcw`, `fldenv`, `frstor`, `fxrstor` and
      `fninit` acquire no source.  A definition is a node property, not a
      textual prefix: it propagates through the call graph exactly as a
      read does, and a call is a KILL rather than a read whenever the
      callee defines the control word without reading it first.  The tool
      asserts that cpu_set_fpuc still assigns before it decodes, so a
      change there fails the run instead of silently inverting eight rows.

  (b) it hands `&env->fp_status` to a routine that is not one of the three
      softfloat EXCEPTION-FLAG accessors.  fp_status carries exactly two
      kinds of state: the accumulated exception flags, which are STATUS
      word, and the decoded rounding mode and precision control, which are
      the CONTROL word -- update_fp_status() is the decoder, writing both
      out of `env->fpuc`.  So a softfloat routine that takes fp_status and
      is not get_float_exception_flags / set_float_exception_flags /
      float_raise consults the rounding fields.

Route (b) is not taken on trust: --control runs the DIFFERENTIAL, which
executes each encoding twice under two different control words and reports
which ones changed their architectural result.  A row route (b) calls YES
that the differential also convicts is proven twice, and a row the
differential convicts that this analysis calls NO is a MISSING EDGE.

Author: Maccoy Merrell.
"""
import argparse
import os
import re
import sys
import collections

Q = '/mnt/md0/QEMU/qemu'

# The softfloat entry points that touch ONLY the accumulated exception
# flags.  Everything else that is handed a float_status consults the
# rounding mode or the precision control, which are the decoded control
# word.
FLAG_ONLY = {'get_float_exception_flags',
             'set_float_exception_flags',
             'float_raise'}

SRC = ['target/i386/tcg/fpu_helper.c',
       'target/i386/tcg/cc_helper.c',
       'target/i386/cpu.h']


def strip_comments(t):
    t = re.sub(r'/\*.*?\*/', ' ', t, flags=re.S)
    t = re.sub(r'//[^\n]*', ' ', t)
    return t


def split_functions(text):
    """C source -> {name: body}.  Definitions only: a name, a parenthesised
    parameter list and a brace-balanced body whose opening brace is at
    column 0 or immediately follows the parameter list."""
    out = {}
    i = 0
    pat = re.compile(r'(?m)^[A-Za-z_][A-Za-z_0-9 \t\*]*?'
                     r'\b([A-Za-z_][A-Za-z_0-9]*)\s*\(')
    while True:
        m = pat.search(text, i)
        if not m:
            break
        # balance the parameter list
        j = m.end() - 1
        depth = 0
        while j < len(text):
            if text[j] == '(':
                depth += 1
            elif text[j] == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        k = j + 1
        while k < len(text) and text[k] in ' \t\n':
            k += 1
        if k >= len(text) or text[k] != '{':
            i = m.end()
            continue
        depth = 0
        e = k
        while e < len(text):
            if text[e] == '{':
                depth += 1
            elif text[e] == '}':
                depth -= 1
                if depth == 0:
                    break
            e += 1
        out.setdefault(m.group(1), text[k:e + 1])
        i = e + 1
    return out


# ---------------------------------------------------------------- the macros
#
# THE READ THE SOURCE TEXT DOES NOT CONTAIN.  QEMU addresses the x87 stack
# through three macros defined at the top of fpu_helper.c:
#
#     #define FT0    (env->ft0)
#     #define ST0    (env->fpregs[env->fpstt].d)
#     #define ST(n)  (env->fpregs[(env->fpstt + (n)) & 7].d)
#     #define ST1    ST(1)
#
# so `helper_fabs_ST0` reads in full as `ST0 = floatx80_abs(ST0)` and the
# read of `env->fpstt` -- the TOP field, which decides WHICH physical
# register `%st(0)` denotes -- never appears in the function's own text.  A
# reading that does not expand the macro concludes that fabs, fchs, fadd,
# fcom, fst, fxch and every other stack-naming form is independent of the
# top of stack.  That conclusion is a property of the reading, not of the
# machine, and it is exactly the shape the maintainer ruled out: "if the
# information is in a macro body, EXPAND THE MACRO."
#
# Expansion is DERIVED, never a table of four strings.  Every single-line
# object-like and function-like macro in the analysed sources is collected;
# the ones whose body reaches `env->` TRANSITIVELY -- which is how `ST1`,
# whose body is just `ST(1)`, is caught -- are expanded to a fixed point in
# every function body before any dataflow question is asked.  A future macro
# that hides a field the same way is therefore covered without an edit here.


_DEF = re.compile(r'(?m)^[ \t]*#[ \t]*define[ \t]+'
                  r'([A-Za-z_][A-Za-z_0-9]*)(\(([^)]*)\))?[ \t]*(.*)$')
_PP = re.compile(r'(?m)^[ \t]*#(?:[^\n\\]|\\\n)*$')


def collect_macros(text):
    """source text -> {name: (params or None, body)} for single-line macros."""
    out = {}
    for m in _DEF.finditer(text):
        name, parens, params, body = m.group(1), m.group(2), m.group(3), \
            m.group(4)
        if body.rstrip().endswith('\\'):
            continue                       # multi-line: not expanded here
        out[name] = ([p.strip() for p in params.split(',')] if parens
                     else None, body.strip())
    return out


def _reaching(macros):
    """The macros whose expansion transitively mentions `env->`."""
    hit = {n for n, (_, b) in macros.items() if 'env->' in b}
    changed = True
    while changed:
        changed = False
        for n, (_, b) in macros.items():
            if n in hit:
                continue
            for w in re.findall(r'[A-Za-z_][A-Za-z_0-9]*', b):
                if w in hit:
                    hit.add(n)
                    changed = True
                    break
    return hit


def _args(text, i):
    """text[i] == '(' -> (list of argument strings, index past the ')')."""
    depth, j, start, args = 0, i, i + 1, []
    while j < len(text):
        c = text[j]
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
            if depth == 0:
                args.append(text[start:j])
                return args, j + 1
        elif c == ',' and depth == 1:
            args.append(text[start:j])
            start = j + 1
        j += 1
    return None, i


def expand_macros(text, macros, names, rounds=8):
    """Expand `names` in `text` to a fixed point (bounded)."""
    pat = re.compile(r'\b(%s)\b' % '|'.join(sorted(names, key=len,
                                                   reverse=True)))
    for _ in range(rounds):
        out, i, hit = [], 0, False
        while True:
            m = pat.search(text, i)
            if not m:
                out.append(text[i:])
                break
            params, body = macros[m.group(1)]
            k = m.end()
            if params is None:
                out.append(text[i:m.start()])
                out.append('(' + body + ')')
                i, hit = k, True
                continue
            j = k
            while j < len(text) and text[j] in ' \t\n':
                j += 1
            if j >= len(text) or text[j] != '(':
                out.append(text[i:k])       # a bare name, not an invocation
                i = k
                continue
            args, end = _args(text, j)
            if args is None or len(args) != len(params):
                out.append(text[i:k])
                i = k
                continue
            rep = body
            for pn, av in zip(params, args):
                rep = re.sub(r'\b%s\b' % re.escape(pn), '(' + av + ')', rep)
            out.append(text[i:m.start()])
            out.append('(' + rep + ')')
            i, hit = end, True
        text = ''.join(out)
        if not hit:
            break
    return text


def preprocess(text):
    """strip comments, expand the env-reaching macros, drop the directives."""
    text = strip_comments(text)
    macros = collect_macros(text)
    names = _reaching(macros)
    text = _PP.sub('', text)
    if names:
        text = expand_macros(text, macros, names)
    return text, {n: macros[n] for n in names}


def load_functions(root):
    fns, expanded = {}, {}
    for rel in SRC:
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            sys.exit('x87_cw_derive: missing %s' % p)
        text, used = preprocess(open(p).read())
        expanded.update(used)
        fns.update(split_functions(text))
    # THE ASSERTION THAT MAKES THE EXPANSION A MEASUREMENT.  If QEMU ever
    # stops hiding the TOP read behind a macro -- or renames the field --
    # this run FAILS instead of quietly reporting that no x87 form reads the
    # top of stack, which is the answer the un-expanded reading gave.
    if not any('env->fpstt' in b for _, b in expanded.values()):
        sys.exit('x87_cw_derive: no macro in %s expands to env->fpstt -- the '
                 'stack-addressing macros have changed, re-derive' % SRC[0])
    return fns, expanded


# The three architectural registers the x87 environment instructions move,
# in QEMU's own field names.  REG_FPCW is the control word; the status
# word, the TOP field that lives inside it and the tag word all land on
# REG_FCSR in the tracer's vocabulary, so they are one group here.
GROUPS = {
    'fpuc':   [r'env->fpuc'],
    'status': [r'env->fpus', r'env->fpstt', r'env->fptags'],
}


def direct_facts(name, body, group):
    """Positional facts for one function body and one field group.

    Returns (read_positions, def_positions, {callee: first_position}).
    A position is a STATEMENT INDEX, not a byte offset.  It has to be:
    `env->fpstt = (env->fpstt + 1) & 7` writes and READS the same field in
    one statement, and a byte-offset dominance test would let the write
    kill the read that feeds it and report `fpop` as touching the top of
    stack without depending on it.  These functions are straight-line with
    respect to the fields in question, so a statement index is all the
    ordering the dominance test needs.
    """
    def stmt(off):
        return body.count(';', 0, off)

    # R7.1 IS APPLIED HERE, and it has to be.  `helper_fcom_ST0_FT0` writes
    # the condition-code FIELD of the status word:
    #
    #     env->fpus = (env->fpus & ~0x4500) | fcom_ccval[ret + 1];
    #
    # The read on the right is there to preserve the bits the write does not
    # produce.  A narrow write does not acquire a source -- the maintainer's
    # ruling, verbatim -- so counting it would have this tool over-name the
    # status word on `fcom`, `fucom`, `ftst` and `ficom` in exactly the way
    # gem5 over-names a narrow register write, which is the row class R7.1
    # was written for.  A masked read (`F &`) inside a statement that assigns
    # F is a PRESERVE read and is dropped; an arithmetic one
    # (`env->fpstt = (env->fpstt + 1) & 7`) is a genuine read-modify-write
    # and is kept, which is what makes `fpush` / `fpop` depend on TOP.
    reads, defs = [], []
    for field in GROUPS[group]:
        for m in re.finditer(field + r'(\[[^\]]*\])?', body):
            tail = body[m.end():m.end() + 4]
            if re.match(r'\s*(=[^=]|\|=|&=|\^=|\+=|-=|\+\+|--)', tail):
                defs.append(stmt(m.start()))
            elif re.match(r'\s*&[^&]', tail) and stmt(m.start()) in [
                    stmt(d.start()) for d in
                    re.finditer(field + r'(\[[^\]]*\])?\s*=[^=]', body)]:
                pass                       # preserve read of a narrow write
            else:
                reads.append(stmt(m.start()))

    # fp_status is the DECODED control word plus the accumulated exception
    # flags.  A softfloat routine handed it that is not one of the three
    # exception-flag accessors consults the rounding mode and the precision
    # control, which update_fp_status() wrote out of env->fpuc.
    if group == 'fpuc':
        for m in re.finditer(r'&\s*env->fp_status\b', body):
            d = 0
            j = m.start()
            while j > 0:
                if body[j] == ')':
                    d += 1
                elif body[j] == '(':
                    if d == 0:
                        break
                    d -= 1
                j -= 1
            c = re.search(r'([A-Za-z_][A-Za-z_0-9]*)\s*$', body[:j])
            if (c.group(1) if c else '') not in FLAG_ONLY:
                reads.append(stmt(m.start()))

    callees = {}
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z_0-9]*)\s*\(', body):
        n = m.group(1)
        if n == name:
            continue
        callees.setdefault(n, stmt(m.start()))
    return sorted(reads), sorted(defs), callees


def _fixpoint(fns, group):
    """Fixed point over (READS the group, WRITES the group).

    A read counts only when no write dominates it.  Both properties travel
    the call graph; a callee that writes without reading first is a KILL at
    its call site, which is what makes `fldcw` a pure write of the control
    word rather than a read of it.
    """
    facts = {n: direct_facts(n, b, group) for n, b in fns.items()}
    INF = float('inf')
    reads = {n: False for n in fns}
    writes = {n: False for n in fns}
    rwhy = {n: '' for n in fns}
    wwhy = {n: '' for n in fns}

    changed = True
    while changed:
        changed = False
        for n, (rpos, dpos, callees) in facts.items():
            dfirst = dpos[0] if dpos else INF
            dwhy = 'assigns it directly'
            for c, p in callees.items():
                if writes.get(c) and not reads.get(c) and p < dfirst:
                    dfirst = p
                    dwhy = 'calls %s (%s)' % (c, wwhy[c])
            # a callee that writes AFTER reading still writes
            wnow, wnow_why = dfirst < INF, dwhy
            if not wnow:
                for c, p in sorted(callees.items(), key=lambda kv: kv[1]):
                    if writes.get(c):
                        wnow = True
                        wnow_why = 'calls %s (%s)' % (c, wwhy[c])
                        break

            rnow, rnow_why = False, ''
            if rpos and rpos[0] <= dfirst:
                rnow = True
                rnow_why = 'reads it directly'
            else:
                for c, p in sorted(callees.items(), key=lambda kv: kv[1]):
                    if p > dfirst:
                        break
                    if reads.get(c):
                        rnow = True
                        rnow_why = 'calls %s (%s)' % (c, rwhy[c])
                        break

            if rnow and not reads[n]:
                reads[n], rwhy[n], changed = True, rnow_why, True
            if wnow and not writes[n]:
                writes[n], wwhy[n], changed = True, wnow_why, True

    return reads, writes, rwhy, wwhy


def build(root):
    fns, macros = load_functions(root)

    csf = fns.get('cpu_set_fpuc')
    if not csf:
        sys.exit('x87_cw_derive: cpu_set_fpuc not found -- re-derive')
    _a = re.search(r'env->fpuc\s*=[^=]', csf)
    _d = csf.find('update_fp_status')
    if not _a or _d < 0 or _a.start() > _d:
        sys.exit('x87_cw_derive: cpu_set_fpuc no longer assigns env->fpuc '
                 'before decoding it -- the def-kill is unsound, re-derive')

    axes = {}
    for g in GROUPS:
        r, w, rw, ww = _fixpoint(fns, g)
        axes[g] = dict(read=r, write=w, rwhy=rw, wwhy=ww)
    return fns, axes, macros


# ------------------------------------------------------- the callable oracle
#
# The derivation above answers a table of 153 subjects placed at fixed
# addresses by x87_cw_probe.  A CONSUMER -- the wrong-path leg -- needs the
# same answer keyed by ENCODING, for whatever encodings its own guests
# happened to contain, and it already runs every guest under
# `-one-insn-per-tb -d op,in_asm` for the preserve oracle.  StatusOracle
# reads those same dumps.
#
# IT REFUSES RATHER THAN GUESSES, on the same terms the preserve oracle
# refuses: an encoding the dump never carried, an encoding QEMU lowered with
# no helper call at all, or a helper whose body is not in the analysed
# sources are all UNKNOWN.  "The walk did not look" is never reported as
# "the machine does not read it" (R5).

STATUS_READ = 'x87-status-read'
STATUS_NOT_READ = 'x87-status-not-read'


class StatusOracle(object):
    """encoding hex -> does QEMU read {fpus, fpstt, fptags}?"""

    def __init__(self, root=Q):
        self.fns, self.axes, self.macros = build(root)
        self.calls = {}             # enc -> [helper names], first dump wins
        self.disas = {}
        self.refused = collections.Counter()

    def add_dump(self, path):
        """Read a `-d op,in_asm` dump, keyed by encoding."""
        import qemu_preserve_oracle as _QPO
        for enc, e in _QPO.parse_dump(path).items():
            if enc in self.calls:
                continue
            self.calls[enc] = [a[0] for name, a in e.ops
                               if name == 'call' and a]
            self.disas[enc] = e.disas

    def _key(self, h):
        if 'helper_' + h in self.fns:
            return 'helper_' + h
        return h if h in self.fns else None

    def reads_status(self, enc):
        """True | False | None (REFUSED)."""
        helpers = self.calls.get(enc)
        if not helpers:
            # No dump for this encoding, or QEMU emitted no call at all.
            # Neither is evidence that nothing is read: env->fpstt is not a
            # TCG global, so the op list alone cannot state the fact.
            self.refused['%s: %s' % (
                self.disas.get(enc, enc),
                'no op dump' if helpers is None else 'no helper call')] += 1
            return None
        out = False
        for h in helpers:
            k = self._key(h)
            if k is None:
                self.refused['%s: helper %s has no body in %s'
                             % (self.disas.get(enc, enc), h,
                                ', '.join(SRC))] += 1
                return None
            out = out or self.axes['status']['read'][k]
        return out


def read_blocks(op_path):
    blocks = collections.defaultdict(list)
    cur = None
    for ln in open(op_path):
        m = re.match(r'\s*---- ([0-9a-f]{16})\b', ln)
        if m:
            cur = int(m.group(1), 16)
            blocks[cur]                      # touch
            continue
        if cur is None:
            continue
        m2 = re.match(r'\s*call ([A-Za-z_0-9]+),', ln)
        if m2:
            blocks[cur].append(m2.group(1))
    return blocks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default=Q)
    ap.add_argument('--op', required=True, help='TCG op dump from x87_cw_probe')
    ap.add_argument('--subjects', required=True,
                    help='TSV: probe_hex, mnemonic, encoding, extension, mech')
    ap.add_argument('--base', default='0x70000000')
    ap.add_argument('--stride', default='0x10000')
    ap.add_argument('-o', '--out', required=True)
    a = ap.parse_args()

    fns, axes, macros = build(a.root)
    blocks = read_blocks(a.op)
    base = int(a.base, 16)
    stride = int(a.stride, 16)

    subs = [l.split('\t') for l in
            open(a.subjects).read().splitlines() if l.strip()]

    AX = [('fpuc', 'read'), ('fpuc', 'write'),
          ('status', 'read'), ('status', 'write')]

    unknown = collections.Counter()
    rows = []
    for i, s_ in enumerate(subs):
        pc = base + i * stride
        helpers = blocks.get(pc)
        if helpers is None:
            rows.append(s_[:5] + ['NO-BLOCK'] * 4 + ['', ''])
            continue
        verdict = {k: 'no' for k in AX}
        why = {k: '' for k in AX}
        for h in helpers:
            key = 'helper_' + h if 'helper_' + h in fns else (
                h if h in fns else None)
            if key is None:
                unknown[h] += 1
                continue
            for g, kind in AX:
                if axes[g][kind][key] and verdict[(g, kind)] == 'no':
                    verdict[(g, kind)] = 'yes'
                    why[(g, kind)] = '%s: %s' % (
                        h, axes[g]['rwhy' if kind == 'read' else 'wwhy'][key])
        rows.append(s_[:5] + [verdict[k] for k in AX] +
                    [','.join(helpers),
                     ' | '.join('%s-%s %s' % (g, k, why[(g, k)])
                                for g, k in AX if verdict[(g, k)] == 'yes')])

    with open(a.out, 'w') as f:
        f.write('probe_hex\tmnemonic\tencoding\textension\tmechanism\t'
                'cw_read\tcw_write\tsw_read\tsw_write\thelpers\twhy\n')
        for r in rows:
            f.write('\t'.join(r) + '\n')

    cnt = collections.Counter()
    for r in rows:
        for n, (g, k) in enumerate(AX):
            cnt['%s_%s' % (g, k)] += (r[5 + n] == 'yes')
    n_bad = sum(1 for r in rows if r[5] == 'NO-BLOCK')
    print('x87_cw_derive: %d subjects' % len(rows))
    print('  macros expanded before the walk (env-reaching, transitive): %s'
          % ', '.join(sorted(macros)))
    for g, k in AX:
        print('  %-12s yes %3d   no %3d' % (
            '%s-%s' % (g, k), cnt['%s_%s' % (g, k)],
            len(rows) - n_bad - cnt['%s_%s' % (g, k)]))
    if unknown:
        print('  helpers with no body in the analysed sources '
              '(treated as touching nothing -- state them):')
        for h, c in unknown.most_common():
            print('    %-24s x%d' % (h, c))
    if n_bad:
        print('  A SUBJECT WITH NO TRANSLATED BLOCK IS NOT A "no": '
              'the probe never reached it.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
