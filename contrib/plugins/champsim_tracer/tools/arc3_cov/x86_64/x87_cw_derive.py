#!/usr/bin/env python3
"""
ARC 3 -- DOES THIS x87 ENCODING READ THE x87 CONTROL WORD?

Answered from QEMU, in two halves that never consult the tracer:

  1. WHICH HELPERS the encoding runs.  Read off an OBSERVED TCG op dump
     (`qemu-x86_64 -one-insn-per-tb -d op`, x87_cw_probe.c), never off the
     switch in gen_x87() by eye.
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


def load_functions(root):
    fns = {}
    for rel in SRC:
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            sys.exit('x87_cw_derive: missing %s' % p)
        fns.update(split_functions(strip_comments(open(p).read())))
    return fns


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
    fns = load_functions(root)

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
    return fns, axes


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

    fns, axes = build(a.root)
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
