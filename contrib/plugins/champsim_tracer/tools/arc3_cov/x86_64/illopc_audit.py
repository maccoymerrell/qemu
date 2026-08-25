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


# ------------------------------------------------- leg (b): the QEMU tables
class Tables(object):
    """decode-new.c.inc, parsed from the tree on every run."""

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
            reg = (d['modrm'] >> 3) & 7
            e = self.root_t.get(0x8f)
            if reg == 0:
                return ('OCCUPIED', 'XOP-REG0-IS-POP',
                        'opcodes_root[0x8F] -> group1A ModRM.reg==0 is POP')
            return ('ABSENT', 'XOP-IS-POP-GROUP1A',
                    'opcodes_root[0x8F] (%s:%d) = X86_OP_GROUPw(group1A, '
                    'E,d64); decode_group1A assigns `*entry = UNKNOWN_OPCODE` '
                    'for ModRM.reg != 0 (here reg=%d) under the comment '
                    '"could be XOP prefix too".  QEMU never decodes the 0x8F '
                    'XOP prefix.' % (_DECODE, e[0], reg))

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
            mod = (d['modrm'] >> 6) & 3 if d['modrm'] is not None else None
            reg = (d['modrm'] >> 3) & 7 if d['modrm'] is not None else None
            if op == 0xc7 and mod != 3 and reg != 1:
                return ('ABSENT', '0F-GROUP9-UNKNOWN',
                        'opcodes_0F[0xC7] (%s:%d) = X86_OP_GROUP0(group9); '
                        'decode_group9 defines only ModRM.reg==1 '
                        '(CMPXCHG8B/16B) for a memory operand and mod==3 '
                        '(multi0F).  This probe is mod=%d reg=%d, which takes '
                        'the final `else { *entry = UNKNOWN_OPCODE; }`.  '
                        'QEMU\'s group 9 has no VMPTRLD/VMPTRST/VMCLEAR/'
                        'VMXON slot.' % (_DECODE, e[0], mod, reg))
            if op == 0x78 and not (d['pre'] & {'66', 'f2'}):
                return ('ABSENT', '0F78-COL-EMPTY',
                        'opcodes_0F[0x78] (%s:%d) = X86_OP_GROUP0(0F78); the '
                        'by-prefix table opcodes_0F78[4] is { {}, EXTRQ_i(66),'
                        ' {}, INSERTQ_i(F2) }.  This probe carries no 66/F2, '
                        'so the column is `{}` -> gen==NULL.  There is no '
                        'VMREAD entry.' % (_DECODE, e[0]))
            if op == 0x79 and not (d['pre'] & {'66', 'f2'}):
                return ('ABSENT', '0F79-GEN-NULL',
                        'opcodes_0F[0x79] (%s:%d) = X86_OP_GROUP2(0F79, ...); '
                        'decode_0F79 sets gen only for F2 (INSERTQ_r) and 66 '
                        '(EXTRQ_r) and otherwise assigns `entry->gen = NULL`. '
                        'There is no VMWRITE entry.' % (_DECODE, e[0]))
            return ('OCCUPIED', '0F-SLOT-OCCUPIED',
                    'opcodes_0F[0x%02x] IS occupied at %s:%d -> %s'
                    % (op, _DECODE, e[0], e[1]))

        e = self.root_t.get(op)
        if e is None:
            return ('ABSENT', 'ROOT-SLOT-EMPTY',
                    'opcodes_root[0x%02x] (table at %s:%d) has no designated '
                    'initializer.' % (op, _DECODE, self.root_l))
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


def judge(mnem, nbytes, ok, length, name, strip=()):
    """One decoder's opinion: OK / NAME:x / LEN:n / REFUSED."""
    if not ok:
        return 'REFUSED'
    if int(length) != nbytes:
        return 'LEN:%s' % length
    n = _norm(name)
    for p in strip:
        if n.startswith(p):
            n = n[len(p):]
            break
    return ('OK:' if n.startswith(_norm(mnem)) else 'NAME:') + name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--matrix', required=True)
    ap.add_argument('--xl3', required=True, help='xl3.tsv (XED + LLVM MC)')
    ap.add_argument('--iced', required=True, help='iced.tsv')
    ap.add_argument('--objdump', action='append', default=None,
                    help='objdump to consult; repeatable.  A DISTRIBUTION '
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
    fatal = []
    for r in rows:
        h, mn = r['probe_hex'], r['mnemonic']
        n = len(h) // 2
        x, l, i = xed.get(h), llvm.get(h), iced.get(h)
        o = od.get(h)
        vx = judge(mn, n, x and x['ok'] == '1', x['len'] if x else 0,
                   x['mnem'] if x else '', ('rep',)) if x else 'REFUSED'
        vl = judge(mn, n, l and l['ok'] == '1', l['len'] if l else 0,
                   l['mnem'] if l else '') if l else 'REFUSED'
        vi = judge(mn, n, i and i['ok'] == '1', i['len'] if i else 0,
                   i['mnem'] if i else '',
                   ('vex', 'evex', 'xop', 'mvex')) if i else 'REFUSED'
        vos = []
        for t in ods:
            e = t.get(h)
            vos.append(judge(mn, n, e[0], e[1], objdump_mnem(e[2]))
                       if e else 'REFUSED')
        opin = (vx, vl, vi) + tuple(vos)
        nok = sum(1 for v in opin if v.startswith('OK'))
        bad = [v for v in opin if v.startswith(('NAME:', 'LEN:'))]
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
        verdict, cls, why = tabs.cite(h)
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
