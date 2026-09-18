#!/usr/bin/env python3
"""
THE WIRE-AXIS CENSUS -- what a corpus actually carries, per fact class.

WHY THIS EXISTS.  The R13 legs answer "does the wire AGREE with a reference",
one leg per reference, and each leg's population is its own probe set.  None
of them answers the prior question: over a corpus, does the wire CARRY the
fact class at all, and on how many distinct encodings?  That question has
been answered by reading a decode by eye, which is exactly the shape a
standing ruling forbids -- a hand-listed instrument proves nothing about what
was not listed, and an axis that carries nothing reports the same clean zero
as an axis that carries everything.

So this reads a whole corpus through ``cst_decode`` and reports, per axis,
two numbers with different meanings:

  FACTS     how many observations of that class the corpus carries.  Zero
            makes the axis INERT over this corpus.  An INERT axis is a GAP,
            never a pass, and ``--require`` turns it into a non-zero exit.
  SUBJECTS  how many DISTINCT INSTRUCTION ENCODINGS carried one.  A loop
            cannot inflate this, and it is the encoding rather than the
            opcode because counting encodings needs no decoder here.  On the
            two WIDTH axes the subject is the distinct WIDTH instead, because
            what has to be shown there is that the extent varies and is not a
            constant the format happens to print.

THE AXES ARE THE ONES A CONSUMER SCHEDULES AGAINST, and the CP and WP halves
are counted separately because they are produced by different machinery and a
WP zero hidden inside a CP total is precisely the survivorship this exists to
expose:

  reg-src            a register named as an input
  reg-dst            a register named as an output
  reg-dst-value      an output that also carries a VALUE
  reg-dst-novalue    an output named with NO value (the value gap, counted
                     rather than left to be discovered)
  reg-dst-width      an output whose value carries a non-zero width
  memop-addr         a memory access with an address
  memop-load         an access stated as a load
  memop-store        an access stated as a store
  memop-value        an access that also carries its datum
  memop-size         an access whose datum carries a non-zero width
  lane-mask          an operand annotated with a lane set (--show-lanes)
  dep-map            an instruction carrying an intra-instruction dep map
                     (--show-deps)

USAGE

  wire_axis_census.py --decode <cst_decode> [-o OUT] <trace.cst|dir> ...
  wire_axis_census.py --decode <cst_decode> --require reg-dst,memop-addr ...

``--require`` names axes that MUST be non-inert; the process exits 1 if any
named axis has zero facts, and it also exits 1 if the corpus decoded to no
instruction at all.  A check that cannot find its subject fails.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

SPDX-License-Identifier: GPL-2.0-or-later
"""
import argparse
import collections
import os
import re
import subprocess
import sys

AXES = ('reg-src', 'reg-dst', 'reg-dst-value', 'reg-dst-novalue',
        'reg-dst-width', 'memop-addr', 'memop-load', 'memop-store',
        'memop-value', 'memop-size', 'lane-mask', 'dep-map')

#: `0x000000400054: 40 00 01 3c   mov   %zero -> %gp1[0x400000/w4]  ; deps: ...`
#: The address may carry a SYMBOL -- `0x40014c <blk_0>: ...` -- and the
#: optional group is not cosmetic: without it this instrument silently read 7
#: instructions out of an 11,266-instruction validator cell, which is the
#: under-count-that-reports-clean shape it exists to expose.
_INSN = re.compile(r'^0x[0-9a-f]+(?:\s+<[^>]*>)?:\s+'
                   r'((?:[0-9a-f]{2}\s)+)\s*(\S+)\s*(.*)$')
#: a memory access: `ld[%gp16](0x410180)` / `st[%gp16](0x410280)`
_MEMOP = re.compile(r'\b(ld|st)\[([^\]]*)\]\((0x[0-9a-f]+)\)')
#: the datum that rides with it: `ld=0x8b68073/w4`
_MEMVAL = re.compile(r'\b(ld|st)=0x[0-9a-f]+(?:/w(\d+))?')
#: a register operand, optionally valued: `%gp1[0x400000/w4]`
_REG = re.compile(r'%([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?')
#: a lane set, as --show-lanes prints it
_LANES = re.compile(r'\{[0-9][0-9.,]*\}')
#: the WP block marker cst_decode writes
_WPHDR = re.compile(r'^;\s+\.{3,}\s*wp\[')
_CPHDR = re.compile(r'^;\s+-{3,}\s*BB ')


class Census(object):
    """FACTS and distinct-encoding SUBJECTS, per axis, per path."""

    def __init__(self):
        self.facts = collections.Counter()
        self.enc = collections.defaultdict(set)
        self.insns = collections.Counter()
        self.insn_enc = collections.defaultdict(set)

    def note(self, path, axis, enc, n=1):
        self.facts[(path, axis)] += n
        self.enc[(path, axis)].add(enc)

    def note_insn(self, path, enc):
        self.insns[path] += 1
        self.insn_enc[path].add(enc)

    def merge(self, other):
        self.facts.update(other.facts)
        self.insns.update(other.insns)
        for k, v in other.enc.items():
            self.enc[k] |= v
        for k, v in other.insn_enc.items():
            self.insn_enc[k] |= v


def scan_lines(lines, cen):
    """Walk one decode; CP until a wp[] header, WP until the next BB header."""
    path = 'cp'
    for line in lines:
        if _WPHDR.match(line):
            path = 'wp'
            continue
        if _CPHDR.match(line):
            path = 'cp'
            continue
        m = _INSN.match(line)
        if m is None:
            continue
        enc = m.group(1).replace(' ', '')
        body = m.group(3)
        cen.note_insn(path, enc)

        deps = None
        if '; deps:' in body:
            body, deps = body.split('; deps:', 1)
        if deps is not None and deps.strip():
            cen.note(path, 'dep-map', enc)

        # The profile tail is bookkeeping, not operands.
        body = body.split('prof:', 1)[0]

        for lane in _LANES.findall(body):
            cen.note(path, 'lane-mask', enc)

        for kind, _base, _addr in _MEMOP.findall(body):
            cen.note(path, 'memop-addr', enc)
            cen.note(path, 'memop-load' if kind == 'ld' else 'memop-store',
                     enc)
        for kind, w in _MEMVAL.findall(body):
            if w and int(w) > 0:
                cen.note(path, 'memop-value', enc)
                cen.note(path, 'memop-size', w)

        # Registers, after the memop tokens are removed so an address base is
        # scored once, on the side of the arrow it was printed on.
        stripped = _MEMVAL.sub('', _MEMOP.sub(lambda m: '%' + m.group(2).strip('%')
                                              if m.group(2).startswith('%')
                                              else '', body))
        lhs, _, rhs = stripped.partition('->')
        for _name, val in _REG.findall(lhs):
            cen.note(path, 'reg-src', enc)
        for _name, val in _REG.findall(rhs):
            cen.note(path, 'reg-dst', enc)
            wm = re.search(r'/w(\d+)', val) if val else None
            if val and val.startswith('[0x') and wm and int(wm.group(1)) > 0:
                # A VALUE is a datum with an extent.  `[0x0]` with no width is
                # a destination the wire names and does not value, and it is
                # counted as such rather than folded in with the valued ones.
                cen.note(path, 'reg-dst-value', enc)
                cen.note(path, 'reg-dst-width', wm.group(1))
            else:
                cen.note(path, 'reg-dst-novalue', enc)


def one(decode, cst, cen):
    p = subprocess.run([decode, '--show-deps', '--show-lanes', cst],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return False
    scan_lines(p.stdout.splitlines(), cen)
    return True


def collect(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.endswith('.cst') or name.endswith('.cst.zst'):
                    out.append(os.path.join(p, name))
        else:
            out.append(p)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--decode', required=True)
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--require', default='',
                    help='comma-separated axes that must not be INERT')
    ap.add_argument('--label', default='')
    ap.add_argument('traces', nargs='+')
    a = ap.parse_args()

    files = collect(a.traces)
    cen = Census()
    ok = bad = 0
    for f in files:
        if one(a.decode, f, cen):
            ok += 1
        else:
            bad += 1

    lines = []
    lines.append('# wire-axis census%s' % ((' -- ' + a.label) if a.label else ''))
    lines.append('# cells decoded %d, cells that would not decode %d' % (ok, bad))
    lines.append('# instructions cp=%d (encodings %d)  wp=%d (encodings %d)'
                 % (cen.insns['cp'], len(cen.insn_enc['cp']),
                    cen.insns['wp'], len(cen.insn_enc['wp'])))
    lines.append('')
    lines.append('%-18s %12s %10s %12s %10s' %
                 ('axis', 'cp-facts', 'cp-subj', 'wp-facts', 'wp-subj'))
    for ax in AXES:
        lines.append('%-18s %12d %10d %12d %10d' %
                     (ax, cen.facts[('cp', ax)], len(cen.enc[('cp', ax)]),
                      cen.facts[('wp', ax)], len(cen.enc[('wp', ax)])))
    text = '\n'.join(lines) + '\n'
    sys.stdout.write(text)
    if a.out:
        with open(a.out, 'w') as f:
            f.write(text)

    rc = 0
    if cen.insns['cp'] == 0 and cen.insns['wp'] == 0:
        sys.stderr.write('wire_axis_census: REFUSING -- the corpus decoded '
                         'to no instruction; a zero over an empty population '
                         'is a gap, not a reading\n')
        rc = 1
    if bad:
        sys.stderr.write('wire_axis_census: %d cell(s) would not decode\n'
                         % bad)
        rc = 1
    for ax in [s for s in a.require.split(',') if s]:
        if ax not in AXES:
            sys.stderr.write('wire_axis_census: unknown axis %s\n' % ax)
            rc = 1
            continue
        if cen.facts[('cp', ax)] == 0 and cen.facts[('wp', ax)] == 0:
            sys.stderr.write('wire_axis_census: INERT %s -- required and '
                             'carries nothing on this corpus\n' % ax)
            rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
