"""
ARC 3 -- the SUBJECT census of a comparison axis.

WHY THIS EXISTS
===============
An execution leg reports one row per DISAGREEMENT, so an axis that compared
nothing at all reports the same clean zero as an axis that compared forty
thousand facts and found them all right.  The two are opposite results and
the report could not tell them apart: the aarch64 leg grew a FACTS column for
exactly that reason (``arc3_cov/gem5: an axis that compared nothing would have
reported a clean zero``), and the other three legs did not have one.

A fact count alone is still not enough.  An axis whose forty thousand facts
all came from ONE encoding, in a loop, has seen one subject -- and a
falsifier that fires on that one subject says nothing about any other.  So
this records two numbers per axis and they answer different questions:

  FACTS      how many comparisons the axis actually performed.  Zero makes
             the axis INERT: its clean row is survivorship bias, and the
             remedy is a better probe, never a pass.
  SUBJECTS   how many DISTINCT ENCODINGS carried a fact on that axis.  This
             is the number a loop cannot inflate, and it is deliberately
             the encoding rather than the opcode: counting encodings needs
             no decoder in the instrument, and it is the conservative
             direction -- N distinct encodings are at most N distinct
             opcodes.  ``leg_census.py`` maps the encodings onto opcodes and
             onto the tracer's generic classes when the vocabulary is what
             is wanted.

Author: Maccoy Merrell.
"""
import collections


class Subjects(object):
    """Per-axis fact and distinct-encoding census for one leg."""

    __slots__ = ('facts', 'enc')

    def __init__(self):
        self.facts = collections.Counter()
        self.enc = collections.defaultdict(set)

    def note(self, axis, insn=None, n=1):
        """Record ``n`` comparisons on ``axis``, carried by ``insn``.

        ``insn`` is a ``wp_trace.Insn``; it is optional because two axes are
        not carried by an instruction at all -- ``pc-sequence`` is one fact
        about a whole excursion and ``wp-entry-state`` is about the state
        installed before the first one.  Those axes get facts and no
        subjects, and the report says so rather than printing a zero that
        would read as INERT.
        """
        self.facts[axis] += n
        if insn is not None:
            self.enc[axis].add(insn.bits.to_bytes(insn.nbytes, 'little').hex())

    def merge(self, other):
        self.facts.update(other.facts)
        for k, v in other.enc.items():
            self.enc[k] |= v

    def inert(self, axes):
        """The axes that compared NOTHING.  Their zero is not a result."""
        return [a for a in axes if not self.facts[a]]

    def render(self, axes, counts, verdicts):
        """The FACTS / SUBJECTS table, as report lines.

        ``counts`` is (axis, verdict) -> n and ``verdicts`` the column order,
        so the table this returns IS the verdict split rather than a second
        table beside it that a reader has to join by eye.
        """
        out = []
        out.append('The FACTS column is the number of comparisons the axis')
        out.append('actually performed and SUBJECTS is how many DISTINCT')
        out.append('encodings carried one.  A zero row count on an axis that')
        out.append('compared NOTHING is survivorship bias, not coverage: such')
        out.append('an axis is marked INERT, which is a demand for a better')
        out.append('probe and never a pass.  A low SUBJECTS count next to a')
        out.append('high FACTS count is a loop, and it is stated rather than')
        out.append('left for a reader to infer.')
        out.append('')
        wid = max(16, max(len(a) for a in axes) + 1)
        hdr = ('%-*s %9s %9s' % (wid, 'axis', 'facts', 'subjects')
               + ''.join('%*s' % (max(len(v) + 2, 12), v) for v in verdicts))
        out.append(hdr)
        out.append('-' * len(hdr))
        for ax in axes:
            f = self.facts[ax]
            s = len(self.enc[ax])
            out.append(('%-*s %9s %9s' % (wid, ax,
                                          'INERT' if not f else str(f),
                                          '-' if not s else str(s)))
                       + ''.join('%*d' % (max(len(v) + 2, 12),
                                          counts[(ax, v)])
                                 for v in verdicts))
        out.append('-' * len(hdr))
        tot = collections.Counter()
        for (ax, v), n in counts.items():
            if ax in axes:
                tot[v] += n
        allenc = set()
        for ax in axes:
            allenc |= self.enc[ax]
        out.append(('%-*s %9d %9d' % (wid, 'TOTAL',
                                      sum(self.facts[a] for a in axes),
                                      len(allenc)))
                   + ''.join('%*d' % (max(len(v) + 2, 12), tot[v])
                             for v in verdicts))
        out.append('')
        dead = self.inert(axes)
        if dead:
            out.append('INERT AXES (compared nothing; their zero is NOT a '
                       'result): %s' % ', '.join(dead))
        else:
            out.append('No axis INERT: every axis above performed at least '
                       'one comparison.')
        thin = [a for a in axes
                if self.facts[a] and len(self.enc[a]) and
                self.facts[a] >= 20 * len(self.enc[a])]
        if thin:
            out.append('LOOP-INFLATED AXES (20x more facts than distinct '
                       'subjects): %s' % ', '.join(thin))
        out.append('')
        return out

    def write_tsv(self, path, axes):
        """axis, facts, subjects, and every encoding, for the census tool."""
        with open(path, 'w') as fh:
            fh.write('axis\tfacts\tsubjects\tencodings\n')
            for ax in axes:
                fh.write('%s\t%d\t%d\t%s\n'
                         % (ax, self.facts[ax], len(self.enc[ax]),
                            ','.join(sorted(self.enc[ax]))))
