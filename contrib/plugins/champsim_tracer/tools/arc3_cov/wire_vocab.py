"""The names the WIRE prints, read from the header that defines them.

WHY THIS EXISTS, AND IT IS NOT TIDINESS.

A comparator's adjudication rules are keyed on the tracer's register NAMES.
Four of them were keyed on ``REG_PC``, a spelling this branch's wire has
never used: ``champsim_tracer_generic_ids.h`` defines ``REG_IP = 252`` and
``cst_generic_reg_name()`` returns the string ``"REG_IP"``.  The rules
therefore matched nothing, and every row they existed to name was reported
UNACCOUNTED -- the disqualifying column -- while the reason the reference
could not state the fact was written down two files away.

The spelling has been both across this tree's history, which is exactly why
a constant copied into a comparator goes stale without anything failing.  So
the name is READ from the header on every run, and the reader REFUSES rather
than guessing: a check that cannot find its subject must fail, and a
comparator that silently adjudicates nothing is that failure wearing a
green.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

SPDX-License-Identifier: GPL-2.0-or-later
"""
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))

#: the header that DEFINES the wire's register vocabulary.
GENERIC_IDS = os.path.abspath(os.path.join(
    _HERE, '..', '..', 'champsim_tracer_generic_ids.h'))

#: `case REG_X: return "REG_X";` -- the name-returning switch in
#: cst_generic_reg_name(), which is what a decoded trace actually prints.
#: The ENUM row is not the authority here: an id can be defined and never
#: reach a name, and it is the printed name a comparator joins on.
_NAME_ROW = re.compile(r'^\s*case\s+(REG_[A-Z0-9_]+)\s*:\s*'
                       r'return\s+"(REG_[A-Z0-9_]+)"\s*;')

#: every spelling this tree has used for the program counter.  The header
#: decides which one is live; this set only bounds the question so that a
#: THIRD spelling arriving one day is a refusal and not a silent miss.
_PC_SPELLINGS = ('REG_IP', 'REG_PC')


def printed_names(path=None):
    """{name} -- every register name cst_generic_reg_name() can return.

    Only the singleton cases; the dense bank ranges (REG_GPR#, REG_VEC#,
    REG_PRED#, REG_ACC#, ...) are formatted, not cased, and no caller here
    needs them.
    """
    path = path or GENERIC_IDS
    if not os.path.exists(path):
        raise SystemExit('wire_vocab: the generic-id header moved: %s' % path)
    names = set()
    with open(path) as fh:
        for line in fh:
            m = _NAME_ROW.match(line)
            if m:
                # the RETURNED STRING, not the case label.  What a decoded
                # trace prints is the string, so that is what a comparator
                # joins on; taking the label instead would answer for a
                # header whose two halves had drifted apart.
                names.add(m.group(2))
    if len(names) < 8:
        raise SystemExit('wire_vocab: the name switch no longer parses out '
                         'of %s (%d names found)' % (path, len(names)))
    return names


def pc_name(path=None):
    """The name the wire prints for the program counter.

    Refuses on zero matches (the vocabulary moved and nothing told us) and
    on two (the header would be defining both, so a rule keyed on either
    would be half right).  Either way the caller stops instead of
    adjudicating against a name that is not on the wire.
    """
    names = printed_names(path)
    live = [n for n in _PC_SPELLINGS if n in names]
    if len(live) != 1:
        raise SystemExit(
            'wire_vocab: %s names %d of %s as a program counter; a rule '
            'keyed on one spelling cannot be right. Found: %s'
            % (os.path.basename(path or GENERIC_IDS), len(live),
               '/'.join(_PC_SPELLINGS), sorted(live) or 'none'))
    return live[0]
