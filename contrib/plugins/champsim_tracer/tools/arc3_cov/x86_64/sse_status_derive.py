"""Does QEMU state a read of `env->sse_status` on this encoding?

THE QUESTION AND WHY IT IS NOT THE x87 ONE.  `x87_cw_derive.StatusOracle`
answers whether a helper touches the x87 STATUS GROUP -- {fpus, fpstt,
fptags} -- by expanding target/i386/tcg/fpu_helper.c's macros and walking its
call graph.  That derivation is sound for the x87 stack and it is SILENT
about SSE: `helper_addsd` is not in fpu_helper.c at all, it is generated out
of target/i386/ops_sse.h, so the oracle refuses every SSE encoding with
"helper addsd has no body in the analysed sources".

A refusal is honest, and a refusal is not an adjudication.  Reaching for the
x87 answer to explain an SSE row -- calling the tracer's REG_FCSR on
`mulps %xmm1,%xmm3` an unresolved x87 TOP read -- is the
false-justification class this tree files against: a plausible tag stretched
over a measurement it does not describe.  The SSE forms read a DIFFERENT
file, and this module is the oracle for that file.

WHERE THE ANSWER COMES FROM: QEMU'S OWN STATEMENT, NOT A RE-DERIVATION.
target/i386 keeps one `float_status` per FP datapath -- `fp_status` (x87),
`mmx_status` (3DNow!) and `sse_status` (SSE/AVX) -- and the generated
helper-usage table names the access outright:

    static const DfHelperField dfu_addsd_env[] = {
        { offsetof(CPUArchState, sse_status),
          sizeof(((CPUArchState *)0)->sse_status),
          INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },  /* ops_sse.h:529 */
    };

because the generator read `&env->sse_status` out of ops_sse.h.  That table
is not this harness's model of QEMU; it is the artifact the emulator itself
consults at translation time, and `bb24f882b2` declared those bytes so the
stated read arrives downstream carrying a NAME.  Reading it back here asks
QEMU the same question the wire asked, off the same file, so the oracle and
the wire cannot drift into separate opinions.

WHAT IT REFUSES.  An encoding the op dump never carried, an encoding QEMU
lowered with no helper call at all, and a helper with no row in the usage
table are all UNKNOWN -- returned as None, never as False.  "The walk did
not look" is never reported as "the machine does not read it" (R5).  The
integer-SIMD forms are the common case of the middle one: `paddq` is
gvec-inlined and calls nothing, so this oracle refuses it, which is correct
-- it reads no float_status and publishes no REG_FCSR either.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import collections
import os
import re

Q = '/mnt/md0/QEMU/qemu'

#: The generated usage table, per target.  Only i386 has an `sse_status`.
TABLE = 'accel/tcg/insn-dataflow-usage/i386.c.inc'

#: The member this oracle answers about, spelled as the table spells it.
MEMBER = 'sse_status'

_ARRAY = re.compile(r'static const DfHelperField (dfu_\w+)\[\]\s*=\s*\{'
                    r'(.*?)\n\};', re.S)
_ROW = re.compile(r'\{\s*"([A-Za-z0-9_]+)"\s*,.*?\b(dfu_\w+)\b', re.S)
_FIELD = re.compile(r'offsetof\(CPUArchState,\s*(\w+)\s*\)[^,]*,[^,]*,'
                    r'\s*([A-Z_|\s]+),')


def _reads(flags):
    """A usage-table access-flag expression -> does it include a READ."""
    return 'INSN_DF_RD' in flags


class SseStatusOracle(object):
    """encoding hex -> does QEMU STATE a read of env->sse_status?

    True | False | None (REFUSED).  Keyed on the encoding for the same
    reason the preserve and x87 oracles are: the same bytes have the same
    TCG lowering wherever they sit, and a PC key would answer from a
    different instruction after a wrong-path walk decoded at an offset the
    correct path never took.
    """

    def __init__(self, root=Q, table=TABLE, member=MEMBER):
        self.member = member
        self.arrays, self.helpers = self._load(os.path.join(root, table),
                                               member)
        if not self.helpers:
            # A table with no occupant would answer False everywhere, which
            # reads exactly like "QEMU reads no float status anywhere" --
            # the silent-false-success shape.  Refuse to be built instead.
            raise SystemExit(
                'sse_status_derive: REFUSING -- no helper in %s names '
                'offsetof(CPUArchState, %s).  Either the member was renamed '
                'or the table was not generated; an oracle that answers NO '
                'to everything is worse than one that will not start.'
                % (os.path.join(root, table), member))
        self.calls = {}                 # enc -> [helper names]
        self.disas = {}
        self.refused = collections.Counter()

    @staticmethod
    def _load(path, member):
        """(arrays that name @member, helper names bound to one of them)."""
        text = open(path).read()
        arrays = set()
        for name, body in _ARRAY.findall(text):
            for m, flags in _FIELD.findall(body):
                if m == member and _reads(flags):
                    arrays.add(name)
                    break
        helpers = {}
        for hname, arr in _ROW.findall(text):
            # The LAST binding wins only if it agrees; a helper bound to two
            # different arrays is not a thing this table emits, and if it
            # ever were, the disagreement must not be resolved silently.
            v = arr in arrays
            if hname in helpers and helpers[hname] != v:
                raise SystemExit(
                    'sse_status_derive: REFUSING -- helper %r is bound to '
                    'two usage arrays that disagree about %s' % (hname, member))
            helpers[hname] = v
        return arrays, helpers

    def add_dump(self, path):
        """Read a `-d op,in_asm` dump, keyed by encoding.  The SAME dumps the
        preserve and x87 oracles read, so no guest is run twice for this."""
        import qemu_preserve_oracle as _QPO
        for enc, e in _QPO.parse_dump(path).items():
            if enc in self.calls:
                continue
            self.calls[enc] = [a[0] for name, a in e.ops
                               if name == 'call' and a]
            self.disas[enc] = e.disas

    def _key(self, h):
        """The op dump's callee spelling -> the usage table's row name."""
        if h in self.helpers:
            return h
        if h.startswith('helper_') and h[len('helper_'):] in self.helpers:
            return h[len('helper_'):]
        return None

    def reads_sse_status(self, enc):
        """True | False | None (REFUSED)."""
        helpers = self.calls.get(enc)
        if not helpers:
            self.refused['%s: %s' % (
                self.disas.get(enc, enc),
                'no op dump' if helpers is None else 'no helper call')] += 1
            return None
        out = False
        for h in helpers:
            k = self._key(h)
            if k is None:
                self.refused['%s: helper %s has no row in %s'
                             % (self.disas.get(enc, enc), h, TABLE)] += 1
                return None
            out = out or self.helpers[k]
        return out


def selftest():
    """The oracle's own proof that it can answer, refuse, and convict.

    It runs against the TABLE ITSELF rather than a fixture: the table is the
    subject, and a selftest over a hand-written stand-in would pass while the
    real file said something else.  Every arm asserts a fact that can be
    checked by eye in the generated file.
    """
    f = 0

    def ck(cond, name):
        nonlocal f
        print(('PASS  ' if cond else 'FAIL  ') + name)
        if not cond:
            f += 1

    o = SseStatusOracle()
    ck(len(o.helpers) > 0, 'A the table parses and binds helper rows (%d)'
       % len(o.helpers))
    ck(o.helpers.get('addsd') is True,
       'B addsd is bound to an array that READS sse_status')
    ck(o.helpers.get('mulps_xmm') is True,
       'C mulps_xmm likewise (the p_wpsse subject)')
    ck(o.helpers.get('addpd_xmm') is True,
       'D addpd_xmm likewise (the p_wpsse subject)')
    # A helper that exists in the table and does NOT read sse_status: the
    # False answer has to have an occupant or the oracle is a constant.
    nos = [h for h, v in o.helpers.items() if not v]
    ck(len(nos) > 0, 'E some helper in the table does NOT read it (%d)'
       % len(nos))
    # REFUSALS, all three shapes, each returning None and none returning
    # False -- the distinction this module exists to keep.
    ck(o.reads_sse_status('90') is None, 'F an encoding with no dump REFUSES')
    o.calls['aa'] = []
    o.disas['aa'] = 'nop'
    ck(o.reads_sse_status('aa') is None, 'G an encoding with no call REFUSES')
    o.calls['bb'] = ['helper_not_a_real_row']
    o.disas['bb'] = 'made up'
    ck(o.reads_sse_status('bb') is None,
       'H a helper with no table row REFUSES (not False)')
    o.calls['cc'] = ['helper_addsd']
    ck(o.reads_sse_status('cc') is True, 'I a bound helper ANSWERS')
    o.calls['dd'] = [nos[0]]
    ck(o.reads_sse_status('dd') is False,
       'J a bound helper that does not read it answers FALSE (%s)' % nos[0])
    ck(len(o.refused) == 3, 'K each refusal is NAMED with its subject (%d)'
       % len(o.refused))
    print('sse_status_derive selftest: %d failure(s)' % f)
    return 1 if f else 0


if __name__ == '__main__':
    import sys
    sys.exit(selftest())
