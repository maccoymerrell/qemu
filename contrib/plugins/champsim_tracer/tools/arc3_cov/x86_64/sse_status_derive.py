"""Does QEMU state a read of `env->sse_status` on this encoding?

THE QUESTION AND WHY IT IS NOT THE x87 ONE.  `x87_cw_derive.StatusOracle`
answers whether a helper touches the x87 STATUS GROUP -- {fpus, fpstt,
fptags} -- by expanding target/i386/tcg/fpu_helper.c's macros and walking its
call graph.  That derivation is sound for the x87 stack and it is SILENT
about SSE: `helper_addsd` is not written in fpu_helper.c's own body at all,
it is generated out of target/i386/ops_sse.h, so a walk of the hand-written
text refuses every SSE encoding with "helper addsd has no body in the
analysed sources".

A refusal is honest, and a refusal is not an adjudication.  Reaching for the
x87 answer to explain an SSE row -- calling the tracer's REG_FCSR on
`mulps %xmm1,%xmm3` an unresolved x87 TOP read -- is the
false-justification class this tree files against: a plausible tag stretched
over a measurement it does not describe.  The SSE forms read a DIFFERENT
file, and this module is the oracle for that file.

WHERE THE ANSWER COMES FROM: QEMU'S OWN SOURCE, EXPANDED BY QEMU'S OWN
BUILD COMMAND.  target/i386 keeps one `float_status` per FP datapath --
`fp_status` (x87), `mmx_status` (3DNow!) and `sse_status` (SSE/AVX) -- and
every helper that consults the SSE one says so in its body:

    d->ZMM_D(0) = float64_sqrt(s->ZMM_D(0), &env->sse_status);

This module compiles `target/i386/tcg/fpu_helper.c` -- the translation unit
that includes `ops_sse.h` once per vector width -- with the PREPROCESSOR
ONLY, using the exact command `build/compile_commands.json` records for it.
Every `helper_*` body in the expanded text is then read for references to
`env->sse_status`, and the references are propagated along the call edges
inside that same unit to a fixed point, so a helper that reaches the member
through a static wrapper is not missed.

WHY THE PREPROCESSOR AND NOT A TEXT WALK.  `ops_sse.h` writes its helpers
through `SSE_HELPER_*` macros and is included three times behind different
`SHIFT` values, so the NAME of the helper that reads `sse_status` does not
appear anywhere in the file that defines it.  Expanding by hand is how a
derivation drifts from the machine; expanding with the build's own command
cannot, because it is the same expansion the emulator was compiled from.

THE PREDECESSOR, AND WHY THE PATH CHANGED.  Until this file was re-homed the
oracle read `accel/tcg/insn-dataflow-usage/i386.c.inc`, a GENERATED artifact
of the helper-usage census programme (4ec775b9db..f05e0515f1) that the clean
restart's baseline reset did not carry.  The in-tree successor
`target/i386/tcg/insn-df-helper-usage.tsv` states the surviving half -- one
DIRECTION character per POINTER ARGUMENT -- and names no env member at all
(`grep -c status` reads 0 over its 607 rows), so re-pointing at it was never
possible: the question "which helpers read env->sse_status" has no answer in
that table's SHAPE.  The answer is taken from the source the generator itself
read, which removes the generated file from the chain rather than restoring
it.

READ OR WRITE, AND THE RULE IS STATED.  A reference to the member is scored
READ unless every occurrence in the function is an argument to one of the
write-only `set_*` configurators (`_WRITE_ONLY` below), which install a
rounding mode or a flush-to-zero bit and consult nothing.  Everything else --
a softfloat operation handed `&env->sse_status`, a direct read of one of its
fields, `get_float_exception_flags()` -- reads the word.  That is the same
criterion the retired table encoded as `INSN_DF_RD`, restated where it can be
checked against the line it is derived from.

WHAT IT REFUSES.  An encoding the op dump never carried, an encoding QEMU
lowered with no helper call at all, and a helper with no definition in the
expanded unit are all UNKNOWN -- returned as None, never as False.  "The walk
did not look" is never reported as "the machine does not read it" (R5).  The
integer-SIMD forms are the common case of the middle one: `paddq` is
gvec-inlined and calls nothing, so this oracle refuses it, which is correct
-- it reads no float_status and publishes no REG_FCSR either.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import collections
import json
import os
import re
import shlex
import subprocess

Q = '/mnt/md0/QEMU/qemu'

#: The translation unit whose expansion holds every SSE helper body.  It is
#: named here for the same reason the old generated path was: the refusal
#: below quotes it, and `compare_wp_gem5.py` prints it beside the row count.
TABLE = 'target/i386/tcg/fpu_helper.c (preprocessed)'

#: The source file, and the build directory whose compile_commands.json
#: supplies the flags.  A derivation that guesses its own -I list is a
#: derivation that can expand something the emulator never compiled.
SOURCE = 'target/i386/tcg/fpu_helper.c'
BUILD = 'build'

#: The retired generated table, named so the record of what moved is on the
#: file rather than in a commit message alone.
RETIRED_TABLE = 'accel/tcg/insn-dataflow-usage/i386.c.inc'

#: The member this oracle answers about, spelled as the source spells it.
MEMBER = 'sse_status'

#: Configurators that WRITE the float_status and read nothing out of it.
#: A function whose only contact with the member is through these is not a
#: reader.  Every name here is a softfloat `set_*` entry point taking the
#: status pointer as its LAST argument; `get_*` is deliberately absent.
_WRITE_ONLY = (
    'set_float_rounding_mode',
    'set_x86_rounding_mode',
    'set_float_exception_flags',
    'set_flush_to_zero',
    'set_flush_inputs_to_zero',
    'set_default_nan_mode',
    'set_floatx80_rounding_precision',
    'set_float_2nan_prop_rule',
    'set_float_3nan_prop_rule',
    'set_float_infzeronan_rule',
    'set_default_nan_pattern',
    'set_float_default_nan_pattern',
    'set_float_ftz_detection',
    'set_no_signaling_nans',
    'set_snan_bit_is_one',
)

#: A C identifier followed by `(` -- the call edges inside one function body.
_CALL = re.compile(r'\b([A-Za-z_]\w*)\s*\(')


def _preprocess(root, build, source):
    """The expanded translation unit, from the build's OWN command.

    Refuses loudly at every step: a missing compile database, a source with
    no entry in it, or a preprocessor that exits non-zero.  A derivation that
    silently expanded something else would answer confidently about a
    different machine.
    """
    db = os.path.join(root, build, 'compile_commands.json')
    if not os.path.exists(db):
        raise SystemExit(
            'sse_status_derive: REFUSING -- %s does not exist.\n'
            '  The oracle expands %s with the command the BUILD recorded\n'
            '  for it; without the compile database there is no such\n'
            '  command and a guessed -I list can expand a different\n'
            '  machine than the emulator was compiled from.' % (db, source))
    try:
        entries = json.load(open(db))
    except ValueError as e:
        raise SystemExit('sse_status_derive: REFUSING -- %s is not readable '
                         'JSON (%s)' % (db, e))
    want = os.path.normpath(os.path.join(root, source))
    for e in entries:
        f = e.get('file', '')
        if not os.path.isabs(f):
            f = os.path.join(e.get('directory', ''), f)
        if os.path.normpath(f) == want:
            hit = e
            break
    else:
        raise SystemExit(
            'sse_status_derive: REFUSING -- %s has no entry for %s.\n'
            '  Either the target was not configured or the file moved; an\n'
            '  oracle that fell back to a default command would be\n'
            '  answering about an expansion nothing builds.' % (db, source))
    argv = shlex.split(hit['command'])
    out = []
    skip = 0
    for i, tok in enumerate(argv):
        if skip:
            skip -= 1
            continue
        if tok in ('-c',):
            continue
        if tok in ('-o', '-MQ', '-MF'):
            skip = 1
            continue
        if tok == '-MD':
            continue
        out.append(tok)
    out.insert(1, '-E')
    proc = subprocess.run(out, cwd=hit.get('directory', os.path.join(
        root, build)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise SystemExit(
            'sse_status_derive: REFUSING -- preprocessing %s exited %d.\n'
            '  stderr (last 20 lines):\n%s'
            % (source, proc.returncode,
               '\n'.join(proc.stderr.decode('utf-8', 'replace')
                         .splitlines()[-20:])))
    return proc.stdout.decode('utf-8', 'replace')


def _function_bodies(text):
    """name -> body, for every function DEFINED at file scope in @text.

    A definition is an identifier, a parenthesised argument list and a `{`
    at depth 0.  Declarations end in `;` before the brace and are skipped,
    which is what keeps the softfloat prototypes out of the map.
    """
    out = {}
    n = len(text)
    i = 0
    while True:
        j = text.find('(', i)
        if j < 0:
            break
        # The identifier immediately left of the paren.
        k = j
        while k > 0 and text[k - 1] in ' \t':
            k -= 1
        e = k
        while k > 0 and (text[k - 1].isalnum() or text[k - 1] == '_'):
            k -= 1
        name = text[k:e]
        i = j + 1
        if not name or name[0].isdigit():
            continue
        # Balance the argument list.
        depth, p = 1, j + 1
        while p < n and depth:
            if text[p] == '(':
                depth += 1
            elif text[p] == ')':
                depth -= 1
            p += 1
        if depth:
            break
        # Whatever follows must be the opening brace of a body.
        while p < n and text[p] in ' \t\r\n':
            p += 1
        if p >= n or text[p] != '{':
            continue
        # Balance the body.
        depth, q = 1, p + 1
        while q < n and depth:
            if text[q] == '{':
                depth += 1
            elif text[q] == '}':
                depth -= 1
            q += 1
        if depth:
            break
        out[name] = text[p:q]
        i = q
    return out


def _enclosing_call(body, pos):
    """The name of the call whose argument list encloses @pos, or ''.

    Walks LEFT through balanced parentheses: a `)` seen on the way out opens
    a nested group that is skipped whole, and the first `(` that has no match
    to its right is the enclosing call's.  The identifier immediately before
    that paren is the callee.

    IT IS A WALK AND NOT A WINDOW, and that was measured rather than
    preferred: a fixed lookback of 220 characters read
    `update_mxcsr_status` as a READER because ONE of its four references
    sits inside a `set_float_exception_flags(` whose argument list spans
    four lines, which pushed the callee's name out of the window.  A rule
    whose answer depends on where the source wraps is not a rule.
    """
    depth = 0
    i = pos - 1
    while i >= 0:
        c = body[i]
        if c == ')':
            depth += 1
        elif c == '(':
            if depth == 0:
                e = i
                while e > 0 and body[e - 1] in ' \t\r\n':
                    e -= 1
                k = e
                while k > 0 and (body[k - 1].isalnum() or body[k - 1] == '_'):
                    k -= 1
                return body[k:e]
            depth -= 1
        elif c in ';{}':
            return ''
        i -= 1
    return ''


def _member_use(body, member):
    """'read' | 'write' | None -- how @body touches env-><member>.

    A reference is a WRITE only when it is an argument to one of the
    write-only configurators; the first reference that is anything else
    makes the function a reader.  A reference enclosed by no call at all is
    a direct field access, which is a read.
    """
    needle = '->' + member
    pos, seen = 0, None
    while True:
        h = body.find(needle, pos)
        if h < 0:
            return seen
        # Confirm the left side is `env` (or a local alias spelled env).
        k = h
        while k > 0 and (body[k - 1].isalnum() or body[k - 1] == '_'):
            k -= 1
        if body[k:h] != 'env':
            pos = h + len(needle)
            continue
        if _enclosing_call(body, k) in _WRITE_ONLY:
            seen = seen or 'write'
        else:
            return 'read'
        pos = h + len(needle)


def _reads_map(bodies, member):
    """helper/function name -> does it READ env-><member>, transitively.

    The closure is over call edges INSIDE this unit, to a fixed point: a
    helper that reaches the member through a static wrapper reads it.  Only
    a READ propagates; a write-only configurator call carries nothing.
    """
    direct = {}
    for name, body in bodies.items():
        direct[name] = _member_use(body, member) == 'read'
    edges = {}
    for name, body in bodies.items():
        edges[name] = set(c for c in _CALL.findall(body)
                          if c in bodies and c != name)
    reads = dict(direct)
    changed = True
    while changed:
        changed = False
        for name, callees in edges.items():
            if reads[name]:
                continue
            for c in callees:
                if reads[c]:
                    reads[name] = True
                    changed = True
                    break
    return reads


class SseStatusOracle(object):
    """encoding hex -> does QEMU STATE a read of env->sse_status?

    True | False | None (REFUSED).  Keyed on the encoding for the same
    reason the preserve and x87 oracles are: the same bytes have the same
    TCG lowering wherever they sit, and a PC key would answer from a
    different instruction after a wrong-path walk decoded at an offset the
    correct path never took.
    """

    def __init__(self, root=Q, build=BUILD, source=SOURCE, member=MEMBER):
        self.member = member
        self.source = source
        text = _preprocess(root, build, source)
        bodies = _function_bodies(text)
        if not bodies:
            raise SystemExit(
                'sse_status_derive: REFUSING -- the expansion of %s defines '
                'no function this reader could find.  An empty map answers '
                'NO to everything, which is the silent-false-success shape.'
                % source)
        reads = _reads_map(bodies, member)
        # The map the rest of the module answers from is the HELPER half:
        # `helper_<name>` is what an op dump spells at a call site.
        self.helpers = dict(
            (n[len('helper_'):], v) for n, v in reads.items()
            if n.startswith('helper_'))
        self.all_functions = reads
        if not any(self.helpers.values()):
            # A map with no occupant would answer False everywhere, which
            # reads exactly like "QEMU reads no float status anywhere" --
            # the silent-false-success shape.  Refuse to be built instead.
            raise SystemExit(
                'sse_status_derive: REFUSING -- no helper in the expansion '
                'of %s reaches env->%s.  Either the member was renamed or '
                'the expansion is not the one that builds; an oracle that '
                'answers NO to everything is worse than one that will not '
                'start.' % (source, member))
        self.calls = {}                 # enc -> [helper names]
        self.disas = {}
        self.refused = collections.Counter()

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
        """The op dump's callee spelling -> this map's row name."""
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
                self.refused['%s: helper %s has no definition in %s'
                             % (self.disas.get(enc, enc), h, TABLE)] += 1
                return None
            out = out or self.helpers[k]
        return out


def selftest():
    """The oracle's own proof that it can answer, refuse, and convict.

    It runs against the EXPANSION ITSELF rather than a fixture: the source
    is the subject, and a selftest over a hand-written stand-in would pass
    while the real file said something else.  Every arm asserts a fact that
    can be checked by eye in target/i386/ops_sse.h.
    """
    f = 0

    def ck(cond, name):
        nonlocal f
        print(('PASS  ' if cond else 'FAIL  ') + name)
        if not cond:
            f += 1

    o = SseStatusOracle()
    ck(len(o.helpers) > 0, 'A the unit expands and binds helper bodies (%d)'
       % len(o.helpers))
    ck(o.helpers.get('addsd') is True,
       'B addsd reaches env->sse_status (ops_sse.h FPU_ADD)')
    ck(o.helpers.get('mulps_xmm') is True,
       'C mulps_xmm likewise (the p_wpsse subject)')
    ck(o.helpers.get('addpd_xmm') is True,
       'D addpd_xmm likewise (the p_wpsse subject)')
    # A helper that exists in the unit and does NOT read sse_status: the
    # False answer has to have an occupant or the oracle is a constant.
    nos = [h for h, v in o.helpers.items() if not v]
    ck(len(nos) > 0, 'E some helper in the unit does NOT reach it (%d)'
       % len(nos))
    # The x87 arithmetic helpers are the named occupants of that False: they
    # read env->fp_status, a DIFFERENT member, so an oracle that answered
    # from "any float_status" would wrongly call them True.
    ck(o.helpers.get('fadd_ST0_FT0') is False,
       'F an x87 helper reads fp_status, not sse_status, and answers FALSE')
    # The write-only rule has NAMED occupants, and the arm asserts they are
    # PRESENT as well as not-reading: `is False` rather than a falsy test,
    # so a function the reader failed to find cannot pass this by being
    # absent.  Both install a float_status and consult nothing.
    ck(o.all_functions.get('cpu_init_fp_statuses') is False,
       'G cpu_init_fp_statuses configures and is not a reader')
    ck(o.all_functions.get('update_mxcsr_status') is False,
       'H update_mxcsr_status installs MXCSR and is not a reader')
    # ... and the converse half of the same file: the function that reads the
    # exception flags back out IS a reader, so the rule is not "every
    # mxcsr-shaped function is a write".
    ck(o.all_functions.get('update_mxcsr_from_sse_status') is True,
       'I update_mxcsr_from_sse_status reads the flags back out')
    # REFUSALS, all three shapes, each returning None and none returning
    # False -- the distinction this module exists to keep.
    ck(o.reads_sse_status('90') is None, 'J an encoding with no dump REFUSES')
    o.calls['aa'] = []
    o.disas['aa'] = 'nop'
    ck(o.reads_sse_status('aa') is None, 'K an encoding with no call REFUSES')
    o.calls['bb'] = ['helper_not_a_real_row']
    o.disas['bb'] = 'made up'
    ck(o.reads_sse_status('bb') is None,
       'L a helper with no definition REFUSES (not False)')
    o.calls['cc'] = ['helper_addsd']
    ck(o.reads_sse_status('cc') is True, 'M a bound helper ANSWERS')
    o.calls['dd'] = [nos[0]]
    ck(o.reads_sse_status('dd') is False,
       'N a bound helper that does not read it answers FALSE (%s)' % nos[0])
    ck(len(o.refused) == 3, 'O each refusal is NAMED with its subject (%d)'
       % len(o.refused))
    print('sse_status_derive selftest: %d failure(s)' % f)
    return 1 if f else 0


if __name__ == '__main__':
    import sys
    sys.exit(selftest())
