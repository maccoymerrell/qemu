"""
Named adjudications for the x86_64 wrong-path execution leg.

A disagreement between the tracer and gem5 is only COVERED when a rule says
WHY the reference cannot state the fact, and the rule's direction matches the
direction that was MEASURED.  A direction with no rule stays UNACCOUNTED and
is printed as such; it is never folded into the superset.

Each rule below names the gem5 source that produces the behaviour.  A rule
whose justification is a plausibility rather than a mechanism does not belong
here: this project has been burnt by four allowlist entries whose written
justification was factually false, each hiding a real defect.

Author: Maccoy Merrell.
"""
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     '..', '..'))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from arc3_taxonomy import Rule, SUPERSET, SUBSET, ORTHOGONAL   # noqa: E402

X86_EXEC = {
    # gem5 keeps the instruction pointer in the PCState, not in a register
    # file: src/arch/x86/regs/int.hh has no RIP entry and misc_reg has no RIP
    # either.  Its `rdip`/`wrip` micro-ops move the value through the micro
    # scratch file and the CS effective base.  Measured on `jnz`: gem5's
    # micro-op trio names integer:17, integer:18, the five cc registers and
    # miscellaneous:153 -- and no instruction pointer at all -- while the
    # tracer names REG_IP as both a source and a destination, which is the
    # architectural truth.
    'REF-NO-RIP-OPERAND':
        Rule('REF-NO-RIP-OPERAND', 'reference-gap', {SUPERSET},
             note='gem5 holds RIP in the PCState, not as a register operand; '
                  'a control transfer names no instruction pointer in its '
                  'operand lists'),

    # In 64-bit mode the processor forces the ES/CS/SS/DS bases to zero (SDM
    # Vol.3 3.4.2.1).  gem5 models the addition anyway and therefore READS
    # miscellaneous:152..155 on every memory reference; those reads are
    # dropped on the reference side by x86_vocab (and COUNTED).  Where the
    # tracer names a segment REGISTER for a prefixed access, the reference has
    # nothing left to match it with.
    'REF-SEG-EFF-BASE-ONLY':
        Rule('REF-SEG-EFF-BASE-ONLY', 'reference-gap', {SUPERSET},
             note='gem5 reads the segment EFFECTIVE BASE (misc 152..155), '
                  'which is architecturally zero in 64-bit mode; it never '
                  'reads the selector the tracer names'),

    # gem5 splits the flags word into Zaps / Cfof / Df / Ecf / Ezf and writes
    # only the ones an instruction actually changes.  An instruction that
    # architecturally leaves a flag UNDEFINED, or that writes a subset of the
    # word, therefore names fewer flag registers than the tracer names
    # REG_FLAGS -- but the tracer has ONE id for the whole word, so the
    # comparison is set-versus-set and any partial write reads as a superset.
    'REF-FLAGS-PARTIAL':
        Rule('REF-FLAGS-PARTIAL', 'reference-gap', {SUPERSET},
             note='gem5 has five cc registers and writes only the ones an '
                  'instruction changes; the tracer names the whole word'),

    # gem5 SE mode implements a syscall by calling into its own syscall
    # emulation and does not retire the instruction through the trace at all.
    # Measured: the injected run's log ends at the instruction BEFORE
    # `syscall`, and the process exits.  A wrong-path excursion that reaches
    # a syscall therefore has no reference beyond that point.
    'REF-SYSCALL-NOT-RETIRED':
        Rule('REF-SYSCALL-NOT-RETIRED', 'reference-gap', {SUPERSET},
             note='gem5 SE mode handles `syscall` outside the instruction '
                  'trace; nothing is logged for it'),

    # gem5's x87 file is 8 physical registers accessed through X87Top, and its
    # FLD80 micro-op sequence is `ld t1 ; ld t2w ; cvtint_fp80` -- the 80-bit
    # datum is rebuilt from a 64-bit mantissa and a 16-bit exponent through a
    # conversion, not stored verbatim.  A value the wire states exactly is not
    # guaranteed to survive the round trip.
    'REF-X87-CONVERTED':
        Rule('REF-X87-CONVERTED', 'reference-gap', {SUPERSET, ORTHOGONAL},
             note='gem5 rebuilds an 80-bit x87 datum through cvtint_fp80 '
                  'rather than holding the architectural encoding'),

    # gem5 writes its x87 status word (misc 194) for `fabs` and `fchs` and
    # does NOT write it for `fadd`, `fmul` or `fsub` -- measured, on the same
    # run: FABS prints `miscellaneous:194=0x3000` and FADD prints no
    # miscellaneous destination at all.  The architecture updates C0..C3 and
    # the exception flags on every x87 arithmetic instruction, so the tracer's
    # REG_FCSR destination is the architectural one and gem5's silence is the
    # reference's own partial modelling.
    'REF-X87-STATUS-NOT-PUBLISHED':
        Rule('REF-X87-STATUS-NOT-PUBLISHED', 'reference-gap', {SUPERSET},
             note='gem5 publishes an x87 status-word destination for some '
                  'x87 instructions and not for others; the architecture '
                  'updates it on all of them'),

    # A vector destination gem5 wrote through the wide path is NAMED with no
    # value (`RW=[...=?]`), and a scalar SSE operation writes only the low
    # half of an XMM register, leaving the word unknowable from one line.
    # The register is compared on the SET axis and skipped on the VALUE axis,
    # which is stated rather than silent.
    'REF-XMM-HALF-ONLY':
        Rule('REF-XMM-HALF-ONLY', 'reference-gap', {SUPERSET},
             note='gem5 publishes XMM as two 64-bit halves; a scalar write '
                  'touches one and the word is not knowable from the line'),

    # gem5 reads its own destination back on a partial-width write so the
    # bytes it does not produce survive.  Measured: `mov di, m16` prints
    # SR=[...,integer:7,...] -- rdi is a source of its own 16-bit load.  The
    # tracer records the same dependency for a partial write (R4), so this is
    # NOT a disagreement; the rule exists for the converse case, where the
    # tracer names a partial-write source gem5's micro-op did not need.
    'REF-NO-PARTIAL-MERGE-READ':
        Rule('REF-NO-PARTIAL-MERGE-READ', 'reference-gap', {SUPERSET},
             note='gem5 reads the destination back only where its micro-op '
                  'lowering needs the merge'),

    # The reference names an architectural register the tracer does not.  This
    # is the DISQUALIFYING direction and has no excusing rule by design: it is
    # listed so that a harness cannot invent one silently.
    'REF-ONLY-UNEXPLAINED':
        Rule('REF-ONLY-UNEXPLAINED', 'tracer-defect', {SUBSET},
             accounts=False,
             note='the reference names architectural state the tracer does '
                  'not; there is no rule that excuses this direction'),
}


def x86_exec_rule(label):
    return X86_EXEC.get(label)
