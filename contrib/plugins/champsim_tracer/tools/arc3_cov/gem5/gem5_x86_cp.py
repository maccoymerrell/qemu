"""
The x86_64 arm of the gem5 CORRECT-PATH execution reference.

WHY THIS FILE IS AN ADAPTER AND NOT A SECOND PARSER
===================================================
The x86_64 WRONG-PATH leg already reads gem5's patched ``Exec`` log for this
ISA, and it had to solve every hard part of doing so: the x87 stack-relative
operand names have to be converted through ``X87Top``, an XMM register arrives
as two 64-bit halves, gem5 keeps no RFLAGS word at all (it has ``Zaps``,
``Cfof`` and ``Df``), a micro-op MERGE READ is not an architectural source, and
one architectural access arrives as several contiguous micro-op requests.
``gem5_wp_ref`` does all of that and is measured.  Writing a second x86 parser
for the correct path would be a second place for those five decisions to drift,
so this module CALLS that one and translates its record into the shape the
correct-path comparator consumes (``gem5_ref.Insn``).

WHAT THE CORRECT PATH NEEDS THAT THE WRONG PATH DOES NOT
========================================================
*ALIGNMENT.*  The other two correct-path ISAs are fixed-width, so the
comparator aligns on ``(pc, encoding)`` with the encoding read out of the ELF
at a four-byte stride.  x86-64 is variable length and gem5 prints no encoding,
so the correct-path leg aligns on the PC alone and the instruction LENGTH is
CHECKED separately: gem5 states one for every instruction whose successor is in
the log -- from the fall-through address a control transfer's ``rdip`` micro-op
publishes, and from the next macro-op's PC otherwise -- and the check asserts
that against the length the tracer published.  It is reported as a count, with
any disagreement printed, rather than being folded into an axis.

*THE x87 REGISTER VALUE IS NOT COMPARABLE AND IS NOT COMPARED.*  gem5 holds the
x87 file as ``double``; the architecture -- and the wire -- hold the 80-bit
extended encoding, so the two are different representations of the same number
and a bitwise comparison would convict the tracer for gem5's storage choice.
Worse, the sidecar readback is further truncated to the WRITING micro-op's data
size: measured on ``flds``, gem5's ``movfp %st(7), %ufp1`` publishes
``floating_point:55=0x60000000`` for a datum whose double is
``0x3916d00e60000000`` -- the low 32 bits.  So the value is suppressed on the
REFERENCE side, the register is still compared on the SET axis, and every
suppression is COUNTED and printed.  A suppressed value contributes NO fact to
``reg-dst-value``; it is never silently scored as agreement.

Author: Maccoy Merrell.
"""
import collections
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(_HERE, 'wp')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gem5_ref                                                 # noqa: E402
import gem5_wp_ref                                              # noqa: E402
import x86_vocab as V                                           # noqa: E402


#: registers whose VALUE the reference cannot state in the wire's
#: representation.  Named per family rather than per row.
_VALUE_SUPPRESSED_PREFIX = ('REG_FPR',)


def parse(logpath, elfpath, dropped=None, notes=None):
    """(gem5 exec log, the guest ELF) -> [gem5_ref.Insn] in execution order.

    ``elfpath`` is accepted for signature compatibility with
    ``gem5_ref.parse`` and is not read: on a variable-length ISA the encoding
    cannot be recovered from the file without a length, and the length is what
    this leg CHECKS rather than assumes.
    """
    if dropped is None:
        dropped = {}
    if notes is None:
        notes = collections.Counter()
    # The wrong-path reader counts into ``Counter``s; the correct-path
    # comparator hands in a plain dict.  Counting locally and merging keeps
    # both callers working without either having to know the other's type.
    drop = collections.Counter()
    folded = collections.Counter()
    merged = collections.Counter()
    raw = gem5_wp_ref.parse(logpath, dropped=drop, folded=folded,
                            merged=merged)
    for k, n in drop.items():
        dropped[k] = dropped.get(k, 0) + n
    for k, n in folded.items():
        notes['folded-access:' + k] += n
    for k, n in merged.items():
        notes['merge-read:' + k] += n

    out = []
    for ins in raw:
        a = gem5_ref.Insn(ins.pc, 0, ins.length or 0)
        a.disas = ins.disas
        a.ctrl = ins.ctrl
        a.unmapped = list(ins.unmapped)
        a.length = ins.length
        # THE FLAGS WORD IS REBUILT PER INSTRUCTION, NOT CARRIED FORWARD.
        #
        # gem5 holds no RFLAGS register -- Zaps carries SF/ZF/AF/PF in their
        # RFLAGS positions, Cfof carries CF/OF and Df carries DF -- so a word
        # can be reassembled from whichever of the three THIS instruction
        # wrote, and the mask names exactly those bits.  The wrong-path leg
        # runs a RUNNING reconstruction because it must compare a word against
        # state it installed; on the correct path every instruction is
        # compared, so carrying a bit forward buys nothing and costs
        # correctness: gem5's `popcnt` writes no Zaps at all, the architecture
        # CLEARS PF, and a running word charged the tracer with a defect for a
        # PF bit set three instructions earlier.  A bit gem5 did not write for
        # THIS instruction is outside the mask and is not compared.
        a.rflags, a.rflags_mask = V.rflags_from_cc(ins.cc)
        a.srcs = sorted(ins.srcs)
        a.preserve_reads = set(ins.preserve_reads)
        for name, val in sorted(ins.writes.items()):
            if name.startswith(_VALUE_SUPPRESSED_PREFIX):
                notes['x87-value-suppressed'] += 1
                a.writes.append((name, 0, 0))
                continue
            if val is None:
                a.writes.append((name, 0, 0))
                if name.startswith('REG_VEC'):
                    notes['xmm-half-only'] += 1
                continue
            a.writes.append((name, val, 16 if name.startswith('REG_VEC')
                             else 8))
        a.loads = list(ins.loads)
        a.stores = list(ins.stores)
        a.uops = ins.uops
        a.syscall = ins.syscall
        out.append(a)
    return out
