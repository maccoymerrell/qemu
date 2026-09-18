#!/usr/bin/env python3
#
# The SET adjudication rules, exercised on what they must CLAIM and on the
# neighbours they must REFUSE.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
#   usage: python rule_selftest.py          (rc=0 all arms pass, rc=1 any fail)
#
# WHY THIS FILE EXISTS.  A rule in cmp_reg.py removes rows from the PIN leg's
# criterion.  A rule that only ever fires is indistinguishable from an
# allowlist: the thing that makes it a rule is the set of rows it turns down,
# and that set has to be exercised or it is an assertion.  So every arm below
# is a NEIGHBOUR of a claimed row -- the same opcode byte with a different
# modrm.reg, the same idiom with two different registers, the same shape with
# one extra unmatched name -- and each names why it must be refused.
#
# The rule bodies are lifted out of cmp_reg.py by source rather than imported,
# because that file runs its whole comparison at import time and has no entry
# point that stops short of it.  The slice is delimited by two markers that
# are checked here, so a rename that moves the rules out of the slice FAILS
# rather than silently testing nothing.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'cmp_reg.py')
BEGIN = 'def _x86_split('
END = '#: The SET rules, in the order they are tried.'

#: (encoding, ref_only, tracer_only) rows the DIV rule must CLAIM.  These are
#: the five encodings the leg reports, verbatim.
FIRE_DIV = [
    ('f7f7',     ['flags'], []),   # F7 /7   idiv %edi
    ('48f7f6',   ['flags'], []),   # REX.W F7 /6   div %rsi
    ('49f7f4',   ['flags'], []),   # REX.WB F7 /6  div %r12
    ('48f775a0', ['flags'], []),   # REX.W F7 /6   divq -0x60(%rbp)
    ('49f7f0',   ['flags'], []),   # REX.WB F7 /6  div %r8
]
#: Rows the DIV rule must REFUSE, each with the reason.
REFUSE_DIV = [
    ('f7d7',     ['flags'], [], 'F7 /2 = NOT, not a divide'),
    ('f7df',     ['flags'], [], 'F7 /3 = NEG, which DEFINES its flags'),
    ('f7e7',     ['flags'], [], 'F7 /4 = MUL, which defines its flags'),
    ('f7ef',     ['flags'], [], 'F7 /5 = IMUL, which defines its flags'),
    ('48f7f6',   ['flags', 'rax'], [], 'a second unmatched reference name'),
    ('48f7f6',   ['flags'], ['rdx'], 'the tracer names something too'),
    ('48f7f6',   ['rdx'], [], 'the unmatched name is not flags'),
    ('39d8',     ['flags'], [], 'CMP: not group 3 at all'),
    ('660fefc0', ['flags'], [], 'the self-zero encoding is not a divide'),
]
#: Rows the self-zero rule must CLAIM: the five PXOR encodings the leg
#: reports, each naming its own operand register.
FIRE_SELFZERO = [
    ('660fefc0', ['vec0'], []),
    ('660fefc9', ['vec1'], []),
    ('660fefdb', ['vec3'], []),
    ('660fefe4', ['vec4'], []),
    ('660fefff', ['vec7'], []),
]
#: Rows the self-zero rule must REFUSE.
REFUSE_SELFZERO = [
    ('660fefc1', ['vec0'], [], 'xmm0,xmm1 -- two DIFFERENT registers'),
    ('660fefc8', ['vec1'], [], 'xmm1,xmm0 -- two different registers'),
    ('660fefc0', ['vec1'], [], 'the name is not the operand register'),
    ('660fefc0', ['vec0', 'vec1'], [], 'a second unmatched reference name'),
    ('660fefc0', ['vec0'], ['rax'], 'the tracer names something too'),
    ('660fef00', ['vec0'], [], 'mod != 3: a memory operand, not a register'),
    ('0fefc0',   ['vec0'], [], 'no 66 prefix: MMX pxor, a different file'),
    ('660febc0', ['vec0'], [], '0F EB = POR: or, not exclusive-or'),
    ('31c0',     ['gpr0'], [], 'integer `xor %eax,%eax` is NOT covered'),
    ('4531e4',   ['gpr4'], [], '`xor %r12d,%r12d` is NOT covered'),
]


def load_rules():
    text = open(SRC, 'r', encoding='utf-8').read()
    if BEGIN not in text or END not in text:
        sys.exit('rule_selftest: cmp_reg.py no longer carries the rule slice '
                 'markers -- this file would test NOTHING.  Fix the markers.')
    body = text[text.index(BEGIN):text.index(END)]
    mod = types.ModuleType('cmp_reg_rules')
    exec(compile(body, SRC, 'exec'), mod.__dict__)
    for need in ('rule_div_undefined_flags', 'rule_selfzero_operand'):
        if need not in mod.__dict__:
            sys.exit('rule_selftest: %s is not in the slice' % need)
    return mod


def main():
    mod = load_rules()
    arms = [
        ('R-DIV-UNDEF-FLAGS', mod.rule_div_undefined_flags,
         FIRE_DIV, REFUSE_DIV),
        ('R-SELFZERO-OPERAND', mod.rule_selfzero_operand,
         FIRE_SELFZERO, REFUSE_SELFZERO),
    ]
    bad = 0
    n = 0
    for name, fn, fire, refuse in arms:
        for enc, p, q in fire:
            n += 1
            got = fn(enc, p, q)
            ok = got == name
            bad += not ok
            print('%-4s CLAIM  %-20s %-10s ref_only=%-14s -> %s'
                  % ('ok' if ok else 'FAIL', name, enc, ','.join(p), got))
        for enc, p, q, why in refuse:
            n += 1
            got = fn(enc, p, q)
            ok = got is None
            bad += not ok
            print('%-4s REFUSE %-20s %-10s ref_only=%-14s -> %-6s  %s'
                  % ('ok' if ok else 'FAIL', name, enc, ','.join(p),
                     got, why))
    print()
    print('arms %d   failures %d' % (n, bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
