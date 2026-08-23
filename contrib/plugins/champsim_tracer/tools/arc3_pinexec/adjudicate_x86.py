#!/usr/bin/env python3
"""Adjudicate a PIN/champsim_tracer register disagreement with a THIRD decoder.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

  usage: adjudicate_x86.py <hex-encoding> [<hex-encoding> ...]
         adjudicate_x86.py --rows              (the rows this arc adjudicated)

PIN is an EXECUTION reference, not an oracle for operand ROLES: `INS_RegR`
reports EXPLICIT operands only, so PIN's SILENCE about a register proves
nothing, and PIN's own decode is XED with the CET operand unset, so it
mis-decodes the CET encodings outright.  When PIN and the tracer disagree
about a register, neither one settles it -- a decoder that is neither
instrument does.

This prints iced-x86's per-register access for an encoding.  Read
COND_WRITE as "the old value survives when the condition is false", i.e. the
register is an input as well as an output.

iced-x86 lives outside this tree; point PYTHONPATH at it, e.g.
  PYTHONPATH=/mnt/md0/QEMU/cst_runs/_arc3_refs/x86_64/pylib
"""
import sys

try:
    import iced_x86 as I
except ImportError:
    sys.exit("iced_x86 not importable; set PYTHONPATH to the iced-x86 install "
             "(see the module docstring)")

RN = {v: k for k, v in I.Register.__dict__.items() if isinstance(v, int)}
AN = {v: k for k, v in I.OpAccess.__dict__.items() if isinstance(v, int)}

# The encodings this arc's PIN cross-check disagreed on, with the disagreement
# each one carried.  `pin` / `qemu` are the SOURCE-register sets the two
# instruments published, except where noted.
ROWS = [
    ('4c0f44ce', 'cmoveq',  'pin=flags,rsi',  'qemu=flags,r9,rsi', 2138),
    ('f30f1efa', 'endbr64', 'pin=rdi,rdx',    'qemu=(none)',        247),
    ('c9',       'leave',   'pin=rbp,rsp',    'qemu=rbp',            19),
    ('0f01d0',   'xgetbv',  'pin=rcx',        'qemu=rcx,sys',         1),
    ('f3480f1ec8', 'rdsspq', 'pin src=rax,rcx dst=(none)',
                             'qemu src=ssp dst=rax',                  2),
]


def show(hexs, note=''):
    b = bytes.fromhex(hexs)
    insn = I.Decoder(64, b, ip=0x1000).decode()
    fmt = I.Formatter(I.FormatterSyntax.INTEL)
    info = I.InstructionInfoFactory().info(insn)
    print('%-12s %-24s %s' % (hexs, fmt.format(insn), note))
    if not info.used_registers():
        print('     (iced names NO register operand)')
    for u in info.used_registers():
        print('     REG %-10s %s' % (RN.get(u.register, u.register),
                                     AN.get(u.access, u.access)))
    for m in info.used_memory():
        print('     MEM base=%s index=%s %s'
              % (RN.get(m.base), RN.get(m.index), AN.get(m.access, m.access)))
    print()


if len(sys.argv) > 1 and sys.argv[1] == '--rows':
    for enc, mnem, pin, qemu, n in ROWS:
        show(enc, '%s   %s  |  %s   (%d instructions)' % (mnem, pin, qemu, n))
else:
    for enc in sys.argv[1:]:
        show(enc)
