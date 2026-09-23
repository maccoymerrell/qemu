#!/usr/bin/env python3
"""ARC 3 -- read ONE isolated CPL0 boot and say what happened to the victim.

A CPL0 probe can legitimately execute HLT, reprogram CR0 or leave ring 0, and
every one of those ends the boot it was running in.  The batch leg can only
say "the machine did not survive this encoding", which it then recorded as
NOT MEASURED -- a hole with a verdict-shaped hole in it, and six of them
reached the published matrix.

THE WEDGE IS THE MEASUREMENT.  Nothing about "QEMU executes these bytes" is
unknown when the machine stops at them; what was missing was an instrument
that reads the boot instead of giving up on it.  This is that instrument: one
victim, one machine, an external watchdog, and QEMU's own execution and
exception logs read back afterwards.  The verdict is derived from what the
log shows, per encoding, and an encoding whose log shows QEMU never reaching
the bytes is reported UNDETERMINED by name rather than folded in with the
ones that ran.

WHAT IS READ, AND WHERE IT COMES FROM
  out.txt   the probe's own debug-console stream.  The probe prints the hex
            BEFORE executing and the vector AFTER, so "<hex>\\t<vec>" means the
            encoding completed and needs no verdict from here, and "<hex>\\t"
            alone means control reached the call and did not come back.
  qlog.txt  QEMU's `-d exec,int,cpu_reset` log.  `Trace ... [.../<pc>/...]`
            is a translation block ENTERED at <pc>; `N: v=XX ... cpl=Y` is an
            exception DELIVERED; `Triple fault` is the machine resetting.
            The victim's bytes are copied into `codebuf` and called there, so
            a Trace at codebuf is QEMU entering the instruction, and the tail
            after the last such Trace is what the instruction did.

THE CLASSES, and the observation that decides each
  MEASURED                         the probe printed a vector.
  EXECUTED-AND-HALTED              codebuf entered; nothing executes after it,
                                   no exception is delivered, and the external
                                   watchdog reaps the boot.  That is HLT.
  EXECUTED-AND-LEFT-CPL0-FLOW      codebuf entered, and the FIRST thing after
                                   it is either a delivered exception at a
                                   privilege level other than 0, or execution
                                   resuming somewhere other than the byte
                                   after the victim.  The instruction
                                   redirected control; SYSCALL and SYSRET
                                   architecturally do exactly that, and the
                                   reachability question is answered the
                                   moment QEMU decodes and enters them.
  EXECUTED-THEN-MACHINE-UNUSABLE   codebuf entered, execution resumed at the
                                   byte after the victim, and the machine
                                   never returned to the probe's resume point.
                                   The instruction completed and its SIDE
                                   EFFECT ended the machine; a mov to CR0 that
                                   clears PG and PE leaves long mode with the
                                   return still in flight.
  UNDETERMINED-QEMU-NEVER-ENTERED-IT   the probe printed the hex and no Trace
                                   at codebuf is in the log.
  UNDETERMINED-PROBE-NEVER-REACHED-IT  the probe never printed the hex.

The two UNDETERMINED classes are the only honest silences, and they are the
only ones that fail the leg.  Everything else is an observation.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import argparse
import os
import re
import sys

MEASURED = 'MEASURED'
HALTED = 'EXECUTED-AND-HALTED'
LEFT = 'EXECUTED-AND-LEFT-CPL0-FLOW'
UNUSABLE = 'EXECUTED-THEN-MACHINE-UNUSABLE'
NO_ENTRY = 'UNDETERMINED-QEMU-NEVER-ENTERED-IT'
NO_PRINT = 'UNDETERMINED-PROBE-NEVER-REACHED-IT'

#: the classes that answer the reachability question.  Everything else is a
#: hole and says so.
EXECUTED = (HALTED, LEFT, UNUSABLE)

TRACE_RE = re.compile(r'^Trace \d+: 0x[0-9a-f]+ \[[0-9a-f]+/([0-9a-f]+)/')
EXC_RE = re.compile(r'^\s*\d+: v=([0-9a-f]+) .*\bcpl=(\d).*\bpc=([0-9a-f]+)')


def read_events(path):
    """-> [(kind, ...)] in log order: ('trace', pc) ('exc', vec, cpl, pc)
    ('triple',).  Anything else in the log is not an event.

    `check_exception` IS NOT AN EVENT HERE, and that distinction cost a wrong
    verdict before it was made: QEMU prints it as it works out whether the
    fault it is about to raise contributes to a double fault, BEFORE the
    record that says where the fault landed.  Treating it as the first thing
    after the victim made 0f07 and 480f07 -- which deliver at CPL 3, and are
    therefore SYSRET leaving ring 0 in plain sight -- read as if nothing had
    transferred.  The delivered record is the observation; the bookkeeping
    line in front of it is not."""
    ev = []
    with open(path, errors='replace') as f:
        for line in f:
            m = TRACE_RE.match(line)
            if m:
                ev.append(('trace', int(m.group(1), 16)))
                continue
            m = EXC_RE.match(line)
            if m:
                ev.append(('exc', int(m.group(1), 16), int(m.group(2)),
                           int(m.group(3), 16)))
                continue
            if line.startswith('Triple fault'):
                ev.append(('triple',))
    return ev


def symbol(elf_nm_path, name):
    """The address of one symbol, read from the `nm` output banked beside the
    image.  Refuses rather than guessing: every verdict below is anchored on
    codebuf, so a missing symbol is a harness failure and not a default."""
    with open(elf_nm_path) as f:
        for line in f:
            p = line.split()
            if len(p) == 3 and p[2] == name:
                return int(p[0], 16)
    sys.exit('%s names no symbol %r: the isolated run cannot be read without '
             'it' % (elf_nm_path, name))


def classify(d, hexstr, reaped):
    """-> (outcome, vector_or_dash, evidence)"""
    codebuf = symbol(os.path.join(d, 'syms.txt'), 'codebuf')
    nbytes = len(hexstr) // 2
    nextpc = codebuf + nbytes

    con = open(os.path.join(d, 'out.txt'), errors='replace').read()
    for line in con.splitlines():
        f = line.split('\t')
        if len(f) == 2 and f[0] == hexstr and f[1].strip().isdigit():
            # NO TAB IN THE EVIDENCE.  This row is a TSV field and the first
            # draft wrote the console line verbatim, tab and all, so the row
            # had five columns and every reader that expected four dropped
            # it -- which is how `dd30' arrived at the enable leg with no
            # verdict at all.  The leg REFUSED rather than publishing the
            # hole, which is the instrument working; the text is fixed here.
            return (MEASURED, f[1].strip(),
                    'the probe printed "%s" and then vector %s, and went on'
                    % (hexstr, f[1].strip()))
    if (hexstr + '\t') not in con:
        return (NO_PRINT, '-',
                'the debug console carries no "%s" line: the probe stopped '
                'before this encoding' % hexstr)

    ev = read_events(os.path.join(d, 'qlog.txt'))
    entered = [i for i, e in enumerate(ev)
               if e[0] == 'trace' and e[1] == codebuf]
    if not entered:
        return (NO_ENTRY, '-',
                'the probe printed "%s" and QEMU logged no translation block '
                'entered at codebuf 0x%x' % (hexstr, codebuf))
    post = ev[entered[-1] + 1:]

    if not post:
        if not reaped:
            # The machine stopped executing and QEMU still exited on its own.
            # That is not a halt and it is not something this instrument has
            # watched; it says so instead of picking the nearest class.
            return (NO_ENTRY, '-',
                    'QEMU entered codebuf 0x%x, logged nothing after it, and '
                    'exited without the watchdog: neither a halt nor a '
                    'transfer, and this instrument cannot name it' % codebuf)
        return (HALTED, '-',
                'QEMU entered codebuf 0x%x and logged no further block, no '
                'delivered exception and no reset; the external watchdog '
                'reaped the boot' % codebuf)

    first = post[0]
    if first[0] == 'exc' and first[2] != 0:
        return (LEFT, '-',
                'QEMU entered codebuf 0x%x; the next delivered exception is '
                'vector 0x%02x AT CPL %d (pc 0x%x), so the instruction left '
                'ring 0' % (codebuf, first[1], first[2], first[3]))
    if first[0] == 'exc' and not (codebuf <= first[3] < codebuf + 16):
        return (LEFT, '-',
                'QEMU entered codebuf 0x%x; the next delivered exception is '
                'vector 0x%02x at pc 0x%x, outside the victim\'s own bytes, '
                'so the instruction redirected control before faulting'
                % (codebuf, first[1], first[3]))
    if first[0] == 'trace' and first[1] != nextpc:
        return (LEFT, '-',
                'QEMU entered codebuf 0x%x and resumed at 0x%x, not at the '
                'byte after the victim (0x%x): the instruction redirected '
                'control' % (codebuf, first[1], nextpc))
    # Execution resumed at the byte after the victim (or faulted still at
    # CPL 0).  The instruction ran.  It did not come back, so whatever it
    # changed took the machine with it.
    tail = ('and the machine reset (Triple fault)'
            if any(e[0] == 'triple' for e in post)
            else 'and the external watchdog reaped the boot')
    return (UNUSABLE, '-',
            'QEMU entered codebuf 0x%x and the instruction completed in '
            'place (next block 0x%x); control never returned to the probe %s'
            % (codebuf, nextpc, tail))


def excerpt(d, codebuf, keep=200):
    """Bank the part of the log the verdict was read off, so the raw log --
    which a runaway victim can drive into the hundreds of megabytes -- does
    not have to be kept to check the verdict."""
    src = os.path.join(d, 'qlog.txt')
    lines = []
    with open(src, errors='replace') as f:
        for i, line in enumerate(f):
            lines.append((i, line))
    mark = None
    for i, line in lines:
        m = TRACE_RE.match(line)
        if m and int(m.group(1), 16) == codebuf:
            mark = i
    out = []
    for i, line in lines:
        if mark is not None and mark <= i <= mark + keep:
            out.append(line)
        elif (EXC_RE.match(line)
              or line.startswith(('check_exception', 'Triple fault'))):
            out.append(line)
    with open(os.path.join(d, 'qlog.excerpt.txt'), 'w') as f:
        f.write('# lines %s..%s of %s plus every exception/reset record\n'
                % (mark, None if mark is None else mark + keep, src))
        f.writelines(out[:20000])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True, help='the isolated run directory')
    ap.add_argument('--hex', required=True)
    ap.add_argument('--qemu-rc', type=int, required=True)
    ap.add_argument('--reaped', type=int, required=True,
                    help='1 if the external watchdog killed the boot')
    a = ap.parse_args()

    outcome, vec, why = classify(a.dir, a.hex, bool(a.reaped))
    # The row below is one TSV line and the evidence is its last field, so a
    # tab or a newline inside it would silently change the row's shape.  It
    # is flattened HERE rather than trusted to every message above.
    why = ' '.join(why.split())
    codebuf = symbol(os.path.join(a.dir, 'syms.txt'), 'codebuf')
    excerpt(a.dir, codebuf)
    with open(os.path.join(a.dir, 'VERDICT.txt'), 'w') as f:
        f.write('%s\t%s\t%s\tqemu_rc=%d reaped=%d\n'
                % (a.hex, outcome, vec, a.qemu_rc, a.reaped))
        f.write('%s\n' % why)
    sys.stdout.write('%s\t%s\t%s\t%s\n' % (a.hex, outcome, vec, why))
    return 0 if outcome in (MEASURED,) + EXECUTED else 1


if __name__ == '__main__':
    sys.exit(main())
