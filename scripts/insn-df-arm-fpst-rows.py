#!/usr/bin/env python3
#
# Emit target/arm's adjudicated helper-argument direction rows for the
# float_status pointer, from the target's OWN expanded helper list.
#
# WHY A GENERATOR AND NOT A HAND LIST.  target/arm's helper declarations are
# overwhelmingly macro bodies -- helper-sve.h builds whole families out of
# DEF_HELPER_FLAGS_* inside DO_* macros, vec_helper.c's families likewise --
# so the NAME of a helper that takes a `fpst' argument appears nowhere in the
# file that declares it.  Reading the macro text and writing down what it
# looks like it expands to is the shape this project has a standing memory
# entry about.  So the compiler expands it: this script re-runs a target/arm
# translation unit's own compile command with -E over a probe that redefines
# DEF_HELPER_FLAGS_n to print one line per helper, and the rows come out of
# that expansion.
#
# WHAT THE ROWS SAY, AND WHY IT IS NOT A GUESS.  A `fpst' argument is a
# `float_status *' built by fpstatus_ptr() from tcg_env, so it names a range
# of CPUARMState and the compiler supplies its extent.  The DIRECTION is the
# same both-ways answer accel/tcg's reader already publishes for an env
# pointer it has no row for (insn-dataflow.c, df_call: `unsigned dir =
# INSN_DF_RD | INSN_DF_WR'), and it is the right one for this pointee:
# softfloat reads the rounding mode, the flush-to-zero and default-NaN
# controls and the FEAT_AFP bits out of float_status on the way in, and ORs
# what it raised into float_exception_flags on the way out.  A helper is
# handed the pointer BECAUSE it performs such an operation.
#
# So this table does not move the direction -- it is byte-for-byte the
# fallback's -- and what it does move is the EXTENT: without a row the range
# is recorded as DF_FIELD_UNBOUNDED, and an unstated extent gets no register
# name at all (insn_dataflow_field_reg refuses one, deliberately).  That is
# why the aarch64 wire published no FPSR read or write on any FP instruction.
#
# Usage:
#   scripts/insn-df-arm-fpst-rows.py --build-dir BUILD \
#       -o target/arm/tcg/insn-df-helper-usage.tsv
#
# Author: Maccoy Merrell
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

# The argument types that name a range of CPUARMState, and therefore need a
# direction character other than '-'.  Kept in step with
# include/exec/insn-df-helper-args.h.inc by the BUILD, not by this comment:
# a helper the reader sees with a register pointer and no row here aborts the
# emulator at startup, and a row naming a helper with none aborts it too.
REGPTR_TYPES = {'fpst'}

REASON = ('the float_status this operation computes through: softfloat reads '
          'the rounding mode and the flush-to-zero, default-NaN and AFP '
          'controls out of it and ORs the exceptions it raised back into it')

PROBE = r'''
#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "exec/helper-head.h.inc"

#define A_(n, ...) __CST_ROW__ n | __VA_ARGS__ | __CST_END__
#define DEF_HELPER_FLAGS_0(NAME, FLAGS, RET) \
    __CST_ROW__ NAME | | __CST_END__
#define DEF_HELPER_FLAGS_1(NAME, FLAGS, RET, T1) \
    __CST_ROW__ NAME | T1 | __CST_END__
#define DEF_HELPER_FLAGS_2(NAME, FLAGS, RET, T1, T2) \
    __CST_ROW__ NAME | T1 T2 | __CST_END__
#define DEF_HELPER_FLAGS_3(NAME, FLAGS, RET, T1, T2, T3) \
    __CST_ROW__ NAME | T1 T2 T3 | __CST_END__
#define DEF_HELPER_FLAGS_4(NAME, FLAGS, RET, T1, T2, T3, T4) \
    __CST_ROW__ NAME | T1 T2 T3 T4 | __CST_END__
#define DEF_HELPER_FLAGS_5(NAME, FLAGS, RET, T1, T2, T3, T4, T5) \
    __CST_ROW__ NAME | T1 T2 T3 T4 T5 | __CST_END__
#define DEF_HELPER_FLAGS_6(NAME, FLAGS, RET, T1, T2, T3, T4, T5, T6) \
    __CST_ROW__ NAME | T1 T2 T3 T4 T5 T6 | __CST_END__
#define DEF_HELPER_FLAGS_7(NAME, FLAGS, RET, T1, T2, T3, T4, T5, T6, T7) \
    __CST_ROW__ NAME | T1 T2 T3 T4 T5 T6 T7 | __CST_END__

#include "helper.h"
'''

ROW_RE = re.compile(r'__CST_ROW__\s+(.*?)\s+\|\s*(.*?)\s*\|\s+__CST_END__',
                    re.S)


def arm_compile_entry(build):
    """A target/arm compile command, from the build's own database."""
    db = json.load(open(os.path.join(build, 'compile_commands.json')))
    for e in db:
        if 'aarch64-linux-user' not in e['command']:
            continue
        if '/target/arm/' not in e['file']:
            continue
        if e['file'].endswith('cpu.c') or e['file'].endswith('helper.c'):
            return e
    raise SystemExit('no target/arm compile command in %s' % build)


def expand(build):
    e = arm_compile_entry(build)
    cmd, out, i = shlex.split(e['command']), [], 0
    while i < len(cmd):
        a = cmd[i]
        if a in ('-o', '-MQ', '-MF'):
            i += 2
            continue
        if a in ('-c', '-MD', '-pipe'):
            i += 1
            continue
        out.append(a)
        i += 1
    d = tempfile.mkdtemp(prefix='insn-df-arm-fpst.')
    src = os.path.join(d, 'probe.c')
    with open(src, 'w') as f:
        f.write(PROBE)
    # The probe replaces the TU's own source; everything else -- the include
    # path, the target defines, the config headers -- is the emulator's.
    out = [a for a in out if not a.endswith('.c')]
    out += ['-E', '-P', src]
    r = subprocess.run(out, cwd=e['directory'], capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr[-4000:])
        raise SystemExit('probe preprocessing failed')
    return r.stdout


def rows(text):
    seen, out = {}, []
    for m in ROW_RE.finditer(text):
        name = m.group(1).strip().replace(' ', '')
        args = m.group(2).split()
        if not any(a in REGPTR_TYPES for a in args):
            continue
        dirs = ''.join('b' if a in REGPTR_TYPES else '-' for a in args)
        if name in seen:
            if seen[name] != dirs:
                raise SystemExit('%s expands twice with different shapes: '
                                 '%s vs %s' % (name, seen[name], dirs))
            continue
        seen[name] = dirs
        out.append((name, dirs))
    return sorted(out)


HEADER = """\
# What each aarch64/arm helper does through a pointer argument that names a
# register.
#
# Column 1 is the helper's name as DEF_HELPER spells it, suffix and all.
# Column 2 is one character per argument: '-' the argument names no register,
# 'r' the helper reads through it, 'w' it writes through it, 'b' both.
# Column 3 is why, and it is not optional: a direction with no stated ground
# is an assertion, and the generator refuses one.
#
# GENERATED by scripts/insn-df-arm-fpst-rows.py from the target's own expanded
# helper list.  Do not hand-edit a row: change the generator and re-emit.
#
# The other half of the completeness -- every helper that takes a register
# pointer has a row, and every row names such a helper -- is enforced where
# this table meets the compiler's view, in insn_dataflow_declare_helper_usage().
#
# Copyright (c) 2026 Maccoy Merrell
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build-dir', required=True)
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args()

    r = rows(expand(a.build_dir))
    if not r:
        raise SystemExit('the expansion produced no register-pointer helper; '
                         'that is a probe failure, not an empty target')
    with open(a.output, 'w') as f:
        f.write(HEADER)
        for name, dirs in r:
            f.write('%s\t%s\t%s\n' % (name, dirs, REASON))
    print('%d row(s) -> %s' % (len(r), a.output))
    return 0


if __name__ == '__main__':
    sys.exit(main())
