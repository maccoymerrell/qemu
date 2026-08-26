#!/usr/bin/env python3
"""Emit the CP-H per-helper usage table as C, one .c.inc per target.

Every field name the reader derived is CHECKED BY THE COMPILER before it is
written down: a probe TU is built with the target's own compile command, and
a name that is not a member of CPUArchState makes it fail.  A row carrying one
is REFUSED WHOLE rather than trimmed -- trimming would delete an access that
may be real and turn an over-approximation into a missing dependency, which is
the error direction this project treats as disqualifying.
"""
import argparse, json, os, re, shlex, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess import entries_for

GUARD = {'x86_64': 'TARGET_I386', 'aarch64': 'TARGET_ARM',
         'riscv64': 'TARGET_RISCV', 'mipsel': 'TARGET_MIPS'}
LIB = {'x86_64': 'x86_64-linux-user', 'aarch64': 'aarch64-linux-user',
       'riscv64': 'riscv64-linux-user', 'mipsel': 'mipsel-linux-user'}
TDIR = {'x86_64': '/target/i386/', 'aarch64': '/target/arm/',
        'riscv64': '/target/riscv/', 'mipsel': '/target/mips/'}


def probe_cmd(isa):
    for e in entries_for(LIB[isa], lambda f: TDIR[isa] in f):
        if e['file'].endswith('cpu.c') or e['file'].endswith('helper.c'):
            return e
    raise SystemExit('no probe compile command for ' + isa)


def check_fields(isa, fields, workdir):
    """Return the subset of @fields that really are CPUArchState members."""
    e = probe_cmd(isa)
    os.makedirs(workdir, exist_ok=True)
    src = os.path.join(workdir, 'probe_%s.c' % isa)
    good = set()
    remaining = sorted(fields)
    while True:
        with open(src, 'w') as f:
            f.write('#include "qemu/osdep.h"\n#include "cpu.h"\n')
            f.write('#include <stdio.h>\nint main(void){\n')
            for i, fl in enumerate(remaining):
                f.write('  printf("%s %zu %zu\\n", "{n}", '
                        '(size_t)offsetof(CPUArchState, {n}), '
                        'sizeof(((CPUArchState *)0)->{n}));\n'.format(n=fl))
            f.write('  return 0;\n}\n')
        cmd = shlex.split(e['command'])
        out, i = [], 0
        while i < len(cmd):
            a = cmd[i]
            if a in ('-o', '-MQ', '-MF'):
                i += 2; continue
            if a in ('-c', '-MD', '-pipe', '-Werror'):
                i += 1; continue
            if a.endswith('.c'):
                out.append(src); i += 1; continue
            out.append(a); i += 1
        binp = os.path.join(workdir, 'probe_%s' % isa)
        out += ['-w', '-o', binp]
        r = subprocess.run(out, cwd=e['directory'], capture_output=True, text=True)
        if r.returncode == 0:
            run = subprocess.run([binp], capture_output=True, text=True)
            res = {}
            for line in run.stdout.splitlines():
                n, off, sz = line.split()
                res[n] = (int(off), int(sz))
            return res
        bad = set(re.findall(r"has no member named '([A-Za-z_0-9]+)'",
                             r.stderr))
        bad |= set(re.findall(r"no member named '([A-Za-z_0-9]+)' in",
                              r.stderr))
        if not bad:
            raise SystemExit('probe failed for %s and named no member:\n%s'
                             % (isa, r.stderr[-4000:]))
        before = len(remaining)
        remaining = [x for x in remaining if x not in bad]
        if len(remaining) == before:
            raise SystemExit('probe made no progress for ' + isa)


DIRNAME = {0: '0', 1: 'INSN_DF_RD', 2: 'INSN_DF_WR',
           3: 'INSN_DF_RD | INSN_DF_WR'}


def emit(isa, derived, extra_rows, offsets, out):
    rows, refused = [], []
    for name, v in sorted(derived['rows'].items()):
        if v['status'] != 'OK':
            refused.append((name, v.get('why', v.get('status'))))
            continue
        bad = [f for f in v['env'] if f not in offsets]
        if bad:
            refused.append((name, 'field(s) not members of CPUArchState: %s'
                            % ','.join(sorted(bad))))
            continue
        rows.append((name, v))
    for name, v in sorted(extra_rows.items()):
        bad = [f for f in v['env'] if f not in offsets]
        if bad:
            refused.append((name, 'hand row names a non-member: %s' % bad))
            continue
        rows.append((name, v))

    w = out.write
    hand = set(extra_rows)
    refused = [(n, why) for n, why in refused if n not in hand]
    w('/*\n * CP-H per-helper usage -- %s.  GENERATED, do not edit.\n'
      ' *\n'
      ' * Generator: contrib/plugins/champsim_tracer/tools/arc3_cov/\n'
      ' *            helper_usage/gen_table.py\n'
      ' * Subjects:  the helpers an OBSERVED run reached (the CP-H census,\n'
      ' *            QEMU_DF_HELPER_CENSUS), never a list from memory.\n'
      ' * Facts:     read off the PREPROCESSED body of each helper -- R5,\n'
      ' *            "if the information is in a macro body, expand the\n'
      ' *            macro" -- and every field name below was accepted by\n'
      ' *            offsetof(CPUArchState, ...) before it was written.\n'
      ' *\n'
      ' * Rows refused, and therefore still OVER-APPROXIMATED at run time:\n' % isa)
    if not refused:
        w(' *   (none)\n')
    for n, why in refused:
        w(' *   %-24s %s\n' % (n, why))
    if hand:
        w(' *\n * Rows the mechanical reader refused and a HAND enumeration '
          'supplies.\n * Each carries its justification in full:\n')
        for n in sorted(hand):
            j = extra_rows[n].get('hand_justification', '')
            w(' *   %s:\n' % n)
            line = ''
            for word in j.split():
                if len(line) + len(word) > 68:
                    w(' *     %s\n' % line)
                    line = ''
                line = (line + ' ' + word).strip()
            if line:
                w(' *     %s\n' % line)
    w(' */\n\n')

    for name, v in rows:
        if not v['env']:
            continue
        w('static const DfHelperField dfu_%s_env[] = {\n' % name)
        for f, d in sorted(v['env'].items()):
            kind = 'DF_HF_XLAT' if f in v.get('xlat', []) else 'DF_HF_OPERAND'
            w('    { offsetof(CPUArchState, %s), '
              'sizeof(((CPUArchState *)0)->%s), %s, %s },'
              '   /* %s */\n'
              % (f, f, DIRNAME[d], kind, v.get('env_where', {}).get(f, '')))
        w('};\n')
    w('\nstatic const DfHelperUsage df_helper_usage[] = {\n')
    for name, v in rows:
        ad = v.get('argdir', {})
        dirs = []
        for k in range(8):
            x = ad.get(str(k), ad.get(k, 0))
            dirs.append(0 if x == 'env' else (x or 0))
        while dirs and dirs[-1] == 0:
            dirs.pop()
        w('    { "%s", { %s },\n' % (name, ', '.join(str(d) for d in dirs) or '0'))
        if v['env']:
            w('      dfu_%s_env, ARRAY_SIZE(dfu_%s_env), true,\n'
              % (name, name))
        else:
            w('      NULL, 0, true,\n')
        w('      "%s" },\n' % v.get('defined_at', '').replace('"', ''))
    w('    { NULL, { 0 }, NULL, 0, false, NULL }\n};\n')
    return len(rows), refused


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True)
    ap.add_argument('--derived', required=True)
    ap.add_argument('--extra', help='hand-written rows, json')
    ap.add_argument('--workdir', required=True)
    ap.add_argument('-o', required=True)
    a = ap.parse_args()
    d = json.load(open(a.derived))
    extra = {}
    if a.extra and os.path.exists(a.extra):
        extra = json.load(open(a.extra)).get(a.isa, {})
    fields = set()
    for v in d['rows'].values():
        if v['status'] == 'OK':
            fields |= set(v['env'])
    for v in extra.values():
        fields |= set(v['env'])
    offs = check_fields(a.isa, fields, a.workdir)
    with open(a.o, 'w') as f:
        n, refused = emit(a.isa, d, extra, offs, f)
    print('%s: %d rows written, %d refused, %d/%d field names accepted by '
          'offsetof' % (a.isa, n, len(refused), len(offs), len(fields)))
