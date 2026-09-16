#!/usr/bin/env python3
"""Preprocess a target's helper translation units.

RULING R5 -- "if the information is in a macro body, EXPAND THE MACRO" -- is
why this exists.  QEMU's helpers are overwhelmingly written as macro bodies:
target/i386/ops_sse.h defines helper_mulss inside SSE_HELPER_S, target/arm's
vec_helper.c generates whole families with DO_3OP.  Reading the macro TEXT and
guessing what it expands to is exactly the false-justification shape this
project has a standing memory entry about.  So the compiler expands it, using
the SAME command meson compiled the TU with, and every fact downstream is read
off the expansion together with the `# line` marker naming the file and line
it came from.
"""
import json, os, re, subprocess, sys, shlex

BUILD = os.environ.get('QEMU_BUILD', '/mnt/md0/QEMU/qemu/build')

def entries_for(target_lib, path_filter):
    db = json.load(open(os.path.join(BUILD, 'compile_commands.json')))
    out = []
    for e in db:
        if target_lib not in e['command']:
            continue
        if not path_filter(e['file']):
            continue
        out.append(e)
    return out

def preprocess(entry, outdir):
    """Re-run the TU's own compile command with -E.  Returns the .i path."""
    cmd = shlex.split(entry['command'])
    # drop -o <file>, -c, -MD/-MQ/-MF <file>, and any -W that turns into an error
    out, i = [], 0
    while i < len(cmd):
        a = cmd[i]
        if a in ('-o', '-MQ', '-MF'):
            i += 2; continue
        if a in ('-c', '-MD', '-pipe'):
            i += 1; continue
        out.append(a); i += 1
    base = os.path.basename(entry['file']).replace('.c', '')
    ipath = os.path.join(outdir, base + '.i')
    out += ['-E', '-o', ipath]
    r = subprocess.run(out, cwd=entry['directory'], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError('preprocess failed for %s:\n%s' % (entry['file'], r.stderr[-3000:]))
    return ipath

if __name__ == '__main__':
    print(len(entries_for(sys.argv[1], lambda f: sys.argv[2] in f)))
