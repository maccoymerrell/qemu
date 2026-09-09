#!/usr/bin/env python3
"""THE LEG-RECORD RESOLVABILITY CHECK: can a reader reach the tree the legs
ran on, from the commit that carries the record?

WHY THIS EXISTS
---------------
An in-commit R13 leg record is a claim of the form "these headlines were
measured on THIS commit's tree".  A reader acts on it by checking out that
tree.  PASS 89 found five records where the reader cannot:

    commit      leg record       TIP named       in history?   tree
    4bcec00e51  exec146/legsA    5c0ae3181f93    ORPHAN        identical
    94d0331aaa  exec146/legsD    2d3aa6aff294    ORPHAN        identical
    bd8bbf0637  exec146/legsE    16ec6cf9f45d    ORPHAN        identical
    209963934a  exec146/legsF    181772640a2a    ORPHAN        identical
    414a647de7  exec145/legs     87e7391a0bbc    in history    DIFFERS

The first four are the AMEND shape: the legs ran, the commit was amended
afterwards for its message, and the sha the run wrote down stopped being
reachable.  The trees are byte-identical and the patch-ids match, so the
measurement is sound and only the POINTER is gone -- which is the whole
problem, because a pointer nobody can follow is not evidence, and neither
the R13 gate nor any battery row could see it.

The fifth is the LEGGED-AT-PARENT shape: the record names a commit that IS
in history and whose tree is NOT the one measured.  That one is worse than
an orphan, because it resolves -- to the wrong tree, silently.

WHAT IT CHECKS, PER RECORD
--------------------------
  C1 RESOLVES     the named TIP is a commit object in this repository.
                  An orphan fails here.

  C2 REACHABLE    the named TIP is an ancestor of (or equal to) the commit
                  the record is attached to.  A sha from a discarded branch
                  fails here even when it still exists in the object store.

  C3 BOUND        the record names the commit itself, OR it binds BY
                  CONTENT: its SO= line matches the sha256 prefix of the
                  built plugin the run used.  Legs are run on a WORKING TREE
                  whose HEAD is still the parent -- that is the honest and
                  normal order -- so a parent TIP is not by itself a defect;
                  a parent TIP with nothing tying the record to the tree
                  that was measured IS one, and that is the fifth row above.

Every check FAILS rather than warns, and a record whose TIP= line cannot be
found FAILS too: a check that cannot find its subject is not a check.

THE BINDINGS TABLE, and why it is not an amnesty list.  The five records
above cannot be re-run: four name trees that exist only as loose objects and
the fifth's run is over.  LEG_RECORD_BINDINGS.tsv states, per record, WHAT
ties it to the tree it claims -- and this file CHECKS that statement against
the object store instead of believing it.  A TREE-IDENTICAL row whose two
trees differ FAILS.  A LEGGED-AT-PARENT row whose named tip is not the
commit's parent, or whose covering commit is not a descendant, FAILS.  A row
naming a kind this file does not implement FAILS.  Deleting the records
instead would have deleted a sound measurement to tidy a pointer.

Author: Maccoy Merrell.

SPDX-License-Identifier: GPL-2.0-or-later
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile

TIP_RE = re.compile(r'^\s*TIP\s*=\s*([0-9a-fA-F]{7,40})\s*$', re.M)
SO_RE = re.compile(r'^\s*SO\s*=\s*([0-9a-fA-F]{8,64})\s*$', re.M)


def git(repo, *args, ok=(0,)):
    p = subprocess.run(['git', '-C', repo] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    if p.returncode not in ok:
        return None
    return p.stdout.strip()


def so_digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for blk in iter(lambda: f.read(1 << 20), b''):
            h.update(blk)
    return h.hexdigest()


def load_bindings(path):
    """tip -> (commit, kind, arg) from the bindings table, or {}."""
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            c = line.rstrip('\n').split('\t')
            if len(c) < 4:
                continue
            out[(c[0][:12].lower(), c[2][:12].lower())] = (c[3].strip(),
                                                           c[4].strip()
                                                           if len(c) > 4
                                                           else '')
    return out


def check_binding(repo, commit, tip, kind, arg):
    """Verify a bindings-table row against the object store."""
    if kind == 'TREE-IDENTICAL':
        a = git(repo, 'rev-parse', '--verify', '--quiet', commit + '^{tree}')
        b = git(repo, 'rev-parse', '--verify', '--quiet', tip + '^{tree}')
        if a is None or b is None:
            return 'TREE-IDENTICAL: one of the two trees is not in this ' \
                   'object store'
        if a != b:
            return 'TREE-IDENTICAL is FALSE: %s vs %s' % (a[:12], b[:12])
        return None
    if kind == 'LEGGED-AT-PARENT':
        par = git(repo, 'rev-parse', '--verify', '--quiet', commit + '^^{commit}')
        full = git(repo, 'rev-parse', '--verify', '--quiet', tip + '^{commit}')
        if par is None or full is None or par != full:
            return 'LEGGED-AT-PARENT is FALSE: %s is not the parent of %s' \
                   % (tip[:12], commit[:12])
        cov = git(repo, 'rev-parse', '--verify', '--quiet',
                  arg.split('\t')[0].strip() + '^{commit}') if arg else None
        if cov is None:
            return 'LEGGED-AT-PARENT names no covering commit'
        if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor',
                           commit, cov], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0:
            return 'LEGGED-AT-PARENT covering commit %s is not a descendant ' \
                   'of %s' % (cov[:12], commit[:12])
        return None
    return 'binding kind %r is not one this check implements' % kind


def check_one(repo, rc_path, commit, so_hex, bindings=None):
    """Return a list of failure strings; empty means the record is sound."""
    bad = []
    bindings = bindings or {}
    try:
        with open(rc_path) as f:
            text = f.read()
    except OSError as e:
        return ['%s: cannot be read (%s)' % (rc_path, e)]

    tips = TIP_RE.findall(text)
    if not tips:
        return ['%s: no TIP= line -- a record that names no tree answers '
                'nothing and FAILS rather than reading as a pass' % rc_path]

    sos = SO_RE.findall(text)
    for tip in tips:
        full = git(repo, 'rev-parse', '--verify', '--quiet', tip + '^{commit}')
        if not full:
            bad.append('%s: TIP=%s C1 RESOLVES -- not a commit in this '
                       'repository (orphaned by an amend?)' % (rc_path, tip))
            continue
        anc = subprocess.run(['git', '-C', repo, 'merge-base',
                              '--is-ancestor', full, commit],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL).returncode
        b = bindings.get((commit[:12].lower(), tip[:12].lower()))
        if b is not None:
            why = check_binding(repo, commit, tip, b[0], b[1])
            if why:
                bad.append('%s: TIP=%s BINDING -- %s' % (rc_path, tip[:12],
                                                         why))
            continue
        if anc != 0:
            bad.append('%s: TIP=%s C2 REACHABLE -- not an ancestor of %s'
                       % (rc_path, tip[:12], commit[:12]))
            continue
        if full == commit:
            continue
        if so_hex is None:
            bad.append('%s: TIP=%s C3 BOUND -- names the PARENT, and no '
                       'plugin was given to bind the record to the tree that '
                       'was measured' % (rc_path, tip[:12]))
            continue
        if not any(so_hex.startswith(s.lower()) for s in
                   (x.lower() for x in sos)):
            bad.append('%s: TIP=%s C3 BOUND -- names the PARENT and its SO= '
                       '%s does not match the built plugin %s'
                       % (rc_path, tip[:12],
                          (sos[0][:12] if sos else '<absent>'), so_hex[:12]))
    return bad


# --------------------------------------------------------------- selftest
# A check is only a check if it can go red.  Seven arms, in a scratch
# repository built here so the fixture cannot drift: a sound record PASSES, an
# orphan FAILS, a parent TIP whose SO= names a different binary FAILS, the
# same parent TIP bound by content PASSES, a TIP-less record FAILS, and the
# two BINDING kinds are proven to be checked rather than believed -- a false
# TREE-IDENTICAL and a LEGGED-AT-PARENT with a non-descendant covering commit
# both go red.
def selftest():
    fails = []
    with tempfile.TemporaryDirectory() as d:
        repo = os.path.join(d, 'r')
        os.makedirs(repo)
        env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t',
                   GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t')

        def g(*a):
            return subprocess.run(['git', '-C', repo] + list(a), env=env,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  universal_newlines=True).stdout.strip()
        g('init', '-q', '-b', 'main')
        for n in ('a', 'b'):
            with open(os.path.join(repo, n), 'w') as f:
                f.write(n)
            g('add', n)
            g('commit', '-q', '-m', n)
        head = g('rev-parse', 'HEAD')
        parent = g('rev-parse', 'HEAD~1')

        sofile = os.path.join(d, 'lib.so')
        with open(sofile, 'wb') as f:
            f.write(b'plugin bytes')
        soh = so_digest(sofile)

        def rc(name, body):
            p = os.path.join(d, name)
            with open(p, 'w') as f:
                f.write(body)
            return p

        # ARM 1 -- the record names the commit itself.  Must PASS.
        r = check_one(repo, rc('good', 'TIP=%s\nSO=%s\n' % (head, soh[:12])),
                      head, soh)
        if r:
            fails.append('arm1 sound-record should PASS: %s' % r)

        # ARM 2 -- the record names a sha nothing in history reaches.
        orphan = 'deadbeef' * 5
        r = check_one(repo, rc('orphan', 'TIP=%s\nSO=%s\n'
                               % (orphan, soh[:12])), head, soh)
        if not any('C1 RESOLVES' in x for x in r):
            fails.append('arm2 orphan should FAIL on C1: %s' % r)

        # ARM 3 -- the record names the PARENT and its SO= is another binary.
        r = check_one(repo, rc('parent', 'TIP=%s\nSO=%s\n'
                               % (parent, 'ffffffffffff')), head, soh)
        if not any('C3 BOUND' in x for x in r):
            fails.append('arm3 parent-tip with a foreign SO should FAIL on '
                         'C3: %s' % r)

        # ARM 4 -- the same parent TIP, bound by content.  Must PASS.
        r = check_one(repo, rc('parent_ok', 'TIP=%s\nSO=%s\n'
                               % (parent, soh[:12])), head, soh)
        if r:
            fails.append('arm4 parent-tip bound by SO should PASS: %s' % r)

        # ARM 5 -- a record with no TIP= line answers nothing.
        r = check_one(repo, rc('empty', 'START=now\n'), head, soh)
        if not any('no TIP=' in x for x in r):
            fails.append('arm5 TIP-less record should FAIL: %s' % r)

        # ARM 6 -- a bindings row is CHECKED, not believed.  A
        # TREE-IDENTICAL claim between two commits whose trees differ must
        # FAIL, or the table is an amnesty list.
        rcp = rc('bindfalse', 'TIP=%s\n' % parent)
        binds = {(head[:12].lower(), parent[:12].lower()):
                 ('TREE-IDENTICAL', '')}
        r = check_one(repo, rcp, head, soh, binds)
        if not any('TREE-IDENTICAL is FALSE' in x for x in r):
            fails.append('arm6 a false TREE-IDENTICAL binding should FAIL: '
                         '%s' % r)

        # ARM 7 -- a LEGGED-AT-PARENT row whose covering commit is not a
        # descendant must FAIL.
        binds = {(head[:12].lower(), parent[:12].lower()):
                 ('LEGGED-AT-PARENT', parent)}
        r = check_one(repo, rcp, head, soh, binds)
        if not any('not a descendant' in x for x in r):
            fails.append('arm7 a LEGGED-AT-PARENT row with a non-descendant '
                         'covering commit should FAIL: %s' % r)

    # ONE LINE PER ARM, in the runner's own grammar (selftest_all.sh's
    # count_arms).  A selftest that prints only a total renders identically
    # to one that asserts nothing, and this directory's runner scores that
    # as RED on purpose -- FINDING 84-A.
    names = ['sound record names the commit',
             'orphan tip fails C1 RESOLVES',
             'parent tip with a foreign SO fails C3 BOUND',
             'parent tip bound by SO passes',
             'TIP-less record fails',
             'a false TREE-IDENTICAL binding fails',
             'LEGGED-AT-PARENT with a non-descendant cover fails']
    hit = set()
    for f in fails:
        print('SELFTEST FAIL: %s' % f)
        idx = int(f[3]) - 1 if f[:3] == 'arm' and f[3].isdigit() else -1
        hit.add(idx)
    for i, nm in enumerate(names):
        if i not in hit:
            print('ARM %d ok: %s' % (i + 1, nm))
    print('legcheck --selftest %d pass / %d fail' % (len(names) - len(fails),
                                                     len(fails)))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rc', nargs='*', help='leg RC.txt file(s)')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--commit', default='HEAD',
                    help='the commit the record is attached to')
    ap.add_argument('--so',
                    default='build/contrib/plugins/libchampsim_tracer.so',
                    help='built plugin whose sha256 binds a parent-tip record')
    ap.add_argument('--bindings',
                    default=os.path.join(os.path.dirname(
                        os.path.abspath(__file__)),
                        'LEG_RECORD_BINDINGS.tsv'),
                    help='checked content bindings for records that cannot '
                         'be re-run')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.rc:
        print('legcheck: no records given -- a check with no subject FAILS')
        return 2

    repo = os.path.abspath(a.repo)
    commit = git(repo, 'rev-parse', '--verify', '--quiet',
                 a.commit + '^{commit}')
    if not commit:
        print('legcheck: --commit %s does not resolve in %s' % (a.commit, repo))
        return 2

    so_path = a.so if os.path.isabs(a.so) else os.path.join(repo, a.so)
    so_hex = so_digest(so_path) if os.path.exists(so_path) else None

    binds = load_bindings(a.bindings)
    bad = []
    for p in a.rc:
        bad += check_one(repo, p, commit, so_hex, binds)
    for b in bad:
        print('LEGCHECK FAIL: %s' % b)
    print('legcheck: %d record(s), %d failure(s), commit %s'
          % (len(a.rc), len(bad), commit[:12]))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
