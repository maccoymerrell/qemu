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

FINDING 90-B -- A BINDING MAY NOT DEPEND ON A FILE THAT GETS REBUILT OVER,
OR ON AN OBJECT NOTHING REFERENCES.  Both of the binding routes PASS 89 left
standing are perishable, and neither says so when it perishes:

  * C3's content route hashes `build/contrib/plugins/libchampsim_tracer.so`.
    That path is one `ninja` away from being a different file, and one `rm
    -rf build` away from being no file at all.  When it changes, C3 fails on
    a record that was always sound; when it is absent, C3 fails with "no
    plugin was given".  Either way the pointer stops resolving for a reason
    that has nothing to do with the measurement -- the same class as the
    amend that orphaned the four tips.

  * TREE-IDENTICAL reads `<orphan-tip>^{tree}`.  The orphan is unreferenced
    by construction, so `git gc` may prune it and the row's own check then
    cannot run.

So every row carries `tree=<40 hex>` -- the tree the legs measured -- and it
is checked against an object REACHABLE FROM THE BRANCH, which cannot be
pruned and cannot be rebuilt over.  Which object is the KIND's question, and
the kinds do not agree on it: TREE-IDENTICAL, TREE-SHA and RECORD-COMPLETED-BY
name the tree their commit carries, while LEGGED-AT-PARENT names the PARENT's
-- that is the whole content of the word `parent` in its name, and asserting
the commit's tree there would make the row say the opposite of what it means.
On top of that, TREE-IDENTICAL still requires the orphan tip's tree to equal
the stated one WHEN the orphan is in the store; when it has been pruned the
row verifies on the durable half alone rather than failing.

The BINDING IS CONSULTED BEFORE C1 for the same reason: a bound row's whole
subject is a tip a reader cannot reach, so asking "is the tip a commit here?"
first meant the compensation stopped working the moment the thing it
compensates for was collected.

A row with no `tree=` column FAILS: a binding that only resolves while a
loose object or a built file survives is not a durable binding, and this
file's whole subject is pointers that stop resolving.

WHAT A RECORD MUST SAY -- FINDING 90-A.  The checks above ask whether a
record's pointer resolves.  They do not ask whether the record is COMPLETE,
and a record can be sound in every word it prints and still answer nothing,
by printing fewer legs than the gate scored.  b5fa1e58be's record says "GATE
PASSED -- 19 legs" and prints FOURTEEN rows: all five gem5 legs -- gem5cp
aarch64 and mipsel, gem5wp aarch64, x86_64 and mipsel -- are missing, with
their reports sitting in the evidence root the record itself names.  Nothing
could see it: the R13 gate scores the RUN and the record is a TRANSCRIPT of
it, and no instrument read the transcript.

`--message` is that reader.  Per commit, over the R13 leg record in its
commit message:

  M1 CLAIMED    the record's "GATE PASSED -- N legs" line and the number of
                rows it prints are the same number.
  M2 COMPLETE   every (leg, isa) pair in the R13 manifest appears as a row.
                The manifest is the gate's own ADJUDICATED.tsv AS OF THE
                RECORD'S OWN COMMIT, so the check cannot drift from what the
                gate scored -- and cannot convict a complete record of
                missing a leg that did not exist when it ran.  Adding a
                twentieth leg makes every record written AFTER it owe a
                twentieth row, and leaves every record written before it
                exactly as complete as it was.
  M3 TREED      the record names the tree its legs measured, as a `TREE=`
                line, and that sha is the commit's own tree -- or, when the
                record is a TRANSCRIPT of another commit's run and says so
                with a `RECORD-OF=` line, the tree THAT commit carries.

A commit named to `--message` that carries no record at all FAILS, for the
reason every other check here fails on a missing subject.  Records written
before this rule are dispositioned in the bindings table by the same
mechanism as the tips -- `RECORD-COMPLETED-BY` names the later commit whose
message carries the missing rows, and THAT commit's message is re-read here
and required to be complete, rather than believed.

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
TREE_RE = re.compile(r'^\s*TREE\s*=\s*([0-9a-fA-F]{40})\s*$', re.M)

#: The gate's own manifest.  M2 reads the (leg, isa) pairs from the file the
#: R13 gate scores against, so "complete" here can never mean a different set
#: of legs from the one that produced the headline the record prints.
#: instruments/ -> arc3_cov/ -> tools/ -> external_truth_gate/.
_HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.normpath(os.path.join(
    _HERE, '..', '..', 'external_truth_gate', 'ADJUDICATED.tsv'))
#: The same file as a REPO-RELATIVE path, so the manifest can be read out of
#: an arbitrary commit's tree rather than only out of the working copy.
MANIFEST_REL = ('contrib/plugins/champsim_tracer/tools/external_truth_gate/'
                'ADJUDICATED.tsv')

#: A row of an in-commit leg record: `leg isa HEADLINE CEILING SCORED`,
#: indented under the GATE line.  The `/` between headline and ceiling is
#: OPTIONAL because both spellings are in use -- the gate prints the columns
#: bare and the records written by hand put a slash between them -- and a
#: check that only reads one of the two spellings reports a record it cannot
#: parse as a record with no rows, which is the silent-false-shape this file
#: exists to stop.
RECORD_ROW_RE = re.compile(
    r'^\s+([a-z][a-z0-9_]*)\s+([A-Za-z][A-Za-z0-9_]*)\s+'
    r'(\d+)\s*(?:/\s*)?(\d+)\s+(\d+)\b', re.M)
#: The record's own claim about how many legs it is transcribing.
CLAIM_RE = re.compile(r'GATE\s+PASSED\s*--\s*(\d+)\s+legs', re.M)
#: A record that TRANSCRIBES another commit's run rather than reporting its
#: own.  Its TREE= is the tree that commit carries, because that is the tree
#: the legs in the table were measured at.
RECORD_OF_RE = re.compile(r'^\s*RECORD-OF\s*=\s*([0-9a-fA-F]{7,40})\s*$',
                          re.M)

BINDINGS_DEFAULT = os.path.join(_HERE, 'LEG_RECORD_BINDINGS.tsv')


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


_TREE_COL = re.compile(r'^tree=([0-9a-fA-F]{40})$')


def load_bindings(path):
    """(commit, tip) -> (kind, arg, tree) from the bindings table, or {}.

    The columns after the kind are POSITIONAL BY KIND -- LEGGED-AT-PARENT's
    fourth column is its covering commit, TREE-IDENTICAL's is prose -- so the
    durable-tree column is picked out by its `tree=` prefix wherever it sits
    rather than by an index every kind would have to agree on.
    """
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            c = [x.strip() for x in line.rstrip('\n').split('\t')]
            if len(c) < 4:
                continue
            tree, arg = None, ''
            for x in c[4:]:
                m = _TREE_COL.match(x)
                if m and tree is None:
                    tree = m.group(1).lower()
                elif not arg:
                    arg = x
            out[(c[0][:12].lower(), c[2][:12].lower())] = (c[3], arg, tree)
    return out


def check_tree_column(repo, tree):
    """The durable half of every binding -- FINDING 90-B, the part that is
    the same for every kind: the row STATES a tree, and that sha is a tree
    object in this store.

    WHICH tree it has to be is the KIND's question and is asked below, because
    the kinds do not agree on it: TREE-IDENTICAL and TREE-SHA name the tree
    the commit carries, LEGGED-AT-PARENT names the parent's -- that is the
    whole content of the word `parent` in its name.  What they do agree on is
    that the answer must be an object nothing has to keep alive by hand.
    """
    if tree is None:
        return ('no `tree=<40 hex>` column.  A binding that resolves only '
                'while an orphaned object or a built file survives is not a '
                'durable binding (FINDING 90-B)')
    if git(repo, 'cat-file', '-t', tree) != 'tree':
        return 'tree=%s is not a tree object in this store' % tree[:12]
    return None


def _tree_is(repo, tree, rev, what):
    got = git(repo, 'rev-parse', '--verify', '--quiet', rev + '^{tree}')
    if got is None:
        return 'cannot resolve %s to a tree here' % what
    if got != tree:
        return ('tree=%s is not %s (%s)' % (tree[:12], what, got[:12]))
    return None


def check_binding(repo, commit, tip, kind, arg, tree=None, manifest=None):
    """Verify a bindings-table row against the object store."""
    durable = check_tree_column(repo, tree)
    if durable:
        return '%s: %s' % (kind, durable)
    if kind in ('TREE-IDENTICAL', 'TREE-SHA', 'RECORD-COMPLETED-BY'):
        why = _tree_is(repo, tree, commit,
                       "the tree %s carries" % commit[:12])
        if why:
            return '%s: %s' % (kind, why)
    if kind == 'TREE-SHA':
        # The whole binding: the record's legs measured THIS commit's tree,
        # and that tree is in the store.  Nothing perishable is consulted.
        return None
    if kind == 'TREE-IDENTICAL':
        a = git(repo, 'rev-parse', '--verify', '--quiet', commit + '^{tree}')
        b = git(repo, 'rev-parse', '--verify', '--quiet', tip + '^{tree}')
        if b is None:
            # The orphan was pruned.  The claim still stands on the tree
            # column, which is what makes it durable; say so rather than
            # failing on an object nothing was ever going to reference.
            return None
        if a != b:
            return 'TREE-IDENTICAL is FALSE: %s vs %s' % (a[:12], b[:12])
        return None
    if kind == 'RECORD-COMPLETED-BY':
        # FINDING 90-A's disposition for a record written before the
        # completeness rule: a LATER commit carries the rows this one left
        # out.  Checked, not believed -- the named commit has to exist, has
        # to be a descendant, and its own message has to be complete.
        cov = git(repo, 'rev-parse', '--verify', '--quiet',
                  arg + '^{commit}') if arg else None
        if cov is None:
            return 'RECORD-COMPLETED-BY names no commit in this repository'
        if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor',
                           commit, cov], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0:
            return ('RECORD-COMPLETED-BY %s is not a descendant of %s -- a '
                    'record cannot be completed by a commit that does not '
                    'carry it' % (cov[:12], commit[:12]))
        bad = check_message(repo, cov, manifest, want_tree=False)
        if bad:
            return ('RECORD-COMPLETED-BY %s does not itself carry a complete '
                    'record: %s' % (cov[:12], '; '.join(bad)))
        return None
    if kind == 'LEGGED-AT-PARENT':
        par = git(repo, 'rev-parse', '--verify', '--quiet', commit + '^^{commit}')
        full = git(repo, 'rev-parse', '--verify', '--quiet', tip + '^{commit}')
        if par is None or full is None or par != full:
            return 'LEGGED-AT-PARENT is FALSE: %s is not the parent of %s' \
                   % (tip[:12], commit[:12])
        why = _tree_is(repo, tree, par,
                       "the parent %s's tree -- which is the tree this kind "
                       "says the legs measured" % par[:12])
        if why:
            return 'LEGGED-AT-PARENT: %s' % why
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


def load_manifest(path):
    """The (leg, isa) pairs the R13 gate scores, from the gate's own file."""
    pairs = []
    if not os.path.exists(path):
        return None
    with open(path) as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            c = line.rstrip('\n').split('\t')
            if len(c) >= 2 and c[0].strip() and c[1].strip():
                pairs.append((c[0].strip(), c[1].strip()))
    return pairs or None


def manifest_at(repo, commit):
    """The (leg, isa) pairs the R13 gate scored AT @commit's tree, or None.

    None means the commit carries no manifest -- a tree from before the gate
    existed -- and the caller falls back to the working tree's copy.  A
    manifest that IS there but unparsable yields an empty list, which the
    caller treats as unreadable rather than as "no legs": a zero-leg
    completeness check passes everything.
    """
    blob = git(repo, 'show', '%s:%s' % (commit, MANIFEST_REL))
    if blob is None:
        return None
    pairs = []
    for line in blob.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        c = line.split('\t')
        if len(c) >= 2 and c[0].strip() and c[1].strip():
            pairs.append((c[0].strip(), c[1].strip()))
    return pairs or None


def check_message(repo, commit, manifest, want_tree=True, bindings=None):
    """FINDING 90-A: is the in-commit leg record COMPLETE?

    Returns a list of failure strings; empty means the record transcribes
    every leg the gate scored and names the tree it measured.

    A record written before this rule cannot be amended -- its commit is in
    history and rewriting it would orphan the very pointers this file's other
    half exists to keep resolvable.  Such a record is dispositioned by a
    `RECORD-COMPLETED-BY` row keyed (commit, `-`), and that row is CHECKED:
    the commit it names is re-read here and required to be complete.
    """
    bad = []
    disp = (bindings or {}).get((commit[:12].lower(), '-'))
    if disp is not None:
        why = check_binding(repo, commit, '-', disp[0], disp[1], disp[2],
                            manifest)
        return ['%s: BINDING -- %s' % (commit[:12], why)] if why else []
    text = git(repo, 'log', '-1', '--format=%B', commit)
    if text is None:
        return ['%s: does not resolve to a commit' % commit[:12]]
    # THE MANIFEST IS READ AS OF THE RECORD'S OWN TREE, and this is the whole
    # difference between a completeness check and an anachronism.  A record
    # transcribes the gate AS IT RAN.  When a later pass adds a twentieth leg,
    # the working tree's manifest lists a row the record's run could not have
    # produced and nobody could have measured, and scoring against it would
    # convict a complete record of missing a leg that did not exist -- which
    # is exactly what happened the first time this check met a manifest that
    # had moved.  So the list of legs comes from the commit's own
    # ADJUDICATED.tsv; the working tree's copy is the fallback for a commit
    # that does not carry one.
    at_tree = manifest_at(repo, commit)
    if at_tree is not None:
        manifest = at_tree
    if manifest is None:
        return ['the R13 manifest %s is not readable at %s and not readable '
                'in the working tree -- a completeness check with no list of '
                'legs is not a check' % (MANIFEST_REL, commit[:12])]

    claim = CLAIM_RE.search(text)
    rows = RECORD_ROW_RE.findall(text)
    seen = set((r[0], r[1]) for r in rows)
    want = set(manifest)
    # Only rows naming a leg the manifest knows count as record rows; the
    # regex is deliberately loose so a MISSPELLED leg is visible as an
    # unknown row rather than silently matching nothing.
    known = set(l for l, _ in manifest)
    record_rows = [r for r in rows if r[0] in known]
    if not claim and not record_rows:
        return ['%s: carries no R13 leg record (no "GATE PASSED -- N legs" '
                'line and no manifest leg rows).  A commit named to '
                '--message is a commit claimed to carry one, and a check '
                'that cannot find its subject FAILS' % commit[:12]]

    stray = seen - want
    if stray:
        bad.append('%s: M2 COMPLETE -- %d row(s) name a leg/isa the R13 '
                   'manifest does not: %s'
                   % (commit[:12], len(stray),
                      ', '.join('%s/%s' % s for s in sorted(stray))))
    missing = want - seen
    if missing:
        bad.append('%s: M2 COMPLETE -- the record prints %d of %d legs; '
                   'MISSING %s'
                   % (commit[:12], len(record_rows), len(want),
                      ', '.join('%s/%s' % s for s in sorted(missing))))
    if claim:
        n = int(claim.group(1))
        if n != len(record_rows):
            bad.append('%s: M1 CLAIMED -- the record says "%d legs" and '
                       'prints %d row(s)' % (commit[:12], n, len(record_rows)))
    else:
        bad.append('%s: M1 CLAIMED -- the record prints rows but never says '
                   'how many legs it is transcribing, so nothing states what '
                   'it should have printed' % commit[:12])

    if want_tree:
        trees = TREE_RE.findall(text)
        # A TRANSCRIPT names the commit whose record it completes, and its
        # TREE= is THAT commit's tree -- the tree the legs actually ran on.
        # Without this a completion would have to claim its own tree, which
        # is a tree no leg in the table was measured at.
        of = RECORD_OF_RE.search(text)
        subject, what = commit, 'the tree %s carries' % commit[:12]
        if of:
            subject = git(repo, 'rev-parse', '--verify', '--quiet',
                          of.group(1) + '^{commit}')
            if subject is None:
                bad.append('%s: M3 TREED -- RECORD-OF=%s does not resolve to '
                           'a commit here' % (commit[:12], of.group(1)))
                return bad
            what = ('the tree %s carries, which RECORD-OF names as the tree '
                    'these legs ran on' % subject[:12])
        own = git(repo, 'rev-parse', '--verify', '--quiet', subject + '^{tree}')
        if not trees:
            bad.append('%s: M3 TREED -- the record names no TREE=<40 hex>, so '
                       'a reader has nothing durable to check it out from '
                       '(FINDING 90-B)' % commit[:12])
        elif own is None or not any(t.lower() == own for t in trees):
            bad.append('%s: M3 TREED -- TREE=%s is not %s (%s)'
                       % (commit[:12], trees[0][:12], what,
                          (own or '<none>')[:12]))
    return bad


def check_one(repo, rc_path, commit, so_hex, bindings=None, manifest=None):
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
        # THE BINDING IS CONSULTED BEFORE C1, and that ordering is the point
        # of FINDING 90-B.  A bound row's whole subject is a tip a reader
        # CANNOT reach; asking C1 first meant the row stopped being checkable
        # the moment `git gc` pruned the orphan it names -- the binding was
        # only ever load-bearing while the thing it compensates for survived.
        b = bindings.get((commit[:12].lower(), tip[:12].lower()))
        if b is not None:
            why = check_binding(repo, commit, tip, b[0], b[1], b[2], manifest)
            if why:
                bad.append('%s: TIP=%s BINDING -- %s' % (rc_path, tip[:12],
                                                         why))
            continue
        full = git(repo, 'rev-parse', '--verify', '--quiet', tip + '^{commit}')
        if not full:
            bad.append('%s: TIP=%s C1 RESOLVES -- not a commit in this '
                       'repository (orphaned by an amend?)' % (rc_path, tip))
            continue
        anc = subprocess.run(['git', '-C', repo, 'merge-base',
                              '--is-ancestor', full, commit],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL).returncode
        if anc != 0:
            bad.append('%s: TIP=%s C2 REACHABLE -- not an ancestor of %s'
                       % (rc_path, tip[:12], commit[:12]))
            continue
        if full == commit:
            continue
        if so_hex is None:
            bad.append('%s: TIP=%s C3 BOUND -- names the PARENT, and no '
                       'plugin was given to bind the record to the tree that '
                       'was measured.  A built .so is a perishable binding '
                       '(FINDING 90-B): give the record a durable one with a '
                       '`tree=<40 hex>` row in %s'
                       % (rc_path, tip[:12],
                          os.path.basename(BINDINGS_DEFAULT)))
            continue
        if not any(so_hex.startswith(s.lower()) for s in
                   (x.lower() for x in sos)):
            bad.append('%s: TIP=%s C3 BOUND -- names the PARENT and its SO= '
                       '%s does not match the built plugin %s'
                       % (rc_path, tip[:12],
                          (sos[0][:12] if sos else '<absent>'), so_hex[:12]))
    return bad


# --------------------------------------------------------------- selftest
# A check is only a check if it can go red.  Fifteen arms, in a scratch
# repository built here so the fixture cannot drift.
#
# 1-5 are the RESOLVABILITY arms: a sound record PASSES, an orphan FAILS, a
# parent TIP whose SO= names a different binary FAILS, the same parent TIP
# bound by content PASSES, a TIP-less record FAILS.
#
# 6-7 prove the BINDING KINDS are checked rather than believed: a false
# TREE-IDENTICAL and a LEGGED-AT-PARENT with a non-descendant covering commit
# both go red.
#
# 8-12 are FINDING 90-B, the DURABILITY arms, and 8 and 12 are the two
# EVAPORATING-FILE shapes this file exists to stop being blind to.  8: the
# .so the C3 route hashes is gone, and a record that was sound yesterday goes
# red today.  9: the same record with a `tree=` binding passes with NO plugin
# at all.  10: a binding row with no `tree=` column FAILS, so the durable
# column cannot be omitted.  11: a `tree=` naming something that is not the
# commit's tree FAILS.  12: the orphaned tip has been PRUNED and the row
# still verifies -- against the commit's own tree, which nothing can prune.
#
# 13-15 are FINDING 90-A, the COMPLETENESS arms: a record that prints fewer
# legs than the manifest FAILS, one that prints them all PASSES, and a
# RECORD-COMPLETED-BY row pointing at an INCOMPLETE commit FAILS.
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
        htree = g('rev-parse', 'HEAD^{tree}')
        ptree = g('rev-parse', 'HEAD~1^{tree}')

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
        # FAIL, or the table is an amnesty list.  The row carries its durable
        # `tree=` column (the commit's own tree), so what goes red here is the
        # TREE-IDENTICAL claim and not the durability check.
        rcp = rc('bindfalse', 'TIP=%s\n' % parent)
        binds = {(head[:12].lower(), parent[:12].lower()):
                 ('TREE-IDENTICAL', '', htree)}
        r = check_one(repo, rcp, head, soh, binds)
        if not any('TREE-IDENTICAL is FALSE' in x for x in r):
            fails.append('arm6 a false TREE-IDENTICAL binding should FAIL: '
                         '%s' % r)

        # ARM 7 -- a LEGGED-AT-PARENT row whose covering commit is not a
        # descendant must FAIL.
        binds = {(head[:12].lower(), parent[:12].lower()):
                 ('LEGGED-AT-PARENT', parent, ptree)}
        r = check_one(repo, rcp, head, soh, binds)
        if not any('not a descendant' in x for x in r):
            fails.append('arm7 a LEGGED-AT-PARENT row with a non-descendant '
                         'covering commit should FAIL: %s' % r)

        # ---------------------------------------------- FINDING 90-B arms
        # ARM 8 -- THE EVAPORATING FILE.  The record is the same sound
        # parent-tip record arm 4 passed; the only thing that changed is that
        # the plugin C3 hashes is gone.  It must go RED, because that is what
        # the build/ route does the first time somebody runs ninja.
        r = check_one(repo, rc('parent_gone', 'TIP=%s\nSO=%s\n'
                               % (parent, soh[:12])), head, None)
        if not any('C3 BOUND' in x for x in r):
            fails.append('arm8 a parent-tip record whose plugin has been '
                         'rebuilt away should FAIL on C3: %s' % r)

        # ARM 9 -- the SAME record with a durable tree binding, and still no
        # plugin anywhere.  Must PASS: the tree is in the object store.
        binds = {(head[:12].lower(), parent[:12].lower()):
                 ('TREE-SHA', '', htree)}
        r = check_one(repo, rc('parent_treed', 'TIP=%s\n' % parent),
                      head, None, binds)
        if r:
            fails.append('arm9 a tree-bound record should PASS with no '
                         'plugin present: %s' % r)

        # ARM 10 -- a binding row with NO tree column.  The durable column is
        # not optional; a row without one only resolves while something
        # perishable survives.
        binds = {(head[:12].lower(), parent[:12].lower()):
                 ('TREE-SHA', '', None)}
        r = check_one(repo, rcp, head, soh, binds)
        if not any('not a durable binding' in x for x in r):
            fails.append('arm10 a binding row with no tree= column should '
                         'FAIL: %s' % r)

        # ARM 11 -- a tree= that is not the commit's tree.  CHECKED, not
        # believed, exactly like the kinds.
        binds = {(head[:12].lower(), parent[:12].lower()):
                 ('TREE-SHA', '', ptree)}
        r = check_one(repo, rcp, head, soh, binds)
        if not any('is not the tree' in x for x in r):
            fails.append('arm11 a tree= naming another tree should FAIL: %s'
                         % r)

        # ARM 12 -- THE PRUNED-ORPHAN SHAPE.  The tip named by the record is
        # not in this object store at all (arm 2's sha), which is what `git
        # gc` leaves behind.  With a durable tree column the row still
        # verifies; C1 must not be consulted first, or the binding would be
        # load-bearing only while the thing it compensates for survived.
        binds = {(head[:12].lower(), orphan[:12].lower()):
                 ('TREE-IDENTICAL', '', htree)}
        r = check_one(repo, rc('pruned', 'TIP=%s\n' % orphan), head, soh,
                      binds)
        if r:
            fails.append('arm12 a tree-bound record whose orphan tip was '
                         'pruned should PASS: %s' % r)

        # ---------------------------------------------- FINDING 90-A arms
        # A two-leg manifest is enough to prove the partition; the real one
        # is read from the gate's ADJUDICATED.tsv at run time.
        man = [('static', 'x86_64'), ('pin', 'x86_64')]
        with open(os.path.join(repo, 'c'), 'w') as f:
            f.write('c')
        g('add', 'c')
        g('commit', '-q', '-m', 'short record\n\n'
          '    static     x86_64      47 / 47     6225 scored\n'
          '\n    GATE PASSED -- 2 legs, every headline at or under its '
          'ceiling\n')
        short = g('rev-parse', 'HEAD')
        stree = g('rev-parse', 'HEAD^{tree}')

        # ARM 13 -- a record that prints fewer legs than the gate scored.
        r = check_message(repo, short, man)
        if not any('M2 COMPLETE' in x for x in r):
            fails.append('arm13 a record printing 1 of 2 legs should FAIL on '
                         'M2: %s' % r)
        if not any('M1 CLAIMED' in x for x in r):
            fails.append('arm13b the same record claims 2 and prints 1, which '
                         'M1 must catch: %s' % r)

        # ARM 14 -- the complete record, naming its own tree.  Must PASS.
        with open(os.path.join(repo, 'e'), 'w') as f:
            f.write('e')
        g('add', 'e')
        g('commit', '-q', '-m', 'full record placeholder')
        full_tree = g('rev-parse', 'HEAD^{tree}')
        g('commit', '-q', '--amend', '-m',
          'full record\n\n    static     x86_64      47 / 47     6225 scored\n'
          '    pin        x86_64     259 / 259  395854\n'
          '\n    GATE PASSED -- 2 legs, every headline at or under its '
          'ceiling\n\nTREE=%s\n' % full_tree)
        fullc = g('rev-parse', 'HEAD')
        r = check_message(repo, fullc, man)
        if r:
            fails.append('arm14 a complete tree-naming record should PASS: %s'
                         % r)

        # ARM 15 -- RECORD-COMPLETED-BY is checked by RE-READING the commit it
        # names.  Pointing an incomplete record at another incomplete record
        # completes nothing.
        binds = {(short[:12].lower(), parent[:12].lower()):
                 ('RECORD-COMPLETED-BY', short, stree)}
        r = check_one(repo, rcp, short, soh, binds, man)
        if not any('does not itself carry a complete record' in x for x in r):
            fails.append('arm15 RECORD-COMPLETED-BY pointing at an incomplete '
                         'record should FAIL: %s' % r)

        # ARM 16 -- THE ANACHRONISM.  A record complete at ITS OWN tree, read
        # after a later pass added a twentieth leg, must still PASS: the
        # manifest comes from the commit, not from the working copy.  The
        # mirror arm proves the reading is not simply lenient -- the SAME
        # message against a commit whose OWN manifest carries the extra leg
        # FAILS, naming it.
        os.makedirs(os.path.join(repo, os.path.dirname(MANIFEST_REL)),
                    exist_ok=True)
        mpath = os.path.join(repo, MANIFEST_REL)
        body = ('full record\n\n'
                '    static     x86_64      47 / 47     6225 scored\n'
                '    pin        x86_64     259 / 259  395854\n'
                '\n    GATE PASSED -- 2 legs, every headline at or under its '
                'ceiling\n\nTREE=%s\n')

        with open(mpath, 'w') as f:          # the OLD manifest: two legs
            f.write('# c\nstatic\tx86_64\tr\t0\t0\t-\tj\n'
                    'pin\tx86_64\tr\t0\t0\t-\tj\n')
        with open(os.path.join(repo, 'f16'), 'w') as f:
            f.write('16')
        g('add', MANIFEST_REL, 'f16')
        g('commit', '-q', '-m', 'old manifest')
        old_tree = g('rev-parse', 'HEAD^{tree}')
        g('commit', '-q', '--amend', '-m', body % old_tree)
        old_rec = g('rev-parse', 'HEAD')

        with open(mpath, 'a') as f:          # a THIRD leg lands later
            f.write('gem5wp\tmipsel\tr\t0\t0\t-\tj\n')
        g('add', MANIFEST_REL)
        g('commit', '-q', '-m', 'new leg')
        new_tree = g('rev-parse', 'HEAD^{tree}')
        g('commit', '-q', '--amend', '-m', body % new_tree)
        new_rec = g('rev-parse', 'HEAD')

        # The working tree now carries THREE legs; both records print two.
        r = check_message(repo, old_rec, [('static', 'x86_64'),
                                          ('pin', 'x86_64'),
                                          ('gem5wp', 'mipsel')])
        if r:
            fails.append('arm16 a record complete at its own tree should '
                         'PASS against a later manifest: %s' % r)
        r = check_message(repo, new_rec, [('static', 'x86_64'),
                                          ('pin', 'x86_64')])
        if not any('gem5wp/mipsel' in x for x in r):
            fails.append('arm16b a record written AFTER the leg landed must '
                         'FAIL naming it: %s' % r)

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
             'LEGGED-AT-PARENT with a non-descendant cover fails',
             'a rebuilt-away plugin makes the SO route fail',
             'a tree-bound record passes with no plugin at all',
             'a binding row with no tree= column fails',
             'a tree= naming another tree fails',
             'a pruned orphan tip still verifies on its tree column',
             'a record printing fewer legs than the manifest fails',
             'a complete record naming its own tree passes',
             'RECORD-COMPLETED-BY pointing at an incomplete record fails',
             'the manifest is read as of the record\'s own tree']
    hit = set()
    for f in fails:
        print('SELFTEST FAIL: %s' % f)
        # `arm13b` is arm 13's second assertion, so the index is every digit
        # after `arm` and not just the first -- reading one character made
        # arm 13 report as arm 1.
        m = re.match(r'arm(\d+)', f)
        hit.add(int(m.group(1)) - 1 if m else -1)
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
    ap.add_argument('--bindings', default=BINDINGS_DEFAULT,
                    help='checked content bindings for records that cannot '
                         'be re-run')
    ap.add_argument('--manifest', default=MANIFEST,
                    help="the R13 gate's ADJUDICATED.tsv, whose (leg, isa) "
                         'pairs a complete in-commit record must transcribe')
    ap.add_argument('--message', action='append', default=[], metavar='COMMIT',
                    help='check the IN-COMMIT R13 leg record on this commit '
                         'for completeness (FINDING 90-A); repeatable')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.rc and not a.message:
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

    manifest = load_manifest(a.manifest)
    binds = load_bindings(a.bindings)
    bad = []
    for p in a.rc:
        bad += check_one(repo, p, commit, so_hex, binds, manifest)
    for c in a.message:
        full = git(repo, 'rev-parse', '--verify', '--quiet', c + '^{commit}')
        if not full:
            bad.append('--message %s does not resolve in %s' % (c, repo))
            continue
        bad += check_message(repo, full, manifest, bindings=binds)
    for b in bad:
        print('LEGCHECK FAIL: %s' % b)
    print('legcheck: %d record(s), %d in-commit record(s), %d failure(s), '
          'commit %s, manifest %d legs'
          % (len(a.rc), len(a.message), len(bad), commit[:12],
             len(manifest or [])))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
