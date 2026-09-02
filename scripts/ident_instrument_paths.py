#!/usr/bin/env python3
"""The path convention the seven ident-instrument generators share.

WHY THIS FILE EXISTS.  Every generator in this family reads tracked sources
and writes tracked artefacts -- a generated `.c.inc` beside the target it
describes, and for three of them a residue report under
`contrib/plugins/champsim_tracer/tools/arc3_qemuid/`.  Each argument used to
carry its own default pointing at its own tracked location, and the defaults
were INDEPENDENT.  That is the trap:

    scripts/x86_vex_ident_instrument.py --out /scratch/vex_ident.c.inc

reads as "regenerate elsewhere and compare", and it does regenerate the
header elsewhere -- while still overwriting the tracked
`VEX_IDENT_RESIDUE.txt`, because `--report` kept its own default.  Nothing
was hardcoded and nothing was wrong with any single default; redirecting one
of a set of three simply does not redirect the run.  A tree tripwire caught
it in verify49, which is the second time that class has been paid for here.

THE CONVENTION.  Outputs are a GROUP and the group is all-or-nothing:

  * An OUTPUT has NO default.  Omitting one is a refusal (rc 2), never a
    silent write to the tree.  A partial redirection is therefore not
    expressible: either every output is named, or none is and the run
    refuses.
  * `--in-tree` is the ONE switch that selects the canonical tracked
    location for EVERY output at once.  It is how the tree is regenerated,
    and it says so in the command line rather than in the absence of one.
  * `--in-tree` together with an explicit output is a refusal.  Two
    statements about where an output goes is not a preference to resolve, it
    is a question the caller has not answered.
  * An INPUT keeps its default, because deriving from the tracked tree is
    what these generators are FOR -- but the default is anchored at the
    repository root computed from the generator's own `__file__`, never
    relative to the caller's cwd.  Four of the seven were cwd-relative, so
    the same command wrote a different tree depending on where it was run.

WHAT THIS DELIBERATELY DOES NOT DO.  It does not make `--in-tree` the
default when stdout is a terminal, or infer the group from a `--outdir`
prefix.  Both restore the property the convention exists to remove: a run
that writes the tree without saying so.

Selftest:  scripts/ident_instrument_paths.py --selftest

Author: Maccoy Merrell.
"""

import os
import sys


class Refusal(Exception):
    """A path question the caller has not answered.  Never a warning."""


class Paths(object):
    """Input/output path registration for one generator.

    Register inputs with `add_input` and outputs with `add_output`, in the
    order `build()` wants them; `install` adds `--in-tree`; `resolve`
    returns the values in registration order or raises `Refusal`.
    """

    def __init__(self, script_file):
        self.root = os.path.dirname(os.path.dirname(
            os.path.abspath(script_file)))
        self.script = os.path.basename(os.path.abspath(script_file))
        self._order = []          # (dest, kind)
        self._outputs = []        # (dest, flag, canonical_rel)

    # -- registration ------------------------------------------------------
    def add_input(self, ap, flag, rel, **kw):
        """An input.  Defaults to <repo-root>/<rel>, absolute, cwd-free."""
        dest = _dest(ap, flag, kw)
        ap.add_argument(flag, default=os.path.join(self.root, rel), **kw)
        self._order.append((dest, 'in'))
        return dest

    def add_output(self, ap, flag, rel, **kw):
        """An output.  NO default; `--in-tree` selects <repo-root>/<rel>."""
        dest = _dest(ap, flag, kw)
        ap.add_argument(flag, default=None, **kw)
        self._order.append((dest, 'out'))
        self._outputs.append((dest, flag, rel))
        return dest

    def install(self, ap):
        ap.add_argument('--in-tree', action='store_true',
                        help='write every output to its tracked location')
        return ap

    # -- resolution --------------------------------------------------------
    def resolve(self, args):
        """Values in registration order, or raise Refusal."""
        given = [(d, f, r) for (d, f, r) in self._outputs
                 if getattr(args, d, None) is not None]
        missing = [(d, f, r) for (d, f, r) in self._outputs
                   if getattr(args, d, None) is None]
        in_tree = bool(getattr(args, 'in_tree', False))

        if in_tree and given:
            raise Refusal(
                '%s: --in-tree and %s both name where an output goes.\n'
                'Pass --in-tree alone to regenerate the tree, or name '
                'every output explicitly.'
                % (self.script, ', '.join(f for (_, f, _) in given)))
        if in_tree:
            for (dest, _flag, rel) in self._outputs:
                setattr(args, dest, os.path.join(self.root, rel))
        elif missing:
            lines = ['%s: refusing -- %d of %d outputs not named.'
                     % (self.script, len(missing), len(self._outputs))]
            for (_d, flag, rel) in missing:
                lines.append('    %-14s tracked location: %s' % (flag, rel))
            lines.append('')
            lines.append('There is no default: a run that names SOME outputs '
                         'would write the')
            lines.append('rest into the tree, which is the trap this '
                         'convention removes.  Use')
            lines.append('    %s --in-tree' % self.script)
            lines.append('to regenerate the tracked files, or name every '
                         'output above.')
            raise Refusal('\n'.join(lines))

        return [getattr(args, dest) for (dest, _kind) in self._order]

    # -- introspection, for the selftest -----------------------------------
    def outputs(self):
        return list(self._outputs)


def _dest(ap, flag, kw):
    if 'dest' in kw:
        return kw['dest']
    return flag.lstrip('-').replace('-', '_')


def main_wrapper(paths, ap, build):
    """Parse, resolve, refuse on stderr with rc 2, else call build(*vals)."""
    args = ap.parse_args()
    try:
        vals = paths.resolve(args)
    except Refusal as exc:
        sys.stderr.write('%s\n' % exc)
        return 2
    return build(args, vals)


# ------------------------------------------------------------------ selftest
def _selftest():
    import argparse
    import subprocess
    import tempfile

    fails = [0]
    n = [0]

    def ok(msg):
        n[0] += 1
        print('PASS  %s' % msg)

    def bad(msg):
        n[0] += 1
        fails[0] += 1
        print('FAIL  %s' % msg)

    def mk():
        ap = argparse.ArgumentParser()
        p = Paths(__file__)
        p.add_input(ap, '--source', 'target/x/src.c')
        p.add_output(ap, '-o', 'target/x/out.c.inc')
        p.add_output(ap, '--report', 'contrib/x/REPORT.txt')
        p.install(ap)
        return ap, p

    # A: no outputs named -> refusal, and the message names both.
    ap, p = mk()
    try:
        p.resolve(ap.parse_args([]))
        bad('A no outputs named must refuse')
    except Refusal as exc:
        if '-o' in str(exc) and '--report' in str(exc):
            ok('A no outputs named refuses, naming both')
        else:
            bad('A refusal does not name both outputs: %s' % exc)

    # B: PARTIAL redirection -- the exact verify49 trap -- refuses.
    ap, p = mk()
    try:
        p.resolve(ap.parse_args(['-o', '/scratch/out.inc']))
        bad('B partial redirection must refuse')
    except Refusal as exc:
        if '--report' in str(exc) and '1 of 2' in str(exc):
            ok('B partial redirection refuses and names the unredirected one')
        else:
            bad('B refusal is not specific: %s' % exc)

    # C: every output named -> used verbatim, in registration order.
    ap, p = mk()
    vals = p.resolve(ap.parse_args(['-o', '/s/o.inc', '--report', '/s/r.txt']))
    if vals[1:] == ['/s/o.inc', '/s/r.txt']:
        ok('C all outputs named are used verbatim, in order')
    else:
        bad('C wrong values %r' % (vals,))

    # D: --in-tree -> every output at its tracked location, absolute.
    ap, p = mk()
    vals = p.resolve(ap.parse_args(['--in-tree']))
    want = [os.path.join(p.root, 'target/x/out.c.inc'),
            os.path.join(p.root, 'contrib/x/REPORT.txt')]
    if vals[1:] == want and all(os.path.isabs(v) for v in vals):
        ok('D --in-tree selects every tracked location, absolute')
    else:
        bad('D wrong in-tree values %r' % (vals,))

    # E: --in-tree WITH an explicit output is two answers, so it refuses.
    ap, p = mk()
    try:
        p.resolve(ap.parse_args(['--in-tree', '-o', '/s/o.inc']))
        bad('E --in-tree plus explicit output must refuse')
    except Refusal:
        ok('E --in-tree plus an explicit output refuses')

    # F: an input default is anchored at the repo root, not at the cwd.
    ap, p = mk()
    here = os.getcwd()
    try:
        os.chdir(tempfile.gettempdir())
        vals = p.resolve(ap.parse_args(['--in-tree']))
    finally:
        os.chdir(here)
    if vals[0] == os.path.join(p.root, 'target/x/src.c'):
        ok('F input default is root-anchored, unchanged by the cwd')
    else:
        bad('F input default moved with the cwd: %s' % vals[0])

    # G: THE CENSUS.  Every ident-instrument generator in scripts/ must use
    #    this module.  A sibling added later that keeps its own defaults is
    #    a convention that has silently stopped being one.
    sd = os.path.dirname(os.path.abspath(__file__))
    sibs = sorted(f for f in os.listdir(sd)
                  if f.endswith('_ident_instrument.py'))
    if len(sibs) < 7:
        bad('G expected at least 7 sibling generators, found %d' % len(sibs))
    else:
        strays = []
        for s in sibs:
            with open(os.path.join(sd, s)) as fh:
                if 'ident_instrument_paths' not in fh.read():
                    strays.append(s)
        if strays:
            bad('G siblings not on the convention: %s' % ', '.join(strays))
        else:
            ok('G all %d sibling generators use this module' % len(sibs))

    # H: THE LIVE ARM.  Run each sibling with NO arguments, from a cwd that
    #    is not the tree, and require rc 2 and an untouched tree.  This is
    #    the arm that would have caught the original defect: it does not ask
    #    what the code says, it asks what the process does.
    for s in sibs:
        path = os.path.join(sd, s)
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run([sys.executable, path],
                               cwd=td, capture_output=True, text=True)
        if r.returncode != 2:
            bad('H %s with no arguments returned %d, want 2' % (s, r.returncode))
        elif 'refusing' not in r.stderr:
            bad('H %s refused without saying so: %r' % (s, r.stderr[:120]))
        else:
            ok('H %s with no arguments refuses (rc 2)' % s)

    # I: and the refusal WROTE NOTHING.  H proves the exit status; this
    #    proves the tree, which is the property that actually matters.
    root = os.path.dirname(sd)
    watched = []
    for s in sibs:
        with open(os.path.join(sd, s)) as fh:
            txt = fh.read()
        for tok in ('_ident.c.inc', '_IDENT_RESIDUE.txt', 'translate_ident'):
            for line in txt.splitlines():
                if 'add_output' in line and tok in line:
                    rel = line.split("'")[-2]
                    p2 = os.path.join(root, rel)
                    if os.path.exists(p2):
                        watched.append(p2)
    watched = sorted(set(watched))
    if not watched:
        bad('I no tracked outputs found to watch -- the arm is blind')
    else:
        before = {w: os.stat(w).st_mtime_ns for w in watched}
        for s in sibs:
            with tempfile.TemporaryDirectory() as td:
                subprocess.run([sys.executable, os.path.join(sd, s)],
                               cwd=td, capture_output=True, text=True)
        moved = [w for w in watched if os.stat(w).st_mtime_ns != before[w]]
        if moved:
            bad('I a refusing run touched %s' % ', '.join(moved))
        else:
            ok('I %d tracked outputs untouched by seven refusing runs'
               % len(watched))

    print('%d arms, %d failures' % (n[0], fails[0]))
    return 1 if fails[0] else 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    sys.stderr.write('%s is a module; run --selftest to check it.\n'
                     % os.path.basename(__file__))
    sys.exit(2)
