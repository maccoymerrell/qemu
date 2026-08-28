"""Re-probe the tracer side for every subject in one isaxcheck --batch call.

Writes tracer_fields.tsv in the shape compare.py consumes:
    hex \t rc \t <fields line> \t SRC{..} \t DST{..}
Equivalent to the per-encoding probe_one.sh loop, ~40000x faster.
"""
import csv, os, subprocess, sys

BASE = os.environ.get('CST_COV_DIR',
                      '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/aarch64'
BIN = sys.argv[1] if len(sys.argv) > 1 else \
    os.environ.get('CST_ISAXCHECK',
                   '/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck')

# THE FIRING CONTROL'S CHANNEL, and it has to be the ENVIRONMENT.
#
# aarch64's headline is 0 TRACER-SUBSET, and a zero is the one result equally
# consistent with "the two models agree" and "the comparison never reached its
# subject" (R8.7).  The other three ISAs prove their zero by damaging the
# tracer arm and watching the agreement fall by exactly the damaged rows;
# aarch64 had no way to do it, because compare.py RE-DERIVES this arm by
# calling render() with no arguments and refuses any file that does not match.
# A command-line flag would therefore damage the file and then be refused by
# the scorer.  CST_FALSIFY reaches BOTH, which is what keeps the control
# honest: the damaged table is what is scored, not a table nobody re-probed.
# The same variable name is already the riscv64 harness's (compare.py:178).
FALSIFY = os.environ.get('CST_FALSIFY')


def render(binary=None):
    """Probe the live tracer and return the tracer_fields.tsv TEXT.

    Split out from main() so a SCORER can re-derive this arm rather than
    trust the file: compare.py calls it and refuses to score a
    tracer_fields.tsv that does not match.
    """
    binary = binary or BIN
    hexes = [r['hex'] for r in
             csv.DictReader(open(BASE + '/opcodes.tsv'), delimiter='\t')]
    argv = [binary, '--isa=aarch64', '--layer=fields', '--batch']
    if FALSIFY:
        argv.append('--falsify=' + FALSIFY)
    p = subprocess.run(argv, input='\n'.join(hexes) + '\n',
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit('isaxcheck --batch failed rc=%d: %s' % (p.returncode,
                                                         p.stderr[-2000:]))
    rows = list(csv.DictReader(p.stdout.splitlines(), delimiter='\t'))
    seen = {r['hex']: r for r in rows}
    missing = [h for h in hexes if h not in seen]
    if missing:
        sys.exit('batch dropped %d encodings, first %s' %
                 (len(missing), missing[:4]))
    buf = []
    for h in hexes:
        r = seen[h]
        fl = 'fields   ok=%s  %s  %s' % (r['f_ok'], r['f_opcode'],
                                         r['f_branch'])
        buf.append('%s\t0\t%s\tSRC{%s}\tDST{%s}\n' %
                   (h, fl, r['f_src'], r['f_dst']))
    return ''.join(buf), len(hexes)


def main():
    text, n = render()
    with open(BASE + '/tracer_fields.tsv', 'w') as out:
        out.write(text)
    print('reprobed %d encodings%s'
          % (n, '  FALSIFIED ' + FALSIFY if FALSIFY else ''))


if __name__ == '__main__':
    main()
