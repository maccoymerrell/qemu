"""Re-probe the tracer side for every subject in one isaxcheck --batch call.

Writes tracer_fields.tsv in the shape compare.py consumes:
    hex \t rc \t <fields line> \t SRC{..} \t DST{..}
Equivalent to the per-encoding probe_one.sh loop, ~40000x faster.
"""
import csv, subprocess, sys

BASE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64'
BIN = sys.argv[1] if len(sys.argv) > 1 else \
    '/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck'


def render(binary=None):
    """Probe the live tracer and return the tracer_fields.tsv TEXT.

    Split out from main() so a SCORER can re-derive this arm rather than
    trust the file: compare.py calls it and refuses to score a
    tracer_fields.tsv that does not match.
    """
    binary = binary or BIN
    hexes = [r['hex'] for r in
             csv.DictReader(open(BASE + '/opcodes.tsv'), delimiter='\t')]
    p = subprocess.run([binary, '--isa=aarch64', '--layer=fields', '--batch'],
                       input='\n'.join(hexes) + '\n',
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
    print('reprobed %d encodings' % n)


if __name__ == '__main__':
    main()
