#!/usr/bin/env python3
"""Run the Arm MRA execute-ASL reference over the aarch64 denominator.

Author: Maccoy Merrell.

Records, per subject: the register source and destination sets, the memory
access COUNTS, the memory BYTE totals, whether a byte total is complete,
whether each Mem[] address resolved, and the interpreter's NOTES.

THE NOTES ARE NOT DIAGNOSTICS.  `undefined-path` says the ASL reached its own
UNDEFINED statement at the vector length this sweep was configured with, and
a consumer that does not read it cannot tell a register set that MOVED with
the vector length from an encoding that is simply not DEFINED at that vector
length.  That distinction is the whole of TOTAL_COVERAGE.md open item 9: 22
of the 23 "VL-conditional" aarch64 register-set subjects are constant across
every vector length at which they are defined, and read as conditional only
because the sweep's low arm evaluated them where they are UNDEFINED.

    python mra_sweep.py --vl 512 --out ref_512.json [--only HEXFILE]
"""
import os
import sys
import csv
import json
import time
import argparse
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aslinterp                                            # noqa: E402
import mra_ref                                              # noqa: E402

BASE = os.environ.get('CST_ARC3_COV',
                      '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vl', type=int, required=True,
                    help='SVE/SME vector length in BITS, a multiple of 128')
    ap.add_argument('--out', required=True)
    ap.add_argument('--only', default=None,
                    help='file of encodings in hex, one per line')
    ap.add_argument('--cov', default=BASE)
    A = ap.parse_args()
    if A.vl % 128 or not 128 <= A.vl <= 2048:
        sys.exit('--vl must be a multiple of 128 in [128, 2048]')

    aslinterp.CONSTS['CurrentVL'] = A.vl
    aslinterp.CONSTS['CurrentSVL'] = A.vl
    only = None
    if A.only:
        only = {l.strip() for l in open(A.only) if l.strip()}

    rows = list(csv.DictReader(open(os.path.join(A.cov, 'opcodes.tsv')),
                               delimiter='\t'))
    if only is not None:
        rows = [x for x in rows if x['hex'] in only]
        if not rows:
            sys.exit('--only matched no subject in the denominator')

    r = mra_ref.Ref()
    res = {}
    st = collections.Counter()
    t0 = time.time()
    for i, x in enumerate(rows):
        w = int.from_bytes(bytes.fromhex(x['hex']), 'little')
        try:
            ef, nt, status = r.run(x['opcode_id'], w, x['xml_file'])
        except Exception as e:
            ef, nt, status = None, ['driver:' + type(e).__name__], 'unprobed'
        st[status] += 1
        if ef is None:
            res[x['hex']] = {'status': status, 'notes': sorted(nt or [])}
        else:
            src, dst = mra_ref.to_sets(ef)
            res[x['hex']] = {'status': status,
                             'src': sorted(src), 'dst': sorted(dst),
                             'mr': ef.mem_r, 'mw': ef.mem_w,
                             'mrb': ef.mem_rb, 'mwb': ef.mem_wb,
                             'bunk': ef.mem_bytes_unknown,
                             'ak': ef.mem_addr_known,
                             'au': ef.mem_addr_unknown,
                             'notes': sorted(nt or [])}
        if (i + 1) % 1500 == 0:
            print(i + 1, dict(st), '%.0fs' % (time.time() - t0), flush=True)
    # The vector length is part of the reading, not of the invocation: a
    # consumer that scores a run against this sweep has to know they were
    # taken at the same VL, and a sweep that does not say which one it used
    # cannot be checked.
    res['__meta__'] = {'vl': A.vl, 'subjects': len(rows)}
    json.dump(res, open(A.out, 'w'))
    print('VL=%d n=%d STATUS %s' % (A.vl, len(rows), dict(st)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
