import csv, sys, os, collections, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mra_ref

BASE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64'

def main(out):
    r = mra_ref.Ref()
    rows = list(csv.DictReader(open(BASE + '/opcodes.tsv'), delimiter='\t'))
    res = {}
    st = collections.Counter()
    notes = collections.Counter()
    t0 = time.time()
    for i, x in enumerate(rows):
        w = int.from_bytes(bytes.fromhex(x['hex']), 'little')
        try:
            ef, nt, status = r.run(x['opcode_id'], w, x['xml_file'])
        except Exception as e:
            ef, nt, status = None, ['driver:' + type(e).__name__ + ':' + str(e)[:60]], 'unprobed'
        st[status] += 1
        for n in nt:
            notes[n.split(':')[0]] += 1
        if ef is None:
            res[x['hex']] = {'status': status, 'notes': nt}
        else:
            s, d = mra_ref.to_sets(ef)
            res[x['hex']] = {'status': status, 'notes': nt, 'src': sorted(s),
                             'dst': sorted(d), 'mr': ef.mem_r, 'mw': ef.mem_w,
                             'unres': sorted('%s:%s' % t for t in ef.unresolved)}
        if (i + 1) % 500 == 0:
            print(i + 1, dict(st), '%.1fs' % (time.time() - t0), flush=True)
    json.dump(res, open(out, 'w'))
    print('STATUS', dict(st))
    print('NOTES', notes.most_common(20))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else BASE + '/ref_mra.json')
