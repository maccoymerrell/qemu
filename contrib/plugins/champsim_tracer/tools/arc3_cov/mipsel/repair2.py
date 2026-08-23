import json, subprocess, sys, os
W = "/mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel/work"
ISAX = "/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck"
d = json.load(open(f"{W}/selection.json"))
unres = d["unres"]

def freebits(mask):
    return [i for i in range(32) if not (mask >> i & 1)]

fixed, still = [], []
for gi, g in enumerate(unres):
    match = int(g["match"], 16); mask = int(g["mask"], 16)
    fb = freebits(mask); n = len(fb)
    names = {r["name"] for r in g["rows"]}
    hits = []
    # exhaustive over the pattern's whole free space, streamed in chunks
    CH = 1 << 20
    total = 1 << n
    pos = 0
    while pos < total and len(hits) < 200:
        chunk = []
        for k in range(pos, min(pos + CH, total)):
            w = match
            for bi, b in enumerate(fb):
                if k >> bi & 1: w |= (1 << b)
            chunk.append("%02x%02x%02x%02x" % (w & 0xff, (w>>8)&0xff, (w>>16)&0xff, (w>>24)&0xff))
        p = subprocess.run([ISAX, "--isa=mipsel", "--batch"], input="\n".join(chunk)+"\n",
                           capture_output=True, text=True)
        for line in p.stdout.splitlines()[1:]:
            f = line.split("\t")
            if len(f) > 18 and f[16] == "1":
                hits.append((f[0], f[18], f[1], f[3]))
                if len(hits) >= 200: break
        pos += CH
    if hits:
        pref = [h for h in hits if h[1].split()[0] in names] or hits
        h = pref[0]
        fixed.append({"match": g["match"], "mask": g["mask"], "hex": h[0],
                      "l_text": h[1], "b_ok": h[2], "b_mnem": h[3],
                      "name_match": h[1].split()[0] in names,
                      "llvm_mnem": h[1].split()[0], "rows": g["rows"],
                      "nhits_seen": len(hits)})
    else:
        still.append({"match": g["match"], "mask": g["mask"], "rows": g["rows"],
                      "free_space": total})
    print(f"[{gi+1}/{len(unres)}] {g['rows'][0]['name']:14s} free=2^{n:<2d} hits={len(hits)}",
          file=sys.stderr)
json.dump({"fixed": fixed, "still": still}, open(f"{W}/repair2.json","w"), indent=1)
print("repaired:", len(fixed), "still:", len(still), file=sys.stderr)
