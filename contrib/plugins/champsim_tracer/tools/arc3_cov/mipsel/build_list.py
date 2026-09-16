import subprocess, sys, os, collections
W = "/mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel/work"
ISAX = "/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck"

def load(v):
    rows = []
    with open(f"{W}/raw_v{v}.tsv") as f:
        hdr = f.readline().rstrip("\n").split("\t")
        for line in f:
            p = line.rstrip("\n").split("\t")
            rows.append(dict(zip(hdr, p)))
    return rows

V = {v: load(v) for v in (0,1,2,3)}
base = V[0]

def keep(r):
    return r["member"] == "1" and r["macro"] == "0" and r["alias"] == "0" and r["enc_bytes_le"]

cands = [r for r in base if keep(r)]
groups = collections.OrderedDict()
for r in cands:
    k = (r["match"], r["mask"])
    groups.setdefault(k, []).append(r)
print("groups:", len(groups), "rows:", len(cands), file=sys.stderr)

def batch(hexes):
    inp = "\n".join(hexes) + "\n"
    out = subprocess.run([ISAX, "--isa=mipsel", "--batch"], input=inp,
                         capture_output=True, text=True)
    res = {}
    lines = out.stdout.splitlines()
    hdr = lines[0].split("\t")
    for line in lines[1:]:
        p = line.split("\t")
        d = dict(zip(hdr, p))
        res[d["hex"]] = d
    return res

# For each group, try variants in order until LLVM decodes AND the mnemonic
# matches one of the group's binutils names.
byrow = {v: {r["row"]: r for r in V[v]} for v in (0,1,2,3)}
order = [0,3,2,1]

# first pass: gather all candidate encodings for all groups/variants
allhex = set()
for k, g in groups.items():
    for r in g:
        for v in order:
            e = byrow[v][r["row"]]["enc_bytes_le"]
            if e: allhex.add(e)
DEC = batch(sorted(allhex))
print("decoded probe set:", len(DEC), file=sys.stderr)

def lmnem(d):
    t = d.get("l_text","")
    return t.split()[0] if t else ""

sel = []
unres = []
for k, g in groups.items():
    names = {r["name"] for r in g}
    chosen = None
    # preference: variant order, row order; require l_ok and mnemonic in names
    for v in order:
        for r in g:
            e = byrow[v][r["row"]]["enc_bytes_le"]
            d = DEC.get(e)
            if d and d["l_ok"] == "1" and lmnem(d) == r["name"]:
                chosen = (r, v, e, d, "exact"); break
        if chosen: break
    if not chosen:
        for v in order:
            for r in g:
                e = byrow[v][r["row"]]["enc_bytes_le"]
                d = DEC.get(e)
                if d and d["l_ok"] == "1" and lmnem(d) in names:
                    chosen = (r, v, e, d, "group-name"); break
            if chosen: break
    if not chosen:
        for v in order:
            for r in g:
                e = byrow[v][r["row"]]["enc_bytes_le"]
                d = DEC.get(e)
                if d and d["l_ok"] == "1":
                    chosen = (r, v, e, d, "llvm-other:"+lmnem(d)); break
            if chosen: break
    if chosen:
        sel.append((k, g, chosen))
    else:
        unres.append((k, g))

print("selected:", len(sel), "unresolved:", len(unres), file=sys.stderr)
import json
with open(f"{W}/selection.json","w") as f:
    json.dump({
      "sel": [{"match":k[0],"mask":k[1],"row":c[0]["row"],"name":c[0]["name"],
               "args":c[0]["args"],"variant":c[1],"hex":c[2],
               "l_text":c[3]["l_text"],"b_ok":c[3]["b_ok"],"b_mnem":c[3]["b_mnem"],
               "how":c[4],"argsig":c[0]["argsig"],
               "altnames":sorted({r["name"] for r in g}),
               "rows":[r["row"] for r in g]}
              for k,g,c in sel],
      "unres": [{"match":k[0],"mask":k[1],
                 "rows":[{"row":r["row"],"name":r["name"],"args":r["args"],
                          "hex":r["enc_bytes_le"]} for r in g]}
                for k,g in unres],
    }, f, indent=1)
print("wrote selection.json", file=sys.stderr)
