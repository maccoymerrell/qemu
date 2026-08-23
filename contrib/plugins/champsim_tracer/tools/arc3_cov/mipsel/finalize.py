import json, subprocess, collections, sys
W   = "/mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel/work"
OUT = "/mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel"
ISAX = "/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck"

def mnem(t):
    for w in t.split():
        if w.startswith('.'): continue
        if w in ('push','pop','set','mips32r2','mips32','mips64','micromips','nomicromips',
                 'dsp','nodsp','msa','nomsa','mips3d','virt','crc','ginv','eva','mt',
                 'fp=64','fp=32','singlefloat','nosinglefloat','arch=default'): continue
        return w
    return ""

sel = json.load(open(f"{W}/selection.json"))["sel"]
fix = json.load(open(f"{W}/repair2.json"))["fixed"]
for f in fix:
    r = f["rows"][0]
    sel.append({"match": f["match"], "mask": f["mask"], "row": r["row"], "name": r["name"],
                "args": r["args"], "variant": "search", "hex": f["hex"], "l_text": f["l_text"],
                "b_ok": f["b_ok"], "b_mnem": f["b_mnem"], "how": "search", "argsig": "",
                "altnames": sorted({x["name"] for x in f["rows"]}),
                "rows": [x["row"] for x in f["rows"]]})

# canonical mnemonic: when the reference decoder (LLVM MC, rank-1 for mipsel)
# names the pattern with one of the group's own alternate spellings, that
# spelling is the primary name.
for s_ in sel:
    lm = mnem(s_.get("l_text",""))
    if lm and lm in s_.get("altnames",[]) and lm != s_["name"]:
        s_["altnames"] = sorted(set(s_["altnames"]) | {s_["name"]})
        s_["name"] = lm

ESCAPES = {"c0", "c1", "c2", "c3"}
RAWSYN  = {("mftr","41000000"), ("mttr","41800000")}
IDIOMS  = {("nal","04100000"), ("neg","00000022"), ("negu","00000023"),
           ("not","00000027"), ("pause","00000140"), ("sync.p","0000040f")}

kept, dropped = [], []
esc = [s for s in sel if s["name"] in ESCAPES]
body = [s for s in sel if s["name"] not in ESCAPES]
for s in esc:
    dropped.append((s, "assembler coprocessor escape (c0/c1/c2/c3: raw 25-bit COPz payload, not an ISA instruction)"))
raw = [s for s in body if (s["name"], s["match"]) in RAWSYN]
for s in raw:
    dropped.append((s, "raw-field assembler spelling of the MT ASE move; the 24 named mft*/mtt* forms carry the shapes (each names a different source register file)"))
body = [s for s in body if (s["name"], s["match"]) not in RAWSYN]

pats = [(int(s["match"],16), int(s["mask"],16), s) for s in body]
for m, k, s in pats:
    sub = None
    for m2, k2, s2 in pats:
        if s is s2: continue
        if k2 != k and (k & k2) == k2 and (m & k2) == m2:
            sub = s2; break
    if sub is None:
        kept.append(s); continue
    if s["name"] == sub["name"]:
        dropped.append((s, f"operand-syntax variant of the same instruction, subsumed by {sub['name']} {sub['match']}/{sub['mask']}"))
    elif (s["name"], s["match"]) in IDIOMS:
        dropped.append((s, f"R3 idiom: fixed-field form of {sub['name']} {sub['match']}/{sub['mask']}"))
    else:
        kept.append(s)          # mftr/mttr named shapes: distinct register files

# rank-1 reference naming: adopt LLVM MC's mnemonic when exactly one kept
# pattern claims it (binutils calls the MIPS32r2 ROTR encoding "ror").
claim = collections.Counter(mnem(s_.get("l_text","")) for s_ in kept)
for s_ in kept:
    lm = mnem(s_.get("l_text",""))
    if lm and lm != s_["name"] and claim[lm] == 1 and \
       not any(o["name"] == lm for o in kept):
        s_["altnames"] = sorted(set(s_["altnames"]) | {s_["name"]})
        s_["name"] = lm

print("kept:", len(kept), "dropped:", len(dropped), file=sys.stderr)

# ---- final verification: every kept encoding must decode ----
hexes = [s["hex"] for s in kept]
assert len(set(hexes)) == len(hexes), "duplicate representative encoding"
p = subprocess.run([ISAX, "--isa=mipsel", "--batch"], input="\n".join(hexes)+"\n",
                   capture_output=True, text=True)
lines = p.stdout.splitlines(); hdr = lines[0].split("\t")
dec = {}
for line in lines[1:]:
    d = dict(zip(hdr, line.split("\t"))); dec[d["hex"]] = d
bad = [s for s in kept if dec[s["hex"]]["l_ok"] != "1"]
capbad = [s for s in kept if dec[s["hex"]]["b_ok"] != "1"]
print("llvm-undecodable in final set:", len(bad), file=sys.stderr)
print("capstone-undecodable in final set:", len(capbad), file=sys.stderr)
assert not bad

names = collections.Counter(s["name"] for s in kept)
rows = []
for s in sorted(kept, key=lambda x: (x["name"], x["match"])):
    oid = f"mipsel.{s['name']}" if names[s["name"]] == 1 else f"mipsel.{s['name']}.{s['match']}"
    src = (f"binutils-2.42/opcodes/mips-opc.c#{s['row']} match={s['match']}/{s['mask']} "
           f"args=\"{s['args']}\"")
    if len(s["altnames"]) > 1:
        src += " altsyntax=" + ",".join(n for n in s["altnames"] if n != s["name"])
    rows.append((oid, s["name"], s["hex"], src))

with open(f"{OUT}/opcodes.tsv", "w") as f:
    f.write("#opcode_id\tmnemonic\trepresentative_encoding_hex_le\tsource_table\n")
    for r in rows:
        f.write("\t".join(r) + "\n")

with open(f"{OUT}/opcodes_verified.tsv", "w") as f:
    f.write("opcode_id\tmnemonic\thex\tllvm_ok\tllvm_text\tcapstone_ok\tcapstone_mnem\tmatch\tmask\targs\tbinutils_row\n")
    for (oid, nm, hx, src), s in zip(rows, sorted(kept, key=lambda x: (x["name"], x["match"]))):
        d = dec[hx]
        f.write(f"{oid}\t{nm}\t{hx}\t{d['l_ok']}\t{d['l_text']}\t{d['b_ok']}\t{d['b_mnem']}\t"
                f"{s['match']}\t{s['mask']}\t{s['args']}\t{s['row']}\n")

with open(f"{OUT}/excluded.tsv", "w") as f:
    f.write("mnemonic\tmatch\tmask\targs\tbinutils_row\treason\n")
    for s, why in sorted(dropped, key=lambda x: (x[0]["name"], x[0]["match"])):
        f.write(f"{s['name']}\t{s['match']}\t{s['mask']}\t{s['args']}\t{s['row']}\t{why}\n")
    # table-level scope exclusions, straight out of the same binutils rows
    for r in open(f"{W}/raw_v0.tsv").read().splitlines()[1:]:
        c = r.split("\t")
        row, nm, args, mtch, msk = c[0], c[1], c[2], c[3], c[4]
        alias, macro, member = c[8], c[9], c[10]
        if macro == "1":
            why = ("assembler macro (INSN_MACRO): expands to a sequence, has no encoding of its own"
                   + ("" if member == "1" else "; also outside the mipsel ISA/ASE scope"))
        elif member != "1":
            why = ("outside the mipsel decode scope (row is not a member of ISA_MIPS32R2 + "
                   "DSP/DSPr2/DSPr3/MSA/MT/EVA/VIRT/GINV/CRC/MIPS3D): MIPS64-only, MIPS32R6-only, "
                   "or a vendor/ASE the mipsel decode target does not select")
        elif alias == "1":
            why = "row flagged INSN2_ALIAS by the reference table: an alternate spelling, not a distinct opcode (R3)"
        else:
            continue
        f.write(f"{nm}\t{mtch}\t{msk}\t{args}\t{row}\t{why}\n")
    # rows collapsed into a pattern already represented by another row
    canon = {s_["row"] for s_ in sel}
    for g in json.load(open(f"{W}/repair2.json"))["still"]:
        canon.add(g["rows"][0]["row"])
    bypat = {}
    for r in open(f"{W}/raw_v0.tsv").read().splitlines()[1:]:
        c = r.split("\t")
        if c[9] != "0" or c[10] != "1" or c[8] != "0":
            continue
        bypat.setdefault((c[3], c[4]), []).append(c)
    for k, rs in bypat.items():
        head = next((x for x in rs if x[0] in canon), rs[0])
        for x in rs:
            if x is head:
                continue
            f.write(f"{x[1]}\t{x[3]}\t{x[4]}\t{x[2]}\t{x[0]}\t"
                    f"identical (match,mask) pattern as {head[1]} row {head[0]}: "
                    f"a second assembler syntax for the same bits\n")
    still = json.load(open(f"{W}/repair2.json"))["still"]
    for g in still:
        r = g["rows"][0]
        f.write(f"{r['name']}\t{g['match']}\t{g['mask']}\t{r['args']}\t{r['row']}\t"
                f"no encoding in this pattern's whole free space (2^{bin((~int(g['mask'],16))&0xffffffff).count('1')}) "
                f"is decoded by either reference decoder at the mipsel target (mips32r2+msa,dsp,dspr2,dspr3,fp64,eva,virt,ginv,crc,mt,mips3d) -- exhaustively searched\n")

print("FINAL COUNT:", len(rows), file=sys.stderr)
print("distinct mnemonics:", len(names), file=sys.stderr)
print("capstone-undecodable:", len(capbad), [s["name"] for s in capbad][:20], file=sys.stderr)
