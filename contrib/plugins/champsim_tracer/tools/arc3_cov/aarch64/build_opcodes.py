#!/usr/bin/env python
"""
ARC 3 coverage denominator, aarch64: enumerate the A64 OPCODE SPACE.

Reference (rank 1 for this ISA, per the ARC 3 reference set): the Arm
Machine Readable Architecture A64 ISA XML, release 2022-12.  Capstone is
NOT consulted -- it is the subject under test (ruling R7).

UNIT OF ENUMERATION.  Arm names every encoding of every instruction, e.g.
`ADC_32_addsub_carry` / `ADC_64_addsub_carry`, `LDR_32_ldst_immpost` /
`LDR_32_ldst_immpre` / `LDR_32_ldst_pos`.  That naming already splits an
instruction section into the forms whose OPERAND SHAPE differs -- datatype
width, register vs immediate, pre-/post-index vs unsigned offset, scalar
vs vector, predicated vs not.  It is exactly the row granularity ARC 3
asks for, and it comes from the architecture rather than from a decoder.

Fields INSIDE one named encoding (Rd/Rn/Rm/imm/label) are generic per
ruling C3, so exactly one representative encoding is emitted per subject.

SUBJECT IDENTITY.  Two named encodings that occupy the SAME bit range --
identical fixed-bit mask, identical fixed-bit values, identical field
constraints -- and whose alias condition is "Unconditionally" are one
subject under two assembly spellings (SVE `CMPLT` is `CMPGT` with the
operands printed the other way round; `ASR` is `ASRV`).  Those are merged
onto one row and the spellings recorded, because no encoding exists that
the tracer could see as one and not the other.  An alias with a REAL
condition (`CINC` is `CSINC` with Rn == Rm) stays a distinct subject: its
operand set genuinely differs.
"""
import os, sys, csv, glob, random, subprocess
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

REF  = sys.argv[1]
OUTD = sys.argv[2]
ISAX = "/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck"

# index_z_ii.xml & friends are the SVE INDEX *instruction*, not an index
# page -- skipping them by name cost four real opcodes.  Everything else is
# filtered structurally, by root tag and by instructionsection/@type.
SKIP = {"onebigfile.xml"}
FIXED = {"0": 0, "1": 1, "(0)": 0, "(1)": 1}
COND = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv")

def cells(box):
    out = []
    for c in box.findall("c"):
        out.extend([(c.text or "").strip()] * int(c.get("colspan", "1")))
    return out

def apply_boxes(boxes, bits, fields, override=False):
    """override=True for an <encoding>'s own boxes: a BLANK cell there means
    "unchanged from the iclass regdiagram", not "free".  Reading it as free
    silently erases a fixed bit -- that is how FCMP came out as FCMPE."""
    for box in boxes:
        hi = int(box.get("hibit")); w = int(box.get("width", "1"))
        vals = cells(box); vals += [""] * (w - len(vals))
        for i in range(w):
            pos = hi - i
            if not (0 <= pos <= 31):
                continue
            v = vals[i]
            if override and v == "":
                continue
            if v == "z":
                bits[pos] = 0 if override else None
                continue
            bits[pos] = FIXED.get(v)
        if box.get("name") or box.get("constraint"):
            fields.append({"name": box.get("name"), "hi": hi, "w": w,
                           "con": box.get("constraint")})

def fill(bits, fields, rng=None, no31=True, tie=None, zero_imm=False):
    b = list(bits); nxt = [1]
    for f in fields:
        span = [p for p in range(f["hi"] - f["w"] + 1, f["hi"] + 1) if 0 <= p <= 31]
        if not any(b[p] is None for p in span):
            continue
        if rng is not None:
            if tie is not None and f["w"] == 5:
                v = tie
            elif zero_imm and f["w"] != 5:
                v = 0
            else:
                v = rng.randrange(0, 1 << f["w"])
                if no31 and f["w"] == 5 and v == 31:
                    v = rng.randrange(0, 31)
        else:
            v = nxt[0]; nxt[0] = 1 if nxt[0] >= 6 else nxt[0] + 1
            v &= (1 << f["w"]) - 1
        for i in range(f["w"]):
            pos = f["hi"] - i
            if 0 <= pos <= 31 and b[pos] is None:
                b[pos] = (v >> (f["w"] - 1 - i)) & 1
    for p in range(32):
        if b[p] is None:
            b[p] = rng.randrange(2) if rng is not None else 0
    for _ in range(64):
        bad = False
        for f in fields:
            con = f["con"]
            if not con or not con.startswith("!="):
                continue
            pat = con[2:].strip()
            if len(pat) != f["w"]:
                continue
            if all(b[f["hi"] - i] == int(ch) for i, ch in enumerate(pat) if ch in "01"):
                bad = True
                for i, ch in enumerate(pat):
                    if ch in "01":
                        b[f["hi"] - i] ^= 1
                        break
        if not bad:
            break
    w = 0
    for p in range(32):
        w |= b[p] << p
    return w

def text_of(el):
    return "".join(el.itertext()).strip() if el is not None else ""

# ------------------------------------------------------------------ parse --
rows, seen, nsec = [], set(), Counter()
for path in sorted(glob.glob(os.path.join(REF, "*.xml"))):
    fn = os.path.basename(path)
    if fn in SKIP:
        continue
    try:
        root = ET.parse(path).getroot()
    except Exception:
        continue
    if root.tag != "instructionsection":
        continue
    nsec[root.get("type")] += 1
    if root.get("type") not in ("instruction", "alias"):
        continue
    st, sec = root.get("type"), root.get("id")
    # alias condition, if any: "Unconditionally" means the alias covers the
    # whole encoding range of the instruction it aliases.
    acond = ""
    for ac in root.iter("aliascond"):
        acond = " ".join(text_of(ac).split())
        break
    for iclass in root.iter("iclass"):
        if iclass.get("isa") not in (None, "A64"):
            continue
        rd = iclass.find("regdiagram")
        if rd is None or rd.get("form") not in (None, "32"):
            continue
        bb, bf = [None] * 32, []
        apply_boxes(rd.findall("box"), bb, bf)
        dvi = {d.get("key"): d.get("value") for d in iclass.findall("docvars/docvar")}
        eidx = 0
        for enc in (iclass.findall("encoding") or [None]):
            eidx += 1
            bits, fields = list(bb), list(bf)
            if enc is not None:
                apply_boxes(enc.findall("box"), bits, fields, override=True)
                name, label = enc.get("name"), enc.get("label") or ""
                if not name:      # Arm leaves a few <encoding name=""> in the
                                  # SVE MOV-alias pages; synthesise a stable id
                    name = "%s__%s_%d" % (sec, iclass.get("id") or "ic", eidx)
                dv = {d.get("key"): d.get("value") for d in enc.findall("docvars/docvar")}
                asm = " ".join(text_of(enc.find("asmtemplate")).split())
            else:
                name, label, dv, asm = sec, "", {}, ""
            if name in seen:
                continue
            seen.add(name)
            rows.append({
                "enc": name, "file": fn, "sec": sec, "type": st, "label": label,
                "bits": bits, "fields": fields, "asm": asm, "acond": acond,
                "mnem": (dv.get("alias_mnemonic") or dvi.get("alias_mnemonic")
                         or dv.get("mnemonic") or dvi.get("mnemonic") or sec).lower(),
                "base": (dv.get("mnemonic") or dvi.get("mnemonic") or sec).lower(),
                "class": dv.get("instr-class") or dvi.get("instr-class") or "",
            })
sys.stderr.write("instructionsections %r   named A64 encodings %d\n"
                 % (dict(nsec), len(rows)))

# ------------------------------------------------------------ subject key --
def key_of(r):
    mask = val = 0
    for p in range(32):
        if r["bits"][p] is not None:
            mask |= 1 << p
            val |= r["bits"][p] << p
    cons = tuple(sorted((f["hi"], f["w"], f["con"]) for f in r["fields"] if f["con"]))
    return (mask, val, cons)

groups = defaultdict(list)
for r in rows:
    r["key"] = key_of(r)
    groups[r["key"]].append(r)

subjects, merged_away = [], 0
for k, g in groups.items():
    # rows that occupy the whole range: instruction rows and unconditional aliases
    whole = [r for r in g if r["type"] != "alias" or r["acond"] == "Unconditionally"]
    narrow = [r for r in g if r not in whole]
    if whole:
        whole.sort(key=lambda r: (r["type"] == "alias", r["enc"]))
        head = whole[0]
        head["spellings"] = sorted({r["mnem"] for r in whole})
        head["merged"] = sorted(r["enc"] for r in whole[1:])
        merged_away += len(whole) - 1
        subjects.append(head)
    for r in narrow:
        r["spellings"] = [r["mnem"]]
        r["merged"] = []
        subjects.append(r)
subjects.sort(key=lambda r: r["enc"])
sys.stderr.write("distinct encoding subjects %d (merged %d pure re-spellings)\n"
                 % (len(subjects), merged_away))

# -------------------------------------------------------------- represent --
def hx(w):
    return "".join("%02x" % ((w >> (8 * i)) & 0xFF) for i in range(4))

def batch(words):
    if not words:
        return {}
    p = subprocess.run([ISAX, "--isa=aarch64", "--batch"],
                       input="\n".join(hx(w) for w in words) + "\n",
                       capture_output=True, text=True)
    return {r["hex"]: r for r in csv.DictReader(p.stdout.splitlines(), delimiter="\t")}

def mn_of(rec):
    if rec is None or rec.get("l_ok") != "1":
        return None
    t = (rec.get("l_text") or "").split()
    return t[0].lower() if t else None

def ok_mn(r, got):
    if got is None:
        return False
    for want in r["spellings"]:
        if got == want:
            return True
        if want.endswith("cond") and got.startswith(want[:-4]):
            return True
        if got.startswith(want + ".") and got.split(".")[-1] in COND:
            return True
    return False

for r in subjects:
    r["word"] = fill(r["bits"], r["fields"])
res = batch([r["word"] for r in subjects])
for r in subjects:
    r["dec"] = res.get(hx(r["word"]))
    r["state"] = "exact" if ok_mn(r, mn_of(r["dec"])) else \
                 ("aliased" if mn_of(r["dec"]) else "nodecode")

rng = random.Random(20260822)
ATT = int(os.environ.get("ATTEMPTS", "400"))
todo = [r for r in subjects if r["state"] != "exact"]
for i in range(ATT):
    if not todo:
        break
    # four search strategies in rotation: free random (register fields never
    # 31, so a base opcode does not fall into its own SP/ZR alias); all 5-bit
    # fields tied to one value (reaches the Rn == Rm aliases: CINC, TST, NEG);
    # random including 31 (reaches the SP/ZR aliases); and zeroed immediates
    # with random registers (reaches MOV-from-ADD-#0 and friends).
    st = i % 4
    tie = rng.randrange(0, 31) if st == 1 else None
    cand = [(r, fill(r["bits"], r["fields"], rng=rng, tie=tie,
                     no31=(st != 2), zero_imm=(st == 3))) for r in todo]
    res = batch([w for _, w in cand])
    still = []
    for r, w in cand:
        rec = res.get(hx(w)); m = mn_of(rec)
        if ok_mn(r, m):
            r["word"], r["dec"], r["state"] = w, rec, "exact"
        else:
            if r["state"] == "nodecode" and m:
                r["word"], r["dec"], r["state"] = w, rec, "aliased"
            still.append(r)
    todo = still
sys.stderr.write("after mnemonic repair: %r\n" % dict(Counter(r["state"] for r in subjects)))

# ------------------------------------------------------------ de-collide ---
# Distinct subjects occupy distinct bit ranges, so distinct representatives
# must exist unless one range is wholly contained in the other's alias range.
for _ in range(int(os.environ.get("DECOL", "300"))):
    byhex = defaultdict(list)
    for r in subjects:
        byhex[r["word"]].append(r)
    clash = [g for g in byhex.values() if len(g) > 1]
    if not clash:
        break
    move = []
    for g in clash:
        g.sort(key=lambda r: (r["type"] == "alias", r["enc"]))
        move.extend(g[1:])
    st = rng.randrange(4)
    tie = rng.randrange(0, 31) if st == 1 else None
    cand = [(r, fill(r["bits"], r["fields"], rng=rng, tie=tie,
                     no31=(st != 2), zero_imm=(st == 3))) for r in move]
    res = batch([w for _, w in cand])
    taken = {r["word"] for r in subjects}
    for r, w in cand:
        rec = res.get(hx(w)); m = mn_of(rec)
        if w in taken or m is None:
            continue
        if r["state"] == "exact" and not ok_mn(r, m):
            continue
        r["word"], r["dec"] = w, rec
        if ok_mn(r, m):
            r["state"] = "exact"
        taken.add(w)
byhex = defaultdict(list)
for r in subjects:
    byhex[r["word"]].append(r)
resid = [g for g in byhex.values() if len(g) > 1]
sys.stderr.write("residual representative collisions: %d groups, %d rows\n"
                 % (len(resid), sum(len(g) for g in resid)))

# ---------------------------------------------------------------- verify ---
res = batch([r["word"] for r in subjects])
nl = nb = 0
for r in subjects:
    rec = res.get(hx(r["word"])); r["dec"] = rec
    nl += 1 if rec and rec.get("l_ok") == "1" else 0
    nb += 1 if rec and rec.get("b_ok") == "1" else 0
sys.stderr.write("verified: %d rows, LLVM decodes %d, Capstone decodes %d\n"
                 % (len(subjects), nl, nb))

os.makedirs(OUTD, exist_ok=True)
with open(os.path.join(OUTD, "opcodes.tsv"), "w") as f:
    w = csv.writer(f, delimiter="\t", lineterminator="\n")
    w.writerow(["opcode_id", "mnemonic", "hex", "source_table", "shape",
                "instr_class", "alias_of", "alias_cond", "spellings",
                "merged_respellings", "decodes", "llvm_disasm",
                "capstone_mnem", "asm_template", "xml_file"])
    for r in subjects:
        rec = r["dec"] or {}
        w.writerow([r["enc"], r["mnem"], hx(r["word"]),
                    "MRA:ISA_A64_xml_A_profile-2022-12" +
                    ("/alias" if r["type"] == "alias" else ""),
                    r["label"] or ("alias" if r["type"] == "alias" else "base"),
                    r["class"], r["base"] if r["type"] == "alias" else "",
                    r["acond"] if r["type"] == "alias" else "",
                    ",".join(r["spellings"]), ",".join(r["merged"]),
                    {"exact": "yes", "aliased": "yes-other-spelling",
                     "nodecode": "NO"}[r["state"]],
                    (rec.get("l_text") or "").strip(), rec.get("b_mnem") or "",
                    r["asm"], r["file"]])
sys.stderr.write("wrote %s/opcodes.tsv  rows=%d\n" % (OUTD, len(subjects)))
