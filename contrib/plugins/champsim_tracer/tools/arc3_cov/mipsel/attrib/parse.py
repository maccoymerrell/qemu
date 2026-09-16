#!/usr/bin/env python
"""Parse the three probe outputs into per-opcode operand sets."""
import os, re, json, sys, collections

BASE = os.environ.get("CST_ARC3_ATTRIB_DIR", os.getcwd()).rstrip("/") + "/"


# ---------------------------------------------------------------- probe
# THE TRACER ARM IS RE-PROBED HERE, NOT READ FROM WHATEVER IS ON DISK.
#
# `tracer_raw.txt` used to be produced by hand and consumed by
# parse_tracer() below, while the documented reproduce block wrote
# `batch_tip.tsv` -- which nothing read.  A reproduction from the tree
# therefore scored the CURRENT reference against whichever tracer snapshot
# happened to be lying in the run directory, and reported the difference as
# a tracer defect: measured 2026-08-23, a HEAD tracer against a snapshot
# taken 19.5 hours earlier turned 977/977 into 676/301, with the 189 FP
# rows that gained REG_FCSR at the top of the signature list.  An arm that
# cannot go stale is the only kind worth quoting, so the probe runs here.
ISAXCHECK = os.environ.get(
    "CST_ISAXCHECK",
    "/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck")


def probe_tracer(path):
    """Decode every opcode's representative encoding with the tracer's own
    fields layer and write the `== id hex` blocks parse_tracer() consumes."""
    import subprocess
    src = BASE + "../opcodes.tsv"
    rows = []
    with open(src) as f:
        next(f)
        for line in f:
            c = line.rstrip("\n").split("\t")
            if len(c) >= 3:
                rows.append((c[0], c[2]))
    if not rows:
        sys.exit("probe_tracer: %s carries no opcode rows" % src)
    with open(path, "w") as out:
        for oid, hexs in rows:
            p = subprocess.run([ISAXCHECK, "--isa=mipsel", "--layer=fields",
                                "--hex=" + hexs],
                               capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit("probe_tracer: %s --hex=%s rc=%d: %s"
                         % (ISAXCHECK, hexs, p.returncode, p.stderr[-500:]))
            out.write("== %s %s\n" % (oid, hexs))
            out.write(p.stdout)
    print("probed %d encodings with %s" % (len(rows), ISAXCHECK))

# ---------------------------------------------------------------- LLVM
def parse_llvm(path):
    out = {}
    cur = None
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("# "):
            continue
        if line.startswith("== "):
            _, name, word = line.split()
            cur = dict(id=name, word=word, opcode=None, asm=None, ops=[], dsc=[],
                       impuse=[], impdef=[], numdefs=None, flags={})
            out[name] = cur
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"opcode\s+(\S+)$", s)
        if m: cur["opcode"] = m.group(1); continue
        m = re.match(r"asm\s+(.*)$", s)
        if m: cur["asm"] = m.group(1).strip(); continue
        m = re.match(r"flags\s+(.*)$", s)
        if m:
            for kv in m.group(1).split():
                k, v = kv.split("=")
                cur["flags"][k] = int(v)
            cur["numdefs"] = cur["flags"].get("numdefs")
            continue
        m = re.match(r"op\[(\d+)\]\s+(\S+)\s+(reg|imm|other)\s*(\S*)(.*)$", s)
        if m:
            idx = int(m.group(1)); role = m.group(2); kind = m.group(3)
            val = m.group(4); rest = m.group(5)
            tied = None
            mt = re.search(r"tied_to=(\d+)", rest + " " + val)
            if mt: tied = int(mt.group(1))
            cur["ops"].append(dict(i=idx, role=role, kind=kind, val=val, tied=tied))
            continue
        m = re.match(r"dsc\[(\d+)\]\s+(\S+)\s+rc=(-?\d+)(.*)$", s)
        if m:
            idx = int(m.group(1)); role = m.group(2); rc = int(m.group(3)); rest = m.group(4)
            tied = None
            mt = re.search(r"TIED_TO=(\d+)", rest)
            if mt: tied = int(mt.group(1))
            cur["dsc"].append(dict(i=idx, role=role, rc=rc, tied=tied,
                                   materialised="NOT MATERIALISED" not in rest))
            continue
        m = re.match(r"impUSE\s+(.*)$", s)
        if m:
            v = m.group(1).strip()
            cur["impuse"] = [] if v == "(none)" else [x.split("{")[0] for x in v.split()]
            continue
        m = re.match(r"impDEF\s+(.*)$", s)
        if m:
            v = m.group(1).strip()
            cur["impdef"] = [] if v == "(none)" else [x.split("{")[0] for x in v.split()]
            continue
    return out

# ---------------------------------------------------------------- binutils
def parse_bu(path):
    out = {}
    cur = None
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("# "): continue
        if line.startswith("== "):
            _, name, word = line.split()
            cur = dict(id=name, rows=[])
            out[name] = cur
            continue
        if cur is None: continue
        s = line.strip()
        m = re.match(r"(hit|alt)\s+row\[(\d+)\]\s+(\S+)\s+args=\"([^\"]*)\"\s+match=(\S+)\s+mask=(\S+)$", s)
        if m:
            cur["rows"].append(dict(kind=m.group(1), row=int(m.group(2)), name=m.group(3),
                                    args=m.group(4), match=m.group(5), mask=m.group(6),
                                    pinfo=[], pinfo2=[]))
            continue
        m = re.match(r"pinfo\s*:\s*(.*)$", s)
        if m and cur["rows"]:
            v = m.group(1).strip()
            cur["rows"][-1]["pinfo"] = [] if v == "(none)" else v.split()
            continue
        m = re.match(r"pinfo2:\s*(.*)$", s)
        if m and cur["rows"]:
            v = m.group(1).strip()
            cur["rows"][-1]["pinfo2"] = [] if v == "(none)" else v.split()
            continue
    return out

# ---------------------------------------------------------------- tracer
def parse_tracer(path):
    out = {}
    cur = None
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("== "):
            _, name, hexs = line.split()
            cur = dict(id=name, hex=hexs, src=[], dst=[], b_rd=[], b_wr=[],
                       gen_rd=[], gen_wr=[], opcode=None, branch=None,
                       loads=None, stores=None, mnem=None, ops=None,
                       l_rd=[], l_wr=[])
            out[name] = cur
            continue
        if cur is None: continue
        s = line.strip()
        m = re.match(r"boundary ok=(\d) sz=(\d+)\s+(\S+)\s*(.*)$", s)
        if m: cur["mnem"] = m.group(3); cur["ops"] = m.group(4); cur["sect"] = "b"; continue
        if s.startswith("llvm     ok="):
            cur["sect"] = "l"; continue
        m = re.match(r"fields   ok=(\d)\s+(\S+)\s+(\S+)(.*)$", s)
        if m:
            cur["opcode"] = m.group(2); cur["branch"] = m.group(3)
            cur["sect"] = "f"; continue
        if s.startswith("boundary-in-generic"):
            cur["sect"] = "g"; continue
        m = re.match(r"loads=(\d+) stores=(\d+)", s)
        if m: cur["loads"] = int(m.group(1)); cur["stores"] = int(m.group(2)); continue
        m = re.match(r"(RD|WR|SRC|DST)\{(.*)\}$", s)
        if m:
            tag = m.group(1)
            vals = [x for x in m.group(2).split(",") if x]
            sect = cur.get("sect")
            if tag == "SRC": cur["src"] = vals
            elif tag == "DST": cur["dst"] = vals
            elif sect == "b": cur["b_rd" if tag == "RD" else "b_wr"] = vals
            elif sect == "l": cur["l_rd" if tag == "RD" else "l_wr"] = vals
            elif sect == "g": cur["gen_rd" if tag == "RD" else "gen_wr"] = vals
            continue
    return out

if __name__ == "__main__":
    L = parse_llvm(BASE + "llvm_raw.txt")
    B = parse_bu(BASE + "bu_raw.txt")
    probe_tracer(BASE + "tracer_raw.txt")
    T = parse_tracer(BASE + "tracer_raw.txt")
    print("llvm=%d bu=%d tracer=%d" % (len(L), len(B), len(T)))
    ids = set(L) & set(B) & set(T)
    print("common=%d" % len(ids))
    json.dump(dict(llvm=L, bu=B, tracer=T), open(BASE + "parsed.json", "w"))
