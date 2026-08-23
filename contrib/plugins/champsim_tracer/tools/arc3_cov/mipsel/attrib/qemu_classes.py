#!/usr/bin/env python
"""
Derive, from QEMU's own MIPS source, the two instruction classes that no static
mipsel reference models: the COP1 instructions that update FCR31, and the MSA
instructions that update MSACSR.

This is the R6 leg of the reference.  Nothing here is transcribed: the class
membership is the set of helpers that reach update_fcr31() / update_msacsr(),
read out of the translator's own C.

Usage:  python qemu_classes.py [qemu-source-root]   (default: cwd)
Writes: qemu_fcr31_class.json, qemu_msacsr_helpers.txt into $CST_ARC3_ATTRIB_DIR
        (default: cwd).
"""
import os, re, sys, json

ROOT = (sys.argv[1] if len(sys.argv) > 1 else os.getcwd()).rstrip("/")
OUT = os.environ.get("CST_ARC3_ATTRIB_DIR", os.getcwd()).rstrip("/") + "/"


def function_bodies(text, name_re):
    """Map function name -> brace-balanced body, for every definition matching."""
    out = {}
    for m in re.finditer(name_re, text, re.M | re.S):
        name = m.group(1)
        i = text.find("{", m.start())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.setdefault(name, text[i:j])
    return out


def macro_bodies(text, name_re):
    """Map macro name -> its (line-continued) body."""
    out = {}
    for m in re.finditer(name_re, text, re.M):
        j = m.end()
        while j < len(text):
            nl = text.find("\n", j)
            if nl < 0:
                nl = len(text)
            if not text[j:nl].rstrip().endswith("\\"):
                break
            j = nl + 1
        out[m.group(1)] = text[m.end():nl]
    return out


# ---------------------------------------------------------------- COP1 / FCR31
fpu = open(ROOT + "/target/mips/tcg/fpu_helper.c").read()
F = function_bodies(fpu, r"^(?:[\w\* ]+?)\b(helper_\w+)\s*\(([^)]*)\)\s*\{")
upd = sorted(n for n, b in F.items() if "update_fcr31" in b)

# The c.cond.fmt / cmp.cond.fmt helpers are macro-generated; every FOP_COND_*
# and FOP_CONDN_* expansion calls update_fcr31, so the instantiation list is
# the class membership.
conds = set()
# Skip the "#define FOP_COND_D(op, cond)" lines themselves: only instantiations
# name a real condition.
for m in re.finditer(r"^(?!#define)\s*FOP_COND_(D|S|PS)\((\w+),", fpu, re.M):
    conds.add(("c", m.group(2), m.group(1).lower()))
for m in re.finditer(r"^(?!#define)\s*FOP_CONDN_(D|S)\((\w+),", fpu, re.M):
    conds.add(("cmp", m.group(2), m.group(1).lower()))

mn, prov = set(), {}
def add(mnem, src):
    mn.add(mnem); prov.setdefault(mnem, src)

for h in upd:
    b = h[len("helper_"):].replace("_2008_", "_")   # the nan2008 forms share a mnemonic
    for pat, fmt in (
        (r"float_cvtd_(\w+)",                 lambda g: "cvt.d." + g[0]),
        (r"float_cvts_(\w+)",                 lambda g: "cvt.s." + g[0]),
        (r"float_cvtps_pw",                   lambda g: "cvt.ps.pw"),
        (r"float_cvtpw_ps",                   lambda g: "cvt.pw.ps"),
        (r"float_(ceil|floor|round|trunc|cvt)_(w|l)_(s|d)", lambda g: "%s.%s.%s" % g),
        (r"float_(\w+)_(s|d|ps)",             lambda g: "%s.%s" % g),
    ):
        m = re.fullmatch(pat, b)
        if m:
            add(fmt(m.groups()), h)
            break
    else:
        print("UNMAPPED fpu helper:", h, file=sys.stderr)

for kind, c, f in conds:
    add(("c.%s.%s" if kind == "c" else "cmp.%s.%s") % (c, f),
        "FOP_COND%s_%s(%s)" % ("" if kind == "c" else "N", f.upper(), c))

json.dump({"fcr31_class": sorted(mn), "prov": prov},
          open(OUT + "qemu_fcr31_class.json", "w"), indent=1)

# --------------------------------------------------------------- MSA / MSACSR
msa = open(ROOT + "/target/mips/tcg/msa_helper.c").read()
G = function_bodies(msa, r"^(?:[A-Za-z_][\w\*\s]*?)\b(\w+)\s*\([^;{]*?\)\s*\{")
dirty_macros = {k for k, v in macro_bodies(msa, r"^#define\s+(MSA_\w+)\(").items()
                if "msacsr" in v}
dirty = {n for n, b in G.items()
         if "msacsr" in b or any(dm + "(" in b for dm in dirty_macros)}
# The compare helpers reach the macro through static compare_*() shims, so the
# seed set has to be closed over direct calls before it names the helpers.
changed = True
while changed:
    changed = False
    for n, b in G.items():
        if n in dirty:
            continue
        if any(c in dirty and c != n for c in set(re.findall(r"\b(\w+)\s*\(", b))):
            dirty.add(n); changed = True

helpers = sorted(x for x in dirty if x.startswith("helper_msa_"))
open(OUT + "qemu_msacsr_helpers.txt", "w").write("\n".join(helpers) + "\n")

print("fcr31 mnemonics: %d (from %d helpers + %d macro conditions)"
      % (len(mn), len(upd), len(conds)))
print("msa helpers reaching update_msacsr: %d" % len(helpers))
