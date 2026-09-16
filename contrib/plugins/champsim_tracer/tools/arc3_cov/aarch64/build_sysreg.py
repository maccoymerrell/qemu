#!/usr/bin/env python
"""Supplementary axis: the MRS/MSR(register) SYSTEM-REGISTER OPERAND space.

Per ruling C3 a register field is GENERIC, so `MRS <Xt>, <systemreg>` is ONE
opcode in the denominator (it is one named MRA encoding, MRS_RS_systemmove).
The system-register selector is a 16-bit register *field*, not an opcode
field.  It is enumerated here anyway, from the rank-1 SysReg XML of the same
MRA release, because the destination/source IDENTITY differs per selector and
that is what the fields layer has to get right.  This file is NOT added to
the opcode denominator; it is the operand-value census behind two of its rows.
"""
import os, sys, csv, glob, subprocess
import xml.etree.ElementTree as ET

REF, OUT = sys.argv[1], sys.argv[2]
ISAX = "/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck"

rows = []
pages = accessor_pages = 0
for path in sorted(glob.glob(os.path.join(REF, "AArch64-*.xml"))):
    try:
        root = ET.parse(path).getroot()
    except Exception:
        continue
    if root.tag != "register_page":
        pass
    regs = list(root.iter("register"))
    if not regs:
        continue
    pages += 1
    had = False
    for reg in regs:
        rname = (reg.findtext("reg_short_name") or reg.findtext("name") or "").strip()
        for am in reg.iter("access_mechanism"):
            if am.get("type") != "SystemAccessor":
                continue
            acc = am.get("accessor") or ""
            enc = am.find("encoding")
            if enc is None:
                continue
            e = {c.get("n"): c.get("v") for c in enc.findall("enc")}
            if not all(k in e for k in ("op0", "op1", "CRn", "CRm", "op2")):
                continue
            def b(x):
                # register ARRAYS (AMEVCNTR0<n>, ICH_LR<n>_EL2, ...) leave the
                # index bits variable; 0 is the representative member.
                x = x.replace("0b", "")
                # array indices appear as `x` or as a spliced expression
                # (`010:m[3]`); 0 is the representative member either way.
                out = ""
                i = 0
                while i < len(x):
                    if x[i] in "01":
                        out += x[i]; i += 1
                    elif x[i] == "x":
                        out += "0"; i += 1
                    elif x[i] == ":":
                        i += 1
                    else:                      # `m[3]`, `n[2:0]`, ...
                        j = x.find("]", i)
                        tok = x[i:j + 1] if j >= 0 else x[i:]
                        if "[" in tok and ":" in tok:
                            a, bb = tok[tok.index("[") + 1:-1].split(":")
                            out += "0" * (int(a) - int(bb) + 1)
                        else:
                            out += "0"
                        i = (j + 1) if j >= 0 else len(x)
                return int(out, 2) if out else 0
            op0, op1, crn, crm, op2 = (b(e["op0"]), b(e["op1"]), b(e["CRn"]),
                                       b(e["CRm"]), b(e["op2"]))
            if acc.startswith("MRS"):
                L, mn = 1, "mrs"
            elif acc.startswith("MSR"):
                L, mn = 0, "msr"
            else:
                continue
            had = True
            w = (0xD5 << 24) | (L << 21) | (op0 << 19) | (op1 << 16) | \
                (crn << 12) | (crm << 8) | (op2 << 5) | 2
            target = acc.split(None, 1)[1] if " " in acc else rname
            rows.append({"acc": acc, "mn": mn, "reg": target, "w": w,
                         "file": os.path.basename(path)})
    accessor_pages += 1 if had else 0

def hx(w):
    return "".join("%02x" % ((w >> (8 * i)) & 0xFF) for i in range(4))

seen, uniq = set(), []
for r in rows:
    k = (r["mn"], r["w"])
    if k in seen:
        continue
    seen.add(k); uniq.append(r)

p = subprocess.run([ISAX, "--isa=aarch64", "--batch"],
                   input="\n".join(hx(r["w"]) for r in uniq) + "\n",
                   capture_output=True, text=True)
dec = {x["hex"]: x for x in csv.DictReader(p.stdout.splitlines(), delimiter="\t")}
nl = nb = 0
with open(OUT, "w") as f:
    w = csv.writer(f, delimiter="\t", lineterminator="\n")
    w.writerow(["accessor_id", "mnemonic", "hex", "source_table", "sysreg",
                "llvm_decodes", "capstone_decodes", "llvm_disasm", "xml_file"])
    for r in uniq:
        d = dec.get(hx(r["w"]), {})
        nl += 1 if d.get("l_ok") == "1" else 0
        nb += 1 if d.get("b_ok") == "1" else 0
        w.writerow([r["acc"].replace(" ", "_"), r["mn"], hx(r["w"]),
                    "MRA:SysReg_xml_A_profile-2022-12", r["reg"],
                    d.get("l_ok", "0"), d.get("b_ok", "0"),
                    (d.get("l_text") or "").strip(), r["file"]])
sys.stderr.write("AArch64 register pages %d (accessor-bearing %d); distinct "
                 "MRS/MSR accessor encodings %d; LLVM decodes %d, Capstone %d\n"
                 % (pages, accessor_pages, len(uniq), nl, nb))
