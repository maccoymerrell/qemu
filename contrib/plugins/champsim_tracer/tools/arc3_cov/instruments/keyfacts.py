#!/usr/bin/env python3
"""Per-PC fact extraction from `cst_decode --format=raw`.

This is the one extractor the ARC-3 waves read; it supersedes the per-wave
copies keyfacts.py / keyfacts2.py / keyfacts3.py and keydst.py.

TWO OUTPUT SHAPES, both TSV `pc <tab> key <tab> colA <tab> colB`:

  --facts (default) -- the `.key` shape.
      DEPENDENCY families      RAW= (the wire mask word) and NAME= (resolved
                               through that template's own src_regs[] list,
                               its load slots and its immediate bit).  This
                               is the J3 key.
      IDENTITY facts           F_opcode, F_branch, F_length, F_slots,
                               F_depflags.  These are what the `mnem` control
                               arm must move: without them a zero in a
                               dependency row cannot be told apart from an
                               inert run.
      DICTIONARY facts         F_src, F_dst -- the register LISTS.  dst_dep[d]
                               belongs to dst[d] (#231/#232), so a mask read
                               without its list is read against the wrong
                               dictionary.
      #230 facts               F_immflag (CST_INSN_FLAG_HAS_IMM as published)
                               and `<fam>@shape` per slot -- the CLASS the
                               mask resolves to (REG / LOAD / IMM / EMPTY).
                               A slot naming no architectural register is the
                               #230 signature; nodep_census.py groups these.

  --dst -- the `.dkey` shape, keyed per destination REGISTER.
      `dst_dep[]` is an ARRAY with one mask per wire destination slot, and
      the slot list is the operand walk's.  Diffing the array reports
      movement whenever the WALK's destination list changes, which under an
      access-flag mutation is nearly every instruction; that movement swamps
      and hides whatever the masks themselves did.  Measured, the array key
      overstated by 219x (#231).  So each row here is
      (pc, dst_dep@<REG>) -> the inputs that destination's mask resolves to.

Run with --selftest to check the extractor against planted defects.
"""
import argparse
import re
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _arc3lib as L  # noqa: E402

RE_INSN = re.compile(
    r'insn\[(\d+)\] pc=(0x[0-9a-f]+)\s+pc_delta=\d+\s+opcode=(\d+)'
    r'(?: \((\w+)\)\s+branch_type=(\d+) \((\w+)\))?')
RE_FLAGS = re.compile(r'flags=(0x[0-9a-f]+) \(([^)]*)\)\s+n_src=(\d+)\s+n_dst=(\d+)')
RE_SRC = re.compile(r'src=\[(.*?)\]\s+dst=\[(.*?)\]')
RE_MDL = re.compile(r'max_dep_loads=(\d+)\s+max_dep_stores=(\d+)')
RE_LEN = re.compile(r'insn_size=(\d+)')
RE_MASK = re.compile(r'(dst_dep|store_data_dep|load_addr_dep|store_addr_dep)=\[(.*?)\]')
RE_DBF = re.compile(r'dep_block flags=(0x[0-9a-f]+)')
RE_REG = re.compile(r'\d+ \((\w+)\)')


def names(mask, src, nloads):
    """Which inputs a mask names, through this template's own dictionary."""
    out = [r for i, r in enumerate(src) if mask & (1 << i)]
    out += ["LOAD%d" % k for k in range(nloads)
            if mask & (1 << (len(src) + k))]
    if mask & (1 << (len(src) + nloads)):
        out.append("IMM")
    return ",".join(out) if out else "-"


def shape(mask, src, nloads):
    """The CLASS of a resolved slot: which KINDS of input, not which ones."""
    parts = []
    if any(mask & (1 << i) for i in range(len(src))):
        parts.append("REG")
    if any(mask & (1 << (len(src) + k)) for k in range(nloads)):
        parts.append("LOAD")
    if mask & (1 << (len(src) + nloads)):
        parts.append("IMM")
    return "+".join(parts) if parts else "EMPTY"


def extract(stream, dst_mode=False):
    """Parse a raw decode into the fact rows.  Returns {(pc, key): (a, b)}."""
    pc = None
    src, dst = [], []
    mdl = 0
    rows = {}
    for line in stream:
        m = RE_INSN.search(line)
        if m:
            pc = m.group(2)
            src, dst, mdl = [], [], 0
            if not dst_mode:
                if m.group(4):
                    rows.setdefault((pc, "F_opcode"), ("V=%s" % m.group(4), "-"))
                if m.group(6):
                    rows.setdefault((pc, "F_branch"), ("V=%s" % m.group(6), "-"))
            continue
        m = RE_FLAGS.search(line)
        if m and pc and not dst_mode:
            rows.setdefault((pc, "F_immflag"),
                            ("V=%d" % (1 if "CST_INSN_FLAG_HAS_IMM" in m.group(2)
                                       else 0), "-"))
            continue
        m = RE_SRC.search(line)
        if m:
            src = RE_REG.findall(m.group(1))
            dst = RE_REG.findall(m.group(2))
            if pc and not dst_mode:
                rows.setdefault((pc, "F_src"), ("V=%s" % ",".join(src), "-"))
                rows.setdefault((pc, "F_dst"), ("V=%s" % ",".join(dst), "-"))
            continue
        m = RE_MDL.search(line)
        if m:
            mdl = int(m.group(1))
            if pc and not dst_mode:
                rows.setdefault((pc, "F_slots"),
                                ("V=%s/%s" % (m.group(1), m.group(2)), "-"))
                ml = RE_LEN.search(line)
                if ml:
                    rows.setdefault((pc, "F_length"), ("V=%s" % ml.group(1), "-"))
            continue
        m = RE_DBF.search(line)
        if m and pc and not dst_mode:
            rows.setdefault((pc, "F_depflags"), ("V=%s" % m.group(1), "-"))
            continue
        m = RE_MASK.search(line)
        if m and pc:
            fam = m.group(1)
            vals = [v.strip() for v in m.group(2).split(",") if v.strip()]
            nloads = 0 if fam.endswith("addr_dep") else mdl
            if dst_mode:
                if fam != "dst_dep":
                    continue
                for i, v in enumerate(vals):
                    # THE KEY IS THE DESTINATION REGISTER, never the slot
                    # index.  SLOT%d is the honest fallback when the wire
                    # published more masks than the list names -- it is
                    # itself a finding, not a key to score silently.
                    reg = dst[i] if i < len(dst) else "SLOT%d" % i
                    rows.setdefault((pc, "dst_dep@" + reg),
                                    ("N=" + names(int(v, 16), src, nloads),
                                     "R=" + v))
                continue
            rows.setdefault((pc, fam),
                            ("RAW=" + " ".join(vals),
                             "NAME=" + " | ".join(
                                 names(int(v, 16), src, nloads) for v in vals)))
            rows.setdefault((pc, fam + "@shape"),
                            ("V=" + " | ".join(
                                shape(int(v, 16), src, nloads) for v in vals),
                             "-"))
    return rows


# --------------------------------------------------------------------------
# selftest

SAMPLE = """\
insn[0] pc=0x401000 pc_delta=0 opcode=17 (OP_ADD) branch_type=0 (BRANCH_NOT)
  flags=0x5 (CST_INSN_FLAG_HAS_IMM|CST_INSN_FLAG_X) n_src=2 n_dst=2
  src=[3 (rcx), 7 (rdx)] dst=[1 (rbx), 0 (rax)]
  max_dep_loads=1 max_dep_stores=0 insn_size=4
  dep_block flags=0x2
  dst_dep=[0x1, 0x8]
  store_data_dep=[0x8]
  load_addr_dep=[0x2]
"""
# Same instruction, destination LIST reversed and nothing else changed.  A
# per-slot key calls this "unchanged"; a per-register key calls it moved.
SAMPLE_SWAPPED_DST = SAMPLE.replace("dst=[1 (rbx), 0 (rax)]",
                                    "dst=[0 (rax), 1 (rbx)]")


def selftest():
    checks = []
    rows = extract(SAMPLE.splitlines(True))

    # LIVENESS.  An extractor that returns nothing passes every "no
    # difference" test ever written, so prove it produces rows first.
    checks.append(("liveness: the extractor produces rows at all",
                   len(rows) > 0, "rows=%d" % len(rows)))

    # VACUITY.  Empty input must produce nothing -- and the caller's
    # require_subject() is what turns that into a failure, not a silent zero.
    empty = extract([])
    checks.append(("vacuity: empty input yields 0 rows (caller must fail)",
                   empty == {}, "rows=%d" % len(empty)))
    reasons = []
    L.require_subject(empty, "planted empty arm", reasons)
    checks.append(("vacuity: require_subject() names an empty arm",
                   len(reasons) == 1 and "VACUITY" in reasons[0],
                   reasons[0].split("--")[0].strip() if reasons else "no reason"))

    # IDENTITY facts present -- the live control's subjects.
    for fact, want in (("F_opcode", "V=OP_ADD"), ("F_branch", "V=BRANCH_NOT"),
                       ("F_length", "V=4"), ("F_slots", "V=1/0"),
                       ("F_depflags", "V=0x2"), ("F_immflag", "V=1"),
                       ("F_src", "V=rcx,rdx"), ("F_dst", "V=rbx,rax")):
        got = rows.get(("0x401000", fact), ("<missing>",))[0]
        checks.append(("identity fact %s" % fact, got == want,
                       "got %s want %s" % (got, want)))

    # MASK RESOLUTION through the template's own dictionary: bit0=rcx,
    # bit1=rdx, bit2=LOAD0, bit3=IMM.
    got = rows.get(("0x401000", "dst_dep"), ("", ""))[1]
    checks.append(("dst_dep resolves through src_regs[]/loads/imm",
                   got == "NAME=rcx | IMM", "got %r" % got))
    got = rows.get(("0x401000", "store_data_dep@shape"), ("",))[0]
    checks.append(("@shape reports the CLASS (the #230 signature)",
                   got == "V=IMM", "got %r" % got))
    got = rows.get(("0x401000", "load_addr_dep"), ("", ""))[1]
    checks.append(("addr families exclude load slots from the dictionary",
                   got == "NAME=rdx", "got %r" % got))

    # PLANTED DEFECT: the WRONG KEY.  --dst must key per destination
    # REGISTER.  Reversing the destination list moves both rows; a
    # slot-indexed key would report no movement at all.
    d1 = extract(SAMPLE.splitlines(True), dst_mode=True)
    d2 = extract(SAMPLE_SWAPPED_DST.splitlines(True), dst_mode=True)
    checks.append(("--dst keys per destination REGISTER, not slot",
                   set(k[1] for k in d1) == {"dst_dep@rbx", "dst_dep@rax"},
                   "keys=%s" % sorted(k[1] for k in d1)))
    moved = sum(1 for k in d1 if d2.get(k) != d1[k])
    checks.append(("planted wrong-key defect: reversed dst list MOVES rows",
                   moved == 2, "moved=%d of %d (a slot key reports 0)"
                   % (moved, len(d1))))
    checks.append(("--dst emits only the dst family",
                   all(k[1].startswith("dst_dep@") for k in d1),
                   "keys=%s" % sorted(set(k[1] for k in d1))))

    return L.selftest_report("keyfacts.py", checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dst", action="store_true",
                    help="emit the .dkey shape, keyed per destination REGISTER")
    ap.add_argument("--selftest", action="store_true",
                    help="check the extractor against planted defects and exit")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    rows = extract(sys.stdin, dst_mode=args.dst)
    sys.stdout.write(L.tsv(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
