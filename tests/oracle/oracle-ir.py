"""Turn the oracle's IR walk into per-instruction read and write sets, and
compare them with the ones the tracer derives from Capstone.

The oracle reports what it read off the raw TCG op stream: an offset into
CPUArchState, a direction, and the op that named it.  Three things have to
happen before that is comparable with a decoder's answer.

1.  An offset no TCG global covers has to be named.  That is the same DWARF
    layout map ``oracle-interpret.py`` already builds, and this reuses it
    rather than repeating it.

2.  An emulation field has to be mapped to the architectural register it
    stands for.  On x86 that is the whole lazy-flags scheme: ``add`` does not
    store EFLAGS, it stores its operands in ``cc_src``/``cc_dst`` and leaves a
    note in ``cc_op`` saying how to compute the flags if anyone asks.  The
    flags are written -- the architecture says so -- and deferring the
    computation is an emulation shortcut.  So a write to any of those fields
    is a write to EFLAGS, and none of them is a register a consumer should
    schedule on.

    That mapping is also what makes the answer context-independent.  The x86
    translator elides the store to ``cc_op`` when the preceding instruction
    already left it right, so the raw op stream for one pc genuinely depends
    on its neighbour.  Once every arm of the lazy-flags representation maps to
    the one register it represents, the elision stops being visible.

3.  The two sides have to speak one vocabulary.  The tracer's is
    ``GenericRegId``, and the mapping from a QEMU register name to it is
    already written down, per ISA, in the generated mnemonic tables -- so it
    is read from there instead of being restated here.

Usage:

    python3 tests/oracle/oracle-ir.py report.oracle --build-dir build-oracle
    python3 tests/oracle/oracle-ir.py report.oracle --compare ./prog

Copyright (c) 2026 Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import collections
import importlib.util
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def _load_interpret():
    """Import oracle-interpret.py for its layout machinery."""
    path = os.path.join(HERE, "oracle-interpret.py")
    spec = importlib.util.spec_from_file_location("oracle_interpret", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


OI = _load_interpret()


class _ArchOpts(object):
    """The knobs OI.arch_name() consults; vlenb is RISC-V's vector length."""
    vlenb = 16


_ARCH_OPTS = _ArchOpts()


# ---------------------------------------------------------------------------
# The emulation-field -> architectural-register map
# ---------------------------------------------------------------------------
#
# Every entry here is a statement about how QEMU represents a register, not
# about any one instruction.  That is the line this file must not cross: a
# per-instruction correction would be the hand-written table the whole
# exercise exists to get rid of.

ARCH_ALIAS = {
    "x86_64": {
        # The lazy-flags representation.  cc_src/cc_dst/cc_src2 hold the
        # operands the flags are computed from, so storing one of them is the
        # flag write, deferred.
        "cc_src": "eflags",
        "cc_dst": "eflags",
        "cc_src2": "eflags",
        # The bits that are not lazy: DF and the system bits live in the
        # eflags word itself.
        "eflags": "eflags",
        "df": "eflags",
        # cc_op is the discriminant, and it is not symmetric.
        #
        # Reading it is part of reading the flags: with CC_OP_DYNAMIC the
        # computation has to ask which rule applies, so a read of the tag is a
        # read of the value.
        #
        # Writing it, on its own, is not a flag write at all -- and the
        # measurement is what says so.  gen_update_cc_op() stores cc_op when
        # s->cc_op_dirty, that is, when some *earlier* instruction changed the
        # flag representation and has not spilled the tag yet.  The store lands
        # on whichever instruction next does something that could observe env.
        # So it is a previous instruction's bookkeeping arriving late, and it
        # is the one thing in the whole x86 walk whose presence depends on the
        # neighbouring instruction: of 7761 pcs, the only four whose access set
        # changed between two translations changed by exactly this store and
        # nothing else.
        #
        # It is dropped, and --variance counts what that costs: on the measured
        # corpus 1229 pcs store cc_op and 1135 of them have no cc_src/cc_dst
        # store to witness the flag write instead.  That number is large and it
        # is not a loss, because those 1135 are the instructions gen_update_cc_op
        # fires in front of -- calls, jumps, returns, faulting memory accesses --
        # and none of them writes EFLAGS.  Treating a lone cc_op store as a flag
        # write would put a phantom EFLAGS destination on every CALL in the
        # program.  --compare is the check that settles it against a decoder
        # that has no lazy flags to confuse it.
        "cc_op": "@ccop",
        # A segment override reaches the address through the segment's cached
        # base, which is the TCG global; the segment register itself is never
        # read in 64-bit mode because nothing but FS and GS has a live base.
        # The access is the same access, so it gets the same name as the
        # register a decoder would call it.
        "es_base": "es",
        "cs_base": "cs",
        "ss_base": "ss",
        "ds_base": "ds",
        "fs_base": "fs",
        "gs_base": "gs",
    },
}

# Fields that are QEMU's bookkeeping and not guest architectural state at all.
NOT_ARCHITECTURAL = {
    "x86_64": ("xmm_t0", "mmx_t0", "tmp0", "tmp4", "cc_tmp", "exception_",
               "error_code", "hflags", "can_do_io", "current_tb"),
}


def arch_field(target, layout, name, off, size, globals_map=None):
    """Name the architectural register an oracle record refers to."""
    alias = ARCH_ALIAS.get(target, {})
    if name == "?" and globals_map:
        # The report carries the target's own offset -> register map in its G
        # lines.  A record that arrived without a name -- the helper interior
        # reports byte offsets, because a page fault has no idea what it hit --
        # gets the same name any other record at that offset would have.
        name = globals_map.get(off) or "?"
    if name != "?" and name in alias:
        return alias[name]
    if name != "?":
        return name

    field = OI.containing(layout, off, size)
    if field is None:
        return "raw@%d" % off
    path = field["path"]
    for bad in NOT_ARCHITECTURAL.get(target, ()):
        if bad in path:
            return None
    root = path.split(".")[0].split("[")[0]
    if root in alias:
        return alias[root]

    # The field-path -> architectural-register step is per target and is
    # already written down once, in oracle-interpret.py.  Repeating the x86
    # half of it here is how the two would drift, so it is asked for instead.
    name, _note = OI.arch_name(target, layout, field, off, size, _ARCH_OPTS)
    if name:
        return name
    return path.split(".")[0]


# ---------------------------------------------------------------------------
# The tracer's vocabulary, read from its own generated tables
# ---------------------------------------------------------------------------

ROW_RE = re.compile(
    r"\[\w+_REG_\w+\]\s*=\s*\{\s*\.reg_id\s*=\s*(\w+).*?\.name\s*=\s*\"([^\"]*)\"")


def load_generic_ids(isa_header):
    """QEMU register name -> GenericRegId, from the generated table.

    A name can appear on several rows (every width view of a GPR carries the
    same 64-bit name); they all agree on the id, which is the point.
    """
    out = {}
    with open(isa_header) as fh:
        for m in ROW_RE.finditer(fh.read()):
            rid, name = m.group(1), m.group(2)
            if name:
                out.setdefault(name, rid)
    return out


# QEMU's own segment ordering, target/i386/cpu.h R_ES..R_GS.  oracle-interpret
# names a descriptor-cache field by its index -- segs[1] is "seg1" -- while the
# tracer's vocabulary is the gdb register name, "cs".  Two names for one
# register is not a disagreement about dataflow, so the index is spelled out
# here rather than left to the catch-all below.
SEG_ORDER = {
    "x86_64": ("es", "cs", "ss", "ds", "fs", "gs"),
}

SEG_RE = re.compile(r"seg(\d+)$")


def to_generic(name, gmap, isa=None):
    if name is None:
        return None
    if name in gmap:
        return gmap[name]
    m = SEG_RE.match(name)
    if m:
        order = SEG_ORDER.get(isa, ())
        idx = int(m.group(1))
        if idx < len(order) and order[idx] in gmap:
            return gmap[order[idx]]
    if name.startswith("seg"):
        # A segment register the index above could not place.  It stays
        # distinct from every named one so it can never match by accident.
        return "REG_SEG?"
    return name


# ---------------------------------------------------------------------------
# Parsing the report
# ---------------------------------------------------------------------------

D_RE = re.compile(r"^D (0x[0-9a-f]+) ([rwkp]) "
                  r"(?:reg=(\S+) off=(-?\d+) size=(\d+)|mem) (.*)$")
FROM_RE = re.compile(r"from=(\S+)")

# The fields that between them represent one register.  A store into any of
# them whose value came only from others in the same group has not changed the
# register -- it has re-encoded it.
ALIAS_GROUP = {
    "x86_64": {"eflags": {"cc_op", "cc_src", "cc_dst", "cc_src2",
                          "eflags", "df"}},
}
A_RE = re.compile(r"^A (0x[0-9a-f]+) ops=(\d+) calls=(\d+) opaque=(\d+)")
C_RE = re.compile(r"^C (0x[0-9a-f]+) helper=(\S+) flags=0x([0-9a-f]+)")
# CP5: what the helper interior touched, from the protection window.
Y_RE = re.compile(r"^Y (0x[0-9a-f]+) ([rw]) off=(\d+) size=(\d+) helper=(\S+)")
Z_RE = re.compile(r"^Z (0x[0-9a-f]+) ir-set-diverged")
W_RE = re.compile(r"^W (0x[0-9a-f]+) (?:reg=(\S+) off=(-?\d+) size=(\d+)|"
                  r"raw off=(\d+) size=(\d+))")


class Insn(object):
    def __init__(self, pc):
        self.pc = pc
        self.r = set()
        self.w = set()
        self.k = set()
        self.p = set()
        self.mem_r = 0
        self.mem_w = 0
        self.helpers = []
        self.ops = 0
        self.diverged = 0
        self.diff_w = set()          # what the runtime differ saw change
        self.ccop_w = 0              # lone cc_op stores, see ARCH_ALIAS
        self.inside = 0              # accesses recovered from inside a helper
        self.opaque = 0              # ops the walk DECLINED to answer for
        self.reenc = {}              # writes that only re-encoded a register
        self.variants = []           # one (r, w) per translation of this pc


G_RE = re.compile(r"^G\s+(-?\d+)\s+(\d+)\s+(\S+)")


def parse(path, target, layout):
    insns = collections.OrderedDict()
    seen_target = target
    cur_r, cur_w = set(), set()
    gmap = {}

    def get(pc):
        if pc not in insns:
            insns[pc] = Insn(pc)
        return insns[pc]

    with open(path) as fh:
        for line in fh:
            if line.startswith("T target="):
                seen_target = line.split("target=")[1].split()[0]
            m = G_RE.match(line)
            if m:
                off, size, nm = int(m.group(1)), int(m.group(2)), m.group(3)
                for b in range(off, off + size):
                    gmap[b] = nm
                continue
            m = A_RE.match(line)
            if m:
                i = get(int(m.group(1), 16))
                i.ops = int(m.group(2))
                i.opaque += int(m.group(4))
                # An A line ends one translation of this pc.  Keeping the
                # variants apart is what makes it possible to say whether the
                # *architectural* set moved when the op stream did.
                i.variants.append((frozenset(cur_r), frozenset(cur_w)))
                cur_r, cur_w = set(), set()
                continue
            m = C_RE.match(line)
            if m:
                get(int(m.group(1), 16)).helpers.append(m.group(2))
                continue
            m = Y_RE.match(line)
            if m:
                # The helper's interior, measured rather than declared.  It is
                # the same access the IR walk would have reported had the call
                # not been opaque, so it goes in the same set -- and it is the
                # only source of a *read* inside a helper there is.
                i = get(int(m.group(1), 16))
                nm = arch_field(seen_target, layout, "?",
                                int(m.group(3)), int(m.group(4)), gmap)
                if nm == "@ccop":
                    nm = "eflags" if m.group(2) == "r" else None
                if nm:
                    (i.r if m.group(2) == "r" else i.w).add(nm)
                    i.inside += 1
                continue
            m = Z_RE.match(line)
            if m:
                get(int(m.group(1), 16)).diverged += 1
                continue
            m = W_RE.match(line)
            if m and not line.startswith("W 0x0"):
                i = get(int(m.group(1), 16))
                if m.group(2):
                    nm = arch_field(seen_target, layout, m.group(2),
                                    int(m.group(3)), int(m.group(4)))
                else:
                    nm = arch_field(seen_target, layout, "?",
                                    int(m.group(5)), int(m.group(6)))
                if nm:
                    i.diff_w.add(nm)
                continue
            m = D_RE.match(line)
            if not m:
                continue
            pc = int(m.group(1), 16)
            rw = m.group(2)
            i = get(pc)
            if m.group(3) is None:
                if rw == "r":
                    i.mem_r += 1
                else:
                    i.mem_w += 1
                continue
            nm = arch_field(seen_target, layout, m.group(3),
                            int(m.group(4)), int(m.group(5)))
            if nm is None:
                continue
            if rw == "w" and nm in ALIAS_GROUP.get(seen_target, {}):
                # gen_compute_eflags() converts the lazy representation to the
                # eager one by storing into cc_src a value it computed out of
                # cc_op/cc_src/cc_dst.  The register is unchanged; only where
                # it is kept has changed.  Without this, every conditional
                # branch in the program writes EFLAGS.
                #
                # An empty provenance is a constant and is a real write -- the
                # zeroing idiom stores a constant into cc_src and does define
                # the flags.
                fm = FROM_RE.search(line)
                src = set((fm.group(1) if fm else "-").split(",")) - {"-", "+"}
                # Provenance arrives in two vocabularies: a TCG global by
                # name, and an env byte range as "@offset" for state no global
                # covers.  The alias groups are written in architectural
                # names, so the offsets have to be resolved into the same
                # vocabulary before the comparison -- otherwise a value that
                # came from eflags-the-env-field does not match
                # eflags-the-group and a re-encoding reads as a write.  This
                # is the same one-question-two-vocabularies problem the
                # extractor had between its register classes, surfacing a
                # layer up.
                src = {arch_field(seen_target, layout, "?", int(t[1:]), 1,
                                  gmap) if t.startswith("@") else t
                       for t in src}
                src = {t for t in src if t}
                if src and src <= ALIAS_GROUP[seen_target][nm]:
                    i.reenc.setdefault(nm, 0)
                    i.reenc[nm] += 1
                    continue
            if nm == "@ccop":
                # See ARCH_ALIAS: reading the tag is reading the flags,
                # storing it is a previous instruction's spill arriving late.
                if rw == "r":
                    nm = "eflags"
                elif rw == "w":
                    i.ccop_w += 1
                    continue
                else:
                    continue
            {"r": i.r, "w": i.w, "k": i.k, "p": i.p}[rw].add(nm)
            if rw == "r":
                cur_r.add(nm)
            elif rw == "w":
                cur_w.add(nm)
    return seen_target, insns


# ---------------------------------------------------------------------------
# The tracer's answer, for the same bytes
# ---------------------------------------------------------------------------

FIELDS_RE = re.compile(r"^\s*(SRC|DST)\{([^}]*)\}")


_ISAX_CACHE = {}


def isaxcheck_sets(tool, isa, hexbytes):
    """The tracer's own SRC/DST for these bytes.

    Keyed on the encoding, not the pc: the tracer's answer is a function of
    the bytes, so a program that executes one encoding a thousand times only
    has to be asked once.
    """
    hit = _ISAX_CACHE.get(hexbytes)
    if hit is not None:
        return hit
    out = subprocess.run([tool, "--isa=" + isa, "--hex=" + hexbytes],
                         capture_output=True, text=True).stdout
    src, dst, seen_fields = set(), set(), False
    for line in out.splitlines():
        if line.startswith("fields"):
            seen_fields = True
            continue
        if line.startswith("boundary-in-generic"):
            break
        if not seen_fields:
            continue
        m = FIELDS_RE.match(line)
        if m:
            toks = [t.strip() for t in m.group(2).split(",")
                    if t.strip() and t.strip() != "-"]
            (src if m.group(1) == "SRC" else dst).update(toks)
    _ISAX_CACHE[hexbytes] = (src, dst)
    return src, dst


def disas_window(elf, lo, hi):
    out = subprocess.check_output(
        ["objdump", "-d", "--insn-width=16", elf], text=True)
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)", line)
        if not m:
            continue
        pc = int(m.group(1), 16)
        if lo <= pc < hi:
            rows.append((pc, m.group(2).replace(" ", ""), m.group(3).strip()))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--build-dir", default="build-oracle")
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--target", default=None)
    ap.add_argument("--compare", metavar="ELF",
                    help="compare with the tracer's sets for this binary")
    ap.add_argument("--isaxcheck",
                    default=os.path.join(ROOT, "build/contrib/plugins/"
                                         "isaxcheck"))
    ap.add_argument("--isa-header", default=None)
    ap.add_argument("--show-diff", action="store_true",
                    help="also show what the runtime differ saw")
    ap.add_argument("--variance", action="store_true",
                    help="check that one pc has one set across every "
                         "translation of it")
    ap.add_argument("--summary", action="store_true",
                    help="group disagreements into signatures instead of "
                         "listing every pc")
    args = ap.parse_args()

    target = args.target or OI.header_target(args.report)
    cache_dir = args.cache_dir or os.path.join(args.build_dir, "oracle-cache")
    layout = OI.load_layout(args.build_dir, target, cache_dir)
    target, insns = parse(args.report, target, layout)

    if args.variance:
        # Does one pc have one set?  The op stream demonstrably does not --
        # x86 spills cc_op wherever it happens to become necessary -- so the
        # question is whether the mapping absorbs that, which is the property
        # the tracer's template model needs and cannot check for itself.
        multi = moved = 0
        for pc, i in insns.items():
            if len(i.variants) < 2:
                continue
            multi += 1
            if len({v for v in i.variants}) > 1:
                moved += 1
                print("0x%x set moved across %d translations:" %
                      (pc, len(i.variants)))
                for r, w in i.variants:
                    print("    R{%s} W{%s}" %
                          (",".join(sorted(r)), ",".join(sorted(w))))
        ccop = sum(1 for i in insns.values() if i.ccop_w)
        ccop_alone = sum(1 for i in insns.values()
                         if i.ccop_w and "eflags" not in i.w)
        print("%d pcs, %d translated more than once, %d whose set moved"
              % (len(insns), multi, moved))
        print("%d pcs store cc_op; %d of those have no other flag write "
              "(a dropped cc_op would lose the flag write on exactly these)"
              % (ccop, ccop_alone))
        return 1 if moved else 0

    if not args.compare:
        for pc, i in insns.items():
            extra = ""
            if i.mem_r or i.mem_w:
                extra += " mem=%dr%dw" % (i.mem_r, i.mem_w)
            if i.helpers:
                extra += " helper=" + ",".join(sorted(set(i.helpers)))
            if i.inside:
                extra += " inside=%d" % i.inside
            if i.reenc:
                extra += " reencoded={%s}" % ",".join(sorted(i.reenc))
            if i.p:
                extra += " envptr={%s}" % ",".join(sorted(i.p))
            if i.k:
                extra += " killed={%s}" % ",".join(sorted(i.k))
            if i.diverged:
                extra += " DIVERGED=%d" % i.diverged
            if args.show_diff:
                extra += " differ_w={%s}" % ",".join(sorted(i.diff_w))
            print("0x%x R{%s} W{%s}%s" %
                  (pc, ",".join(sorted(i.r)), ",".join(sorted(i.w)), extra))
        return 0

    isa_header = args.isa_header or os.path.join(
        ROOT, "contrib/plugins/champsim_tracer/champsim_tracer_mnemonics_x86.h")
    gmap = load_generic_ids(isa_header)
    isa = "x86_64" if target.startswith("x86") else target

    lo = min(insns) if insns else 0
    hi = max(insns) + 16 if insns else 0
    rows = {pc: (b, t) for pc, b, t in disas_window(args.compare, lo, hi)}

    agree = disagree = 0
    # A REFUSAL IS NOT A DISAGREEMENT.  Where the walk met a helper it could
    # not see inside, it marks the instruction opaque and says so; summing
    # those with instructions it answered completely inflates the headline
    # with rows that are a statement about the derivation's reach, not about
    # the decoder.  On the first x86_64 sample that was 31 of 66 signatures --
    # half the number a reader would otherwise take as disagreement.  The
    # plugin API already draws this line (an incomplete set is refused, never
    # truncated); the comparison has to draw it too.
    opaque_insns = 0
    opaque_groups = collections.Counter()
    groups = collections.Counter()
    reenc_cost = collections.Counter()
    examples = {}
    helper_only = collections.Counter()
    if not args.summary:
        print("%-12s %-24s %s" % ("pc", "mnemonic", "disagreement"))
    for pc, i in insns.items():
        if pc not in rows:
            continue
        hexb, text = rows[pc]
        src, dst = isaxcheck_sets(args.isaxcheck, isa, hexb)

        ir_r = {to_generic(n, gmap, isa) for n in i.r}
        ir_w = {to_generic(n, gmap, isa) for n in i.w}
        # RIP is materialised lazily and is dropped from both sides of every
        # comparison isaxcheck makes, for the same reason: whether it appears
        # is a property of where the TB ended, not of the instruction.
        ir_r.discard("REG_PC")
        ir_w.discard("REG_PC")
        src.discard("REG_PC")
        dst.discard("REG_PC")

        mnem = text.split()[0] if text else "?"
        if i.reenc and "REG_FLAGS" in dst and "eflags" not in i.w:
            reenc_cost[mnem] += 1
        notes = []
        for kind, delta in (("IR-rd-extra", ir_r - src),
                            ("IR-rd-missing", src - ir_r),
                            ("IR-wr-extra", ir_w - dst),
                            ("IR-wr-missing", dst - ir_w)):
            if not delta:
                continue
            notes.append("%s{%s}" % (kind, ",".join(sorted(delta))))
            # A signature keyed the way isaxcheck keys its own: the class, the
            # mnemonic, and the register set with numbers elided, so one
            # instruction visited with many register fillings is one row.
            sig = "%s %s +%s" % (kind, mnem,
                                 ",".join(sorted(re.sub(r"\d+", "#", d)
                                                 for d in delta)))
            (opaque_groups if i.opaque else groups)[sig] += 1
            examples.setdefault(sig, (pc, text, hexb))
        if notes:
            if i.opaque:
                opaque_insns += 1
            else:
                disagree += 1
            if i.helpers:
                helper_only[mnem] += 1
            if not args.summary:
                print("0x%-10x %-24s %s%s" %
                      (pc, text[:24], "; ".join(notes),
                       (" (helper %s)" % ",".join(sorted(set(i.helpers))))
                       if i.helpers else ""))
        else:
            agree += 1

    if args.summary:
        print("%-8s %-46s %s" % ("count", "signature", "example"))
        for sig, n in groups.most_common():
            pc, text, hexb = examples[sig]
            print("%-8d %-46s 0x%x %s [%s]" % (n, sig, pc, text[:30], hexb))
        if opaque_groups:
            print("\nOPAQUE -- the walk met a helper and declined; these are "
                  "the derivation's reach, not the decoder's error:")
            for sig, n in opaque_groups.most_common():
                pc, text, hexb = examples[sig]
                print("%-8d %-46s 0x%x %s [%s]"
                      % (n, sig, pc, text[:30], hexb))
    if reenc_cost:
        print("\nthe re-encoding rule takes a flag write away from these, and "
              "the tracer still claims one:")
        for m, n in reenc_cost.most_common():
            print("    %-12s %d" % (m, n))
    print("\n%d agree, %d disagree, %d instructions, %d distinct signatures"
          % (agree, disagree, agree + disagree + opaque_insns, len(groups)))
    print("%d instruction(s) the walk declined (opaque: a helper it cannot see "
          "inside), carrying %d signature(s) -- reported apart from the "
          "disagreement count on purpose"
          % (opaque_insns, len(opaque_groups)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
