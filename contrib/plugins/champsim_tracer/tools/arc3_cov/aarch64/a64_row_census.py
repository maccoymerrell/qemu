#!/usr/bin/env python3
"""THE aarch64 DECODE ROWS A USER-MODE TRACE CAN REACH, derived from the tree.

WHY A CENSUS AND NOT A LIST.  "Which instructions has the tracer been exercised
over" has been answered up to now by counting ENCODINGS, and an encoding count
cannot say what is missing: the aarch64 encoding space is 2^32 words, almost
all of them undefined, and a sweep that decodes ten million of them has still
only reached whatever decode rows those words happened to select.  The unit
that CAN be complete is the decode row -- the decodetree pattern QEMU's own
decoder matched -- because the tree states every one of them and the tracer
reports which one it reached (`qemu_plugin_insn_decode_name`).

WHAT THE ROW IS, and the two numbers are not the same number:

  PATTERN   one `decodetree.py` pattern: a fixed-bit mask plus its fields.
            This is the architectural encoding family.

  RULE      the pattern's NAME, which is what decodetree passes to
            `insn_dataflow_note_rule()` and therefore the only one of the two
            a trace can be scored against.  Several patterns commonly share a
            name (one `trans_` function serving a family), so reaching a rule
            does NOT prove every pattern under it was reached.

Both are reported.  The coverage denominator is the RULE, because that is the
unit the wire can witness; the pattern count rides beside it so a reader can
see how much encoding space one witnessed rule stands for.

REACHABLE, AND HOW THE TREE DECIDES IT.  `target/arm/tcg/meson.build` states
the partition itself:

    arm_ss.add(gen_a32)                                  # always
    arm_ss.add(when: 'TARGET_AARCH64', if_true: gen_a64)

and `translate-a64.c` enters only four decoders --
`disas_a64`, `disas_sme`, `disas_sve` and `disas_sme_fa64`.  So in
`qemu-aarch64`, whose guest is in AArch64 state at EL0, the eleven A32/T16/T32
/VFP/Neon/MVE decoders are not entered at all.  That is a structural fact of
the build, read out of the build, and it is the one remainder class this file
can settle without running anything.

WHAT THIS FILE DELIBERATELY DOES NOT DECIDE.  Inside the A64 group, whether a
row needs EL1, a CPU feature the model lacks, or a trap state the guest never
enters is a RUNTIME property.  Deciding it here would mean writing a hand list
of privileged rows, which is exactly the maintained-by-hand artefact the order
forbids and the shape that goes stale silently.  Those subsets are named as
UNRESOLVED-BY-CENSUS and belong to the measurement pass, which scores the
corpora against this census and attributes every row it could not reach.

REFUSALS, because a census that came back short without saying so would be
read as a coverage result:

  * a meson.build whose gen_a64 / gen_a32 lists do not parse, or that puts one
    decode file in both, FAILS
  * a .decode source named by meson that is not in the tree FAILS
  * a generated .c.inc the build is supposed to carry and does not FAILS
  * a decoder group whose rule set comes out EMPTY FAILS
  * a rule the BUILD states that the SOURCE has no pattern for FAILS -- that
    is a stale build directory, and every count taken from it would describe a
    tree nobody has

Author: Maccoy Merrell.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import importlib.util
import os
import re
import subprocess
import sys

#: The emulator and the library directory decodetree writes its output into.
EMULATOR = "qemu-aarch64"
LIBDIR = "libqemu-aarch64-linux-user.a.p"

#: decodetree emits this for every pattern it compiles; the literals in the
#: build's own generated files ARE the rules that build can reach.
NOTE_RULE = re.compile(r'insn_dataflow_note_rule\("([^"]+)"\)')

#: `decodetree.process('NAME.decode', ...)` inside a gen_* list.
PROCESS = re.compile(r"decodetree\.process\(\s*'([^']+\.decode)'")

#: sme-fa64.decode is not an instruction decoder.  It is the streaming-mode
#: permission filter: its patterns spell OK / FAIL and select nothing to
#: translate, so its two rules are decode rows in no useful sense.
FILTER_FILES = {"sme-fa64.decode"}


class Refusal(Exception):
    pass


def build_id(path):
    """The emulator's GNU build-id, so a reader can pin the census to a build."""
    if not os.path.exists(path):
        raise Refusal("%s: no emulator -- a census derived from a build that "
                      "is not there would describe nothing" % path)
    try:
        out = subprocess.run(["readelf", "-n", path], check=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL).stdout.decode()
    except (OSError, subprocess.CalledProcessError) as e:
        raise Refusal("%s: cannot read notes (%s)" % (path, e))
    m = re.search(r"Build ID:\s*([0-9a-f]{16,})", out)
    if not m:
        raise Refusal("%s: no GNU build-id; an unstamped census cannot be "
                      "shown to describe the corpus's own build" % path)
    return m.group(1)


def decoder_groups(root):
    """{decode-file: group} from target/arm/tcg/meson.build's own lists."""
    path = os.path.join(root, "target/arm/tcg/meson.build")
    if not os.path.exists(path):
        raise Refusal("%s: absent -- the a64/a32 partition is stated there "
                      "and nowhere else this file is willing to read" % path)
    text = open(path, "r", errors="replace").read()

    groups = {}
    for name, group in (("gen_a64", "a64"), ("gen_a32", "a32")):
        m = re.search(re.escape(name) + r"\s*=\s*\[(.*?)\n\]", text, re.S)
        if not m:
            raise Refusal("%s: no %s list.  The partition this census rests "
                          "on is the build's, and it is not readable here"
                          % (path, name))
        files = PROCESS.findall(m.group(1))
        if not files:
            raise Refusal("%s: %s names no decode file.  An empty group would "
                          "silently move every one of its rows into the other "
                          "group's count" % (path, name))
        for f in files:
            if f in groups:
                raise Refusal("%s: %s is in both gen_a64 and gen_a32; the "
                              "partition is not a partition" % (path, f))
            groups[f] = group
    return groups


def rules_from_build(build, groups):
    """{rule: {decode-file, ...}} from the BUILD's generated decoders.

    A NAME CAN BELONG TO MORE THAN ONE DECODER, and that is not a curiosity to
    round off: 34 of aarch64's names (`B`, `NOP`, `ADR`, the AES family ...)
    are stated by an A64 decode file AND by an AArch32 one, because both
    architectures spell the same instruction the same way.  An earlier form of
    this reader kept the FIRST file it happened to see in sorted order, which
    put `B` under a32.decode and marked one of the most reachable rows in the
    ISA unreachable.  The set is kept whole and the group decided from it.
    """
    libdir = os.path.join(build, LIBDIR)
    out = {}
    per_file = {}
    for dfile in sorted(groups):
        inc = os.path.join(libdir, "decode-" + dfile[:-len(".decode")] + ".c.inc")
        if not os.path.exists(inc):
            raise Refusal("%s: meson compiles %s and the build does not carry "
                          "its output.  Every row of that decoder would be "
                          "absent from a census that shrugged this off"
                          % (inc, dfile))
        names = NOTE_RULE.findall(open(inc, "r", errors="replace").read())
        if not names:
            raise Refusal("%s: matched no insn_dataflow_note_rule literal.  "
                          "decodetree emits one per pattern, so a zero here "
                          "is a generator whose shape moved under this reader "
                          "-- the silent short census this file exists to end"
                          % inc)
        per_file[dfile] = len(set(names))
        for n in set(names):
            out.setdefault(n, set()).add(dfile)
    if not out:
        raise Refusal("the aarch64 rule universe came out EMPTY")
    return out, per_file


def patterns_from_source(root, groups):
    """{rule: [pattern, ...]} parsed with the tree's OWN decodetree.py."""
    parser = os.path.join(root, "scripts/decodetree.py")
    if not os.path.exists(parser):
        raise Refusal("%s: absent.  The pattern side of the census is parsed "
                      "with the tree's OWN decodetree, and a second parser "
                      "written here could disagree with the one that built "
                      "the decoder" % parser)
    spec = importlib.util.spec_from_file_location("decodetree", parser)
    if spec is None or spec.loader is None:
        raise Refusal("%s: cannot be loaded as a module" % parser)
    dt = importlib.util.module_from_spec(spec)
    sys.modules["decodetree"] = dt
    spec.loader.exec_module(dt)

    out = {}
    for dfile in sorted(groups):
        src = os.path.join(root, "target/arm/tcg", dfile)
        if not os.path.exists(src):
            raise Refusal("%s: meson names this decode file and the tree does "
                          "not have it" % src)
        # decodetree keeps its parse in module globals; reset per file so one
        # file's patterns are never credited to another's.
        dt.fields = {}
        dt.arguments = {}
        dt.formats = {}
        dt.allpatterns = []
        dt.anyextern = False
        dt.insnwidth = 16 if dfile == "t16.decode" else 32
        dt.insnmask = (1 << dt.insnwidth) - 1
        dt.variablewidth = False
        dt.input_file = src
        top = dt.ExcMultiPattern(0)
        with open(src, "rt", encoding="utf-8") as fh:
            dt.parse_file(fh, top)
        for p in top.pats:
            p.prop_masks()
        for p in dt.allpatterns:
            out.setdefault(p.name, []).append(
                (dfile, p.fixedbits, p.fixedmask, sorted(p.fields)))
    if not out:
        raise Refusal("the decode sources yielded no patterns at all")
    return out


def census(root, build):
    groups = decoder_groups(root)
    stamp = build_id(os.path.join(build, EMULATOR))
    rules, per_file = rules_from_build(build, groups)
    pats = patterns_from_source(root, groups)

    # A rule the BUILD can state and the SOURCE has no pattern for means the
    # build directory and the tree are not the same tree.  Every number below
    # would then describe neither.
    orphan = sorted(r for r in rules if r not in pats)
    if orphan:
        raise Refusal("%d rule(s) the build states have no pattern in the "
                      "tree's decode sources -- the build directory is stale "
                      "against this checkout: %s"
                      % (len(orphan), " ".join(orphan[:8])))

    rows = []
    for rule, dfiles in sorted(rules.items()):
        a64_files = sorted(f for f in dfiles
                           if groups[f] == "a64" and f not in FILTER_FILES)
        filt_files = sorted(f for f in dfiles if f in FILTER_FILES)

        # THE GROUP IS DECIDED BY MEMBERSHIP, NOT BY ORDER.  A name any A64
        # decode file states is reachable, whatever else also states it.
        if a64_files:
            klass, why = ("reachable-candidate",
                          "stated by %s, compiled from gen_a64 and reached "
                          "through disas_a64/disas_sme/disas_sve -- the three "
                          "decoders translate-a64.c calls for every AArch64 "
                          "word" % ",".join(a64_files))
            scoped = a64_files
        elif filt_files:
            klass, why = ("fa64-streaming-filter",
                          "stated only by sme-fa64.decode, the SME "
                          "streaming-mode permission filter read by "
                          "disas_sme_fa64; its patterns spell OK/FAIL and "
                          "translate nothing")
            scoped = filt_files
        else:
            klass, why = ("aarch32-only",
                          "stated only by %s, compiled from gen_a32, whose "
                          "decoders (disas_a32/t16/t32/vfp/neon/mve) "
                          "translate-a64.c never enters -- a qemu-aarch64 "
                          "guest is in AArch64 state at EL0"
                          % ",".join(sorted(dfiles)))
            scoped = sorted(dfiles)

        # Count only the patterns from the files this row is credited to, so
        # a name shared with AArch32 does not inflate the A64 pattern count
        # with encodings no aarch64 guest can reach.
        npat = sum(1 for (df, _fb, _fm, _fl) in pats[rule] if df in scoped)
        shared = "yes" if len(dfiles) > 1 else "no"
        rows.append((rule, klass, ",".join(scoped), shared, npat, why))
    return stamp, rows, per_file


def write(out_dir, stamp, rows, build, root):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "a64_rows.tsv")
    with open(path, "w") as f:
        f.write("#emulator %s\n" % stamp)
        f.write("#builddir %s\n" % os.path.abspath(build))
        f.write("#root %s\n" % os.path.abspath(root))
        f.write("#rule\tclass\tdecodefiles\tshared_with_other_group"
                "\tpatterns\twhy\n")
        for rule, klass, dfiles, shared, npat, why in rows:
            f.write("%s\t%s\t%s\t%s\t%d\t%s\n"
                    % (rule, klass, dfiles, shared, npat, why))
    return path


def selftest():
    """Prove each refusal fires, on planted inputs."""
    import tempfile
    cases = []

    def check(name, fn, want):
        try:
            fn()
            got = "ok"
        except Refusal:
            got = "REFUSED"
        except Exception as e:                       # a crash is not a refusal
            got = "CRASH(%s)" % type(e).__name__
        ok = got == want
        print("  %-34s %s" % (name, "ok" if ok else "FAILED (%s)" % got))
        cases.append(ok)

    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "target/arm/tcg"))
        mb = os.path.join(d, "target/arm/tcg/meson.build")

        check("no meson.build", lambda: decoder_groups(d), "REFUSED")

        open(mb, "w").write("gen_a64 = [\n]\n")
        check("gen_a64 present, gen_a32 absent",
              lambda: decoder_groups(d), "REFUSED")

        open(mb, "w").write("gen_a64 = [\n]\ngen_a32 = [\n]\n")
        check("both lists empty", lambda: decoder_groups(d), "REFUSED")

        open(mb, "w").write(
            "gen_a64 = [\n  decodetree.process('x.decode'),\n]\n"
            "gen_a32 = [\n  decodetree.process('x.decode'),\n]\n")
        check("a file in both groups", lambda: decoder_groups(d), "REFUSED")

        open(mb, "w").write(
            "gen_a64 = [\n  decodetree.process('x.decode'),\n]\n"
            "gen_a32 = [\n  decodetree.process('y.decode'),\n]\n")
        check("a good partition parses",
              lambda: decoder_groups(d), "ok")

        # A build with no emulator, and one whose generated file is missing.
        check("no emulator binary",
              lambda: build_id(os.path.join(d, EMULATOR)), "REFUSED")
        check("missing generated .c.inc",
              lambda: rules_from_build(d, {"x.decode": "a64"}), "REFUSED")

        # A generated file that exists and carries no rule literal.
        os.makedirs(os.path.join(d, LIBDIR))
        open(os.path.join(d, LIBDIR, "decode-x.c.inc"), "w").write("/* none */")
        check("generated file with no rules",
              lambda: rules_from_build(d, {"x.decode": "a64"}), "REFUSED")

        # A decode file meson names and the tree does not carry.
        check("decode source absent",
              lambda: patterns_from_source(d, {"x.decode": "a64"}), "REFUSED")

    n = len(cases)
    print("a64_row_census selftest: %d of %d arms fired as designed"
          % (sum(cases), n))
    return 0 if all(cases) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--root", default=None,
                    help="QEMU source root (default: derived from this file)")
    ap.add_argument("--build-dir", default=None)
    ap.add_argument("-o", "--out", default=None)
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.build_dir or not a.out:
        print("a64_row_census: --build-dir and -o are required",
              file=sys.stderr)
        return 2

    root = a.root or os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "..", "..", "..", "..", ".."))
    try:
        stamp, rows, per_file = census(root, a.build_dir)
    except Refusal as e:
        print("a64_row_census: REFUSED: %s" % e, file=sys.stderr)
        return 1

    path = write(a.out, stamp, rows, a.build_dir, root)

    by = {}
    pat = {}
    shared_n = 0
    for _rule, klass, _df, shared, npat, _why in rows:
        by[klass] = by.get(klass, 0) + 1
        pat[klass] = pat.get(klass, 0) + npat
        if shared == "yes":
            shared_n += 1
    print("emulator %s" % stamp)
    print("decode files and the distinct rules each states:")
    for f in sorted(per_file):
        print("  %-22s %5d" % (f, per_file[f]))
    print("rows by class (rules / patterns):")
    for k in sorted(by):
        print("  %-24s %5d / %6d" % (k, by[k], pat[k]))
    print("TOTAL rules %d   patterns %d" % (len(rows), sum(pat.values())))
    print("rule names stated by more than one decode file: %d" % shared_n)
    print("census written to %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
