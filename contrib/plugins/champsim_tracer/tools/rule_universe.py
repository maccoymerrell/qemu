#!/usr/bin/env python3
"""Every decode rule a BUILD can state, derived from that build and nothing else.

WHY THIS FILE EXISTS.  `gapreport --require-ruled` refuses in two directions: a
disagreement class nobody arbitrated, and an arbitration that reaches no class.
The first direction reads the corpora and is a statement about them.  The
second one read the corpora too -- and it is not a statement about them.  It
asked "did any encoding in this sample reach this ruling's class", and called
a ruling DEAD when the answer was no.

That verdict moves with the sample.  mipsel `OPC_TGE` flipped UNRULED -> DEAD
between two corpora of the same tree: all 27 of its encodings are ident-only
(the Capstone side of the join is a strict subset of the QEMU side on every
ISA), so the class cannot form, so the ruling that decides it "reaches no
class".  Nothing about the ruling changed.  Nothing about the decoder changed.
A wider sample would have said UNRULED and a narrower one says DEAD, and both
readings were printed as a property of the arbitration corpus.

So the DEAD test needs a subject that a sample cannot move: the set of rules
the decoder CAN state.  That is a property of the build, and this tool reads
it out of the build, one source per decoder shape:

  decodetree      scripts/decodetree.py emits insn_dataflow_note_rule("NAME")
                  into the generated .c.inc for every pattern it compiles, so
                  the literals in the build's own generated files ARE the
                  pattern names that build can reach.  (aarch64, riscv64, and
                  the decodetree half of mipsel.)

  mips switches   translate.c decodes the base ISA in hand-written switches,
                  and scripts/mips-df-ident.py compiles their case labels into
                  insn-df-ident.h.inc as { value, rule, word } rows.  The rule
                  column of that generated table is the rest of mipsel.

  i386 tables     X86_DF_IDENT(op) pastes X86_DF_WORD_<op>, and the generated
                  insn-df-words.h.inc "defines exactly the rules the table
                  names" -- its own header says so, and the build FAILS if the
                  table names a rule the TSV does not adjudicate.  So the set
                  of X86_DF_WORD_ macros is the x86 universe, checked in both
                  directions by the compiler rather than by this reader.

WHAT THIS IS NOT.  It is not a claim that every rule here is REACHABLE by some
byte sequence, and a caller must not read an unreached rule as a defect: a
pattern can be gated on a CPU feature the guest does not have, on a privilege
level a user-mode trace never enters, or on an ASE nothing in the corpus was
built for.  "The rule exists" is the whole claim, and it is exactly the claim
the DEAD test needs -- a ruling whose rule the build can still state is
RESERVED, and only a ruling naming a rule the build no longer has is dead.

REFUSALS, because a universe that came back empty would silently make every
ruling DEAD -- the precise failure this tool exists to end:

  * a build directory with no emulator for the ISA FAILS
  * an emulator with no GNU build-id FAILS: the stamp is how a caller proves
    the universe and the corpus describe the same binary
  * a source this ISA is supposed to have and does not FAILS
  * an ISA whose universe comes out EMPTY FAILS

Copyright (c) 2026 Maccoy Merrell

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import glob
import os
import re
import subprocess
import sys

#: isa -> (emulator basename, the library directory decodetree writes into)
ISAS = {
    "x86_64":  ("qemu-x86_64",  "libqemu-x86_64-linux-user.a.p"),
    "aarch64": ("qemu-aarch64", "libqemu-aarch64-linux-user.a.p"),
    "riscv64": ("qemu-riscv64", "libqemu-riscv64-linux-user.a.p"),
    "mipsel":  ("qemu-mipsel",  "libqemu-mipsel-linux-user.a.p"),
}

#: The generated, non-decodetree half, per ISA: (path under the build, source
#: label, the pattern whose group 1 is the rule name).  An ISA listed here and
#: missing the file is a refusal -- the file is part of its decoder.
EXTRA = {
    "mipsel": ("target/mips/tcg/insn-df-ident.h.inc", "mips-switch",
               re.compile(r'\{ 0x[0-9a-fA-F]+u, "([^"]+)"')),
    "x86_64": ("target/i386/tcg/insn-df-words.h.inc", "i386-table",
               re.compile(r'^#define X86_DF_WORD_(\S+)', re.M)),
}

NOTE_RULE = re.compile(r'insn_dataflow_note_rule\("([^"]+)"\)')

#: The one rule name that is not a decoder's.  gapreport synthesises a class
#: keyed on it for bytes that reached NO rule while the incumbent still named
#: an opcode, so a ruling may legitimately name it and no build ever will.
SYNTHETIC = "#undecoded"

HEADER = "#isa\trule\tsource\n"


class Refusal(Exception):
    pass


def build_id(path):
    """The emulator's GNU build-id -- the same stamp the capture writes."""
    if not os.path.exists(path):
        raise Refusal("%s: no emulator -- a universe derived from a build "
                      "that is not there would describe nothing" % path)
    try:
        out = subprocess.run(["readelf", "-n", path], check=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL).stdout.decode()
    except (OSError, subprocess.CalledProcessError) as e:
        raise Refusal("%s: cannot read notes (%s)" % (path, e))

    m = re.search(r"Build ID:\s*([0-9a-f]{16,})", out)
    if not m:
        raise Refusal("%s: no GNU build-id.  The stamp is how a caller proves "
                      "this universe and a corpus describe the same binary, "
                      "and an unstamped universe cannot be joined to anything"
                      % path)
    return m.group(1)


def universe(build, isa):
    """Every rule name this build's decoder for @isa can state, with sources."""
    if isa not in ISAS:
        raise Refusal("%s: not an ISA this tool knows (%s)"
                      % (isa, ", ".join(sorted(ISAS))))
    emu, libdir = ISAS[isa]
    stamp = build_id(os.path.join(build, emu))

    rules = {}
    gen = sorted(glob.glob(os.path.join(build, libdir, "*.c.inc")))
    if not gen:
        raise Refusal("%s/%s: no generated decoder files.  Every target in "
                      "this tree compiles at least one decodetree source, so "
                      "an empty set here is a wrong build directory rather "
                      "than a decoder without patterns" % (build, libdir))
    for f in gen:
        with open(f, "r", errors="replace") as fh:
            for name in NOTE_RULE.findall(fh.read()):
                rules.setdefault(name, "decodetree:" + os.path.basename(f))

    if isa in EXTRA:
        rel, label, pat = EXTRA[isa]
        path = os.path.join(build, rel)
        if not os.path.exists(path):
            raise Refusal("%s: %s decodes part of its ISA through this "
                          "generated file and it is absent -- the universe "
                          "would be short by that whole half" % (path, isa))
        with open(path, "r", errors="replace") as fh:
            found = pat.findall(fh.read())
        if not found:
            raise Refusal("%s: matched no rule rows.  The generator's output "
                          "shape moved and this reader did not; a silent zero "
                          "here is the whole defect this tool addresses"
                          % path)
        for name in found:
            rules.setdefault(name, label)

    if not rules:
        raise Refusal("%s: the rule universe came out EMPTY.  Every ruling "
                      "would be DEAD against it, which is the reading this "
                      "tool exists to make impossible" % isa)
    return stamp, rules


def write(path, isa, stamp, rules, build):
    with open(path, "w") as f:
        f.write("#emulator %s\n" % stamp)
        f.write("#builddir %s\n" % os.path.abspath(build))
        f.write(HEADER)
        for name in sorted(rules):
            f.write("%s\t%s\t%s\n" % (isa, name, rules[name]))


def read(path):
    """A universe file as (emulator stamp, {rule: source}).  Refuses empty."""
    if not os.path.exists(path):
        raise Refusal("%s: no universe file -- the DEAD verdict has no "
                      "corpus-independent subject without one" % path)
    stamp = None
    rules = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#emulator "):
                stamp = line[len("#emulator "):].strip()
                continue
            if line.startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < 3:
                continue
            rules[p[1]] = p[2]
    if not stamp:
        raise Refusal("%s: no #emulator stamp; an unstamped universe cannot "
                      "be proven to describe the corpus's own build" % path)
    if not rules:
        raise Refusal("%s: no rule rows.  A universe that reports nothing "
                      "makes every arbitration look dead" % path)
    return stamp, rules


def selftest(tmp=None):
    """Prove the reader's refusals fire, on planted files.

    The derivation itself is proven by USE -- it runs against a real build in
    every pass and the counts are published -- but a refusal nobody has seen
    say no is a refusal nobody has seen work.
    """
    import tempfile

    cases = []

    def check(name, fn, want):
        try:
            fn()
            got = "ok"
        except Refusal:
            got = "REFUSED"
        ok = got == want
        print("  %-22s %s" % (name, "ok" if ok else "FAILED (%s)" % got))
        cases.append(ok)

    with tempfile.TemporaryDirectory(dir=tmp) as d:
        good = os.path.join(d, "good.tsv")
        write(good, "q", "abc123", {"R_ONE": "decodetree:x.c.inc"}, d)
        check("reads a good file", lambda: read(good), "ok")

        missing = os.path.join(d, "nope.tsv")
        check("absent file", lambda: read(missing), "REFUSED")

        empty = os.path.join(d, "empty.tsv")
        with open(empty, "w") as f:
            f.write("#emulator abc123\n" + HEADER)
        check("no rule rows", lambda: read(empty), "REFUSED")

        nostamp = os.path.join(d, "nostamp.tsv")
        with open(nostamp, "w") as f:
            f.write(HEADER + "q\tR_ONE\tdecodetree:x.c.inc\n")
        check("no emulator stamp", lambda: read(nostamp), "REFUSED")

        check("unknown isa",
              lambda: universe(d, "vax"), "REFUSED")
        check("no emulator binary",
              lambda: universe(d, "x86_64"), "REFUSED")

        # An emulator that IS there but carries no build-id.
        nb = os.path.join(d, "nb")
        os.makedirs(nb, exist_ok=True)
        with open(os.path.join(nb, "qemu-x86_64"), "wb") as f:
            f.write(b"not an elf")
        check("emulator without build-id",
              lambda: universe(nb, "x86_64"), "REFUSED")

    n = len(cases)
    print("rule_universe selftest: %d of %d arms fired as designed"
          % (sum(cases), n))
    return 0 if all(cases) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--selftest", action="store_true",
                    help="prove every refusal fires, then exit")
    ap.add_argument("--build-dir", default=None,
                    help="the build whose decoders define the universe")
    ap.add_argument("--isa", action="append", default=[],
                    help="ISA to derive; repeat for several (default: all)")
    ap.add_argument("-o", "--out", default=None,
                    help="directory to write rules_<isa>.tsv into")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not args.build_dir or not args.out:
        print("rule_universe: --build-dir and -o are required", file=sys.stderr)
        return 2

    isas = args.isa or sorted(ISAS)
    os.makedirs(args.out, exist_ok=True)
    bad = 0
    for isa in isas:
        try:
            stamp, rules = universe(args.build_dir, isa)
        except Refusal as e:
            print("rule_universe: REFUSED: %s" % e, file=sys.stderr)
            bad += 1
            continue
        path = os.path.join(args.out, "rules_%s.tsv" % isa)
        write(path, isa, stamp, rules, args.build_dir)
        bysrc = {}
        for src in rules.values():
            bysrc["decodetree" if src.startswith("decodetree:") else src] = \
                bysrc.get("decodetree" if src.startswith("decodetree:")
                          else src, 0) + 1
        print("%-8s %6d rules  emulator %s  (%s)"
              % (isa, len(rules), stamp,
                 ", ".join("%s %d" % (k, v) for k, v in sorted(bysrc.items()))))
    print("rule_universe: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
