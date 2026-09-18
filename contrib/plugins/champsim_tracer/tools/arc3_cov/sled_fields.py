#!/usr/bin/env python3
"""The coverage legs' TRACER ARM, read out of the emulator (FINDING 244-H).

    sled_fields.py --isa <isa> --capture <dir> [--falsify drop-src:<mnem>]
        < hex-encodings-one-per-line  > fields.tsv

WHAT THIS REPLACES AND WHY IT HAD TO BE REPLACED
------------------------------------------------
All four arc3_cov legs scored the tracer's own InsnFields against a reference,
and all four got them from `isaxcheck --isa=<isa> --layer=fields --batch`.
isaxcheck linked Capstone into the build and was deleted with it at c32824defa,
so every leg has had no tracer arm since -- aarch64/REPRODUCE.sh:72,78,
riscv64:103,110, mipsel:86,92,95, x86_64:128,405.  The legs could not be
re-run, so the four coverage percentages could not be re-derived at any tip
after that commit.

WHERE THE ANSWER LIVES NOW.  The wire's register lists are QEMU's own ordered
statements, made at TRANSLATION time inside the emulator, and no host tool has
them.  srcenc_sled.py performs the translations -- a guest image whose text is
a run of fixed-stride slots, one encoding each, translated and never executed
-- and the capture writes what QEMU said.  This module is the join from that
capture to the columns the legs' parsers read:

    f_ok       1 when the capture carries a seated register list for the
               encoding.  0 when the encoding produced no row at all (QEMU
               built no chain for it) and 0 when the seating REFUSED -- see
               below, the two are distinguished in f_ident, not collapsed.
    f_opcode   the generic opcode word, from CST_QEMU_IDENT_PAIRS.
    f_branch   the branch class, from the same row.
    f_src      the wire's src_regs[], CST_GEN_SET_DUMP side `q` direction `r`.
    f_dst      the wire's dst_regs[], the same corpus, direction `w`.
    f_ident    what the capture had to say: `seated`, `refused:<why>`, or
               `unreached`.

A REFUSAL IS NOT AN EMPTY LIST, AND UNREACHED IS NEITHER.  The seating writes
`@refused:<why>` as a set MEMBER precisely so that a refused list cannot be
read as an instruction that touches no register, and the sled reports an
encoding QEMU built no chain for rather than dropping it.  Flattening either
into `f_src=` would hand a scorer a silence it would count as agreement.  So
f_ok is 0 for both and f_ident says which, and a leg that wants to exclude one
of them can.

THE MNEMONIC IS QEMU'S DECODE RULE.  The identity corpus's `mnem` column reads
"-" since the other decoder was retired; the rule name is what QEMU's decoder
actually reached and is the honest occupant of that column.

THE FALSIFIER, AND WHAT ITS REACH NOW IS.  Three legs prove their headline zero
can go red by damaging the tracer arm for one mnemonic and requiring the
agreement to fall by exactly the damaged rows.  `--falsify drop-src:<mnem>`
(also read from CST_FALSIFY, the name the legs already export) drops the source
list of every row whose rule matches, and REFUSES if it matched none -- an arm
that damages nothing is not a control, and the leg must name a mnemonic that is
in its own denominator instead.  STATED PLAINLY: this damages the EXPORTED
TABLE, where isaxcheck damaged its in-process model.  What the control still
proves is that the scorer reads this table and moves with it; what it no longer
proves is anything about the emulator's own classification path.  That is a
weaker claim than the one the legs' comments make, and it is written here
rather than left for a reader to assume.

Author: Maccoy Merrell.
"""

import argparse
import os
import sys

FIELDS = ("hex", "f_ok", "f_opcode", "f_branch", "f_src", "f_dst", "f_ident")


def _rows(path, ncol):
    """-> [row], refusing a file that is absent or carries only its header."""
    if not os.path.exists(path):
        sys.exit("sled_fields: no %s -- REFUSING.  The tracer arm is read out "
                 "of a capture; without one there is no arm, and a leg that "
                 "scored an empty arm would report the reference against "
                 "nothing." % path)
    out = []
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) >= ncol:
                out.append(c)
    if not out:
        sys.exit("sled_fields: %s carries a header and no row -- REFUSING.  "
                 "A header is not a corpus." % path)
    return out


def load(isa, capture_dir):
    """-> {encoding: {src, dst, opcode, branch, rule, ident}}.

    Reads the two corpora srcenc_sled.py leaves in its output directory.  Both
    are keyed on the ENCODING, and both are written by the same run over the
    same translations, so a row present in one and absent from the other is a
    fact about that encoding and not about two sweeps drifting apart.
    """
    gen = _rows(os.path.join(capture_dir, "gen_%s.tsv" % isa), 7)
    ident = _rows(os.path.join(capture_dir, "ident_%s.tsv" % isa), 7)

    info = {}
    for c in gen:
        if c[2] != "q":
            continue
        enc, direction, names = c[1], c[3], c[6]
        e = info.setdefault(enc, {"src": "", "dst": "", "opcode": "",
                                  "branch": "", "rule": "-",
                                  "ident": "unreached"})
        if direction == "r":
            e["src"] = names
        elif direction == "w":
            e["dst"] = names
        why = [m for m in names.split(",") if m.startswith("@refused:")]
        if why:
            e["ident"] = "refused:" + why[0][len("@refused:"):]
        elif e["ident"] == "unreached":
            e["ident"] = "seated"
    for c in ident:
        e = info.get(c[1])
        if e is None:
            continue
        e["rule"] = c[3] or "-"
        e["opcode"] = c[5]
        e["branch"] = c[6]
    return info


def render(isa, capture_dir, encodings, falsify=None):
    """-> the TSV text, in the shape the legs' parsers consume."""
    info = load(isa, capture_dir)
    damaged = 0
    want = None
    if falsify:
        if not falsify.startswith("drop-src:"):
            sys.exit("sled_fields: --falsify takes drop-src:<mnem>, got %r"
                     % falsify)
        want = falsify[len("drop-src:"):]

    out = ["\t".join(FIELDS)]
    for h in encodings:
        e = info.get(h)
        if e is None:
            out.append("\t".join((h, "0", "", "", "", "", "unreached")))
            continue
        src, ok = e["src"], e["ident"] == "seated"
        if want is not None and e["rule"] == want:
            src, damaged = "", damaged + 1
        out.append("\t".join((h, "1" if ok else "0", e["opcode"], e["branch"],
                              src, e["dst"], e["ident"])))
    if want is not None and damaged == 0:
        sys.exit(
            "sled_fields: --falsify drop-src:%s matched NO row -- REFUSING.  "
            "A control arm that damages nothing cannot make the comparison go "
            "red, and a leg that reported an unchanged agreement from it would "
            "be quoting a number no instrument produced.  Name a mnemonic that "
            "is in this leg's own denominator." % want)
    if want is not None:
        sys.stderr.write("sled_fields: falsified drop-src:%s rows=%d\n"
                         % (want, damaged))
    return "\n".join(out) + "\n", damaged


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--isa", required=True)
    ap.add_argument("--capture", required=True,
                    help="directory srcenc_sled.py wrote gen_<isa>.tsv and "
                         "ident_<isa>.tsv into")
    ap.add_argument("--falsify", default=os.environ.get("CST_FALSIFY"))
    a = ap.parse_args()

    encodings = []
    for line in sys.stdin:
        h = "".join(ch for ch in line.strip() if ch in "0123456789abcdefABCDEF")
        if h:
            encodings.append(h.lower())
    if not encodings:
        sys.exit("sled_fields: stdin carried no encoding -- REFUSING")
    text, _n = render(a.isa, a.capture, encodings, a.falsify)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
