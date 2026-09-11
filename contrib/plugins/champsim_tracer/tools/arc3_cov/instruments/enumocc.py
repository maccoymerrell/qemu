#!/usr/bin/env python3
"""THE ENUM-TABLE OCCUPANCY CENSUS: who the Capstone enum table is still the
classification for, named, over the sled's whole encoding population.

WHY THIS EXISTS.  R14 retires the four `champsim_tracer_mnemonics_<isa>.h`
tables.  A retirement needs an occupancy argument, and the enumerated-zeros
ruling says which kind: not a hand-list of instruments that happened to read
zero, but an exhaustive account of every path that can reach the consumer,
with a control proving the instrument CAN report otherwise.

THE CONSUMER IS ONE `if`.  `classify_insn_id()` (champsim_tracer_decode.cc)
asks QEMU's decode identity first and falls to the enum row on exactly one
condition:

    if (info->decode_id == 0 && cap) { ... return cap; }

`decode_id == 0` is QEMU's own statement that it exported no identity for the
instruction, so the population that the enum table answers for is precisely
the encodings whose `decode_id` is zero AND for which the enum table holds a
row with a class.  Both facts are per-ENCODING and both are already in the
per-encoding MECHANISM corpus that `srcenc_sled.py --mech` writes: column 4
is the decode id, column 19 is the opcode the wire publishes.  So the census
is a read of a capture that already exists, and it inherits the sled's
coverage -- the whole enumerated encoding population, not the encodings some
program happened to execute.

WHAT IT DOES NOT SAY, stated so its number is not read as more than it is.
The corpus row is written at TEMPLATE BUILD, which runs whether or not the
block is later admitted to the trace, so this is the TRANSLATION-level
occupancy.  It is an upper bound on the wire-level one and deliberately so:
a bound that cannot be under-counted is what a deletion argument needs.  The
wire-level occupant count for an executed workload is the sidecar's own
`ENUM-PUBLISHED` row (qemu_ident_shadow_report), and the two answer different
questions -- do not quote one for the other.

THE CONTROL IS NOT A PLANT.  The four ISAs are read by one instrument at one
tip and do not agree: aarch64 and riscv64 read 0 while x86_64 and mipsel read
thousands.  A census that reported zero everywhere could be a census that had
stopped looking; a census that separates four ISAs measured the same way
cannot be.  The selftest supplies the remaining direction -- a corpus that is
missing, empty, or not the mech corpus at all must REFUSE rather than read 0.

Author: Maccoy Merrell.
"""

import argparse
import os
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")

#: The mech corpus's first line, as srcenc_sled.py writes it.  Checked rather
#: than assumed: pointed at the READ-LIST corpus this census would score
#: column 19 of a four-column file and call every encoding silent, which is a
#: zero produced by reading the wrong file.
MECH_HEAD_0 = "#isa"
MECH_HEAD_3 = "decode_id"
MECH_HEAD_18 = "OPC"

#: The opcode spellings that are NOT a classification.  `GEN_OP_UNKNOWN` is
#: what classify_insn_id() publishes when neither key answered; "-" and "" are
#: the corpus's own empty cells.
NO_CLASS = ("GEN_OP_UNKNOWN", "-", "")


class Refused(Exception):
    """A census that cannot look reports that, never a zero."""


def _check_header(path):
    with open(path, "r", errors="replace") as f:
        head = f.readline().rstrip("\n").split("\t")
    if (len(head) < 19 or head[0] != MECH_HEAD_0
            or head[3] != MECH_HEAD_3 or head[18] != MECH_HEAD_18):
        raise Refused("%s is not a mechanism corpus -- its header is %r"
                      % (path, head[:5]))


def score_file(path):
    """(rows, decode_id0, enum-answered, [(enc, mnem, opc), ...])."""
    if not os.path.isfile(path):
        raise Refused("no corpus at %s" % path)
    _check_header(path)
    rows = zero = 0
    named = []
    with open(path, "r", errors="replace") as f:
        f.readline()
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 19:
                continue
            rows += 1
            if c[3] != "00000000":
                continue
            zero += 1
            if c[18] not in NO_CLASS:
                named.append((c[1], c[2], c[18]))
    if rows == 0:
        raise Refused("%s carries no data rows -- a corpus with no subject "
                      "cannot report an occupancy" % path)
    return rows, zero, named


def score_isa(sled, isa, wps):
    out = []
    merged = {}
    for wp in wps:
        p = os.path.join(sled, "%s.wp%s" % (isa, wp),
                         "corpus_mech_%s.tsv" % isa)
        rows, zero, named = score_file(p)
        out.append("%s wp%s rows=%d decode_id0=%d enum-answered=%d"
                   % (isa, wp, rows, zero, len(named)))
        for enc, mnem, opc in named:
            merged.setdefault(enc, (mnem, opc))
    return out, merged


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--sled", help="sled capture directory")
    ap.add_argument("--out", help="directory for the named occupant tables")
    ap.add_argument("--isa", action="append", default=None)
    ap.add_argument("--wp", action="append", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()
    if not a.sled:
        print("enumocc: --sled is required", file=sys.stderr)
        return 2

    isas = a.isa or list(ISAS)
    wps = a.wp or ["0", "16"]
    if a.out:
        os.makedirs(a.out, exist_ok=True)

    rc = 0
    total = 0
    lines = []
    for isa in isas:
        try:
            per, merged = score_isa(a.sled, isa, wps)
        except Refused as e:
            lines.append("%s REFUSED-TO-SCORE -- %s" % (isa, e))
            rc = 2
            continue
        lines.extend(per)
        lines.append("%s TOTAL enum-answered encodings=%d" % (isa, len(merged)))
        total += len(merged)
        if a.out:
            with open(os.path.join(a.out, "%s.occ.tsv" % isa), "w") as f:
                f.write("#isa\tencoding\tmnemonic\tpublished_opcode\n")
                for enc in sorted(merged):
                    mnem, opc = merged[enc]
                    f.write("%s\t%s\t%s\t%s\n" % (isa, enc, mnem, opc))
    lines.append("ENUM-OCCUPANCY total=%d rc=%d" % (total, rc))
    text = "\n".join(lines)
    print(text)
    if a.out:
        with open(os.path.join(a.out, "OCC.txt"), "w") as f:
            f.write(text + "\n")
    return rc


# ------------------------------------------------------------------ selftest
_HEAD = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate"
         "\tPUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\tWSTQ"
         "\tOPC\tBR\tCFLAGS\tREFINE\tLANEK\tLANEP\tWRU\n")


def _row(enc, mnem, did, opc):
    c = ["isa", enc, mnem, did] + ["-"] * 14 + [opc] + ["-"] * 6
    return "\t".join(c) + "\n"


def _write(path, rows, head=_HEAD):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(head)
        for r in rows:
            f.write(r)


def selftest():
    import tempfile
    fails = []
    with tempfile.TemporaryDirectory() as d:
        # ARM 1 CLEAN ZERO.  Every row carries an identity, so the enum table
        # answers for nothing and the census must say 0 -- and must not
        # refuse, because this is the RESULT the deletion is aiming at.
        s = os.path.join(d, "clean")
        for wp in ("0", "16"):
            _write(os.path.join(s, "x86_64.wp%s" % wp, "corpus_mech_x86_64.tsv"),
                   [_row("90", "nop", "00000123", "GEN_OP_NOP"),
                    _row("31c0", "xorl", "00000456", "GEN_OP_XOR")])
        rc = main(["--sled", s, "--isa", "x86_64"])
        if rc != 0:
            fails.append("arm1 a clean corpus must score 0, not refuse")

        # ARM 2 THE OCCUPANT.  One row with no identity and a class from the
        # enum table.  The census must NAME it; a census that cannot go
        # non-zero is not a census.
        s = os.path.join(d, "occ")
        for wp in ("0", "16"):
            _write(os.path.join(s, "mipsel.wp%s" % wp, "corpus_mech_mipsel.tsv"),
                   [_row("00000000", "nop", "00000123", "GEN_OP_NOP"),
                    _row("45800000", "bz.v", "00000000", "GEN_OP_BRANCH")])
        o = os.path.join(d, "occout")
        rc = main(["--sled", s, "--isa", "mipsel", "--out", o])
        if rc != 0:
            fails.append("arm2 a corpus with an occupant must still score 0 rc")
        got = open(os.path.join(o, "mipsel.occ.tsv")).read()
        if "45800000" not in got or "bz.v" not in got:
            fails.append("arm2 the occupant was not NAMED: %r" % got)
        if "00000000\tnop" in got:
            fails.append("arm2 a row WITH an identity was counted as an "
                         "occupant")

        # ARM 3 THE ABSENT CORPUS.  A missing arm must REFUSE.  This is the
        # shape every zero in this tree has to survive: a census pointed at
        # nothing reads 0 unless it is built not to.
        rc = main(["--sled", os.path.join(d, "nothing"), "--isa", "x86_64"])
        if rc != 2:
            fails.append("arm3 a missing corpus must REFUSE, got rc=%d" % rc)

        # ARM 4 THE EMPTY CORPUS.  Header present, no rows: also a refusal,
        # for the same reason and by a different route.
        s = os.path.join(d, "empty")
        for wp in ("0", "16"):
            _write(os.path.join(s, "riscv64.wp%s" % wp,
                                "corpus_mech_riscv64.tsv"), [])
        rc = main(["--sled", s, "--isa", "riscv64"])
        if rc != 2:
            fails.append("arm4 an empty corpus must REFUSE, got rc=%d" % rc)

        # ARM 5 THE WRONG FILE.  Pointed at the READ-LIST corpus -- four
        # columns, no decode id, no OPC -- the census must refuse rather than
        # score column 19 of a file that has none.
        s = os.path.join(d, "wrong")
        for wp in ("0", "16"):
            _write(os.path.join(s, "aarch64.wp%s" % wp,
                                "corpus_mech_aarch64.tsv"),
                   ["aarch64\td503201f\tnop\tREG_PC\n"],
                   head="#isa\tencoding\tmnem\tsrc\n")
        rc = main(["--sled", s, "--isa", "aarch64"])
        if rc != 2:
            fails.append("arm5 the wrong corpus must REFUSE, got rc=%d" % rc)

    for f in fails:
        print("enumocc SELFTEST FAIL: %s" % f)
    print("enumocc selftest: %d check(s), %d failure(s)" % (5, len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
