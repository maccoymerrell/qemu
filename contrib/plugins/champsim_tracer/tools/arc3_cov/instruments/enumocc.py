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

THE KEY STATES ITSELF, AND THE OLD ANSWER WAS AN INFERENCE.  This census
used to decide "the enum table answered" from two columns -- `decode_id` is
zero AND the published opcode is a class.  That is not the condition the `if`
above tests.  Its actual condition is "QEMU's identity answered NOTHING, and
the decode id is zero, and the table holds a row", and an encoding for which
`qemu_ident_classify()` answers DESPITE a zero decode id satisfies the
inference while the enum table answered nothing at all.  Counted as an
occupant it makes the retirement look more expensive than it is, which is the
direction that keeps a dead table alive.  The plugin now states the key on
every corpus row (column 26, `IDK`: QEMU / ENUM / NONE), so the occupancy is
read from the statement.  Both numbers are reported -- STATED and what the
old INFERENCE would have said -- because the difference is the finding.

A corpus swept before the column existed is scored on the inference and SAYS
`key=INFERRED`.  It is not refused: the sweep is hours and the inference is
an upper bound, which is the safe direction for a bound.  It is also not
quotable as the occupancy.

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

#: The STATED identity key, column 26, added so this census reads the
#: condition instead of a coincidence (see THE KEY STATES ITSELF, below).
#: Optional: a corpus swept before the column existed is still scorable, and
#: says INFERRED rather than pretending to a statement it does not carry.
MECH_HEAD_25 = "IDK"

#: The opcode spellings that are NOT a classification.  `GEN_OP_UNKNOWN` is
#: what classify_insn_id() publishes when neither key answered; "-" and "" are
#: the corpus's own empty cells.
NO_CLASS = ("GEN_OP_UNKNOWN", "-", "")


class Refused(Exception):
    """A census that cannot look reports that, never a zero."""


def _open(path):
    """A banked corpus is COMPRESSED, and that must not read as absent.

    The mechanism corpus is gigabytes per ISA and the disk discipline
    compresses it the moment it has been scored.  A census that refused a
    corpus it could have read would send the next pass off to re-sweep for
    a file that is sitting right there, so `.zst` and `.xz` are opened as
    themselves.  `zstandard` is not a dependency: the command-line `zstd`
    is what wrote the file and is what reads it back.
    """
    if path.endswith(".zst"):
        import subprocess
        p = subprocess.Popen(["zstd", "-dc", path], stdout=subprocess.PIPE,
                             universal_newlines=True, errors="replace")
        return p.stdout
    if path.endswith(".xz"):
        import lzma
        return lzma.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def _resolve(path):
    """The plain name, or the compressed one beside it.  None if neither."""
    for p in (path, path + ".zst", path + ".xz"):
        if os.path.isfile(p):
            return p
    return None


def _check_header(path):
    """Refuse a file that is not the mech corpus; report whether it STATES."""
    with _open(path) as f:
        head = f.readline().rstrip("\n").split("\t")
    if (len(head) < 19 or head[0] != MECH_HEAD_0
            or head[3] != MECH_HEAD_3 or head[18] != MECH_HEAD_18):
        raise Refused("%s is not a mechanism corpus -- its header is %r"
                      % (path, head[:5]))
    return len(head) > 25 and head[25] == MECH_HEAD_25


class Scored(object):
    """One arm's answer, both ways, so the difference stays visible."""

    def __init__(self, stated):
        self.stated = stated      # does the corpus carry the IDK column
        self.rows = 0
        self.zero = 0             # rows with decode_id == 0
        self.named = []           # OCCUPANTS: the key the plugin stated
        self.inferred = []        # what decode_id==0 + a class would say
        self.qemu_at_zero = 0     # decode_id==0 and QEMU's identity answered


def score_file(path):
    """Score one arm's mechanism corpus.  Returns a Scored."""
    real = _resolve(path)
    if real is None:
        raise Refused("no corpus at %s (nor .zst / .xz beside it)" % path)
    path = real
    sc = Scored(_check_header(path))
    with _open(path) as f:
        f.readline()
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 19:
                continue
            sc.rows += 1
            if c[3] != "00000000":
                continue
            sc.zero += 1
            if c[18] in NO_CLASS:
                continue
            # THE INFERENCE, kept and reported rather than deleted: it is
            # what every reading before the IDK column said, and the two
            # numbers together are what makes the correction checkable.
            sc.inferred.append((c[1], c[2], c[18]))
            if not sc.stated:
                sc.named.append((c[1], c[2], c[18]))
                continue
            key = c[25] if len(c) > 25 else "-"
            if key == "ENUM":
                sc.named.append((c[1], c[2], c[18]))
            elif key == "QEMU":
                sc.qemu_at_zero += 1
    if sc.rows == 0:
        raise Refused("%s carries no data rows -- a corpus with no subject "
                      "cannot report an occupancy" % path)
    return sc


def score_isa(sled, isa, wps):
    out = []
    merged = {}
    inferred = {}
    stated_all = True
    for wp in wps:
        p = os.path.join(sled, "%s.wp%s" % (isa, wp),
                         "corpus_mech_%s.tsv" % isa)
        sc = score_file(p)
        stated_all = stated_all and sc.stated
        out.append("%s wp%s rows=%d decode_id0=%d enum-answered=%d "
                   "inference=%d qemu_answered_at_zero_id=%d key=%s"
                   % (isa, wp, sc.rows, sc.zero, len(sc.named),
                      len(sc.inferred), sc.qemu_at_zero,
                      "STATED" if sc.stated else "INFERRED"))
        for enc, mnem, opc in sc.named:
            merged.setdefault(enc, (mnem, opc))
        for enc, mnem, opc in sc.inferred:
            inferred.setdefault(enc, (mnem, opc))
    return out, merged, inferred, stated_all


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
    total_inf = 0
    all_stated = True
    lines = []
    for isa in isas:
        try:
            per, merged, inferred, stated = score_isa(a.sled, isa, wps)
        except Refused as e:
            lines.append("%s REFUSED-TO-SCORE -- %s" % (isa, e))
            rc = 2
            continue
        lines.extend(per)
        all_stated = all_stated and stated
        lines.append("%s TOTAL enum-answered encodings=%d "
                     "(inference would say %d) key=%s"
                     % (isa, len(merged), len(inferred),
                        "STATED" if stated else "INFERRED"))
        total += len(merged)
        total_inf += len(inferred)
        if a.out:
            with open(os.path.join(a.out, "%s.occ.tsv" % isa), "w") as f:
                f.write("#key\t%s\n" % ("STATED" if stated else "INFERRED"))
                f.write("#isa\tencoding\tmnemonic\tpublished_opcode\n")
                for enc in sorted(merged):
                    mnem, opc = merged[enc]
                    f.write("%s\t%s\t%s\t%s\n" % (isa, enc, mnem, opc))
            # THE DIFFERENCE, NAMED.  Encodings the inference credited to
            # the enum table that the plugin says it did not answer for.
            gone = sorted(set(inferred) - set(merged))
            with open(os.path.join(a.out, "%s.notocc.tsv" % isa), "w") as f:
                f.write("#isa\tencoding\tmnemonic\tpublished_opcode"
                        "\t# inference-only, another key answered\n")
                for enc in gone:
                    mnem, opc = inferred[enc]
                    f.write("%s\t%s\t%s\t%s\n" % (isa, enc, mnem, opc))
    lines.append("ENUM-OCCUPANCY total=%d inference_total=%d key=%s rc=%d"
                 % (total, total_inf,
                    "STATED" if all_stated else "INFERRED", rc))
    text = "\n".join(lines)
    print(text)
    if a.out:
        with open(os.path.join(a.out, "OCC.txt"), "w") as f:
            f.write(text + "\n")
    return rc


# ------------------------------------------------------------------ selftest
_HEAD_NOKEY = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate"
               "\tPUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR"
               "\tPUBD\tWSTQ\tOPC\tBR\tCFLAGS\tREFINE\tLANEK\tLANEP"
               "\tWRU\n")
_HEAD = _HEAD_NOKEY.rstrip("\n") + "\tIDK\n"


def _row(enc, mnem, did, opc, key="ENUM"):
    """One corpus row.  @key is the STATED identity key (column 26)."""
    c = ["isa", enc, mnem, did] + ["-"] * 14 + [opc] + ["-"] * 6
    if key is not None:
        c.append(key)
    return "\t".join(c) + "\n"


def _write(path, rows, head=_HEAD):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(head)
        for r in rows:
            f.write(r)


def selftest():
    """Every arm prints its own line, and the count is the lines.

    The instrument roll-up (`selftest_all.sh`) scores a selftest by counting
    its arms, and it reported this one as ASSERTS NOTHING for as long as it
    existed -- six checks, three of them REFUSE arms, none of them spelled in
    a grammar the counter knew (FINDING 97-B).  A green whose subject was
    never established is the failure this tree files against everywhere else,
    so the arms say `ok` one per line, a failure says FAIL instead, and the
    summary count is the number of arms actually run rather than a literal.
    """
    import tempfile
    fails = []
    arms = [0]

    def ck(name, bad=None):
        """One arm, one line.  `bad` is the message when it failed."""
        arms[0] += 1
        if bad:
            fails.append(bad)
            print("  ARM %s FAIL -- %s" % (name, bad))
        else:
            print("  ARM %s ok" % name)

    with tempfile.TemporaryDirectory() as d:
        # ARM 1 CLEAN ZERO.  Every row carries an identity, so the enum table
        # answers for nothing and the census must say 0 -- and must not
        # refuse, because this is the RESULT the deletion is aiming at.
        s = os.path.join(d, "clean")
        for wp in ("0", "16"):
            _write(os.path.join(s, "x86_64.wp%s" % wp, "corpus_mech_x86_64.tsv"),
                   [_row("90", "nop", "00000123", "GEN_OP_NOP", "QEMU"),
                    _row("31c0", "xorl", "00000456", "GEN_OP_XOR", "QEMU")])
        rc = main(["--sled", s, "--isa", "x86_64"])
        ck("1 clean-zero", None if rc == 0 else
           "a clean corpus must score 0, not refuse (rc=%d)" % rc)

        # ARM 2 THE OCCUPANT.  One row with no identity and a class from the
        # enum table.  The census must NAME it; a census that cannot go
        # non-zero is not a census.
        s = os.path.join(d, "occ")
        for wp in ("0", "16"):
            _write(os.path.join(s, "mipsel.wp%s" % wp, "corpus_mech_mipsel.tsv"),
                   [_row("00000000", "nop", "00000123", "GEN_OP_NOP", "QEMU"),
                    _row("45800000", "bz.v", "00000000", "GEN_OP_BRANCH",
                         "ENUM")])
        o = os.path.join(d, "occout")
        rc = main(["--sled", s, "--isa", "mipsel", "--out", o])
        ck("2a occupant-scores", None if rc == 0 else
           "a corpus with an occupant must still score rc=0, got %d" % rc)
        got = open(os.path.join(o, "mipsel.occ.tsv")).read()
        ck("2b occupant-named",
           None if ("45800000" in got and "bz.v" in got)
           else "the occupant was not NAMED: %r" % got)
        ck("2c identity-not-counted",
           "a row WITH an identity was counted as an occupant"
           if "00000000\tnop" in got else None)

        # ARM 3 THE ABSENT CORPUS.  A missing arm must REFUSE.  This is the
        # shape every zero in this tree has to survive: a census pointed at
        # nothing reads 0 unless it is built not to.
        rc = main(["--sled", os.path.join(d, "nothing"), "--isa", "x86_64"])
        ck("3 absent-refuses", None if rc == 2 else
           "a missing corpus must REFUSE, got rc=%d" % rc)

        # ARM 4 THE EMPTY CORPUS.  Header present, no rows: also a refusal,
        # for the same reason and by a different route.
        s = os.path.join(d, "empty")
        for wp in ("0", "16"):
            _write(os.path.join(s, "riscv64.wp%s" % wp,
                                "corpus_mech_riscv64.tsv"), [])
        rc = main(["--sled", s, "--isa", "riscv64"])
        ck("4 empty-refuses", None if rc == 2 else
           "an empty corpus must REFUSE, got rc=%d" % rc)

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
        ck("5 wrong-file-refuses", None if rc == 2 else
           "the wrong corpus must REFUSE, got rc=%d" % rc)

        # ARM 6 THE BANKED CORPUS.  The same corpus as arm 2, compressed the
        # way the disk discipline compresses it once it has been scored.  It
        # must read THE SAME, not refuse -- a census that cannot read the
        # bank sends the next pass off to re-sweep a file that is right
        # there.
        s = os.path.join(d, "zst")
        for wp in ("0", "16"):
            f = os.path.join(s, "mipsel.wp%s" % wp, "corpus_mech_mipsel.tsv")
            _write(f, [_row("00000000", "nop", "00000123", "GEN_OP_NOP",
                            "QEMU"),
                       _row("45800000", "bz.v", "00000000", "GEN_OP_BRANCH",
                            "ENUM")])
            import subprocess
            if subprocess.call(["zstd", "-q", "--rm", f]) != 0:
                ck("6a fixture-compressed",
                   "could not compress the fixture -- no zstd?")
        o = os.path.join(d, "zstout")
        rc = main(["--sled", s, "--isa", "mipsel", "--out", o])
        ck("6b banked-scores", None if rc == 0 else
           "a compressed corpus must score, not refuse (rc=%d)" % rc)
        if rc == 0:
            got = open(os.path.join(o, "mipsel.occ.tsv")).read()
            ck("6c banked-occupant-kept", None if "45800000" in got else
               "the occupant was lost under compression: %r" % got)

        # ARM 7 THE CORRECTION ITSELF.  A row with a ZERO decode id whose
        # published class came from QEMU's identity satisfies the old
        # inference and is NOT an occupant.  The census must exclude it,
        # must still report what the inference would have said, and must
        # name it in the not-occupant table -- a correction nobody can see
        # is a number changing for no stated reason.
        s = os.path.join(d, "zerokey")
        for wp in ("0", "16"):
            _write(os.path.join(s, "x86_64.wp%s" % wp,
                                "corpus_mech_x86_64.tsv"),
                   [_row("0f0b", "ud2", "00000000", "GEN_OP_TRAP", "QEMU"),
                    _row("f30f01e8", "setssbsy", "00000000", "GEN_OP_OTHER",
                         "ENUM")])
        o = os.path.join(d, "zerokeyout")
        rc = main(["--sled", s, "--isa", "x86_64", "--out", o])
        ck("7a stated-scores", None if rc == 0 else
           "a stated corpus must score, got rc=%d" % rc)
        got = open(os.path.join(o, "x86_64.occ.tsv")).read()
        ck("7b enum-row-kept", None if "f30f01e8" in got else
           "the ENUM-keyed occupant was dropped: %r" % got)
        ck("7c qemu-row-excluded",
           "a zero-decode-id row QEMU answered for was counted as an "
           "occupant: %r" % got if "0f0b" in got else None)
        notocc = open(os.path.join(o, "x86_64.notocc.tsv")).read()
        ck("7d correction-named", None if "0f0b" in notocc else
           "the inference-only row was not named: %r" % notocc)
        ck("7e both-numbers-reported", None
           if "TOTAL enum-answered encodings=1 (inference would say 2)"
           in open(os.path.join(o, "OCC.txt")).read()
           else "the inference's own answer was not reported beside it")

        # ARM 8 A CORPUS FROM BEFORE THE COLUMN.  Scored on the inference,
        # an upper bound, and it must SAY so rather than pass itself off
        # as a statement.
        s = os.path.join(d, "nokey")
        for wp in ("0", "16"):
            _write(os.path.join(s, "mipsel.wp%s" % wp,
                                "corpus_mech_mipsel.tsv"),
                   [_row("45800000", "bz.v", "00000000", "GEN_OP_BRANCH",
                         None)],
                   head=_HEAD_NOKEY)
        o = os.path.join(d, "nokeyout")
        rc = main(["--sled", s, "--isa", "mipsel", "--out", o])
        ck("8a old-corpus-scores", None if rc == 0 else
           "a corpus without the key column must score, got rc=%d" % rc)
        txt = open(os.path.join(o, "OCC.txt")).read()
        ck("8b says-inferred", None if "key=INFERRED" in txt else
           "an inferred answer did not say so: %r" % txt)

    for f in fails:
        print("enumocc SELFTEST FAIL: %s" % f)
    print("enumocc selftest: %d check(s), %d failure(s)" % (arms[0], len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
