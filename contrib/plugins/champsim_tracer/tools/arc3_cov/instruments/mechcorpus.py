#!/usr/bin/env python3
"""THE MECHANISM CORPUS READER, IN ONE PLACE -- FINDING 99-F.

`srcenc_sled.py` writes `corpus_mech_<isa>.tsv` with a `#`-prefixed COLUMN
HEADER, and since `1291bba8ab` it writes TWO `#`-prefixed STAMP lines above
that header:

    #tip   <sha>              clean|dirty
    #so    <plugin-sha>       <emulator-sha>
    #isa   encoding  mnem  decode_id  rule  src_state  ...

Nine instruments in this directory bound the header to "the FIRST `#` line",
which was correct until that commit and silently wrong after it.  What they
bound instead is `['tip', '<sha>', 'clean']`, a three-column header, and
every data row then became `{'tip': isa, '<sha>': encoding, 'clean': mnem}`.
`srcbar.py` died on `KeyError: 'src_state'`, `dstbar.py` on `KeyError:
'PUBD'`, and `barscore.sh` refused at precondition because neither bar wrote
its family table.  The source bar and the destination bar -- two numbers the
standing records quote -- had no value at all, for three commits.

THE SELFTESTS COULD NOT SEE IT, AND THAT IS THE SHARPER HALF.  Each of those
instruments builds its own fixture corpus, and every fixture wrote the column
header as the file's FIRST line -- the shape the sled had stopped producing.
A fixture that does not look like the artefact is a fixture that cannot fail
for the artefact's reasons, which is the same survivorship shape this tree
files against enumerated zeros.  So `_arm()` below writes the stamps, every
caller's fixture goes through it, and arm E proves the reader still finds the
header underneath them.

THE RULE THIS FILE ENFORCES, so the next stamp cannot repeat it:

  * The header is the `#` line whose FIRST field is `isa` -- identified by
    CONTENT, not by position.  A stamp line is skipped whatever it is called,
    so a third stamp is not a fourth outage.
  * A corpus with no such line is a REFUSAL naming the file, never an empty
    read.  Rows silently skipped for want of a header is how a bar reports
    zero families and a census reports a clean sweep.
  * A column the caller needs and the header does not carry is a REFUSAL
    naming the column and the reason the caller gave -- raised BEFORE the row
    loop indexes it, so the failure is the sentence and not a KeyError three
    frames down.

Usage:  from mechcorpus import read_mech_corpus
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evopen import evopen, resolve                      # noqa: E402

#: The mechanism corpus's column header begins with this field.  It is the
#: ISA column's name and it has been since the corpus existed; the stamps
#: above it are keyed `tip` and `so`.
HDR_FIRST = "isa"


def is_header(line):
    """True for the corpus COLUMN HEADER, false for a `#tip`/`#so` stamp."""
    if not line.startswith("#"):
        return False
    return line.lstrip("#").rstrip("\n").split("\t")[0] == HDR_FIRST


def parse_header(line):
    return line.lstrip("#").rstrip("\n").split("\t")


def stamp(paths, key):
    """The value of a `#<key>` stamp line, or None.  First file that has it."""
    if isinstance(paths, str):
        paths = [paths]
    for p in paths:
        with evopen(p, errors="replace") as f:
            for line in f:
                if not line.startswith("#"):
                    break
                c = line.lstrip("#").rstrip("\n").split("\t")
                if c[0] == key:
                    return c[1:]
    return None


def read_mech_corpus(paths, need=(), differs=None, max_examples=8,
                     key=1, label="mech-corpus"):
    """Merge `corpus_mech_<isa>.tsv` files -> (rows, conflicts, examples, hdr).

    `rows` maps the `key`-th column (the encoding) to that row as a dict.
    `need` is an iterable of column names, or of (column, reason) pairs; each
    is required of the bound header and its absence is a refusal carrying the
    reason.  `differs(prev, row)` decides what counts as a wp-arm conflict;
    the default is whole-row inequality.  Up to `max_examples` conflicting
    pairs are returned for the caller to print.

    REFUSES rather than returning a partial read.  Every failure names the
    file, because a bar that reports on the wrong corpus and a bar that
    reports on none read the same from the outside.
    """
    if isinstance(paths, str):
        paths = [paths]
    if differs is None:
        differs = lambda a, b: a != b            # noqa: E731
    wants = [(n, "") if isinstance(n, str) else (n[0], n[1]) for n in need]

    d, conf, confex = {}, 0, []
    hdr = None
    for p in paths:
        # NAMED, NOT TRACEBACKED.  `evopen` resolves a compressed sibling, so
        # the question is whether EITHER exists; when neither does, a caller
        # reading this refusal knows which corpus it wanted, which a
        # FileNotFoundError three frames down does not say.
        if not os.path.exists(resolve(p)):
            sys.exit("%s: %s missing -- REFUSING (no compressed sibling "
                     "either)" % (label, p))
        with evopen(p, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    if hdr is None and is_header(line):
                        hdr = parse_header(line)
                        for col, why in wants:
                            if col not in hdr:
                                sys.exit(
                                    "%s: %s has no `%s` column -- REFUSING%s"
                                    % (label, p, col,
                                       (" (%s)" % why) if why else ""))
                    continue
                if hdr is None:
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < len(hdr):
                    continue
                row = dict(zip(hdr, c))
                prev = d.get(c[key])
                if prev is not None and differs(prev, row):
                    conf += 1
                    if len(confex) < max_examples:
                        confex.append((c[key], prev, row))
                d[c[key]] = row
    if hdr is None:
        sys.exit(
            "%s: no column header in %s -- REFUSING.  The mechanism corpus "
            "carries `#tip` and `#so` STAMPS above its `#%s\\t...` header "
            "(srcenc_sled.py); a reader that takes the first `#` line binds "
            "the stamp and then skips every row, which reads as an empty "
            "corpus rather than as the refusal it is (FINDING 99-F)."
            % (label, ", ".join(paths), HDR_FIRST))
    return d, conf, confex, hdr


# ------------------------------------------------------------------ selftest
MECH_HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\t"
            "PUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\t"
            "WSTQ\tOPC\tBR\tCFLAGS\tREFINE\tLANEK\tLANEP\tWRU\n")

#: THE TWO LINES srcenc_sled.py PUTS ABOVE THE HEADER.  Every instrument's
#: own fixture writer emits these, because a fixture that does not look like
#: the artefact cannot fail for the artefact's reasons -- which is exactly
#: how nine instruments carried FINDING 99-F with green selftests.  The
#: values are fictional and deliberately so: nothing may join on them.
FIXTURE_STAMP = ("#tip\t0123456789abcdef0123456789abcdef01234567\tclean\n"
                 "#so\tfixtureplug\tfixtureemu\n")

#: THE FIXTURE WRITER EVERY INSTRUMENT'S SELFTEST GOES THROUGH.  It emits the
#: stamps because the sled emits them; a fixture shaped like the artefact is
#: the only kind that can fail for the artefact's reasons.  `stamps=False`
#: exists ONLY so an arm can prove the reader still refuses a corpus that
#: carries no header at all.
def write_fixture(path, rows, hdr=MECH_HDR, stamps=True,
                  tip="0123456789abcdef", so=("plugsha", "emusha")):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        if stamps:
            f.write("#tip\t%s\tclean\n" % tip)
            f.write("#so\t%s\t%s\n" % so)
        if hdr:
            f.write(hdr)
        for r in rows:
            f.write("\t".join(r) + "\n")
    return path


def _row(enc, **kw):
    names = MECH_HDR.lstrip("#").rstrip("\n").split("\t")
    base = dict.fromkeys(names, "-")
    base["isa"] = "x86_64"
    base["encoding"] = enc
    base["mnem"] = "m" + enc
    kw and base.update(kw)
    return [base[n] for n in names]


def selftest(tmp):
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    checks, fails = 0, 0

    def ok(label, cond):
        nonlocal checks, fails
        checks += 1
        if cond:
            print("  %s ok" % label)
        else:
            print("  %s FAILED" % label)
            fails += 1

    def refuses(label, fn, needle):
        nonlocal checks, fails
        checks += 1
        try:
            fn()
        except SystemExit as e:
            msg = str(e)
            if needle in msg:
                print("  %s ok" % label)
                return
            print("  %s FAILED -- refused with %r, wanted %r"
                  % (label, msg, needle))
        else:
            print("  %s FAILED -- did not refuse" % label)
        fails += 1

    # A -- THE STAMPED CORPUS, which is what the sled writes today.  This is
    # the arm that was missing everywhere and is the whole finding.
    p = write_fixture(os.path.join(tmp, "a", "corpus_mech_x86_64.tsv"),
                      [_row("aa", src_state="S", PUBD="REG_A"),
                       _row("bb", src_state="T", PUBD="REG_B")])
    rows, conf, _, hdr = read_mech_corpus([p], need=("src_state", "PUBD"))
    ok("A  a STAMPED corpus binds the `#isa` header, not `#tip`",
       hdr[0] == "isa" and len(rows) == 2
       and rows["aa"]["src_state"] == "S" and rows["bb"]["PUBD"] == "REG_B")

    # B -- the UNSTAMPED shape, which every pre-1291bba8ab corpus has and
    # which must keep working: this reader is content-directed, so the stamps
    # are optional rather than required.
    p = write_fixture(os.path.join(tmp, "b", "corpus_mech_x86_64.tsv"),
                      [_row("aa", src_state="S")], stamps=False)
    rows, _, _, hdr = read_mech_corpus([p], need=("src_state",))
    ok("B  an UNSTAMPED corpus still reads, header unchanged",
       hdr[0] == "isa" and rows["aa"]["src_state"] == "S")

    # C -- NO HEADER AT ALL is a refusal, not an empty read.  This is the
    # direction the old reader failed in: it returned {} and let the caller
    # print a zero.
    p = write_fixture(os.path.join(tmp, "c", "corpus_mech_x86_64.tsv"),
                      [_row("aa")], hdr=None)
    refuses("C  a corpus with NO header REFUSES rather than reading empty",
            lambda: read_mech_corpus([p]), "no column header")

    # D -- a column the caller needs and the header lacks is refused BEFORE
    # the row loop, with the caller's own reason in the message.
    short = "#isa\tencoding\tmnem\n"
    p = write_fixture(os.path.join(tmp, "d", "corpus_mech_x86_64.tsv"),
                      [["x86_64", "aa", "maa"]], hdr=short)
    refuses("D  a MISSING needed column refuses with the caller's reason",
            lambda: read_mech_corpus(
                [p], need=(("PUBD", "the arm predates the column"),)),
            "the arm predates the column")

    # E -- the exact 99-F artefact: stamps present, and the FIRST `#` line is
    # `#tip`.  Bound naively the header is 3 columns wide and every row
    # parses into it.  Proven by measuring what the naive rule would give.
    p = write_fixture(os.path.join(tmp, "e", "corpus_mech_x86_64.tsv"),
                      [_row("aa", src_state="S")])
    with evopen(p) as f:
        first_hash = next(l for l in f if l.startswith("#"))
    naive = parse_header(first_hash)
    rows, _, _, hdr = read_mech_corpus([p], need=("src_state",))
    ok("E  the naive first-`#` rule binds `tip`; this reader binds `isa`",
       naive[0] == "tip" and len(naive) == 3
       and hdr[0] == "isa" and len(hdr) == 25
       and rows["aa"]["src_state"] == "S")

    # F -- wp-arm merge: the LAST file wins and a disagreement is counted,
    # with the caller's own `differs` deciding what disagreement means.
    p0 = write_fixture(os.path.join(tmp, "f", "wp0.tsv"),
                       [_row("aa", PUBD="REG_A"), _row("bb", PUBD="REG_B")])
    p16 = write_fixture(os.path.join(tmp, "f", "wp16.tsv"),
                        [_row("aa", PUBD="REG_Z"), _row("bb", PUBD="REG_B")])
    rows, conf, ex, _ = read_mech_corpus(
        [p0, p16], differs=lambda a, b: a["PUBD"] != b["PUBD"])
    ok("F  a wp-arm disagreement is COUNTED and exemplified",
       conf == 1 and len(ex) == 1 and ex[0][0] == "aa"
       and rows["aa"]["PUBD"] == "REG_Z")

    # G -- and the same pair with a differs() that ignores PUBD reports NO
    # conflict, so arm F's 1 is the predicate's and not an artefact of the
    # merge.  A counter with no zero arm is not a counter.
    _, conf0, _, _ = read_mech_corpus(
        [p0, p16], differs=lambda a, b: a["mnem"] != b["mnem"])
    ok("G  the conflict count follows the CALLER's predicate (0 arm)",
       conf0 == 0)

    # H -- a missing file is the reader's refusal, not a traceback.
    refuses("H  a missing corpus REFUSES by name",
            lambda: read_mech_corpus([os.path.join(tmp, "nope.tsv")]),
            "nope.tsv")

    # I -- the stamp accessor reads through the header, both keys.
    ok("I  the `#so` stamp is readable past `#tip`",
       stamp(p, "so") == ["plugsha", "emusha"]
       and stamp(p, "tip")[0] == "0123456789abcdef"
       and stamp(p, "nosuch") is None)

    print("mechcorpus selftest: %d check(s), %d failure(s)" % (checks, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--tmp", default="/tmp/mechcorpus_selftest")
    a = ap.parse_args()
    if a.selftest:
        raise SystemExit(selftest(a.tmp))
    ap.error("nothing to do without --selftest")
