#!/usr/bin/env python3
"""THE DESTINATION-SIDE BAR (#232): what the source-list flip costs and gains.

IN THE TREE BECAUSE A SCORER EACH PASS COPIES IS A SCORER EACH PASS CAN
EDIT.  This ran for nine passes as a frozen copy inside a wave root, and the
ledger those copies produced carries a two-register discrepancy nobody could
settle -- not because the measurement was wrong but because the per-register
tables were cut to their top eight rows with no marker, and at the aarch64
base arm the eighth row is 1,185.  Every register below that read as zero.
FINDING 66V-C: "whether REG_FLAGS read 82 or 84 at the base is NOT READABLE
from the banked evidence."  Same reason bc9d3c24df moved the R17.3 oracle in
here.  Landed from exec114/bardst.py with the truncation fixed and nothing
else changed.

The source-side bar is a two-ARM measurement: tip against the banked deletion,
because the source flip has already landed and the deletion is what shows
which registers the Capstone operand walk still supplies.

The destination side has no such pair yet.  Deleting the walk's WRITE arm
today does not produce "the wire without the walk" -- it produces a wire with
NO destination list at all, because nothing else fills dst_regs[].  An arm
like that measures the absence of a replacement, not the cost of one.

So the destination bar is computed from ONE arm, on the pair of columns that
now sit on the same row:

    PUBD   the wire's destination dictionary -- what dst_regs[] carries
    WR     QEMU's write list for the same instruction, by generic name

    WALK-ONLY  = PUBD - WR   the flip's COST: destinations the operand walk
                             supplies that QEMU does not state.  Every one is
                             a register the wire would lose.
    QEMU-ONLY  = WR - PUBD   the flip's GAIN: destinations QEMU states that
                             the walk never had.

R10.1 IS APPLIED TO THE GAIN SIDE AND NAMED.  QEMU charges a translation
block's final pc write to whichever instruction the block ended on, so WR
carries REG_PC on instructions the ISA does not define as writing it.
reseat_dst_for_qemu() drops exactly that case -- REG_PC in QEMU's list when
the wire's list has none -- and this scorer drops it in the same place, and
counts it separately so the size of the carve-out is a number and not a
silence.

Reach is the tree's own structural discriminator, unchanged: a bar computed
over encodings QEMU never decoded, or decoded only an enable check for, is
not a bar.
"""
import argparse, collections, os, sys


#: EVERY REGISTER, OR A STATED CAP AND AN OVERFLOW MARKER -- never a silent
#: cut.
#:
#: The per-wave copies of this scorer printed `counter.most_common(8)` for
#: each per-register table.  On the aarch64 base arm the eighth row is 1,185,
#: so every register below that read as ABSENT, and the ledger's own
#: reconciliation recorded `REG_FLAGS 0 -> 84` when 0 was the truncation and
#: not a measurement.  FINDING 66V-C could not settle a two-register
#: discrepancy from the banked evidence for exactly this reason: "whether
#: REG_FLAGS read 82 or 84 at the base is NOT READABLE from the banked
#: evidence."
#:
#: A per-register table is small -- the register file is the bound -- so the
#: default is ALL OF IT.  `--regtop N` caps it, and a capped table prints
#: what it dropped, by count and by sum, so a reader can always tell a zero
#: from a cut.
#: A TIE MUST NOT DEPEND ON WHICH RUN THIS IS.
#:
#: `walk_only` and `qemu_only` are frozenset differences, and iterating a set
#: of strings visits them in an order that changes with the interpreter's hash
#: seed -- so the Counters below were filled in a different order every run,
#: and `most_common()` (a stable sort) carried that order into every tie.
#: Measured: two runs of this scorer over ONE unchanged corpus differ, at
#: `REG_ACC0`/`REG_ACCHI0` both reading 24 and at two `addu_s.qb` rule rows.
#: Nothing about the BAR moves -- every count is identical -- but a bar whose
#: text is not reproducible cannot be diffed against the bar of another arm,
#: which is the only way this scorer is ever used.
#:
#: Both ends are closed: the set iterations are sorted at the point of
#: counting, and every table below orders by (-count, key) so a tie is
#: settled by the name and never by insertion history.
def ordered(counter, cap=0):
    rows = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return rows[:cap] if cap else rows


def print_regtable(counter, indent, cap):
    rows = ordered(counter)
    shown = rows if not cap else rows[:cap]
    for r, n in shown:
        print("%s%-16s %8d" % (indent, r, n))
    rest = rows[len(shown):]
    if rest:
        print("%s... %d further register(s) totalling %d NOT SHOWN "
              "(--regtop %d); the smallest shown is %d"
              % (indent, len(rest), sum(n for _, n in rest), cap,
                 shown[-1][1] if shown else 0))
    elif not rows:
        print("%s(none)" % indent)
sys.path.insert(0, "/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/"
                   "arc3_cov/instruments")
import srcenc_reach
# THE MECH CORPUS MAY BE COMPRESSED, AND THIS SCORER USED TO CALL THAT
# MISSING.  A mech corpus is 12G of text per pass and the disk rule says
# archive it; `open()` on the uncompressed name then finds nothing and the
# arm refuses with "corpus_mech_<isa>.tsv missing", which is the right
# behaviour and the wrong capability -- the evidence a bar was derived from
# becomes unreadable the moment it is stored the way it must be stored.
# `bar.py` has read through a sweep since evopen landed; this one did not,
# and the two read the same files.
from evopen import evopen, resolve


#: THE REFUSAL SET, joined from an arm that carries it.
#:
#: Adding a reach class means BOTH ends of the trajectory must be re-derived
#: on the NEW discriminator (the 49-B rule), and an arm captured before
#: insn_dataflow_note_translation_refused() existed carries no `refused` key
#: at all.  Joining just that ONE BIT from an arm that does carry it -- over
#: the same encoding population -- lets the base end be scored on the new
#: discriminator using its OWN register columns, which is what the rule asks
#: for.  It is legitimate because the statement is proven CAPTURE-ONLY: the
#: whole-population RD / WR / PUB / PUBD diff across the arm that added it is
#: 0 on all four ISAs, so nothing about the translation moved, only what the
#: target says about it.
def load_refused(arm, isa, wps):
    if not arm:
        return None
    out = set()
    can_answer = False
    for w in wps:
        p = os.path.join(arm, "%s.wp%s" % (isa, w), "corpus_mech_%s.tsv" % isa)
        if not os.path.exists(resolve(p)):
            sys.exit("refused-arm: %s missing -- REFUSING (no compressed "
                     "sibling either)" % p)
        with evopen(p, errors="replace") as f:
            hdr = None
            for line in f:
                if line.startswith("#"):
                    if hdr is None:
                        hdr = line.lstrip("#").rstrip().split("\t")
                    continue
                c = line.rstrip("\n").split("\t")
                if hdr is None or len(c) < len(hdr):
                    continue
                row = dict(zip(hdr, c))
                if "refused=" in row.get("XLAT", ""):
                    can_answer = True
                    if "refused=1" in row["XLAT"]:
                        out.add(c[1])
    if not can_answer:
        # The arm predates insn_dataflow_note_translation_refused(), so its
        # rows carry no `refused` key in EITHER direction.  That is a corpus
        # that cannot answer, and it must not read as a clean zero.  An arm
        # that CAN answer and finds none is a different fact -- riscv64
        # states nothing today -- and is returned as the empty set.
        sys.exit("refused-arm: %s carries no `refused` key for %s -- "
                 "REFUSING (a corpus that cannot answer must not read as a "
                 "clean zero)" % (arm, isa))
    return out


def classify_joined(row, refused):
    """srcenc_reach.classify(), with the refusal bit joined in first."""
    if (refused is not None and row["encoding"] in refused
            and "refused=" not in row.get("XLAT", "")):
        row = dict(row, XLAT=row.get("XLAT", "") + ",refused=1")
    return srcenc_reach.classify(row)

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")

#: state_name(QDEP_OK) -- the only WSTQ under which QEMU has stated a write
#: list COMPLETELY.  Most other values are a refusal, and a refusal is not an
#: empty list.
OKW = "PUBLISHED from QEMU's emitters"

#: state_name(QDEP_W_SHORT) -- the extraction reported itself incomplete and
#: QEMU stated a write list anyway.  IT IS NOT A REFUSAL AND IT IS NOT OKW,
#: and this scorer has to hold both halves of that at once:
#:
#:   THE GAIN SIDE IS SCORABLE.  QEMU-ONLY = WR - PUBD asks what the WIRE
#:   does not carry, and the wire's list is fully known.  Every member of a
#:   short list is a write QEMU's own emitters stated, so a gain counted here
#:   is a real destination the wire is missing -- the count can only be LOW.
#:
#:   THE COST SIDE IS NOT.  WALK-ONLY = PUBD - WR asks what QEMU does not
#:   state, which is precisely the sentence a short list is not entitled to:
#:   a register missing from the shortfall would be scored as a published
#:   destination QEMU disowns.  That is the direction that turns an absent
#:   measurement into a loss, which is the shape #231's 219x overstatement
#:   had, so these rows stay out of the loss bar and are reported apart.
WSHORT = "LOWER BOUND: extraction incomplete, QEMU's write list taken anyway"


def regs(s):
    return frozenset(r for r in s.split(",") if r and r != "-")


def read_mech_merged(paths):
    """encoding -> row; a wp-arm disagreement on PUBD or WR is a CONFLICT."""
    d, conf, confex = {}, 0, []
    hdr = None
    for p in paths:
        with evopen(p, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    if hdr is None:
                        hdr = line.lstrip("#").rstrip("\n").split("\t")
                    continue
                c = line.rstrip("\n").split("\t")
                if hdr is None or len(c) < len(hdr):
                    continue
                row = dict(zip(hdr, c))
                prev = d.get(c[1])
                if prev is not None and (regs(prev["PUBD"]) != regs(row["PUBD"])
                                         or regs(prev["WR"]) != regs(row["WR"])):
                    conf += 1
                    if len(confex) < 8:
                        confex.append((c[1], row.get("mnem"),
                                       prev["PUBD"], row["PUBD"],
                                       prev["WR"], row["WR"]))
                d[c[1]] = row
    return d, conf, confex, hdr



MECH_HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\t"
            "PUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\t"
            "WSTQ\tOPC\tBR\tCFLAGS\tREFINE\tLANEK\tLANEP\tWRU\n")
BODY  = "noret=0,calls=0,memr=0,memw=0,refused=0"


def _write_arm(root, isa, wp, rows, drop=()):
    d = os.path.join(root, "%s.wp%s" % (isa, wp))
    os.makedirs(d, exist_ok=True)
    hdr = MECH_HDR.lstrip("#").rstrip("\n").split("\t")
    keep = [i for i, h in enumerate(hdr) if h not in drop]
    with open(os.path.join(d, "corpus_mech_%s.tsv" % isa), "w") as f:
        f.write("#" + "\t".join(hdr[i] for i in keep) + "\n")
        for r in rows:
            cells = [isa, r["enc"], r.get("mnem", "m"), r.get("did", "aa"),
                     r.get("rule", "rule_x"), OKW, r.get("wstate", OKW),
                     "-", "-", "-", "-", "-", "-", "-",
                     r.get("xlat", BODY), r.get("WR", "-"),
                     r.get("PUBD", "-"), r.get("WSTQ", OKW),
                     "-", "-", "-", "-", "0", "0", r.get("WRU", "0")]
            f.write("\t".join(cells[i] for i in keep) + "\n")
    return d


def selftest(tmp):
    """FINDING 83-D.  This scorer prints the DESTINATION BAR -- a number the
    standing records quote -- and had never been asked to fail at anything.
    Each arm plants one defect the bar would otherwise absorb silently."""
    import shutil, subprocess
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    isa, wp = "riscv64", "0"
    arm = os.path.join(tmp, "arm")
    ROWS = [
        # the wire names a destination QEMU does not: the flip's COST
        dict(enc="01", mnem="cost", PUBD="R1,R9", WR="R1"),
        # QEMU names one the wire lacks: the flip's GAIN
        dict(enc="02", mnem="gain", PUBD="R2",    WR="R2,R8"),
        # agreement -- neither side
        dict(enc="03", mnem="same", PUBD="R3",    WR="R3"),
        # REG_PC on QEMU's side only: the R10.1 block-pc carve-out
        dict(enc="04", mnem="pc",   PUBD="R4",    WR="R4,REG_PC"),
        # a container write whose index QEMU could not state (FINDING 75-C)
        dict(enc="05", mnem="wru",  PUBD="R5",    WR="R5,R7", WRU="1"),
        # a lower-bound write list: GAIN ONLY, never a loss
        dict(enc="06", mnem="short", PUBD="R6,R9", WR="R6,R8", WSTQ=WSHORT),
        # a SECOND cost family, on a different register -- so the capped
        # table below has something to drop and the cap arm is not vacuous
        dict(enc="07", mnem="cost2", PUBD="R1,R10", WR="R1"),
    ]
    _write_arm(arm, isa, wp, ROWS)

    def run(*extra, root=None):
        return subprocess.run([sys.executable, __file__, "--a", root or arm,
                               "--isa", isa, "--wps", wp] + list(extra),
                              capture_output=True, text=True)

    fails = 0; n = 0
    def chk(cond, what):
        nonlocal fails, n
        n += 1
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    r = run()
    o = r.stdout
    chk(r.returncode == 0, "the scorer runs on a well-formed arm")
    chk("WALK-ONLY DESTINATIONS (the flip's COST): 2 encodings / 2 registers"
        in o, "COST is PUBD-minus-WR and counts the two cost rows, not the "
              "agreeing ones")
    chk("QEMU-ONLY DESTINATIONS (the flip's GAIN): 1 encodings / 1 registers"
        in o, "GAIN is WR-minus-PUBD, with the PC row carved out of it")
    chk("R10.1 block-pc carve-outs: 1]" in o,
        "a REG_PC the wire does not publish is CARVED OUT and counted, not "
        "scored as a gain")
    chk("INDEX NOT STATED" in o,
        "a container write with an unstated index is NOT SCORABLE "
        "(FINDING 75-C)")
    chk("R7" not in o.split("ON A LOWER-BOUND")[0],
        "and its member does not reach the cost or gain tables")
    chk("ON A LOWER-BOUND WRITE LIST (QDEP_W_SHORT), GAIN ONLY: 1 row(s), "
        "of which 1 encoding(s) / 1 register(s)" in o,
        "a lower-bound write list is scored for GAIN only")
    chk("R9" in o.split("WALK-ONLY")[1].split("QEMU-ONLY")[0],
        "the lower-bound row's R9 is NOT counted as a walk-only cost")

    # THE COLUMN GUARDS.  Each required column dropped in its own arm; each
    # drop must REFUSE.  A scorer that reads a renamed column as absent
    # prints a bar over nothing.
    for col, why in (("PUBD", "the wire's destination dictionary"),
                     ("WSTQ", "QEMU's own write verdict"),
                     ("WRU", "the unstated-index bit")):
        a2 = os.path.join(tmp, "drop_" + col)
        _write_arm(a2, isa, wp, ROWS, drop=(col,))
        r2 = run(root=a2)
        chk(r2.returncode != 0 and "REFUSING" in (r2.stdout + r2.stderr),
            "a corpus without %s REFUSES -- %s" % (col, why))

    # A CUT TABLE SAYS SO.
    r3 = run("--regtop", "1")
    chk("NOT SHOWN (--regtop 1)" in r3.stdout,
        "a capped register table prints what it dropped (FINDING 66V-C)")

    # A MISSING ARM REFUSES.
    r4 = run(root=os.path.join(tmp, "nothing"))
    chk(r4.returncode != 0 and "REFUSING" in (r4.stdout + r4.stderr),
        "a missing arm REFUSES; it is never a bar of zero")

    # DETERMINISM, the property the ordering comment claims.
    import os as _os
    e1 = dict(_os.environ, PYTHONHASHSEED="1")
    e2 = dict(_os.environ, PYTHONHASHSEED="12345")
    cmd = [sys.executable, __file__, "--a", arm, "--isa", isa, "--wps", wp]
    s1 = subprocess.run(cmd, capture_output=True, text=True, env=e1).stdout
    s2 = subprocess.run(cmd, capture_output=True, text=True, env=e2).stdout
    chk(s1 == s2 and s1 != "",
        "two hash seeds give ONE report, byte for byte")
    print("arms=%d failures=%d" % (n, fails))
    return 0 if fails == 0 else 1

def main():
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        tmp = (sys.argv[i + 1] if len(sys.argv) > i + 1
               and not sys.argv[i + 1].startswith("-")
               else "/tmp/dstbar_st")
        return selftest(tmp)
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="arm dir (the tip)")
    ap.add_argument("--isa", action="append", default=None)
    ap.add_argument("--wps", default="0 16")
    ap.add_argument("--top", type=int, default=14)
    #: 0 = every register.  See print_regtable() for why that is the default.
    ap.add_argument("--regtop", type=int, default=0)
    a = ap.parse_args()
    isas = a.isa or list(ISAS)
    wps = a.wps.split()

    G = dict(cost_enc=0, cost_reg=0, gain_enc=0, gain_reg=0,
             pc_carve=0, rows=0, ins=0)
    gcostreg = collections.Counter()
    ggainreg = collections.Counter()
    per_isa = {}

    for isa in isas:
        REFUSED = load_refused(os.environ.get("REFUSEDARM"), isa, wps)
        pm = [os.path.join(a.a, "%s.wp%s" % (isa, w),
                           "corpus_mech_%s.tsv" % isa) for w in wps]
        for p in pm:
            if not os.path.exists(resolve(p)):
                sys.exit("bardst: %s missing -- REFUSING (no compressed "
                         "sibling either)" % p)
        M, cm, cex, hdr = read_mech_merged(pm)
        if hdr is None or "PUBD" not in hdr or "WSTQ" not in hdr:
            sys.exit("bardst: %s has no PUBD/WSTQ column -- REFUSING (the arm "
                     "predates the columns and cannot answer)" % pm[0])
        # WRU IS REQUIRED, NOT OPTIONAL.  An arm captured before the column
        # existed cannot say which rows carry a container write with an
        # unstated index, and reading its absence as "none of them" is the
        # silent false success this file's own WSTQ refusal exists against:
        # the number it would print is the 6.7x bar FINDING 75-C explained.
        if "WRU" not in hdr:
            sys.exit("bardst: %s has no WRU column -- REFUSING (the arm "
                     "predates it, so a container write whose index QEMU "
                     "could not state is indistinguishable from a complete "
                     "write list; see FINDING 75-C)" % pm[0])

        costreg = collections.Counter(); costrule = collections.Counter()
        gainreg = collections.Counter(); gainrule = collections.Counter()
        cost_enc = gain_enc = pc_carve = 0
        cost_reg = gain_reg = 0
        cost_pub_enc = cost_pub_reg = gain_pub_enc = gain_pub_reg = 0
        byreach = collections.Counter()
        outbarreg = collections.Counter(); outbarrule = collections.Counter()
        outbar_enc = outbar_reg = 0
        unscorable = collections.Counter()
        wsreg = collections.Counter(); wsrule = collections.Counter()
        ws_rows = ws_enc = ws_reg = 0
        ins = 0; scor = 0
        for enc, row in M.items():
            reach, sub, _ = classify_joined(row, REFUSED)
            byreach[reach] += 1
            if reach != "INSTRUCTION":
                # STILL SCORED FOR THE ADMISSION, and only for it.  A
                # NO-DECODE row is outside the loss BAR by ruling -- QEMU
                # recorded no decode-table slot, so there is no statement a
                # published register can be missing FROM -- but QEMU can and
                # does state a WRITE for one (mipsel's DSP space translates
                # a Reserved Instruction raise and names the exception
                # state), and the seating admits it.  A wire change the bar
                # is blind to is exactly the thing this pass must not leave
                # unquoted.
                if row["WSTQ"] == OKW and row["wstate"] == OKW:
                    q = regs(row["WR"]) - regs(row["PUBD"])
                    if "REG_PC" in q and "REG_PC" not in regs(row["PUBD"]):
                        q = q - {"REG_PC"}
                    if q:
                        outbar_enc += 1; outbar_reg += len(q)
                        for r in q:
                            outbarreg[r] += 1
                            outbarrule[(row.get("rule", "?"),
                                        row.get("mnem", "?"), r)] += 1
                continue
            ins += 1
            # QEMU'S OWN WRITE VERDICT GATES THE SCORE.  A refused extraction
            # states nothing, and scoring a published destination against a
            # statement nobody made turns an absent measurement into a loss.
            # A CONTAINER WRITE WHOSE INDEX IS NOT STATED CANNOT REFUTE A
            # MEMBER WRITE (FINDING 75-C).  QEMU's CP-H row for
            # cpu_x86_load_seg_cache() states the WHOLE `segs` array and
            # says the index is not a static fact -- `&env->segs[seg_reg]`
            # with seg_reg a parameter -- so the list it produces is short
            # by a member it cannot name.  A destination naming ONE member
            # is then an ABSENT MEASUREMENT, not a loss, and it reaches the
            # same NOT SCORABLE bucket a refused extraction does.  Scored as
            # a loss it was 37,448 encodings: 36,000 lfs/lgs x
            # REG_SEG3/REG_SEG4 and 1,416 movw into REG_SEG1..5.
            #
            # THE GAIN SIDE GOES WITH IT.  WR is a lower bound here in
            # exactly the WSHORT sense, and the same argument that forbids
            # scoring the loss forbids reading its complement as a gain.
            if row["WRU"] == "1":
                unscorable["INDEX NOT STATED: a container write cannot "
                           "refute a member write"] += 1
                continue
            if row["WSTQ"] != OKW:
                unscorable[row["WSTQ"][:64]] += 1
                if row["WSTQ"] == WSHORT:
                    # GAIN ONLY -- see WSHORT for why the loss side may not
                    # be scored from a list that is a lower bound.
                    q = regs(row["WR"]) - regs(row["PUBD"])
                    if "REG_PC" in q and "REG_PC" not in regs(row["PUBD"]):
                        q = q - {"REG_PC"}
                    ws_rows += 1
                    if q:
                        ws_enc += 1
                        ws_reg += len(q)
                        for r in q:
                            wsreg[r] += 1
                            wsrule[(row.get("rule", "?"),
                                    row.get("mnem", "?"), r)] += 1
                continue
            scor += 1
            published = row["wstate"] == OKW    # the family reached the wire
            pubd, wr = regs(row["PUBD"]), regs(row["WR"])
            walk_only = pubd - wr
            qemu_only = wr - pubd
            if "REG_PC" in qemu_only and "REG_PC" not in pubd:
                qemu_only = qemu_only - {"REG_PC"}
                pc_carve += 1
            if walk_only:
                cost_enc += 1; cost_reg += len(walk_only)
                if published:
                    cost_pub_enc += 1; cost_pub_reg += len(walk_only)
                for r in sorted(walk_only):
                    costreg[r] += 1
                    costrule[(row.get("rule", "?"), row.get("mnem", "?"), r)] += 1
                    gcostreg[r] += 1
            if qemu_only:
                gain_enc += 1; gain_reg += len(qemu_only)
                if published:
                    gain_pub_enc += 1; gain_pub_reg += len(qemu_only)
                for r in sorted(qemu_only):
                    gainreg[r] += 1
                    gainrule[(row.get("rule", "?"), row.get("mnem", "?"), r)] += 1
                    ggainreg[r] += 1

        per_isa[isa] = (cost_enc, cost_reg, gain_enc, gain_reg)
        G["cost_enc"] += cost_enc; G["cost_reg"] += cost_reg
        G["gain_enc"] += gain_enc; G["gain_reg"] += gain_reg
        G["pc_carve"] += pc_carve; G["rows"] += len(M); G["ins"] += ins
        G["scor"] = G.get("scor", 0) + scor
        G["cpe"] = G.get("cpe", 0) + cost_pub_enc
        G["cpr"] = G.get("cpr", 0) + cost_pub_reg
        G["gpe"] = G.get("gpe", 0) + gain_pub_enc
        G["gpr"] = G.get("gpr", 0) + gain_pub_reg
        G["obe"] = G.get("obe", 0) + outbar_enc
        G["obr"] = G.get("obr", 0) + outbar_reg
        G["wse"] = G.get("wse", 0) + ws_enc
        G["wsr"] = G.get("wsr", 0) + ws_reg
        G["wsrows"] = G.get("wsrows", 0) + ws_rows

        print("=== %s ===" % isa)
        print("  rows=%d  wp-merge conflicts=%d  REACH=INSTRUCTION=%d  "
              "QEMU-STATED WRITE SIDE=%d" % (len(M), cm, ins, scor))
        for k, v in ordered(unscorable):
            print("     not scorable  %-8d %s" % (v, k))
        for k, v in ordered(byreach):
            print("     reach %-16s %d" % (k, v))
        if cex:
            for e in cex:
                print("     CONFLICT %s %s PUBD %s|%s WR %s|%s" % e)
        print("  WALK-ONLY DESTINATIONS (the flip's COST): %d encodings / "
              "%d registers" % (cost_enc, cost_reg))
        print_regtable(costreg, "      ", a.regtop)
        for k, n in ordered(costrule, a.top):
            print("      -%7d  %-46s %-12s %s" % (n, k[0][:46], k[1][:12], k[2]))
        print("     of which the destination FAMILY PUBLISHED: %d enc / "
              "%d regs" % (cost_pub_enc, cost_pub_reg))
        print("  QEMU-ONLY DESTINATIONS OUTSIDE THE BAR'S REACH CLASS "
              "(admitted all the same): %d encodings / %d registers"
              % (outbar_enc, outbar_reg))
        print_regtable(outbarreg, "      ", a.regtop)
        for k, n in ordered(outbarrule, 6):
            print("      *%7d  %-46s %-12s %s" % (n, k[0][:46], k[1][:12], k[2]))
        print("  ON A LOWER-BOUND WRITE LIST (QDEP_W_SHORT), GAIN ONLY: "
              "%d row(s), of which %d encoding(s) / %d register(s) name a "
              "destination the wire lacks" % (ws_rows, ws_enc, ws_reg))
        print_regtable(wsreg, "      ", a.regtop)
        for k, n in ordered(wsrule, a.top):
            print("      >%7d  %-46s %-12s %s" % (n, k[0][:46], k[1][:12], k[2]))
        print("  QEMU-ONLY DESTINATIONS (the flip's GAIN): %d encodings / "
              "%d registers   [R10.1 block-pc carve-outs: %d]"
              % (gain_enc, gain_reg, pc_carve))
        print("     of which the destination FAMILY PUBLISHED: %d enc / "
              "%d regs   <-- what the ADMISSION seats today"
              % (gain_pub_enc, gain_pub_reg))
        print_regtable(gainreg, "      ", a.regtop)
        for k, n in ordered(gainrule, a.top):
            print("      +%7d  %-46s %-12s %s" % (n, k[0][:46], k[1][:12], k[2]))
        print()

    print("=== ALL ISAs ===")
    for isa in isas:
        c = per_isa[isa]
        print("  %-9s cost %6d enc / %6d regs   gain %6d enc / %6d regs"
              % (isa, c[0], c[1], c[2], c[3]))
    print("  THE DESTINATION BAR (flip COST) : %d encodings / %d registers"
          % (G["cost_enc"], G["cost_reg"]))
    print("     by register:")
    print_regtable(gcostreg, "       ", a.regtop)
    print("  THE FLIP'S GAIN                 : %d encodings / %d registers"
          % (G["gain_enc"], G["gain_reg"]))
    print("     by register:")
    print_regtable(ggainreg, "       ", a.regtop)
    print("  ... on rows whose family PUBLISHED: %d encodings / %d registers"
          % (G.get("cpe", 0), G.get("cpr", 0)))
    print("  THE ADMISSION SEATS TODAY        : %d encodings / %d registers"
          % (G.get("gpe", 0), G.get("gpr", 0)))
    print("  ADMITTED OUTSIDE THE REACH CLASS : %d encodings / %d registers"
          % (G.get("obe", 0), G.get("obr", 0)))
    print("  ON A LOWER-BOUND WRITE LIST     : %d row(s), %d encodings / "
          "%d registers  <-- GAIN ONLY, never scored as a loss"
          % (G.get("wsrows", 0), G.get("wse", 0), G.get("wsr", 0)))
    print("  R10.1 block-pc carve-outs       : %d encodings" % G["pc_carve"])
    print("  rows read %d, REACH=INSTRUCTION %d, QEMU-STATED WRITE SIDE %d"
          % (G["rows"], G["ins"], G.get("scor", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
