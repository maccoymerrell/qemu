#!/usr/bin/env python3
"""EXERCISE EVERY aarch64 DECODE ROW UNDER THE TRACER, AND PROVE IT ON THE WIRE.

WHAT "EXERCISED" MEANS HERE
---------------------------
Not "QEMU ran it".  A row counts exercised only when the encoding QEMU's own
decoder routed to that row is found ON THE WIRE: the guest runs with the
plugin attached, `cst_decode` renders the `.cst`, and the line for the probe's
own address must carry the same bytes the image placed there.  A row QEMU
executes and the tracer drops is exactly the hole this pass exists to find, and
nothing weaker than a per-row wire witness can see it.

THE ROW KEY IS THE DECODE RULE, AND THE WORD IS QEMU'S CHOICE OF IT
--------------------------------------------------------------------
`a64_row_encodings.py` builds candidate words from each pattern's fixed bits;
the sled then asks QEMU which row each candidate actually reached, because a
word satisfying a pattern's mask can still be routed to an earlier, more
specific pattern.  This file takes only the words QEMU agreed belong to the row
-- so a row is never credited with a sibling row's encoding, which is how a
coverage number comes back complete while a row sits unreached.

THE VERDICTS, AND WHY THEY ARE NOT ONE VERDICT
-----------------------------------------------
  EXERCISED       the probe's bytes came back off the wire.
  ABSENT          a trace was written and the probe's address is not in it.
                  The guest was stopped before the probe, or the tracer did not
                  publish it; the two are separated by the triage pass, not by
                  this file's opinion.
  BYTES-DIFFER    the wire carries the probe address with OTHER bytes.  That is
                  not a coverage miss, it REFUTES the join, and it fails.
  TIMEOUT         the guest did not terminate.  A branch to itself is the
                  common cause and is a fact about the operand values.
  NO-TRACE        the run produced no `.cst` at all.

THE CONTROL IS NOT OPTIONAL.  `add x0, x0, #1` must come back EXERCISED.  If the
frame cannot see an instruction everyone agrees is on the wire, then every
"not exercised" below is the frame's and not the tracer's, and the run refuses
rather than publish a number.

Author: Maccoy Merrell.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import concurrent.futures
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import a64_probe_elf as P                                  # noqa: E402

COMPRESS = "zstd -T0 -3 -q -c"

_LINE = re.compile(r"^0x0*%x:\s+((?:[0-9a-f]{2} )+)" % P.PROBE_PC)


def sha_prefix(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return "unknown"


def stamp_lines(repo, plugin, qemu):
    """`#tip` and `#so`: which tree, which binaries.  A dirty tree says so."""
    try:
        sha = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"],
                                      stderr=subprocess.DEVNULL).decode().strip()
        dirt = subprocess.check_output(
            ["git", "-C", repo, "status", "--porcelain",
             "--untracked-files=no"],
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        sha, dirt = "", ""
    tip = "#tip\t%s\t%s\n" % (sha or "unknown",
                              "dirty" if dirt else ("clean" if sha else
                                                    "unknown"))
    return tip, "#so\t%s\t%s\n" % (sha_prefix(plugin), sha_prefix(qemu))


def exercise(job):
    """Run one encoding under the tracer and read its bytes back off the wire."""
    (qemu, cpu, plugin, decode, outdir, rule, arm, word, timeout) = job
    cell = os.path.join(outdir, "%s_%s_%08x" % (rule, arm, word))
    os.makedirs(cell, exist_ok=True)
    elf = os.path.join(cell, "p.elf")
    with open(elf, "wb") as fh:
        fh.write(P.build_elf(word, arm))
    os.chmod(elf, 0o755)

    plug = "%s,outfile=t,compress=%s" % (plugin, COMPRESS)
    try:
        subprocess.run([qemu, "-cpu", cpu, "-plugin", plug, elf],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=timeout, cwd=cell)
    except subprocess.TimeoutExpired:
        return (rule, arm, word, "TIMEOUT", cell)

    trace = None
    for cand in sorted(os.listdir(cell)):
        if cand.startswith("t.cst"):
            trace = os.path.join(cell, cand)
            break
    if trace is None:
        return (rule, arm, word, "NO-TRACE", cell)

    try:
        out = subprocess.run([decode, trace], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        return (rule, arm, word, "DECODE-TIMEOUT", cell)

    want = " ".join("%02x" % b for b in struct.pack("<I", word))
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        m = _LINE.match(line.strip())
        if m:
            got = m.group(1).strip()
            if got == want:
                return (rule, arm, word, "EXERCISED", cell)
            return (rule, arm, word, "BYTES-DIFFER:%s" % got, cell)
    return (rule, arm, word, "ABSENT", cell)


def read_words(path, per_row):
    """{rule: [word, ...]} from a64_row_encodings.py's identity-joined table."""
    rows = {}
    for line in open(path, "r", errors="replace"):
        if line.startswith("#") or not line.strip():
            continue
        p = line.rstrip("\n").split("\t")
        if len(p) < 2:
            continue
        ws = [int(w, 16) for w in p[1].split()][:per_row]
        if ws:
            rows[p[0]] = ws
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--cpu", default="max")
    ap.add_argument("--plugin", required=True)
    ap.add_argument("--cst-decode", required=True)
    ap.add_argument("--words", required=True,
                    help="rule<TAB>space-separated words QEMU routed there")
    ap.add_argument("--cells", required=True)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--per-row", type=int, default=2)
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--keep-cells", action="store_true",
                    help="keep every cell; by default only the cells that did "
                         "NOT verify are kept, because those are the evidence")
    a = ap.parse_args()

    for p in (a.qemu, a.plugin, a.cst_decode):
        if not os.path.exists(p):
            sys.exit("REFUSING: %s does not exist" % p)

    rows = read_words(a.words, a.per_row)
    if not rows:
        sys.exit("REFUSING: %s named no row -- a corpus built over an empty "
                 "population is a gap, not a coverage result" % a.words)

    os.makedirs(a.cells, exist_ok=True)

    # THE CONTROL FIRST.  `add x0, x0, #1`.
    ctl = exercise((a.qemu, a.cpu, a.plugin, a.cst_decode, a.cells,
                    "_control", "plain", 0x91000400, a.timeout))
    print("control (add x0, x0, #1): %s" % ctl[3])
    if ctl[3] != "EXERCISED":
        sys.exit("REFUSING: the control encoding did not come back off the "
                 "wire, so no verdict in this run means anything")

    def run(arm, subset):
        jobs = [(a.qemu, a.cpu, a.plugin, a.cst_decode, a.cells, r, arm, w,
                 a.timeout)
                for r in subset for w in rows[r]]
        res = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
            for x in ex.map(exercise, jobs):
                res.append(x)
        return res

    verdicts = {}                       # rule -> {(arm, word): verdict}
    results = run("plain", sorted(rows))
    for (r, arm, w, v, cell) in results:
        verdicts.setdefault(r, {})[(arm, w)] = (v, cell)

    def hit(r):
        return any(v == "EXERCISED" for v, _c in verdicts[r].values())

    # THE LATER ARMS ARE ARCHITECTURAL STATE, not a retry of the same thing:
    # SME encodings are UNDEFINED until PSTATE.SM/ZA are set, and a
    # base-plus-index address needs some register to hold zero (see
    # a64_probe_elf.ARMS).  Only rows no earlier arm reached are re-run, so
    # each arm's cost is paid on the rows that still need it and nowhere else.
    for arm in [a for a in P.ARMS if a != "plain"]:
        retry = sorted(r for r in rows if not hit(r))
        print("%d of %d rows reached; %d go to the %s arm"
              % (len(rows) - len(retry), len(rows), len(retry), arm))
        if not retry:
            break
        for (r, _a, w, v, cell) in run(arm, retry):
            verdicts[r][(arm, w)] = (v, cell)

    tip, so = stamp_lines(a.repo, a.plugin, a.qemu)
    nex = 0
    bad = []
    with open(a.out, "w") as f:
        f.write(tip)
        f.write(so)
        f.write("#rule\tverdict\tarm\tword\tall\n")
        for r in sorted(rows):
            best, barm, bword = "ABSENT", "plain", rows[r][0]
            for (arm, w), (v, _c) in sorted(verdicts[r].items()):
                if v == "EXERCISED":
                    best, barm, bword = v, arm, w
                    break
            if best != "EXERCISED":
                # Report the most informative non-verdict rather than the
                # first: a TIMEOUT and an ABSENT are different animals.
                order = {"BYTES-DIFFER": 0, "TIMEOUT": 1, "NO-TRACE": 2,
                         "DECODE-TIMEOUT": 3, "ABSENT": 4}
                vs = sorted(verdicts[r].items(),
                            key=lambda kv: order.get(kv[1][0].split(":")[0], 9))
                (barm, bword), (best, _c) = vs[0]
            if best == "EXERCISED":
                nex += 1
            if best.startswith("BYTES-DIFFER"):
                bad.append(r)
            allv = ",".join("%s/%08x=%s" % (arm, w, v)
                            for (arm, w), (v, _c) in sorted(verdicts[r].items()))
            f.write("%s\t%s\t%s\t%08x\t%s\n" % (r, best, barm, bword, allv))

    if not a.keep_cells:
        for r in sorted(rows):
            if hit(r):
                for (_arm, _w), (v, cell) in verdicts[r].items():
                    if v == "EXERCISED" and os.path.isdir(cell):
                        shutil.rmtree(cell, ignore_errors=True)
        shutil.rmtree(ctl[4], ignore_errors=True)

    print("rows %d   exercised on the wire %d   %.2f%%"
          % (len(rows), nex, 100.0 * nex / len(rows)))
    print("written to %s" % a.out)
    if bad:
        print("BYTES-DIFFER on %d row(s) -- the join is refuted: %s"
              % (len(bad), " ".join(bad[:10])), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
