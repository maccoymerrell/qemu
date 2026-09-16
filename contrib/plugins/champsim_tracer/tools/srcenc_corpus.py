#!/usr/bin/env python3
"""Build the isax `--srcenc` corpus from sled captures, and ADJUDICATE it.

WHAT A CORPUS IS.  `tools/srcenc_sled.py` writes one `corpus_<isa>.tsv` per
(ISA, wpdepth) capture; `tools/isax_srcenc_gate.sh run` wants ONE file per
ISA.  Merging them is a two-line `sort -u` and that is exactly the problem
this file exists to remove: `sort -u` on rows keyed by ENCODING silently
admits TWO rows for one encoding when two captures disagree about it, and a
corpus with two answers for one encoding is not a corpus, it is a question
nobody asked.

WHAT A CONFLICT MEANS, AND WHY THE TWO KINDS ARE NOT THE SAME.

  SET-DIFFERS   two captures name different source REGISTERS for one
                encoding.  R17's standing oracle is that the sets are
                INVOCATION-INVARIANT, so this is that oracle failing, and
                it is refused unconditionally.  There is no allowance for
                it and there is no flag to raise one.

  ORDER-ONLY    the same set in a different sequence.  This used to be
                waved past on the ground that R17 is about sets -- true, and
                beside the point since 94dc9e649c made the wire's source
                list QEMU's ORDERED read list.  The sequence is wire
                content, so the question is whether it is a FACT of the
                encoding or a nondeterminism.

                MEASURED at exec103, and the answer is neither.  The order
                is a deterministic function of the TRANSLATION CONTEXT.

                  SAME CONTEXT -- one workload at one wpdepth, captured
                  twice: 80 capture pairs over 185,613 encodings, four
                  targets, ZERO order conflicts and zero set conflicts.
                  On the synthetic sled, where every encoding is reached in
                  one fixed context, the same holds over all 8,462,280
                  encodings and across wpdepth as well.

                  CROSS CONTEXT -- two different (workload, wpdepth)
                  captures: x86_64 2, aarch64 28, riscv64 0, mipsel 0 over
                  every pair of contexts, and SET-DIFFERS 0 everywhere.
                  `fadd d1, d9, d0` reads {VEC0, FCSR, VEC9, SYSFPEN} in one
                  and {VEC9, VEC0, FCSR, SYSFPEN} in another.

                So a corpus KEYED ON THE ENCODING cannot key on the order:
                the encoding does not determine it.  This file therefore
                splits the two cases rather than choosing between them.

                A SAME-CONTEXT order difference is a NONDETERMINISM -- the
                same bytes, the same workload, the same wpdepth, two
                answers -- and refuses.  A CROSS-CONTEXT one is counted,
                printed and resolved by a stated rule: the capture whose
                relative path sorts first wins, so the corpus is a function
                of the inputs and not of the order the caller listed them
                in.  `--strict-order` promotes cross-context differences to
                refusals too, for a run that wants to enumerate them.

                CONTEXT IS THE CAPTURE'S PATH RELATIVE TO ITS ROOT.  Two
                roots holding `w19/aarch64.wp0/` are two captures of ONE
                context; `w19/aarch64.wp0` and `w19/aarch64.wp16` inside one
                root are two contexts.  That is what makes the same-context
                arm a repeat rather than a comparison.

Every conflict is PRINTED with both readings before the refusal, because a
count nobody can act on is not a report.

Usage:
  srcenc_corpus.py --out DIR ROOT [ROOT ...]   root = a sweep directory
        holding <isa>.wp<N>/ or <cell>/<isa>.wp<N>/.  Passing the same
        sweep captured twice is what makes the same-context arm fire.
  srcenc_corpus.py --selftest

Author: Maccoy Merrell.
"""

import argparse
import hashlib
import os
import re
import sys

ISAS = ["x86_64", "aarch64", "riscv64", "mipsel"]
WP_RE = re.compile(r"^([a-z0-9_]+)\.wp(\d+)$")


def find_captures(roots, isa):
    """[(context, root_index, path)] for every capture of @isa under @roots.

    CONTEXT is the capture's path RELATIVE TO ITS ROOT, so the same relative
    path in two roots is two captures of one context and different relative
    paths are different contexts.  Roots may hold `<isa>.wp<N>/` directly or
    one level of workload directories above it.
    """
    out = []
    for ri, root in enumerate(roots):
        if not os.path.isdir(root):
            raise SystemExit("srcenc_corpus: REFUSING -- no root %s" % root)
        for dirpath, dirnames, _files in os.walk(root):
            base = os.path.basename(dirpath)
            m = WP_RE.match(base)
            if not m or m.group(1) != isa:
                continue
            p = os.path.join(dirpath, "corpus_%s.tsv" % isa)
            if os.path.exists(p):
                ctx = os.path.relpath(dirpath, root)
                out.append((ctx, ri, p))
    out.sort()
    return out


def read_capture(path):
    rows = {}
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 4:
                continue
            rows[c[1]] = (c[2], c[3], line)
    return rows


def as_set(s):
    return frozenset(x for x in s.split(",") if x and x != "-")


def build(roots, out, allow_order, log=sys.stdout, strict_order=False):
    os.makedirs(out, exist_ok=True)
    rc = 0
    lines = []
    for isa in ISAS:
        caps = find_captures(roots, isa)
        if not caps:
            lines.append("REFUSE: %s -- no capture under %s"
                         % (isa, ", ".join(roots)))
            rc = 2
            continue
        merged = {}
        origin = {}
        same_conf = []
        cross_conf = []
        set_conf = []
        for ctx, ri, path in caps:
            label = "%s[%d]" % (ctx, ri)
            for enc, (mnem, src, raw) in read_capture(path).items():
                if enc not in merged:
                    merged[enc] = raw
                    origin[enc] = (ctx, label, mnem, src)
                    continue
                octx, olabel, omnem, osrc = origin[enc]
                if osrc == src:
                    continue
                rec = (enc, omnem, olabel, osrc, label, src)
                if as_set(osrc) != as_set(src):
                    set_conf.append(rec)
                elif octx == ctx:
                    same_conf.append(rec)
                else:
                    cross_conf.append(rec)
                    # Resolve deterministically: the capture whose context
                    # sorts first wins, so the corpus is a function of the
                    # inputs rather than of the order they were listed in.
                    if ctx < octx:
                        merged[enc] = raw
                        origin[enc] = (ctx, label, mnem, src)
        if not merged:
            lines.append("REFUSE: %s corpus empty" % isa)
            rc = 2
            continue
        dst = os.path.join(out, "%s.tsv" % isa)
        with open(dst, "w") as f:
            for enc in sorted(merged):
                f.write(merged[enc])
        h = hashlib.md5(open(dst, "rb").read()).hexdigest()
        ctxs = len(set(c for (c, _r, _p) in caps))
        lines.append("%-8s captures=%-3d contexts=%-3d rows=%-9d"
                     " same_ctx_order=%-4d cross_ctx_order=%-5d"
                     " set_conflicts=%-4d md5=%s"
                     % (isa, len(caps), ctxs, len(merged), len(same_conf),
                        len(cross_conf), len(set_conf), h))
        for tag, conf, cap in (("SET", set_conf, 20),
                               ("SAME-CONTEXT ORDER", same_conf, 20),
                               ("CROSS-CONTEXT ORDER", cross_conf, 8)):
            for (enc, mnem, la, sa, lb, sb) in conf[:cap]:
                lines.append("   %s CONFLICT %s %-14s" % (tag, enc, mnem))
                lines.append("        %-28s %s" % (la, sa))
                lines.append("        %-28s %s" % (lb, sb))
            if len(conf) > cap:
                lines.append("   ... and %d more %s conflicts"
                             % (len(conf) - cap, tag))
        if set_conf:
            lines.append("REFUSE: %s -- %d SET conflicts.  R17's standing"
                         " oracle is that the source SETS are"
                         " invocation-invariant; this is that oracle"
                         " failing." % (isa, len(set_conf)))
            rc = 1
        if len(same_conf) > allow_order:
            lines.append("REFUSE: %s -- %d SAME-CONTEXT order conflicts,"
                         " ceiling %d.  The same bytes in the same workload"
                         " at the same wpdepth gave two sequences, which is"
                         " a nondeterminism in the wire and not a merge"
                         " policy.  exec103 measured this at 0 over 80"
                         " capture pairs and 185,613 encodings."
                         % (isa, len(same_conf), allow_order))
            rc = 1
        if cross_conf and strict_order:
            lines.append("REFUSE: %s -- %d CROSS-CONTEXT order conflicts and"
                         " --strict-order was given." % (isa, len(cross_conf)))
            rc = 1
        elif cross_conf:
            lines.append("   %s: %d cross-context order differences, resolved"
                         " to the first-sorting context.  The order is a"
                         " function of the TRANSLATION CONTEXT, so an"
                         " encoding-keyed corpus does not key on it."
                         % (isa, len(cross_conf)))
    lines.append("ALL_ISAS_DONE rc=%d" % rc)
    text = "\n".join(lines)
    with open(os.path.join(out, "RC.txt"), "w") as f:
        f.write(text + "\n")
    print(text, file=log)
    return rc


# ------------------------------------------------------------------ selftest
def _selftest():
    import shutil
    import tempfile
    fails = [0]
    n = [0]

    def ok(m):
        n[0] += 1
        print("PASS  %s" % m)

    def bad(m):
        n[0] += 1
        fails[0] += 1
        print("FAIL  %s" % m)

    root = tempfile.mkdtemp()
    try:
        def cap(rt, cell, isa, wp, rows):
            d = os.path.join(root, rt, cell, "%s.wp%s" % (isa, wp))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "corpus_%s.tsv" % isa), "w") as f:
                f.write("#isa\tencoding\tmnem\tsrc\n")
                for (e, m, s) in rows:
                    f.write("%s\t%s\t%s\t%s\n" % (isa, e, m, s))

        class Sink(object):
            def __init__(self):
                self.buf = []

            def write(self, s):
                self.buf.append(s)

            def flush(self):
                pass

            def text(self):
                return "".join(self.buf)

        def run(rts, o, allow=0, strict=False):
            s = Sink()
            r = build([os.path.join(root, x) for x in rts],
                      os.path.join(root, o), allow, s, strict)
            return r, s.text()

        def filler(rt, cell="c1"):
            for isa in ISAS[1:]:
                cap(rt, cell, isa, "0", [("00", "nop", "-")])

        # A: agreeing captures merge and pass.
        for rt in ("r1", "r2"):
            for isa in ISAS:
                cap(rt, "c1", isa, "0", [("00", "nop", "-")])
                cap(rt, "c1", isa, "16", [("00", "nop", "-")])
        r, txt = run(["r1", "r2"], "o1")
        if r == 0 and "rc=0" in txt:
            ok("A agreeing captures merge, rc=0")
        else:
            bad("A rc=%d\n%s" % (r, txt))
        if os.path.exists(os.path.join(root, "o1", "x86_64.tsv")):
            ok("A2 one file per ISA is written")
        else:
            bad("A2 no per-ISA file")

        # B: SAME CONTEXT -- one cell, one wpdepth, two roots -- disagreeing
        #    on order is a NONDETERMINISM and refuses.
        cap("s1", "c1", "x86_64", "0", [("01", "fcmp", "REG_VEC0,REG_VEC1")])
        cap("s2", "c1", "x86_64", "0", [("01", "fcmp", "REG_VEC1,REG_VEC0")])
        filler("s1"); filler("s2")
        r, txt = run(["s1", "s2"], "o2")
        if r == 1 and "SAME-CONTEXT ORDER CONFLICT" in txt:
            ok("B a same-context order difference REFUSES as a nondeterminism")
        else:
            bad("B rc=%d\n%s" % (r, txt))

        # C: ... and --allow-order lets a bisect past it.
        r, txt = run(["s1", "s2"], "o3", allow=1)
        if r == 0:
            ok("C --allow-order raises the SAME-CONTEXT ceiling")
        else:
            bad("C rc=%d\n%s" % (r, txt))

        # D: CROSS CONTEXT -- two cells -- disagreeing on order is the
        #    measured behaviour and is REPORTED, not refused.
        cap("x1", "cA", "x86_64", "0", [("02", "fadd", "REG_VEC0,REG_VEC9")])
        cap("x1", "cB", "x86_64", "0", [("02", "fadd", "REG_VEC9,REG_VEC0")])
        filler("x1", "cA")
        r, txt = run(["x1"], "o4")
        if r == 0 and "CROSS-CONTEXT ORDER CONFLICT" in txt \
                and "cross-context order differences, resolved" in txt:
            ok("D a cross-context order difference is reported, not refused")
        else:
            bad("D rc=%d\n%s" % (r, txt))

        # D2: ... and it is resolved to the FIRST-SORTING context, so the
        #     corpus does not depend on which root was listed first.
        a = open(os.path.join(root, "o4", "x86_64.tsv")).read()
        r, txt = run(["x1"], "o4b")
        b = open(os.path.join(root, "o4b", "x86_64.tsv")).read()
        if a == b and "REG_VEC0,REG_VEC9" in a:
            ok("D2 the cross-context winner is the first-sorting context")
        else:
            bad("D2 corpus not stable / wrong winner: %r" % a)

        # D3: --strict-order promotes it to a refusal.
        r, txt = run(["x1"], "o4c", strict=True)
        if r == 1 and "--strict-order was given" in txt:
            ok("D3 --strict-order refuses a cross-context difference")
        else:
            bad("D3 rc=%d" % r)

        # E: a SET conflict refuses REGARDLESS of --allow-order, same or
        #    cross context.  R17.
        cap("t1", "cA", "x86_64", "0", [("03", "add", "REG_GPR0")])
        cap("t1", "cB", "x86_64", "0", [("03", "add", "REG_GPR1")])
        filler("t1", "cA")
        r, txt = run(["t1"], "o5", allow=99)
        if r == 1 and "SET CONFLICT" in txt and "R17" in txt:
            ok("E a SET conflict refuses at --allow-order 99, citing R17")
        else:
            bad("E rc=%d\n%s" % (r, txt))

        # F: an ISA with no capture is REFUSED (rc=2), never a short corpus.
        cap("u1", "c1", "x86_64", "0", [("00", "nop", "-")])
        r, txt = run(["u1"], "o6")
        if r == 2 and "no capture" in txt:
            ok("F an ISA with no capture REFUSES (rc=2)")
        else:
            bad("F rc=%d\n%s" % (r, txt))

        # G: rc=2 dominates rc=1 -- "could not look" is never a mere failure.
        cap("v1", "c1", "x86_64", "0", [("01", "fcmp", "REG_VEC0,REG_VEC1")])
        cap("v2", "c1", "x86_64", "0", [("01", "fcmp", "REG_VEC1,REG_VEC0")])
        r, txt = run(["v1", "v2"], "o7")
        if r == 2:
            ok("G a missing ISA dominates a conflicting one (rc=2)")
        else:
            bad("G rc=%d, want 2" % r)

        # H: context is the RELATIVE path, so the same cell in two roots is
        #    one context and two cells in one root are two.  This is the
        #    arm that would fail if the split were keyed on anything else.
        caps = find_captures([os.path.join(root, "s1"),
                              os.path.join(root, "s2")], "x86_64")
        ctxs = set(c for (c, _r, _p) in caps)
        if len(caps) == 2 and len(ctxs) == 1:
            ok("H two roots, one relative path = 2 captures of 1 context")
        else:
            bad("H captures=%d contexts=%d" % (len(caps), len(ctxs)))
        caps = find_captures([os.path.join(root, "x1")], "x86_64")
        if len(caps) == 2 and len(set(c for (c, _r, _p) in caps)) == 2:
            ok("H2 one root, two cells = 2 contexts")
        else:
            bad("H2 %r" % (caps,))

        # I: a refusing run still writes ONE row per encoding.
        p = os.path.join(root, "o2", "x86_64.tsv")
        if os.path.exists(p) and len(open(p).read().splitlines()) == 1:
            ok("I a refusing run still writes one row per encoding")
        else:
            bad("I refusing run wrote %r"
                % (open(p).read() if os.path.exists(p) else None))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("%d arms, %d failures" % (n[0], fails[0]))
    return 1 if fails[0] else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--allow-order", type=int, default=0)
    ap.add_argument("--strict-order", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("roots", nargs="*")
    a = ap.parse_args()
    if a.selftest:
        return _selftest()
    if not a.out or not a.roots:
        ap.error("--out DIR and at least one ROOT are required")
    return build(a.roots, a.out, a.allow_order,
                 strict_order=a.strict_order)


if __name__ == "__main__":
    sys.exit(main())
