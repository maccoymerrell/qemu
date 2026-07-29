#!/usr/bin/env python3
"""implicit_audit — the implicit-operand assertion table.

An *implicit* operand is architectural state an instruction touches that its
encoding does not name: AArch64 ``ret`` reading ``x30``, RISC-V ``vmerge``
reading ``v0`` and every vector op reading ``vl``/``vtype``, MIPS ``c.eq.s``
writing an FCC and ``bc1t`` reading it, MIPS ``ins`` reading its own
destination.  Every decode defect this project has found has been one of
these, and this table asserts, per encoding and per operand, that the
tracer's decode boundary still reports the ones it reports today.

THREE PROPERTIES, WHICH ARE THE POINT
-------------------------------------
**1. It is not derived from a decoder.**  Every other oracle in this project
reads Capstone-derived metadata — the same metadata the tracer consumes — so
a decoder defect is invisible to all of them: the trace is corrupted and the
oracles agree with the corruption.  The expectations here come from sources
derived from *behaviour*, never from an operand list:

  aarch64   Arm's Machine Readable Architecture (the A64 ISA XML), read as
            execute-clause ASL, cross-checked against QEMU's translator.
  riscv64   the Sail RISC-V model's ``execute`` clauses (``riscv-opcodes``
            for encodings only — it carries no semantics), cross-checked
            against QEMU's translator.
  mipsel    QEMU's own TCG translators.  For MIPS the translator is the ONLY
            correct witness: no vendor machine-readable MIPS spec exists,
            and the two candidate substitutes — binutils' ``mips-opc.c``
            ``pinfo`` bits and the REMS Sail MIPS model — share the same
            tied-destination error, both reporting ``movn``/``movz``/``ins``/
            ``lwl``/``lwr`` destinations as write-only (``mips_regfp.sail``
            concedes it in a comment).  A table lifted from either silently
            drops those read-after-write edges.

**2. It asserts agreement rather than detecting difference.**  A comparison
between two decoders can only see where they disagree, so it fails *open*
when both move together.  The RVV ``v0`` mask class is exactly that case:
Capstone and LLVM agree, and both are wrong, because a disassembler
transcribes encodings and does not model behaviour.  No n-way decoder
comparison can ever see it.  Here every row states what must be true, so a
row goes red when the boundary stops reporting it no matter what any other
decoder does — which is what makes a future Capstone bump unable to silently
drop ``x30`` from an AArch64 return.

**3. It carries dynamic weight.**  Each row records the dynamic instruction
count its *form* reached in a real traced population, so a reviewer can rank
"SME ZA missing" (weight 0) against "MRS TPIDR_EL0 missing" (18.7 M).  The
weight is keyed by instruction form — the operand text with register numbers
and immediates wildcarded, see ``skeleton()`` — and deliberately NOT by bare
mnemonic: weighting ``ldr za[w12,0],[x0]`` by every ``ldr`` in the trace is a
gross over-estimate, since the SME form and the ordinary load share nothing
but four letters.  Matching the form keeps them apart while still folding
across register numbers.

MODES
-----
``--mode assert`` (the gate)
    Every row recorded as ``OK`` must still score ``OK``.  Exits non-zero on
    any regression.  Runs only the probe encodings — no sweep — so it costs
    a few hundred decodes per ISA and is affordable on every build.

``--mode known-gap``
    The bookkeeping mode.  Every row that is neither ``OK`` nor
    ``NOT-MODELLED`` must carry an explicit disposition — ``fix`` /
    ``modelling-decision`` / ``wont-fix`` — and a justification.  Dispositions are keyed by the whole row
    ``(family, hex, kind, operand)`` and never by family, so a NEW member of
    an already-known family arrives as a row with no disposition and fails,
    while the family's existing rows stay green; the mode proves that
    property on itself before checking anything.  A disposition standing
    over a gap that has since closed fails too, in the other direction — a
    justification is a claim about something that happens.

``--mode regenerate``
    Rebuild the expectation table against a newer MRA / Sail / translator and
    print the diff.  It writes ``<isa>.tsv.new`` beside the table and never
    overwrites: the reviewer sees what moved and promotes it by hand.
    Human columns (``source``, ``disposition``, ``justification``) are
    carried forward by row key so a regeneration does not discard the
    reasoning attached to a gap that is still open.  With no ``--probes``
    it re-scores the encodings the table already carries, which is all a
    Capstone bump needs; ``--probes`` is for a derivation that adds probes,
    and ``--weights`` for a fresh traced population.

VERDICTS
--------
  OK                      the boundary reports the implicit operand
  MISS-BOUNDARY           the spec and LLVM have it, the boundary does not
                          — the two-way decoder gate could have caught this
  MISS-BOUNDARY-LLVMREJ   the spec has it and LLVM would not decode the
                          encoding at all, so only the spec can judge
  MISS-BOTH               neither the boundary nor LLVM has it — the shared
                          blind spot, and the reason this table exists
  MISS-STRUCTURAL         the expectation names a structural relationship a
                          register-name set cannot express — the implied
                          second register of a CASP pair, the seven
                          consecutive registers of an LS64 group, the upper
                          half of a SIMD destination.  Recorded, never
                          silently scored as agreement OR as a shared blind
                          spot, because it is neither
  NOT-MODELLED            architectural state the tracer's register model
                          deliberately does not carry; scoring it as a
                          defect would report a modelling decision as a bug
  PROBE-BAD               the probe encoding did not decode; the probe is at
                          fault, not the boundary

The boundary side is ``isaxcheck --batch``: ``cap_disas_raw_detail()`` in
``disas/capstone.c`` (Capstone plus every correction applied on top), with
the plugin's ``include_implicit_regs`` policy modelled, so what is compared
is what the dependency model would actually record.  The LLVM subtargets live
in ``isaxcheck``'s own ``kIsaTable`` — a fact about the ISA belongs with the
tool that knows the ISA — so nothing here passes ``--mattr``; a run's verdict
must not depend on who invoked it.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import argparse
import collections
import difflib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TABLE_DIR = HERE / "implicit"

ISAS = ("aarch64", "riscv64", "mipsel")

# Which behavioural source the expectations for an ISA come from when a probe
# family carries no finer attribution of its own.  The per-row `source`
# column overrides this; it exists so a reviewer can tell, without leaving
# the table, whether a red row is a claim about Arm's ASL, Sail's execute
# clause or QEMU's translator.
PRIMARY_SOURCE = {"aarch64": "MRA", "riscv64": "SAIL", "mipsel": "QEMU"}

DISPOSITIONS = ("fix", "modelling-decision", "wont-fix")

COLS = ("family", "hex", "asm", "kind", "operand", "source", "expect",
        "weight", "disposition", "justification")

# ---------------------------------------------------------------------------
# spec canonical name -> the name isaxcheck's normaliser produces
# (norm_aarch64 / norm_riscv / norm_mips in tools/isaxcheck.cc).
# ---------------------------------------------------------------------------
NAMEMAP = {
    # norm_aarch64 truncates a register name at its first underscore, so
    # the two decoders' spellings of a system register meet on a common
    # stem; a spec token carrying the full architectural name has to be
    # reduced the same way to compare against it.
    "aarch64": {"x30": "r30", "lr": "r30", "sp": "sp", "pstate": "nzcv",
                "nzcv": "nzcv", "xzr": "zr", "wzr": "zr",
                "tpidr_el0": "tpidr", "tpidrro_el0": "tpidr"},
    "riscv64": {"ra": "r1", "sp": "r2", "zero": "r0", "x1": "r1", "x2": "r2"},
    "mipsel":  {"hi": "ac0", "lo": "ac0", "ac0": "ac0", "ac1": "ac1",
                "ac2": "ac2", "ac3": "ac3", "dspctrl": "dsp",
                "r31": "r31", "r29": "r29", "fcsr": "fcsr"},
}

# Architectural state the tracer's register model deliberately does not
# carry.  Counting these as defects would report a modelling decision as a
# bug, so they are scored NOT-MODELLED and never gate.
NOT_MODELLED = {
    "aarch64": {"pc"},
    "riscv64": {"pc", "mstatus"},
    "mipsel":  {"pc", "llbit"},
}


# A spec token that one boundary name does not exhaust.  Any one of the
# accepted names satisfies the row, and the mismatch runs in both
# directions.
#
# Sometimes the TRACER is the more precise of the two: MIPS `cfc1 $6,$25`
# reads the FCCR view of the FP control/status register and the boundary
# says so, where the spec table writes `fcsr` for all four views; the SME
# ZA array is named per tile.
#
# Sometimes the SPEC TABLE is.  A system register does not live in the
# ISA's register file, so it reaches the boundary as its own operand type
# carrying its architectural ROLE, and the boundary reports the CLASS the
# dependency model records for it -- `flags`, `fcsr`, `tls`, `vctrl`,
# `sys` -- because that is the granularity at which the
# trace expresses a dependency.  The spec tables name the architectural
# register, which is finer.  Asserting one against the other is what the
# entries below make possible; the rule, and why each class groups the
# registers it does, is stated in docs/reference.rst under the register
# IDs.  Adding a register to a class means adding its name here.
ACCEPT = {
    "mipsel": {
        "fcsr": {"fcsr", "cop25", "cop26", "cop28", "cop31"},
        # MSA control and status folds onto REG_FCSR -- it is the vector
        # unit's rounding-mode and status word, the role that ID already
        # carries for the scalar FP unit.  It briefly held an ID of its
        # own, REG_VCSR, hence the retired `vcsr` spelling; a register
        # only MIPS has does not earn a generic ID.
        # `cop1` is how BOTH decoders now spell it: MSA control registers
        # are numbered (MSAIR 0 .. MSAUnmap 7) and the normaliser folds
        # the name onto the number, so LLVM's `msair`/`msacsr` and
        # Capstone's `cop<n>` meet.  Accepting it here is safe because
        # every row asserting `msacsr` is an MSA instruction, where
        # control register 1 is unambiguous.
        "msacsr": {"msacsr", "fcsr", "vcsr", "cop1"},
        # DSPControl likewise folds onto REG_FLAGS.
        "dspctrl": {"dsp", "dspctrl", "flags"},
    },
    "aarch64": {
        "za": {"za"} | {"za%d" % i for i in range(16)},
        # A system register reaches the boundary as its own operand
        # type, and the boundary reports the CLASS the dependency model
        # records for it rather than the architectural name -- see the
        # note above.  The same register named by an ordinary operand
        # still arrives under its own name (`adds` writes `nzcv`, `mrs
        # x0, nzcv` reads `flags`), so both spellings are accepted.
        "nzcv": {"nzcv", "flags"},
        "fpcr": {"fpcr", "fcsr"},
        "fpsr": {"fpsr", "fcsr"},
        "tpidr_el0": {"tpidr", "tls"},
        "tpidrro_el0": {"tpidr", "tls"},
    },
    "riscv64": {
        # Same class-vs-name rule.  The vector CONFIGURATION -- vl and
        # vtype, which a vsetvl writes as a pair, plus the vstart resume
        # index -- is `vctrl`.  vxrm, vxsat and the vcsr that is the two
        # of them in one word are the fixed-point rounding mode and
        # saturation flag, which is what `fcsr` already means.  vlenb is
        # a read-only implementation constant that belongs with the ID
        # registers (`sys`).
        #
        # vstart and vcsr held generic IDs of their own until those were
        # retired for naming a register that exists in exactly one ISA
        # (see the register IDs in docs/reference.rst).  The
        # architectural names stay in the assertion tables, which are
        # derived from the Sail model and say `vstart` because that is
        # the register Sail reads; the fold belongs here, where the
        # class the trace records is matched against the name the spec
        # uses -- exactly as `vl` has always been matched against
        # `vctrl`.
        "vl": {"vl", "vctrl"},
        "vtype": {"vtype", "vctrl"},
        "vstart": {"vstart", "vctrl"},
        "vxrm": {"vxrm", "fcsr"},
        "vxsat": {"vxsat", "fcsr"},
        "vcsr": {"vcsr", "fcsr"},
        "vlenb": {"vlenb", "sys"},
        # `cycle` is the unprivileged cycle counter read by `rdcycle`, which
        # is `csrrs rd, cycle, x0`.  It reaches the boundary the same way
        # vlenb does -- as a system-register operand, not a member of the
        # ISA's register file -- and lands in the same REG_SYS class, so the
        # same class-vs-name rule applies.  Without this line the row reads
        # as MISS-BOTH, which claims neither decoder reports the CSR: the
        # boundary does (`--hex=732500c0` gives RD{sys}), it just reports the
        # class rather than the name.  Its siblings `time` and `instret`
        # join the same way if a probe for them is ever derived.
        "cycle": {"cycle", "sys"},
        "fcsr": {"fcsr"},
        "fflags": {"fflags", "fcsr"},
        "frm": {"frm", "fcsr"},
    },
}


def mapnames(isa: str, n: str) -> set:
    """Boundary names any one of which satisfies a spec operand token."""
    n = n.strip().lower()
    if not n:
        return set()
    if n in ACCEPT[isa]:
        return set(ACCEPT[isa][n])
    if n.startswith("cop0_"):
        return {"cop" + n[5:]}
    if n in NAMEMAP[isa]:
        return {NAMEMAP[isa][n]}
    # generic architectural-register spellings the tables use directly
    if isa == "aarch64" and n[0] in "xw" and n[1:].isdigit():
        return {"r" + n[1:]}
    if isa == "riscv64" and n[0] == "x" and n[1:].isdigit():
        return {"r" + n[1:]}
    return {n}


def skeleton(mnem: str, ops: str) -> str:
    """Instruction *form* signature: the operand text with register numbers
    and immediates wildcarded.  See property 3 in the module docstring for
    why the dynamic weight is keyed by this and not by the mnemonic."""
    o = ops.strip().lower()
    o = re.sub(r"\b[a-z]+\d+\b", "R", o)
    o = re.sub(r"(?<![a-z])[#$]?-?(0x)?[0-9a-f]+\b", "N", o)
    o = re.sub(r"\s+", "", o)
    return mnem + "|" + o


def setof(s) -> set:
    return set(x for x in (s or "-").split(",") if x and x != "-")


# ---------------------------------------------------------------------------
# boundary
# ---------------------------------------------------------------------------

def find_tool(explicit=None, build_dir=None) -> Path:
    cands = []
    if explicit:
        cands.append(Path(explicit))
    if build_dir:
        cands.append(Path(build_dir) / "contrib/plugins/isaxcheck")
    # HERE = <repo>/contrib/plugins/champsim_tracer/tools
    repo = HERE.parents[3]
    for b in ("build", "build-gate"):
        cands.append(repo / b / "contrib/plugins/isaxcheck")
    for c in cands:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    raise SystemExit(
        "implicit_audit: isaxcheck not found (tried %s).  It needs LLVM MC "
        "(llvm-18-dev or newer supplying llvm-config); meson skips the "
        "target with a warning when llvm-config is absent."
        % ", ".join(str(c) for c in cands))


def run_boundary(tool: Path, isa: str, hexes) -> dict:
    """Feed encodings to `isaxcheck --batch` and return hex -> column dict.

    No --mattr / --mcpu: the LLVM subtargets are kIsaTable's business, and a
    gate whose verdict depends on the flags its caller happened to pass is
    not a gate.
    """
    hexes = list(hexes)
    if not hexes:
        return {}
    p = subprocess.run([str(tool), "--isa=" + isa, "--batch"],
                       input="\n".join(hexes) + "\n",
                       capture_output=True, text=True, timeout=900)
    if p.returncode != 0:
        sys.stderr.write(p.stderr[:4000])
        raise SystemExit("implicit_audit: isaxcheck --batch failed for %s"
                         % isa)
    lines = p.stdout.splitlines()
    if not lines:
        raise SystemExit("implicit_audit: isaxcheck --batch produced nothing")
    hdr = lines[0].split("\t")
    out = {}
    for ln in lines[1:]:
        f = ln.split("\t")
        if len(f) == len(hdr):
            out[f[0]] = dict(zip(hdr, f))
    return out


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def score_operand(isa: str, b: dict, kind: str, raw: str) -> str:
    """Verdict for one (encoding, kind, spec operand) triple."""
    brd, bwr = setof(b["b_rd"]), setof(b["b_wr"])
    lrd, lwr = setof(b["l_rd"]), setof(b["l_wr"])
    llvm_ok = b["l_ok"] == "1"

    if raw in ("<tied-dst>", "<base-wb>"):
        # the destination must also appear on the other side
        ok = bool(bwr & brd)
        llvm_has = bool(lwr & lrd) if llvm_ok else None
    elif raw.startswith("<"):
        return "MISS-STRUCTURAL"
    else:
        names = mapnames(isa, raw)
        if names & NOT_MODELLED[isa]:
            return "NOT-MODELLED"
        got = brd if kind == "READ" else bwr
        lgot = lrd if kind == "READ" else lwr
        ok = bool(names & got)
        llvm_has = bool(names & lgot) if llvm_ok else None

    if ok:
        return "OK"
    if llvm_has:
        return "MISS-BOUNDARY"
    if llvm_has is None:
        return "MISS-BOUNDARY-LLVMREJ"
    return "MISS-BOTH"


def score_rows(isa: str, rows, bnd: dict):
    """Yield (row, verdict) for every table row."""
    for r in rows:
        b = bnd.get(r["hex"])
        if not b or b["b_ok"] != "1":
            yield r, "PROBE-BAD"
            continue
        if r["operand"] in ("-", ""):
            # a row that exists only to pin a probe that used to be bad
            yield r, "OK"
            continue
        yield r, score_operand(isa, b, r["kind"], r["operand"])


# ---------------------------------------------------------------------------
# table I/O
# ---------------------------------------------------------------------------

def table_path(isa: str) -> Path:
    return TABLE_DIR / (isa + ".tsv")


def read_table(path: Path):
    rows, banner = [], []
    with open(path) as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if ln.startswith("#"):
                banner.append(ln)
                continue
            if not ln.strip():
                continue
            fl = ln.split("\t")
            if fl[0] == "family":
                continue
            fl += [""] * (len(COLS) - len(fl))
            rows.append(dict(zip(COLS, fl[:len(COLS)])))
    return banner, rows


def render_table(isa: str, banner, rows) -> str:
    out = list(banner)
    out.append("\t".join(COLS))
    for r in rows:
        out.append("\t".join(str(r.get(c, "")) or "-" for c in COLS))
    return "\n".join(out) + "\n"


def rowkey(r: dict):
    return (r["family"], r["hex"], r["kind"], r["operand"])


def needs_disposition(r: dict) -> bool:
    """OK needs no disposition, and neither does NOT-MODELLED: that verdict
    IS its own disposition, recorded once in this file's NOT_MODELLED sets
    rather than re-justified on every row that lands in it."""
    return r["expect"] not in ("OK", "NOT-MODELLED")


# ---------------------------------------------------------------------------
# modes
# ---------------------------------------------------------------------------

def mode_assert(tool: Path, isas, verbose: bool):
    """Every row recorded OK must still be OK."""
    ok_all = True
    report = []
    for isa in isas:
        banner, rows = read_table(table_path(isa))
        bnd = run_boundary(tool, isa, sorted({r["hex"] for r in rows}))
        regress, improved = [], []
        tally = collections.Counter()
        for r, v in score_rows(isa, rows, bnd):
            tally[v] += 1
            if r["expect"] == "OK" and v != "OK":
                regress.append((r, v))
            elif r["expect"] != "OK" and v == "OK":
                improved.append((r, v))
        ok = not regress
        ok_all = ok_all and ok
        report.append({
            "isa": isa, "ok": ok, "rows": len(rows),
            "tally": dict(tally),
            "regressions": [
                {"family": r["family"], "hex": r["hex"], "asm": r["asm"],
                 "operand": "%s %s" % (r["kind"], r["operand"]),
                 "source": r["source"], "weight": int(r["weight"] or 0),
                 "was": "OK", "now": v}
                for r, v in regress],
            "improved": [
                {"family": r["family"], "hex": r["hex"], "asm": r["asm"],
                 "operand": "%s %s" % (r["kind"], r["operand"]),
                 "was": r["expect"], "now": "OK"}
                for r, v in improved],
        })
        print("%-8s rows=%-4d %s  regressions=%d improved=%d  %s"
              % (isa, len(rows),
                 " ".join("%s=%d" % (k, tally[k]) for k in sorted(tally)),
                 len(regress), len(improved), "OK" if ok else "FAIL"))
        for r, v in regress:
            print("  REGRESSION %-24s %-10s %-6s %-18s w=%-12s %s -> %s"
                  % (r["family"], r["hex"], r["kind"], r["operand"],
                     r["weight"], "OK", v))
            print("             %s   [source %s]" % (r["asm"], r["source"]))
        if verbose:
            for r, v in improved:
                print("  improved   %-24s %-10s %-6s %-18s %s -> OK"
                      % (r["family"], r["hex"], r["kind"], r["operand"],
                         r["expect"]))
    return ok_all, report


def mode_known_gap(tool: Path, isas, verbose: bool):
    """Every non-OK row carries an explicit disposition and justification."""
    ok_all = True
    report = []
    for isa in isas:
        banner, rows = read_table(table_path(isa))
        problems = []

        # --- the family-key property, proved before it is relied on -------
        # A disposition is keyed by the WHOLE row, so a new mnemonic joining
        # a known-gap family produces a key nothing covers.  Synthesise one
        # per known-gap family and confirm it stays uncovered; if this ever
        # passes vacuously the mode is not enforcing what it claims.
        covered = {rowkey(r) for r in rows if r["disposition"] not in ("", "-")}
        gap_families = sorted({r["family"] for r in rows
                               if needs_disposition(r)})
        for fam in gap_families:
            probe = (fam, "ffffffff-newmember", "READ", "<novel>")
            if probe in covered:
                problems.append(("KEY-TOO-WIDE", fam,
                                 "a disposition matches a synthetic new "
                                 "member of this family"))

        # --- per-row bookkeeping ------------------------------------------
        seen = set()
        for r in rows:
            k = rowkey(r)
            if k in seen:
                problems.append(("DUPLICATE-ROW", r["family"],
                                 "%s %s %s" % (r["hex"], r["kind"],
                                               r["operand"])))
            seen.add(k)
            disp = r["disposition"]
            just = r["justification"]
            if not needs_disposition(r):
                if disp not in ("", "-"):
                    problems.append(("ORPHAN-DISPOSITION", r["family"],
                                     "%s %s %s scores %s but carries '%s'"
                                     % (r["hex"], r["kind"], r["operand"],
                                        r["expect"], disp)))
            else:
                if disp not in DISPOSITIONS:
                    problems.append(("NO-DISPOSITION", r["family"],
                                     "%s %s %s (%s) has disposition '%s'"
                                     % (r["hex"], r["kind"], r["operand"],
                                        r["expect"], disp or "-")))
                elif len(just.strip()) < 20 or just.strip() == "-":
                    problems.append(("NO-JUSTIFICATION", r["family"],
                                     "%s %s %s carries '%s' with no "
                                     "justification"
                                     % (r["hex"], r["kind"], r["operand"],
                                        disp)))

        # --- drift, both directions ---------------------------------------
        bnd = run_boundary(tool, isa, sorted({r["hex"] for r in rows}))
        drift = []
        for r, v in score_rows(isa, rows, bnd):
            if v != r["expect"]:
                drift.append((r, v))
                problems.append(("DRIFT", r["family"],
                                 "%s %s %s recorded %s, now %s"
                                 % (r["hex"], r["kind"], r["operand"],
                                    r["expect"], v)))

        bydisp = collections.Counter(r["disposition"] for r in rows
                                     if needs_disposition(r))
        byfam = collections.Counter(r["family"] for r in rows
                                    if needs_disposition(r))
        ok = not problems
        ok_all = ok_all and ok
        report.append({"isa": isa, "ok": ok, "rows": len(rows),
                       "gap_rows": sum(bydisp.values()),
                       "gap_families": len(byfam),
                       "by_disposition": dict(bydisp),
                       "drift": len(drift),
                       "problems": [list(p) for p in problems]})
        print("%-8s rows=%-4d gap_rows=%-4d gap_families=%-3d %s  %s"
              % (isa, len(rows), sum(bydisp.values()), len(byfam),
                 " ".join("%s=%d" % (k, bydisp[k]) for k in sorted(bydisp)),
                 "OK" if ok else "FAIL"))
        for cls, fam, msg in problems[:20]:
            print("  %-18s %-24s %s" % (cls, fam, msg))
        if len(problems) > 20:
            print("  ... and %d more" % (len(problems) - 20))
        if verbose:
            for fam, n in byfam.most_common():
                w = max((int(r["weight"] or 0) for r in rows
                         if r["family"] == fam and needs_disposition(r)),
                        default=0)
                d = sorted({r["disposition"] for r in rows
                            if r["family"] == fam and needs_disposition(r)})
                print("    %-28s rows=%-3d w=%-12d %s"
                      % (fam, n, w, ",".join(d)))
    return ok_all, report


def build_rows(isa: str, tool: Path, probes, srcmap: dict, weights: dict,
               carry: dict):
    """Score a probe table into expectation rows, carrying the human columns
    (source / disposition / justification) forward from `carry` by row key."""
    bnd = run_boundary(tool, isa, [p["hexbytes_le"] for p in probes])

    fweight = collections.Counter()
    if weights:
        pop = run_boundary(tool, isa, list(weights))
        for h, b in pop.items():
            if b["b_ok"] == "1":
                fweight[skeleton(b["b_mnem"], b["b_ops"])] += weights.get(h, 0)

    rows = []
    for p in probes:
        h = p["hexbytes_le"]
        b = bnd.get(h)
        fam = p["family"]
        src = srcmap.get(fam, PRIMARY_SOURCE[isa])
        asm = p["asm"]
        if not b or b["b_ok"] != "1":
            rows.append({"family": fam, "hex": h, "asm": asm, "kind": "-",
                         "operand": "-", "source": src, "expect": "PROBE-BAD",
                         "weight": 0, "disposition": "", "justification": ""})
            continue
        w = fweight.get(skeleton(b["b_mnem"], b["b_ops"]), 0)
        n_before = len(rows)
        for kind, want in (("READ", p.get("expect_implicit_reads", "")),
                           ("WRITE", p.get("expect_implicit_writes", ""))):
            # the spec tables use ',' or whitespace as the separator
            for raw in [x for x in re.split(r"[,\s]+", want.strip())
                        if x and x not in ("-", "none")]:
                rows.append({"family": fam, "hex": h, "asm": asm,
                             "kind": kind, "operand": raw, "source": src,
                             "expect": score_operand(isa, b, kind, raw),
                             "weight": w, "disposition": "",
                             "justification": ""})
        if len(rows) == n_before:
            # A probe whose whole expectation is NOT-MODELLED state, or a
            # deliberate negative result (the spec table carries `jr $ra` and
            # 2-operand `jalr rd,rs` precisely to record that they imply
            # NOTHING).  It still earns a row: the encoding must keep
            # decoding, so a probe that rots into PROBE-BAD is caught rather
            # than silently leaving the table.
            rows.append({"family": fam, "hex": h, "asm": asm, "kind": "-",
                         "operand": "-", "source": src, "expect": "OK",
                         "weight": w, "disposition": "", "justification": ""})
    for r in rows:
        old = carry.get(rowkey(r))
        if old:
            for c in ("source", "disposition", "justification"):
                if old.get(c) and old[c] != "-":
                    r[c] = old[c]
            # Without a population to re-weight against, keep the recorded
            # weight rather than silently zeroing every row: a regeneration
            # driven by a decoder bump has nothing to say about how often
            # an instruction form ran.
            if not weights and old.get("weight"):
                r["weight"] = old["weight"]
    order = {"MISS-BOTH": 0, "MISS-BOUNDARY": 1, "MISS-BOUNDARY-LLVMREJ": 2,
             "MISS-STRUCTURAL": 3, "PROBE-BAD": 4, "NOT-MODELLED": 5, "OK": 6}
    rows.sort(key=lambda r: (order.get(r["expect"], 9), -int(r["weight"]),
                             r["family"], r["hex"], r["kind"], r["operand"]))
    return rows


def probes_from_table(rows):
    """Reconstruct the probe list from an existing table.

    A Capstone bump does not change WHICH encodings are probed, only what
    the boundary says about them, so the common regeneration needs no
    external derivation: the table already carries every probe's encoding,
    disassembly, family and expected operands.  --probes is for the other
    case, a genuinely newer MRA / Sail / translator that adds probes.
    """
    order, byhex = [], {}
    for r in rows:
        h = r["hex"]
        if h not in byhex:
            order.append(h)
            byhex[h] = {"hexbytes_le": h, "asm": r["asm"],
                        "family": r["family"],
                        "expect_implicit_reads": [],
                        "expect_implicit_writes": []}
        if r["operand"] != "-":
            byhex[h]["expect_implicit_%ss"
                     % r["kind"].lower()].append(r["operand"])
    out = []
    for h in order:
        d = byhex[h]
        d["expect_implicit_reads"] = ",".join(d["expect_implicit_reads"])
        d["expect_implicit_writes"] = ",".join(d["expect_implicit_writes"])
        out.append(d)
    return out


def read_probes(path: Path):
    out = []
    with open(path) as f:
        hdr = f.readline().rstrip("\n").split("\t")
        for ln in f:
            fl = ln.rstrip("\n").split("\t")
            if len(fl) < 3 or not fl[0].strip():
                continue
            fl += [""] * (len(hdr) - len(fl))
            d = dict(zip(hdr, fl))
            d["hexbytes_le"] = d["hexbytes_le"].strip()
            out.append(d)
    return out


def read_srcmap(path):
    m = {}
    if not path:
        return m
    with open(path) as f:
        hdr = f.readline().rstrip("\n").split("\t")
        for ln in f:
            fl = ln.rstrip("\n").split("\t")
            if len(fl) >= len(hdr):
                d = dict(zip(hdr, fl))
                m[d["family"]] = d.get("source", "")
    return m


def read_weights(path):
    w = {}
    if not path or not os.path.exists(path):
        return w
    for ln in open(path):
        fl = ln.rstrip("\n").split("\t")
        if len(fl) >= 2 and fl[0] != "hex":
            try:
                w[fl[0]] = int(fl[1])
            except ValueError:
                pass
    return w


def mode_regenerate(tool: Path, isas, args):
    """Rebuild against a newer source and print the diff.  Never overwrites."""
    ok_all = True
    report = []
    for isa in isas:
        old_banner, old_rows = ([], [])
        tp = table_path(isa)
        if tp.is_file():
            old_banner, old_rows = read_table(tp)
        srcmap = {}
        if args.probes:
            pf = Path(args.probes) / ("%s_probes.tsv" % isa)
            if not pf.is_file():
                raise SystemExit(
                    "implicit_audit --mode regenerate: --probes names a "
                    "directory holding <isa>_probes.tsv (the "
                    "objdump-verified probe table the spec derivation "
                    "emits); missing for %s" % isa)
            sf = Path(args.probes) / ("%s_implicit.tsv" % isa)
            srcmap = read_srcmap(sf if sf.is_file() else None)
            probes = read_probes(pf)
        elif old_rows:
            probes = probes_from_table(old_rows)
        else:
            raise SystemExit(
                "implicit_audit --mode regenerate: no table at %s and no "
                "--probes to build one from" % tp)
        weights = read_weights(Path(args.weights) / ("%s.weights.tsv" % isa)
                               if args.weights else None)
        carry = {rowkey(r): r for r in old_rows}
        rows = build_rows(isa, tool, probes, srcmap, weights, carry)
        tally = collections.Counter(r["expect"] for r in rows)
        banner = [
            "# ChampSim Tracer implicit-operand assertion table — %s" % isa,
            "# Expectations derived from %s; see docs/validator.rst "
            "(features.implicit_operands) for provenance and method."
            % {"aarch64": "Arm's Machine Readable Architecture (A64 ISA XML)",
               "riscv64": "the Sail RISC-V model",
               "mipsel": "QEMU's MIPS TCG translator"}[isa],
            "# Generated by tools/implicit_audit.py --mode regenerate; the "
            "source / disposition / justification columns are written by "
            "hand and carried forward.",
            "# probes %d  rows %d  %s"
            % (len({r["hex"] for r in rows}), len(rows),
               "  ".join("%s %d" % (k, tally[k]) for k in sorted(tally))),
        ]
        new_text = render_table(isa, banner, rows)
        old_text = tp.read_text() if tp.is_file() else ""
        TABLE_DIR.mkdir(parents=True, exist_ok=True)
        outp = tp.with_suffix(".tsv.new")
        outp.write_text(new_text)
        diff = list(difflib.unified_diff(
            old_text.splitlines(True), new_text.splitlines(True),
            fromfile=str(tp), tofile=str(outp)))
        changed = bool(diff)
        ok_all = ok_all and not changed
        report.append({"isa": isa, "ok": not changed, "rows": len(rows),
                       "tally": dict(tally), "diff_lines": len(diff),
                       "written": str(outp)})
        print("%-8s rows=%-4d %s  ->  %s  (%s)"
              % (isa, len(rows),
                 " ".join("%s=%d" % (k, tally[k]) for k in sorted(tally)),
                 outp.name,
                 "no change" if not changed else "%d diff lines" % len(diff)))
        if changed:
            sys.stdout.writelines(diff[:args.diff_lines])
            if len(diff) > args.diff_lines:
                print("... %d more diff lines (full file at %s)"
                      % (len(diff) - args.diff_lines, outp))
    if not ok_all:
        print("\nregenerate: the table MOVED.  Review the diff, then promote "
              "each <isa>.tsv.new over <isa>.tsv by hand and give every new "
              "non-OK row a disposition + justification.")
    return ok_all, report


def main():
    ap = argparse.ArgumentParser(
        description="implicit-operand assertion table for the ChampSim "
                    "Tracer decode boundary")
    ap.add_argument("--mode", default="assert",
                    choices=("assert", "known-gap", "regenerate"))
    ap.add_argument("--isa", action="append", default=None,
                    help="restrict to one ISA (repeatable); default all")
    ap.add_argument("--tool", default=None, help="path to isaxcheck")
    ap.add_argument("--build-dir", default=None,
                    help="build dir holding contrib/plugins/isaxcheck")
    ap.add_argument("--probes", default=None,
                    help="regenerate: directory holding <isa>_probes.tsv "
                         "(and optionally <isa>_implicit.tsv for sources) "
                         "of a NEWER derivation; omit to re-score the "
                         "probes the existing table already carries")
    ap.add_argument("--weights", default=None,
                    help="regenerate: directory holding <isa>.weights.tsv, "
                         "hex<TAB>dynamic count of a traced population")
    ap.add_argument("--diff-lines", type=int, default=200)
    ap.add_argument("--json", default=None, help="write a JSON summary here")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    isas = a.isa or list(ISAS)
    for i in isas:
        if i not in ISAS:
            raise SystemExit("implicit_audit: unknown isa %r (have %s)"
                             % (i, ", ".join(ISAS)))
    if a.mode != "regenerate":
        for i in isas:
            if not table_path(i).is_file():
                raise SystemExit("implicit_audit: no table at %s"
                                 % table_path(i))
    tool = find_tool(a.tool, a.build_dir)

    if a.mode == "assert":
        ok, report = mode_assert(tool, isas, a.verbose)
    elif a.mode == "known-gap":
        ok, report = mode_known_gap(tool, isas, a.verbose)
    else:
        ok, report = mode_regenerate(tool, isas, a)

    if a.json:
        Path(a.json).write_text(json.dumps(
            {"mode": a.mode, "ok": ok, "isas": report}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
