#!/usr/bin/env python3
"""THE SLED'S REACHABILITY INSTRUMENT: did the sweep reach an INSTRUCTION, or
only an encoding QEMU declined to be one?

WHY THE LOSS BAR NEEDED THIS BEFORE IT NEEDED ANYTHING ELSE
-----------------------------------------------------------
`srcenc_ab` scores a register published for an encoding in one arm and absent
in the other.  It is keyed on the encoding, and over the sled that key is the
whole population -- 8.4M encodings, most of which no guest will ever execute.
That was accepted as a superset: a bar that over-counts is safe.

It is not a superset.  exec89 measured that 2,908,759 "losing" encodings
include at least 559,523 (19.2%) the sweep reaches as ENCODINGS and never as
INSTRUCTIONS, and two different things were being counted as one:

  * 521,123 rows read `decode_id=0`, `rule=?`.  QEMU decoded NOTHING.  The
    encoding is unimplemented (`c1000000` takes SIGILL in a real aarch64
    guest) or illegal in the sled's flat architectural context and legal in a
    real one (`vadd.vv` reads id 0 here and `decode_insn32/vadd_vv` in a guest
    that ran `vsetvli` first).  There is no statement for a register to be
    missing FROM.

  * 38,400 rows carry a NAMED rule -- `disas_sme/LDST1` -- and are still not
    an instruction: `sme_smza_enabled_check()` returns early, QEMU translates
    the ACCESS TRAP, and no operand is ever touched.  Every other column on
    that row reads exactly like an instruction with few stated reads.

Scoring either as a loss is scoring the sled's own context.  A bar computed
over them is not a bar, which is why this instrument blocks the deletion.

THE DISCRIMINATOR IS STRUCTURAL, NOT A LIST OF RULE NAMES
---------------------------------------------------------
A rule-name allowlist would be the dead-allowlist trap this tree keeps
filing: it goes stale the moment a decoder moves, and it cannot answer for a
rule nobody has looked at.  The classification here reads what the TRANSLATOR
EMITTED, from columns the plugin's mechanism corpus carries:

  decode_id   QEMU's own decode-table slot.  0 means no identity was recorded.
  XLAT        noret= calls= memr= memw= -- the translation's SHAPE.  `noret`
              is the count of calls the translator declared TCG_CALL_NO_RETURN,
              which on every target is how a translation RAISES instead of
              computing.  It is TCG's own flag, set by the DEF_HELPER
              declaration and acted on by the register allocator, not an
              annotation invented for this reader.
  RD          QEMU's ordered read list.
  WR          QEMU's write side, by generic name.

    INSTRUCTION      QEMU produced an identity and the translation is a body.
    NO-DECODE        decode_id == 0.  QEMU never decoded it.
    TRAP-TRANSLATED  an identity, and the translation is an ENABLE CHECK that
                     refused: it raised (noret >= 1), performed no access,
                     wrote no architectural destination, and READ THE GATE --
                     a non-empty read list consisting only of system state.

WHY THE GATE MUST BE STATE THE TRANSLATION READ AND DID NOT WRITE
-----------------------------------------------------------------
"Read only system state" alone is not the gate check.  EVERY raising
translation reads and writes its own exception bookkeeping, so a register in
both lists is the raise's own housekeeping and is no evidence that anything
consulted a gate.  MIPS `teq $0,$0` is the class this cost: QEMU folds the
comparison away because both operands are the zero register, emits an
unconditional raise, and states `RD=REG_SYSEXC WR=REG_PC,REG_SYSEXC`.  The
first reading of this discriminator classified all 207 such mipsel encodings
(TEQ / TGE / TGEU / TEQI / TGEI / TGEIU / SDBBP with zero operands) as gate
checks and excluded them -- and their lost register is `REG_ZERO`, which under
R15 is architectural truth QEMU merely does not lower.  Excluding them would
have hidden a real loss, which is the one direction R12.1 forbids.

So the gate must be state the translation READ AND DID NOT WRITE.  SME's
enable check reads `REG_SYSFPEN` and writes only `REG_PC`; `teq $0,$0` reads
nothing it does not also write, and stays in the bar.

WHY THE READ LIST MUST BE NON-EMPTY AND ALL-SYSTEM, AND WHAT THAT LEAVES IN
--------------------------------------------------------------------------
`svc`, `brk`, `udf` and x86 `syscall` also raise through a noreturn helper,
perform no access and write only the program counter -- and for those the
exception IS the instruction body.  They read NOTHING, so they fall to
INSTRUCTION and stay inside the bar.  That direction is deliberate and it is
the conservative one: x86 `syscall` architecturally writes RCX and R11 inside
`helper_syscall`, so excluding it would HIDE a real loss, which is exactly
the error R12.1 forbids.  An excluded row has to be justified; an
unconditional body trap cannot be, so it is not excluded.

What the non-empty all-system read list DOES name is the gate check itself:
`disas_sme/LDST1` reads `REG_SYSFPEN` and nothing else, because
`sme_smza_enabled_check()` consulted the enable state and refused on it.

"System" is read from the tracer's own register NAMESPACE (the `REG_SYS`
prefix) plus the program counter, not from a hand-written set of register
names -- the namespace is generated, so it cannot go stale under this reader
the way a list would.

WHAT THIS INSTRUMENT DOES NOT CLAIM
-----------------------------------
It does not claim the excluded encodings are unreachable in every context.
They are unreachable IN THE SLED'S, which is the context the corpus was taken
in and the only one its rows describe.  Where a class is excluded because the
sled's context caused it, `--report` says so per class, and the exclusion is
argued against a MEASURED witness (see `--witness`) rather than as prose: an
encoding QEMU never decodes is never traced, so the operand walk's registers
for it never reach a wire, and the way to show that is to look at a real
guest's traces and find it absent.

Run with --selftest for the constructed-case proof: every class reached by a
row, and firing controls in BOTH directions -- a trap row that loses its
`noret` is CLASSIFIED AS AN INSTRUCTION, and an instruction row given one is
CLASSIFIED AS A TRAP.  A discriminator nobody has shown can misfire is not a
discriminator.

Author: Maccoy Merrell.
"""
import argparse
import bz2
import gzip
import lzma
import os
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")

REACH_INSN = "INSTRUCTION"
REACH_NODEC = "NO-DECODE"
REACH_TRAP = "TRAP-TRANSLATED"
REACH_UNREADABLE = "UNREADABLE"

#: The register namespace's SYSTEM half, by prefix.  The tracer generates
#: these names, so a prefix test tracks the generator; an enumeration of the
#: names would not.  REG_PC is included because every raise writes it and no
#: raise writes it as an architectural destination the encoding named.
SYS_PREFIXES = ("REG_SYS",)
SYS_EXACT = ("REG_PC",)


def _is_system(reg):
    return reg.startswith(SYS_PREFIXES) or reg in SYS_EXACT


def _open(path):
    """Corpora are banked compressed (the I/O rule); read them as they lie."""
    if path.endswith(".xz"):
        return lzma.open(path, "rt", errors="replace")
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    if path.endswith(".bz2"):
        return bz2.open(path, "rt", errors="replace")
    if path.endswith(".zst"):
        import subprocess
        p = subprocess.Popen(["zstd", "-dcq", path],
                             stdout=subprocess.PIPE, text=True)
        return p.stdout
    return open(path, errors="replace")


def parse_xlat(s):
    """`noret=1,calls=1,memr=0,memw=0` -> dict, or None where the plugin
       wrote `shape=-` because the status read itself failed.  An ABSENT
       count is not a zero and this returns None rather than a dict of
       zeroes -- a reader that took the two for each other would classify
       every unreadable row as an instruction."""
    out = {}
    for part in s.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k == "shape":
            return None
        try:
            out[k] = int(v)
        except ValueError:
            return None
    if "noret" not in out:
        return None
    return out


def reglist(s):
    return [r for r in s.replace(" ", "").split(",") if r and r != "-"]


def classify(row):
    """One mechanism row -> (reach, subclass, why).

       @row is a dict keyed by the mechanism corpus's own header names.  The
       four columns it reads are decode_id, XLAT, RD and WR; nothing here
       looks at a rule name, a mnemonic or an ISA."""
    xl = parse_xlat(row.get("XLAT", ""))
    if xl is None:
        # The shape is ABSENT, not zero.  Refuse to classify rather than
        # let an unreadable row default into the population being scored.
        return REACH_UNREADABLE, "no-shape", \
            "the dataflow status read failed; the counts are absent, not zero"

    try:
        did = int(row.get("decode_id", "0"), 16)
    except ValueError:
        did = 0
    if did == 0:
        return REACH_NODEC, "no-identity", \
            "decode_id=0: QEMU recorded no decode-table slot, so there is " \
            "no statement a register can be missing from"

    rd = reglist(row.get("RD", ""))
    wr = reglist(row.get("WR", ""))
    raises = xl.get("noret", 0) >= 1
    accesses = xl.get("memr", 0) + xl.get("memw", 0)
    arch_wr = [r for r in wr if not _is_system(r)]
    arch_rd = [r for r in rd if not _is_system(r)]

    # The GATE is state the translation READ AND DID NOT WRITE.  A register
    # in both lists is the raise's own exception bookkeeping and is evidence
    # of nothing -- see the header's `teq $0,$0` block.
    gate = [r for r in rd if r not in set(wr)]

    if raises and accesses == 0 and not arch_wr and not arch_rd and gate:
        return REACH_TRAP, "gate-check", \
            "raised through a noreturn helper having performed no access, " \
            "written no architectural destination, and CONSULTED system " \
            "state it does not write (%s): an enable check that refused" \
            % ",".join(gate)

    if raises and accesses == 0 and not arch_wr and not gate:
        # svc / brk / udf / syscall: the exception IS the body, the
        # instruction has no operands, and it STAYS IN THE BAR.
        return REACH_INSN, "body-trap", \
            "raised having consulted no state it does not also write: an " \
            "unconditional trap whose body is the exception, not a context " \
            "gate that refused"

    return REACH_INSN, "body", "QEMU translated a body"


def read_mech(path):
    """[(row-dict)], header-checked.  A file missing the columns this reads
       REFUSES: a corpus taken before the XLAT column existed would classify
       every row UNREADABLE and read as a clean exclusion of nothing."""
    rows, hdr = [], None
    with _open(path) as fh:
        for line in fh:
            if line.startswith("#"):
                if hdr is None:
                    hdr = line.lstrip("#").rstrip("\n").split("\t")
                continue
            f = line.rstrip("\n").split("\t")
            if hdr is None or len(f) < len(hdr):
                continue
            rows.append(dict(zip(hdr, f)))
    if hdr is None:
        raise SystemExit("srcenc_reach: %s has no header row -- REFUSING"
                         % path)
    for need in ("encoding", "decode_id", "rule", "RD", "WR", "XLAT"):
        if need not in hdr:
            raise SystemExit(
                "srcenc_reach: %s carries no '%s' column -- REFUSING.  This "
                "corpus predates the translation-shape columns; classifying "
                "it would report every row UNREADABLE, which downstream "
                "cannot tell from an honest exclusion of nothing." % (path, need))
    if not rows:
        raise SystemExit("srcenc_reach: %s carried no rows -- REFUSING "
                         "(an empty corpus is not a clean one)" % path)
    return rows


def do_classify(paths, out):
    """Write <isa>\\t<encoding>\\t<reach>\\t<subclass>\\t<rule>\\t<mnem>."""
    n = 0
    with open(out, "w") as fh:
        fh.write("#isa\tencoding\treach\tsubclass\trule\tmnem\n")
        for p in paths:
            for r in read_mech(p):
                reach, sub, _ = classify(r)
                fh.write("%s\t%s\t%s\t%s\t%s\t%s\n"
                         % (r.get("isa", "?"), r["encoding"].lower(), reach,
                            sub, r.get("rule", "?"), r.get("mnem", "?")))
                n += 1
    return n


def read_reach(path):
    out = {}
    with _open(path) as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 4:
                continue
            out[(f[0], f[1].lower())] = (f[2], f[3],
                                         f[4] if len(f) > 4 else "?",
                                         f[5] if len(f) > 5 else "?")
    if not out:
        raise SystemExit("srcenc_reach: %s carried no rows -- REFUSING" % path)
    return out


# -------------------------------------------------------------------------
# THE SELFTEST.  Constructed rows, one per class, plus firing controls in
# BOTH directions.  The rows are the real exemplars' own columns, taken from
# a live capture, so a change that moves what the plugin writes fails here
# rather than silently reclassifying a population.
# -------------------------------------------------------------------------
_EX_INSN = dict(isa="aarch64", encoding="2000028b", mnem="add",
                decode_id="488ccfe4", rule="disas_a64/ADD_r",
                RD="REG_GPR1,REG_GPR2", WR="REG_GPR0",
                XLAT="noret=0,calls=0,memr=0,memw=0")
_EX_LOAD = dict(isa="aarch64", encoding="000040f9", mnem="ldr",
                decode_id="b91f3fad", rule="disas_a64/LDR_i",
                RD="REG_GPR0", WR="REG_GPR0",
                XLAT="noret=0,calls=0,memr=1,memw=0")
_EX_NODEC = dict(isa="aarch64", encoding="c1000000", mnem="udf",
                 decode_id="00000000", rule="?", RD="-", WR="REG_PC",
                 XLAT="noret=1,calls=1,memr=0,memw=0")
_EX_TRAP = dict(isa="aarch64", encoding="000040e0", mnem="ld1h",
                decode_id="f9e0bce3", rule="disas_sme/LDST1",
                RD="REG_SYSFPEN", WR="REG_PC",
                XLAT="noret=1,calls=1,memr=0,memw=0")
_EX_SVC = dict(isa="aarch64", encoding="010000d4", mnem="svc",
               decode_id="d7983768", rule="disas_a64/SVC", RD="-", WR="REG_PC",
               XLAT="noret=1,calls=1,memr=0,memw=0")
#: MIPS `teq $0,$0`, from the live mipsel sweep.  QEMU folds the comparison
#: away (both operands are the zero register), raises unconditionally, and
#: reads nothing it does not also write.  Its lost register is REG_ZERO.
_EX_TEQ0 = dict(isa="mipsel", encoding="34000000", mnem="teq",
                decode_id="d5f4ab5f", rule="translate_mips/OPC_TEQ",
                RD="REG_SYSEXC", WR="REG_PC,REG_SYSEXC",
                XLAT="noret=1,calls=1,memr=0,memw=0")
_EX_NOSHAPE = dict(isa="x86_64", encoding="0f0b", mnem="ud2",
                   decode_id="11111111", rule="illegal_op", RD="-", WR="-",
                   XLAT="shape=-")


def selftest():
    fails = []

    def arm(name, row, want_reach, want_sub=None):
        got, sub, _ = classify(row)
        ok = got == want_reach and (want_sub is None or sub == want_sub)
        print("%-4s %-46s -> %-15s %-12s %s"
              % ("PASS" if ok else "FAIL", name, got, sub,
                 "" if ok else "(wanted %s/%s)" % (want_reach, want_sub)))
        if not ok:
            fails.append(name)

    print("--- the three KNOWN exemplars ---")
    arm("A  a real instruction (add x0,x1,x2)", _EX_INSN, REACH_INSN, "body")
    arm("B  smlall c1000000, the SIGILL class", _EX_NODEC, REACH_NODEC,
        "no-identity")
    arm("C  disas_sme/LDST1 000040e0, the trap", _EX_TRAP, REACH_TRAP,
        "gate-check")

    print("--- the classes the exemplars do not cover ---")
    arm("D  a load (memr=1) is a body", _EX_LOAD, REACH_INSN, "body")
    arm("E  svc: a BODY trap stays in the bar", _EX_SVC, REACH_INSN,
        "body-trap")
    arm("F  an absent shape is UNREADABLE, not clean", _EX_NOSHAPE,
        REACH_UNREADABLE, "no-shape")

    arm("E2 teq $0,$0: bookkeeping is not a gate", _EX_TEQ0, REACH_INSN,
        "body-trap")

    print("--- FIRING CONTROLS, both directions ---")
    # 1. A genuine trap that LOSES its noreturn signal must stop being a
    #    trap.  If it did not, the classifier would be answering from the
    #    rule name or the register list, not from the translation's shape.
    t = dict(_EX_TRAP, XLAT="noret=0,calls=1,memr=0,memw=0")
    arm("G  trap with noret=0 is NOT excluded", t, REACH_INSN, "body")
    # 2. A real instruction GIVEN a noreturn signal must not become a trap:
    #    it writes an architectural destination and reads architectural
    #    registers, and either alone must keep it in.
    i = dict(_EX_INSN, XLAT="noret=1,calls=1,memr=0,memw=0")
    arm("H  add with noret=1 is STILL an instruction", i, REACH_INSN, "body")
    # 3. ... and the same instruction stripped to the trap's exact shape
    #    MUST classify as a trap, or the discriminator is inert and control
    #    H proved nothing.
    i2 = dict(_EX_INSN, RD="REG_SYSFPEN", WR="REG_PC",
              XLAT="noret=1,calls=1,memr=0,memw=0")
    arm("I  ... but stripped to the trap's shape it IS one", i2, REACH_TRAP,
        "gate-check")
    # 4. A trap-shaped row that performs an ACCESS is a body: QEMU reached
    #    the operand.
    t2 = dict(_EX_TRAP, XLAT="noret=1,calls=1,memr=1,memw=0")
    arm("J  a raise that ALSO accessed memory is a body", t2, REACH_INSN,
        "body")
    # 5. A trap-shaped row that writes an architectural destination is a
    #    body -- the write is an operand QEMU named.
    t3 = dict(_EX_TRAP, WR="REG_PC,REG_GPR3")
    arm("K  a raise that wrote a GPR is a body", t3, REACH_INSN, "body")
    # 5b. A gate register the instruction ALSO WRITES is bookkeeping, not a
    #     gate: the trap's own exemplar with SYSFPEN moved into the write
    #     list must stop being a trap.
    t4 = dict(_EX_TRAP, WR="REG_PC,REG_SYSFPEN")
    arm("K2 a 'gate' the raise also WRITES is not one", t4, REACH_INSN,
        "body-trap")
    # 5c. ... and the converse: teq's row with the exception state removed
    #     from the WRITE list becomes a gate check, so arm E2's answer comes
    #     from the read/write join and not from the ISA or the rule name.
    t5 = dict(_EX_TEQ0, WR="REG_PC")
    arm("K3 ... and teq WITHOUT that write IS a gate check", t5, REACH_TRAP,
        "gate-check")
    # 6. decode_id wins over everything: no identity, no statement.
    n2 = dict(_EX_INSN, decode_id="00000000")
    arm("L  decode_id=0 outranks a clean body shape", n2, REACH_NODEC,
        "no-identity")

    print("failures=%d" % len(fails))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--mech", action="append", default=[],
                    help="a mechanism corpus (corpus_mech_<isa>.tsv[.xz])")
    ap.add_argument("--out", help="write the reach corpus here")
    ap.add_argument("--report", action="store_true",
                    help="print the population by class, and by RULE within "
                         "each excluded class")
    ap.add_argument("--top", type=int, default=25)
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.mech:
        raise SystemExit("srcenc_reach: --mech is required -- REFUSING")

    rows = []
    for p in a.mech:
        rows += read_mech(p)

    if a.out:
        n = do_classify(a.mech, a.out)
        print("reach corpus %s rows=%d" % (a.out, n))

    if a.report:
        by = {}
        rules = {}
        for r in rows:
            reach, sub, _ = classify(r)
            isa = r.get("isa", "?")
            by.setdefault(isa, {}).setdefault((reach, sub), 0)
            by[isa][(reach, sub)] += 1
            if reach != REACH_INSN:
                rules.setdefault((isa, reach), {}).setdefault(
                    r.get("rule", "?"), 0)
                rules[(isa, reach)][r.get("rule", "?")] += 1
        print("=== REACH, per ISA ===")
        for isa in sorted(by):
            tot = sum(by[isa].values())
            print("  %s  total=%d" % (isa, tot))
            for k in sorted(by[isa], key=lambda k: -by[isa][k]):
                print("    %-16s %-12s %9d  %5.1f%%"
                      % (k[0], k[1], by[isa][k], 100.0 * by[isa][k] / tot))
        print("=== THE EXCLUDED POPULATION, BY RULE ===")
        for key in sorted(rules):
            print("  %s / %s" % key)
            tot = sum(rules[key].values())
            for rn in sorted(rules[key], key=lambda r: -rules[key][r])[:a.top]:
                print("    %-58s %9d" % (rn[:58], rules[key][rn]))
            print("    (%d distinct rules, %d encodings)"
                  % (len(rules[key]), tot))
    return 0


if __name__ == "__main__":
    sys.exit(main())
