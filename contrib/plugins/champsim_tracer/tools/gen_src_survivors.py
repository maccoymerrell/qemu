#!/usr/bin/env python3
"""Emit champsim_tracer_src_survivors.h from the plugin's own source census.

WHY A GENERATOR AND NOT A TABLE.  The rows below are a MEASUREMENT: for each
instruction the tracer's per-ISA decode publishes as a source and QEMU's
ordered read list does not justify, which decode rule it belongs to and how
the register is reached.  Hand-copying that measurement into a header is how
the number and the table drift apart, and the mnemonic tables in this
directory are generated for exactly that reason.  The input is the census
block the plugin prints into every stats sidecar; the output is the header
the plugin compiles.

INPUT.  One stats sidecar per ISA, each containing the block headed
"SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY".  Its rows read

    <count>  <decode_id>  <rule name>  <generic register>  <role>  <mnemonic>

where <role> is SELF@<p> when the register the wire publishes as a source is
also the register the wire publishes as DESTINATION NUMBER p of the same
instruction, and FIXED when it is not a destination at all.  That distinction
is the whole of the classification and it is read, never guessed:

  FIXED  the register is a property of the RULE -- x86 `ret` reads SS, an
         aarch64 FP instruction reads the FP-enable gate.  The row carries the
         register's generic id, because it is the same register on every
         instruction the rule decodes.
  SELF   the register is a property of the INSTANCE -- `movlpd` merges into
         whichever XMM the encoding names, `mthc1` into whichever FPR.  The
         row carries NO register: it says "destination number p of this rule
         is also one of its sources", and the register is read at translation
         time from that ONE position in the instruction's own destination
         list.

         THE POSITION IS NOT DECORATION.  Without it the row supplied the
         whole destination list, and an aarch64 `fadd v0.2d,v1.2d,v2.2d` --
         whose survivor is REG_FCSR, a destination as well as a source --
         handed REG_VEC0 to a wire that never published it.  Eight
         fabricated registers on the golden net, from four rules.

A rule that shows BOTH roles gets both kinds of row.

A TABLE DERIVED FROM ONE CORPUS IS A SNAPSHOT, NOT A CLOSURE, and this is
measured rather than hoped: the first table this generator emitted was built
from one workload and the plugin's own flip-cost census immediately reported
16 published sources it did not carry on the golden-net workloads -- fourteen
aarch64 FP/SIMD rules the first corpus never executed, one x86 `movsd` and
one mipsel `addu rd,rs,$zero`.  The CLASSES were right; the ROW SET was the
corpus's.  So the generator takes as many sidecars per ISA as the caller has,
and the caller is expected to hand it every corpus the tree gates on.

THREE THINGS THIS REFUSES TO DO, each because it did them once and the
result was false:

1. IT WILL NOT READ A LIVE PATH.  The sidecars it reads are produced by
   `golden_net.py validate`, which deletes and re-creates the cell
   directories it is about to run.  A generator reading those paths directly
   races the gate that writes them, and a table derived half from one run and
   half from the next is not derived from anything.  So emitting requires a
   SNAPSHOT: `--snapshot DIR <isa>=<path> ...` copies every input into DIR
   and writes DIR/MANIFEST.sha256; `--out H --from-snapshot DIR` re-verifies
   every copy against that manifest and emits from the copies alone.  A
   changed byte, a missing file, or a bare path handed to the emit mode is a
   refusal, not a warning.

2. IT WILL NOT SAY AN EMPTY TABLE IS TRUE OF THE ISA.  The header this
   generator emitted before carried, for riscv64, the sentence "every
   published source on this ISA is justified by QEMU's read list, so the
   flip has nothing to carry".  Measured against the golden net at the same
   tip, riscv64 was the WORST ISA: 139 published sources the union did not
   contain.  The sentence was not false about the corpus it was derived
   from -- that corpus really did print `(none)` -- it was false about the
   ISA, which is what it said.  An empty table is now written as a fact
   about THE SIDECARS, named and counted, and the header refuses the
   generalisation in its own words.

3. IT WILL NOT KEY A ROW ON A DECODE ID THAT CARRIES MORE THAN ONE
   INSTRUCTION.  x86 decode id 0x00000776 is QEMU's `x87` slot and carries
   `fldt`, `fstpt` and `fucomi`; a row derived from `fstpt` and keyed on the
   id alone fired on `fldt`, which does not read FPR0, and the plugin's own
   FABRICATION row read 2.  The census already measures this, twice, and the
   generator reads BOTH:

     the DECODE-IDENTITY COLLISION WITNESS -- (decode id, rule, mnemonic)
       over the WHOLE scored population.  An id printed with two different
       mnemonics is one rule carrying several instructions, and that is the
       criterion, because it is the exact condition under which an id-keyed
       row fabricates.  It is strictly wider than the one below: x86
       0x0000054b is QEMU's NOP slot, carries `endbr64` beside `rdsspq`, and
       the census does NOT call it split (it is adjudicated), so a table
       keyed on the id alone would have handed 410 `endbr64` rows a
       REG_GPR0 + REG_SSP source they do not have.
     the QID_SPLIT set, from "SURVIVOR rules REACHED by this run", kept as
       well because it names ids whose CLASSIFICATION is ambiguous even when
       this corpus happened to reach only one spelling.

4. IT WILL NOT CARRY A ROW THE CENSUS COUNTS AS ADJUDICATION-OWED.  Those
   are the (id, register) pairs whose deletion was written, landed, measured
   against the external references and REVERTED because the references
   contradicted it.  Carrying one would move it out of the loss direction
   and drop the ADJUDICATION-OWED count to zero, and that count is the thing
   that says no source-list flip may land while a maintainer question is
   open.  Answering an open question by making its counter read zero is the
   failure this whole file is shaped against, so those rows are refused with
   their own reason and stay owed.

   The refused rows are printed and written into the header as a comment,
   because a row that is not carried stays in the loss direction and blocks
   the flip -- that has to be visible rather than silently absent.

   A RULED ROW IS A DIFFERENT ROW, AND IT IS CARRIED.  The ledger the census
   prints has two states and marks them apart in the row itself: an OPEN row
   reads `Q: <question>` and a row a ruling has closed reads
   `R16: <ruling>`.  Only the `Q:` form is refused here.  That is not an
   accident of the regex, it is the rule: a ruling that the wire is right is
   exactly the statement that a flip MUST keep publishing the register, so
   the survivor table -- which is how a flip says what it carries -- has to
   carry it.  Refusing a ruled row would make the flip delete a register a
   maintainer has just ruled architectural, which is the R12.1 direction
   that is never available.  Proven by ARM D2 of the selftest, which plants
   an `R16:` row and requires it to appear in the emitted header.

5. IT WILL NOT KEY A ROW ON AN ABSENT DECODE IDENTITY.  The census prints
   a row whose rule QEMU did not name as decode id `00000000` with the rule
   spelled `?`.  That is not a weak identity, it is the statement that there
   is no identity, and it fails the table's key in the widest possible way:
   a row keyed on id 0 fires on EVERY instruction whose decode rule is
   unknown, on every ISA, forever.  Refusal 3 cannot catch it -- its test is
   whether the id carries more than one mnemonic, and within any one corpus
   the absent id has usually only collected one.

   The first full-coverage snapshot produced exactly this: mipsel `swc2`
   (a COP2 store) arrived with REG_COPROC0 and REG_GPR7 under id 0 from a
   WRONG-PATH excursion decoding undefined bytes.  It is not reproducible --
   the same cell, same binary, same options, same `setarch -R` produced it
   in 1 run of 12, and with a different row count -- so carrying it would
   have written run-to-run noise into a compiled table.  Refused with its
   own reason, and counted in the loss direction like every other refusal.

Usage:
  gen_src_survivors.py --snapshot DIR <isa>=<stats.log> [<isa>=<stats.log> ...]
  gen_src_survivors.py --out <header> --from-snapshot DIR
  gen_src_survivors.py --selftest

An ISA may be repeated; the rows union.

Author: Maccoy Merrell.
"""
import hashlib
import os
import re
import shutil
import sys
import tempfile

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")
HDR = "SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY"
SPLIT_HDR = "SURVIVOR rules REACHED by this run"
WITNESS_HDR = "DECODE-IDENTITY COLLISION WITNESS"
OWED_HDR = "ADJUDICATION-OWED -- published sources"
ROW = re.compile(r"^\s*(\d+)\s+([0-9a-f]{8})\s+(\S+)\s+(REG_\S+)\s+(SELF@\d+|FIXED)\s+(\S+)\s*$")
SPLIT_ROW = re.compile(r"^\s*0x([0-9a-f]{8})\s+QID_SPLIT\s")
WITNESS_ROW = re.compile(r"^\s*\d+\s+([0-9a-f]{8})\s+(\S+)\s+(\S+)\s*$")
# An OPEN ledger row, and ONLY an open one: the census marks a ruled row
# `R16:` in the same column, and a ruled row is carried (docstring item 4).
OWED_ROW = re.compile(r"^\s*\d+\s+([0-9a-f]{8})\s+(\S+)\s+(REG_\S+)\s+\S+\s+Q:")
RULED_ROW = re.compile(r"^\s*\d+\s+([0-9a-f]{8})\s+(\S+)\s+(REG_\S+)\s+\S+\s+R16:")
MANIFEST = "MANIFEST.sha256"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse(path):
    """Return (rows, ambiguous_ids, owed, saw_none) for one sidecar.

    rows           {(decode_id, role, reg): (rule, count, {mnemonics})}
    ambiguous_ids  {decode_id} that must not key a row: the collision
                   witness shows the id carrying more than one mnemonic, or
                   the census reports it QID_SPLIT
    owed           {(decode_id, reg)} the census counts as ADJUDICATION-OWED
    saw_none       True when the survivor block was present and read `(none)`
    """
    text = open(path, "r", errors="replace").read()
    if HDR not in text:
        sys.exit("FAIL %s: no survivor block -- the census did not run" % path)

    split_ids = set()
    if SPLIT_HDR in text:
        for line in text.split(SPLIT_HDR, 1)[1].splitlines():
            m = SPLIT_ROW.match(line)
            if m:
                split_ids.add(int(m.group(1), 16))
            elif split_ids and not line.strip():
                # The block ends at its first blank line; the lines BEFORE the
                # first row are the block's own prose (and the tail of the
                # header line the split above cut), which must not end it.
                break

    if WITNESS_HDR in text:
        seen = {}
        for line in text.split(WITNESS_HDR, 1)[1].splitlines():
            m = WITNESS_ROW.match(line)
            if m:
                seen.setdefault(int(m.group(1), 16), set()).add(m.group(3))
            elif seen and not line.strip():
                break
        for did, mn in seen.items():
            if len(mn) > 1:
                split_ids.add(did)

    owed = set()
    if OWED_HDR in text:
        for line in text.split(OWED_HDR, 1)[1].splitlines():
            m = OWED_ROW.match(line)
            if m:
                owed.add((int(m.group(1), 16), m.group(3)))
            elif RULED_ROW.match(line):
                # A ruled row sits in the same ledger and is deliberately
                # NOT added: it is carried.  Matched explicitly so that a
                # future third state cannot fall through as "not owed".
                continue
            elif owed and not line.strip():
                break

    block = text.split(HDR, 1)[1]
    rows, seen_any = {}, False
    for line in block.splitlines():
        if line.strip() == "(none)":
            return rows, split_ids, owed, True
        m = ROW.match(line)
        if not m:
            if seen_any and not line.strip():
                break
            continue
        seen_any = True
        cnt, did, rule, reg, role, mnem = m.groups()
        key = (int(did, 16), role, reg if role == "FIXED" else "")
        _, c, mn = rows.get(key, (rule, 0, set()))
        rows[key] = (rule, c + int(cnt), mn | {mnem})
    if not seen_any:
        sys.exit("FAIL %s: survivor block present but unparsable" % path)
    return rows, split_ids, owed, False


def make_snapshot(dest, inputs):
    """Copy every input under @dest and record its sha256.  The copies are
    what the emit mode reads, so a gate re-running underneath cannot move the
    table's inputs out from under it."""
    os.makedirs(dest, exist_ok=True)
    lines, n = [], 0
    for isa in ISAS:
        for i, path in enumerate(inputs.get(isa, [])):
            if not os.path.isfile(path):
                sys.exit("FAIL: no such sidecar: %s" % path)
            name = "%s.%02d.%s" % (isa, i, os.path.basename(path))
            shutil.copyfile(path, os.path.join(dest, name))
            lines.append("%s  %s  %s" % (sha256(path), name, os.path.abspath(path)))
            n += 1
    if not n:
        sys.exit("FAIL: --snapshot with no inputs; a snapshot of nothing is "
                 "not a corpus")
    with open(os.path.join(dest, MANIFEST), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("snapshot %s: %d sidecar(s), manifest %s" % (dest, n, MANIFEST))
    return 0


def read_snapshot(src):
    """Verify @src against its manifest and return {isa: [paths]}."""
    man = os.path.join(src, MANIFEST)
    if not os.path.isfile(man):
        sys.exit("FAIL: %s has no %s -- emitting is only allowed from a "
                 "snapshot this tool made (a live path races the gate that "
                 "writes it)" % (src, MANIFEST))
    out, n = {}, 0
    for line in open(man):
        line = line.rstrip("\n")
        if not line:
            continue
        want, name, origin = line.split("  ", 2)
        path = os.path.join(src, name)
        if not os.path.isfile(path):
            sys.exit("FAIL: snapshot %s is missing %s (from %s)"
                     % (src, name, origin))
        got = sha256(path)
        if got != want:
            sys.exit("FAIL: snapshot %s: %s changed under us\n"
                     "  manifest %s\n  now      %s" % (src, name, want, got))
        isa = name.split(".", 1)[0]
        if isa not in ISAS:
            sys.exit("FAIL: snapshot %s: %s names no known ISA" % (src, name))
        out.setdefault(isa, []).append(path)
        n += 1
    if sorted(out) != sorted(ISAS):
        sys.exit("FAIL: snapshot %s covers %s; all four ISAs are required "
                 "(a table missing an ISA reads as 'this ISA has no "
                 "survivors', which is the falsehood this refuses to emit)"
                 % (src, sorted(out)))
    print("snapshot %s verified: %d sidecar(s), all four ISAs" % (src, n))
    return out


def emit(out, inputs, src):
    per, splits, seen, clean, owed = {}, {}, {}, {}, {}
    for isa in ISAS:
        merged, sp, ow, files, all_none = {}, set(), set(), 0, True
        for path in inputs[isa]:
            rows, s, o, saw_none = parse(path)
            files += 1
            sp |= s
            ow |= o
            if not saw_none:
                all_none = False
            for key, (rule, cnt, mn) in rows.items():
                _, c0, m0 = merged.get(key, (rule, 0, set()))
                merged[key] = (rule, c0 + cnt, m0 | mn)
        per[isa], splits[isa], seen[isa], owed[isa] = merged, sp, files, ow
        clean[isa] = all_none and files > 0

    # REFUSAL 3: an id that carries more than one instruction cannot key a row.
    # REFUSAL 5 is checked FIRST: a row with no decode identity at all cannot
    # be qualified by any of the tests below, because they all take the id as
    # a key and it has none.
    refused = {isa: [] for isa in ISAS}
    for isa in ISAS:
        for key in list(per[isa]):
            if key[0] == 0 or per[isa][key][0] == "?":
                refused[isa].append((key, per[isa].pop(key), "NOIDENT"))
            elif key[0] in splits[isa]:
                refused[isa].append((key, per[isa].pop(key), "AMBIGUOUS"))
            elif (key[0], key[2]) in owed[isa]:
                refused[isa].append((key, per[isa].pop(key), "OWED"))

    w = []
    a = w.append
    a("/*")
    a(" * SOURCE SURVIVORS, per decode identity -- GENERATED, DO NOT HAND-EDIT.")
    a(" *")
    a(" * Re-emit with tools/gen_src_survivors.py; see that file for what a row")
    a(" * means and where the measurement comes from.  Every row here is a")
    a(" * register the tracer's per-ISA decode publishes as a source that QEMU's")
    a(" * ordered read list does not state -- the population R12.1 forbids")
    a(" * dropping when the source list stops being the operand walk's.")
    a(" *")
    a(" * DERIVED FROM A SNAPSHOT, and a snapshot is not a closure.  The corpus")
    a(" * is %s, %d sidecar(s):" % (os.path.abspath(src),
                                    sum(seen[i] for i in ISAS)))
    for isa in ISAS:
        a(" *   %-8s %d sidecar(s), %d row(s)%s"
          % (isa, seen[isa], len(per[isa]),
             ", %d REFUSED (reason on each row below)" % len(refused[isa])
             if refused[isa] else ""))
    a(" * Nothing here says anything about an instruction no sidecar executed.")
    a(" *")
    a(" * Author: Maccoy Merrell.")
    a(" */")
    a("#ifndef CHAMPSIM_TRACER_SRC_SURVIVORS_H")
    a("#define CHAMPSIM_TRACER_SRC_SURVIVORS_H")
    a("")
    a("#include <stdint.h>")
    a("")
    a("#include \"champsim_tracer_generic_ids.h\"")
    a("")
    a("typedef enum {")
    a("    SRC_SURV_FIXED = 0,   /* @reg, the same register on every instance */")
    a("    SRC_SURV_SELF  = 1,   /* @dst_pos, ONE slot of this instance's own  */")
    a("                          /* destination list -- never the whole list   */")
    a("} SrcSurvivorKind;")
    a("")
    a("typedef struct {")
    a("    uint32_t decode_id;")
    a("    uint8_t  kind;        /* SrcSurvivorKind */")
    a("    uint8_t  reg;         /* generic id; REG_NONE for SRC_SURV_SELF */")
    a("    uint8_t  dst_pos;     /* SRC_SURV_SELF: which destination slot;")
    a("                           * 0 and unread for SRC_SURV_FIXED */")
    a("    const char *rule;     /* annotation: QEMU's spelling of the rule */")
    a("} SrcSurvivorRow;")
    a("")
    a("typedef struct {")
    a("    const SrcSurvivorRow *rows;")
    a("    unsigned              n;")
    a("} SrcSurvivorTable;")
    a("")
    total = 0
    for isa in ISAS:
        rows = per[isa]
        ents = sum(v[1] for v in rows.values())
        a("/* %s -- %d row%s, %d census entr%s, from %d sidecar(s) */"
          % (isa, len(rows), "" if len(rows) == 1 else "s",
             ents, "y" if ents == 1 else "ies", seen[isa]))
        for (did, role, reg), (rule, cnt, mn), why in sorted(refused[isa]):
            a("/* REFUSED, not carried: 0x%08xu %s %s (%s x%d) --"
              % (did, rule, reg or role, ",".join(sorted(mn)), cnt))
            if why == "NOIDENT":
                a(" * the census printed NO decode identity for this row (id 0,")
                a(" * rule `?`): QEMU named no decode rule for the bytes.  That")
                a(" * is not an identity to key on -- a row keyed on it fires on")
                a(" * EVERY instruction whose rule is unknown.  Measured to be")
                a(" * wrong-path wander over undefined bytes, and not")
                a(" * reproducible: 1 run in 12 of the same cell produced it,")
                a(" * with a differing row count.  It stays in the loss")
                a(" * direction. */")
            elif why == "AMBIGUOUS":
                a(" * the census shows this decode id carrying more than one")
                a(" * instruction, so an id-keyed row would fire on the others")
                a(" * too.  It stays in the loss direction and blocks the flip")
                a(" * until the id is qualified. */")
            else:
                a(" * the census counts this row as ADJUDICATION-OWED: an open")
                a(" * maintainer question, measured against the external")
                a(" * references and reverted.  Carrying it would zero the")
                a(" * count that blocks the flip while the question is open,")
                a(" * which is answering it by arithmetic. */")
        if not rows:
            a("/* No array.  THIS IS A FACT ABOUT THE %d SIDECAR(S) NAMED"
              % seen[isa])
            a(" * ABOVE, NOT ABOUT THE ISA: each of them printed the survivor")
            if clean[isa]:
                a(" * block and each read `(none)`, so no instruction THEY")
                a(" * EXECUTED publishes a source QEMU's read list lacks.")
            else:
                a(" * block and none of them contributed a row, so no")
                a(" * instruction THEY EXECUTED publishes a source QEMU's read")
                a(" * list lacks.")
            a(" * An instruction no sidecar ran is not covered by this and")
            a(" * would land in the census's loss direction the first time it")
            a(" * does run.  A wider corpus is the only thing that widens this")
            a(" * claim; the null pointer below does not. */")
            a("")
            continue
        a("static const SrcSurvivorRow g_src_survivors_%s[] = {" % isa)
        for (did, role, reg), (rule, cnt, mnems) in sorted(rows.items()):
            kind = "SRC_SURV_FIXED" if role == "FIXED" else "SRC_SURV_SELF"
            r = reg if role == "FIXED" else "REG_NONE"
            pos = 0 if role == "FIXED" else int(role.split("@", 1)[1])
            a("    { 0x%08xu, %-14s, %-14s, %u, \"%s\" },   /* %s x%d */"
              % (did, kind, r, pos, rule, ",".join(sorted(mnems)), cnt))
        a("};")
        a("")
        total += len(rows)
    a("/* Indexed by TraceISA.  A null row pointer means the arrays above say")
    a(" * which of the two things it is for that ISA -- a measured `(none)` or")
    a(" * a corpus that never reached it. */")
    a("static const SrcSurvivorTable g_src_survivor_tables[] = {")
    a("    [TRACE_ISA_UNKNOWN] = { NULL, 0 },")
    for isa, enum in (("x86_64", "TRACE_ISA_X86"), ("aarch64", "TRACE_ISA_AARCH64"),
                      ("riscv64", "TRACE_ISA_RISCV"), ("mipsel", "TRACE_ISA_MIPS")):
        if per[isa]:
            a("    [%-17s] = { g_src_survivors_%s," % (enum, isa))
            a("                            G_N_ELEMENTS(g_src_survivors_%s) }," % isa)
        else:
            a("    [%-17s] = { NULL, 0 }," % enum)
    a("};")
    a("")
    a("/* %d rows over the four ISAs. */" % total)
    a("")
    a("#endif /* CHAMPSIM_TRACER_SRC_SURVIVORS_H */")
    open(out, "w").write("\n".join(w) + "\n")
    nref = sum(len(refused[i]) for i in ISAS)
    print("wrote %s: %d rows, %d refused" % (out, total, nref))
    for isa in ISAS:
        for (did, role, reg), (rule, cnt, mn), why in sorted(refused[isa]):
            print("  REFUSED %-8s 0x%08x %s %s (%s x%d): %s"
                  % (isa, did, rule, reg or role, ",".join(sorted(mn)), cnt,
                     "the id carries more than one instruction"
                     if why == "AMBIGUOUS" else
                     "no decode identity at all (id 0 / rule `?`)"
                     if why == "NOIDENT" else
                     "ADJUDICATION-OWED, an open maintainer question"))
        if not per[isa]:
            print("  EMPTY %-8s: %d sidecar(s) contributed no row -- a fact "
                  "about those sidecars, not about the ISA" % (isa, seen[isa]))
    return 0


# ---------------------------------------------------------------- selftest
_BLOCK = """
%s -- the same
rows as the block above.  This is the column tools/gen_src_survivors.py reads:
%s

%s -- (decode id, rule, mnemonic):
%s

SURVIVOR rules REACHED by this run, by decode rule:
%s

%s the union does not
contain that are NOT counted as MISSING:
%s

next section
""" % (HDR, "%s", WITNESS_HDR, "%s", "%s", OWED_HDR, "%s")


def _sidecar(path, rows, splits, witness=(), owed=()):
    open(path, "w").write(_BLOCK % ("\n".join(rows) or "  (none)",
                                    "\n".join(witness),
                                    "\n".join(splits),
                                    "\n".join(owed)))


def selftest():
    d = tempfile.mkdtemp(prefix="gen_src_survivors_selftest.")
    fails = []
    ran = []

    def chk(name, cond, why=""):
        # COUNT THE CHECK THAT ACTUALLY RAN.  The summary below used to
        # print a hard-coded literal, so adding or removing an arm left the
        # reported total untouched -- a summary asserting a number it never
        # took is the failure shape this whole instrument exists to catch.
        ran.append(name)
        print("  %-46s %s%s" % (name, "ok" if cond else "FAIL",
                                "" if cond else "  -- " + why))
        if not cond:
            fails.append(name)

    import subprocess
    me = [sys.executable, os.path.abspath(__file__)]

    good = ["       521  000006da RET                        REG_SEG5"
            "       FIXED   retq",
            # A SELF row, at destination slot 1.  The position is the whole
            # point of the role: a row that supplied the instance's WHOLE
            # destination list fabricated eight registers on the golden net.
            "         2  e91326ac disas_a64/FADD_v           REG_FCSR"
            "       SELF@1  fadd"]
    split = ["         2  00000776 x87                        REG_FPR0"
             "       FIXED fstpt",
             "         3  0000054b NOP                        REG_SSP"
             "        FIXED rdsspq"]
    splitline = ["    0x00000776 QID_SPLIT      x87                      15"]
    # 0x0000054b is NOT QID_SPLIT; only the collision witness catches it.
    witness = ["       521  000006da RET                        retq",
               "         2  00000776 x87                        fstpt",
               "         1  00000776 x87                        fldt",
               "       410  0000054b NOP                        endbr64",
               "         3  0000054b NOP                        rdsspq",
               "         2  e91326ac disas_a64/FADD_v           fadd"]

    owedrow = ["        16  ecf2c479 decode_insn32/fence        REG_SYS"
               "        fence     Q: does R7.4 reach FIOM?"]
    owedsurv = ["        16  ecf2c479 decode_insn32/fence        REG_SYS"
                "        FIXED fence"]
    # ... and a RULED row of the same shape, in the same ledger block.  It
    # must be CARRIED: a ruling that the wire is right is the statement that
    # a flip has to keep publishing the register.
    ruledrow = ["         9  30a7252a disas_a64/FABS_s           REG_FCSR"
                "       fabs      R16: ADJUDICATED-KEEP-R16, architectural"]
    ruledsurv = ["         9  30a7252a disas_a64/FABS_s           REG_FCSR"
                 "       FIXED fabs"]
    # A row the census could not name a rule for: id 0, rule `?`.  Its
    # witness line carries ONE mnemonic, so refusal 3 stays silent and only
    # refusal 5 can catch it -- that is what this fixture is shaped to prove.
    noident = ["         1  00000000 ?                          REG_COPROC0"
               "    FIXED   swc2"]
    witness = witness + ["         1  00000000 ?                          swc2"]
    x = os.path.join(d, "x86_64.log")
    _sidecar(x, good + split + owedsurv + ruledsurv + noident, splitline,
             witness, owedrow + ruledrow)
    a_ = os.path.join(d, "aarch64.log"); _sidecar(a_, [], [])
    r = os.path.join(d, "riscv64.log"); _sidecar(r, [], [])
    m = os.path.join(d, "mipsel.log"); _sidecar(m, [], [])

    snap = os.path.join(d, "snap")
    rc = subprocess.run(me + ["--snapshot", snap, "x86_64=" + x,
                              "aarch64=" + a_, "riscv64=" + r, "mipsel=" + m],
                        capture_output=True, text=True)
    chk("ARM A: snapshot is created", rc.returncode == 0, rc.stderr.strip())

    h = os.path.join(d, "out.h")
    rc = subprocess.run(me + ["--out", h, "--from-snapshot", snap],
                        capture_output=True, text=True)
    txt = open(h).read() if os.path.exists(h) else ""
    chk("ARM B: emit from a verified snapshot", rc.returncode == 0,
        rc.stderr.strip())
    chk("ARM C: the QID_SPLIT row is NOT carried",
        "0x00000776u, SRC_SURV" not in txt)
    chk("ARM C1: an id the WITNESS alone shows colliding is NOT carried",
        "0x0000054bu, SRC_SURV" not in txt)
    chk("ARM C2: and both are REPORTED, not silently dropped",
        "REFUSED, not carried: 0x00000776" in txt
        and "REFUSED, not carried: 0x0000054b" in txt
        and "carries \nmore than one" not in txt
        and "more than one instruction" in rc.stdout)
    chk("ARM D: the un-split row IS carried", "0x000006dau, SRC_SURV" in txt)
    chk("ARM D0: a SELF row carries its DESTINATION POSITION, not the list",
        "0xe91326acu, SRC_SURV_SELF , REG_NONE      , 1," in txt,
        "expected dst_pos 1 on the SELF row")
    chk("ARM C3: a row with NO decode identity is NOT carried",
        "0x00000000u, SRC_SURV_FIXED, REG_COPROC0" not in txt
        and "REFUSED, not carried: 0x00000000u" in txt
        and "no decode identity at all" in rc.stdout,
        "an id-0 / rule-`?` row reached the table")
    chk("ARM D1: an ADJUDICATION-OWED row is NOT carried",
        "0xecf2c479u, SRC_SURV" not in txt
        and "ADJUDICATION-OWED, an open maintainer question" in rc.stdout)
    chk("ARM D2: a RULED (R16) row in the same ledger IS carried",
        "0x30a7252au, SRC_SURV" in txt,
        "a ruling that the wire is right must not make the flip drop it")
    chk("ARM E: an empty table is scoped to the sidecars, not the ISA",
        "FACT ABOUT THE" in txt and "NOT ABOUT THE ISA" in txt)
    chk("ARM F: and it makes no claim about the ISA in general",
        "every published source on this ISA is justified" not in txt)

    rc = subprocess.run(me + ["--out", h + ".2", "x86_64=" + x,
                              "aarch64=" + a_, "riscv64=" + r, "mipsel=" + m],
                        capture_output=True, text=True)
    chk("ARM G: emitting from LIVE paths is refused",
        rc.returncode != 0 and not os.path.exists(h + ".2"), rc.stdout.strip())

    open(os.path.join(snap, "x86_64.00.x86_64.log"), "a").write("tamper\n")
    rc = subprocess.run(me + ["--out", h + ".3", "--from-snapshot", snap],
                        capture_output=True, text=True)
    chk("ARM H: a snapshot that moved under us is refused",
        rc.returncode != 0 and "changed under us" in (rc.stdout + rc.stderr))

    shutil.rmtree(d, ignore_errors=True)
    print("\ngen_src_survivors.py selftest: %d check(s), %d failure(s)"
          % (len(ran), len(fails)))
    return 1 if fails else 0


def main(argv):
    if argv[:1] == ["--selftest"]:
        return selftest()
    out = snapshot = from_snapshot = None
    inputs, i = {}, 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 2; continue
        if argv[i] == "--snapshot":
            snapshot = argv[i + 1]; i += 2; continue
        if argv[i] == "--from-snapshot":
            from_snapshot = argv[i + 1]; i += 2; continue
        isa, _, path = argv[i].partition("=")
        if isa not in ISAS:
            sys.exit("unknown isa %r" % isa)
        inputs.setdefault(isa, []).append(path)
        i += 1

    if snapshot:
        if out or from_snapshot:
            sys.exit("--snapshot takes inputs and nothing else")
        if sorted(inputs) != sorted(ISAS):
            sys.exit("--snapshot needs at least one sidecar for each of %s"
                     % ", ".join(ISAS))
        return make_snapshot(snapshot, inputs)

    if not out:
        sys.exit(__doc__)
    if not from_snapshot:
        sys.exit("REFUSING: emitting requires --from-snapshot DIR.\n"
                 "A sidecar path is written by the same gate that produces "
                 "it, and reading one live gave this table a corpus that no "
                 "single run ever had.  Run --snapshot DIR <isa>=<path>... "
                 "first, then emit from DIR.")
    if inputs:
        sys.exit("REFUSING: --from-snapshot and bare <isa>=<path> inputs "
                 "together; the snapshot is the corpus or nothing is")
    return emit(out, read_snapshot(from_snapshot), from_snapshot)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
