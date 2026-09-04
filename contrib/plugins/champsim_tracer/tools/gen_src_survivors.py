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

6. IT WILL NOT CARRY A FIXED ROW WHOSE ID ALREADY CARRIES ANOTHER FIXED ROW
   FROM THE SAME NUMBERED REGISTER BANK.  SRC_SURV_FIXED means "the same
   register on every instruction this rule decodes".  Two of them naming
   two different vectors -- or two different predicates -- under ONE decode
   id is the table saying a rule reads both on every instance, which is
   what an ENCODED OPERAND looks like once it has been frozen at whatever
   the deriving corpus happened to run.

   MEASURED, on live instructions, not argued.  riscv64 `vadd.vv v8,v9,v10`
   published REG_VEC1 and REG_VEC2 beside its own v9 and v10; x86
   `vfmadd132sd %xmm7,%xmm8,%xmm6` published REG_VEC1 and REG_VEC2 beside
   its own three; aarch64 `st4 {v20.16b-v23.16b},[x11]` published REG_VEC5
   through REG_VEC8 and REG_GPR9, the registers of the ONE st4 the deriving
   corpus ran.  Thirteen decode ids, thirty-three rows.

   The runtime refutation route cannot reach these: it needs the emulator
   to STATE the register on at least one instance, and for RVV and scalar
   FMA every instance was silent, so a join over them read a clean 0 while
   the rows fabricated in the same run.  This test is STATIC, over the
   table's own shape, and it is the same test the plugin prints as a
   MUST-BE-0 row (champsim_tracer_qdep.cc) so that the header and the
   counter cannot disagree.

   SINGLETON REGISTERS ARE NEVER A BANK.  A rule reading one fixed vector
   and one fixed control register says nothing suspicious; only a COLLISION
   inside one numbered bank is read as a refutation.  A row refused here is
   printed and written into the header with its reason, like every other
   refusal -- the register the encoding names is still published, by the
   emulator's own statement where the decode site makes one and by the
   operand walk until it goes, and the removal is an ADJUDICATED
   CORRECTION under R15/R16 rather than a loss under R12.1: a register the
   encoding does not name was never information.

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

#: REGISTERS `disas/capstone.c` ALREADY DROPS, by (isa, decode-rule
#: substring, register-name prefix).  See REFUSAL 7.  Each row names the
#: boundary function that makes the drop, so a boundary repair that is
#: retired on a Capstone bump leaves a row here with nothing to match and the
#: dead-rule detector can see it.
BOUNDARY_DROPS = (
    # cap_x86_is_x87_escape(): Capstone 6.0.0-Alpha7 names a SEGMENT REGISTER
    # in the implicit read list of every x87 escape -- `fcoms (%rax)` comes
    # back reading SS and `ficoms (%rax)` reading DS, for a shape that
    # `movl (%rax),%eax` reports no segment for at all.  The boundary drops
    # all six because "the only segment an access genuinely takes an input
    # from is an override, and an override arrives as the memory operand's
    # segment_id".
    #
    # The two rows this refuses are `fnstcw` and the memory form of `fnstsw`,
    # both claiming REG_SEG0 (CS).  QEMU refutes them at its own decode site:
    # translate.c sets `update_fip = update_fdp = false` for both, so the
    # `segs[R_CS].selector` load that every FIP-updating x87 instruction
    # emits is not emitted for these -- and the SDM says the same thing, by
    # listing FNSTCW and FNSTSW among the control instructions that do not
    # update the FPU instruction pointer.
    ("x86_64", "x87", "REG_SEG"),
)

#: REGISTERS QEMU'S OWN DECODE SITE SAYS THE INSTRUCTION DOES NOT READ, by
#: (isa, decode-rule substring, register-name prefix).  See REFUSAL 8.  Each
#: row cites the site and quotes what it says, because the whole force of the
#: category is that the emulator's translator states the refutation itself --
#: not that this file has an opinion about the encoding.
#:
#: DIFFERENT FROM BOUNDARY_DROPS ABOVE, and the difference is which decoder
#: made the ruling.  A BOUNDARY row says `disas/capstone.c` has already
#: stopped supplying the register, so a survivor row would re-add it one layer
#: up.  A REFUTED row says the register is still arriving from the operand
#: walk and QEMU's translator contradicts it -- so the survivor table would
#: not merely re-add a removed dependency, it would make this table the
#: PERMANENT supplier of one the emulator denies.  That is the worse of the
#: two, and it is why the category is separate rather than folded in: a reader
#: has to be able to tell "already removed" from "still published and wrong".
DECODE_SITE_REFUTED = (
    # `ffree %st(i)` / `ffreep %st(i)`, ModRM.reg = 4 in the DD and DF
    # escapes.  Capstone-6.0.0-Alpha7 reports the explicit ST(i) operand of
    # `ffree` with READ access; QEMU's x87 translation refutes it at the
    # decode site, in its own words, at gen_note_sti_read() in
    # target/i386/tcg/translate.c:
    #
    #   "`ffree %st(i)` and `ffreep %st(i)` are NOT annotated: they mark the
    #    tag word empty and never look at the value, so ST(i) is not a source
    #    of theirs and stating it would fabricate."
    #
    # helper_ffree_STN() is the whole execution and it is one statement,
    # `env->fptags[(env->fpstt + st_index) & 7] = 1` -- the tag, and nothing
    # that reads the register.  The SDM agrees: FFREE "sets the tag ...
    # associated with register ST(i) to empty", and lists no source operand.
    #
    # CAPSTONE CONTRADICTS ITSELF HERE, which is the defect witness rather
    # than an argument: `ffreep` publishes no FP register at all on the same
    # sled (PUB REG_FCSR,REG_SEG0), while `ffree` publishes ST(i).  Two
    # encodings of one operation, decoded two different ways.
    #
    # WHAT THE ROW WAS DOING.  The refused row is FIXED REG_FPR1 on decode id
    # 0x44ae204e, whose rule `x87@1101110111000...` covers all EIGHT ffree
    # encodings -- so the table supplied REG_FPR1 on `ffree %st(0)`,
    # `%st(2)`, `%st(3)` and the rest, a register those encodings do not
    # name.  Measured on the exec123 sled: `40ddc0` (ffree %st(0)) publishes
    # SURV REG_FPR1 beside the walk's REG_FPR0, and `40ddc2` publishes
    # REG_FPR1 beside REG_FPR2.  It is a FROZEN ENCODED OPERAND that
    # REFUSAL 6 cannot see, because REFUSAL 6 needs two FIXED rows of one
    # bank to collide and this id carries only one.
    ("x86_64", "x87@1101110111000", "REG_FPR",
     "gen_note_sti_read(), target/i386/tcg/translate.c -- ffree/ffreep "
     "mark the tag word and never look at the value"),
)
HDR = "SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY"
# The SECOND survivor block, same columns and same role measurement, and a
# DIFFERENT CLAIM: a published source on an instruction whose read list QEMU
# withheld or reported short.  The census may not call those unjustified -- it
# may only say nobody could ask -- so they are printed apart.  They are read
# here because the FLIP has the same obligation either way: after it, the read
# list supplies nothing on those instructions, so a register the wire publishes
# reaches it only from this table.  Until this header was read, 30 of the 33
# program counters the operand walk's read arm was the only supplier for were
# invisible to this generator, and it emitted a table that dropped them.
NOSTATE_HDR = "SOURCE SURVIVORS ON THE POPULATION THE CENSUS CANNOT SCORE"
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

# The NUMBERED REGISTER BANKS, by the generic-id spelling the census prints.
# Kept as name prefixes rather than as numbers because the census's column is
# the name and the enumerators renumber; the plugin's own must-be-0 counter
# asks the same question of the same four banks over the compiled ids.
BANKS = ("REG_GPR", "REG_FPR", "REG_VEC", "REG_PRED")


def bank_of(reg):
    """Which numbered bank @reg belongs to, or None for a singleton.

    A bank member is a stem followed by digits and nothing else: `REG_VEC12`
    is v12 and `REG_VCTRL` is not a vector at all.  Matching on the stem
    alone would fold every control register whose name starts with one of
    these into a bank and refuse rows that are not frozen operands.
    """
    for b in BANKS:
        if reg.startswith(b) and reg[len(b):].isdigit():
            return b
    return None


# Members of a numbered file that the VOCABULARY gives a name outside that
# file's stem.  These are not aliases of convenience: each is a register the
# ISA encodes in the same numbered field as its bank, which the tracer's own
# per-ISA table maps to a distinct generic word --
#
#   aarch64  sp = x31 in the SP-form, x29 = REG_FP_REG, x30 = REG_LR
#   riscv64  sp = x2,  fp = x8,  ra = x1
#   mipsel   sp = $29, s8 = $30, ra = $31
#   x86_64   rsp and rbp are the 4th and 5th slots of the same file
#
# read off champsim_tracer_qemu_regs_<isa>.h, where every one of them sits in
# the same GDB core feature as the numbered registers beside it.  A rule that
# freezes ONE of these has frozen a member of the general file exactly as a
# rule that freezes REG_GPR7 has, and bank_of() cannot see it because the
# name carries no digits.
BANK_ALIASES = {"REG_SP": "REG_GPR", "REG_LR": "REG_GPR",
                "REG_FP_REG": "REG_GPR"}


def bank_family(reg):
    """The numbered file @reg belongs to, counting the aliases above.

    Used by the RUNTIME arm only.  bank_of() is left alone because it keys
    the STATIC arm, whose subject is two rows of one bank colliding under one
    id -- a different question, with its own landed row set.
    """
    return bank_of(reg) or BANK_ALIASES.get(reg)


def read_corpus(path):
    """{decode_id: [set-of-published-source-registers, per instance]}.

    The mechanism corpus srcenc_sled.py writes: one row per encoding, with
    the decode identity in column `decode_id` and the wire's published source
    list in column `PUB`.  Read by NAME from the header row, never by index,
    because a column added to the middle of that corpus would otherwise
    silently re-point this at another column's contents.
    """
    out, cols = {}, None
    with open(path, "r", errors="replace") as f:
        for line in f:
            v = line.rstrip("\n").split("\t")
            if cols is None:
                if not v or not v[0].startswith("#"):
                    sys.exit("FAIL %s: no header row; the columns cannot be "
                             "named" % path)
                cols = [c.lstrip("#") for c in v]
                for need in ("decode_id", "PUB"):
                    if need not in cols:
                        sys.exit("FAIL %s: corpus has no %r column -- this is "
                                 "not the mechanism corpus (--mech)"
                                 % (path, need))
                di, pi = cols.index("decode_id"), cols.index("PUB")
                continue
            if len(v) <= max(di, pi):
                continue
            did = v[di].strip()
            if not did or did == "-":
                continue
            pub = set()
            for r in v[pi].split(","):
                r = r.strip()
                if r.startswith("REG_"):
                    pub.add(r)
            out.setdefault(int(did, 16), []).append(pub)
    if not out:
        sys.exit("FAIL %s: corpus carries no decode identity -- an empty "
                 "corpus cannot be told from a complete one, so it is "
                 "refused rather than read as 'nothing varies'" % path)
    return out


def merged_corpus(paths):
    """One {decode_id: [pub-sets]} over every corpus file of an ISA.

    Several corpora merge by CONCATENATING the instance lists: each file is a
    set of encodings that were run, and the arm's question -- does this file
    vary across the rule's instances -- is asked of all of them at once.  A
    register constant across two corpora and varying within neither is still
    not varying.
    """
    out = {}
    for p in paths:
        for did, inst in read_corpus(p).items():
            out.setdefault(did, []).extend(inst)
    return out


def frozen_runtime(did, reg, corpus):
    """Is @reg a FROZEN OPERAND of @did, measured against the corpus?

    FINDING 71-B.  The STATIC arm (REFUSAL 6) fires when two FIXED rows of
    one bank collide under one decode id, so it can only see a frozen operand
    that happened to be frozen TWICE.  `prfum` was frozen once -- one row,
    REG_SP, on a rule whose base register is encoded -- and passed.

    The question this asks instead is about the rule's INSTANCES: does the
    same numbered file supply a VARYING register beside the constant one?  If
    it does, the file is what the encoding selects from and a constant member
    of it is the deriving corpus's own operand, not a property of the rule.

    Returns (True, why) or (False, why-not); the reason is carried either way
    so the header can say what was measured rather than that something was
    not refused.
    """
    fam = bank_family(reg)
    if not fam:
        return False, "not a member of a numbered file"
    inst = corpus.get(did)
    if not inst:
        return False, "no instance of this id in the corpus"
    n = len(inst)
    if not all(reg in pub for pub in inst):
        return False, ("published on %d of %d instances, so it is not a "
                       "constant of the rule" % (
                           sum(1 for pub in inst if reg in pub), n))
    others = set()
    for pub in inst:
        for r in pub:
            if r != reg and bank_family(r) == fam:
                others.add(r)
    if len(others) < 2:
        return False, ("the %s file supplies %d other register(s) beside it "
                       "(%s), which is not variation"
                       % (fam, len(others), ",".join(sorted(others)) or "none"))
    return True, ("constant on %d of %d instances while the %s file varies "
                  "over %d other register(s): %s"
                  % (n, n, fam, len(others),
                     ",".join(sorted(others)[:6])
                     + ("..." if len(others) > 6 else "")))


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

    def read_block(hdr, rows, required):
        """Fold one survivor block's rows into @rows.

        Returns (saw_any, saw_none).  A block whose header is present and
        whose body is neither rows nor the literal `(none)` is a REFUSAL,
        not an empty result: a reader that cannot find its subject must
        fail rather than emit a table derived from nothing.
        """
        if hdr not in text:
            if required:
                sys.exit("FAIL %s: no survivor block -- the census did not "
                         "run" % path)
            return False, False
        seen_any = False
        for line in text.split(hdr, 1)[1].splitlines():
            if line.strip() == "(none)":
                return False, True
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
            sys.exit("FAIL %s: block %r present but unparsable" % (path, hdr))
        return True, False

    rows = {}
    any_a, none_a = read_block(HDR, rows, True)
    # NOT required: a sidecar produced before the second block existed is a
    # readable sidecar, and refusing it would make this generator unable to
    # read its own corpus history.  Its ABSENCE is reported by the caller.
    any_b, none_b = read_block(NOSTATE_HDR, rows, False)
    return rows, split_ids, owed, (none_a and not any_b)


def make_snapshot(dest, inputs, corpora=None):
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
    # The corpora go in under the SAME manifest and the same hash, because
    # REFUSAL 6b reads them and an input a gate can move under us is exactly
    # what the snapshot rule exists to forbid.  Named `<isa>.corpus.NN.` so
    # the ISA is still the first component read_snapshot() keys on.
    nc = 0
    for isa in ISAS:
        for i, path in enumerate((corpora or {}).get(isa, [])):
            if not os.path.isfile(path):
                sys.exit("FAIL: no such corpus: %s" % path)
            name = "%s.corpus.%02d.%s" % (isa, i, os.path.basename(path))
            shutil.copyfile(path, os.path.join(dest, name))
            lines.append("%s  %s  %s"
                         % (sha256(path), name, os.path.abspath(path)))
            nc += 1
    if not n:
        sys.exit("FAIL: --snapshot with no inputs; a snapshot of nothing is "
                 "not a corpus")
    with open(os.path.join(dest, MANIFEST), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("snapshot %s: %d sidecar(s), %d corpus file(s), manifest %s"
          % (dest, n, nc, MANIFEST))
    return 0


def read_snapshot(src):
    """Verify @src against its manifest; return ({isa: [sidecars]},
    {isa: [corpora]})."""
    man = os.path.join(src, MANIFEST)
    if not os.path.isfile(man):
        sys.exit("FAIL: %s has no %s -- emitting is only allowed from a "
                 "snapshot this tool made (a live path races the gate that "
                 "writes it)" % (src, MANIFEST))
    out, cor, n, nc = {}, {}, 0, 0
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
        if name.split(".")[1:2] == ["corpus"]:
            cor.setdefault(isa, []).append(path)
            nc += 1
        else:
            out.setdefault(isa, []).append(path)
            n += 1
    if sorted(out) != sorted(ISAS):
        sys.exit("FAIL: snapshot %s covers %s; all four ISAs are required "
                 "(a table missing an ISA reads as 'this ISA has no "
                 "survivors', which is the falsehood this refuses to emit)"
                 % (src, sorted(out)))
    print("snapshot %s verified: %d sidecar(s), %d corpus file(s), all four "
          "ISAs%s" % (src, n, nc,
                      "" if nc else
                      " -- NO CORPUS, so REFUSAL 6b's runtime arm cannot run"))
    return out, cor


def emit(out, inputs, src, corpora=None):
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
    # REFUSAL 6, applied after the three above so that a row already refused
    # for a worse reason keeps that reason: an id with no identity, or one
    # carrying several instructions, is not merely a frozen operand.
    for isa in ISAS:
        banked = {}
        for (did, role, reg) in per[isa]:
            if role != "FIXED":
                continue
            b = bank_of(reg)
            if b:
                banked.setdefault((did, b), set()).add(reg)
        for key in list(per[isa]):
            did, role, reg = key
            if role != "FIXED":
                continue
            b = bank_of(reg)
            if b and len(banked.get((did, b), ())) > 1:
                refused[isa].append((key, per[isa].pop(key), "FROZEN"))

    # REFUSAL 6b -- THE RUNTIME ARM.  FINDING 71-B.
    #
    # REFUSAL 6 above is a question about the TABLE'S SHAPE: two FIXED rows
    # of one numbered bank under one decode id.  That only catches a frozen
    # operand the deriving corpus happened to freeze TWICE.  aarch64 `prfum`
    # was frozen once -- a single FIXED REG_SP row on
    # `disas_a64/NOP@11111000100.........00..........`, a rule whose base
    # register is ENCODED -- and walked straight through, so all 1,536 prfum
    # encodings published a stack pointer none of them names.
    #
    # This arm asks the corpus instead of the table: for a FIXED row naming a
    # member of a numbered file, do the rule's own instances supply a VARYING
    # register of that same file beside the constant?  Where they do, the
    # file is what the encoding selects from and the constant is the deriving
    # corpus's operand, frozen into a compiled table.  prfum answers yes on
    # 1,536 of 1,536.
    #
    # IT NEEDS THE ALIASES (bank_family, not bank_of): the register prfum
    # froze is spelled REG_SP, which carries no digits and so is in no bank
    # by the static arm's reading, while the registers it varies over are
    # REG_GPR0..REG_GPR9 and REG_LR.  A file member the vocabulary names
    # outside the stem is still a file member.
    #
    # NOT MEASURABLE IS NOT ZERO.  Without a corpus in the snapshot this arm
    # does not run, and the header says so by name; it never reports that
    # nothing was frozen.
    rt_refused = {isa: [] for isa in ISAS}
    rt_ran = {isa: (corpora or {}).get(isa) is not None for isa in ISAS}
    for isa in ISAS:
        if not rt_ran[isa]:
            continue
        corpus = corpora[isa]
        for key in list(per[isa]):
            did, role, reg = key
            if role != "FIXED":
                continue
            hit, why = frozen_runtime(did, reg, corpus)
            if hit:
                rt_refused[isa].append((key, per[isa][key], why))
                refused[isa].append((key, per[isa].pop(key), "FROZEN-RT"))

    # REFUSAL 7, applied last so a row already refused for a structural
    # reason keeps that reason: THE DECODE BOUNDARY ALREADY DROPS THIS
    # REGISTER FOR THIS INSTRUCTION CLASS.
    #
    # A survivor row is a register the WIRE published and QEMU did not state.
    # When `disas/capstone.c` explicitly removes that register from that
    # instruction class as a DISASSEMBLER DEFECT, the operand walk stops
    # supplying it and this table becomes its only remaining supplier -- so a
    # row here re-adds, one layer up, exactly the dependency the boundary
    # just took out.  That is not the loss direction R12.1 protects: a
    # register the boundary has ruled the instruction cannot read was never
    # information, so the removal is an ADJUDICATED CORRECTION under R15/R16.
    for isa in ISAS:
        for key in list(per[isa]):
            did, role, reg = key
            rule = per[isa][key][0]
            for b_isa, b_rule, b_pfx in BOUNDARY_DROPS:
                if isa == b_isa and b_rule in rule and (reg or "").startswith(
                        b_pfx):
                    refused[isa].append((key, per[isa].pop(key), "BOUNDARY"))
                    break

    # REFUSAL 8, applied after REFUSAL 7 for the same reason REFUSAL 7 is
    # applied after 6: a row already refused keeps the reason it was first
    # refused for.  QEMU'S OWN DECODE SITE SAYS THIS INSTRUCTION DOES NOT
    # READ THIS REGISTER.
    #
    # REFUSAL 7's subject is a register the DISASSEMBLER has stopped
    # supplying.  This one's subject is a register the disassembler is STILL
    # supplying and the EMULATOR denies -- so carrying it would make this
    # table the permanent supplier of a dependency QEMU's translator states,
    # in its own comment, that the instruction does not have.  The register
    # is not lost under R12.1: a source the encoding does not read was never
    # information, and the removal is an ADJUDICATED CORRECTION under R15/R16
    # exactly as REFUSAL 6's and REFUSAL 7's are.
    for isa in ISAS:
        for key in list(per[isa]):
            did, role, reg = key
            rule = per[isa][key][0]
            for r_isa, r_rule, r_pfx, _site in DECODE_SITE_REFUTED:
                if isa == r_isa and r_rule in rule and (reg or "").startswith(
                        r_pfx):
                    refused[isa].append((key, per[isa].pop(key), "REFUTED"))
                    break

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
            elif why == "BOUNDARY":
                a(" * disas/capstone.c already DROPS this register for this")
                a(" * instruction class as a disassembler defect, so the")
                a(" * operand walk no longer supplies it and this table would")
                a(" * be its only remaining supplier -- re-adding, one layer")
                a(" * up, the dependency the boundary removed.  QEMU refutes")
                a(" * it at its own decode site as well.  An ADJUDICATED")
                a(" * CORRECTION under R15/R16: a register the instruction")
                a(" * cannot read was never information. */")
            elif why == "REFUTED":
                a(" * QEMU'S OWN DECODE SITE REFUTES THIS READ.  The operand")
                a(" * walk still supplies the register, so this is not the")
                a(" * boundary case above -- carrying the row would make this")
                a(" * table the PERMANENT supplier of a dependency the")
                a(" * emulator's translator states the instruction does not")
                a(" * have.  The site and its own words:")
                for r_isa, r_rule, r_pfx, site in DECODE_SITE_REFUTED:
                    if r_isa == isa and r_rule in rule and \
                            (reg or "").startswith(r_pfx):
                        a(" *   %s" % site)
                a(" * An ADJUDICATED CORRECTION under R15/R16, not a loss")
                a(" * under R12.1: a source the encoding does not read was")
                a(" * never information. */")
            elif why == "FROZEN-RT":
                a(" * a FROZEN ENCODED OPERAND, measured against the deriving")
                a(" * corpus rather than against this table's shape")
                a(" * (FINDING 71-B).  The rule's own instances publish this")
                a(" * register on EVERY one of them while the same numbered")
                a(" * file supplies a VARYING register beside it, so the file")
                a(" * is what the encoding selects from and the constant is")
                a(" * the corpus's operand.  What was measured:")
                for k2, _v2, why2 in rt_refused[isa]:
                    if k2 == (did, role, reg):
                        a(" *   %s" % why2)
                a(" * An ADJUDICATED CORRECTION under R15/R16, not a loss")
                a(" * under R12.1: a register the encoding does not name was")
                a(" * never information. */")
            elif why == "FROZEN":
                a(" * this decode id carries another FIXED row from the SAME")
                a(" * NUMBERED BANK, so the pair claims one rule reads two")
                a(" * different registers of that bank on every instance --")
                a(" * an ENCODED OPERAND frozen at whatever the deriving")
                a(" * corpus ran.  Measured fabricating on live instructions")
                a(" * (riscv64 RVV, x86 scalar FMA, aarch64 st4).  The")
                a(" * register the encoding names is published by the")
                a(" * emulator's own statement; this row published the")
                a(" * deriving corpus's instead.  An adjudicated correction")
                a(" * under R15/R16, not a loss under R12.1. */")
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
                     "a FROZEN ENCODED OPERAND: the id carries another FIXED "
                     "row from the same numbered bank"
                     if why == "FROZEN" else
                     "a FROZEN ENCODED OPERAND measured on the corpus: the "
                     "rule's instances vary this file (FINDING 71-B)"
                     if why == "FROZEN-RT" else
                     "the DECODE BOUNDARY already drops this register for "
                     "this instruction class"
                     if why == "BOUNDARY" else
                     "REFUTED BY QEMU'S OWN DECODE SITE: the translator "
                     "states the instruction does not read it"
                     if why == "REFUTED" else
                     "ADJUDICATION-OWED, an open maintainer question"))
        if not per[isa]:
            print("  EMPTY %-8s: %d sidecar(s) contributed no row -- a fact "
                  "about those sidecars, not about the ISA" % (isa, seen[isa]))
    for isa in ISAS:
        if rt_ran[isa]:
            print("  RUNTIME-ARM %-8s: ran over %d decode id(s), %d row(s) "
                  "refused as frozen operands"
                  % (isa, len(corpora[isa]), len(rt_refused[isa])))
        else:
            print("  RUNTIME-ARM %-8s: DID NOT RUN -- no corpus in the "
                  "snapshot.  This is NOT a measurement that nothing is "
                  "frozen; REFUSAL 6b had no subject to ask about." % isa)
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


_NOSTATE_BLOCK = """
%s --
same columns, DIFFERENT CLAIM:
%s

""" % (NOSTATE_HDR, "%s")


def _sidecar(path, rows, splits, witness=(), owed=(), nostate=None):
    body = _BLOCK % ("\n".join(rows) or "  (none)",
                     "\n".join(witness),
                     "\n".join(splits),
                     "\n".join(owed))
    if nostate is not None:
        body += _NOSTATE_BLOCK % ("\n".join(nostate) or "  (none)")
    open(path, "w").write(body)


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
    # REFUSAL 6's fixtures, and its NEGATIVE controls.
    #
    #   0x000002e0  two FIXED rows from ONE bank -- a frozen encoded operand,
    #               and the shape that must be refused.
    #   0x0000abcd  one FIXED bank row beside a SINGLETON -- carried; a rule
    #               reading one fixed vector and one fixed control register
    #               says nothing suspicious.
    #   0x0000dcba  two FIXED rows from DIFFERENT banks -- carried, for the
    #               same reason.
    #   0x0000face  a bank row beside a SELF row of the same bank -- carried;
    #               a SELF row names an instance's own destination and is not
    #               a frozen constant, so it can never make a pair.
    #   0x0000feed  REG_VCTRL beside REG_VEC9: `REG_VCTRL` starts with no
    #               bank stem followed by digits and is not a bank member, so
    #               a stem-only match would refuse this row wrongly.
    frozen = ["         3  000002e0 VFMADD132Sx                REG_VEC1"
              "       FIXED   vfmadd132sd",
              "         3  000002e0 VFMADD132Sx                REG_VEC2"
              "       FIXED   vfmadd132sd"]
    notfrozen = ["         4  0000abcd SOMERULE                   REG_VEC3"
                 "       FIXED   somemn",
                 "         4  0000abcd SOMERULE                   REG_FPCW"
                 "       FIXED   somemn",
                 "         5  0000dcba OTHERRULE                  REG_VEC4"
                 "       FIXED   othermn",
                 "         5  0000dcba OTHERRULE                  REG_GPR7"
                 "       FIXED   othermn",
                 "         6  0000face SELFRULE                   REG_VEC5"
                 "       FIXED   selfmn",
                 "         6  0000face SELFRULE                   REG_VEC6"
                 "       SELF@0  selfmn",
                 "         7  0000feed CTRLRULE                   REG_VEC9"
                 "       FIXED   ctrlmn",
                 "         7  0000feed CTRLRULE                   REG_VCTRL"
                 "     FIXED   ctrlmn"]
    witness = witness + [
        "         3  000002e0 VFMADD132Sx                vfmadd132sd",
        "         4  0000abcd SOMERULE                   somemn",
        "         5  0000dcba OTHERRULE                  othermn",
        "         6  0000face SELFRULE                   selfmn",
        "         7  0000feed CTRLRULE                   ctrlmn"]
    x = os.path.join(d, "x86_64.log")
    _sidecar(x, good + split + owedsurv + ruledsurv + noident + frozen
             + notfrozen, splitline, witness, owedrow + ruledrow)
    # aarch64 carries the SECOND claim and NOTHING in the first: its
    # survivor block reads `(none)` and its NOT-SCORED block carries two
    # rows, one on an id the witness shows colliding.  This is the exact
    # shape the corpus produced -- x86 `cpuid` and `rdtsc` are only ever in
    # the second block -- and without this arm the whole NOT-SCORED reader
    # would be untested.
    nostate = ["        15  00000507 CPUID                      REG_GPR0"
               "       SELF@0  cpuid",
               "         2  48fe989e disas_a64/SYS@1101         REG_SYSID"
               "      FIXED   mrs"]
    nswitness = ["        15  00000507 CPUID                      cpuid",
                 "         2  48fe989e disas_a64/SYS@1101         mrs",
                 "         1  48fe989e disas_a64/SYS@1101         msr"]
    a_ = os.path.join(d, "aarch64.log")
    _sidecar(a_, [], [], nswitness, (), nostate)
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
    chk("ARM K1: a FROZEN ENCODED OPERAND pair is NOT carried",
        "0x000002e0u, SRC_SURV" not in txt
        and "REFUSED, not carried: 0x000002e0" in txt
        and "FROZEN ENCODED OPERAND" in rc.stdout,
        "two FIXED rows from one bank under one id reached the table")
    chk("ARM K1a: BOTH rows of the pair are refused, not just one",
        txt.count("REFUSED, not carried: 0x000002e0") == 2)
    chk("ARM K2: a bank row beside a SINGLETON is CARRIED",
        "0x0000abcdu, SRC_SURV_FIXED, REG_VEC3" in txt
        and "0x0000abcdu, SRC_SURV_FIXED, REG_FPCW" in txt,
        "a singleton register is never a bank")
    chk("ARM K3: two FIXED rows from DIFFERENT banks are CARRIED",
        "0x0000dcbau, SRC_SURV_FIXED, REG_VEC4" in txt
        and "0x0000dcbau, SRC_SURV_FIXED, REG_GPR7" in txt)
    chk("ARM K4: a SELF row cannot make a bank pair",
        "0x0000faceu, SRC_SURV_FIXED, REG_VEC5" in txt
        and "0x0000faceu, SRC_SURV_SELF" in txt,
        "SELF names the instance's own destination, never a constant")
    chk("ARM K5: a stem that is not followed by digits is not a bank",
        "0x0000feedu, SRC_SURV_FIXED, REG_VEC9" in txt
        and "0x0000feedu, SRC_SURV_FIXED, REG_VCTRL" in txt,
        "REG_VCTRL is not a member of the REG_VEC bank")
    chk("ARM E: an empty table is scoped to the sidecars, not the ISA",
        "FACT ABOUT THE" in txt and "NOT ABOUT THE ISA" in txt)
    chk("ARM F: and it makes no claim about the ISA in general",
        "every published source on this ISA is justified" not in txt)

    rc = subprocess.run(me + ["--out", h + ".2", "x86_64=" + x,
                              "aarch64=" + a_, "riscv64=" + r, "mipsel=" + m],
                        capture_output=True, text=True)
    chk("ARM N: a NOT-SCORED-block row IS carried (the second claim)",
        "0x00000507u, SRC_SURV_SELF , REG_NONE      , 0," in txt,
        "the survivor block read (none); only the NOT-SCORED block has it")
    chk("ARM N1: and the collision witness still refuses one there",
        "0x48fe989eu, SRC_SURV" not in txt
        and "REFUSED, not carried: 0x48fe989e" in txt)
    chk("ARM N2: an ISA with rows ONLY in the second block is not EMPTY",
        "EMPTY aarch64" not in rc.stdout)
    chk("ARM G: emitting from LIVE paths is refused",
        rc.returncode != 0 and not os.path.exists(h + ".2"), rc.stdout.strip())

    # --------------------------------------------------------------- 6b
    # THE RUNTIME ARM, with its negative controls.  A rule that refused
    # everything would make its refusal vacuous, so the arms that must NOT
    # fire are what give the one that must its meaning.
    #
    # PRFUM is the shape FINDING 71-B measured: one FIXED row naming REG_SP,
    # on a rule whose instances publish REG_GPR0/1/2 and REG_LR beside it.
    # RTFIX is a genuine fixed source: the same register on every instance
    # and NOTHING else of its file varies.
    # RTONE varies over exactly ONE other member, which is not variation --
    # a two-register rule is not a file being selected from.
    # RTSOME publishes the candidate on only some instances, so it is not a
    # constant of the rule at all.
    rt_rows = [
        "      1536  8e2f807f PRFUMRULE                  REG_SP"
        "        FIXED   prfum",
        "        10  0000b1b1 RTFIXRULE                  REG_GPR7"
        "      FIXED   rtfix",
        "        10  0000b2b2 RTONERULE                  REG_GPR7"
        "      FIXED   rtone",
        "        10  0000b3b3 RTSOMERULE                 REG_GPR7"
        "      FIXED   rtsome",
    ]
    rt_witness = [
        "      1536  8e2f807f PRFUMRULE                  prfum",
        "        10  0000b1b1 RTFIXRULE                  rtfix",
        "        10  0000b2b2 RTONERULE                  rtone",
        "        10  0000b3b3 RTSOMERULE                 rtsome",
    ]
    r2 = os.path.join(d, "riscv64.rt.log")
    _sidecar(r2, rt_rows, [], rt_witness)
    corp = os.path.join(d, "riscv64.corpus.tsv")
    with open(corp, "w") as f:
        f.write("#isa\tencoding\tmnem\tdecode_id\tPUB\n")
        # prfum: REG_SP on every instance, GPR file varies over four others
        for i, other in enumerate(["REG_GPR0", "REG_GPR1", "REG_GPR2",
                                   "REG_LR"]):
            f.write("riscv64\t%08x\tprfum\t8e2f807f\tREG_SP,%s\n"
                    % (i, other))
        # rtfix: REG_GPR7 constant and nothing else of the file at all
        for i in range(4):
            f.write("riscv64\t%08x\trtfix\t0000b1b1\tREG_GPR7,REG_FCSR\n"
                    % (0x100 + i))
        # rtone: REG_GPR7 constant, exactly ONE other member beside it
        for i in range(4):
            f.write("riscv64\t%08x\trtone\t0000b2b2\tREG_GPR7,REG_GPR3\n"
                    % (0x200 + i))
        # rtsome: REG_GPR7 on half the instances only
        for i, pub in enumerate(["REG_GPR7,REG_GPR0", "REG_GPR1,REG_GPR2",
                                 "REG_GPR7,REG_GPR4", "REG_GPR5,REG_GPR6"]):
            f.write("riscv64\t%08x\trtsome\t0000b3b3\t%s\n"
                    % (0x300 + i, pub))
    snap2 = os.path.join(d, "snap_rt")
    rc = subprocess.run(me + ["--snapshot", snap2, "x86_64=" + x,
                              "aarch64=" + a_, "riscv64=" + r2,
                              "mipsel=" + m, "--corpus", "riscv64=" + corp],
                        capture_output=True, text=True)
    chk("ARM R0: a snapshot carries the corpus too", rc.returncode == 0,
        rc.stderr.strip())
    chk("ARM R0a: and says how many corpus files it took",
        "1 corpus file(s)" in rc.stdout, rc.stdout.strip())

    h2 = os.path.join(d, "out_rt.h")
    rc = subprocess.run(me + ["--out", h2, "--from-snapshot", snap2],
                        capture_output=True, text=True)
    txt2 = open(h2).read() if os.path.exists(h2) else ""
    chk("ARM R1: emit with a corpus present", rc.returncode == 0,
        rc.stderr.strip())
    chk("ARM R2: the FROZEN OPERAND (prfum/REG_SP) is NOT carried",
        "0x8e2f807fu, SRC_SURV" not in txt2, txt2[:0])
    chk("ARM R3: and it is REPORTED with what was measured -- the counts and "
        "the registers the file varied over, not a bare verdict",
        "REFUSED, not carried: 0x8e2f807f" in txt2
        and "constant on 4 of 4 instances" in txt2
        and "REG_GPR0,REG_GPR1,REG_GPR2,REG_LR" in txt2,
        [L for L in txt2.split("\n") if "8e2f807f" in L or "constant on" in L])
    chk("ARM R4 (NEGATIVE): a genuine FIXED source IS carried",
        "0x0000b1b1u, SRC_SURV" in txt2)
    chk("ARM R5 (NEGATIVE): ONE other member is not variation",
        "0x0000b2b2u, SRC_SURV" in txt2)
    chk("ARM R6 (NEGATIVE): a register on only SOME instances is not a "
        "constant of the rule", "0x0000b3b3u, SRC_SURV" in txt2)
    chk("ARM R7: the arm reports that it RAN, per ISA",
        "RUNTIME-ARM riscv64 : ran over" in rc.stdout
        or "RUNTIME-ARM riscv64" in rc.stdout and "ran over" in rc.stdout,
        rc.stdout.strip())
    chk("ARM R8: an ISA with NO corpus says the arm DID NOT RUN, never zero",
        "RUNTIME-ARM x86_64" in rc.stdout and "DID NOT RUN" in rc.stdout,
        rc.stdout.strip())

    # Without the corpus, the SAME sidecar carries the frozen row -- which is
    # what makes the arm's effect a measurement rather than a coincidence of
    # some other refusal.
    snap3 = os.path.join(d, "snap_nort")
    subprocess.run(me + ["--snapshot", snap3, "x86_64=" + x, "aarch64=" + a_,
                         "riscv64=" + r2, "mipsel=" + m],
                   capture_output=True, text=True)
    h3 = os.path.join(d, "out_nort.h")
    rc = subprocess.run(me + ["--out", h3, "--from-snapshot", snap3],
                        capture_output=True, text=True)
    txt3 = open(h3).read() if os.path.exists(h3) else ""
    chk("ARM R9: WITHOUT the corpus the same row IS carried -- the arm is "
        "what removes it", "0x8e2f807fu, SRC_SURV" in txt3, rc.stdout.strip())

    # A corpus that is not the mechanism corpus is refused, not read as empty.
    bad = os.path.join(d, "riscv64.badcorpus.tsv")
    open(bad, "w").write("#isa\tencoding\tmnem\tsrc\nriscv64\t0\tx\t-\n")
    snap4 = os.path.join(d, "snap_bad")
    subprocess.run(me + ["--snapshot", snap4, "x86_64=" + x, "aarch64=" + a_,
                         "riscv64=" + r2, "mipsel=" + m,
                         "--corpus", "riscv64=" + bad],
                   capture_output=True, text=True)
    rc = subprocess.run(me + ["--out", h + ".4", "--from-snapshot", snap4],
                        capture_output=True, text=True)
    chk("ARM R10: a corpus with no decode_id column is REFUSED, not read as "
        "'nothing varies'",
        rc.returncode != 0 and "not the mechanism corpus"
        in (rc.stdout + rc.stderr), (rc.stdout + rc.stderr).strip())

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
    inputs, corpora, i = {}, {}, 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 2; continue
        if argv[i] == "--snapshot":
            snapshot = argv[i + 1]; i += 2; continue
        if argv[i] == "--from-snapshot":
            from_snapshot = argv[i + 1]; i += 2; continue
        if argv[i] == "--corpus":
            c_isa, _, c_path = argv[i + 1].partition("=")
            if c_isa not in ISAS:
                sys.exit("unknown isa %r" % c_isa)
            corpora.setdefault(c_isa, []).append(c_path)
            i += 2; continue
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
        return make_snapshot(snapshot, inputs, corpora)

    if not out:
        sys.exit(__doc__)
    if not from_snapshot:
        sys.exit("REFUSING: emitting requires --from-snapshot DIR.\n"
                 "A sidecar path is written by the same gate that produces "
                 "it, and reading one live gave this table a corpus that no "
                 "single run ever had.  Run --snapshot DIR <isa>=<path>... "
                 "first, then emit from DIR.")
    if inputs or corpora:
        sys.exit("REFUSING: --from-snapshot and bare <isa>=<path> inputs "
                 "together; the snapshot is the corpus or nothing is")
    sidecars, cor = read_snapshot(from_snapshot)
    return emit(out, sidecars, from_snapshot,
                {isa: merged_corpus(paths) for isa, paths in cor.items()})


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
