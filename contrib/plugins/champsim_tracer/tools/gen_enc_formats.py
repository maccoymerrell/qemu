#!/usr/bin/env python3
#
# THE FORMATS AN ENCODING FIELD IS A REGISTER IN.
#
# Author: Maccoy Merrell
# SPDX-License-Identifier: GPL-2.0-or-later
#
# WHY THIS EXISTS.  champsim_tracer_enc_fields.h says WHERE the MSA vector
# fields sit -- `wt = 20:16, ws = 15:11, wd = 10:6` of a 32-bit MIPS word --
# and it said so unconditionally, with its own reason written down:
#
#     a role naming `wt` on an I8 encoding is a numeric coincidence and the
#     census's ambiguity report is what catches it, not a per-format table
#     here: the census scores a field against an OBSERVED register number,
#     and a format table would let this file decide an answer the
#     measurement is supposed to give.
#
# THE MEASUREMENT IT DEFERRED TO WAS A GUEST CONTAINING ONE FORMAT.  Every
# MSA instruction reaches QEMU through the single decode rule
# `translate_mips/OPC_MDMX`, so the two `and.v`-derived ENC rows keyed on
# that rule fire on every MSA instruction there is -- and on 192 mnemonics of
# the I5, I8, I10, BIT, ELM, 2R and MI10 formats bits 20:16 hold an
# IMMEDIATE, a df selector or an opcode subfield.  14,975 mipsel encodings
# published a vector register that no field of theirs selects; LLVM refutes
# 100% of them.  The ambiguity guard catches `ws == wd` coincidences and
# cannot ask whether the position is a register at all.
#
# SO THE QUESTION IS ASKED, AND IT IS ASKED OF A FORMAT TABLE, because
# "is bits 20:16 of THIS word a vector register" is a property of the
# instruction FORMAT and of nothing an execution can observe: an I8 whose
# immediate happens to spell 14 is indistinguishable, register-number for
# register-number, from a 3R naming $w14.  No corpus can separate them, which
# is exactly why the deferral could not work.
#
# THE TABLE IS NOT WRITTEN HERE EITHER.  It is read out of QEMU's own
# `target/mips/tcg/msa.decode`, whose header cites MSA32 revision 1.12
# (MD00866) -- the same document champsim_tracer_enc_fields.h cites for the
# field offsets.  The decodetree gives, per instruction, the fixed bits that
# select it and the format that says which of wt/ws/wd it encodes AS A FIELD
# at all; a format that assigns `wt=0` does not encode wt, and a pattern the
# tree does not match is a format this file cannot name, which REFUSES rather
# than guesses.
#
# WHAT THE DECODETREE CANNOT SAY is which BANK the field indexes, because
# decodetree only names bits.  Five MSA instructions put a GPR or an MSA
# control register in a position the format calls ws or wd, and those are
# STATED below with the QEMU translator function that proves each one.  A
# stated row naming an instruction the decode file does not define is a
# REFUSAL: a table that can go stale silently is the defect this generator
# exists to remove.
#
# Regenerate with:
#     python tools/gen_enc_formats.py --root <qemu-root> \
#            -o ../champsim_tracer_enc_formats_mips.h
#
import argparse
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
DECODE_REL = os.path.join("target", "mips", "tcg", "msa.decode")

# The three field names champsim_tracer_enc_fields.h defines for MIPS, and
# the enumerator each one carries.  PARSED from that header rather than
# repeated -- the two files may not drift, and a field added there without a
# format answer here must be a refusal, not a silent unqualified publication.
FIELDS_H = os.path.join(HERE, "..", "champsim_tracer_enc_fields.h")

# ---------------------------------------------------------------------------
# THE STATED ROWS.  Position -> bank, where the decodetree names the position
# and only the architecture names the bank.  Each carries the QEMU translator
# that proves it; each names an instruction msa.decode must define.
#
# `legal` is the set of {wt, ws, wd} positions this instruction encodes A
# VECTOR REGISTER in.  Everything absent from the set is refused.
STATED = {
    # ctcmsa cd, rs -- MSA32 1.12 s.3.1: the ws position is rs, a GPR, and
    # the wd position is cd, an MSA CONTROL register.  Neither is a vector
    # register.  trans_CTCMSA(): gen_load_gpr(telm, a->ws), and a->wd is
    # passed to helper_msa_ctcmsa as the control index.
    "CTCMSA": (set(), "trans_CTCMSA: gen_load_gpr(a->ws); wd is the control index"),
    # cfcmsa rd, cs -- the mirror: ws is the control index, wd is a GPR.
    # trans_CFCMSA(): helper_msa_cfcmsa(a->ws), gen_store_gpr(telm, a->wd).
    "CFCMSA": (set(), "trans_CFCMSA: a->ws is the control index; gen_store_gpr(a->wd)"),
    # copy_s.df rd, ws[n] -- the wd position is rd, a GPR destination.
    "COPY_S": ({"ws"}, "trans_COPY_S -> trans_msa_elm_fn: wd is the GPR destination"),
    # copy_u.df rd, ws[n] -- likewise.
    "COPY_U": ({"ws"}, "trans_COPY_U -> trans_msa_elm_fn: wd is the GPR destination"),
    # insert.df wd[n], rs -- the ws position is rs, a GPR source.
    "INSERT": ({"wd"}, "trans_INSERT -> trans_msa_elm_fn: ws is the GPR source"),
    # ld.df wd, s10(rs) / st.df -- the position @ldst calls ws is the base
    # GPR.  trans_msa_ldst(): gen_base_offset_addr(ctx, taddr, a->ws, ...).
    "LD": ({"wd"}, "trans_msa_ldst: gen_base_offset_addr(a->ws) -- ws is the base GPR"),
    "ST": ({"wd"}, "trans_msa_ldst: gen_base_offset_addr(a->ws) -- ws is the base GPR"),
    # sld.df wd, ws[rt] / splat.df wd, ws[rt] -- the @3r `wt` position is rt,
    # a GPR holding the column/element index.  Not enumerated: msa_helper.c's
    # `env->active_tc.gpr[` sites are the complete list of MSA operands that
    # index the GPR bank, and these two are the only 3R-family members on it.
    "SLD": ({"ws", "wd"}, "helper_msa_sld_df: msa_sld_df(..., env->active_tc.gpr[rt]) -- wt is rt"),
    "SPLAT": ({"ws", "wd"}, "helper_msa_splat_df: msa_splat_df(..., env->active_tc.gpr[rt]) -- wt is rt"),
    # fill.df wd, rs -- the @2r `ws` position is rs, a GPR.
    "FILL": ({"wd"}, "helper_msa_fill_df: pwd->b[i] = env->active_tc.gpr[rs] -- ws is rs"),
}

TOKEN = re.compile(r"^[01.]+$")
FIELD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(s?)(\d+)$")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def refuse(msg):
    raise SystemExit("gen_enc_formats: REFUSING -- " + msg)


def field_enumerators(path=FIELDS_H):
    """{field name: enumerator} for MIPS, out of the plugin's own header."""
    try:
        txt = open(path).read()
    except OSError as e:
        refuse("cannot read %s (%s).  The field names live there and "
               "nowhere else." % (path, e))
    out = {}
    for m in re.finditer(r"\{\s*(SRC_ENC_FIELD_[A-Z0-9_]+)\s*,\s*"
                         r"(TRACE_ISA_[A-Z0-9_]+)\s*,[^}]*?"
                         r'"([a-z0-9_]+)"\s*\}', txt):
        if m.group(2) == "TRACE_ISA_MIPS":
            out[m.group(3)] = m.group(1)
    if not out:
        refuse("%s defines no MIPS encoding fields; there would be nothing "
               "to qualify." % path)
    return out


def strip_comment(line):
    i = line.find("#")
    return line if i < 0 else line[:i]


def parse_decode(path):
    """(formats, insns) out of a decodetree file.

    formats  {name: {field: (lsb, width)}}  -- only the BIT fields; a
             constant assignment (`wt=0`) is deliberately not one, because a
             position the encoding does not carry is a position no register
             can be read out of.
    insns    [(name, mask, value, fmt, lineno)] in FILE ORDER, which is
             decodetree's own match order inside an overlap group.
    """
    formats, insns = {}, []
    try:
        lines = open(path).read().splitlines()
    except OSError as e:
        refuse("cannot read the decode file %s (%s)" % (path, e))

    for n, raw in enumerate(lines, 1):
        line = strip_comment(raw).strip()
        if not line or line in ("{", "}", "{}"):
            continue
        # An overlap group opens with `{` on its own line here; a pattern may
        # not share the line in this file and a future one that did would be
        # unparsed rather than misparsed.
        if line.startswith("{") or line.endswith("{"):
            continue
        toks = line.split()
        name = toks[0]
        if name.startswith("&") or name.startswith("%"):
            continue                      # an argument set or a function field
        body = toks[1:]
        isfmt = name.startswith("@")
        fmt_ref, mask, value, pos = None, 0, 0, 0
        fields = {}
        for t in body:
            if t.startswith("@"):
                fmt_ref = t[1:]
                continue
            if t.startswith("&") or t.startswith("%") or ASSIGN.match(t):
                continue                  # argument set / constant assignment
            if TOKEN.match(t):
                for c in t:
                    mask <<= 1
                    value <<= 1
                    if c != ".":
                        mask |= 1
                        value |= (c == "1")
                    pos += 1
                continue
            m = FIELD.match(t)
            if not m:
                refuse("%s:%d: token %r is neither fixed bits, a field nor an "
                       "assignment.  A pattern this parser cannot read must "
                       "not be scored as one with no constraints." %
                       (path, n, t))
            w = int(m.group(3))
            fields[m.group(1)] = (32 - pos - w, w)
            mask <<= w
            value <<= w
            pos += w
        if pos != 32:
            refuse("%s:%d: %s spells %d bits, not 32.  A short pattern would "
                   "mask the wrong end of the word." % (path, n, name, pos))
        if isfmt:
            formats[name[1:]] = fields
        else:
            if fmt_ref is None:
                refuse("%s:%d: instruction %s names no format, so which of "
                       "wt/ws/wd it encodes is unstated." % (path, n, name))
            insns.append((name, mask, value, fmt_ref, n))
    if not formats or not insns:
        refuse("%s yielded %d formats and %d instructions -- an empty table "
               "would qualify nothing and refuse everything." %
               (path, len(formats), len(insns)))
    return formats, insns


def build_rows(formats, insns, enums, decode_rel):
    """One row per instruction: (mask, value, legal-set, name, why)."""
    seen = set()
    rows = []
    for name, mask, value, fmt, lineno in insns:
        if fmt not in formats:
            refuse("instruction %s at line %d names format @%s, which the "
                   "file does not define." % (name, lineno, fmt))
        declared = {f for f in enums if f in formats[fmt]}
        if name in STATED:
            legal, why = STATED[name]
            seen.add(name)
            unknown = legal - declared
            if unknown:
                refuse("the stated row for %s allows %s, which @%s does not "
                       "encode as a field at all." %
                       (name, ",".join(sorted(unknown)), fmt))
            why = "STATED: " + why
        else:
            legal = declared
            why = "@%s" % fmt
        # The field must sit where champsim_tracer_enc_fields.h says it does.
        rows.append((mask, value, legal, name, fmt, lineno, why))
    missing = set(STATED) - seen
    if missing:
        refuse("stated rows for %s name no instruction in %s.  A bank "
               "correction whose subject has moved is a correction that no "
               "longer applies to anything." %
               (",".join(sorted(missing)), decode_rel))
    return rows


def check_offsets(formats, enums, fields_h_text):
    """Every format that encodes a named field must put it where the plugin's
    header says it is.  The two files cite the same document; if they ever
    disagree, one of them is wrong and neither may be believed."""
    want = {}
    for m in re.finditer(r"\{\s*(SRC_ENC_FIELD_[A-Z0-9_]+)\s*,\s*TRACE_ISA_MIPS\s*,"
                         r"\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,", fields_h_text):
        want[m.group(1)] = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
    bad = []
    for fmt, fields in formats.items():
        for fname, (lsb, width) in fields.items():
            if fname not in enums:
                continue
            e = enums[fname]
            if e not in want:
                refuse("field %r has enumerator %s but no definition row this "
                       "parser can read in the header." % (fname, e))
            nbytes, wlsb, wwidth = want[e]
            if nbytes != 4 or (wlsb, wwidth) != (lsb, width):
                bad.append("@%s %s at %d:%d, header says %d:%d (%d bytes)" %
                           (fmt, fname, lsb + width - 1, lsb,
                            wlsb + wwidth - 1, wlsb, nbytes))
    if bad:
        refuse("the decode file and champsim_tracer_enc_fields.h disagree "
               "about where a field is:\n  " + "\n  ".join(sorted(set(bad))))


def emit(rows, enums, decode_path, decode_rel, out):
    txt = open(decode_path, "rb").read()
    md5 = hashlib.md5(txt).hexdigest()
    a = []
    a.append("#ifndef CHAMPSIM_TRACER_ENC_FORMATS_MIPS_H")
    a.append("#define CHAMPSIM_TRACER_ENC_FORMATS_MIPS_H")
    a.append("")
    a.append("/*")
    a.append(" * THE MIPS ENCODING FORMATS, and which of wt/ws/wd each one")
    a.append(" * carries a VECTOR REGISTER in -- auto-generated by")
    a.append(" * tools/gen_enc_formats.py.  Do not hand-edit a row.")
    a.append(" *")
    a.append(" * Read from QEMU's own %s" % decode_rel)
    a.append(" *   md5 %s, %d patterns over %d formats" %
             (md5, len(rows), len({r[4] for r in rows})))
    a.append(" * whose header cites MSA32 revision 1.12 (MD00866), the same")
    a.append(" * document champsim_tracer_enc_fields.h cites for the offsets.")
    a.append(" *")
    a.append(" * WHAT A ROW ANSWERS.  champsim_tracer_enc_fields.h says where")
    a.append(" * `wt`, `ws` and `wd` sit in a 32-bit MIPS word.  It cannot say")
    a.append(" * whether the word in hand PUTS A REGISTER THERE: every MSA")
    a.append(" * instruction decodes through one rule, and across the I5, I8,")
    a.append(" * I10, BIT, ELM, 2R and MI10 formats bits 20:16 hold an")
    a.append(" * immediate, a df selector or an opcode subfield.  A register")
    a.append(" * number read out of those bits is a fabrication that no")
    a.append(" * measurement over encodings can detect -- an I8 immediate that")
    a.append(" * spells 14 is bit-for-bit a 3R naming $w14 -- so the answer is")
    a.append(" * a FORMAT fact and it is taken from the format table.")
    a.append(" *")
    a.append(" * .legal carries one bit per SrcEncFieldId: field `f` is a")
    a.append(" * vector register in this pattern iff (legal >> f) & 1.  A word")
    a.append(" * matching NO row is legal in nothing: an encoding whose format")
    a.append(" * this table cannot name is one no field can be read out of.")
    a.append(" *")
    a.append(" * Rows are in DECODETREE ORDER and the first match wins, which")
    a.append(" * is decodetree's own rule inside an overlap group -- `ctcmsa`")
    a.append(" * precedes `sldi` there and must here.")
    a.append(" *")
    a.append(" * A row marked STATED carries a bank the decodetree cannot")
    a.append(" * state: decodetree names bits, and five MSA instructions put a")
    a.append(" * GPR or an MSA control register in a position the format calls")
    a.append(" * ws or wd.  The QEMU translator that proves each is named.")
    a.append(" */")
    a.append("")
    a.append("typedef struct {")
    a.append("    uint32_t    mask;   /* the bits this pattern fixes         */")
    a.append("    uint32_t    value;  /* what it fixes them to               */")
    a.append("    uint8_t     legal;  /* 1u << SrcEncFieldId, per field      */")
    a.append("    const char *name;   /* the decodetree pattern's own name   */")
    a.append("} SrcEncFormatRow;")
    a.append("")
    a.append("static const SrcEncFormatRow g_src_enc_formats_mips[] = {")
    for mask, value, legal, name, fmt, lineno, why in rows:
        bits = " | ".join("(1u << %s)" % enums[f] for f in sorted(legal)) or "0u"
        a.append("    { 0x%08xu, 0x%08xu, %-58s \"%s\" },%s" %
                 (mask, value, bits + ",", name,
                  "" if why.startswith("@") else ""))
        a.append("        /* %s:%d  %s */" % (decode_rel, lineno, why))
    a.append("};")
    a.append("")
    a.append("/*")
    a.append(" * The fields @word may be read as a register out of, or 0.")
    a.append(" * Linear and first-match: the table is a few hundred rows, this")
    a.append(" * runs at TRANSLATION time only, and a bisect would have to")
    a.append(" * reorder rows whose order is the decode semantics.")
    a.append(" */")
    a.append("static inline uint8_t src_enc_format_legal_mips(uint32_t word)")
    a.append("{")
    a.append("    for (unsigned i = 0; i < G_N_ELEMENTS(g_src_enc_formats_mips);")
    a.append("         i++) {")
    a.append("        const SrcEncFormatRow *r = &g_src_enc_formats_mips[i];")
    a.append("")
    a.append("        if ((word & r->mask) == r->value) {")
    a.append("            return r->legal;")
    a.append("        }")
    a.append("    }")
    a.append("    return 0;")
    a.append("}")
    a.append("")
    a.append("#endif /* CHAMPSIM_TRACER_ENC_FORMATS_MIPS_H */")
    text = "\n".join(a) + "\n"
    if out == "-":
        sys.stdout.write(text)
    else:
        open(out, "w").write(text)
    return md5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=DEFAULT_ROOT,
                    help="QEMU source root holding " + DECODE_REL)
    ap.add_argument("-o", "--out", default="-")
    args = ap.parse_args()

    path = os.path.join(args.root, DECODE_REL)
    enums = field_enumerators()
    formats, insns = parse_decode(path)
    check_offsets(formats, enums, open(FIELDS_H).read())
    rows = build_rows(formats, insns, enums, DECODE_REL)
    md5 = emit(rows, enums, path, DECODE_REL, args.out)
    nq = sum(1 for r in rows if r[2])
    sys.stderr.write("gen_enc_formats: %d patterns, %d formats, %d carry a "
                     "qualified field (md5 %s)\n" %
                     (len(rows), len(formats), nq, md5))


if __name__ == "__main__":
    main()
