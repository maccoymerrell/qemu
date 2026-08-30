#!/usr/bin/env python3
#
# Qualify i386 decode-table rows that serve BOTH encodings of an
# instruction on the encoding bit QEMU already has.
#
# THE PROBLEM.  A row of the i386 decode table is reached by the legacy
# SSE encoding of an instruction and by its VEX encoding alike -- the
# table is indexed by opcode, and the VEX prefix only supplies the
# implied 0F/66/F2/F3 bytes.  So ONE __LINE__ slot, one identity, answers
# for two spellings, and where the two spellings classify differently the
# identity cannot say which it is:
#
#     champsim_tracer_qemu_ident_x86.h
#       { 0x000003cdu, "VMOVLPx", QID_SPLIT, ...
#         /* SPLIT: GEN_OP_FP_MOV <- movsd; GEN_OP_VEC_MOV <- vmovsd */
#
#     -- 0x3cd is decode-new.c.inc:973.  `movsd xmm, xmm` merges into a
#        destination it also reads; `vmovsd` writes a full vector
#        destination from two sources.  Both readings are right, each of
#        its own spelling, so no amount of further observation settles
#        the row and neither does picking a winner.
#
# The discriminator is not missing.  `s->prefix & PREFIX_VEX` is set by
# decode_insn() before the row is ever consulted: the encoding is a fact
# the DisasContext holds at translation time.  It simply never reached
# the identity.
#
# WHAT THIS SCRIPT DOES, mechanically, in the shape
# scripts/x86_x87_ident_instrument.py established:
#
#   * it scans target/i386/tcg/decode-new.c.inc for every X86_OP_* site
#     whose mnemonic is in QUALIFY below, and emits
#     target/i386/tcg/vex_ident.c.inc: TWO identity rows per site, named
#     `decode-new/<mnemonic>@vex=0` and `@vex=1`;
#
#   * THE NAME IS NOT UNIQUE AND THE ID IS.  That is the contract's own
#     split, and on i386 it is not a corner case: 472 of the 854 base
#     slots already share their name with another slot, because QEMU's
#     table names a row for the generator it dispatches to.  Two rows of
#     the table name MOVQ and three name VMOVLPx, so `decode-new/MOVQ@vex=0`
#     is the name of two rules and may not be the id of one.  The id is
#     therefore FNV-1a-32 -- the derivation scripts/decodetree.py, the MIPS
#     leg and the x87 leg all use -- of the name with the base slot
#     appended, `decode-new/MOVQ@vex=0#553`, which is printed beside every
#     row so the hash can be recomputed by hand.  A qualified id thus
#     inherits exactly the stability the base id already has: stable for a
#     given source tree, not stable across a source edit that moves the
#     row, which is what the contract says an id guarantees;
#
#   * it inserts ONE call into decode-new.c.inc, immediately after the
#     unconditional publish, so a qualified slot's identity is REPLACED
#     by the arm the instruction was actually encoded in and every other
#     slot keeps the row's own id and name, bit for bit;
#
#   * it checks the selector EXHAUSTIVELY over the whole (slot, vex)
#     space -- every __LINE__ decode-new.c.inc can hand out, times both
#     values of the bit -- so "every encoding reaches exactly one
#     qualified identity, and no unqualified slot reaches any" is
#     measured rather than asserted.
#
# THE BASE ROWS DO NOT MOVE.  No X86_OP_* row is edited, no line is
# inserted above one, and the script REFUSES if the insertion point is
# not below every site in the file -- inserting a line above a row would
# renumber its __LINE__ and silently reattach every banked observation to
# a different rule.
#
# ALL FORMS ARE QUALIFIED.  The set is by MNEMONIC, not by slot, so every
# row of QEMU's table that names a member is carved, including the ones
# no corpus has reached.  Carving only the observed row would leave a
# sibling row answering for both encodings with one classification --
# the same defect one file over.
#
# WHERE THE SET COMES FROM.  Each member was measured, not chosen: the
# VEX/legacy collision witness partitions each identity's observed
# Capstone constants into the two arms and runs both through the
# generator's own classifier.  These are the mnemonics whose arms
# disagree AND whose row is currently QID_SPLIT, i.e. the rows that
# publish nothing today because the identity cannot tell the two
# encodings apart.  Every one of them carries a vexN flag in QEMU's own
# table, and the script REFUSES a member that does not -- a row with no
# VEX form has no bit to qualify on.
#
# Author: Maccoy Merrell

import argparse
import os
import re
import sys

# The one-row-two-encodings group.  Ordered as the witness reports them.
#
#   MOVD_from   0x228  legacy movd/movq GEN_OP_MOV vs VEX GEN_OP_VEC_MOV
#   MOVQ        0x229, 0x26a          same disagreement, both directions
#   MOVD_to     0x572                 same disagreement
#   VMOVLPx     0x3cd  movsd GEN_OP_FP_MOV vs vmovsd GEN_OP_VEC_MOV
#   VMOVSD_ld   0x3d4                 same
#   VMOVLPx_st  0x3eb                 same
#   VCVTSI2Sx   0x433  cvtsi2sd dep_passthrough vs vcvtsi2sd none --
#                      adjudicated both-correct-per-spelling, the upper
#                      lane of the VEX form comes from a THIRD register
#   VCMP        0x517  legacy arm resolves to cmpps; the VEX arm carries
#                      a further disagreement of its own, which this
#                      qualification does not claim to settle
QUALIFY = (
    "MOVD_from",
    "MOVQ",
    "MOVD_to",
    "VMOVLPx",
    "VMOVSD_ld",
    "VMOVLPx_st",
    "VCVTSI2Sx",
    "VCMP",
)

# The same scanner the plugin's generator uses to derive the identity
# universe (champsim_tracer_mnemonic_audit.py: X86_SLOT_RE).  The two
# MUST agree on which lines carry a slot, or the table would name a slot
# the universe does not have.
SLOT_RE = re.compile(
    r'\bX86_OP_(ENTRY[0-4rw]{0,2}|GROUP[0-3rw]{0,2}|LEAF|SET_GEN)'
    r'\s*\(\s*([A-Za-z0-9_]+)\s*(?:,\s*([A-Za-z0-9_]+))?')

# A row's VEX flag.  vex1..vex7 and the vexN_* variants; see the
# X86_VEX_* class table in decode-new.c.inc.
VEX_FLAG_RE = re.compile(r'\bvex\d[A-Za-z0-9_]*')

PUBLISH_RE = re.compile(
    r'^\s*plugin_gen_record_insn_identity\(decode\.e\.slot,'
    r'\s*decode\.e\.mnemonic\);\s*$')

TAG = '/* vex_ident */'
CALL = ('vex_ident_publish(decode.e.slot, (s->prefix & PREFIX_VEX) != 0);'
        '  ' + TAG)


def fnv1a32(text):
    """FNV-1a 32 of TEXT, with 0 remapped to 1.

       Identical derivation to scripts/decodetree.py's ident_hash(), to the
       MIPS leg's and to the x87 leg's, so every identity in this tree is
       made the same way.  0 is reserved by the plugin API for 'no identity
       recorded'."""
    h = 0x811c9dc5
    for byte in text.encode('utf-8'):
        h = ((h ^ byte) * 0x01000193) & 0xffffffff
    return h if h else 1


def scan_slots(lines):
    """Every X86_OP_* site, as (slot, mnemonic, macro-kind, raw line).

       Macro DEFINITIONS expand X86_OP_ENTRY3 inside themselves and are
       skipped, exactly as the generator skips them: counting those would
       mint slots no row ever carries."""
    out = []
    in_define = False
    for lineno, line in enumerate(lines, 1):
        cont = line.endswith('\\')
        if line.lstrip().startswith('#define'):
            in_define = cont
            continue
        if in_define:
            in_define = cont
            continue
        for m in SLOT_RE.finditer(line):
            kind = m.group(1)
            name = m.group(3) if kind == 'SET_GEN' else m.group(2)
            out.append((lineno, name, kind, line))
    return out


def strip_instrumentation(lines):
    out, removed = [], 0
    for l in lines:
        if l.rstrip().endswith(TAG):
            removed += 1
            continue
        out.append(l)
    return out, removed


def selector_model(rows):
    """slot -> (index of the vex=0 row, index of the vex=1 row).

       The model the emitted vex_ident_of() implements; the exhaustive
       check runs against THIS, and the emitter writes THIS out, so the
       two cannot drift."""
    model = {}
    for idx, (slot, mnem, kind, arm, name, h, keyed) in enumerate(rows, 1):
        model.setdefault(slot, [0, 0])[arm] = idx
    return model


def check_exhaustive(model, n_lines):
    """Every (slot, vex) in the whole space, against the model.

       Not a sample: the i386 slot space IS the line space of one file, so
       it can be walked entire.  Reports the residual -- the slots that
       reach no qualified identity -- rather than only the hits, because a
       selector that answered for everything would pass a hits-only check."""
    hits = 0
    residual = 0
    for slot in range(1, n_lines + 2):
        for vex in (0, 1):
            got = model.get(slot, [0, 0])[vex]
            if slot in model:
                if got == 0:
                    return None, 'slot %d arm vex=%d reaches NO row' % (slot, vex)
                hits += 1
            else:
                if got != 0:
                    return None, ('unqualified slot %d reaches row %d'
                                  % (slot, got))
                residual += 1
    seen = {}
    for slot, pair in model.items():
        for vex, idx in enumerate(pair):
            if idx in seen:
                return None, ('row %d is reached by two selectors: %s and %s'
                              % (idx, seen[idx], (slot, vex)))
            seen[idx] = (slot, vex)
    return (hits, residual), None


def build(path_dec, path_out, report):
    with open(path_dec) as f:
        src = f.read().split('\n')
    src, removed = strip_instrumentation(src)

    sites = scan_slots(src)
    by_line = {}
    for slot, name, kind, line in sites:
        by_line.setdefault(slot, []).append(name)
    clash = {k: v for k, v in by_line.items() if len(v) > 1}
    if clash:
        for k, v in sorted(clash.items()):
            print('ERROR: line %d carries %d slots: %s'
                  % (k, len(v), ', '.join(v)), file=sys.stderr)
        return 1

    rows = []
    matched = {}
    for slot, name, kind, line in sites:
        if name not in QUALIFY:
            continue
        if not VEX_FLAG_RE.search(line):
            print('ERROR: %s at line %d carries no vexN flag -- a row with '
                  'no VEX form has no bit to qualify on' % (name, slot),
                  file=sys.stderr)
            return 1
        matched.setdefault(name, []).append(slot)
        for arm in (0, 1):
            ident = 'decode-new/%s@vex=%d' % (name, arm)
            keyed = '%s#%d' % (ident, slot)
            rows.append((slot, name, kind, arm, ident, fnv1a32(keyed), keyed))
    missing = [m for m in QUALIFY if m not in matched]
    if missing:
        print('ERROR: %d qualify member(s) match no X86_OP_* site: %s -- a '
              'carve with no subject is a stale argument, not a no-op'
              % (len(missing), ', '.join(missing)), file=sys.stderr)
        return 1
    rows.sort(key=lambda r: (r[0], r[3]))

    # Ids live in the same uint32_t space as the __LINE__ slots and as the
    # x87 leaves.  Two rules sharing one id merge silently in every
    # consumer, so a collision is refused rather than reported.
    slots = set(range(1, len(src) + 2))
    bad = [r for r in rows if r[5] in slots]
    dupes = [r for r in rows if [q[5] for q in rows].count(r[5]) > 1]
    x87 = os.path.join(os.path.dirname(path_out), 'x87_ident.c.inc')
    x87_ids = set()
    if os.path.exists(x87):
        with open(x87) as f:
            x87_ids = {int(m.group(1), 16) for m in
                       re.finditer(r'\{\s*(0x[0-9a-f]+)u,', f.read())}
    cross = [r for r in rows if r[5] in x87_ids]
    for tag, bunch in (('a __LINE__ slot', bad), ('another vex row', dupes),
                       ('an x87 leaf', cross)):
        if bunch:
            for r in bunch:
                print('ERROR: id 0x%08x (%s) collides with %s'
                      % (r[5], r[4], tag), file=sys.stderr)
            return 1

    model = selector_model(rows)
    got, why = check_exhaustive(model, len(src))
    if why:
        print('ERROR: selector check failed -- %s' % why, file=sys.stderr)
        return 1
    hits, residual = got

    # The insertion point: the unconditional publish.  It must be BELOW
    # every X86_OP_* site in the file, or the inserted line renumbers a
    # slot and silently reattaches every banked observation to a
    # different rule.
    pub = [i for i, l in enumerate(src) if PUBLISH_RE.match(l)]
    if len(pub) != 1:
        print('ERROR: %d unconditional publish sites in %s, expected exactly 1'
              % (len(pub), os.path.basename(path_dec)), file=sys.stderr)
        return 1
    pub_line = pub[0] + 1
    below = [s for s, _n, _k, _l in sites if s >= pub_line]
    if below:
        print('ERROR: %d X86_OP_* site(s) at or below the publish (line %d): '
              '%s -- inserting there would renumber their slots'
              % (len(below), pub_line, below[:5]), file=sys.stderr)
        return 1

    base = os.path.basename(path_dec)
    with open(path_out, 'w') as f:
        f.write(
            '/*\n'
            ' * Auto-generated by scripts/%s -- do not edit.\n'
            ' *\n'
            ' * QEMU\'s own identity for the two ENCODINGS of a decode-table\n'
            ' * row that serves both.  The i386 table is indexed by opcode,\n'
            ' * and a VEX prefix only supplies the implied 0F/66/F2/F3\n'
            ' * bytes, so one __LINE__ slot answers for the legacy SSE\n'
            ' * spelling of an instruction and for its VEX spelling alike.\n'
            ' * Where the two classify differently the slot cannot say\n'
            ' * which it is, and the row publishes nothing at all.\n'
            ' *\n'
            ' * The discriminator is not missing: decode_insn() sets\n'
            ' * PREFIX_VEX before the row is consulted.  These rows carry\n'
            ' * it into the identity.\n'
            ' *\n'
            ' * The name is `decode-new/<mnemonic>@vex=<bit>`: the rule\'s\n'
            ' * own name in QEMU\'s source, qualified by the encoding bit,\n'
            ' * in the same `@`-suffixed form decodetree writes when one\n'
            ' * trans_ function is reached from several patterns.\n'
            ' *\n'
            ' * THE NAME IS NOT UNIQUE AND THE ID IS -- the contract\'s own\n'
            ' * split.  QEMU names a table row for the generator it\n'
            ' * dispatches to, so two rows name MOVQ and three name\n'
            ' * VMOVLPx, and 472 of the 854 base slots already share a name\n'
            ' * with another slot.  The id is therefore FNV-1a 32 -- the\n'
            ' * derivation scripts/decodetree.py uses -- of the name with\n'
            ' * the base slot appended, printed beside each row so it can be\n'
            ' * recomputed by hand.  A qualified id is exactly as stable as\n'
            ' * the base id it is folded from, and no more.\n'
            ' *\n'
            ' * THE BASE ROWS DO NOT MOVE.  %s is not edited\n'
            ' * apart from the one inserted call, which sits BELOW every\n'
            ' * X86_OP_* site so no slot is renumbered, and a slot that is\n'
            ' * not qualified here keeps the row\'s own id and name bit for\n'
            ' * bit.  Both arms of a qualified slot are present: the\n'
            ' * selector is checked over the whole (slot, vex) space, so a\n'
            ' * qualified row cannot fall back to the base identity for one\n'
            ' * value of the bit and publish for the other.\n'
            ' */\n\n'
            % (os.path.basename(__file__), base))
        f.write('static const struct {\n'
                '    uint32_t id;\n'
                '    const char *name;\n'
                '} vex_ident_tab[] = {\n'
                '    { 0, NULL },\n')
        for (slot, mnem, kind, arm, name, h, keyed) in rows:
            f.write('    /* %s %s encoding, X86_OP_%s; FNV-1a-32 of "%s" */\n'
                    % (mnem, 'VEX' if arm else 'legacy', kind, keyed))
            f.write('    /* %s:%d */\n' % (base, slot))
            f.write('    { 0x%08xu, "%s" },\n' % (h, name))
        f.write('};\n\n')
        f.write('/*\n'
                ' * The qualified rows a slot reaches, indexed by the VEX\n'
                ' * bit.  Sorted by slot; a slot absent here is not\n'
                ' * qualified and keeps its own identity.\n'
                ' */\n')
        f.write('static const struct {\n'
                '    uint32_t slot;\n'
                '    uint16_t idx[2];\n'
                '} vex_ident_slots[] = {\n')
        for slot in sorted(model):
            a, b = model[slot]
            f.write('    { %4d, { %2d, %2d } },\n' % (slot, a, b))
        f.write('};\n\n')
        f.write('static inline uint16_t vex_ident_of(uint32_t slot, bool vex)\n'
                '{\n'
                '    for (size_t i = 0; i < ARRAY_SIZE(vex_ident_slots); i++) {\n'
                '        if (vex_ident_slots[i].slot == slot) {\n'
                '            return vex_ident_slots[i].idx[vex];\n'
                '        }\n'
                '    }\n'
                '    return 0;\n'
                '}\n\n')
        f.write('/*\n'
                ' * Publish the encoding-qualified identity for a slot that\n'
                ' * has one.  A slot that has none publishes nothing and\n'
                ' * keeps what the unconditional publish above recorded.\n'
                ' */\n'
                'static inline void vex_ident_publish(uint32_t slot, bool vex)\n'
                '{\n'
                '    uint16_t idx = vex_ident_of(slot, vex);\n\n'
                '    if (idx) {\n'
                '        plugin_gen_record_insn_identity(vex_ident_tab[idx].id,\n'
                '                                        vex_ident_tab[idx].name);\n'
                '    }\n'
                '}\n')

    indent = re.match(r'^(\s*)', src[pub[0]]).group(1)
    out = src[:pub[0] + 1] + ['%s%s' % (indent, CALL)] + src[pub[0] + 1:]
    with open(path_dec, 'w') as f:
        f.write('\n'.join(out))

    with open(report, 'w') as f:
        f.write('x86_vex_ident_instrument residue report\n')
        f.write('=======================================\n\n')
        f.write('decode table      : %s\n' % path_dec)
        f.write('previous inserts stripped: %d\n' % removed)
        f.write('publish site      : line %d (below all %d sites, max %d)\n'
                % (pub_line, len(sites), max(s for s, _n, _k, _l in sites)))
        f.write('qualify members   : %d\n' % len(QUALIFY))
        f.write('rows carved       : %d over %d slot(s)\n'
                % (len(rows), len(model)))
        f.write('(slot, vex) pairs checked: %d  qualified %d  residual %d\n\n'
                % (hits + residual, hits, residual))
        f.write('every member, every slot of it\n')
        f.write('------------------------------\n')
        for m in QUALIFY:
            f.write('%-12s %s\n'
                    % (m, ', '.join('%s:%d' % (base, s)
                                    for s in matched[m])))
        f.write('\nevery row, in selector order\n')
        f.write('----------------------------\n')
        for (slot, mnem, kind, arm, name, h, keyed) in rows:
            f.write('0x%08x  %-34s  %s:%d  X86_OP_%-10s  hashed "%s"\n'
                    % (h, name, base, slot, kind, keyed))
    print('vex: %d rows over %d slots, %d (slot,vex) pairs checked, '
          '%d qualified' % (len(rows), len(model), hits + residual, hits))
    return 0


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument('--decode',
                    default=os.path.join(here, 'target/i386/tcg/decode-new.c.inc'))
    ap.add_argument('--out',
                    default=os.path.join(here, 'target/i386/tcg/vex_ident.c.inc'))
    ap.add_argument('--report',
                    default=os.path.join(
                        here, 'contrib/plugins/champsim_tracer/tools/'
                        'arc3_qemuid/VEX_IDENT_RESIDUE.txt'))
    args = ap.parse_args()
    return build(args.decode, args.out, args.report)


if __name__ == '__main__':
    sys.exit(main())
