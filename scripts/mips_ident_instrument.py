#!/usr/bin/env python3
#
# Export QEMU's own decode identity from the hand-written MIPS switch.
#
# The MIPS base ISA is not decoded by decodetree.  It is decoded by a
# nest of hand-written switch statements in target/mips/tcg/translate.c,
# so scripts/decodetree.py's identity export (which emits the recording
# call at each generated dispatch site) reaches none of it and a mipsel
# trace carries no QEMU identity at all.  The identity is nevertheless
# there: it is the `case OPC_*` label the switch dispatched on.
#
# This script states that identity in the source, mechanically:
#
#   * it emits target/mips/tcg/translate_ident.c.inc -- one row per
#     distinct opcode enumerator that appears as a case label, with the
#     decoder-qualified name "translate_mips/<OPC>" and its FNV-1a-32,
#     the same derivation the decodetree leg uses;
#   * it rewrites translate.c, inserting one mips_ident() call after each
#     group of opcode case labels, selecting the row FROM THE SWITCH'S
#     OWN CONTROLLING EXPRESSION so a group covering several labels says
#     which one it committed to, and a fallthrough into a later group
#     selects nothing rather than the later group's first label.
#
# It is idempotent: an already-instrumented translate.c is stripped back
# to pristine before being instrumented again.
#
# What it deliberately does NOT do is guess.  Every case group it does
# not instrument is listed by file and line in the residue report, and a
# group whose preprocessor directives do not balance inside the group is
# a hard error rather than a silent skip.
#
# Author: Maccoy Merrell

import argparse
import os
import re
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ident_instrument_paths  # noqa: E402  (path fixed up just above)

# The opcode-enumerator families that appear as case labels in the
# hand-written MIPS decoder.  A case label outside these families is not
# an instruction identity (CP0 register selectors, DISAS_* states, format
# codes, plain integers) and is reported as residue rather than exported.
OPC_PREFIXES = ('OPC_', 'R6_OPC_', 'MMI_OPC_', 'TX79_OPC_')

# ---------------------------------------------------------------------------
# ENCODING-QUALIFIED SUB-RULES
# ---------------------------------------------------------------------------
#
# One `case OPC_*` label, several ARCHITECTURAL INSTRUCTIONS, told apart by
# FIXED ENCODING BITS and by nothing else.  MIPS defines its execution hints
# inside the SLL encoding: SLL r0,r0,sa with rs=rt=rd=0 is NOP at sa=0, SSNOP
# at 1, EHB at 3 and PAUSE at 5.  QEMU's switch is on MASK_SPECIAL(), which
# masks those fields off, so all of them arrive at `case OPC_SLL` and the one
# identity cannot say which instruction ran.  The plugin's identity table
# therefore reported the rule QID_SPLIT -- observed decoding to two different
# classifications, deciding neither -- and every instruction through it fell
# back to the Capstone table.
#
# The discriminator here is the INSTRUCTION WORD, never a disassembler's
# spelling: a (mask, value) pair over the encoding, in the shape decodetree
# already publishes for a pattern reached from several rules
# (`decode_insn16/addi@000...........01`).  The base rule's own name and id do
# NOT move -- a form that matches none of the qualifications still reports
# `translate_mips/OPC_SLL`, exactly as it did.  Only the qualified forms get a
# new identity, and that is the deliberate, adjudicated part.
#
# THE COMPLETENESS RULE, and it is why all four hints are listed rather than
# just the one the corpus happened to split on.  Carving `ssnop` out and
# leaving the rest would make the base row claim to be `sll` for encodings
# that are NOT an sll -- an identity answering confidently and wrongly, which
# is worse than the split it replaced.  A rule is qualified for every form the
# architecture defines inside it, or not at all.
#
# Fields: enumerator -> [(mask, value, bits, why), ...].  `bits` is the
# match written out MSB-first with '.' for a don't-care, so the generated name
# reads the same way a decodetree pattern's does.  The generator CHECKS that
# mask/value are consistent with bits and refuses otherwise.
ENCODING_QUALIFIED = {
    'OPC_SLL': [
        (0xffffffff, 0x00000000,
         '00000000000000000000000000000000',
         'NOP -- SLL r0,r0,0'),
        (0xffffffff, 0x00000040,
         '00000000000000000000000001000000',
         'SSNOP -- SLL r0,r0,1'),
        (0xffffffff, 0x000000c0,
         '00000000000000000000000011000000',
         'EHB -- SLL r0,r0,3'),
        (0xffffffff, 0x00000140,
         '00000000000000000000000101000000',
         'PAUSE -- SLL r0,r0,5, and QEMU names this one itself at the '
         'OPC_SLL arm of decode_opc_special'),
    ],
}


def qual_suffix(bits):
    """The identity-name suffix for a qualified form: `@` + its fixed bits."""
    return '@' + bits


def qual_c_ident(name, idx):
    """A C enumerator for a qualified form.

       The bits go in the NAME (which is the identity) and a short ordinal in
       the C identifier: a 32-character bit string makes an unreadable
       enumerator, and the row's comment carries the bits verbatim."""
    return '%s__Q%d' % (name, idx)


def check_qualifications():
    """Refuse a self-inconsistent entry rather than emitting one.

       An entry whose bit string disagrees with its (mask, value) would
       publish an identity naming an encoding it does not match, which is a
       fabricated decode dressed as a finer key."""
    for name, forms in ENCODING_QUALIFIED.items():
        seen = set()
        for (mask, value, bits, why) in forms:
            if len(bits) != 32:
                return '%s: %r is %d bits, not 32' % (name, bits, len(bits))
            m = v = 0
            for ch in bits:
                m <<= 1
                v <<= 1
                if ch == '.':
                    continue
                if ch not in '01':
                    return '%s: %r has a character that is not 0, 1 or .' % (
                        name, bits)
                m |= 1
                v |= int(ch)
            if m != mask or v != (value & mask):
                return ('%s: bits %s say mask=0x%08x value=0x%08x, the entry '
                        'says mask=0x%08x value=0x%08x'
                        % (name, bits, m, v, mask, value & mask))
            if value & ~mask:
                return '%s: value 0x%08x has bits outside its mask' % (
                    name, value)
            if bits in seen:
                return '%s: %s listed twice' % (name, bits)
            seen.add(bits)
    return None


MARK = 'mips_ident(ctx,'
GEN_BY = 'Auto-generated by scripts/mips_ident_instrument.py'
FT_TAG = '  /* mips_ident */'


def fnv1a32(text):
    """FNV-1a 32 of TEXT, with 0 remapped to 1.

       Identical derivation to scripts/decodetree.py's ident_hash(), so
       the two legs of one target agree on how an id is made.  0 is
       reserved by the plugin API for 'no identity recorded'."""
    h = 0x811c9dc5
    for b in text.encode('utf-8'):
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h if h else 1


def strip_for_structure(lines):
    """Blank out comments, string and character literals.

       Returns a parallel list of the same length: index i of the result
       is line i with everything that must not be read as C structure
       removed.  Preprocessor lines are returned blank -- they are
       handled separately -- so that an #if body's braces still count
       (they are real code) but the directive itself never does."""
    out = []
    in_block = False
    for raw in lines:
        s = raw
        res = []
        i = 0
        if in_block:
            end = s.find('*/')
            if end < 0:
                out.append('')
                continue
            s = s[end + 2:]
            in_block = False
        while i < len(s):
            c = s[i]
            if c == '/' and s[i:i + 2] == '/*':
                end = s.find('*/', i + 2)
                if end < 0:
                    in_block = True
                    break
                i = end + 2
                continue
            if c == '/' and s[i:i + 2] == '//':
                break
            if c in '"\'':
                q = c
                i += 1
                while i < len(s):
                    if s[i] == '\\':
                        i += 2
                        continue
                    if s[i] == q:
                        i += 1
                        break
                    i += 1
                continue
            res.append(c)
            i += 1
        line = ''.join(res)
        if line.lstrip().startswith('#'):
            line = ''
        out.append(line)
    return out


CASE_RE = re.compile(r'^\s*case\s+(.+?)\s*:\s*$')
DEFAULT_RE = re.compile(r'^\s*default\s*:\s*$')
SWITCH_RE = re.compile(r'^\s*switch\s*\((.*)\)\s*\{\s*$')


def is_pp(raw):
    return raw.lstrip().startswith('#')


def is_blank_or_comment(raw, clean):
    return clean.strip() == '' and not is_pp(raw)


def label_identity(label):
    """The identity a case label carries, or None.

       `case R6_OPC_LDPC + (1 << 16):` is not a second instruction: the
       addend is immediate bits that landed in the field the switch reads,
       and QEMU's own comment on the group says so ('bits 16 and 17 are
       part of immediate').  The base enumerator is the identity."""
    base = label.split('+')[0].strip()
    if not re.match(r'^[A-Za-z_]\w*$', base):
        return None
    if not base.startswith(OPC_PREFIXES):
        return None
    return base


def scan(lines, clean):
    """Find every case-label group, with the switch it belongs to."""
    depth = 0
    sw = []          # (depth_at_switch, expr, header_line_index)
    groups = []
    i = 0
    n = len(lines)
    while i < n:
        c = clean[i]
        m = SWITCH_RE.match(c)
        if m:
            sw.append((depth, m.group(1).strip(), i))
        if sw and (CASE_RE.match(c) or DEFAULT_RE.match(c)):
            # Consume the maximal run of labels, allowing comments,
            # blank lines and preprocessor directives between them.
            start = i
            labels = []      # (line_index, label_text or None for default)
            last_label = i
            j = i
            while j < n:
                cj = clean[j]
                mj = CASE_RE.match(cj)
                if mj:
                    labels.append((j, mj.group(1).strip()))
                    last_label = j
                    j += 1
                    continue
                if DEFAULT_RE.match(cj):
                    labels.append((j, None))
                    last_label = j
                    j += 1
                    continue
                if is_pp(lines[j]) or is_blank_or_comment(lines[j], cj):
                    j += 1
                    continue
                break
            groups.append({
                'sw_expr': sw[-1][1],
                'sw_line': sw[-1][2],
                'start': start,
                'last_label': last_label,
                'labels': labels,
            })
            i = last_label + 1
            # brace bookkeeping for the consumed label lines is a no-op:
            # a label line has no braces.
            continue
        depth += c.count('{') - c.count('}')
        while sw and depth <= sw[-1][0]:
            sw.pop()
        i += 1
    return groups


def pp_balance(lines, a, b):
    """Net preprocessor conditional depth over lines[a..b] inclusive."""
    d = 0
    for k in range(a, b + 1):
        s = lines[k].lstrip()
        if s.startswith('#if'):
            d += 1
        elif s.startswith('#endif'):
            d -= 1
    return d


def function_of(lines, clean, idx):
    """Name of the top-level function containing line idx (best effort,
       used only for the residue report)."""
    depth = 0
    cur = '<file scope>'
    fn_re = re.compile(r'^(static\s+)?(inline\s+)?[A-Za-z_][\w \*]*?[\s\*]'
                       r'([a-zA-Z_]\w*)\s*\(')
    for k in range(0, idx + 1):
        c = clean[k]
        if depth == 0 and c and not c[0].isspace():
            m = fn_re.match(c)
            if m:
                cur = m.group(3)
        depth += c.count('{') - c.count('}')
    return cur


def pp_depths(lines):
    """Preprocessor conditional depth in effect ON each line."""
    d = 0
    out = []
    for raw in lines:
        t = raw.lstrip()
        if t.startswith('#endif'):
            d -= 1
        out.append(d)
        if t.startswith('#if'):
            d += 1
    return out


def next_label_line(lines, clean, idx):
    """Index of the next case/default label after idx, or None if the
       next significant line is not one."""
    for k in range(idx + 1, len(lines)):
        if is_pp(lines[k]) or is_blank_or_comment(lines[k], clean[k]):
            continue
        if CASE_RE.match(clean[k]) or DEFAULT_RE.match(clean[k]):
            return k
        return None
    return None


def next_is_label(lines, clean, idx):
    """Is the next significant line after idx another case/default label?"""
    for k in range(idx + 1, len(lines)):
        if is_pp(lines[k]) or is_blank_or_comment(lines[k], clean[k]):
            continue
        return bool(CASE_RE.match(clean[k]) or DEFAULT_RE.match(clean[k]))
    return False


def strip_instrumentation(lines):
    """Remove a previous run's inserted calls, restoring pristine source."""
    out = []
    i = 0
    n = len(lines)
    removed = 0
    while i < n:
        if lines[i].lstrip().startswith(MARK):
            j = i
            while j < n and 'MIPS_ID_NONE);' not in lines[j]:
                j += 1
            i = j + 1
            removed += 1
            continue
        if lines[i].endswith(FT_TAG):
            i += 1
            removed += 1
            continue
        out.append(lines[i])
        i += 1
    return out, removed


def build(path_c, path_inc, report):
    bad = check_qualifications()
    if bad is not None:
        print('ERROR: ENCODING_QUALIFIED is self-inconsistent -- %s' % bad,
              file=sys.stderr)
        return 1
    with open(path_c) as f:
        lines = f.read().split('\n')
    lines, removed = strip_instrumentation(lines)
    clean = strip_for_structure(lines)
    ppd = pp_depths(lines)
    groups = scan(lines, clean)

    names = []
    seen = set()
    first_line = {}
    inserts = {}      # last_label_index -> list of output lines
    residue = []
    errors = []

    for g in groups:
        labs = g['labels']
        idents = []
        bad = None
        for (ln, lab) in labs:
            if lab is None:
                bad = 'default:'
                break
            ident = label_identity(lab)
            if ident is None:
                bad = 'non-opcode label %r' % lab
                break
            idents.append((ln, lab, ident))
        if bad is not None:
            residue.append((g, bad))
            continue

        # A label may be guarded by a preprocessor conditional that the
        # rest of its group is not in, and a statement placed inside that
        # conditional would vanish from the build where the OTHER labels
        # live.  So the group is split into RUNS of labels sharing one
        # preprocessor context -- delimited by the directives themselves --
        # and each run gets its own selection, placed after the run's last
        # label, where it is compiled exactly when those labels are.  A
        # balanced group is one run and gets one statement, which is the
        # overwhelmingly common case.
        runs = []
        cur = []
        for k in range(g['start'], g['last_label'] + 1):
            if is_pp(lines[k]):
                if cur:
                    runs.append(cur)
                    cur = []
                continue
            m = CASE_RE.match(clean[k])
            if m:
                cur.append((k, m.group(1).strip()))
        if cur:
            runs.append(cur)
        if not runs:
            errors.append('case group at %s:%d produced no runs'
                          % (path_c, g['start'] + 1))
            continue

        for (ln, _, ident) in idents:
            if ident not in seen:
                seen.add(ident)
                names.append(ident)
                first_line[ident] = ln + 1

        expr = g['sw_expr']
        for run in runs:
            at = run[-1][0]
            lab_ind = re.match(r'^(\s*)', lines[run[0][0]]).group(1)
            indent = lab_ind + '    '
            cont = indent + '    '
            body = ['%s%s' % (indent, MARK)]
            for (_, lab) in run:
                ident = label_identity(lab)
                # An opcode with encoding-qualified sub-rules selects through
                # its generated qualifier, which reads the INSTRUCTION WORD.
                # Same statement, same place, same base identity when nothing
                # matches -- see ENCODING_QUALIFIED.
                pick = ('mips_ident_q_%s(ctx->opcode)' % ident
                        if ident in ENCODING_QUALIFIED else 'MIPS_ID_%s' % ident)
                arm = '%s%s == %s ? %s :' % (cont, expr, lab, pick)
                if len(arm) <= 79:
                    body.append(arm)
                else:
                    body.append('%s%s == %s ?' % (cont, expr, lab))
                    body.append('%s    %s :' % (cont, pick))
            body.append('%sMIPS_ID_NONE);' % cont)
            # The statement just introduced turns what was a bare stack of
            # case labels into a fallthrough that -Wimplicit-fallthrough=2
            # rejects.  QEMU_FALLTHROUGH rather than a comment, because
            # these runs exist precisely BECAUSE a preprocessor directive
            # separates the labels and a directive between the comment and
            # the label defeats the comment form -- the case compiler.h
            # names the attribute for.
            #
            # Which SIDE of that directive the marker goes on is decided by
            # the guard, not by taste.  The marker has to be either
            # immediately before a case label or absent, in EVERY build of
            # this file: put it on the less-guarded side and the build
            # where the guard is false is left with an attribute in front
            # of ordinary code, which is an error.  So it goes adjacent to
            # the boundary on the MORE guarded side.
            nxt = next_label_line(lines, clean, at)
            if nxt is not None:
                if ppd[nxt] > ppd[at]:
                    marker_at = nxt - 1
                    marker_ind = re.match(r'^(\s*)',
                                          lines[nxt]).group(1) + '    '
                else:
                    marker_at = at
                    marker_ind = indent
                    body.append('%sQEMU_FALLTHROUGH;%s' % (marker_ind, FT_TAG))
            inserts.setdefault(at, []).extend(body)
            if nxt is not None and ppd[nxt] > ppd[at]:
                inserts.setdefault(marker_at, []).append(
                    '%sQEMU_FALLTHROUGH;%s' % (marker_ind, FT_TAG))

    if errors:
        for e in errors:
            print('ERROR: %s' % e, file=sys.stderr)
        return 1

    if not names:
        print('ERROR: no opcode case labels found -- the scanner has '
              'stopped matching %s' % path_c, file=sys.stderr)
        return 1

    # Identity table.  A hash collision is fatal: two instructions sharing
    # an id would silently merge in every consumer.
    rows = []
    byhash = {}
    qualified = {}      # base enumerator -> [(c_ident, mask, value, bits, why)]
    for nm in sorted(names):
        qual = 'translate_mips/' + nm
        h = fnv1a32(qual)
        if h in byhash:
            print('ERROR: decode identity hash collision between %s and %s'
                  % (byhash[h], qual), file=sys.stderr)
            return 1
        byhash[h] = qual
        rows.append((nm, qual, h, first_line[nm]))
        # The qualified forms of this rule, if it has any.  They are rows in
        # their own right: same table, same id derivation, name suffixed by
        # the fixed bits that select the form.
        for idx, (mask, value, bits, why) in enumerate(
                ENCODING_QUALIFIED.get(nm, [])):
            cid = qual_c_ident(nm, idx)
            qname = qual + qual_suffix(bits)
            qh = fnv1a32(qname)
            if qh in byhash:
                print('ERROR: decode identity hash collision between %s and %s'
                      % (byhash[qh], qname), file=sys.stderr)
                return 1
            byhash[qh] = qname
            rows.append((cid, qname, qh, first_line[nm]))
            qualified.setdefault(nm, []).append((cid, mask, value, bits, why))
    for nm in ENCODING_QUALIFIED:
        if nm not in qualified:
            print('ERROR: ENCODING_QUALIFIED names %s, which is not a case '
                  'label this decoder switches on -- a qualification with no '
                  'rule to qualify is a stale entry, not a no-op' % nm,
                  file=sys.stderr)
            return 1

    with open(path_inc, 'w') as f:
        f.write('/*\n'
                ' * %s -- do not edit.\n'
                ' *\n'
                ' * QEMU\'s own identity for each opcode the hand-written MIPS\n'
                ' * decoder switches on, handed to plugins by\n'
                ' * plugin_gen_record_insn_identity().  The name is qualified by\n'
                ' * the decoder so it does not collide with a decodetree pattern\n'
                ' * name from the same target; the id is FNV-1a 32 of that name,\n'
                ' * which is the derivation scripts/decodetree.py uses, so both\n'
                ' * legs of this target make an id the same way.\n'
                ' */\n\n' % GEN_BY)
        f.write('typedef enum {\n')
        f.write('    MIPS_ID_NONE = 0,\n')
        for (nm, _, _, _) in rows:
            f.write('    MIPS_ID_%s,\n' % nm)
        f.write('    MIPS_ID_FAULTED = 0xffff,\n')
        f.write('} MipsIdent;\n\n')
        f.write('static const struct {\n'
                '    uint32_t id;\n'
                '    const char *name;\n'
                '} mips_ident_tab[] = {\n')
        f.write('    { 0, NULL },\n')
        base = os.path.basename(path_c)
        for (nm, qual, h, ln) in rows:
            if '@' in qual:
                # A qualified name is 55 characters of identity; the row plus
                # a trailing provenance comment does not fit 80 columns, so
                # the provenance goes above it rather than off the edge.
                f.write('    /* %s:%d */\n    { 0x%08xu, "%s" },\n'
                        % (base, ln, h, qual))
            else:
                f.write('    { 0x%08xu, "%s" },  /* %s:%d */\n'
                        % (h, qual, base, ln))
        f.write('};\n')
        if qualified:
            f.write('\n/*\n'
                    ' * ENCODING-QUALIFIED SUB-RULES.  One case label, several\n'
                    ' * architectural instructions, told apart by fixed encoding\n'
                    ' * bits -- MIPS puts its execution hints inside the SLL\n'
                    ' * encoding, and MASK_SPECIAL() masks the deciding fields\n'
                    ' * off before the switch sees them.  The discriminator is\n'
                    ' * the instruction word and nothing else; an encoding that\n'
                    ' * matches no qualification keeps the base rule\'s own\n'
                    ' * identity, unchanged.\n'
                    ' */\n')
            for nm in sorted(qualified):
                f.write('static inline MipsIdent mips_ident_q_%s(uint32_t insn)'
                        '\n{\n' % nm)
                for (cid, mask, value, bits, why) in qualified[nm]:
                    for line in textwrap.wrap(why, 68):
                        f.write('    /* %s */\n' % line)
                    f.write('    if ((insn & 0x%08xu) == 0x%08xu) {\n'
                            '        return MIPS_ID_%s;\n'
                            '    }\n' % (mask, value, cid))
                f.write('    return MIPS_ID_%s;\n}\n' % nm)

    # Emit the instrumented translate.c.
    out = []
    for i, l in enumerate(lines):
        out.append(l)
        if i in inserts:
            out.extend(inserts[i])
    with open(path_c, 'w') as f:
        f.write('\n'.join(out))

    with open(report, 'w') as f:
        f.write('mips_ident_instrument residue report\n')
        f.write('====================================\n\n')
        f.write('source           : %s\n' % path_c)
        f.write('previous inserts stripped: %d\n' % removed)
        f.write('case groups seen : %d\n' % len(groups))
        f.write('groups exported  : %d\n' % len(inserts))
        f.write('case labels      : %d\n'
                % sum(len(g['labels']) for g in groups))
        f.write('opcode labels    : %d\n'
                % sum(len(g['labels']) for g in groups
                      if all(lab and label_identity(lab)
                             for (_, lab) in g['labels'])))
        f.write('distinct opcodes : %d\n\n' % len(rows))
        f.write('NOT exported -- every one, by line, for review\n')
        f.write('---------------------------------------------\n')
        for (g, why) in residue:
            fn = function_of(lines, clean, g['start'])
            f.write('%s:%d  in %s  switch (%s)  -- %s\n'
                    % (os.path.basename(path_c), g['start'] + 1, fn,
                       g['sw_expr'], why))
        f.write('\ndistinct opcode identities exported\n')
        f.write('-----------------------------------\n')
        for (nm, qual, h, ln) in rows:
            f.write('0x%08x  %s  (%s:%d)\n'
                    % (h, qual, os.path.basename(path_c), ln))

    print('instrumented %d case groups, %d distinct identities'
          % (len(inserts), len(rows)))
    print('residue: %d groups not exported (see %s)' % (len(residue), report))
    return 0


def main():
    ap = argparse.ArgumentParser()
    paths = ident_instrument_paths.Paths(__file__)
    paths.add_input(ap, '--source', 'target/mips/tcg/translate.c')
    paths.add_output(ap, '--table', 'target/mips/tcg/translate_ident.c.inc')
    paths.add_output(ap, '--report',
                     'contrib/plugins/champsim_tracer/tools/arc3_qemuid/'
                     'MIPS_IDENT_RESIDUE.txt')
    paths.install(ap)
    return ident_instrument_paths.main_wrapper(
        paths, ap, lambda a, v: build(v[0], v[1], v[2]))


if __name__ == '__main__':
    sys.exit(main())
