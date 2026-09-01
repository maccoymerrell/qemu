#!/usr/bin/env python3
#
# Qualify the i386 reserved-NOP row that carries the CET instructions.
#
# THE PROBLEM.  QEMU does not model CET, so it decodes `endbr64`,
# `endbr32` and `rdsspd/rdsspq` through the reserved-NOP row of its 0F
# table -- one X86_OP_* site, one __LINE__ slot, one identity:
#
#     decode-new.c.inc:1355  [0x1e] = X86_OP_ENTRY1(NOP,  nop,v)
#
#     champsim_tracer_qemu_ident_x86.h
#       { 0x0000054bu, "NOP", QID_ADJUDICATED, ...
#         /* ADJUDICATED from GEN_OP_NOP <- endbr64, nop;
#            GEN_OP_MOV <- rdsspq */
#
# Those are different instructions.  `endbr64` reads nothing; `rdsspq`
# reads the shadow-stack pointer and writes it to a general register --
# the wire publishes REG_SSP as its source, and XED and PIN agree that
# the FORM reads SSP whatever the machine's CET state is (R16).  With
# one identity for both, a row keyed on it fires on every `endbr64` in
# the program: 228 of them in the w19 x86 corpus against one `rdsspq`.
# tools/gen_src_survivors.py measures exactly that and REFUSES the row,
# saying so on its own face -- "it stays in the loss direction and
# blocks the flip until the id is qualified".
#
# The discriminator is not missing.  All three encodings are F3 0F 1E
# plus a modrm byte, and `s->prefix` and `s->modrm` are both facts the
# DisasContext holds before the row is published:
#
#     F3 0F 1E FA        endbr64
#     F3 0F 1E FB        endbr32
#     F3 0F 1E /1 mod=11 rdsspd / rdsspq
#
# WHAT THIS SCRIPT DOES, in the shape scripts/x86_x87_ident_instrument.py
# and scripts/x86_vex_ident_instrument.py established:
#
#   * it finds the reserved-NOP site the CET encodings reach -- by the
#     table INDEX and the mnemonic, read out of decode-new.c.inc, never
#     by a line number written down here -- and refuses unless there is
#     exactly one;
#
#   * it emits target/i386/tcg/cet_ident.c.inc: three identity rows for
#     that site, named in the x87 leg's `@bits` form,
#     `decode-new/NOP@f3=1,modrm=<8 bits>`, MSB first and '.' for a bit
#     the arm does not read;
#
#   * THE NAME IS NOT UNIQUE AND THE ID IS.  QEMU's table names a row for
#     the generator it dispatches to and 472 of the 854 base slots
#     already share a name, so the id is FNV-1a-32 -- the derivation
#     scripts/decodetree.py, the MIPS leg, the x87 leg and the VEX leg
#     all use -- of the name with the base slot appended,
#     `decode-new/NOP@f3=1,modrm=11111010#1355`, printed beside each row
#     so it can be recomputed by hand;
#
#   * it inserts ONE call into decode-new.c.inc, below the unconditional
#     publish and below every X86_OP_* site in the file, so no slot is
#     renumbered -- and REFUSES if that ever stops being true;
#
#   * THE BASE ROW DOES NOT MOVE.  An encoding that reaches no arm --
#     every plain reserved NOP, and every `0F 1E` without F3 -- publishes
#     nothing here and keeps the row's own id and name bit for bit.
#
#   * it checks the selector EXHAUSTIVELY over the WHOLE (slot, f3,
#     modrm) space -- every __LINE__ the file can hand out, times two
#     prefix states, times all 256 modrm bytes -- and reports the
#     residual as well as the hits, because a selector that answered for
#     everything would pass a hits-only check.
#
# Author: Maccoy Merrell.
import argparse
import re
import sys

SLOT_RE = re.compile(
    r'\bX86_OP_(ENTRY[0-4rw]{0,2}|GROUP[0-3rw]{0,2}|LEAF|SET_GEN)'
    r'\s*\(\s*([A-Za-z0-9_]+)\s*(?:,\s*([A-Za-z0-9_]+))?')

# The site the CET encodings reach, identified by what the TABLE says:
# entry index 0x1e of a table whose row names the NOP generator.
SUBJECT_RE = re.compile(r'^\s*\[0x1[eE]\]\s*=\s*X86_OP_ENTRY1\(NOP,')

PUBLISH_RE = re.compile(r'^\s*vex_ident_publish\(decode\.e\.slot,')

TAG = '/* cet_ident */'
# Two lines, because one would run past the 80-column limit.  The tag is
# on the LAST line so strip_instrumentation() removes the pair as a unit.
CALL = ('    cet_ident_publish(decode.e.slot,\n'
        '                      (s->prefix & PREFIX_REPZ) != 0, s->modrm);'
        '  ' + TAG)

# (mask, value, spelling, what it is).  MASK/VALUE over the modrm byte;
# an arm is reached only with the F3 prefix, which is what makes these
# the CET encodings rather than reserved NOPs.
ARMS = (
    (0xff, 0xfa, 'endbr64',
     'F3 0F 1E FA -- terminate an indirect branch, 64-bit'),
    (0xff, 0xfb, 'endbr32',
     'F3 0F 1E FB -- terminate an indirect branch, 32-bit'),
    (0xf8, 0xc8, 'rdssp',
     'F3 0F 1E /1 mod=11 -- read the shadow-stack pointer into a GPR;'
     ' rdsspd and rdsspq differ by REX.W alone and read the same'
     ' register, so operand size is not a discriminator here'),
)


def fnv1a32(text):
    """FNV-1a 32 of TEXT, with 0 remapped to 1.

       Identical derivation to scripts/decodetree.py's ident_hash() and to
       the x87 and VEX legs, so every identity in this tree is made the
       same way.  0 is reserved by the plugin API for 'no identity'."""
    h = 0x811c9dc5
    for byte in text.encode('utf-8'):
        h = ((h ^ byte) * 0x01000193) & 0xffffffff
    return h if h else 1


def bits_name(mask, value):
    """The 8 modrm bits, MSB first, '.' where the arm does not look."""
    return ''.join('.' if not (mask >> b) & 1 else str((value >> b) & 1)
                   for b in range(7, -1, -1))


def scan_slots(lines):
    """Every X86_OP_* site as (slot, name).  Macro DEFINITIONS expand the
       macros inside themselves and are skipped, exactly as the plugin's
       identity generator skips them."""
    out, in_define = [], False
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
            out.append((lineno,
                        m.group(3) if kind == 'SET_GEN' else m.group(2)))
    return out


def strip_instrumentation(lines):
    out, removed, pend = [], 0, []
    for l in lines:
        if 'cet_ident_publish(' in l or (pend and l.rstrip().endswith(TAG)):
            pend.append(l)
            if l.rstrip().endswith(TAG):
                removed += 1
                pend = []
            continue
        out.extend(pend)
        pend = []
        out.append(l)
    out.extend(pend)
    return out, removed


def check_exhaustive(slots, n_lines):
    """Every (slot, f3, modrm) in the whole space, against the emitted
       selector's own model.  Reports hits AND residual."""
    hits = residual = 0
    reached = {}
    for slot in range(1, n_lines + 2):
        for f3 in (0, 1):
            for modrm in range(256):
                idx = 0
                if slot in slots and f3:
                    for i, (mask, value, _, _) in enumerate(ARMS, 1):
                        if modrm & mask == value:
                            if idx:
                                return None, ('slot %d f3=%d modrm=0x%02x '
                                              'reaches rows %d and %d'
                                              % (slot, f3, modrm, idx, i))
                            idx = i
                if idx:
                    hits += 1
                    reached.setdefault(idx, 0)
                    reached[idx] += 1
                else:
                    residual += 1
    if len(reached) != len(ARMS):
        return None, ('only %d of %d arms is reachable'
                      % (len(reached), len(ARMS)))
    return (hits, residual, reached), None


def build(path_dec, path_out, report):
    with open(path_dec) as f:
        src = f.read().split('\n')
    src, removed = strip_instrumentation(src)

    sites = dict(scan_slots(src))
    subject = [n for n, l in enumerate(src, 1) if SUBJECT_RE.match(l)]
    if len(subject) != 1:
        print('ERROR: expected exactly one [0x1e] NOP site, found %d'
              % len(subject), file=sys.stderr)
        return 1
    slot = subject[0]
    if sites.get(slot) != 'NOP':
        print('ERROR: line %d is not an X86_OP_* NOP site' % slot,
              file=sys.stderr)
        return 1

    max_site = max(sites)
    pub = [n for n, l in enumerate(src, 1) if PUBLISH_RE.match(l)]
    if len(pub) != 1:
        print('ERROR: expected exactly one publish site, found %d' % len(pub),
              file=sys.stderr)
        return 1
    if pub[0] <= max_site:
        print('ERROR: the insertion point (line %d) is at or above the last '
              'X86_OP_* site (line %d); inserting there would renumber slots'
              % (pub[0], max_site), file=sys.stderr)
        return 1

    rows = []
    for mask, value, spell, why in ARMS:
        name = 'decode-new/NOP@f3=1,modrm=%s' % bits_name(mask, value)
        rows.append((name, fnv1a32('%s#%d' % (name, slot)), spell, why,
                     mask, value))

    ids = [r[1] for r in rows]
    if len(set(ids)) != len(ids):
        print('ERROR: two arms hash to the same id', file=sys.stderr)
        return 1

    got, err = check_exhaustive({slot}, len(src))
    if err:
        print('ERROR: ' + err, file=sys.stderr)
        return 1
    hits, residual, reached = got

    out = []
    w = out.append
    w('/*')
    w(' * Auto-generated by scripts/x86_cet_ident_instrument.py -- do not'
      ' edit.')
    w(' *')
    w(' * QEMU does not model CET, so `endbr64`, `endbr32` and')
    w(' * `rdsspd`/`rdsspq` are all decoded through the RESERVED')
    w(' * NOP row of the 0F table -- one slot, one identity, for')
    w(' * instructions that do not read the same registers.  A')
    w(' * consumer keyed on that identity cannot tell the one')
    w(' * that reads the shadow-stack pointer from the ones that')
    w(' * read nothing, and a row keyed on it fires on every')
    w(' * `endbr64` in the program.')
    w(' *')
    w(' * The discriminator is not missing: all three are F3 0F 1E')
    w(' * plus a modrm byte, and decode_insn() has both facts')
    w(' * before the row is published.  These rows carry them into')
    w(' * the identity.')
    w(' *')
    w(' * The name is `decode-new/NOP@f3=1,modrm=<bits>`: the 8')
    w(' * modrm bits, MSB first, \'.\' for a bit the arm does not')
    w(' * read, in the same `@`-suffixed form the x87 leaf rows')
    w(' * use.  The id is FNV-1a 32 of that name with the base')
    w(' * slot appended -- the derivation scripts/decodetree.py')
    w(' * uses -- so a qualified id is exactly as stable as the')
    w(' * base id it folds, and no more.')
    w(' *')
    w(' * THE BASE ROW DOES NOT MOVE.  decode-new.c.inc is not')
    w(' * edited apart from the one inserted call, which sits')
    w(' * below every X86_OP_* site in the file (last site line')
    w(' * %d, call line %d) so no slot is renumbered.  An encoding'
      % (max_site, pub[0]))
    w(' * that reaches no arm -- every plain reserved NOP, and')
    w(' * every 0F 1E without F3 -- publishes nothing here and')
    w(' * keeps the row\'s own id and name bit for bit.')
    w(' *')
    w(' * EXHAUSTIVE, not sampled: %d (slot, f3, modrm) triples --' % (hits +
                                                                       residual))
    w(' * every __LINE__ this file can hand out, times both prefix')
    w(' * states, times all 256 modrm bytes -- checked against the')
    w(' * selector below.  %d reach a qualified identity, %d do' % (hits,
                                                                    residual))
    w(' * not, no triple reaches two, and every arm is reachable.')
    w(' */')
    w('')
    w('static const struct {')
    w('    uint32_t id;')
    w('    const char *name;')
    w('} cet_ident_tab[] = {')
    w('    { 0, NULL },')
    for name, ident, spell, why, mask, value in rows:
        # The PROVENANCE line sits directly above the row and names the
        # base slot, in the form the plugin's identity generator reads
        # (champsim_tracer_mnemonic_audit.py: IDENT_PROV_RE).  A row it
        # cannot read is a row invisible to the universe, which reports
        # as 'this rule was never qualified'.
        w('    /* %s: %s; FNV-1a-32 of "%s#%d" */' % (spell, why, name, slot))
        # The WORD rides on the provenance line the plugin's identity
        # generator reads.  QEMU has no word for these encodings at all --
        # not modelling CET is the whole reason this table exists -- so
        # the arm's own name is the only one there is, and leaving it in
        # prose would make the qualified row state the reserved NOP the
        # base row states and undo the carve.
        w('    /* decode-new.c.inc:%d word=%s(arm) */' % (slot, spell))
        w('    { 0x%08xu, "%s" },' % (ident, name))
    w('};')
    w('')
    w('/* The site the CET encodings reach: decode-new.c.inc:%d,' % slot)
    w(' * [0x1e] = X86_OP_ENTRY1(NOP, nop,v). */')
    w('#define CET_IDENT_SLOT %du' % slot)
    w('')
    w('static const struct {')
    w('    uint8_t mask;')
    w('    uint8_t value;')
    w('    uint16_t idx;')
    w('} cet_ident_arms[] = {')
    for i, (name, ident, spell, why, mask, value) in enumerate(rows, 1):
        w('    { 0x%02x, 0x%02x, %d },   /* %s */' % (mask, value, i, spell))
    w('};')
    w('')
    w('static inline uint16_t cet_ident_of(uint32_t slot, bool repz,')
    w('                                    uint8_t modrm)')
    w('{')
    w('    if (slot != CET_IDENT_SLOT || !repz) {')
    w('        return 0;')
    w('    }')
    w('    for (size_t i = 0; i < ARRAY_SIZE(cet_ident_arms); i++) {')
    w('        if ((modrm & cet_ident_arms[i].mask)'
      ' == cet_ident_arms[i].value) {')
    w('            return cet_ident_arms[i].idx;')
    w('        }')
    w('    }')
    w('    return 0;')
    w('}')
    w('')
    w('/*')
    w(' * Publish the encoding-qualified identity for an encoding')
    w(' * that has one.  An encoding that has none publishes')
    w(' * nothing and keeps what the unconditional publish above')
    w(' * recorded.')
    w(' */')
    w('static inline void cet_ident_publish(uint32_t slot, bool repz,')
    w('                                     uint8_t modrm)')
    w('{')
    w('    uint16_t idx = cet_ident_of(slot, repz, modrm);')
    w('')
    w('    if (idx) {')
    w('        plugin_gen_record_insn_identity(cet_ident_tab[idx].id,')
    w('                                        cet_ident_tab[idx].name);')
    w('    }')
    w('}')
    w('')
    with open(path_out, 'w') as f:
        f.write('\n'.join(out))

    for i, line in enumerate(CALL.split('\n')):
        src.insert(pub[0] + i, line)
    with open(path_dec, 'w') as f:
        f.write('\n'.join(src))

    if report:
        print('cet_ident: slot %d, %d arm(s); %d triples checked, %d '
              'qualified, %d residual; call at line %d, last site %d; '
              '%d stale call(s) removed'
              % (slot, len(rows), hits + residual, hits, residual,
                 pub[0], max_site, removed))
        for name, ident, spell, why, mask, value in rows:
            print('  0x%08x  %-38s %-8s %d encoding(s)'
                  % (ident, name, spell, reached[
                      [r[0] for r in rows].index(name) + 1]))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--decode', default='target/i386/tcg/decode-new.c.inc')
    ap.add_argument('-o', default='target/i386/tcg/cet_ident.c.inc')
    ap.add_argument('-q', action='store_true')
    a = ap.parse_args()
    return build(a.decode, a.o, not a.q)


if __name__ == '__main__':
    sys.exit(main())
