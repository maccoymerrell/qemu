#!/usr/bin/env python3
#
# Qualify the two i386 NOP rows that carry the PREFETCH instructions.
#
# THE PROBLEM.  QEMU models no cache, so it generates nothing for a
# prefetch -- and it therefore decodes the whole SSE prefetch group and
# the whole 3DNow! prefetch group through rows it NAMES `NOP`:
#
#     decode-new.c.inc  [0x0d] = X86_OP_ENTRY1(NOP,  M,v)    3DNow! prefetch
#     decode-new.c.inc  [0x18] = X86_OP_ENTRY1(NOP,  nop,v)  SSE prefetch
#
# Two X86_OP_* sites, two __LINE__ slots, two identities -- for eleven
# architecturally distinct instructions plus the reserved NOPs beside
# them.  `prefetchnta`, `prefetcht0`, `prefetcht1`, `prefetcht2`,
# `prefetch`, `prefetchw` and `prefetchwt1` are ISA-defined memory hints
# with an address operand; the reserved encodings that share the [0x18]
# row are not.  With one identity for all of them a consumer keyed on it
# can only say `NOP`, which is the class of the reserved forms and the
# class of none of the hints.
#
# THE ROW'S NAME IS A LOWERING FACT, AND R16 FORBIDS ONE ON THE WIRE.
# QEMU spells the rule NOP because gen_NOP emits no code, which is a
# statement about the emulator, not about the architecture.  The ISA
# defines the hint and names its operand; the trace records what the ISA
# defines.  (The same principle, on the register side, is 391e65d07f.)
#
# THE DISCRIMINATOR IS NOT MISSING.  Both groups are ModRM group opcodes
# and the reg field is the whole selector, exactly as the SDM and the APM
# write them:
#
#     0F 18 /0  PREFETCHNTA m8      0F 0D /0  PREFETCH  m8
#     0F 18 /1  PREFETCHT0  m8      0F 0D /1  PREFETCHW m8
#     0F 18 /2  PREFETCHT1  m8      0F 0D /2  PREFETCHWT1 m8
#     0F 18 /3  PREFETCHT2  m8
#     0F 18 /4../7            reserved NOP -- NOT a hint
#
# and `s->modrm` is a fact decode_insn() holds before the row is
# published.  The memory form is part of the definition: every one of
# these is defined on m8, and `0F 18` with mod=11 is a reserved NOP that
# binutils and Capstone both name `nop`.  The [0x0d] row's own operand
# template already refuses mod=11 (X86_TYPE_M returns false, so the
# encoding faults and never reaches the publish); the [0x18] row's `nop`
# template does not, so the arms carry the mod test themselves.
#
# WHAT THIS SCRIPT DOES, in the shape scripts/x86_x87_ident_instrument.py,
# scripts/x86_vex_ident_instrument.py and scripts/x86_cet_ident_instrument.py
# established:
#
#   * it finds the two subject sites -- by the table INDEX and the macro
#     form read out of decode-new.c.inc, never by a line number written
#     down here -- and refuses unless there is exactly one of each;
#
#   * it emits target/i386/tcg/prefetch_ident.c.inc: one identity row per
#     arm, named in the x87 leg's `@bits` form,
#     `decode-new/NOP@0f18,mod!=11,modrm=<8 bits>`, MSB first and '.' for
#     a bit the arm does not read;
#
#   * THE NAME IS NOT UNIQUE AND THE ID IS.  The id is FNV-1a-32 -- the
#     derivation scripts/decodetree.py, the MIPS leg, the x87 leg, the VEX
#     leg and the CET leg all use -- of the name with the base slot
#     appended, printed beside each row so it can be recomputed by hand;
#
#   * it inserts ONE call into decode-new.c.inc, below the unconditional
#     publish and below every X86_OP_* site in the file, so no slot is
#     renumbered -- and REFUSES if that ever stops being true;
#
#   * THE BASE ROWS DO NOT MOVE.  An encoding that reaches no arm -- every
#     reserved NOP of the [0x18] group, every mod=11 form, and every
#     ModRM.reg value the references do not define -- publishes nothing
#     here and keeps its row's own id and name bit for bit;
#
#   * it checks the selector EXHAUSTIVELY over the WHOLE (slot, modrm)
#     space -- every __LINE__ the file can hand out, times all 256 modrm
#     bytes -- and reports the residual as well as the hits, because a
#     selector that answered for everything would pass a hits-only check.
#
# THE RESERVED ModRM.reg VALUES ARE LEFT UNQUALIFIED, DELIBERATELY.  The
# AMD APM aliases 0F 0D /2../7 to PREFETCH and binutils disassembles them
# that way; Capstone 6.0.0-Alpha7 decodes /0, /1 and /2 and rejects /3../7
# outright.  An arm for /3../7 would state a hint the decoder this tree
# links against does not name, so those encodings keep the base NOP row
# and the disagreement is recorded here rather than resolved by guess.
#
# Author: Maccoy Merrell.
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ident_instrument_paths  # noqa: E402  (path fixed up just above)

SLOT_RE = re.compile(
    r'\bX86_OP_(ENTRY[0-4rw]{0,2}|GROUP[0-3rw]{0,2}|LEAF|SET_GEN)'
    r'\s*\(\s*([A-Za-z0-9_]+)\s*(?:,\s*([A-Za-z0-9_]+))?')

# The two sites, identified by what the TABLE says: the entry index and
# the operand template of the row, not a remembered line number.  The
# template is part of the key because [0x19], [0x1c], [0x1d], [0x1e] and
# [0x1f] are all `X86_OP_ENTRY1(NOP, nop,v)` too and only the index tells
# the prefetch group from the reserved rows beside it.
SUBJECTS = (
    ('0f0d', re.compile(r'^\s*\[0x0[dD]\]\s*=\s*X86_OP_ENTRY1\(NOP,\s*M,v\)'),
     '[0x0d] = X86_OP_ENTRY1(NOP, M,v), the 3DNow! prefetch group'),
    ('0f18', re.compile(r'^\s*\[0x18\]\s*=\s*X86_OP_ENTRY1\(NOP,\s*nop,v\)'),
     '[0x18] = X86_OP_ENTRY1(NOP, nop,v), the SSE prefetch group'),
)

PUBLISH_RE = re.compile(r'^\s*cet_ident_publish\(decode\.e\.slot,')

TAG = '/* prefetch_ident */'
# Two lines, because one would run past the 80-column limit.  The tag is
# on the LAST line so strip_instrumentation() removes the pair as a unit.
CALL = ('    prefetch_ident_publish(decode.e.slot, s->modrm);'
        '  ' + TAG)

# (subject, mask, value, spelling, what it is).  MASK/VALUE over the
# ModRM.reg field.  Every arm is defined on a memory operand, so every
# arm is also gated on mod != 11; see MEM_ONLY below.
ARMS = (
    ('0f0d', 0x38, 0x00, 'prefetch',
     '0F 0D /0 m8 -- AMD 3DNow! prefetch, read-intent'),
    ('0f0d', 0x38, 0x08, 'prefetchw',
     '0F 0D /1 m8 -- prefetch with intent to write'),
    ('0f0d', 0x38, 0x10, 'prefetchwt1',
     '0F 0D /2 m8 -- prefetch with intent to write, T1 hint'),
    ('0f18', 0x38, 0x00, 'prefetchnta',
     '0F 18 /0 m8 -- non-temporal hint'),
    ('0f18', 0x38, 0x08, 'prefetcht0',
     '0F 18 /1 m8 -- temporal hint, all cache levels'),
    ('0f18', 0x38, 0x10, 'prefetcht1',
     '0F 18 /2 m8 -- temporal hint, level 2 and higher'),
    ('0f18', 0x38, 0x18, 'prefetcht2',
     '0F 18 /3 m8 -- temporal hint, level 3 and higher'),
)

# Every arm is defined on m8, so mod=11 reaches none of them.  It is
# stated once here rather than per arm because it is one architectural
# fact about the whole group, and a per-arm flag would let a future edit
# make one arm disagree with the reference the rest are read from.
MEM_ONLY = True


def fnv1a32(text):
    """FNV-1a 32 of TEXT, with 0 remapped to 1.

       Identical derivation to scripts/decodetree.py's ident_hash() and to
       the x87, VEX and CET legs, so every identity in this tree is made
       the same way.  0 is reserved by the plugin API for 'no identity'."""
    h = 0x811c9dc5
    for byte in text.encode('utf-8'):
        h = ((h ^ byte) * 0x01000193) & 0xffffffff
    return h if h else 1


def bits_name(mask, value):
    """The 8 modrm bits, MSB first, '.' where the arm does not look."""
    return ''.join('.' if not (mask >> b) & 1 else str((value >> b) & 1)
                   for b in range(7, -1, -1))


def arm_name(subject, mask, value):
    return 'decode-new/NOP@%s,mod!=11,modrm=%s' % (subject,
                                                   bits_name(mask, value))


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
        if 'prefetch_ident_publish(' in l or (pend
                                              and l.rstrip().endswith(TAG)):
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


def check_exhaustive(slot_of, n_lines):
    """Every (slot, modrm) in the whole space, against the emitted
       selector's own model.  Reports hits AND residual."""
    hits = residual = 0
    reached = {}
    by_slot = {}
    for subject, slot in slot_of.items():
        by_slot.setdefault(slot, subject)
    if len(by_slot) != len(slot_of):
        return None, 'two subjects resolved to one slot'
    for slot in range(1, n_lines + 2):
        for modrm in range(256):
            idx = 0
            subject = by_slot.get(slot)
            if subject is not None and not (MEM_ONLY and (modrm >> 6) == 3):
                for i, (sub, mask, value, _, _) in enumerate(ARMS, 1):
                    if sub == subject and modrm & mask == value:
                        if idx:
                            return None, ('slot %d modrm=0x%02x reaches rows '
                                          '%d and %d' % (slot, modrm, idx, i))
                        idx = i
            if idx:
                hits += 1
                reached[idx] = reached.get(idx, 0) + 1
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
    slot_of = {}
    for subject, rx, what in SUBJECTS:
        found = [n for n, l in enumerate(src, 1) if rx.match(l)]
        if len(found) != 1:
            print('ERROR: expected exactly one %s site, found %d'
                  % (what, len(found)), file=sys.stderr)
            return 1
        if sites.get(found[0]) != 'NOP':
            print('ERROR: line %d is not an X86_OP_* NOP site' % found[0],
                  file=sys.stderr)
            return 1
        slot_of[subject] = found[0]

    max_site = max(sites)
    pub = [n for n, l in enumerate(src, 1) if PUBLISH_RE.match(l)]
    if len(pub) != 1:
        print('ERROR: expected exactly one cet_ident publish site, found %d'
              % len(pub), file=sys.stderr)
        return 1
    # The CET call is two source lines; the insertion goes after the
    # SECOND, which is the one carrying its tag.
    ins = pub[0]
    while ins < len(src) and '/* cet_ident */' not in src[ins - 1]:
        ins += 1
    if ins > len(src):
        print('ERROR: the cet_ident call is not terminated by its tag',
              file=sys.stderr)
        return 1
    if ins <= max_site:
        print('ERROR: the insertion point (line %d) is at or above the last '
              'X86_OP_* site (line %d); inserting there would renumber slots'
              % (ins, max_site), file=sys.stderr)
        return 1

    rows = []
    for subject, mask, value, spell, why in ARMS:
        slot = slot_of[subject]
        name = arm_name(subject, mask, value)
        rows.append((name, fnv1a32('%s#%d' % (name, slot)), spell, why,
                     subject, slot, mask, value))

    ids = [r[1] for r in rows]
    if len(set(ids)) != len(ids):
        print('ERROR: two arms hash to the same id', file=sys.stderr)
        return 1

    got, err = check_exhaustive(slot_of, len(src))
    if err:
        print('ERROR: ' + err, file=sys.stderr)
        return 1
    hits, residual, reached = got

    out = []
    w = out.append
    w('/*')
    w(' * Auto-generated by scripts/x86_prefetch_ident_instrument.py --'
      ' do not edit.')
    w(' *')
    w(' * QEMU models no cache, so every PREFETCH is decoded')
    w(' * through a row it NAMES `NOP` -- [0x0d] for the 3DNow!')
    w(' * group and [0x18] for the SSE group.  Two slots, two')
    w(' * identities, for seven architecturally distinct memory')
    w(' * hints and the reserved NOPs beside them.  A consumer')
    w(' * keyed on those identities can only say NOP, which is')
    w(' * the class of the reserved forms and of none of the')
    w(' * hints.')
    w(' *')
    w(' * THE ROW NAME IS A LOWERING FACT.  `NOP` is what gen_NOP')
    w(' * emits, not what the instruction is: PREFETCHNTA is an')
    w(' * ISA-defined hint with an m8 operand whether or not the')
    w(' * emulator has a cache to prefetch into.  R16 keeps the')
    w(' * lowering off the wire; these rows keep the ISA on it.')
    w(' *')
    w(' * The discriminator is not missing: both groups select on')
    w(' * ModRM.reg, and every arm is defined on a memory operand,')
    w(' * so mod=11 reaches none of them.  decode_insn() holds')
    w(' * s->modrm before the row is published.')
    w(' *')
    w(' * The name is `decode-new/NOP@<opcode>,mod!=11,modrm=<bits>`:')
    w(' * the 8 modrm bits, MSB first, \'.\' for a bit the arm does')
    w(' * not read, in the same `@`-suffixed form the x87 leaf rows')
    w(' * use.  The id is FNV-1a 32 of that name with the base slot')
    w(' * appended -- the derivation scripts/decodetree.py uses --')
    w(' * so a qualified id is exactly as stable as the base id it')
    w(' * folds, and no more.')
    w(' *')
    w(' * THE BASE ROWS DO NOT MOVE.  decode-new.c.inc is not')
    w(' * edited apart from the one inserted call, which sits below')
    w(' * every X86_OP_* site in the file (last site line %d, call'
      % max_site)
    w(' * line %d) so no slot is renumbered.  An encoding that' % ins)
    w(' * reaches no arm -- every reserved NOP of the [0x18] group,')
    w(' * every mod=11 form -- publishes nothing here and keeps the')
    w(' * row\'s own id and name bit for bit.')
    w(' *')
    w(' * THE RESERVED ModRM.reg VALUES ARE LEFT UNQUALIFIED.  The')
    w(' * AMD APM aliases 0F 0D /2../7 to PREFETCH and binutils')
    w(' * disassembles them so; Capstone 6.0.0-Alpha7 decodes /0,')
    w(' * /1 and /2 and rejects /3../7.  An arm for /3../7 would')
    w(' * state a hint the decoder this tree links against does not')
    w(' * name, so those encodings keep the base NOP row.')
    w(' *')
    w(' * EXHAUSTIVE, not sampled: %d (slot, modrm) pairs -- every'
      % (hits + residual))
    w(' * __LINE__ this file can hand out, times all 256 modrm')
    w(' * bytes -- checked against the selector below.  %d reach a' % hits)
    w(' * qualified identity, %d do not, no pair reaches two, and' % residual)
    w(' * every arm is reachable.')
    w(' */')
    w('')
    w('static const struct {')
    w('    uint32_t id;')
    w('    const char *name;')
    w('} prefetch_ident_tab[] = {')
    w('    { 0, NULL },')
    for name, ident, spell, why, subject, slot, mask, value in rows:
        # The PROVENANCE line sits directly above the row and names the
        # base slot, in the form the plugin's identity generator reads
        # (champsim_tracer_mnemonic_audit.py: IDENT_PROV_RE).  A row it
        # cannot read is a row invisible to the universe, which reports
        # as 'this rule was never qualified'.
        w('    /* %s: %s; FNV-1a-32 of "%s#%d" */' % (spell, why, name, slot))
        # The WORD rides on the provenance line the plugin's identity
        # generator reads.  QEMU has no word for these encodings -- the
        # whole reason this table exists is that it calls them all NOP --
        # so the arm's own name is the only one there is, and leaving it
        # in prose would make the qualified row state the NOP the base
        # row states and undo the carve.
        w('    /* decode-new.c.inc:%d word=%s(arm) */' % (slot, spell))
        w('    { 0x%08xu, "%s" },' % (ident, name))
    w('};')
    w('')
    for subject, rx, what in SUBJECTS:
        w('/* %s: decode-new.c.inc:%d. */' % (what, slot_of[subject]))
    w('static const struct {')
    w('    uint32_t slot;')
    w('    uint8_t mask;')
    w('    uint8_t value;')
    w('    uint16_t idx;')
    w('} prefetch_ident_arms[] = {')
    for i, (name, ident, spell, why, subject, slot, mask,
            value) in enumerate(rows, 1):
        w('    { %du, 0x%02x, 0x%02x, %d },   /* %s */'
          % (slot, mask, value, i, spell))
    w('};')
    w('')
    w('/*')
    w(' * mod=11 is not a prefetch on either group: every arm is')
    w(' * defined on m8.  [0x0d] already refuses it in the operand')
    w(' * template (X86_TYPE_M returns false and the encoding')
    w(' * faults), [0x18] does not, and stating it here means the')
    w(' * two groups answer the reserved register form the same')
    w(' * way -- as the NOP the base row states.')
    w(' */')
    w('static inline uint16_t prefetch_ident_of(uint32_t slot, uint8_t modrm)')
    w('{')
    w('    if ((modrm >> 6) == 3) {')
    w('        return 0;')
    w('    }')
    w('    for (size_t i = 0; i < ARRAY_SIZE(prefetch_ident_arms); i++) {')
    w('        if (slot == prefetch_ident_arms[i].slot &&')
    w('            (modrm & prefetch_ident_arms[i].mask)'
      ' == prefetch_ident_arms[i].value) {')
    w('            return prefetch_ident_arms[i].idx;')
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
    w('static inline void prefetch_ident_publish(uint32_t slot, uint8_t modrm)')
    w('{')
    w('    uint16_t idx = prefetch_ident_of(slot, modrm);')
    w('')
    w('    if (idx) {')
    w('        plugin_gen_record_insn_identity(prefetch_ident_tab[idx].id,')
    w('                                        prefetch_ident_tab[idx].name);')
    w('    }')
    w('}')
    w('')
    with open(path_out, 'w') as f:
        f.write('\n'.join(out))

    for i, line in enumerate(CALL.split('\n')):
        src.insert(ins + i, line)
    with open(path_dec, 'w') as f:
        f.write('\n'.join(src))

    if report:
        print('prefetch_ident: slots %s, %d arm(s); %d pairs checked, %d '
              'qualified, %d residual; call at line %d, last site %d; '
              '%d stale call(s) removed'
              % (', '.join('%s=%d' % (s, l) for s, l in
                           sorted(slot_of.items())),
                 len(rows), hits + residual, hits, residual, ins, max_site,
                 removed))
        for i, (name, ident, spell, why, subject, slot, mask,
                value) in enumerate(rows, 1):
            print('  0x%08x  %-44s %-12s %d encoding(s)'
                  % (ident, name, spell, reached[i]))
    return 0


def main():
    ap = argparse.ArgumentParser()
    paths = ident_instrument_paths.Paths(__file__)
    paths.add_input(ap, '--decode', 'target/i386/tcg/decode-new.c.inc')
    paths.add_output(ap, '-o', 'target/i386/tcg/prefetch_ident.c.inc')
    paths.install(ap)
    ap.add_argument('-q', action='store_true')
    return ident_instrument_paths.main_wrapper(
        paths, ap, lambda a, v: build(v[0], v[1], not a.q))


if __name__ == '__main__':
    sys.exit(main())
