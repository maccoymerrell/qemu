#!/usr/bin/env python3
#
# Qualify the i386 row that carries the whole 3DNow! instruction set.
#
# THE PROBLEM.  3DNow!'s opcode byte comes *after* the modrm byte and any
# displacement, so QEMU's decode table cannot index on it and models it as
# an immediate:
#
#     decode-new.c.inc  [0x0f] = X86_OP_ENTRY3(3dnow, P,q, Q,q, I,b,
#                                              cpuid(3DNOW))
#
# One X86_OP_* site, one __LINE__ slot, one identity -- for twenty-four
# architecturally distinct instructions.  `pfadd`, `pfsub`, `pfmul`,
# `pfcmpge`, `pi2fd`, `pf2id`, `pavgusb`, `pmulhrw` and the rest all arrive
# at a consumer as the placeholder word `3dnow`, which classifies as none of
# them: an add, a compare, a multiply and a convert share one class because
# the encoding puts their opcode where the table cannot reach it.
#
# THE DISCRIMINATOR IS NOT MISSING.  gen_3dnow() reads `decode->immediate`
# and indexes `fns_3dnow[]` with it -- one array, one index, one helper per
# instruction -- and the immediate is a fact decode_insn() has already
# recorded (decode-new.c.inc, X86_TYPE_I sets decode->immediate) before the
# identity is published.
#
# WHAT THIS SCRIPT DOES, in the shape scripts/x86_x87_ident_instrument.py,
# scripts/x86_vex_ident_instrument.py, scripts/x86_cet_ident_instrument.py,
# scripts/x86_multi0f_ident_instrument.py and
# scripts/x86_prefetch_ident_instrument.py established:
#
#   * it reads the ARMS OUT OF QEMU'S OWN TABLE -- every `[0xNN] =` row of
#     `fns_3dnow[]` in target/i386/tcg/emit.c.inc -- and takes each arm's
#     WORD from the helper QEMU dispatches to (`gen_helper_pfadd` -> `pfadd`)
#     or, for the three rows spelled FN_3DNOW_MOVE, from the mnemonic QEMU
#     wrote in the comment beside them.  An arm with neither is REFUSED: a
#     row may not outlive the arm it describes;
#
#   * it finds the subject site by the table INDEX and the row's own name
#     read out of decode-new.c.inc, never by a line number written here, and
#     refuses unless there is exactly one;
#
#   * it emits target/i386/tcg/threednow_ident.c.inc, named in the x87 leg's
#     `@bits` form, `decode-new/3dnow@imm=<8 bits>`, MSB first;
#
#   * THE NAME IS NOT UNIQUE AND THE ID IS.  The id is FNV-1a-32 -- the
#     derivation scripts/decodetree.py and every other leg use -- of the name
#     with the base slot appended, printed beside each row;
#
#   * it inserts ONE call into decode-new.c.inc, below the unconditional
#     publish and below every X86_OP_* site in the file, so no slot is
#     renumbered -- and REFUSES if that ever stops being true;
#
#   * THE BASE ROW DOES NOT MOVE.  An immediate that indexes no arm --
#     every byte QEMU answers with gen_illegal_opcode() -- publishes nothing
#     here and keeps the row's own id and name bit for bit;
#
#   * it checks the selector EXHAUSTIVELY over the WHOLE (slot, immediate)
#     space -- every __LINE__ the file can hand out, times all 256 immediate
#     bytes -- and reports the residual as well as the hits.
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

# The site, identified by what the TABLE says: entry index 0x0f of a row
# naming the 3dnow generator.
SUBJECT_RE = re.compile(r'^\s*\[0x0[fF]\]\s*=\s*X86_OP_ENTRY3\(3dnow,')

PUBLISH_RE = re.compile(r'^\s*prefetch_ident_publish\(decode\.e\.slot,')

TAG = '/* threednow_ident */'
CALL = ('    threednow_ident_publish(decode.e.slot, decode.immediate);'
        '  ' + TAG)

# QEMU's own arm table, in its own file.  Read, never transcribed: a copy
# here would be a second table to keep in step, and the whole defect this
# repairs is one table answering for another.
FNS_START_RE = re.compile(r'^\s*static const SSEFunc_0_epp fns_3dnow\[\]')
ARM_RE = re.compile(
    r'^\s*\[(0x[0-9a-fA-F]+)\]\s*=\s*([A-Za-z0-9_]+)\s*,'
    r'(?:\s*/\*\s*([A-Za-z0-9_]+))?')
# The rows QEMU implements as a plain 64-bit move; the instruction is named
# only in the comment, which is why the comment is read.
MOVE_FN = 'FN_3DNOW_MOVE'
HELPER_PREFIX = 'gen_helper_'


def fnv1a32(text):
    """FNV-1a 32 of TEXT, with 0 remapped to 1."""
    h = 0x811c9dc5
    for byte in text.encode('utf-8'):
        h = ((h ^ byte) * 0x01000193) & 0xffffffff
    return h if h else 1


def bits_name(value):
    """The 8 immediate bits, MSB first."""
    return ''.join(str((value >> b) & 1) for b in range(7, -1, -1))


def read_arms(path_emit):
    """[(imm, word, how)] out of QEMU's own fns_3dnow[]."""
    arms, inside = [], False
    with open(path_emit) as f:
        for line in f:
            if not inside:
                if FNS_START_RE.match(line):
                    inside = True
                continue
            if line.startswith('};'):
                break
            m = ARM_RE.match(line)
            if not m:
                continue
            imm = int(m.group(1), 16)
            fn, note = m.group(2), m.group(3)
            if fn.startswith(HELPER_PREFIX):
                word = fn[len(HELPER_PREFIX):]
                # QEMU suffixes several of these helpers with the register
                # file they operate on (`pmulhrw_mmx`); the suffix is the
                # implementation and the instruction is what precedes it.
                if word.endswith('_mmx'):
                    word = word[:-len('_mmx')]
                arms.append((imm, word, 'helper'))
            elif fn == MOVE_FN:
                if not note:
                    return None, ('arm 0x%02x is %s and names no instruction '
                                  'in its comment' % (imm, MOVE_FN))
                arms.append((imm, note.lower(), 'comment'))
            else:
                return None, ('arm 0x%02x dispatches to %r, which is neither '
                              'a helper nor %s' % (imm, fn, MOVE_FN))
    if not inside:
        return None, 'fns_3dnow[] is not in the file'
    if not arms:
        return None, 'fns_3dnow[] carries no arm this reader recognises'
    if len({a[0] for a in arms}) != len(arms):
        return None, 'two arms share one immediate'
    return sorted(arms), None


def scan_slots(lines):
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
        if 'threednow_ident_publish(' in l or (pend
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


def check_exhaustive(slot, n_lines, arms):
    """Every (slot, immediate) pair, against the emitted selector's model."""
    by_imm = {a[0]: i for i, a in enumerate(arms, 1)}
    hits = residual = 0
    reached = set()
    for sl in range(1, n_lines + 2):
        for imm in range(256):
            idx = by_imm.get(imm, 0) if sl == slot else 0
            if idx:
                hits += 1
                reached.add(idx)
            else:
                residual += 1
    if len(reached) != len(arms):
        return None, ('only %d of %d arms is reachable'
                      % (len(reached), len(arms)))
    return (hits, residual), None


def build(path_dec, path_emit, path_out, report):
    arms, err = read_arms(path_emit)
    if err:
        print('ERROR: ' + err, file=sys.stderr)
        return 1

    with open(path_dec) as f:
        src = f.read().split('\n')
    src, removed = strip_instrumentation(src)

    sites = dict(scan_slots(src))
    subject = [n for n, l in enumerate(src, 1) if SUBJECT_RE.match(l)]
    if len(subject) != 1:
        print('ERROR: expected exactly one [0x0f] 3dnow site, found %d'
              % len(subject), file=sys.stderr)
        return 1
    slot = subject[0]
    if sites.get(slot) != '3dnow':
        print('ERROR: line %d is not an X86_OP_* 3dnow site' % slot,
              file=sys.stderr)
        return 1

    max_site = max(sites)
    pub = [n for n, l in enumerate(src, 1) if PUBLISH_RE.match(l)]
    if len(pub) != 1:
        print('ERROR: expected exactly one prefetch_ident publish site, '
              'found %d' % len(pub), file=sys.stderr)
        return 1
    ins = pub[0]
    if ins <= max_site:
        print('ERROR: the insertion point (line %d) is at or above the last '
              'X86_OP_* site (line %d); inserting there would renumber slots'
              % (ins, max_site), file=sys.stderr)
        return 1

    rows = []
    for imm, word, how in arms:
        name = 'decode-new/3dnow@imm=%s' % bits_name(imm)
        rows.append((name, fnv1a32('%s#%d' % (name, slot)), imm, word, how))
    ids = [r[1] for r in rows]
    if len(set(ids)) != len(ids):
        print('ERROR: two arms hash to the same id', file=sys.stderr)
        return 1

    got, err = check_exhaustive(slot, len(src), arms)
    if err:
        print('ERROR: ' + err, file=sys.stderr)
        return 1
    hits, residual = got

    out = []
    w = out.append
    w('/*')
    w(' * Auto-generated by scripts/x86_3dnow_ident_instrument.py --'
      ' do not edit.')
    w(' *')
    w(' * 3DNow!\'s opcode byte comes AFTER the modrm byte and any')
    w(' * displacement, so QEMU\'s decode table cannot index on it')
    w(' * and models it as an immediate:')
    w(' *')
    w(' *   [0x0f] = X86_OP_ENTRY3(3dnow, P,q, Q,q, I,b, cpuid(3DNOW))')
    w(' *')
    w(' * One slot, one identity, for %d architecturally distinct'
      % len(rows))
    w(' * instructions -- an add, a compare, a multiply and two')
    w(' * conversions among them.  The only word the row offers is')
    w(' * the placeholder `3dnow`, which classifies as none of them.')
    w(' *')
    w(' * The discriminator is not missing: gen_3dnow() reads')
    w(' * decode->immediate and indexes fns_3dnow[] with it, and')
    w(' * decode_insn() has recorded that immediate before the')
    w(' * identity is published.')
    w(' *')
    w(' * EVERY ARM BELOW IS READ OUT OF fns_3dnow[] ITSELF, in')
    w(' * target/i386/tcg/emit.c.inc, at generation time.  The word')
    w(' * is the helper QEMU dispatches to with its gen_helper_')
    w(' * prefix and any register-file suffix removed; for the rows')
    w(' * QEMU implements as a plain 64-bit move it is the mnemonic')
    w(' * QEMU wrote in the comment beside them, which is the only')
    w(' * place those three are named at all.  An arm that is')
    w(' * neither is REFUSED rather than guessed.')
    w(' *')
    w(' * THE BASE ROW DOES NOT MOVE.  decode-new.c.inc is not')
    w(' * edited apart from the one inserted call, which sits below')
    w(' * every X86_OP_* site in the file (last site line %d, call'
      % max_site)
    w(' * line %d) so no slot is renumbered.  An immediate that' % ins)
    w(' * indexes no arm -- every byte gen_3dnow() answers with')
    w(' * gen_illegal_opcode() -- publishes nothing here and keeps')
    w(' * the row\'s own id and name bit for bit.')
    w(' *')
    w(' * EXHAUSTIVE, not sampled: %d (slot, immediate) pairs --'
      % (hits + residual))
    w(' * every __LINE__ this file can hand out, times all 256')
    w(' * immediate bytes.  %d reach a qualified identity, %d do' % (hits,
                                                                     residual))
    w(' * not, and every arm is reachable.')
    w(' */')
    w('')
    w('static const struct {')
    w('    uint32_t id;')
    w('    const char *name;')
    w('} threednow_ident_tab[] = {')
    w('    { 0, NULL },')
    for name, ident, imm, word, how in rows:
        w('    /* %s: 0F 0F /r %02X; FNV-1a-32 of "%s#%d" */'
          % (word, imm, name, slot))
        w('    /* decode-new.c.inc:%d word=%s(arm) */' % (slot, word))
        w('    { 0x%08xu, "%s" },' % (ident, name))
    w('};')
    w('')
    w('/* The 3DNow! row: decode-new.c.inc:%d,' % slot)
    w(' * [0x0f] = X86_OP_ENTRY3(3dnow, P,q, Q,q, I,b, cpuid(3DNOW)). */')
    w('#define THREEDNOW_IDENT_SLOT %du' % slot)
    w('')
    w('/* Immediate -> row, 0 where gen_3dnow() has no arm. */')
    w('static const uint16_t threednow_ident_by_imm[256] = {')
    line = '   '
    by_imm = {imm: i for i, (_, _, imm, _, _) in enumerate(rows, 1)}
    for imm in range(256):
        line += ' %d,' % by_imm.get(imm, 0)
        if (imm % 16) == 15:
            w(line)
            line = '   '
    w('};')
    w('')
    w('/*')
    w(' * THE IMMEDIATE IS TRUNCATED TO EIGHT BITS, exactly as')
    w(' * gen_3dnow() truncates it: `uint8_t b = decode->immediate`.')
    w(' * decode_insn() fills decode->immediate through')
    w(' * insn_get_signed(), so a 3DNow! opcode byte of 0x9e arrives')
    w(' * as -98 and a range test on the wide value rejects every arm')
    w(' * above 0x7f -- which is every arm but four.  Mirroring QEMU\'s')
    w(' * own conversion is not a convenience: it is what makes this')
    w(' * selector answer for the byte QEMU dispatched on.')
    w(' */')
    w('static inline uint16_t threednow_ident_of(uint32_t slot,')
    w('                                          int64_t imm)')
    w('{')
    w('    if (slot != THREEDNOW_IDENT_SLOT) {')
    w('        return 0;')
    w('    }')
    w('    return threednow_ident_by_imm[(uint8_t)imm];')
    w('}')
    w('')
    w('/*')
    w(' * Publish the encoding-qualified identity for an immediate')
    w(' * that has an arm.  One that has none publishes nothing and')
    w(' * keeps what the unconditional publish above recorded.')
    w(' */')
    w('static inline void threednow_ident_publish(uint32_t slot,')
    w('                                           int64_t imm)')
    w('{')
    w('    uint16_t idx = threednow_ident_of(slot, imm);')
    w('')
    w('    if (idx) {')
    w('        plugin_gen_record_insn_identity(threednow_ident_tab[idx].id,')
    w('                                        threednow_ident_tab[idx].name);')
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
        print('threednow_ident: slot %d, %d arm(s); %d pairs checked, %d '
              'qualified, %d residual; call at line %d, last site %d; '
              '%d stale call(s) removed'
              % (slot, len(rows), hits + residual, hits, residual, ins,
                 max_site, removed))
        for name, ident, imm, word, how in rows:
            print('  0x%08x  imm=0x%02x  %-10s (%s)'
                  % (ident, imm, word, how))
    return 0


def main():
    ap = argparse.ArgumentParser()
    paths = ident_instrument_paths.Paths(__file__)
    paths.add_input(ap, '--decode', 'target/i386/tcg/decode-new.c.inc')
    paths.add_input(ap, '--emit', 'target/i386/tcg/emit.c.inc')
    paths.add_output(ap, '-o', 'target/i386/tcg/threednow_ident.c.inc')
    paths.install(ap)
    ap.add_argument('-q', action='store_true')
    return ident_instrument_paths.main_wrapper(
        paths, ap, lambda a, v: build(v[0], v[1], v[2], not a.q))


if __name__ == '__main__':
    sys.exit(main())
