#!/usr/bin/env python3
#
# Qualify the encodings the 0F 01 group's decode row answers for and
# gen_multi0F() has NO CASE FOR AT ALL.
#
# THE PROBLEM.  `[0x01] = X86_OP_ENTRY1(multi0F, nop,v, nolea)` is one
# decode-table slot -- one __LINE__, one identity -- dispatching to
# gen_multi0F(), whose `switch (modrm)` for b == 0x101 has case labels for
# twenty-four encodings and a `default: goto illegal_op` for everything
# else.  scripts/x86_multi0f_ident_instrument.py qualifies the labelled
# twenty-four, and it publishes on gen_multi0F's RETURNING path, so an
# encoding that reaches the default keeps the shared slot id.  Measured on
# the exec118 sled corpus, that slot (0x000004ae) carries THIRTY-THREE
# mnemonics, and one of them is 63% of the whole census on it:
#
#     rstorssp                                4726 encoding(s)
#     xtest xend vmxoff vmfunc vmcall ...        94 each
#     setssbsy saveprevssp                       17 each
#
# `rstorssp` reads and writes the shadow-stack pointer.  R16 has already
# ruled, on `rdsspq` and the very same register, that the instruction
# FORM's dependency on SSP is recorded whatever the modelled machine's CET
# state is -- so the wire is right to publish REG_SSP, and the row that
# says so has nowhere to be keyed: a row keyed on 0x4ae fires on all
# thirty-three.  That is the failure the qdep ledger already records
# happening once, when 0x0000054b was QEMU's NOP slot carrying `endbr64`
# beside `rdsspq`.
#
# WHAT THIS SCRIPT CARVES, AND WHAT IT DELIBERATELY LEAVES ALONE.
#
# The thirty-three split cleanly in two, and the split is a STRUCTURAL
# fact about QEMU's source rather than a fact about the machine QEMU was
# configured as:
#
#   * STRUCTURAL HOLES -- modrm values gen_multi0F's 0F 01 switch has no
#     case label for.  `0F 01 D6` (xtest) reaches `default:` on every
#     machine QEMU can be built or configured as, because there is no
#     `case 0xd6:` to reach.  These are carved here.
#
#   * MACHINE-STATE REFUSALS -- `monitor`, `xgetbv`, `vmrun`, `stac` and
#     the rest DO have case labels, and reach `illegal_op` only because
#     this CPU model lacks the feature or the code is not at CPL 0.  They
#     are NOT carved here and must not be: an arm for them would publish
#     one identity on a machine that refuses the encoding and let
#     x86_multi0f_ident_instrument.py's returning-path arm publish a
#     different one on a machine that accepts it, making the identity a
#     function of machine state.  R16 forbids exactly that.  They keep the
#     shared row, which is what they had.
#
# THE HANDLED SET IS READ OUT OF gen_multi0F, NOT WRITTEN DOWN HERE.  The
# script parses the 0F 01 arm of the function's own switch -- its `case
# 0x..:` labels and its CASE_MODRM_OP / CASE_MODRM_MEM_OP macro uses,
# expanded exactly as translate.c's macros expand them -- and REFUSES if
# any arm below covers a modrm value QEMU has a case for.  So the day QEMU
# implements `xtest`, this generator fails loudly instead of publishing a
# carve for an encoding that no longer reaches the default.
#
# THE SHAPE is scripts/x86_cet_ident_instrument.py's, because the position
# is the same one: a table-row carve, keyed on facts DisasContext holds
# before the row is published, emitted as `@`-suffixed names with FNV-1a-32
# ids over the base slot, with the call inserted below every X86_OP_* site
# so no slot is renumbered, and with the selector checked EXHAUSTIVELY over
# the whole (slot, prefix, modrm) space rather than sampled.
#
# THE BASE ROW DOES NOT MOVE.  An encoding that reaches no arm -- every
# machine-state refusal, every labelled encoding, and every hole this table
# does not name -- publishes nothing here and keeps the row's own id and
# name bit for bit.
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

# The site the 0F 01 group reaches, identified by what the TABLE says:
# entry index 0x01 of a table whose row names the multi0F generator.
SUBJECT_RE = re.compile(r'^\s*\[0x01\]\s*=\s*X86_OP_ENTRY1\(multi0F,')

# The last publish already in place; the call goes below it.
PUBLISH_RE = re.compile(r'^\s*threednow_ident_publish\(decode\.e\.slot,')

TAG = '/* grp0f01_ident */'
CALL = ('    grp0f01_ident_publish(decode.e.slot,\n'
        '                          (s->prefix & PREFIX_REPZ) != 0,'
        ' s->modrm);  ' + TAG)

# gen_multi0F's own 0F 01 arm, located by these.
FUNC_RE = re.compile(r'^static void gen_multi0F\(')
B101_RE = re.compile(r'^\s*case 0x101:')
BNEXT_RE = re.compile(r'^\s*case 0x1[0-9a-f]{2}:')
EXACT_CASE_RE = re.compile(r'^\s*case (0x[0-9a-f]{2}):')
MODRM_MACRO_RE = re.compile(r'^\s*CASE_MODRM_(MEM_)?OP\((\d)\):')

# (repz, mask, value, mem_only, mnemonic, what it is).
#
# MASK/VALUE over the modrm byte; `mem_only` is QEMU's own
# CASE_MODRM_MEM_OP shape -- mod 0, 1 and 2 and not mod 3 -- which cannot
# be spelled as a bit pattern.  `repz` says the arm is reached only with
# the F3 prefix, which is what makes the shadow-stack encodings themselves
# rather than a reserved hole.
#
# EVERY ARM IS WITNESSED.  Each names a mnemonic the exec118 sled corpus
# measured landing on the shared slot; nothing here is an encoding this
# tree has never seen decode.  An SDM encoding in the same hole that no
# corpus witnesses (`rdpru`, 0F 01 FD) is deliberately absent -- naming it
# would put an unmeasured claim in a generated table.
ARMS = (
    (True,  0x38, 5 << 3, True,  'rstorssp',
     'F3 0F 01 /5, mod != 3 -- restore a saved shadow-stack pointer;'
     ' reads and writes SSP'),
    (True,  0xff, 0xe8, False, 'setssbsy',
     'F3 0F 01 E8 -- mark the shadow stack busy; reads and writes SSP'),
    (True,  0xff, 0xea, False, 'saveprevssp',
     'F3 0F 01 EA -- save the previous shadow-stack pointer'),
    (False, 0xff, 0xc0, False, 'enclv', '0F 01 C0 -- SGX leaf, VMM'),
    (False, 0xff, 0xc1, False, 'vmcall', '0F 01 C1 -- VMX call to the VMM'),
    (False, 0xff, 0xc2, False, 'vmlaunch', '0F 01 C2 -- VMX launch'),
    (False, 0xff, 0xc3, False, 'vmresume', '0F 01 C3 -- VMX resume'),
    (False, 0xff, 0xc4, False, 'vmxoff', '0F 01 C4 -- leave VMX operation'),
    (False, 0xff, 0xc5, False, 'pconfig',
     '0F 01 C5 -- platform configuration'),
    (False, 0xff, 0xcf, False, 'encls', '0F 01 CF -- SGX leaf, supervisor'),
    (False, 0xff, 0xd4, False, 'vmfunc', '0F 01 D4 -- VMX function'),
    (False, 0xff, 0xd5, False, 'xend', '0F 01 D5 -- end a TSX region'),
    (False, 0xff, 0xd6, False, 'xtest',
     '0F 01 D6 -- test for a transactional region'),
    (False, 0xff, 0xd7, False, 'enclu', '0F 01 D7 -- SGX leaf, user'),
    (False, 0xff, 0xfa, False, 'monitorx', '0F 01 FA -- AMD monitor'),
    (False, 0xff, 0xfb, False, 'mwaitx', '0F 01 FB -- AMD mwait'),
    (False, 0xff, 0xfc, False, 'clzero', '0F 01 FC -- AMD zero a cache line'),
)


def fnv1a32(text):
    """FNV-1a 32 of TEXT, with 0 remapped to 1.

       Identical derivation to scripts/decodetree.py's ident_hash() and to
       the x87, VEX, CET, prefetch and 3DNow! legs, so every identity in
       this tree is made the same way.  0 is reserved by the plugin API
       for 'no identity'."""
    h = 0x811c9dc5
    for byte in text.encode('utf-8'):
        h = ((h ^ byte) * 0x01000193) & 0xffffffff
    return h if h else 1


def bits_name(mask, value, mem_only):
    """The 8 modrm bits, MSB first, '.' where the arm does not look."""
    body = ''.join('.' if not (mask >> b) & 1 else str((value >> b) & 1)
                   for b in range(7, -1, -1))
    return body + (',mem' if mem_only else '')


def arm_name(repz, mask, value, mem_only):
    """`f3=1` where the arm requires the prefix, `f3=.` where it does not
       look at one -- the same '.' the modrm bits use for a bit the arm
       does not read.  Spelling a don't-care as `f3=0` would name a
       condition the selector never applies."""
    return 'decode-new/multi0F@f3=%s,modrm=%s' % (
        '1' if repz else '.', bits_name(mask, value, mem_only))


def arm_modrms(repz, mask, value, mem_only):
    """The modrm bytes this arm answers for."""
    out = set()
    for m in range(256):
        if mem_only and (m >> 6) == 3:
            continue
        if (m & mask) == value:
            out.add(m)
    return out


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
        if 'grp0f01_ident_publish(' in l or (pend
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


def handled_modrms(path_tr):
    """The modrm bytes gen_multi0F's 0F 01 switch has a case label for.

       READ OUT OF THE FUNCTION, so an arm below can never claim an
       encoding QEMU decodes.  The macros are expanded here exactly as
       translate.c defines them: CASE_MODRM_MEM_OP(N) is mod 0, 1 and 2,
       CASE_MODRM_OP(N) is those and mod 3."""
    with open(path_tr) as f:
        src = f.read().split('\n')
    start = None
    for n, l in enumerate(src, 1):
        if FUNC_RE.match(l):
            start = n
            break
    if start is None:
        return None, 'gen_multi0F() not found in translate.c'
    end = None
    for n in range(start, len(src) + 1):
        if src[n - 1] == '}':
            end = n
            break
    if end is None:
        return None, 'gen_multi0F() has no closing brace'

    first = None
    for n in range(start, end + 1):
        if B101_RE.match(src[n - 1]):
            if first is not None:
                return None, 'two `case 0x101:` labels in gen_multi0F()'
            first = n
    if first is None:
        return None, 'gen_multi0F() has no `case 0x101:` arm'
    last = end
    for n in range(first + 1, end + 1):
        if BNEXT_RE.match(src[n - 1]):
            last = n - 1
            break

    out = {}
    for n in range(first + 1, last + 1):
        line = src[n - 1]
        m = MODRM_MACRO_RE.match(line)
        if m:
            reg = int(m.group(2))
            mods = (0, 1, 2) if m.group(1) else (0, 1, 2, 3)
            for mod in mods:
                for rm in range(8):
                    out[(mod << 6) | (reg << 3) | rm] = n
            continue
        m = EXACT_CASE_RE.match(line)
        if m:
            out[int(m.group(1), 16)] = n
    if not out:
        return None, ('the 0F 01 arm of gen_multi0F() yielded no case '
                      'labels -- the reader does not fit the source')
    return (out, first, last), None


def check_exhaustive(slot, n_lines):
    """Every (slot, f3, modrm) in the whole space, against the emitted
       selector's own model.  Reports hits AND residual."""
    hits = residual = 0
    reached = {}
    for s in range(1, n_lines + 2):
        for f3 in (0, 1):
            for modrm in range(256):
                idx = 0
                if s == slot:
                    for i, arm in enumerate(ARMS, 1):
                        repz, mask, value, mem_only = arm[:4]
                        if repz and not f3:
                            continue
                        if mem_only and (modrm >> 6) == 3:
                            continue
                        if (modrm & mask) != value:
                            continue
                        if idx:
                            return None, ('slot %d f3=%d modrm=0x%02x '
                                          'reaches rows %d and %d'
                                          % (s, f3, modrm, idx, i))
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


def build(path_dec, path_tr, path_out, report):
    got, err = handled_modrms(path_tr)
    if err:
        print('ERROR: ' + err, file=sys.stderr)
        return 1
    handled, h_first, h_last = got

    with open(path_dec) as f:
        src = f.read().split('\n')
    src, removed = strip_instrumentation(src)

    sites = dict(scan_slots(src))
    subject = [n for n, l in enumerate(src, 1) if SUBJECT_RE.match(l)]
    if len(subject) != 1:
        print('ERROR: expected exactly one [0x01] multi0F site, found %d'
              % len(subject), file=sys.stderr)
        return 1
    slot = subject[0]
    if sites.get(slot) != 'multi0F':
        print('ERROR: line %d is not an X86_OP_* multi0F site' % slot,
              file=sys.stderr)
        return 1

    # THE REFUSAL THAT MAKES THIS A READING OF QEMU.  An arm that claims a
    # modrm value gen_multi0F has a case for would publish an identity for
    # an encoding the returning-path instrument ALSO publishes one for, on
    # whichever machine accepts it -- the machine-state-dependent identity
    # this carve exists to avoid.
    clash = []
    for arm in ARMS:
        repz, mask, value, mem_only, mnem = arm[:5]
        for m in sorted(arm_modrms(repz, mask, value, mem_only) & set(handled)):
            clash.append('%s claims modrm 0x%02x, which gen_multi0F handles '
                         'at translate.c:%d' % (mnem, m, handled[m]))
    if clash:
        for c in clash:
            print('ERROR: ' + c, file=sys.stderr)
        print('ERROR: %d arm(s) claim an encoding QEMU decodes -- this carve '
              'is stale' % len(clash), file=sys.stderr)
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
    for repz, mask, value, mem_only, mnem, why in ARMS:
        name = arm_name(repz, mask, value, mem_only)
        rows.append((name, fnv1a32('%s#%d' % (name, slot)), mnem, why,
                     repz, mask, value, mem_only))
    ids = [r[1] for r in rows]
    if len(set(ids)) != len(ids):
        print('ERROR: two arms hash to the same id', file=sys.stderr)
        return 1
    names = [r[0] for r in rows]
    if len(set(names)) != len(names):
        print('ERROR: two arms carry the same name', file=sys.stderr)
        return 1

    got, err = check_exhaustive(slot, len(src))
    if err:
        print('ERROR: ' + err, file=sys.stderr)
        return 1
    hits, residual, reached = got

    # The holes this table does NOT name, reported rather than hidden: a
    # carve that covered everything would pass a hits-only check, and the
    # residual is the honest statement of what still shares the base row.
    covered = set()
    for repz, mask, value, mem_only, _m, _w in ARMS:
        covered |= arm_modrms(repz, mask, value, mem_only)
    holes = set(range(256)) - set(handled)
    unnamed = sorted(holes - covered)

    out = []
    w = out.append
    w('/*')
    w(' * Auto-generated by scripts/x86_0f01_ident_instrument.py -- do not'
      ' edit.')
    w(' *')
    w(' * `[0x01] = X86_OP_ENTRY1(multi0F, nop,v, nolea)` is ONE')
    w(' * decode-table slot for the whole 0F 01 group.  gen_multi0F()')
    w(' * has case labels for %d of the 256 modrm bytes and a'
      % len(handled))
    w(' * `default: goto illegal_op` for the other %d; the arms'
      % len(holes))
    w(' * qualified on its RETURNING path never publish for those,')
    w(' * so they keep the shared slot id.  The rows below give the')
    w(' * ones this tree has measured an identity of their own.')
    w(' *')
    w(' * STRUCTURAL, NOT MACHINE STATE.  Every arm here reaches')
    w(' * `default:` because gen_multi0F has NO CASE for it, on every')
    w(' * machine QEMU can be configured as.  `monitor`, `xgetbv`,')
    w(' * `vmrun` and the other feature-gated encodings DO have case')
    w(' * labels and are deliberately absent: an arm for them would')
    w(' * make the published identity a function of CPUID and CPL,')
    w(' * which R16 forbids.  They keep the shared row.')
    w(' *')
    w(' * The handled set is READ OUT OF gen_multi0F (translate.c')
    w(' * lines %d..%d), not written down here, and the generator'
      % (h_first, h_last))
    w(' * REFUSES if any arm claims a modrm value QEMU decodes.')
    w(' *')
    w(' * The name is `decode-new/multi0F@f3=<1|.>,modrm=<bits>`: the')
    w(' * 8 modrm bits, MSB first, \'.\' for a bit the arm does not')
    w(' * read, `,mem` for QEMU\'s own CASE_MODRM_MEM_OP shape (mod 0,')
    w(' * 1 and 2 and not mod 3), in the `@`-suffixed form the x87,')
    w(' * VEX and CET rows use.  The id is FNV-1a 32 of that name with')
    w(' * the base slot appended, so a qualified id is exactly as')
    w(' * stable as the base id it folds, and no more.')
    w(' *')
    w(' * THE BASE ROW DOES NOT MOVE.  decode-new.c.inc is not edited')
    w(' * apart from the one inserted call, which sits below every')
    w(' * X86_OP_* site in the file (last site line %d, call line %d)'
      % (max_site, pub[0]))
    w(' * so no slot is renumbered.  An encoding that reaches no arm')
    w(' * publishes nothing here and keeps the row\'s own id and name')
    w(' * bit for bit -- including the %d unnamed hole(s):' % len(unnamed))
    for i in range(0, len(unnamed), 12):
        w(' *   ' + ' '.join('%02x' % m for m in unnamed[i:i + 12]))
    w(' *')
    w(' * EXHAUSTIVE, not sampled: %d (slot, f3, modrm) triples --'
      % (hits + residual))
    w(' * every __LINE__ this file can hand out, times both prefix')
    w(' * states, times all 256 modrm bytes -- checked against the')
    w(' * selector below.  %d reach a qualified identity, %d do'
      % (hits, residual))
    w(' * not, no triple reaches two, and every arm is reachable.')
    w(' */')
    w('')
    w('static const struct {')
    w('    uint32_t id;')
    w('    const char *name;')
    w('} grp0f01_ident_tab[] = {')
    w('    { 0, NULL },')
    for name, ident, mnem, why, repz, mask, value, mem_only in rows:
        w('    /* %s: %s; FNV-1a-32 of "%s#%d" */' % (mnem, why, name, slot))
        # The WORD rides on the provenance line the plugin's identity
        # generator reads (champsim_tracer_mnemonic_audit.py:
        # IDENT_PROV_RE).  QEMU has no word for these encodings -- having
        # no case for them is the whole reason this table exists -- so the
        # arm's own name is the only one there is, and leaving it in prose
        # would make the qualified row state the placeholder `multi0F` the
        # base row states and undo the carve.
        w('    /* decode-new.c.inc:%d word=%s(arm) */' % (slot, mnem))
        w('    { 0x%08xu, "%s" },' % (ident, name))
    w('};')
    w('')
    w('/* The site the 0F 01 group reaches: decode-new.c.inc:%d,' % slot)
    w(' * [0x01] = X86_OP_ENTRY1(multi0F, nop,v, nolea). */')
    w('#define GRP0F01_IDENT_SLOT %du' % slot)
    w('')
    w('static const struct {')
    w('    uint8_t  mask;')
    w('    uint8_t  value;')
    w('    bool     repz;')
    w('    bool     mem_only;')
    w('    uint16_t idx;')
    w('} grp0f01_ident_arms[] = {')
    for i, (name, ident, mnem, why, repz, mask, value,
            mem_only) in enumerate(rows, 1):
        w('    { 0x%02x, 0x%02x, %-5s, %-5s, %2d },   /* %s */'
          % (mask, value, 'true' if repz else 'false',
             'true' if mem_only else 'false', i, mnem))
    w('};')
    w('')
    w('static inline uint16_t grp0f01_ident_of(uint32_t slot, bool repz,')
    w('                                        uint8_t modrm)')
    w('{')
    w('    if (slot != GRP0F01_IDENT_SLOT) {')
    w('        return 0;')
    w('    }')
    w('    for (size_t i = 0; i < ARRAY_SIZE(grp0f01_ident_arms); i++) {')
    w('        if (grp0f01_ident_arms[i].repz && !repz) {')
    w('            continue;')
    w('        }')
    w('        if (grp0f01_ident_arms[i].mem_only && (modrm >> 6) == 3) {')
    w('            continue;')
    w('        }')
    w('        if ((modrm & grp0f01_ident_arms[i].mask)'
      ' == grp0f01_ident_arms[i].value) {')
    w('            return grp0f01_ident_arms[i].idx;')
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
    w('static inline void grp0f01_ident_publish(uint32_t slot, bool repz,')
    w('                                         uint8_t modrm)')
    w('{')
    w('    uint16_t idx = grp0f01_ident_of(slot, repz, modrm);')
    w('')
    w('    if (idx) {')
    w('        plugin_gen_record_insn_identity(grp0f01_ident_tab[idx].id,')
    w('                                        grp0f01_ident_tab[idx].name);')
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
        print('grp0f01_ident: slot %d, %d arm(s); gen_multi0F handles %d '
              'modrm value(s) (translate.c:%d..%d), %d are holes, %d hole(s) '
              'unnamed; %d triples checked, %d qualified, %d residual; call '
              'at line %d, last site %d; %d stale call(s) removed'
              % (slot, len(rows), len(handled), h_first, h_last, len(holes),
                 len(unnamed), hits + residual, hits, residual, pub[0],
                 max_site, removed))
        for i, (name, ident, mnem, why, repz, mask, value,
                mem_only) in enumerate(rows, 1):
            print('  0x%08x  %-44s %-12s %d encoding(s)'
                  % (ident, name, mnem, reached[i]))
    return 0


def main():
    ap = argparse.ArgumentParser()
    paths = ident_instrument_paths.Paths(__file__)
    paths.add_input(ap, '--decode', 'target/i386/tcg/decode-new.c.inc')
    paths.add_input(ap, '--translate', 'target/i386/tcg/translate.c')
    paths.add_output(ap, '-o', 'target/i386/tcg/grp0f01_ident.c.inc')
    paths.install(ap)
    ap.add_argument('-q', action='store_true')
    return ident_instrument_paths.main_wrapper(
        paths, ap, lambda a, v: build(v[0], v[1], v[2], not a.q))


if __name__ == '__main__':
    sys.exit(main())
