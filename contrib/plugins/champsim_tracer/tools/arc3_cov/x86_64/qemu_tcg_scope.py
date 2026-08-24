#!/usr/bin/env python3
"""
ARC 3 -- what a QEMU x86_64 TCG guest can execute, DERIVED FROM QEMU.

An opcode the tracer cannot decode drops EVERYTHING for that instruction, so
"the tracer never saw it, and that is fine" is the most expensive sentence in
this arc.  It is only allowed to stand when the *reason* comes from somewhere
other than the tracer.

The reason used to come from the tracer twice over.  reach.tsv is measured --
each encoding is executed under qemu-x86_64 and SIGILL is QEMU refusing it --
but its INPUT set is `tracer_batch.tsv` filtered to the rows the tracer's
decoder rejected (REPRODUCE.sh), and for a CPL0-only opcode SIGILL at CPL3
says "privilege", not "unimplemented".  So a row could be excluded because the
decoder failed on it and then confirmed excluded by a signal that the opcode
never had to earn.  This module supplies the missing independent leg.

The arc's thesis is that QEMU's modelling is the truth.  So the scope of a
QEMU x86_64 guest is read off QEMU:

  * target/i386/tcg/decode-new.c.inc -- the prefix loop and the feature
    vocabulary the decode tables can gate on.  A feature the decoder cannot
    NAME is a feature no instruction in it can require.
  * target/i386/cpu.c -- the TCG_*_FEATURES masks.  x86_cpu_expand_features()
    intersects a CPU model against these, so a CPUID bit outside them cannot
    be advertised to a TCG guest by ANY model, `max` included.

Both are parsed at run time from the tree, never transcribed.  selfcheck()
re-asserts every cited fact and FAILS when one stops holding, so a QEMU rebase
that adds AVX-512 to TCG breaks this file loudly instead of leaving 2,466 rows
silently excused.  That is what makes the exclusion a measured boundary rather
than a permanent one.

WHAT THIS DOES NOT CLAIM.  It is a statement about a QEMU TCG guest, not about
x86.  Every mechanism below carries a `remedy` naming what would make its rows
reachable; where the remedy is "another accelerator", the rows leave the
tracer's reach entirely, because KVM and HVF execute guest code on the host
CPU and a TCG plugin observes no instruction at all.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import os
import re
import collections

QEMU_ROOT = os.environ.get('CST_QEMU_ROOT', '/mnt/md0/QEMU/qemu')
_CPU_C = 'target/i386/cpu.c'
_DECODE = 'target/i386/tcg/decode-new.c.inc'
_TRANSLATE = 'target/i386/tcg/translate.c'

Scope = collections.namedtuple('Scope', 'mechanism citation remedy')

_LEGACY_PREFIX = {'66', '67', 'f0', 'f2', 'f3',
                  '2e', '36', '3e', '26', '64', '65'}


# --------------------------------------------------------------- QEMU facts
class QemuFacts(object):
    """Everything this module asserts about QEMU, read out of the tree."""

    def __init__(self, root=None):
        self.root = root or QEMU_ROOT
        self.cpu_c = self._read(_CPU_C)
        self.decode = self._read(_DECODE)
        self.translate = self._read(_TRANSLATE)

        # CPUID_* symbols named inside any TCG_*_FEATURES mask (and the
        # *_KERNEL_FEATURES macros folded into them).  A feature word bit
        # outside this set cannot reach a TCG guest's CPUID.
        self.tcg_cpuid = (self._macro_symbols(r'TCG_\w+_FEATURES') |
                          self._macro_symbols(r'CPUID_\w+_KERNEL_FEATURES'))
        # Every CPUID_* symbol QEMU defines at all.  A feature absent here is
        # one QEMU has no name for, which is a stronger exclusion still.
        self.known_cpuid = set(re.findall(r'CPUID_[A-Za-z0-9_]+', self.cpu_c))
        # The feature names the decode tables can gate an entry on.
        self.decoder_feats = set(
            re.findall(r'X86_FEAT_([A-Za-z0-9_]+)', self.decode))
        # VEX.mmmmm values the 3-byte VEX prefix accepts.
        self.vex_maps = self._vex_maps()
        # 0F escape opcodes QEMU decodes as an UNGATED NOP.  A feature whose
        # encodings live in this hint space still EXECUTES on a TCG guest --
        # the architectural effect is absent, the instruction is not -- so no
        # feature argument may exclude them.  ENDBR64 is the case that caught
        # this: CET has no CPUID bit in cpu.c, and f3 0f 1e fa runs anyway.
        self.hint_nops = self._hint_nops()

    def _read(self, rel):
        p = os.path.join(self.root, rel)
        if not os.path.exists(p):
            raise IOError('%s: not in the QEMU tree at %s.  The scope model '
                          'cannot be derived and must not be guessed.'
                          % (rel, self.root))
        return open(p).read()

    def _macro_symbols(self, name_re):
        out = set()
        for m in re.finditer(r'#define\s+(%s)\s' % name_re, self.cpu_c):
            i, buf = m.end(), ''
            while True:
                j = self.cpu_c.index('\n', i)
                line = self.cpu_c[i:j]
                buf += line
                i = j + 1
                if not line.rstrip().endswith('\\'):
                    break
            out |= set(re.findall(r'CPUID_[A-Za-z0-9_]+', buf))
        return out

    def _hint_nops(self):
        i = self.decode.index('X86OpEntry opcodes_0F[256]')
        t = self.decode[i:self.decode.index('\n};', i)]
        out = set()
        for line in t.splitlines():
            m = re.match(r'\s*\[(0x[0-9a-f]{2})\] = X86_OP_ENTRY1\(NOP,'
                         r'\s*(?:nop|M),v\)(.*)', line)
            if m and 'cpuid(' not in m.group(2):
                out.add(m.group(1)[2:])
        return out

    def _vex_maps(self):
        m = re.search(r'switch \(vex2 & 0x1f\) \{(.*?)\n\s*\}',
                      self.decode, re.S)
        if not m:
            raise AssertionError(
                'the 3-byte VEX map switch is no longer written as '
                '`switch (vex2 & 0x1f)` in %s; the map citation is stale'
                % _DECODE)
        return {int(v, 16) for v in re.findall(r'case (0x[0-9a-f]+):', m.group(1))}

    # ------------------------------------------------------------- checkers
    def _root_table(self):
        i = self.decode.index('X86OpEntry opcodes_root')
        return self.decode[i:self.decode.index('\n};', i)]

    def evex_prefix_absent(self):
        """0x62 is neither a prefix nor a 64-bit opcode in QEMU's decoder.

        The prefix loop has no case for it, and the one-byte table spends the
        byte on BOUND, which chk(i64) makes illegal in long mode.
        """
        root = self._root_table()
        return ('case 0x62' not in self.decode and
                'case 0x62' not in self.translate and
                bool(re.search(r'\[0x62\] = X86_OP_ENTRYrr\(BOUND.*chk\(i64\)',
                               root)))

    def rex2_is_an_opcode(self):
        """0xd5 is the AAD entry, so an APX REX2 prefix is never a prefix."""
        return bool(re.search(r'\[0xD5\] = X86_OP_ENTRY2\(AAD', self.decode))

    def prefetch_is_memory_only(self):
        """0F 0D is implemented, ungated, and takes a memory operand only."""
        return bool(re.search(r'\[0x0d\] = X86_OP_ENTRY1\(NOP,\s+M,v\)',
                              self.decode))

    def supports(self, cpuid_symbol):
        return cpuid_symbol in self.tcg_cpuid


_FACTS = None


def facts(root=None):
    global _FACTS
    if _FACTS is None or (root and root != _FACTS.root):
        _FACTS = QemuFacts(root)
    return _FACTS


# ------------------------------------------------------- extension -> CPUID
# The one hand-written mapping in this file: an XED extension / isa-set name to
# the CPUID bit QEMU would have to advertise for it.  `None` records that QEMU
# defines no such bit at all -- checked, not assumed, by selfcheck().
EXT_CPUID = {
    'AVX512EVEX':     'CPUID_7_0_EBX_AVX512F',
    'AVX512VEX':      'CPUID_7_0_EBX_AVX512F',
    'AMX_TILE':       'CPUID_7_0_EDX_AMX_TILE',
    'ACE':            'CPUID_7_0_EDX_AMX_TILE',
    'AVX_VNNI':       'CPUID_7_1_EAX_AVX_VNNI',
    'AVX_IFMA':       'CPUID_7_1_EAX_AVX_IFMA',
    'AVX_VNNI_INT8':  'CPUID_7_1_EDX_AVX_VNNI_INT8',
    'AVX_VNNI_INT16': 'CPUID_7_1_EDX_AVX_VNNI_INT16',
    'AVX_NE_CONVERT': 'CPUID_7_1_EDX_AVX_NE_CONVERT',
    'SM3':            'CPUID_7_1_EAX_SM3',
    'SM4':            'CPUID_7_1_EAX_SM4',
    'SHA512':         'CPUID_7_1_EAX_SHA512',
    'SERIALIZE':      'CPUID_7_0_EDX_SERIALIZE',
    'TSX_LDTRK':      'CPUID_7_0_EDX_TSX_LDTRK',
    'LKGS':           'CPUID_7_1_EAX_LKGS',
    'MOVDIR':         'CPUID_7_0_ECX_MOVDIR64B',
    # QEMU models no CPUID bit for these at all.
    'KEYLOCKER':      None,
    'KEYLOCKER_WIDE': None,
    'ENQCMD':         None,
    'UINTR':          None,
    'RDPRU':          None,
    'HRESET':         None,
    'PBNDKB':         None,
    'MSRLIST':        None,
    'MSR_IMM':        None,
    'WRMSRNS':        None,
    'RAO':            None,
    'USER_MSR':       None,
    'MOVRS':          None,
    'CET':            None,
    'SNP':            None,
    'TDX':            None,
    'AMD_INVLPGB':    None,
}

_CITE = {
    'evex': '%s -- the prefix loop decodes 0xc4/0xc5 (VEX) and REX and has no '
            'case for 0x62; the one-byte table spends the byte on '
            '[0x62] = BOUND chk(i64), illegal in long mode.  The EVEX prefix '
            'is not a prefix to this decoder' % _DECODE,
    'rex2': '%s -- [0xD5] = X86_OP_ENTRY2(AAD, 0,w, I,b): 0xd5 is an OPCODE in '
            "QEMU's one-byte table, never an APX REX2 prefix" % _DECODE,
    'vexmap': '%s -- switch (vex2 & 0x1f) accepts maps %s and falls to '
              '`default: goto unknown_op`' % (_DECODE, '%s'),
    'form': '%s -- [0x0d] = X86_OP_ENTRY1(NOP, M,v): 0F 0D is implemented and '
            'ungated, but M rejects mod==3.  Real silicon executes the '
            'register form as a reserved NOP; QEMU refuses it.  A QEMU '
            'divergence from hardware, not a tracer gap' % _DECODE,
    'nofeat': '%s -- %s is outside every TCG_*_FEATURES mask, which '
              'x86_cpu_expand_features() intersects every CPU model against; '
              'and %s',
    'noname': '%s defines no CPUID bit for %s at all, and %s',
    'novocab': 'X86_FEAT_%s is absent from the decode tables\' feature '
               'vocabulary in %s (%d names, none of them this one), so no '
               'entry there can require it',
}

_REMEDY_TCG = ('a QEMU release whose x86 TCG front end implements it: no CPU '
               'model can reach it today, because -cpu max is intersected '
               'with the TCG_*_FEATURES masks')
_REMEDY_ACCEL = ('another accelerator (KVM/HVF) on host silicon that has the '
                 'feature -- but that removes the instruction from a TCG '
                 "plugin's view entirely, so it is out of the tracer's reach "
                 'either way')


def _strip_prefixes(hexs):
    """-> (list of bytes, index of the first non-legacy/non-REX byte)."""
    b = [hexs[i:i + 2].lower() for i in range(0, len(hexs), 2)]
    i = 0
    while i < len(b) and b[i] in _LEGACY_PREFIX:
        i += 1
    if i < len(b) and len(b[i]) == 2:
        try:
            if 0x40 <= int(b[i], 16) <= 0x4f:
                i += 1
        except ValueError:
            pass
    return b, i


def classify(hexs, ext, isa_set, root=None):
    """Why no QEMU x86_64 TCG guest can execute these bytes, or None.

    None is NOT 'reachable' -- it is 'this model has nothing to say', which the
    caller must treat as an unjustified exclusion rather than a silent pass.
    """
    f = facts(root)
    b, i = _strip_prefixes(hexs)
    op = b[i] if i < len(b) else ''

    if op == '62':
        return Scope('EVEX-PREFIX-NOT-DECODED', _CITE['evex'], _REMEDY_ACCEL)
    if op == 'd5':
        return Scope('REX2-PREFIX-IS-AN-OPCODE', _CITE['rex2'], _REMEDY_ACCEL)
    if op == 'c4' and i + 1 < len(b):
        m = int(b[i + 1], 16) & 0x1f
        if m not in f.vex_maps:
            return Scope('VEX-MAP-RESERVED',
                         _CITE['vexmap'] % sorted(f.vex_maps), _REMEDY_TCG)
    # 0F 0D with a register operand: the opcode IS QEMU's, the FORM is not.
    if (op == '0f' and i + 1 < len(b) and b[i + 1] == '0d' and
            i + 2 < len(b) and int(b[i + 2], 16) >> 6 == 3):
        return Scope('OPERAND-FORM-REFUSED', _CITE['form'],
                     'nothing -- the memory forms of this opcode are already '
                     'reachable and already decoded by the tracer')
    # The hint-NOP space executes whatever the feature bits say, so nothing
    # below may exclude it.  Declining here is the point: ENDBR64, ENDBR32,
    # RDSSPD/Q and PREFETCHRST2 all run on a TCG guest as NOPs even though
    # cpu.c models no CET or MOVRS bit at all.
    if op == '0f' and i + 1 < len(b) and b[i + 1] in f.hint_nops:
        return None

    if isa_set.startswith('APX_') or ext.startswith('APX'):
        return Scope('QEMU-MODELS-NO-SUCH-FEATURE',
                     _CITE['noname'] % (_CPU_C, 'APX_F',
                                        _CITE['novocab'] % ('APX', _DECODE,
                                                            len(f.decoder_feats))),
                     _REMEDY_TCG)

    key = isa_set if isa_set in EXT_CPUID else ext
    if key in EXT_CPUID:
        sym = EXT_CPUID[key]
        vocab = _CITE['novocab'] % (key.replace('EVEX', '').replace('LEGACY', '')
                                    or key, _DECODE, len(f.decoder_feats))
        if sym is None:
            return Scope('QEMU-MODELS-NO-SUCH-FEATURE',
                         _CITE['noname'] % (_CPU_C, key, vocab), _REMEDY_TCG)
        if not f.supports(sym):
            return Scope('CPUID-FEATURE-OUTSIDE-TCG',
                         _CITE['nofeat'] % (_CPU_C, sym, vocab), _REMEDY_TCG)
    return None


# ------------------------------------------------------------------ selfcheck
def selfcheck(root=None):
    """-> list of stale citations.  Empty means every cited fact still holds."""
    f = facts(root)
    bad = []
    if not f.evex_prefix_absent():
        bad.append('0x62 now appears in the decoder: EVEX may be decoded, and '
                   'the EVEX-PREFIX-NOT-DECODED exclusion is stale')
    if not f.rex2_is_an_opcode():
        bad.append('[0xD5] is no longer the AAD entry: REX2 may now be a '
                   'prefix, and the APX-legacy exclusion is stale')
    if not f.prefetch_is_memory_only():
        bad.append('0F 0D no longer reads `X86_OP_ENTRY1(NOP, M,v)`: the '
                   'OPERAND-FORM-REFUSED citation is stale')
    if f.vex_maps != {1, 2, 3}:
        bad.append('the 3-byte VEX prefix now accepts maps %s, not {1,2,3}: '
                   'the VEX-MAP-RESERVED exclusion is stale' % sorted(f.vex_maps))
    # An instrument that cannot fire proves nothing: the vocabulary parse must
    # find features TCG really does have.
    if '1e' not in f.hint_nops or '0d' not in f.hint_nops:
        bad.append('0F 1E / 0F 0D are no longer ungated NOP entries: the '
                   'hint-NOP space may no longer execute unconditionally, and '
                   'declining to exclude it is no longer justified')
    for must in ('AVX2', 'BMI1', 'SHA_NI', 'CMPCCXADD'):
        if must not in f.decoder_feats:
            bad.append('X86_FEAT_%s missing from the parsed decoder '
                       'vocabulary: the parse is broken, not the decoder' % must)
    if 'CPUID_7_0_EBX_AVX2' not in f.tcg_cpuid:
        bad.append('the TCG_*_FEATURES parse found no AVX2: it is broken, and '
                   'every "outside TCG" citation it produced is worthless')
    for ext, sym in sorted(EXT_CPUID.items()):
        if sym is None:
            hit = [s for s in f.known_cpuid
                   if s.endswith('_' + ext) or ext in s.split('_')[-1:]]
            if hit:
                bad.append('%s: recorded as unmodelled, but %s now defines %s'
                           % (ext, _CPU_C, ', '.join(sorted(hit)[:3])))
        elif sym not in f.known_cpuid:
            bad.append('%s: cited %s, which %s no longer defines'
                       % (ext, sym, _CPU_C))
        elif f.supports(sym):
            bad.append('%s: %s IS now inside a TCG_*_FEATURES mask -- TCG can '
                       'advertise it, so these rows are REACHABLE and their '
                       'exclusion must be withdrawn' % (ext, sym))
    return bad


if __name__ == '__main__':
    import sys
    f = facts()
    print('QEMU root                       : %s' % f.root)
    print('CPUID symbols QEMU defines      : %d' % len(f.known_cpuid))
    print('  ... inside a TCG_*_FEATURES   : %d' % len(f.tcg_cpuid))
    print('decode-table feature vocabulary : %d  (%s)'
          % (len(f.decoder_feats), ' '.join(sorted(f.decoder_feats))))
    print('3-byte VEX maps accepted        : %s' % sorted(f.vex_maps))
    print('EVEX prefix (0x62) decoded      : %s' % (not f.evex_prefix_absent()))
    print('REX2 (0xd5) is the AAD opcode   : %s' % f.rex2_is_an_opcode())
    print()
    bad = selfcheck()
    for s in bad:
        print('STALE: %s' % s)
    print('selfcheck: %d stale citation(s)' % len(bad))
    sys.exit(1 if bad else 0)
