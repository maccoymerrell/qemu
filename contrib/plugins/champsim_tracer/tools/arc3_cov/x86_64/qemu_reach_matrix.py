#!/usr/bin/env python3
"""
ARC 3 -- the three-valued verdict for every x86_64 opcode with no comparison.

There are three verdicts and no fourth.  Every opcode ends COVERED (compared
against a reference and agreeing, or disagreeing only as TRACER-SUPERSET),
UNREACHABLE (no configuration of QEMU can execute it, SHOWN per row), or
UNCOVERED (a defect).  "Partial", "out of scope" and "not measured" are not
verdicts; a row that cannot be decided is UNCOVERED and is named.

WHY THIS FILE EXISTS.  qemu_tcg_scope.py charges an excluded row to a citation
read out of the QEMU tree, which is the right kind of reason but the wrong
strength of one.  It answers "can -cpu max under TCG execute this today"; it
does not answer the three questions that decide whether the row is really
dead:

  * does ANY QEMU CPU model advertise the feature?  A model whose definition
    names the bit is a model the row should be PROBED under, not excluded by.
  * is it reachable at CPL 0 though not at CPL 3?  qemu-x86_64 runs everything
    at CPL 3, so a #UD from a privileged opcode says "privilege", not
    "unimplemented", and the row needs a system-mode probe rather than an
    exclusion.
  * is it QEMU's decoder refusing the OPCODE, or the PREFIX, or nothing at all
    -- i.e. did QEMU decode the bytes as some OTHER instruction and run them?
    That last case is the worst: the guest executes an instruction and the
    tracer decodes nothing.

All three are MEASURED here, per encoding, and the measurement is what the row
carries:

  exec_user_cpl3_max     qemu-x86_64 -cpu max, the encoding called for real
  exec_user_models       the same, under EVERY 64-bit-capable CPU model QEMU
                         has (-cpu help), so "no model reaches it" is counted
                         and not assumed
  exec_user_allflags     the same, with EVERY CPUID flag QEMU recognises
                         forced on at once
  exec_sys_cpl0          qemu-system-x86_64, long mode, CPL 0, paging and
                         XCR0 on, the exception vector the encoding took
  qemu_refusal           WHERE QEMU refused, discriminated by -d unimp:
                         gen_unknown_opcode() logs ILLOPC and means the decode
                         tables have no entry; its absence means QEMU decoded
                         something and refused it later (feature gate, i64
                         check, CPL check, operand form) or ran it
  models_advertising     how many of those models' CPUID actually shows the
                         gating bit, read out of the guest with CPUID rather
                         than out of cpu.c
  models_naming_in_cpu_c which model definitions in target/i386/cpu.c name the
                         bit at all -- the accelerator question, since a bit a
                         model names but TCG filters is reachable under KVM
                         and unreachable to a TCG plugin

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import os
import re
import csv
import sys
import glob
import argparse
import collections

QEMU_ROOT = os.environ.get('CST_QEMU_ROOT', '/mnt/md0/QEMU/qemu')
_CPU_C = 'target/i386/cpu.c'
_CPU_H = 'target/i386/cpu.h'
_DECODE = 'target/i386/tcg/decode-new.c.inc'
_TRANSLATE = 'target/i386/tcg/translate.c'

COVERED, UNREACHABLE, UNCOVERED = 'COVERED', 'UNREACHABLE', 'UNCOVERED'

_LEGACY_PREFIX = {'66', '67', 'f0', 'f2', 'f3',
                  '2e', '36', '3e', '26', '64', '65'}


# ----------------------------------------------------------------- QEMU tree
class Tree(object):
    """The QEMU facts this file asserts, parsed from the tree on every run."""

    def __init__(self, root=QEMU_ROOT):
        self.root = root
        self.cpu_c = self._read(_CPU_C)
        self.cpu_h = self._read(_CPU_H)
        self.decode = self._read(_DECODE)
        self.translate = self._read(_TRANSLATE)
        self.bits = self._defines()
        self.words = self._feature_words()
        self.models = self._models()
        self.tcg_syms = self._tcg_mask_symbols()

    def _read(self, rel):
        p = os.path.join(self.root, rel)
        if not os.path.exists(p):
            raise IOError('%s is not in the QEMU tree at %s; the matrix cannot '
                          'be derived and must not be guessed' % (rel, self.root))
        return open(p).read()

    def _defines(self):
        """CPUID_* symbol -> bit index, from cpu.h's #defines."""
        out = {}
        for m in re.finditer(r'#define\s+(CPUID_[A-Za-z0-9_]+)\s+'
                             r'\(\s*1U?L?L?\s*<<\s*(\d+)\s*\)', self.cpu_h):
            out[m.group(1)] = int(m.group(2))
        return out

    def _feature_words(self):
        """FEAT_* -> dict(leaf, subleaf, reg, names[32], tcg_features)."""
        out = {}
        for m in re.finditer(r'\[(FEAT_[A-Za-z0-9_]+)\] = \{', self.cpu_c):
            i = m.end()
            depth, j = 1, i
            while depth:
                if self.cpu_c[j] == '{':
                    depth += 1
                elif self.cpu_c[j] == '}':
                    depth -= 1
                j += 1
            body = self.cpu_c[i:j]
            fn = re.search(r'\.feat_names = \{(.*?)\}', body, re.S)
            cp = re.search(r'\.cpuid = \{(.*?)\}', body, re.S)
            if not cp:
                continue
            names = []
            if fn:
                for tok in re.findall(r'NULL|"[^"]*"', fn.group(1)):
                    names.append(None if tok == 'NULL' else tok.strip('"'))
            leaf = re.search(r'\.eax = ([0-9a-fA-Fx]+)', cp.group(1))
            sub = re.search(r'\.ecx = ([0-9a-fA-Fx]+)', cp.group(1))
            reg = re.search(r'\.reg = R_(E[A-D]X)', cp.group(1))
            out[m.group(1)] = {
                'leaf': int(leaf.group(1), 0) if leaf else None,
                'subleaf': int(sub.group(1), 0) if sub else 0,
                'reg': reg.group(1) if reg else None,
                'names': names,
                'tcg': re.search(r'\.tcg_features = (\w+)', body),
            }
        return out

    def _tcg_mask_symbols(self):
        """Every CPUID_* symbol named inside a TCG_*_FEATURES mask."""
        out = set()
        for m in re.finditer(r'#define\s+((?:TCG_\w+_FEATURES)|'
                             r'(?:CPUID_\w+_KERNEL_FEATURES))\s', self.cpu_c):
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

    def _models(self):
        """model name -> the text of its builtin_x86_defs[] entry."""
        i = self.cpu_c.index('static const X86CPUDefinition builtin_x86_defs[]')
        j = self.cpu_c.index('\n};', i)
        blob = self.cpu_c[i:j]
        out, marks = {}, list(re.finditer(r'\.name = "([^"]+)"', blob))
        for k, m in enumerate(marks):
            end = marks[k + 1].start() if k + 1 < len(marks) else len(blob)
            out[m.group(1)] = blob[m.start():end]
        return out

    # ----------------------------------------------------------- accessors
    def word_of(self, sym):
        """CPUID_7_0_EBX_AVX512F -> ('FEAT_7_0_EBX', bit) or (None, None)."""
        m = re.match(r'(CPUID_[0-9A-Fa-f]+_[0-9]+_E[A-D]X)_', sym)
        if m:
            feat = 'FEAT_' + m.group(1)[len('CPUID_'):]
            return feat, self.bits.get(sym)
        return None, self.bits.get(sym)

    def naming_models(self, sym):
        """Which builtin CPU models name this bit, by symbol or by feat name."""
        feat, bit = self.word_of(sym)
        alias = None
        if feat in self.words and bit is not None:
            names = self.words[feat]['names']
            if bit < len(names):
                alias = names[bit]
        hits = []
        for name, body in self.models.items():
            if sym in body or (alias and '"%s"' % alias in body):
                hits.append(name)
        return sorted(hits), alias

    def decoder_mentions(self, mnemonic):
        """Does the x86 TCG front end name this mnemonic at all?"""
        pat = re.compile(r'\b%s\b' % re.escape(mnemonic), re.I)
        for label, text in (('decode-new.c.inc', self.decode),
                            ('translate.c', self.translate)):
            m = pat.search(text)
            if m:
                line = text[text.rfind('\n', 0, m.start()) + 1:
                            text.find('\n', m.start())]
                return 'present:%s:%s' % (label, line.strip()[:70])
        return 'absent'


def strip_prefixes(hexs):
    b = [hexs[i:i + 2].lower() for i in range(0, len(hexs), 2)]
    i = 0
    while i < len(b) and b[i] in _LEGACY_PREFIX:
        i += 1
    if i < len(b):
        try:
            if 0x40 <= int(b[i], 16) <= 0x4f:
                i += 1
        except ValueError:
            pass
    return b, i


# --------------------------------------------------------------- the inputs
def load_tsv(path, key, val=None):
    with open(path) as f:
        rd = csv.DictReader(f, delimiter='\t')
        return {r[key]: (r if val is None else r[val]) for r in rd}


SIGNAME = {0: 'ran', 4: 'SIGILL', 8: 'SIGFPE', 11: 'SIGSEGV', 7: 'SIGBUS',
           5: 'SIGTRAP'}
VECNAME = {6: '#UD', 13: '#GP', 14: '#PF', 0: '#DE', 255: 'ran', 8: '#DF',
           17: '#AC', 19: '#XM', 16: '#MF', 7: '#NM'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--evidence', required=True,
                    help='directory holding the measured legs')
    ap.add_argument('--attrib', required=True, help='the comparison table')
    ap.add_argument('--meta', required=True, help='opcodes_meta.tsv (isa_set)')
    ap.add_argument('--root', default=QEMU_ROOT)
    ap.add_argument('-o', required=True, help='write the matrix here')
    a = ap.parse_args()
    E = a.evidence
    t = Tree(a.root)

    def need(p):
        q = os.path.join(E, p)
        if not os.path.exists(q):
            sys.exit('%s: missing.  A verdict this file cannot measure is not '
                     'a verdict it may assume' % q)
        return q

    cpl3 = load_tsv(need('r_max_postfix.tsv'), 'hex')
    allfl = load_tsv(need('r_maxall_postfix.tsv'), 'hex')
    cpl0 = load_tsv(need('cpl0.tsv'), 'hex')
    matrix = load_tsv(need('model_matrix.tsv'), 'hex')
    illopc = {}
    with open(need('illopc.tsv')) as f:
        for line in f:
            h, v = line.split()
            illopc[h] = v == '1'
    cpuid = {}
    for p in glob.glob(os.path.join(E, 'cpuid', '*.tsv')):
        m = os.path.basename(p)[:-4]
        d = {}
        for line in open(p):
            f_ = line.split()
            d[(int(f_[0], 16), int(f_[1], 16))] = [int(x, 16) for x in f_[2:6]]
        cpuid[m] = d
    if not cpuid:
        sys.exit('%s/cpuid: no per-model CPUID dumps.  "no model advertises '
                 'it" would then be an assumption' % E)

    meta = load_tsv(a.meta.replace('#', ''), '#opcode_id'
                    if open(a.meta).readline().startswith('#') else 'opcode_id')
    with open(a.attrib) as f:
        txt = f.read()
    rows = list(csv.DictReader(txt.lstrip('#').splitlines(), delimiter='\t'))

    # --------------------------------------------------- extension -> CPUID
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import qemu_tcg_scope as S                                   # noqa: E402
    ext_cpuid = dict(S.EXT_CPUID)
    ext_cpuid.setdefault('AVX512EVEX', 'CPUID_7_0_EBX_AVX512F')

    REG = {'EAX': 0, 'EBX': 1, 'ECX': 2, 'EDX': 3}

    def advertised(sym):
        """How many probed models' CPUID actually shows the bit (MEASURED)."""
        feat, bit = t.word_of(sym)
        if feat not in t.words or bit is None:
            return None
        w = t.words[feat]
        if w['leaf'] is None or w['reg'] is None:
            return None
        n = 0
        for m, d in cpuid.items():
            v = d.get((w['leaf'], w['subleaf']))
            if v and (v[REG[w['reg']]] >> bit) & 1:
                n += 1
        return n

    # R8.7: an instrument nobody has watched fire vouches for nothing.  The
    # CPUID leg's whole job is to say "no model advertises this bit"; if it
    # cannot see a bit TCG DOES advertise, that sentence is worthless.
    live = advertised('CPUID_7_0_EBX_AVX2')
    dead = advertised('CPUID_7_0_EBX_AVX512F')
    print('CPUID leg control: AVX2 (in TCG) advertised by %s/%s configs, '
          'AVX512F (not in TCG) by %s/%s'
          % (live, len(cpuid), dead, len(cpuid)))
    if not live:
        sys.exit('the CPUID leg reports that NO configuration advertises '
                 'AVX2, which TCG certainly does: the leg is broken and every '
                 '"no model advertises it" it produced is worthless')
    if dead:
        sys.exit('the CPUID leg reports AVX512F advertised: TCG has gained '
                 'AVX-512 or the leg is broken, and either way the EVEX rows '
                 'must be re-probed rather than excluded')

    out = []
    tally = collections.Counter()
    for r in rows:
        opid = r['opcode_id']
        h = r['probe_hex']
        mn = r['mnemonic']
        isa_set = meta.get(opid, {}).get('isa_set', '')
        ext = r['extension']

        # ---------------------------------------------- the compared rows
        compared = r['verdict'] != 'UNPROBED'
        if compared and r['direction'] in ('-', 'TRACER-SUPERSET'):
            why = ('compared: %s' % (r['direction'] if r['direction'] != '-'
                                     else 'AGREE'))
            out.append((opid, mn, isa_set, ext, h, '-', '-', '-', '-', '-',
                        '-', '-', '-', '-', '-', why, COVERED))
            tally[COVERED] += 1
            continue
        if compared and h not in cpl3:
            # A comparison that DISAGREES is a defect unless the instruction
            # cannot be executed at all, and that second question has to be
            # MEASURED before it may be answered.  A row whose encoding never
            # entered the reachability legs has no such measurement, so it
            # stays UNCOVERED and says why -- never "probably unreachable".
            out.append((opid, mn, isa_set, ext, h, '-', '-', '-', '-',
                        'NOT-MEASURED', t.decoder_mentions(mn),
                        '-', '-', '-', '-',
                        'compared: %s, and the reachability legs were never '
                        'run on this encoding' % r['direction'], UNCOVERED))
            tally[UNCOVERED] += 1
            continue

        # ---------------------------------------------- the uncompared rows
        c3 = int(cpl3[h]['signal']) if h in cpl3 else None
        af = int(allfl[h]['signal']) if h in allfl else None
        c0 = int(cpl0[h]['cpl0_vec']) if h in cpl0 else None
        mm = matrix.get(h)
        b, i = strip_prefixes(h)
        op = b[i] if i < len(b) else ''

        if c3 is None or c0 is None or mm is None:
            refusal = 'NOT-MEASURED'
        elif op == '62':
            refusal = 'EVEX-PREFIX-NOT-DECODED'
        elif op == 'd5':
            refusal = 'REX2-PREFIX-IS-AN-OPCODE'
        elif illopc.get(h):
            refusal = 'NO-TABLE-ENTRY(ILLOPC)'
        elif c3 == 0 or c0 == 255:
            refusal = 'NONE-QEMU-EXECUTES-IT'
        else:
            refusal = 'DECODED-THEN-REFUSED'

        key = isa_set if isa_set in ext_cpuid else ext
        sym = ext_cpuid.get(key, 'unmapped')
        if key.startswith('APX') or isa_set.startswith('APX_'):
            sym = None
        if sym in (None, 'unmapped'):
            word = ('QEMU-MODELS-NO-SUCH-BIT' if sym is None
                    else 'NO-FEATURE-GATE')
            in_tcg, adv, naming, alias = '-', '-', '-', '-'
        else:
            word = sym
            in_tcg = 'yes' if sym in t.tcg_syms else 'no'
            n = advertised(sym)
            adv = ('%d/%d' % (n, len(cpuid))) if n is not None else '?'
            nm, alias = t.naming_models(sym)
            naming = ('%d:%s' % (len(nm), ','.join(nm[:4]))) if nm else 'none'
            alias = alias or '-'

        present = t.decoder_mentions(mn)

        # ------------------------------------------------------- the verdict
        if refusal == 'NOT-MEASURED':
            # The reachability legs are fed the encodings the TRACER's decoder
            # rejected, so a row the tracer DOES decode never enters them.  It
            # is uncompared for the opposite reason -- no reference decodes it
            # -- and a reference gap is not a verdict either.
            out.append((opid, mn, isa_set, ext, h, '-', '-', '-', '-',
                        refusal, t.decoder_mentions(mn), '-', '-', '-', '-',
                        'tracer decodes it, NO reference does (%s): the row '
                        'has no comparison and a reference gap is not a '
                        'verdict' % r['mechanism'], UNCOVERED))
            tally[UNCOVERED] += 1
            continue
        elif refusal == 'NONE-QEMU-EXECUTES-IT' and not compared:
            v = UNCOVERED
            why = ('QEMU EXECUTES these bytes and the tracer decodes nothing: '
                   'the whole instruction is dropped')
        elif c3 == 4 and c0 == 6 and mm['models_ran'] == '0' and af == 4:
            # The same four-way proof decides a COMPARED row as well as an
            # uncompared one.  A disagreement about an instruction NO QEMU
            # guest can execute describes an instruction that can never enter
            # a trace: it is unreachable, not a dropped fact.  The row still
            # carries every leg, so the claim is checkable per instruction
            # and collapses the moment QEMU learns to decode the bytes.
            v = UNREACHABLE
            why = ('#UD at CPL3 (-cpu max), #UD at CPL3 under all %s CPU '
                   'models, #UD at CPL3 with every CPUID flag forced, #UD at '
                   'CPL0 in system mode; refused at %s%s'
                   % (mm['models_probed'], refusal,
                      ('; the comparison disagrees (%s) about an instruction '
                       'no guest reaches' % r['direction']) if compared
                      else ''))
        elif compared:
            v = UNCOVERED
            why = ('compared: %s -- and the instruction IS reachable '
                   '(cpl3=%s allflags=%s cpl0=%s models_ran=%s)'
                   % (r['direction'], SIGNAME.get(c3, c3),
                      SIGNAME.get(af, af), VECNAME.get(c0, c0),
                      mm['models_ran']))
        else:
            v = UNCOVERED
            why = ('executes or faults inconsistently: cpl3=%s allflags=%s '
                   'cpl0=%s models_ran=%s'
                   % (SIGNAME.get(c3, c3), SIGNAME.get(af, af),
                      VECNAME.get(c0, c0), mm['models_ran']))

        out.append((opid, mn, isa_set, ext, h,
                    SIGNAME.get(c3, str(c3)),
                    '%s/%s ran' % (mm['models_ran'], mm['models_probed']),
                    SIGNAME.get(af, str(af)),
                    VECNAME.get(c0, str(c0)),
                    refusal, present, word, in_tcg, adv, naming, why, v))
        tally[v] += 1

    hdr = ('opcode_id', 'mnemonic', 'isa_set', 'extension', 'probe_hex',
           'exec_user_cpl3_max', 'exec_user_models', 'exec_user_allflags',
           'exec_sys_cpl0', 'qemu_refusal', 'decode_new_mnemonic',
           'cpuid_word', 'cpuid_in_tcg_mask', 'models_advertising_measured',
           'models_naming_in_cpu_c', 'evidence', 'verdict')
    with open(a.o, 'w') as f:
        f.write('\t'.join(hdr) + '\n')
        for row in out:
            f.write('\t'.join(str(x) for x in row) + '\n')

    for k in (COVERED, UNREACHABLE, UNCOVERED):
        print('%-12s %d' % (k, tally[k]))
    print('%-12s %d' % ('total', sum(tally.values())))
    return 1 if tally[UNCOVERED] else 0


if __name__ == '__main__':
    sys.exit(main())
