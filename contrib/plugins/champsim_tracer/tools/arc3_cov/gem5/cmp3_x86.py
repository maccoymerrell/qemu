"""
ARC 3 -- the x86_64 correct path against TWO references at once: gem5 and PIN.

WHY BOTH, AND WHY THE INTERESTING OUTPUT IS THE REFERENCES DISAGREEING
=====================================================================
The correct path on x86_64 has been scored against PIN alone.  PIN observes a
REAL execution on REAL silicon, which makes it authoritative about a value --
but it is an observer, not a model: ``INS_RegR``/``INS_RegW`` report the
EXPLICIT operands, so PIN can convict a SUBSET and never a SUPERSET, and it
cannot read the x87 status word at all.  gem5 is the opposite kind of witness:
its own decoder and its own semantics, complete operand sets, and no silicon
underneath it.

Where the two references disagree WITH EACH OTHER, neither can be quoted as
ground truth for the tracer, and the disagreement is a fact about the
REFERENCES.  This arc has already found several of that shape -- gem5
publishing raw memory bytes rather than the register value on ``flds``, XED
defaulting MPX decoding off, PIN's explicit-operand-only silence, and both
static decoders inheriting LLVM's assembler-scratch ``$at`` implicit-def on
MIPS -- so the pairing is run as an instrument rather than as a formality.

WHAT IS COMPARED
================
All three streams are the SAME probe binary, run three ways, and they are
aligned on the PC sequence: the probes are fixed-address ``-nostdlib``
non-PIE ELFs that install their own stack, so no address in any of them
depends on how a loader laid out a process.

    reg-dst-value   the value written, on registers BOTH sides of a pair name
    memop-count     loads and stores per instruction
    memop-addr      the effective address of each
    memop-width     the bytes each moved
    store-data      the bytes a store moved
    load-data       the bytes a load returned

The register SET axis is deliberately absent from the PIN pairings: PIN's
operand lists are explicit-only, so a set difference against PIN measures
PIN's instrumentation and not the tracer.  That is the retraction this arc
already made, and it is honoured here by not asking PIN the question.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.join(HERE, '..'),
           os.path.join(HERE, '..', 'riscv64', 'spike'),
           os.path.join(HERE, '..', '..', 'arc3_pinexec')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gem5_ref                                                 # noqa: E402
import gem5_env                                                 # noqa: E402
import tracer_log                                               # noqa: E402
import pinreglib                                                # noqa: E402
import pinmemlib                                                # noqa: E402

AXES = ('reg-dst-value', 'memop-count', 'memop-addr', 'memop-width',
        'store-data', 'load-data')
PAIRS = ('tracer-vs-gem5', 'tracer-vs-PIN', 'gem5-vs-PIN')

#: PIN / XED canonical register name -> the tracer's GenericRegId.  The
#: reverse of ``pinreglib.q_canon``, written out rather than inverted at run
#: time so that a name with no generic counterpart is VISIBLY absent instead
#: of silently mapping to something.
_GPR = ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
PIN_TO_GENERIC = {}
for _i, _n in enumerate(_GPR):
    PIN_TO_GENERIC[_n] = 'REG_GPR%d' % _i
PIN_TO_GENERIC.update({'rsp': 'REG_SP', 'rbp': 'REG_FP_REG',
                       'rip': 'REG_PC', 'flags': 'REG_FLAGS',
                       'rflags': 'REG_FLAGS', 'eflags': 'REG_FLAGS'})
for _i in range(32):
    PIN_TO_GENERIC['vec%d' % _i] = 'REG_VEC%d' % _i
    PIN_TO_GENERIC['xmm%d' % _i] = 'REG_VEC%d' % _i
for _i in range(8):
    PIN_TO_GENERIC['st%d' % _i] = 'REG_FPR%d' % _i
PIN_TO_GENERIC['mxcsr'] = 'REG_MXCSR'
PIN_TO_GENERIC['x87status'] = 'REG_FCSR'
PIN_TO_GENERIC['x87control'] = 'REG_FPCW'

#: Registers PIN names that this comparison does not score, each for a stated
#: reason.  Counted, never silently dropped.
#:
#: RFLAGS IS SCORED, and the reason it looked as though it should not be is
#: worth stating: XED names RFLAGS as a destination of instructions that do
#: not write it, so PIN's flags SET is unusable -- but this tool never asks
#: any reference for a set.  The VALUE PIN reports is the architectural RFLAGS
#: after the instruction, read off the real machine, and it is the only
#: witness that can settle a bit the SDM leaves UNDEFINED, which is what the
#: gem5 pairing keeps producing rows about.  It is compared only where the
#: TRACER also names the register, so an instruction that writes no flags
#: contributes nothing.
PIN_NOT_SCORED = {}

#: Registers whose VALUE gem5 does not state in a comparable form.  Counted.
GEM5_NOT_VALUED = {
    # gem5 has no x87 status word as such: it keeps X87Top (misc 191), Fsw
    # (194), Ftw (195) and Ftag (196) as four separate misc registers, all of
    # which the shared vocabulary folds onto the one id the wire uses.
    # Whichever wrote last would be read as "the value of REG_FCSR", which is
    # not a value of anything.  ``compare_exec_gem5`` reaches the same
    # conclusion by putting the register in its own partition and never
    # comparing its value; this states it explicitly so the two tools cannot
    # drift.  PIN cannot settle it either -- it reports `x87status` with NO
    # value captured.
    'REG_FCSR': 'gem5 folds four misc registers onto this id',
}


class Rec(object):
    """One instruction as one of the three tools recorded it."""

    __slots__ = ('pc', 'nbytes', 'writes', 'loads', 'stores', 'vmask')

    def __init__(self, pc, nbytes):
        self.pc = pc
        self.nbytes = nbytes
        self.writes = {}      # GenericRegId -> (value, width) | (None, 0)
        self.loads = []       # [(addr, data|None, width)]
        self.stores = []
        #: GenericRegId -> the bit mask of the value this tool STATED.  gem5
        #: reconstructs RFLAGS from three condition-code registers and speaks
        #: only about the bits they carry; comparing outside that mask would
        #: credit or convict a bit no reference claimed.
        self.vmask = {}


# ------------------------------------------------------------------- the runs
def run_pin(pin_root, tools, guest, outdir, which):
    tool = os.path.join(tools, 'obj-intel64',
                        'champsim_%s_pintool.so' % which)
    if not os.path.exists(tool):
        raise gem5_env.MissingPrerequisite(
            'MISSING PREREQUISITE: %s.\n  Build it: make -C %s PIN_ROOT=%s'
            % (tool, tools, pin_root))
    out = os.path.join(outdir, '%s.%s' % (os.path.basename(guest), which))
    # ONE minimal environment, and `setarch -R`: the reference and the tracer
    # must not differ because one of them got a randomised layout or a longer
    # environment block.
    cmd = ['env', '-i', 'HOME=/tmp', 'LANG=C', 'setarch', '-R',
           os.path.join(pin_root, 'pin'), '-t', tool,
           '-o', out, '-s', '0', '-t', '400000', '--', guest]
    p = subprocess.run(cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    tail = p.stdout.decode('utf-8', 'replace')
    with open(out + '.out', 'w') as fh:
        fh.write(tail)
    if p.returncode != 0 or not os.path.exists(out):
        raise RuntimeError('PIN %s tool failed on %s (rc=%d):\n%s'
                           % (which, guest, p.returncode, tail[-1200:]))
    # The pintool prints its own census.  `skipped=` is how many instructions
    # its arming gate consumed, and it is READ rather than assumed: hard-coding
    # 1 is how an off-by-one alignment becomes a page of value disagreements.
    skipped = 0
    for tok in tail.split():
        if tok.startswith('skipped='):
            skipped = int(tok.split('=')[1])
    return out, skipped


def pin_records(regpath, mempath, skipped, notes):
    """The two PIN streams -> [Rec], joined on their record index."""
    a, names = pinreglib.read(regpath)
    m = pinmemlib.read_memop(mempath)
    if len(a) != len(m):
        raise RuntimeError('PIN register stream has %d records and the memop '
                           'stream %d; they are the same run and must agree'
                           % (len(a), len(m)))
    out = []
    for i in range(len(a)):
        e, mm = a[i], m[i]
        if int(e['ip']) != int(mm['ip']):
            raise RuntimeError('PIN streams disagree at record %d: reg ip '
                               '0x%x, memop ip 0x%x' % (i, int(e['ip']),
                                                        int(mm['ip'])))
        r = Rec(int(e['ip']), int(e['len']))
        for d in e['dst'][:int(e['dst_rec'])]:
            n = pinreglib.canon(names, d)
            if n is None:
                continue
            n = pinreglib.norm(n)
            if n in PIN_NOT_SCORED:
                notes['pin-not-scored:' + n] += 1
                continue
            g = PIN_TO_GENERIC.get(n)
            if g is None:
                notes['pin-unmapped:' + n] += 1
                continue
            v = pinreglib.value(d)
            r.writes[g] = (v, int(d['width']) if v is not None else 0)
        for k in range(int(mm['ld_rec'])):
            got = int(mm['ld_got'][k])
            data = (int.from_bytes(bytes(mm['ld_data'][k][:got]), 'little')
                    if got else None)
            r.loads.append((int(mm['ld_ea'][k]), data, int(mm['ld_sz'][k])))
        for k in range(int(mm['st_rec'])):
            got = int(mm['st_got'][k])
            data = (int.from_bytes(bytes(mm['st_data'][k][:got]), 'little')
                    if got else None)
            r.stores.append((int(mm['st_ea'][k]), data, int(mm['st_sz'][k])))
        if int(mm['n_ld']) > int(mm['ld_rec']):
            notes['pin-load-overflow'] += 1
        if int(mm['n_st']) > int(mm['st_rec']):
            notes['pin-store-overflow'] += 1
        out.append(r)
    del out[:0]
    return out


#: gem5 holds no RFLAGS register, so its flags VALUE is a reconstruction with
#: a MASK naming which bits it spoke about.  Carried on the record so the
#: comparison can restrict itself to those bits instead of comparing a word
#: gem5 never claimed to have.
def gem5_records(insns, notes):
    out = []
    for i in insns:
        r = Rec(i.pc, i.nbytes)
        for n, v, w in i.writes:
            if n in GEM5_NOT_VALUED:
                notes['gem5-not-valued:' + n] += 1
                r.writes[n] = (None, 0)
                continue
            r.writes[n] = (v, w) if w else (None, 0)
        if i.rflags_mask:
            r.writes['REG_FLAGS'] = (i.rflags, 4)
            r.vmask['REG_FLAGS'] = i.rflags_mask
        r.loads = list(i.loads)
        r.stores = list(i.stores)
        out.append(r)
    return out


def tracer_records(insns):
    out = []
    for i in insns:
        r = Rec(i.pc, i.nbytes)
        for n, v, w in i.writes:
            r.writes[n] = (v, w) if w else (None, 0)
        r.loads = list(i.loads)
        r.stores = list(i.stores)
        out.append(r)
    return out


# ------------------------------------------------------------------ alignment
def align3(streams):
    """[[Rec]] -> the positions where ALL streams agree on the PC.

    A three-way comparison is only meaningful where all three tools are on the
    same instruction, and the probes are deterministic straight-line programs
    with the same entry, so a walk with a common prefix is the whole of it.
    Where any stream diverges the walk STOPS and the number of instructions
    dropped is reported by name -- never skipped over silently.
    """
    n = min(len(s) for s in streams)
    k = 0
    while k < n and len(set(s[k].pc for s in streams)) == 1:
        k += 1
    return k


# ----------------------------------------------------------------- comparison
def cmp_pair(a, b):
    """Two Recs -> (disagreements, facts, keys compared).

    ``keys`` is what makes the three-way ADJUDICATION possible: a pairing that
    never compared a key cannot be read as agreement on it, and the prefetch
    rows are exactly that case -- the tracer states an address-only memop with
    no width, so there is no width fact against PIN at all, and treating its
    silence as agreement would have made PIN appear to side with the tracer
    about a number the tracer never stated.
    """
    bad, facts, keys = [], collections.Counter(), set()
    both = set(a.writes) & set(b.writes)
    for n in sorted(both):
        av, aw = a.writes[n]
        bv, bw = b.writes[n]
        if av is None or bv is None:
            continue
        w = min(aw, bw) or 8
        m = (1 << (8 * w)) - 1 if w < 16 else (1 << 128) - 1
        m &= a.vmask.get(n, ~0) & b.vmask.get(n, ~0)
        if not m:
            continue
        facts['reg-dst-value'] += 1
        keys.add(('reg-dst-value', n))
        if (av & m) != (bv & m):
            bad.append(('reg-dst-value', n, '0x%x' % (av & m),
                        '0x%x' % (bv & m)))
    if a.loads or a.stores or b.loads or b.stores:
        facts['memop-count'] += 1
        keys.add(('memop-count', ''))
        if (len(a.loads), len(a.stores)) != (len(b.loads), len(b.stores)):
            bad.append(('memop-count', '',
                        '%dL/%dS' % (len(a.loads), len(a.stores)),
                        '%dL/%dS' % (len(b.loads), len(b.stores))))
            return bad, facts, keys
    for kind, al, bl in (('load', a.loads, b.loads),
                         ('store', a.stores, b.stores)):
        for (aa, ad, aw), (ba, bd, bw) in zip(al, bl):
            facts['memop-addr'] += 1
            keys.add(('memop-addr', kind))
            if aa != ba:
                bad.append(('memop-addr', kind, '0x%x' % aa, '0x%x' % ba))
                continue
            if aw and bw:
                facts['memop-width'] += 1
                keys.add(('memop-width', kind))
                if aw != bw:
                    bad.append(('memop-width', kind, aw, bw))
            if ad is None or bd is None or not aw or not bw:
                continue
            w = min(aw, bw)
            m = (1 << (8 * w)) - 1
            axis = 'load-data' if kind == 'load' else 'store-data'
            facts[axis] += w
            keys.add((axis, kind))
            if (ad & m) != (bd & m):
                bad.append((axis, kind, '0x%x' % (ad & m), '0x%x' % (bd & m)))
    return bad, facts, keys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--qemu-dir', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--pin-root', required=True)
    ap.add_argument('--pin-tools', required=True)
    ap.add_argument('--gem5-out', required=True,
                    help='the directory the gem5 correct-path leg wrote, '
                         'holding <guest>.g5/exec.log and <guest>.cst')
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    ap.add_argument('--adjudication', metavar='TSV',
                    help='write the per-row adjudication -- which reference '
                         'the third witness sides with -- for '
                         'compare_exec_gem5.py --pin-adjudicate to read back')
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    notes = collections.Counter()
    facts = dict((p, collections.Counter()) for p in PAIRS)
    rows = []
    adjud = []
    per_guest = []
    for guest in args.guest:
        g = os.path.basename(guest)
        log = os.path.join(args.gem5_out, g + '.g5', 'exec.log')
        cst = os.path.join(args.gem5_out, g + '.cst')
        for f in (log, cst):
            if not os.path.exists(f):
                raise gem5_env.MissingPrerequisite(
                    'MISSING PREREQUISITE: %s.  Run compare_exec_gem5.py '
                    '--isa x86_64 first; this tool scores its output against '
                    'PIN and does not re-run it.' % f)
        gm = gem5_records(gem5_ref.parse(log, guest, 'x86_64',
                                         gem5_dir=args.gem5_dir, notes=notes),
                          notes)
        tr, _ = tracer_log.parse(args.decode, cst)
        tc = tracer_records(tr)
        regp, sk1 = run_pin(args.pin_root, args.pin_tools, guest,
                            args.outdir, 'reg')
        memp, sk2 = run_pin(args.pin_root, args.pin_tools, guest,
                            args.outdir, 'memop')
        if sk1 != sk2:
            raise RuntimeError('the two PIN tools skipped different numbers '
                               'of instructions (%d and %d) on %s'
                               % (sk1, sk2, g))
        pn = pin_records(regp, memp, sk1, notes)
        # PIN's arming gate consumes `skipped` instructions before it records,
        # so the reference's record 0 is the guest's instruction `skipped`.
        tc_p, gm_p = tc[sk1:], gm[sk1:]
        k = align3([tc_p, gm_p, pn])
        per_guest.append((g, len(tc), len(gm), len(pn), sk1, k))
        notes['instructions-past-common-prefix'] += (
            max(len(tc_p), len(gm_p), len(pn)) - k)
        for i in range(k):
            seen, hit = {}, {}
            for name, x, y in (('tracer-vs-gem5', tc_p[i], gm_p[i]),
                               ('tracer-vs-PIN', tc_p[i], pn[i]),
                               ('gem5-vs-PIN', gm_p[i], pn[i])):
                bad, f, ks = cmp_pair(x, y)
                facts[name].update(f)
                seen[name] = ks
                hit[name] = set((b[0], b[1]) for b in bad)
                for ax, what, a_, b_ in bad:
                    rows.append((g, tc_p[i].pc, name, ax, what, a_, b_))
            # THE ADJUDICATION.  Per key, which of the two references does the
            # third witness side with?  A key the tracer/PIN pairing never
            # COMPARED cannot be read as agreement on it -- that is a distinct
            # verdict, and it is the honest answer for a prefetch whose width
            # the trace states as 0 by construction.
            for key in (seen['tracer-vs-gem5'] | seen['gem5-vs-PIN'] |
                        seen['tracer-vs-PIN']):
                gp = key in hit['gem5-vs-PIN']
                tp = key in hit['tracer-vs-PIN']
                if key not in seen['tracer-vs-PIN']:
                    v = 'PIN-VS-TRACER-NOT-COMPARED'
                elif key not in seen['gem5-vs-PIN']:
                    # gem5 states nothing about this key, so PIN disagreeing
                    # with the tracer is a two-witness fact and the third is
                    # silent.  Naming it PIN-AGREES-WITH-GEM5 would credit
                    # gem5 with an answer it never gave.
                    v = ('GEM5-SILENT-PIN-DISAGREES' if tp
                         else 'GEM5-SILENT-PIN-AGREES')
                elif gp and not tp:
                    v = 'PIN-AGREES-WITH-TRACER'
                elif tp and not gp:
                    v = 'PIN-AGREES-WITH-GEM5'
                elif tp and gp:
                    v = 'PIN-AGREES-WITH-NEITHER'
                else:
                    v = 'ALL-THREE-AGREE'
                adjud.append((g, tc_p[i].pc, key[0], key[1], v))

    out = []
    w = out.append
    w('ARC 3 -- x86_64 CORRECT PATH against TWO references: gem5 AND PIN')
    w('=' * 72)
    w('')
    w('PIN observes real silicon and is authoritative about a VALUE, but its')
    w('operand lists are EXPLICIT-ONLY, so it can convict a subset and never')
    w('a superset -- the register SET axis is therefore not asked of it.')
    w('gem5 has complete operand sets and its own semantics, and no silicon.')
    w('Where the two disagree WITH EACH OTHER, neither is ground truth for')
    w('the tracer and the row is a fact about the REFERENCES.')
    w('')
    w('%-16s %8s %8s %8s %8s %10s' % ('guest', 'tracer', 'gem5', 'PIN',
                                      'pin-skip', 'compared'))
    for r in per_guest:
        w('%-16s %8d %8d %8d %8d %10d' % r)
    w('')
    w('FACTS COMPARED, per pairing and axis')
    w('%-16s' % 'axis' + ''.join('%16s' % p for p in PAIRS))
    for ax in AXES:
        w('%-16s' % ax + ''.join('%16s' % ('INERT' if not facts[p][ax]
                                           else facts[p][ax]) for p in PAIRS))
    w('')
    dead = [(p, ax) for p in PAIRS for ax in AXES if not facts[p][ax]]
    if dead:
        w('INERT CELLS (compared nothing; the zero is NOT a result): %s'
          % ', '.join('%s/%s' % d for d in dead))
    else:
        w('No cell INERT: every axis performed at least one comparison in '
          'every pairing.')
    w('')
    bypair = collections.Counter()
    for r in rows:
        bypair[(r[2], r[3])] += 1
    w('DISAGREEING ROWS, per pairing and axis')
    w('%-16s' % 'axis' + ''.join('%16s' % p for p in PAIRS))
    for ax in AXES:
        w('%-16s' % ax + ''.join('%16d' % bypair[(p, ax)] for p in PAIRS))
    w('%-16s' % 'TOTAL' + ''.join(
        '%16d' % sum(bypair[(p, ax)] for ax in AXES) for p in PAIRS))
    w('')
    w('THE ROWS THAT ARE A FACT ABOUT THE REFERENCES -- gem5 vs PIN')
    ref = [r for r in rows if r[2] == 'gem5-vs-PIN']
    if not ref:
        w('  none: the two references agree on every fact both of them state.')
    for r in ref:
        w('  %-12s 0x%08x %-14s %-6s gem5=%-22s PIN=%s'
          % (r[0], r[1], r[3], r[4], r[5], r[6]))
    w('')
    w('EVERY ROW, all three pairings')
    for r in rows:
        w('  %-12s 0x%08x %-14s %-14s %-6s %-22s %s'
          % (r[0], r[1], r[2], r[3], r[4], r[5], r[6]))
    w('')
    w('THE ADJUDICATION -- which reference the third witness sides with')
    w('  A key the tracer/PIN pairing never COMPARED is its own verdict:')
    w('  silence is not agreement.')
    for k, n in sorted(collections.Counter(r[4] for r in adjud).items()):
        w('    %-30s %d' % (k, n))
    w('')
    if notes:
        w('NOTES, counted')
        for k, n in sorted(notes.items(), key=lambda kv: -kv[1]):
            w('    %8d  %s' % (n, k))
    txt = '\n'.join(out) + '\n'
    with open(os.path.join(args.outdir, 'REPORT.txt'), 'w') as fh:
        fh.write(txt)
    sys.stdout.write(txt)
    if args.tsv:
        with open(args.tsv, 'w') as fh:
            fh.write('guest\tpc\tpairing\taxis\twhat\ta\tb\n')
            for r in rows:
                fh.write('%s\t0x%x\t%s\t%s\t%s\t%s\t%s\n' % r)
    if args.adjudication:
        with open(args.adjudication, 'w') as fh:
            fh.write('guest\tpc\taxis\twhat\tverdict\n')
            for r in adjud:
                fh.write('%s\t0x%x\t%s\t%s\t%s\n' % r)
    byv = collections.Counter(r[4] for r in adjud)
    n3 = len(ref)
    sys.stderr.write('rows=%d gem5-vs-PIN=%d tracer-vs-PIN=%d inert=%d %s\n'
                     % (len(rows), n3,
                        sum(1 for r in rows if r[2] == 'tracer-vs-PIN'),
                        len(dead),
                        ' '.join('%s=%d' % kv for kv in sorted(byv.items())
                                 if kv[0] != 'ALL-THREE-AGREE')))
    return 1 if (rows or dead) else 0


if __name__ == '__main__':
    sys.exit(main())
