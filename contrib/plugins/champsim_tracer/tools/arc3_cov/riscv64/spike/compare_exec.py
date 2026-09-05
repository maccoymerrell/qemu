"""
ARC 3 -- riscv64 EXECUTION cross-check: the tracer against Spike, 1 to 1.

Runs one guest binary twice -- once under ``spike`` + the RISC-V proxy kernel,
once under ``qemu-riscv64`` with the ChampSim Tracer plugin -- and compares the
two records of the SAME run, instruction by instruction, on every facet the
execution leg owns:

    reg-src-set    SOURCE registers named
    reg-src-value  the VALUE each source held
    csr-src-set    SOURCE CSRs named, at the tracer's fold granularity
    reg-dst-set    destination registers named
    reg-dst-value  the VALUE each destination received
    csr-dst-set    destination CSRs, at the tracer's fold granularity
    csr-dst-value  the value each such CSR received
    memop-count    loads and stores per instruction
    memop-addr     effective address of each
    load-data      the datum each load returned
    store-data     the datum each store wrote
    memop-width    the byte width of every access, load and store

NO AXIS HERE READS "NOT MEASURED".  The reference used to be silent about
sources, load data and load width; it is now patched to state all three
(``spike-patches/``), and ``spike_ref.require_patched`` refuses a log from a
binary that is not.  The source-VALUE axis is measured against the register
model ``format.rst`` §5.4 defines for a consumer -- the REGFILE seed plus the
destination snapshots, replayed forward -- because the wire deliberately
carries no source values; where that model cannot yet value a register the
row is counted as MODEL-UNKNOWN and named, never scored as agreement.

Every disagreeing row carries a DIRECTION and a CATEGORY through
``arc3_taxonomy``, so that "N disagree" is never the result.  The headline is
TRACER-SUBSET + UNACCOUNTED: rows where execution information is dropped, plus
rows nobody has interrogated.

Author: Maccoy Merrell.
"""
import argparse
import collections
import difflib
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '..'))

import spike_ref
import tracer_log
from arc3_taxonomy import (set_relation, classify, render_crosstab,
                           render_conflicts, render_unaccounted, EQUAL,
                           SUBSET, SUPERSET, ORTHOGONAL, UNACCOUNTED)
from arc3_rules import riscv_exec_rule


#: The register axis is split into NAME and VALUE deliberately.  Compared as
#: one set, a wrong value shows up as ORTHOGONAL -- "different vocabulary for
#: the same fact" -- which is exactly what a wrong value is not.  Split, a
#: register both sides name but value differently is unambiguously a defect.
#: CSRs are a third partition because the tracer folds several of them onto
#: one GenericRegId, and that vocabulary question must not be allowed to
#: dilute the register-file result in either direction.
AXES = ('reg-src-set', 'reg-src-value', 'csr-src-set',
        'reg-dst-set', 'reg-dst-value', 'csr-dst-set', 'csr-dst-value',
        'memop-count', 'memop-addr', 'load-data', 'store-data',
        'memop-width')


# ------------------------------------------------------------------- the ELF
def exec_ranges(path):
    """Executable PT_LOAD ranges of a little-endian ELF64.

    Used to select the guest program's own instructions out of a spike run
    that also executes the proxy kernel.  Derived from the file rather than
    hardcoded, so a differently-linked guest does not silently select nothing.
    """
    with open(path, 'rb') as fh:
        data = fh.read()
    assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1, path
    e_phoff, = struct.unpack_from('<Q', data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from('<II', data, off)
        p_vaddr, = struct.unpack_from('<Q', data, off + 0x10)
        p_memsz, = struct.unpack_from('<Q', data, off + 0x28)
        if p_type == 1 and (p_flags & 1):            # PT_LOAD, PF_X
            out.append((p_vaddr, p_vaddr + p_memsz))
    assert out, 'no executable PT_LOAD in %s' % path
    return out


# ------------------------------------------------------------------ the runs
def run_spike(spike, pk, guest, out, dtc_dir=None, isa='rv64gcv'):
    env = dict(os.environ)
    if dtc_dir:
        env['PATH'] = dtc_dir + os.pathsep + env.get('PATH', '')
    log = out + '.commits.log'
    p = subprocess.run([spike, '--isa=' + isa, '-l', '--log-commits',
                        '--log=' + log, pk, guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env)
    if p.returncode != 0:
        raise RuntimeError('spike exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    return log


#: The standing compression for every trace this harness writes.
#: A reference run's trace is a working file, not a deliverable, and an
#: uncompressed one costs disk for nothing -- 124 of them, 34.6 MB, were
#: measured under one evidence root because these drivers built their
#: plugin option string without it.  It is set HERE, where the option
#: string is built, so no caller can forget it; `cst_audit` names the
#: member codec, which is how the compliance check reads it back rather
#: than assuming.
CST_COMPRESS = 'zstd -T0 -3 -q -c'


def run_tracer(qemu, plugin, guest, out):
    trace = out + '.cst'
    p = subprocess.run(
        [qemu, '-plugin',
         '%s,outfile=%s,memdata=1,regdata=1,wp=0,compress=%s'
         % (plugin, out, CST_COMPRESS),
         guest],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RuntimeError('qemu exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    return trace


# --------------------------------------------------------------- the mapping
def split_ref(ins):
    """Spike's writes -> ({arch generic name: value}, {csr name: value}).

    A register spike names that the tracer's vocabulary cannot spell is kept
    under its spike name in the CSR map, so it reports as a vocabulary gap
    rather than vanishing into agreement.
    """
    arch, csr = {}, {}
    for name, val in ins.writes:
        if spike_ref.bank(name) == 'csr':
            csr[name.split('_', 1)[1]] = val
        else:
            g = spike_ref.to_generic(name)
            if g is None:
                csr['UNMAPPABLE:' + name] = val
            else:
                arch[g] = val
    return arch, csr


def split_ref_reads(ins):
    """Spike's reads -> ({arch generic name: value}, {csr name: value}).

    Same partition as `split_ref` uses for writes, for the same reason: a CSR
    vocabulary question must not be allowed to move the register-file number
    in either direction.
    """
    arch, csr = {}, {}
    for name, val in ins.reads:
        if spike_ref.bank(name) == 'csr':
            csr[name.split('_', 1)[1]] = val
        else:
            g = spike_ref.to_generic(name)
            if g is None:
                csr['UNMAPPABLE:' + name] = val
            else:
                arch[g] = val
    return arch, csr


#: how many source-value comparisons the consumer register model could not
#: make, by reason.  A comparison that could not happen is NOT an agreement,
#: so it is counted apart and reported, never folded into the rate.
SRC_VALUE_STATE = collections.Counter()


def split_trc(ins):
    """The tracer's writes -> ({arch id: value}, {csr id: value}).

    w == 0 means the width was not stated, NOT a zero-byte field: masking to
    8*w bits there would force every such value to 0 and manufacture an
    agreement (or a disagreement) out of the harness's own arithmetic.  The
    negative control caught exactly that before this guard existed.
    """
    arch, csr = {}, {}
    for name, val, w in ins.writes:
        v = val & ((1 << (8 * w)) - 1) if 0 < w < 8 else val
        (csr if name in spike_ref.CSR_IDS else arch)[name] = v
    return arch, csr


def zero_width(ins):
    """Destination fields the tracer published with no width.

    A destination named with width 0 and value 0 is a field whose value was
    never captured -- the register is correctly identified and its content is
    not.  Counted separately because a value that is always 0 agrees with the
    reference whenever the true value happens to be 0, so an agreement rate
    alone would hide it.
    """
    return [n for n, v, w in ins.writes if w == 0]


#: how many reference writes NONARCH_CSRS has actually removed.  A named
#: exclusion that matches nothing is a justification nobody can check, so it
#: is counted and the run refuses on a zero (see the emit.py precedent in the
#: static harness, where a stale "neither decoder decodes this" kept two
#: Zicfiss opcodes out of the denominator long after it stopped being true).
NONARCH_DROPPED = collections.Counter()


def fold_ref_csr(csr):
    """Reference CSR writes, grouped by the tracer id each folds onto.

    {tracer id: {spike csr name: value}}.  Grouping rather than collapsing is
    what lets the value axis say "one id, two architectural writes" instead of
    choosing one of them and calling the other agreement.

    A CSR OUTSIDE THE ISA THE GUEST WAS BUILT FOR IS NOT PART OF THE
    REFERENCE.  spike at this revision carries the matrix/Zvt extension and
    clears its `mtype` (0xC23) inside `vectorUnit_t::set_vl`
    (vector_unit.cc:148-152) as its own bookkeeping, so EVERY vsetvl logged a
    write to a register RVV 1.0 does not have and the tracer correctly has no
    id for.  Labelling that `REF-NONARCH-CSR` named the mechanism and left the
    row a TRACER-SUBSET -- a permanent coverage hole charged to the tracer for
    a simulator implementation detail.  It is dropped here instead, on the
    reference side where it comes from, and the drop is counted so a
    justification that stops matching cannot go unnoticed.
    """
    out = {}
    for name, val in csr.items():
        if name in spike_ref.NONARCH_CSRS:
            NONARCH_DROPPED[name] += 1
            continue
        tid = None
        for k, members in spike_ref.FOLD_MEMBERS.items():
            if name in members:
                tid = k
                break
        out.setdefault(tid or ('CSR:' + name), {})[name] = val
    return out


Disagreement = collections.namedtuple(
    'Disagreement', 'pc axis ref trc relation label')


def _set_row(pc, axis, ref, trc, label=None):
    if ref == trc:
        return None
    rel = set_relation((), sorted(map(repr, ref)), (), sorted(map(repr, trc)))
    if rel == EQUAL:
        return None
    return Disagreement(pc, axis, ref, trc, rel, label)


def is_sc(bits):
    """True for a store-conditional encoding (funct5 00011, opcode 0101111).

    Tested on the encoding rather than on a mnemonic string so the label is a
    measured property of the instruction, not a reading of a disassembler.
    """
    return (bits & 0x7f) == 0x2f and ((bits >> 27) & 0x1f) == 0x03


def is_fence(bits):
    """True for a FENCE / FENCE.I encoding (opcode 0001111).

    Tested on the encoding, like `is_sc`, so the label is a measured property
    of the instruction rather than a reading of a disassembler.
    """
    return (bits & 0x7f) == 0x0f


def is_vset(bits):
    """True for VSETVLI / VSETIVLI / VSETVL (opcode 1010111, funct3 111).

    Tested on the ENCODING, like `is_fence` and `is_sc`, so the label below is
    a measured property of the instruction and not a reading of a
    disassembler.  The three forms differ only in their top bits, which is why
    one predicate covers the family:

        vsetvli   imm[10:0]  rs1 111 rd 1010111      bit31     = 0
        vsetivli  11 imm[9:0] uimm 111 rd 1010111    bits31:30 = 11
        vsetvl    1000000 rs2 rs1 111 rd 1010111     bits31:25 = 1000000
    """
    return (bits & 0x7f) == 0x57 and ((bits >> 12) & 7) == 7


def compare_insn(r, t):
    """One aligned instruction -> its disagreeing axes (possibly none)."""
    rows = []
    ra, rc = split_ref(r)
    ta, tc = split_trc(t)
    rsa, rsc = split_ref_reads(r)
    tsa = frozenset(n for n in t.srcs if n not in spike_ref.CSR_IDS)
    tsc = frozenset(n for n in t.srcs if n in spike_ref.CSR_IDS)

    # --- reg-src-set: WHICH architectural registers were READ.
    #
    # This axis exists only because the reference was patched to record its
    # reads; before that it could not be measured on any ISA by execution.
    row = _set_row(r.pc, 'reg-src-set', frozenset(rsa), tsa)
    if row is not None:
        only_ref = frozenset(rsa) - tsa
        if only_ref and tsa <= frozenset(rsa):
            if all(n.startswith('REG_VEC') for n in only_ref) and \
                    all(n in ta for n in only_ref):
                # spike reads the DESTINATION vector register back, element
                # by element, to honour the tail-undisturbed policy.  It is a
                # real architectural read, and it is a read of a register the
                # same instruction writes.
                row = row._replace(label='REF-VEC-TAIL-READ')
            elif all(n.startswith('REG_VEC') for n in only_ref):
                row = row._replace(label='REF-VEC-ELEMENT-READ')
        only_trc = tsa - frozenset(rsa)
        if only_trc and frozenset(rsa) <= tsa:
            if all(n == 'REG_ZERO' for n in only_trc):
                row = row._replace(label='REF-C-IMM-NO-X0-READ')
            elif is_fence(r.bits) and all(n == 'REG_SYS' for n in only_trc):
                row = row._replace(label='REF-NO-ORDERING-STATE')
            elif is_vset(r.bits) and 'REG_SYS' in only_trc and \
                    only_trc <= frozenset({'REG_SYS', 'REG_ZERO'}):
                # THE CURRENT XLEN, WHICH SPIKE HAS NO REGISTER FOR.
                # helper_vsetvl() reads CPURISCVState::xl to size the new vl,
                # and that field was given a declared regfile target, so the
                # read reaches the wire as REG_SYS on every vset form.  Spike
                # keeps the same fact in `state.xlen` -- a machine MODE, not a
                # CSR and not a GPR -- so its commit log has nothing to name
                # it with.  Same shape and same category as
                # REF-NO-ORDERING-STATE above.
                #
                # REG_ZERO rides in the same row on the vsetvli forms whose
                # rs1 is x0, and it is covered by REF-C-IMM-NO-X0-READ's own
                # ground.  One row takes one label, so the label naming the
                # register the reference genuinely CANNOT represent wins and
                # the rule's note carries both facts.
                #
                # THE BRANCH SITS INSIDE `frozenset(rsa) <= tsa`, so it can
                # only fire where the reference's set is a SUBSET of the
                # tracer's: a row this rule covers is never one where the
                # tracer dropped something a reference stated.
                row = row._replace(label='REF-NO-XLEN-STATE')
            elif all(n.startswith('REG_VEC') for n in only_trc):
                row = row._replace(label='REF-VEC-ELEMENT-READ-ONLY')
        rows.append(row)

    # --- csr-src-set, at the tracer's fold granularity
    grouped_src = fold_ref_csr(rsc)
    row = _set_row(r.pc, 'csr-src-set', frozenset(grouped_src), tsc)
    if row is not None:
        unmap = [k for k in grouped_src if k.startswith('CSR:')]
        if unmap and frozenset(grouped_src) - frozenset(unmap) <= tsc:
            row = row._replace(label='REF-CSR-UNMAPPED')
        rows.append(row)

    # --- reg-src-value: the operand values a conforming consumer would have.
    #
    # Only registers BOTH sides name are compared, and only where the
    # consumer register model can value them; everything else is counted in
    # SRC_VALUE_STATE and reported as its own line.  Comparison is over the
    # width the tracer PUBLISHED for that register's last write: the trace
    # states w bytes, so w bytes is what it can be held to.
    bad_src = []
    for n in frozenset(rsa) & tsa:
        known = t.src_vals.get(n)
        if known is None:
            SRC_VALUE_STATE['model-unknown'] += 1
            continue
        val, w = known
        if w >= 8:
            SRC_VALUE_STATE['compared-full'] += 1
            mask = (1 << 64) - 1
        else:
            SRC_VALUE_STATE['compared-narrow'] += 1
            mask = (1 << (8 * w)) - 1
        if (rsa[n] & mask) != (val & mask):
            bad_src.append((n, rsa[n] & mask, val & mask))
    if bad_src:
        rows.append(Disagreement(
            r.pc, 'reg-src-value',
            frozenset((n, v) for n, v, _ in bad_src),
            frozenset((n, v) for n, _, v in bad_src),
            SUBSET, 'SRC-VALUE-MISMATCH'))

    # --- reg-dst-set: WHICH architectural registers were written
    row = _set_row(r.pc, 'reg-dst-set', frozenset(ra), frozenset(ta))
    if row is not None:
        only_trc = frozenset(ta) - frozenset(ra)
        if only_trc and frozenset(ra) <= frozenset(ta):
            if all(n == 'REG_ZERO' for n in only_trc):
                row = row._replace(label='REF-X0-DISCARD')
            elif all(n.startswith('REG_VEC') for n in only_trc):
                row = row._replace(label='REF-VEC-ELEMENT-ONLY')
        rows.append(row)

    # --- reg-dst-value: on the registers BOTH sides name, do the values agree
    both = frozenset(ra) & frozenset(ta)
    bad = frozenset((n, ra[n], ta[n]) for n in both if ra[n] != ta[n])
    if bad:
        rows.append(Disagreement(
            r.pc, 'reg-dst-value',
            frozenset((n, v) for n, v, _ in bad),
            frozenset((n, v) for n, _, v in bad),
            SUBSET, 'VALUE-MISMATCH'))

    # --- csr-dst-set / csr-dst-value, at the tracer's granularity
    grouped = fold_ref_csr(rc)
    row = _set_row(r.pc, 'csr-dst-set', frozenset(grouped), frozenset(tc))
    if row is not None:
        unmap = [k for k in grouped if k.startswith('CSR:')]
        nonarch = [k for k in unmap
                   if k[4:] in spike_ref.NONARCH_CSRS]
        if not grouped and frozenset(tc) <= frozenset(
                spike_ref.FOLD_MEMBERS):
            row = row._replace(label='REF-CSR-ACCESSOR-ONLY')
        elif unmap and frozenset(grouped) - frozenset(unmap) <= frozenset(tc):
            row = row._replace(
                label='REF-NONARCH-CSR' if len(nonarch) == len(unmap)
                else 'REF-CSR-UNMAPPED')
        rows.append(row)

    for tid in frozenset(grouped) & frozenset(tc):
        members = grouped[tid]
        if len(members) > 1:
            # One GenericRegId, several architectural writes: the id cannot
            # carry them, so no value comparison here is honest.
            rows.append(Disagreement(
                r.pc, 'csr-dst-value',
                frozenset(members.items()), frozenset(((tid, tc[tid]),)),
                SUBSET, 'CSR-FOLD-MULTI'))
            continue
        cname, cval = next(iter(members.items()))
        got = spike_ref.fcsr_field(cname, tc[tid]) if tid == 'REG_FCSR' \
            else tc[tid]
        if got != cval:
            rows.append(Disagreement(
                r.pc, 'csr-dst-value',
                frozenset(((cname, cval),)), frozenset(((tid, got),)),
                SUBSET, 'VALUE-MISMATCH'))

    # --- memop-count
    #
    # A COUNT IS ORDERED AND A SET IS NOT, and spelling the counts as the
    # tokens `ld=0` / `ld=1` and comparing them as sets got the direction
    # WRONG: {ld=0,st=1} and {ld=1,st=1} are neither a subset nor a superset
    # of one another, so a row where the tracer records strictly MORE
    # accesses than the reference -- the store-conditional whose cmpxchg
    # lowering really reads -- came out ORTHOGONAL, "different vocabulary for
    # the same fact".  It is not a vocabulary difference; one side counted
    # more, and which side is the whole result.  Compare the two axes as the
    # numbers they are: >= on both with > on one is TRACER-SUPERSET, <= with
    # < is TRACER-SUBSET, and only a genuine split -- more loads and fewer
    # stores, or the reverse -- is ORTHOGONAL.
    rcnt = (len(r.loads), len(r.stores))
    tcnt = (len(t.loads), len(t.stores))
    if rcnt != tcnt:
        if tcnt[0] >= rcnt[0] and tcnt[1] >= rcnt[1]:
            rel = SUPERSET
        elif tcnt[0] <= rcnt[0] and tcnt[1] <= rcnt[1]:
            rel = SUBSET
        else:
            rel = ORTHOGONAL
        lab = 'QEMU-SC-CMPXCHG' if (is_sc(r.bits) and rcnt[0] == 0 and
                                    tcnt[0] == 1 and
                                    rcnt[1] == tcnt[1]) else None
        rows.append(Disagreement(r.pc, 'memop-count', rcnt, tcnt, rel, lab))

    # --- memop-addr
    raddr = {('L', a) for a, _, _ in r.loads} | \
            {('S', a) for a, _, _ in r.stores}
    taddr = {('L', a) for a, _, _ in t.loads} | \
            {('S', a) for a, _, _ in t.stores}
    row = _set_row(r.pc, 'memop-addr', raddr, taddr)
    if row is not None:
        extra = taddr - raddr
        if is_sc(r.bits) and extra and \
                all(k == 'L' and ('S', a) in raddr for k, a in extra):
            row = row._replace(label='QEMU-SC-CMPXCHG')
        rows.append(row)

    # --- load-data: what the load RETURNED.  Measurable only because the
    # reference was patched; upstream pushed a literal 0 in the data slot.
    row = _set_row(r.pc, 'load-data',
                   {(a, d) for a, d, _ in r.loads},
                   {(a, d) for a, d, _ in t.loads})
    if row is not None:
        if is_sc(r.bits) and len(t.loads) > len(r.loads):
            row = row._replace(label='QEMU-SC-CMPXCHG')
        rows.append(row)

    # --- store-data
    row = _set_row(r.pc, 'store-data', set(r.stores), set(t.stores))
    if row is not None:
        rows.append(row)

    # --- memop-width: the byte width of EVERY access, both directions.
    # Its own axis rather than a component of the data axes, because a width
    # can be wrong while the value happens to agree (a zero-extended datum
    # reads the same at 4 bytes and at 8).
    rwid = {('L', a, w) for a, _, w in r.loads} | \
           {('S', a, w) for a, _, w in r.stores}
    twid = {('L', a, w) for a, _, w in t.loads} | \
           {('S', a, w) for a, _, w in t.stores}
    row = _set_row(r.pc, 'memop-width', rwid, twid)
    if row is not None:
        if is_sc(r.bits) and twid - rwid and \
                all(k == 'L' for k, _, _ in twid - rwid):
            row = row._replace(label='QEMU-SC-CMPXCHG')
        rows.append(row)

    return rows


# ---------------------------------------------------------------- alignment
def align(ref, trc):
    """(matched pairs, ref-only, trc-only).

    Anchored on (pc, encoding).  Deletions on the REFERENCE side are expected
    and named: spike's commit log has no line for an instruction that traps
    (``execute_insn_logged`` prints only on completion).  An insertion on the
    reference side -- an instruction spike ran and the tracer did not -- would
    be a divergence of the runs themselves and is reported, never absorbed.
    """
    rk = [(i.pc, i.bits) for i in ref]
    tk = [(i.pc, i.bits) for i in trc]
    sm = difflib.SequenceMatcher(a=rk, b=tk, autojunk=False)
    pairs, ref_only, trc_only = [], [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for k in range(i2 - i1):
                pairs.append((ref[i1 + k], trc[j1 + k]))
        else:
            ref_only.extend(ref[i1:i2])
            trc_only.extend(trc[j1:j2])
    return pairs, ref_only, trc_only


# ------------------------------------------------------------------- report
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--spike', required=True)
    ap.add_argument('--pk', required=True)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--dtc-dir')
    ap.add_argument('--isa', default='rv64gcv',
                    help='spike --isa string; must cover the guests')
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    all_rows, labels_seen = [], collections.Counter()
    unaligned = []
    corpus = []
    zw = collections.Counter()
    provenance = collections.Counter()
    totals = collections.Counter()
    per_guest = []

    for guest in args.guest:
        stem = os.path.join(args.outdir, os.path.basename(guest))
        log = run_spike(args.spike, args.pk, guest, stem, args.dtc_dir,
                        args.isa)
        trace = run_tracer(args.qemu, args.plugin, guest, stem)

        lo, hi = exec_ranges(guest)[0]
        ref = spike_ref.parse_commit_log(log, lo, hi, priv=0)
        # A stale, unpatched spike would make three axes compare nothing
        # against nothing and report agreement.  Refuse it by name.
        spike_ref.require_patched(log, len(ref))
        traps = spike_ref.parse_traps(log)
        trc, prov = tracer_log.parse(args.decode, trace)
        for k, v in prov.items():
            provenance[k] += v

        corpus.append((os.path.basename(guest), ref, trc))
        pairs, ref_only, trc_only = align(ref, trc)
        # An instruction the tracer recorded and the reference did not must be
        # one the reference could not have recorded.  Proven per PC from the
        # trap lines, not inferred from the fact that nothing lined up.
        for ins in trc_only:
            names = traps.get(ins.pc)
            if names:
                unaligned.append((os.path.basename(guest), ins.pc,
                                  'REF-TRAP-SILENT', '/'.join(sorted(set(names)))))
            else:
                unaligned.append((os.path.basename(guest), ins.pc,
                                  'UNEXPLAINED-TRACER-ONLY', ''))
        for ins in ref_only:
            unaligned.append((os.path.basename(guest), ins.pc,
                              'UNEXPLAINED-REFERENCE-ONLY', ''))
        totals['ref_insns'] += len(ref)
        totals['trc_insns'] += len(trc)
        totals['aligned'] += len(pairs)
        totals['ref_only'] += len(ref_only)
        totals['trc_only'] += len(trc_only)

        for r, t in pairs:
            totals['reg_writes_ref'] += len(r.writes)
            totals['reg_writes_trc'] += len(t.writes)
            totals['reg_reads_ref'] += len(r.reads)
            totals['reg_reads_trc'] += len(t.srcs)
            totals['loads_ref'] += len(r.loads)
            totals['loads_trc'] += len(t.loads)
            totals['stores_ref'] += len(r.stores)
            totals['stores_trc'] += len(t.stores)

            for n in zero_width(t):
                totals['zero_width_dst'] += 1
                zw[n] += 1
            rows = compare_insn(r, t)
            for row in rows:
                all_rows.append((os.path.basename(guest), row))
                labels_seen[row.label or ''] += 1
            for ax in AXES:
                if not any(x.axis == ax for x in rows):
                    totals['agree_' + ax] += 1
        per_guest.append((os.path.basename(guest), len(ref), len(trc),
                          len(pairs), len(ref_only), len(trc_only),
                          len([1 for g, _ in all_rows if g ==
                               os.path.basename(guest)])))

    # ---- classify
    classified = []
    for guest, row in all_rows:
        rule = riscv_exec_rule(row.label)
        rel = row.relation if row.relation != EQUAL else ORTHOGONAL
        classified.append(classify('%s@0x%x#%s' % (guest, row.pc, row.axis),
                                   row.axis, row.label or '(none)',
                                   rel, rule))

    out = []
    w = out.append
    w('ARC 3 -- riscv64 EXECUTION cross-check: ChampSim Tracer vs Spike')
    w('=' * 72)
    w('')
    w('REFERENCE   spike (riscv-isa-sim) --log-commits, via riscv-pk.')
    w('            An execution reference: real values, real addresses,')
    w('            real counts, 1-to-1 against a real run.')
    w('')
    w('%-28s %8s %8s %8s %8s %8s' % ('guest', 'ref', 'tracer', 'aligned',
                                     'ref-only', 'trc-only'))
    for g, nr, nt, na, ro, to_, _ in per_guest:
        w('%-28s %8d %8d %8d %8d %8d' % (g, nr, nt, na, ro, to_))
    w('')
    w('TOTALS')
    for k in ('ref_insns', 'trc_insns', 'aligned', 'ref_only', 'trc_only',
              'reg_writes_ref', 'reg_writes_trc',
              'reg_reads_ref', 'reg_reads_trc', 'loads_ref', 'loads_trc',
              'stores_ref', 'stores_trc'):
        w('  %-20s %10d' % (k, totals[k]))
    w('')
    w('PER-AXIS AGREEMENT (over %d aligned instructions)' % totals['aligned'])
    for ax in AXES:
        n = totals['agree_' + ax]
        w('  %-14s %8d / %-8d  %s' % (
            ax, n, totals['aligned'],
            'ALL AGREE' if n == totals['aligned'] else
            '%d disagree' % (totals['aligned'] - n)))
    w('')
    w('DESTINATION FIELDS PUBLISHED WITH NO WIDTH (w=0)')
    if not zw:
        w('  none')
    else:
        w('  A destination named with width 0 carries no captured value: the')
        w('  register is identified, its content is not.  Such a field reads')
        w('  as 0, so it AGREES with the reference on every instruction where')
        w('  the true value is also 0 -- an agreement rate alone hides it.')
        for n, c in sorted(zw.items()):
            w('    %-14s %5d occurrences' % (n, c))
    w('')
    w('SOURCE-VALUE COMPARISONS -- what the consumer register model of')
    w('format.rst 5.4 (REGFILE seed + destination snapshots, replayed')
    w('forward) could and could not value.  A comparison that could not be')
    w('made is NOT an agreement and is never folded into the rate above.')
    tot_sv = sum(SRC_VALUE_STATE.values())
    for k in ('compared-full', 'compared-narrow', 'model-unknown'):
        n = SRC_VALUE_STATE[k]
        w('  %-16s %8d  (%.4f%% of %d)'
          % (k, n, 100.0 * n / tot_sv if tot_sv else 0.0, tot_sv))
    if SRC_VALUE_STATE['compared-narrow']:
        w('  compared-narrow: the tracer published a width < 8 for that')
        w('  register\'s last write, so only those bytes were held to.')
    w('  Where each operand value CAME FROM in that model:')
    for k in ('dst-snapshot', 'seed', 'arch-const', 'unknown'):
        w('    %-16s %8d' % (k, provenance[k]))
    w('    %-16s %8d  (registers the REGFILE record carried)'
      % ('seed-registers', provenance['seed-registers']))
    if not provenance['seed']:
        w('    THE REGFILE SEED WAS NEVER CONSULTED on this corpus: every')
        w('    operand was valued from a destination snapshot or is an')
        w('    architectural constant.  The seed is therefore UNTESTED here')
        w('    and no number above is evidence about it.')
    if SRC_VALUE_STATE['model-unknown']:
        w('  model-unknown: the trace had published no value for that')
        w('  register at that point -- neither in the REGFILE seed nor in any')
        w('  preceding destination snapshot.  Named, not scored.')
    w('')
    w('AXES THE EXECUTION REFERENCE DOES NOT EXPOSE:')
    w('  none.  Register reads, load data and load width were the three, and')
    w('  the reference is patched to state all three (spike-patches/).')
    w('  spike_ref.require_patched refuses a log from a binary that is not.')
    w('')
    w('UNALIGNED INSTRUCTIONS -- every one named, none left as a bare count')
    if not unaligned:
        w('  none')
    else:
        byk = collections.Counter(u[2] for u in unaligned)
        for k, n in sorted(byk.items()):
            w('  %-26s %5d  %s' % (k, n,
              'the reference COULD NOT record these: spike prints a commit '
              'line only on completion' if k == 'REF-TRAP-SILENT' else
              '*** DIVERGENCE OF THE RUNS ***'))
        for g, pc, k, why in unaligned[:20]:
            w('      %-26s 0x%x  %s  %s' % (k, pc, g, why))
    w('')
    # The negative control runs on the same corpus that produced the numbers
    # above, so a reported zero always arrives with the evidence that the
    # check which produced it could have said otherwise.
    import selftest_exec
    fired, unproven = selftest_exec.run(corpus, verbose=False)
    w('NEGATIVE CONTROL -- every axis above, proven able to report a')
    w('disagreement by perturbing one fact on one side:')
    for axis, name, pc, why in fired:
        w('  FIRES     %-14s %s @ 0x%x  (%s)' % (axis, name, pc, why))
    for axis, why in unproven:
        w('  UNPROVEN  %-14s  *** its zero means nothing ***  (%s)'
          % (axis, why))
    w('  %d/%d axes proven live' % (len(fired), len(fired) + len(unproven)))
    w('')
    w(render_crosstab(classified, 'CROSS-TABULATION -- riscv64 execution leg'))
    w('')
    w(render_conflicts(classified))
    w(render_unaccounted(classified))
    w('')
    # The reference-side exclusion, stated with its count.  A named exclusion
    # that removed nothing is a justification nobody can check, so it counts
    # against the headline rather than passing quietly.
    w('REFERENCE-SIDE EXCLUSIONS -- CSRs outside the ISA the guest was')
    w('built for, dropped where they come from and counted here')
    stale = []
    for name in sorted(spike_ref.NONARCH_CSRS):
        k = NONARCH_DROPPED[name]
        w('  %-12s %6d reference writes dropped%s'
          % (name, k, '' if k else '   STALE: matched nothing'))
        if not k:
            stale.append(name)
    w('')
    bad_unaligned = sum(1 for u in unaligned if u[2].startswith('UNEXPLAINED'))
    hl = sum(1 for r in classified
             if r.direction in (SUBSET, UNACCOUNTED)) + bad_unaligned
    if unproven:
        hl += len(unproven)          # an unproven axis is not a passing axis
    hl += len(stale)
    w('HEADLINE  TRACER-SUBSET + UNACCOUNTED = %d' % hl)

    text = '\n'.join(out)
    print(text)
    with open(os.path.join(args.outdir, 'REPORT.txt'), 'w') as fh:
        fh.write(text + '\n')

    tsv = args.tsv or os.path.join(args.outdir, 'exec_attrib.tsv')
    with open(tsv, 'w') as fh:
        fh.write('guest\tpc\taxis\tlabel\trelation\tdirection\tcategory\t'
                 'ref\ttracer\n')
        for (guest, row), c in zip(all_rows, classified):
            fh.write('%s\t0x%x\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (
                guest, row.pc, row.axis, row.label or '(none)',
                row.relation, c.direction, c.category,
                repr(sorted(row.ref, key=repr)) if isinstance(
                    row.ref, (set, frozenset)) else repr(row.ref),
                repr(sorted(row.trc, key=repr)) if isinstance(
                    row.trc, (set, frozenset)) else repr(row.trc)))
    return 1 if hl else 0


if __name__ == '__main__':
    sys.exit(main())
