"""
The tracer side of the riscv64 execution cross-check: cst_decode's own output,
parsed back into per-instruction records with the same shape spike_ref.Insn has.

Three cst_decode formats are read, because no one of them carries all of what
a 1-to-1 execution comparison needs:

  --format=legacy   the CP delta stream: per entry, ``insn[i] dst[k] REG=..``
                    and ``insn[i] load=..:data=..:size=..``.  Machine-readable,
                    and the only place the destination VALUES appear.  It also
                    carries the per-thread ``REGFILE`` seed record.
  --format=disasm   the same entries with each instruction's PC and raw bytes
                    on its own line, which is what turns the legacy stream's
                    ``insn[i]`` index into an address the reference can be
                    aligned against.
  --format=raw      the structural dump, read for the TEMPLATE dictionary:
                    ``src=[..]  dst=[..]`` per template instruction.  This is
                    where the tracer states an instruction's SOURCE registers,
                    and it is read structurally rather than scraped out of the
                    rendered disassembly.

legacy and disasm are joined on the entry sequence number (``ENTRY 0002`` <->
``seq=2``); raw is joined on (template id, index within the template), which
the disasm block header states as ``BB <id>``.

SOURCE VALUES.  The wire carries none -- ``format.rst`` §5.4 is explicit that
"source-register values are not emitted on the wire; consumers reconstruct
them from a regfile that the initial-state REGFILE records and the DST_REG
snapshots collectively define".  This module performs exactly that
reconstruction, in execution order, and hands each instruction the operand
values a conforming consumer would have had.  Comparing THOSE against the
reference's real reads is a genuine execution check of the tracer's published
values, not a restatement of them: a wrong destination value, a missing width,
or a wrong source-register NAME all surface as a wrong operand.

Author: Maccoy Merrell.
"""
import collections
import re
import subprocess

_ENTRY_L = re.compile(r'^ENTRY\s+(\d+)\s')
_REG_L = re.compile(
    r'^\s*insn\[(\d+)\]\s+dst\[(\d+)\]\s+(\S+?)=0x([0-9a-f]+):w=(\d+)\s*$')
_MEM_L = re.compile(
    r'^\s*insn\[(\d+)\]\s+(load|store)=0x([0-9a-f]+):data=0x([0-9a-f]+)'
    r':size=(\d+)\s*$')

_BBHDR = re.compile(r'^;\s*-+\s*BB\s+(\d+)\s+entry\s+pc=0x([0-9a-f]+)\s+'
                    r'insns=(\d+)\s+seq=(\d+)\b')
_INSN_L = re.compile(r'^0x([0-9a-f]+)\s*(?:<[^>]*>)?:\s+'
                     r'((?:[0-9a-f]{2} )+)\s')


class Insn(object):
    """One executed instruction as the tracer recorded it."""

    __slots__ = ('pc', 'bits', 'nbytes', 'entry', 'idx',
                 'writes', 'srcs', 'src_vals', 'loads', 'stores')

    def __init__(self, pc, bits, nbytes, entry, idx):
        self.pc = pc
        self.bits = bits
        self.nbytes = nbytes
        self.entry = entry
        self.idx = idx
        self.writes = []      # [(REG_NAME, value, width_bytes)]
        self.srcs = []        # [REG_NAME]           -- from the template
        self.src_vals = {}    # REG_NAME -> (value, width) | None (unknown)
        self.loads = []       # [(addr, data, width_bytes)]
        self.stores = []      # [(addr, data, width_bytes)]

    def __repr__(self):
        return 'Insn(pc=0x%x bits=0x%x w=%r s=%r ld=%r st=%r)' % (
            self.pc, self.bits, self.writes, self.srcs,
            self.loads, self.stores)


#: raw-format template dictionary rows.
_RAW_TPL = re.compile(r'\btemplate_id=(\d+)\s+start_pc=0x([0-9a-f]+)')
_RAW_INSN = re.compile(r'\binsn\[(\d+)\]\s+pc=0x([0-9a-f]+)\b')
_RAW_REGS = re.compile(r'\bsrc=\[(.*?)\]\s+dst=\[(.*?)\]')
_RAW_NAME = re.compile(r'\((REG_[A-Z0-9_]+)\)')

#: the tracer's REGFILE seed record, as --format=legacy prints it.
_RF_HDR = re.compile(r'^REGFILE\s+thread=(\d+)\s+n=(\d+)')
_RF_ROW = re.compile(r'^\s+(REG_\S+)\s+([0-9a-f]+)\s*$')


def _run(decode, trace, fmt):
    p = subprocess.run([decode, '--format=' + fmt, trace],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError('cst_decode --format=%s exit %d: %s'
                           % (fmt, p.returncode,
                              p.stderr.decode('utf-8', 'replace')[-800:]))
    return p.stdout.decode('utf-8', 'replace').splitlines()


def parse(decode, trace):
    """(decode binary, .cst path) -> [Insn] in execution order.

    Raises when the trace carries wrong-path blocks: WP is not part of the
    architectural stream the reference executes, so silently mixing it in
    would compare two different things.
    """
    # ---- skeleton: entry -> [(pc, bits, nbytes)], from the disasm view
    order = []                       # [(tid, seq, [ (pc,bits,nbytes), ... ])]
    cur = None
    for line in _run(decode, trace, 'disasm'):
        h = _BBHDR.match(line)
        if h:
            cur = (int(h.group(1)), int(h.group(4)), [])
            order.append(cur)
            continue
        if line.startswith(';'):
            if ' WP ' in line or line.startswith('; ----- WP'):
                raise RuntimeError('trace carries wrong-path blocks; '
                                   'run the tracer with wp=0')
            continue
        m = _INSN_L.match(line)
        if m and cur is not None:
            by = bytes(int(b, 16) for b in m.group(2).split())
            cur[2].append((int(m.group(1), 16),
                           int.from_bytes(by, 'little'), len(by)))

    # ---- SOURCE registers: the template dictionary, keyed the way the
    # disasm block header keys it (BB <template id>, index within the block).
    tsrc = _template_srcs(decode, trace)

    insns = {}                       # (seq, idx) -> Insn
    flat = []
    for tid, seq, lst in order:
        for i, (pc, bits, nb) in enumerate(lst):
            ins = Insn(pc, bits, nb, seq, i)
            ins.srcs = list(tsrc.get((tid, i), ()))
            insns[(seq, i)] = ins
            flat.append(ins)

    # ---- values: the legacy CP delta stream
    legacy = _run(decode, trace, 'legacy')
    seq = None
    for line in legacy:
        e = _ENTRY_L.match(line)
        if e:
            seq = int(e.group(1))
            continue
        if seq is None:
            continue
        m = _REG_L.match(line)
        if m:
            ins = insns.get((seq, int(m.group(1))))
            if ins is not None:
                ins.writes.append((m.group(3), int(m.group(4), 16),
                                   int(m.group(5))))
            continue
        m = _MEM_L.match(line)
        if m:
            ins = insns.get((seq, int(m.group(1))))
            if ins is not None:
                rec = (int(m.group(3), 16), int(m.group(4), 16),
                       int(m.group(5)))
                (ins.loads if m.group(2) == 'load' else ins.stores).append(rec)

    # ---- SOURCE values, by the reconstruction format.rst §5.4 mandates.
    seed = _regfile_seed(legacy)
    prov = _reconstruct_sources(flat, seed)
    prov['seed-registers'] = len(seed)
    return flat, prov

def _template_srcs(decode, trace):
    """(template id, index) -> [source GenericRegId names], from --format=raw.

    Read structurally out of the template dictionary rather than scraped from
    the rendered disassembly: the render reorders operands, folds immediates
    in, and decorates memory operands, none of which the source SET should
    depend on.
    """
    out, tid = {}, None
    idx = None
    for line in _run(decode, trace, 'raw'):
        m = _RAW_TPL.search(line)
        if m:
            tid, idx = int(m.group(1)), None
            continue
        m = _RAW_INSN.search(line)
        if m:
            idx = int(m.group(1))
            continue
        m = _RAW_REGS.search(line)
        if m and tid is not None and idx is not None:
            out[(tid, idx)] = _RAW_NAME.findall(m.group(1))
            idx = None
    return out


def _regfile_seed(lines):
    """The tracer's per-thread REGFILE record -> {REG_NAME: (value, width)}.

    format.rst §4.6: bytes are LITTLE-ENDIAN and `width` is the snapshot
    byte count, which --format=legacy prints as the raw byte string.  Only
    the first record is read: this leg runs single-threaded guests, and a
    second thread's seed would belong to a different register model.
    """
    seed, taking = {}, False
    for line in lines:
        if _RF_HDR.match(line):
            if seed:
                break
            taking = True
            continue
        if taking:
            m = _RF_ROW.match(line)
            if not m:
                if line.startswith('ENTRY') or line.startswith('BODY'):
                    break
                continue
            raw = m.group(2)
            by = bytes.fromhex(raw)
            seed[m.group(1)] = (int.from_bytes(by, 'little'), len(by))
    return seed


#: registers whose value is architecturally fixed and therefore known without
#: any snapshot at all.  Stated, not assumed: x0 reads as zero on RISC-V.
_ARCH_CONST = {'REG_ZERO': (0, 8)}


def _reconstruct_sources(flat, seed):
    """Fill `src_vals` by replaying the trace the way a consumer must.

    format.rst §5.4 defines the register model as "the initial-state REGFILE
    records and the DST_REG snapshots collectively"; this is that model, run
    forward in execution order.  A register the model cannot value yet maps
    to None -- an honest "the trace has not said", never a silent 0, because
    a silent 0 would agree with the reference on every zeroed register and
    manufacture a pass.

    A destination published with WIDTH 0 carries no value, so it INVALIDATES
    the model's entry rather than updating it: after such a write the trace
    genuinely no longer states what the register holds.
    """
    shadow = dict(seed)
    shadow.update(_ARCH_CONST)
    # PROVENANCE.  A register's operand value can come from the REGFILE seed
    # or from a destination snapshot this trace already published, and the two
    # are not equally trustworthy: a seed that is never consulted is a claim
    # nobody has tested, and reporting a source-value rate without saying
    # which of the two produced it is exactly the enumerated-zero shape this
    # project rejects.  So it is counted.
    prov = collections.Counter()
    from_seed = set(seed) - set(_ARCH_CONST)
    for ins in flat:
        vals = {}
        for n in ins.srcs:
            if n in _ARCH_CONST:
                vals[n] = _ARCH_CONST[n]
                prov['arch-const'] += 1
                continue
            vals[n] = shadow.get(n)
            if vals[n] is None:
                prov['unknown'] += 1
            elif n in from_seed:
                prov['seed'] += 1
            else:
                prov['dst-snapshot'] += 1
        ins.src_vals = vals
        for n, v, w in ins.writes:
            if n in _ARCH_CONST:
                continue
            from_seed.discard(n)
            if w == 0:
                shadow.pop(n, None)
            else:
                shadow[n] = (v, w)
    return prov
