"""
The tracer side of the riscv64 execution cross-check: cst_decode's own output,
parsed back into per-instruction records with the same shape spike_ref.Insn has.

Two cst_decode formats are read, because neither alone carries both halves of
what a 1-to-1 execution comparison needs:

  --format=legacy   the CP delta stream: per entry, ``insn[i] dst[k] REG=..``
                    and ``insn[i] load=..:data=..:size=..``.  Machine-readable,
                    and the only place the VALUES appear.
  --format=disasm   the same entries with each instruction's PC and raw bytes
                    on its own line, which is what turns the legacy stream's
                    ``insn[i]`` index into an address the reference can be
                    aligned against.

The two are joined on the entry sequence number (``ENTRY 0002`` <-> ``seq=2``).

The CP delta stream is DESTINATION-ORIENTED -- it carries ``dst[k]`` and no
``src`` -- which is the same orientation spike's commit log has.  Source
registers live in the template, not in the body, and are the static leg's
business.

Author: Maccoy Merrell.
"""
import re
import subprocess

_ENTRY_L = re.compile(r'^ENTRY\s+(\d+)\s')
_REG_L = re.compile(
    r'^\s*insn\[(\d+)\]\s+dst\[(\d+)\]\s+(\S+?)=0x([0-9a-f]+):w=(\d+)\s*$')
_MEM_L = re.compile(
    r'^\s*insn\[(\d+)\]\s+(load|store)=0x([0-9a-f]+):data=0x([0-9a-f]+)'
    r':size=(\d+)\s*$')

_BBHDR = re.compile(r'^;\s*-+\s*BB\s+\d+\s+entry\s+pc=0x([0-9a-f]+)\s+'
                    r'insns=(\d+)\s+seq=(\d+)\b')
_INSN_L = re.compile(r'^0x([0-9a-f]+)\s*(?:<[^>]*>)?:\s+'
                     r'((?:[0-9a-f]{2} )+)\s')


class Insn(object):
    """One executed instruction as the tracer recorded it."""

    __slots__ = ('pc', 'bits', 'nbytes', 'entry', 'idx',
                 'writes', 'loads', 'stores')

    def __init__(self, pc, bits, nbytes, entry, idx):
        self.pc = pc
        self.bits = bits
        self.nbytes = nbytes
        self.entry = entry
        self.idx = idx
        self.writes = []      # [(REG_NAME, value, width_bytes)]
        self.loads = []       # [(addr, data, width_bytes)]
        self.stores = []      # [(addr, data, width_bytes)]

    def __repr__(self):
        return 'Insn(pc=0x%x bits=0x%x w=%r ld=%r st=%r)' % (
            self.pc, self.bits, self.writes, self.loads, self.stores)


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
    order = []                       # [(seq, [ (pc,bits,nbytes), ... ])]
    cur = None
    for line in _run(decode, trace, 'disasm'):
        h = _BBHDR.match(line)
        if h:
            cur = (int(h.group(3)), [])
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
            cur[1].append((int(m.group(1), 16),
                           int.from_bytes(by, 'little'), len(by)))

    insns = {}                       # (seq, idx) -> Insn
    flat = []
    for seq, lst in order:
        for i, (pc, bits, nb) in enumerate(lst):
            ins = Insn(pc, bits, nb, seq, i)
            insns[(seq, i)] = ins
            flat.append(ins)

    # ---- values: the legacy CP delta stream
    seq = None
    for line in _run(decode, trace, 'legacy'):
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
    return flat
