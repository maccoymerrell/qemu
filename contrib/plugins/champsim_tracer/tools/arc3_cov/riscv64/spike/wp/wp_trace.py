"""
The trace side of the riscv64 WRONG-PATH execution cross-check.

The correct-path leg (``../tracer_log.py``) REFUSES a trace that carries
wrong-path blocks, and that refusal is exactly the hole this module exists to
close: no WP golden exists on any ISA, so a wrong-path divergence is invisible
today, and the WP arm is a large fraction of what the tracer emits.

WHAT AN EXCURSION IS HERE
=========================
The unit is the whole WP CHAIN hanging off one CP entry, not one WP block.
``emit_finalized_bb`` kicks a single synchronous excursion that runs until the
``wpdepth`` budget exhausts; the decoder renders it as ``wp[0] wp[1] ...``
because a chain is cut into basic blocks, not because each block is an
independent event.  Comparing per block would compare N starting states the
tracer never claimed.  So an ``Excursion`` is the concatenation, and its
starting state is the architectural state at the END of its CP entry.

THE STARTING STATE, AND WHY IT IS THE INTERESTING PART
======================================================
``format.rst`` §5.4 says the consumer reconstructs the register file from the
REGFILE seed plus the destination snapshots.  This module performs exactly
that reconstruction and then hands it to a real simulator.  Three things can
happen, and the taxonomy keeps them apart:

  * the reconstruction is complete and Spike agrees      -> COVERED
  * the reconstruction is complete and Spike disagrees   -> a WP DEFECT
  * the reconstruction cannot be built from the wire     -> a RECONSTRUCTION
                                                            GAP, which is a
                                                            finding about the
                                                            FORMAT, not about
                                                            the excursion

Only CORRECT-PATH effects update the architectural state.  A wrong-path write
is discarded by the machine at the end of the excursion, so replaying it into
the shadow would seed the next excursion from a state that never existed.

MEMORY.  The wire states memory three ways: the guest image the ELF loaded,
the DATA every correct-path load returned, and the DATA every correct-path
store wrote.  All three are replayed, in order, and an address none of them
established is recorded as unestablished -- so a wrong-path load that reads
one is reported as a reconstruction gap rather than as a wrong datum.

Author: Maccoy Merrell.
"""
import collections
import re
import subprocess

# ----------------------------------------------------------------- disasm view
_BBHDR = re.compile(r'^;\s*-+\s*BB\s+(\d+)\s+entry\s+pc=0x([0-9a-f]+)\s+'
                    r'insns=(\d+)\s+seq=(\d+)\b')
_WPHDR = re.compile(r'^;\s*\.+\s*wp\[(\d+)\]\s+BB\s+(\d+)\s+n_insns=(\d+)')
_INSN_L = re.compile(r'^0x([0-9a-f]+)\s*(?:<[^>]*>)?:\s+'
                     r'((?:[0-9a-f]{2} )+)\s')
#: The byte column is PADDED, so on a fixed-width ISA the encoding is always
#: followed by two spaces or more and the pattern above suffices.  A
#: variable-length ISA overflows that column: cst_decode prints a 9-byte
#: x86 instruction as `66 41 0f d6 a7 e0 01 00 00 mov`, with ONE space, and
#: the pattern above then matches NOTHING -- the instruction vanished from
#: the reconstruction silently, which is how an excursion came to be
#: rebuilt with an instruction missing from the middle of it.
#:
#: The relaxed pattern is tried ONLY after the padded one fails, because it
#: cannot tell a two-hex-character MNEMONIC (mipsel has `bc`) from another
#: encoding byte.  Ordering it second means a fixed-width ISA never reaches
#: it and the ambiguity cannot arise where it would matter.
_INSN_L_TIGHT = re.compile(r'^0x([0-9a-f]+)\s*(?:<[^>]*>)?:\s+'
                           r'((?:[0-9a-f]{2} )+)(?=[a-z])')

# ----------------------------------------------------------------- legacy view
_ENTRY_L = re.compile(r'^ENTRY\s+(\d+)\s')
_WPBLK_L = re.compile(r'^\s+wp\[(\d+)\]\s+template=BB(\d+)\s+n_insns=(\d+)')
_CPBLK_L = re.compile(r'^\s+cp:\s*$')
_REG_L = re.compile(
    r'^\s*insn\[(\d+)\]\s+dst\[(\d+)\]\s+(\S+?)=0x([0-9a-f]+):w=(\d+)\s*$')
_MEM_L = re.compile(
    r'^\s*insn\[(\d+)\]\s+(load|store)=0x([0-9a-f]+)'
    r'(?::data=0x([0-9a-f]+))?(?::size=(\d+))?\s*$')

_RF_HDR = re.compile(r'^REGFILE\s+thread=(\d+)\s+n=(\d+)')
_RF_ROW = re.compile(r'^\s+(REG_\S+)\s+([0-9a-f]+)\s*$')

_RAW_TPL = re.compile(r'\btemplate_id=(\d+)\s+start_pc=0x([0-9a-f]+)')
_RAW_INSN = re.compile(r'\binsn\[(\d+)\]\s+pc=0x([0-9a-f]+)\b')
_RAW_REGS = re.compile(r'\bsrc=\[(.*?)\]\s+dst=\[(.*?)\]')
_RAW_NAME = re.compile(r'\((REG_[A-Z0-9_]+)\)')


class Insn(object):
    """One instruction as the tracer recorded it, CP or WP alike."""

    __slots__ = ('pc', 'bits', 'nbytes', 'writes', 'srcs', 'loads', 'stores')

    def __init__(self, pc, bits, nbytes):
        self.pc = pc
        self.bits = bits
        self.nbytes = nbytes
        self.writes = []          # [(REG_NAME, value, width_bytes)]
        self.srcs = []            # [REG_NAME]  from the template dictionary
        self.loads = []           # [(addr, data|None, width|None)]
        self.stores = []

    def __repr__(self):
        return 'Insn(pc=0x%x w=%r ld=%r st=%r)' % (
            self.pc, self.writes, self.loads, self.stores)


class Excursion(object):
    """One wrong-path excursion: where it started, and what it did."""

    __slots__ = ('seq', 'start_pc', 'insns', 'regs', 'unknown_regs',
                 'mem', 'mem_src', 'blocks', 'cp_index')

    def __init__(self, seq, start_pc):
        self.seq = seq
        self.start_pc = start_pc
        self.insns = []
        self.regs = {}            # REG_NAME -> (value, width) -- the state
        self.unknown_regs = []    # names the model could not value
        self.mem = {}             # addr -> byte, the reconstructed image
        self.mem_src = {}         # addr -> 'elf' | 'cp-load' | 'cp-store'
        self.blocks = []          # [(wp index, n_insns)] for reporting
        self.cp_index = 0         # correct-path instructions retired before it

    def __repr__(self):
        return 'Excursion(seq=%d pc=0x%x n=%d)' % (
            self.seq, self.start_pc, len(self.insns))


def _run(decode, trace, fmt):
    p = subprocess.run([decode, '--format=' + fmt, trace],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError('cst_decode --format=%s exit %d: %s'
                           % (fmt, p.returncode,
                              p.stderr.decode('utf-8', 'replace')[-800:]))
    return p.stdout.decode('utf-8', 'replace').splitlines()


def _template_srcs(decode, trace):
    """(template id, index) -> [source GenericRegId names] from --format=raw."""
    out, tid, idx = {}, None, None
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


def _skeleton(decode, trace):
    """--format=disasm -> [(seq, cp_tid, [cp insn], [(wp idx, tid, [insn])])].

    The disasm view is the only one that carries a PC per instruction, so it
    is what turns the legacy stream's ``insn[i]`` index into an address.
    """
    order, cur, wp = [], None, None
    for line in _run(decode, trace, 'disasm'):
        h = _BBHDR.match(line)
        if h:
            cur = {'seq': int(h.group(4)), 'tid': int(h.group(1)),
                   'cp': [], 'wp': []}
            order.append(cur)
            wp = None
            continue
        h = _WPHDR.match(line)
        if h and cur is not None:
            wp = {'idx': int(h.group(1)), 'tid': int(h.group(2)), 'insns': []}
            cur['wp'].append(wp)
            continue
        if line.startswith(';'):
            continue
        m = _INSN_L.match(line) or _INSN_L_TIGHT.match(line)
        if m and cur is not None:
            by = bytes(int(b, 16) for b in m.group(2).split())
            rec = (int(m.group(1), 16), int.from_bytes(by, 'little'), len(by))
            (wp['insns'] if wp is not None else cur['cp']).append(rec)
    return order


def _effects(decode, trace):
    """--format=legacy -> {seq: {'cp': eff, wpidx: eff}} and the REGFILE seed.

    ``eff`` is {insn index: (writes, loads, stores)}.  The legacy stream is
    the only place the destination VALUES appear, and it states them for the
    wrong-path blocks exactly as it does for the correct path.
    """
    lines = _run(decode, trace, 'legacy')
    per = {}
    seq, blk = None, None
    seed, taking = {}, False
    for line in lines:
        if _RF_HDR.match(line):
            taking = not seed
            continue
        if taking:
            m = _RF_ROW.match(line)
            if m:
                by = bytes.fromhex(m.group(2))
                seed[m.group(1)] = (int.from_bytes(by, 'little'), len(by))
                continue
            if line.startswith('ENTRY') or line.startswith('BODY'):
                taking = False
            elif line.strip():
                continue
        e = _ENTRY_L.match(line)
        if e:
            seq = int(e.group(1))
            per[seq] = {}
            blk = None
            continue
        if seq is None:
            continue
        if _CPBLK_L.match(line):
            blk = 'cp'
            per[seq][blk] = {}
            continue
        m = _WPBLK_L.match(line)
        if m:
            blk = int(m.group(1))
            per[seq][blk] = {}
            continue
        if blk is None:
            continue
        m = _REG_L.match(line)
        if m:
            slot = per[seq][blk].setdefault(int(m.group(1)), ([], [], []))
            slot[0].append((m.group(3), int(m.group(4), 16), int(m.group(5))))
            continue
        m = _MEM_L.match(line)
        if m:
            slot = per[seq][blk].setdefault(int(m.group(1)), ([], [], []))
            data = int(m.group(4), 16) if m.group(4) else None
            size = int(m.group(5)) if m.group(5) else None
            rec = (int(m.group(3), 16), data, size)
            (slot[1] if m.group(2) == 'load' else slot[2]).append(rec)
    return per, seed


#: architecturally fixed, and therefore known with no snapshot at all.
_ARCH_CONST = {'REG_ZERO': (0, 8)}


def build(decode, trace, image):
    """(cst_decode, .cst, {addr: byte} image) -> ([Excursion], [CP Insn], stats).

    Walks the body stream in order, maintaining the architectural register
    file and memory a conforming consumer would have, and snapshots both at
    every wrong-path kick.
    """
    skel = _skeleton(decode, trace)
    eff, seed = _effects(decode, trace)
    tsrc = _template_srcs(decode, trace)

    shadow = dict(seed)
    shadow.update(_ARCH_CONST)
    mem = dict(image)
    mem_src = dict((a, 'elf') for a in image)
    stats = collections.Counter()
    stats['seed-registers'] = len(seed)
    out = []
    cp_stream = []                # every correct-path instruction, in order

    for blkinfo in skel:
        seq = blkinfo['seq']
        e = eff.get(seq, {})

        # -------- correct path: build the instructions, then COMMIT them.
        cp_ins = []
        for i, (pc, bits, nb) in enumerate(blkinfo['cp']):
            ins = Insn(pc, bits, nb)
            ins.srcs = list(tsrc.get((blkinfo['tid'], i), ()))
            w, ld, st = e.get('cp', {}).get(i, ([], [], []))
            ins.writes, ins.loads, ins.stores = w, ld, st
            cp_ins.append(ins)

        for ins in cp_ins:
            for addr, data, size in ins.loads:
                if data is None or size is None:
                    stats['cp-load-without-data'] += 1
                    continue
                for k in range(size):
                    if addr + k not in mem:
                        mem[addr + k] = (data >> (8 * k)) & 0xff
                        mem_src[addr + k] = 'cp-load'
            for addr, data, size in ins.stores:
                if data is None or size is None:
                    stats['cp-store-without-data'] += 1
                    continue
                for k in range(size):
                    mem[addr + k] = (data >> (8 * k)) & 0xff
                    mem_src[addr + k] = 'cp-store'
            for n, v, w in ins.writes:
                if n in _ARCH_CONST:
                    continue
                if w == 0:
                    shadow.pop(n, None)         # published with no value
                else:
                    shadow[n] = (v, w)
            cp_stream.append(ins)

        # -------- wrong path: the chain as ONE excursion, seeded from HERE.
        if not blkinfo['wp']:
            continue
        wp_ins, blocks = [], []
        for wb in blkinfo['wp']:
            weff = e.get(wb['idx'], {})
            blocks.append((wb['idx'], len(wb['insns'])))
            for i, (pc, bits, nb) in enumerate(wb['insns']):
                ins = Insn(pc, bits, nb)
                ins.srcs = list(tsrc.get((wb['tid'], i), ()))
                w, ld, st = weff.get(i, ([], [], []))
                ins.writes, ins.loads, ins.stores = w, ld, st
                wp_ins.append(ins)
        if not wp_ins:
            stats['excursion-empty'] += 1
            continue
        ex = Excursion(seq, wp_ins[0].pc)
        ex.cp_index = len(cp_stream)
        ex.insns = wp_ins
        ex.blocks = blocks
        ex.regs = dict(shadow)
        ex.mem = dict(mem)
        ex.mem_src = dict(mem_src)
        out.append(ex)
        stats['excursions'] += 1
        stats['wp-insns'] += len(wp_ins)
    stats['cp-insns'] = len(cp_stream)
    return out, cp_stream, stats


def dedupe(excursions):
    """Collapse excursions whose injected state is byte-identical.

    Two excursions with the same start PC, the same register file and the same
    bytes under every address the excursion reads are the SAME experiment: the
    simulator is deterministic, so running the second adds a repeat, not
    coverage.  The key is exact and the collapse is counted, so the report can
    state how many dynamic excursions each distinct one stands for.
    """
    seen = {}
    order = []
    for ex in excursions:
        key = (ex.start_pc,
               tuple(sorted((k, v) for k, v in ex.regs.items())),
               tuple((i.pc, i.bits) for i in ex.insns),
               tuple(sorted(a for i in ex.insns for (a, _d, _s) in i.loads)),
               tuple(sorted((a, ex.mem.get(a))
                            for i in ex.insns
                            for (ad, _d, s) in i.loads
                            for a in range(ad, ad + (s or 0)))))
        if key in seen:
            seen[key][1] += 1
            continue
        seen[key] = [ex, 1]
        order.append(key)
    return [(seen[k][0], seen[k][1]) for k in order]
