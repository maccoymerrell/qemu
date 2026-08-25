"""
The reference side of the x86_64 WRONG-PATH execution cross-check.

gem5 decodes and executes x86-64 with its own decoder and its own semantics;
no part of QEMU is involved.  That is the property this leg needs and the
reason gem5 rather than PIN is the reference here: **PIN is explicitly not an
execution reference for the wrong path** -- it observes only what the machine
really retired, and a wrong-path excursion is by construction a path the
machine did not take.

WHAT THE LOG CARRIES, AND WHAT HAD TO BE ADDED
==============================================
Stock ``--debug-flags=Exec`` prints the PC, the micro-op disassembly, the
OpClass, one data word ``D=`` and an effective address ``A=``.  The gem5 this
harness drives is patched (``../gem5.patch``) to add ``S=``/``MF=`` (access
width and request flags), ``RW=`` (EVERY destination with its own value),
``MD=`` (the bytes a store moved) and ``SR=``/``DR=`` (the register operands).

MICRO-OPS
=========
gem5 cracks x86 hard: ``jnz`` is ``rdip t1 ; limm t2 ; wrip t1, t2``, and a
read-modify-write is three micro-ops.  The tracer's record is per
ARCHITECTURAL instruction, so the micro-ops of one macro-op are folded back
together.  A new architectural instruction starts when the line carries no
micro-PC, or when its micro-PC is not one more than the previous line's --
which is what a loop back to the same PC looks like, and is why the PC alone
cannot delimit them.

INSTRUCTION LENGTH INSTEAD OF INSTRUCTION BITS
==============================================
The riscv64 leg compares the ENCODING, because Spike prints it.  gem5 does
not print an encoding at all, so on this leg the equivalent fact is the
instruction's LENGTH -- which on a variable-length ISA is the substantive
question anyway: do the two decoders agree about where the instruction ends?
Two independent sources in gem5's own output give it:

  * a control transfer's ``rdip`` micro-op publishes the fall-through address
    (measured: ``0x40101d`` prints ``D=0x40101f`` for a two-byte ``jnz``), so
    length = that minus the PC;
  * for anything else, the next macro-op's PC when the flow is sequential.

Where neither is available -- the last instruction in the log -- the length is
UNKNOWN, and it is reported as a named reference limit, never as agreement.

Author: Maccoy Merrell.
"""
import collections
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import x86_vocab as V                                          # noqa: E402

# ``  <tick>: system.cpu: T0 : 0x401000. 0 :   MOV_R_I : limm ... ``
_LINE = re.compile(
    r'^\s*\d+:\s+\S+:\s+(?:A\d+\s+)?(?:T(\d+)\s+:\s+)?'
    r'0x([0-9a-f]+)(?:\.\s*(\d+))?\s+:\s+(.*)$')

_D = re.compile(r'\sD=(0x[0-9a-fA-F]+)')
_A = re.compile(r'\sA=0x([0-9a-f]+)')
_S = re.compile(r'\sS=(\d+)')
_MF = re.compile(r'\sMF=0x([0-9a-f]+)')
_RW = re.compile(r'\sRW=\[([^\]]*)\]')
_SR = re.compile(r'\sSR=\[([^\]]*)\]')
_MD = re.compile(r'\sMD=0x([0-9a-f]+)')
_FL = re.compile(r'\s\sflags=\(([^)]*)\)')

#: the direction bits the patched gem5 sets on the request flags.
ARC3_READ = 0x4000000000000000
ARC3_WRITE = 0x8000000000000000
ARC3_AMO = 0x2000000000000000


class Insn(object):
    """One executed architectural x86-64 instruction as gem5 recorded it."""

    __slots__ = ('pc', 'length', 'writes', 'srcs', 'loads', 'stores',
                 'uops', 'disas', 'unmapped', 'ctrl', 'cc', 'rflags',
                 'rflags_mask', 'syscall', 'full_written', 'raw_reads',
                 'raw_writes', 'top_before', 'top_after', 'x87_valued',
                 'half_seen', 'ufp')

    def __init__(self, pc):
        self.pc = pc
        self.length = None       # None = the reference cannot say
        self.writes = {}         # generic id -> value
        self.srcs = set()
        self.loads = []          # [(addr, data|None, width)]
        self.stores = []
        self.uops = 0
        self.disas = ''
        self.unmapped = []
        self.ctrl = False
        self.cc = {}             # gem5 cc index -> value, this instruction
        self.rflags = None       # the running word AFTER this instruction
        self.rflags_mask = 0
        self.syscall = False
        self.full_written = set()   # gem5 (cls, idx) written at FULL width
        self.raw_reads = []         # [(cls, idx, uop_seq, named_in_text)]
        self.raw_writes = []        # [(cls, idx, value|None, uop_seq)]
        self.half_seen = set()      # XMM halves this macro-op has written
        self.ufp = None             # last micro-op FP scratch value written
        self.top_before = None
        self.top_after = None
        self.x87_valued = {}        # generic id -> gem5's 64-bit datum

    def __repr__(self):
        return 'g5x86(pc=0x%x len=%s uops=%d w=%r ld=%r st=%r)' % (
            self.pc, self.length, self.uops, self.writes,
            self.loads, self.stores)


def _split_tokens(field):
    for tok in field.split(','):
        tok = tok.strip()
        if tok:
            yield tok


def parse(logpath, sel=None, dropped=None, folded=None, merged=None):
    """(gem5 exec log) -> [Insn] in execution order, micro-ops folded.

    ``sel`` is a predicate on the PC; the injection prologue is excluded BY
    ADDRESS through it, never by counting instructions.  ``dropped`` counts
    every reference register put aside as non-architectural, ``folded``
    every contiguous access pair merged back into one instruction-level
    access, and ``merged`` every micro-op MERGE READ suppressed -- so an
    exclusion that stops matching cannot go unnoticed.
    """
    if dropped is None:
        dropped = collections.Counter()
    if folded is None:
        folded = collections.Counter()
    if merged is None:
        merged = collections.Counter()
    out = []
    cur = None
    prev_upc = None
    prev_pc = None
    for line in open(logpath, 'r', errors='replace'):
        m = _LINE.match(line)
        if not m:
            continue
        pc = int(m.group(2), 16)
        upc = int(m.group(3)) if m.group(3) is not None else None
        rest = m.group(4)
        new_insn = (cur is None or prev_pc != pc or upc is None or
                    prev_upc is None or upc != prev_upc + 1)
        prev_pc, prev_upc = pc, upc
        if new_insn:
            cur = Insn(pc)
            out.append(cur)
        cur.uops += 1
        # gem5 prints a CRACKED instruction as
        #     <MACRO_NAME> : <micro-op disassembly> : <OpClass> : <fields>
        # and an uncracked one as
        #     <disassembly> : <OpClass> : <fields>
        # The micro-PC is what tells the two apart.  Reading field 0 in both
        # cases makes every micro-op's disassembly read as its MACRO name,
        # which is how the `rdip` fall-through -- the only source of an
        # instruction LENGTH on this ISA -- went missing.
        parts = rest.split(' : ')
        head = (parts[1] if (upc is not None and len(parts) > 2)
                else parts[0]).strip()
        if not cur.disas:
            cur.disas = head

        mfl = _FL.search(rest)
        fset = set(mfl.group(1).split('|')) if mfl else set()
        if 'IsControl' in fset:
            cur.ctrl = True
        if 'IsSyscall' in fset or head.startswith('syscall'):
            cur.syscall = True

        # ---- the instruction's LENGTH, from the fall-through address the
        # `rdip` micro-op publishes.  Read from the micro-op's own name so a
        # different micro-op that happens to carry a D= cannot be mistaken
        # for it.
        if head.startswith('rdip'):
            md = _D.search(rest)
            if md:
                nxt = int(md.group(1), 16)
                if nxt > pc and nxt - pc <= 15:
                    cur.length = nxt - pc

        ops = head.split(None, 1)
        optext = ops[1] if len(ops) > 1 else ''
        first_op = optext.split(',')[0].strip()
        after_comma = optext.split(',', 1)[1] if ',' in optext else ''

        # ---- destinations, from the patched sidecar.
        mrw = _RW.search(rest)
        if mrw:
            for tok in _split_tokens(mrw.group(1)):
                lhs, _, rhs = tok.rpartition('=')
                cls, _, idx = lhs.rpartition(':')
                try:
                    i = int(idx)
                except ValueError:
                    cur.unmapped.append(lhs)
                    continue
                g = V.to_generic(cls, i)
                if g is None:
                    cur.unmapped.append(lhs)
                    continue
                if g is V.INTERNAL:
                    dropped[lhs] += 1
                    # The micro-op FP scratch is not architectural state, but
                    # on an x87 LOAD it carries the converted datum before
                    # the destination write publishes it -- which is the only
                    # way to tell a reference PUBLICATION defect from a real
                    # value disagreement.  Kept as evidence, never as a fact.
                    if cls == 'floating_point' and 40 <= i < 48 \
                            and rhs != '?':
                        cur.ufp = int(rhs, 16)
                    continue
                val = None if rhs == '?' else int(rhs, 16)
                # A write is FULL-WIDTH when the destination operand carries
                # the register's 64-bit spelling.  That is the whole of the
                # merge-read adjudication, so it comes from gem5's own text.
                if cls == 'integer' and i in V.INT_FULL_NAME:
                    if first_op == V.INT_FULL_NAME[i]:
                        cur.full_written.add((cls, i))
                elif cls == 'floating_point' and (i < 8 or 48 <= i < 56):
                    cur.full_written.add((cls, i))
                elif V.xmm_half(cls, i) is not None:
                    # An XMM half on its own is a PARTIAL write; the pair is
                    # a full one.  `movq %rax, %xmm4` is two micro-ops --
                    # `mov2fp %xmm4_low` then `lfpimm %xmm4_high, 0` -- and
                    # architecturally it overwrites the whole register, so
                    # the low half's merge read is gem5's lowering and not a
                    # dependency.  Recorded per half and resolved once the
                    # macro-op is complete.
                    other = i ^ 1
                    if (cls, other) in cur.half_seen:
                        cur.full_written.add((cls, i))
                        cur.full_written.add((cls, other))
                    cur.half_seen.add((cls, i))
                if cls == 'miscellaneous' and i == 191 and val is not None:
                    cur.top_after = val & 7
                cur.raw_writes.append((cls, i, val, cur.uops))
                if cls == 'condition_code' and val is not None:
                    cur.cc[i] = val

        # ---- the memory access.
        ma, ms, mf = _A.search(rest), _S.search(rest), _MF.search(rest)
        if ma:
            addr = int(ma.group(1), 16)
            size = int(ms.group(1)) if ms else 0
            fl = int(mf.group(1), 16) if mf else 0
            mmd = _MD.search(rest)
            sdata = int(mmd.group(1), 16) if mmd else None
            valued = [v for (_c, _i, v, _u) in cur.raw_writes
                      if v is not None]
            ldata = valued[-1] if (len(valued) == 1 and 0 < size <= 8) \
                else None
            if 'IsAtomic' in fset:
                cur.loads.append((addr, ldata, size))
                cur.stores.append((addr, sdata, size))
            elif 'IsStore' in fset:
                cur.stores.append((addr, sdata, size))
            elif 'IsLoad' in fset:
                cur.loads.append((addr, ldata, size))
            elif fl & ARC3_WRITE:
                cur.stores.append((addr, sdata, size))
            elif fl & (ARC3_READ | ARC3_AMO):
                cur.loads.append((addr, ldata, size))
            else:
                cur.loads.append((addr, ldata, size))
                cur.unmapped.append('MEMDIR?')

        msr = _SR.search(rest)
        if msr:
            for tok in _split_tokens(msr.group(1)):
                cls, _, idx = tok.rpartition(':')
                try:
                    i = int(idx)
                except ValueError:
                    cur.unmapped.append(tok)
                    continue
                g = V.to_generic(cls, i)
                if g is None:
                    cur.unmapped.append(tok)
                    continue
                if g is V.INTERNAL:
                    dropped[tok] += 1
                    continue
                # Does the micro-op NAME this register as a source in its own
                # disassembly?  `adc rdi, rdi, rbx` does, and rdi is then an
                # architectural input; `mov2int rbx, %xmm3_low, 0` does not,
                # and its read of rbx is gem5's own merge.  The operand LISTS
                # alone cannot make that distinction.
                named = False
                if cls == 'integer' and i in V.INT_NAMES:
                    named = any(re.search(r'\b%s\b' % n, after_comma)
                                for n in V.INT_NAMES[i])
                elif cls == 'floating_point':
                    half = V.xmm_half(cls, i)
                    if half is not None:
                        named = ('%%xmm%s' % half[0][7:]) in after_comma
                    elif 48 <= i < 56:
                        named = ('%%st(%d)' % (i - 48)) in after_comma
                    elif i < 8:
                        named = ('%%mmx%d' % i) in after_comma
                else:
                    named = True      # cc / misc carry no operand text
                cur.raw_reads.append((cls, i, cur.uops, named))

    _finalize(out, dropped, folded, merged)
    for i, ins in enumerate(out):
        if ins.length is not None:
            continue
        if i + 1 < len(out):
            d = out[i + 1].pc - ins.pc
            if 0 < d <= 15:
                ins.length = d
    if sel is not None:
        out = [i for i in out if sel(i.pc)]
    return out


def _x87_name(raw_idx, top_before, top_after):
    """gem5's x87 operand index -> the id the TRACER would give it.

    gem5 prints the UNFLATTENED operand, so ``%st(7)`` on an ``fld`` names
    the slot the value lands in RELATIVE TO THE TOP BEFORE the push, while
    Capstone -- and so the tracer -- names it ``ST(0)``, relative to the top
    AFTER.  Both denote the same PHYSICAL register: measured on ``flds``,
    gem5 writes floating_point:55 and sets X87Top to 7, and physical
    ``(0 + 7) % 8 == (7 + 0) % 8``.

    Converting here rather than excusing the difference is what keeps the
    x87 destination axis a real comparison instead of a named exception.
    """
    if raw_idx < 8:
        return 'REG_FPR%d' % raw_idx        # the MMX view: already physical
    i = raw_idx - 48
    tb = 0 if top_before is None else top_before
    ta = tb if top_after is None else top_after
    return 'REG_FPR%d' % ((tb + i - ta) % 8)


def _finalize(insns, dropped, folded, merged):
    """Turn the raw per-micro-op records into per-INSTRUCTION facts.

    Three things happen here that cannot be done line by line:

    * the x87 stack-relative operand names are converted to the tracer's
      convention, which needs the TOP on both sides of the instruction;
    * a MERGE READ -- a register gem5 reads only because its own micro-op
      lowering passes a value through it -- is suppressed, by a mechanical
      rule and never by inspection;
    * contiguous accesses of one macro-op are folded back into the single
      access the INSTRUCTION makes.
    """
    top = 0          # gem5 X86 resets X87Top to 0; measured on the prologue
    for ins in insns:
        ins.top_before = top
        if ins.top_after is None:
            ins.top_after = top
        top = ins.top_after

        # ---- destinations
        for cls, i, val, _u in ins.raw_writes:
            if cls == 'floating_point' and (i < 8 or 48 <= i < 56):
                g = _x87_name(i, ins.top_before, ins.top_after)
                ins.x87_valued[g] = val
                if val is None:
                    ins.writes.setdefault(g, None)
                else:
                    ins.writes[g] = val
                continue
            g = V.to_generic(cls, i)
            if cls == 'condition_code':
                ins.writes[g] = None          # the value comes from the word
                continue
            if cls == 'miscellaneous' and i == 24:
                # gem5's Rflags misc register holds only the bits that do NOT
                # live in the cc file -- measured: installing 0x202 and
                # executing `popfq` prints `miscellaneous:24=0x200`, without
                # the architecturally fixed 0x2.  It is therefore not the
                # flags word, and taking its value as one would compare the
                # tracer's whole word against a fragment.
                ins.writes.setdefault(g, None)
                continue
            half = V.xmm_half(cls, i)
            if half is not None:
                vid, which = half
                cur = ins.writes.get(vid)
                prev = ins.writes.get('_half_' + vid)
                have = prev if isinstance(prev, dict) else {}
                if val is not None:
                    have[which] = val
                ins.writes['_half_' + vid] = have
                if 0 in have and 1 in have:
                    ins.writes[vid] = (have[1] << 64) | have[0]
                elif vid not in ins.writes or cur is None:
                    # Only one half known: a scalar SSE write touches the low
                    # 64 and leaves the rest, so the WORD is not knowable
                    # from the line.  Named, not valued.
                    ins.writes.setdefault(vid, None)
                continue
            if val is None:
                ins.writes.setdefault(g, None)
            else:
                ins.writes[g] = val
        for k in [k for k in ins.writes if k.startswith('_half_')]:
            del ins.writes[k]

        # ---- sources, with the merge reads suppressed.
        wrote_by = {}
        for cls, i, _v, u in ins.raw_writes:
            wrote_by.setdefault((cls, i), u)
        for cls, i, u, named in ins.raw_reads:
            key = (cls, i)
            if cls == 'floating_point' and (i < 8 or 48 <= i < 56):
                g = _x87_name(i, ins.top_before, ins.top_before)
            else:
                g = V.to_generic(cls, i)
            # (a) the value was produced by an EARLIER micro-op of this same
            #     macro-op -- gem5 forwarding through an architectural
            #     register it also uses as its temporary.
            if key in wrote_by and wrote_by[key] < u:
                merged['intra-macroop:%s:%d' % (cls, i)] += 1
                continue
            # (b) the micro-op does not NAME the register as a source, and
            #     the macro-op writes it at FULL architectural width, so
            #     nothing of the old value survives.  `ld r9b` is not this
            #     case: an 8-bit write is partial and the read is real.
            if (not named and key in wrote_by and key in ins.full_written):
                merged['merge-read:%s:%d' % (cls, i)] += 1
                continue
            ins.srcs.add(g)

        # ---- contiguous accesses of one macro-op are ONE instruction-level
        # access.  gem5 cracks a 128-bit `movups` into two 64-bit halves; the
        # question the memop axes ask is how many accesses the INSTRUCTION
        # makes and where, and the cracking is an answer to a different one.
        for which in ('loads', 'stores'):
            recs = getattr(ins, which)
            if len(recs) < 2:
                continue
            recs = sorted(recs, key=lambda r: r[0])
            out2 = [recs[0]]
            for a, d, sz in recs[1:]:
                pa, pd, psz = out2[-1]
                if pa + psz == a and pd is not None and d is not None:
                    out2[-1] = (pa, pd | (d << (8 * psz)), psz + sz)
                    folded['%s:%s' % (which, ins.disas.split()[0])] += 1
                elif pa + psz == a:
                    out2[-1] = (pa, None, psz + sz)
                    folded['%s:%s' % (which, ins.disas.split()[0])] += 1
                else:
                    out2.append((a, d, sz))
            setattr(ins, which, out2)


def running_rflags(insns, entry_word):
    """Fill ``rflags``/``rflags_mask`` from the entry word forward.

    gem5 holds no RFLAGS register: it keeps ``Zaps``, ``Cfof`` and ``Df``,
    each carrying its bits in their RFLAGS positions.  The word after an
    instruction is therefore the word before it with the bits that
    instruction's cc writes state replaced -- which is what makes REG_FLAGS a
    real VALUE axis on this leg instead of a skipped one.

    ``entry_word`` is the value the injection prologue INSTALLED, so the
    reference's word starts from the same place the tracer's did.  Bits gem5
    never speaks about stay outside the mask and are never compared.
    """
    word = (entry_word or 0) & V.RFLAGS_MASK
    mask = V.RFLAGS_MASK if entry_word is not None else 0
    for ins in insns:
        if ins.cc:
            w, m = V.rflags_from_cc(ins.cc)
            word = (word & ~m) | (w & m)
            mask |= m
        ins.rflags = word
        ins.rflags_mask = mask
    return insns


# ------------------------------------------------------------------ the run
class Gem5Run(object):
    """A gem5 invocation and what it produced, including WHY it stopped."""

    __slots__ = ('log', 'exit', 'tail', 'stdout')

    def __init__(self, log, exit_code, tail, stdout):
        self.log = log
        self.exit = exit_code
        self.tail = tail
        self.stdout = stdout


def run(gem5_bin, gem5_dir, env, elf, outdir, tag, maxinsts, timeout=900):
    """Run gem5 X86 SE mode on ``elf``; -> Gem5Run.

    A non-zero exit is NOT an error here.  An injected wrong-path excursion
    runs off the end of anything the guest ever mapped, and gem5 answers that
    with a page-table panic; the log written up to that point is the
    reference's answer, and the panic text is kept so the row it produces can
    be named as a reference limit instead of quoted as agreement.
    """
    d = os.path.join(outdir, tag + '.g5')
    os.makedirs(d, exist_ok=True)
    cmd = [gem5_bin, '-d', d,
           '--debug-flags=ExecEnable,ExecUser,ExecKernel,ExecMicro,'
           'ExecEffAddr,ExecResult,ExecOpClass,ExecThread,ExecRegDelta,'
           'ExecFlags',
           '--debug-file=exec.log',
           os.path.join(gem5_dir, 'configs/deprecated/example/se.py'),
           '--cpu-type=AtomicSimpleCPU',
           '-I', str(maxinsts),
           '-c', elf]
    try:
        p = subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        rc, so = p.returncode, p.stdout.decode('utf-8', 'replace')
    except subprocess.TimeoutExpired as e:
        rc = -9
        so = (e.output or b'').decode('utf-8', 'replace')
    log = os.path.join(d, 'exec.log')
    tail = ''
    for line in so.splitlines():
        if 'panic' in line or 'fatal' in line or 'Assertion' in line:
            tail = line.strip()
    return Gem5Run(log if os.path.exists(log) else None, rc, tail, so)
