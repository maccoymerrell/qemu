"""
The tracer's EMITTER-STATED intra-instruction dependency map, as a consumer
reads it.

WHAT IS READ, AND WHY IT IS READ THAT WAY
=========================================
The wire carries four mask families (``docs/format.rst`` 4.5, and
``champsim_tracer_mnemonics.h``)::

    dst_dep_mask[d]          bits [0,n_src) src slots, then load slots,
    store_data_dep_mask[s]     then one immediate bit
    load_addr_dep_mask[l]    bits [0,n_src) src slots, then one immediate bit
    store_addr_dep_mask[s]

Three separate rules turn those raw masks into what a consumer actually sees,
and ALL THREE live in ``cst_decode``:

  1. an ABSENT ``HAS_REG`` block is not an absent dependency -- the format
     defines it as the all-to-all over-approximation, and the renderer
     synthesizes ``all_inputs & ~addr_only_srcs`` in its place
     (``cst_decode_main.cc:emit_disasm_deps_annotation``);
  2. a SATURATED mask has the addressing-only sources stripped from it, so
     that an address register does not read as a second, direct edge into a
     sink it already reaches through the memop (``effective()``);
  3. the immediate bit sits at a different index in the address masks than in
     the data masks, because the address masks have no load slots.

REIMPLEMENTING THOSE THREE RULES HERE WOULD BE THE FABRICATION THIS ARC IS
ABOUT.  ``DEPMAP_DESIGN.md`` §1 names the mechanism -- "re-derivation is where
fabrication enters" -- and a second implementation of the synthesis rule is
exactly that: it would agree with the renderer until the day it did not, and
on that day the harness would report a tracer defect that only its own copy of
the rule believed in.  So the map is read from ``cst_decode --show-deps``,
which is the renderer's own answer, and the RAW view is used only to CHECK
that reading, never to recompute it.

THE CHECK, AND WHY IT IS NOT DECORATION
=======================================
``--show-deps`` names registers the way the disassembly names them -- ``%gp5``,
``%acchi0`` -- while every other reference in this arc speaks ``REG_*``.  The
translation is LEARNED, never transcribed: the raw view states each template
instruction's ``dst=[id (REG_NAME)]`` list in slot order, and the deps line
emits one entry per destination IN THAT SAME ORDER, so the two can be zipped.
Every learned pair is asserted against every later sighting, and a conflict
REFUSES rather than picking a winner -- a display name silently bound to the
wrong ``REG_*`` id would put a register in the wrong family on both sides at
once and read as agreement.

The zip is also the arity check.  If the renderer emits a different number of
destination entries than the wire declares ``n_dst``, the reading is wrong in
a way that would quietly re-attribute every edge, and nothing is returned.

Author: Maccoy Merrell.
"""
import re
import subprocess


#: ``; ----- BB 2 entry pc=0x10144 insns=48 seq=1 ...``
_BBHDR = re.compile(r'^;\s*-+\s*BB\s+(\d+)\s+entry\s+pc=0x([0-9a-f]+)\s+'
                    r'insns=(\d+)\s+seq=(\d+)')

#: a wrong-path block, as the renderer actually writes it.  The correct-path
#: dependency map is the subject here; folding WP instructions into the
#: preceding CP block would score two different things as one.
_WPHDR = re.compile(r'^;\s*\.+\s*wp\[')

#: ``0x000000010144: 97 1f 00 00   lea ...  ; deps: %gp31=[imm]``
#: The byte column is taken as TOKENS, not by a regex with a fixed separator:
#: ``cst_decode`` pads that column for the <=7-byte case and separates a
#: LONGER instruction from its mnemonic by a single space, and a pattern that
#: demanded two dropped every x86-64 instruction of 8 bytes or more in silence
#: (the defect ``tracer_log`` was repaired for).
_INSN_PC = re.compile(r'^0x([0-9a-f]+)\s*(?:<[^>]*>)?:\s+(.*)$')
_HEXBYTE = re.compile(r'^[0-9a-f]{2}$')

#: THE MAP IS NOT THE FIRST ITEM IN THE TRAILING COMMENT.
#:
#: ``emit_disasm_trailing_meta`` writes the comment block as a sequence of
#: items -- a wrong-path status, ``atomic``, then the map -- so anchoring on
#: ``"; deps:"`` finds the annotation only when nothing precedes it.  Measured:
#: every ATOMIC instruction on the mipsel probe set (``ll``, ``sc``, and three
#: more) renders as ``; atomic deps: ...``, and the anchored pattern read all
#: five as having NO dependency map at all.  They were then scored as an empty
#: tracer set against a reference that named real registers -- five
#: manufactured MISSING-EDGE rows, with the tracer's actual map sitting in the
#: line the whole time.  The marker is therefore matched wherever it appears.
_DEPS = re.compile(r'\bdeps:\s*(.*)$')

#: one ``name=[a,b,c]`` entry of the deps line.
_ENTRY = re.compile(r'(\S+?)=\[([^\]]*)\]')

#: THE DEPS LIST ENDS AT THE FIRST KEY THAT IS NOT A DEPENDENCY KEY.
#:
#: The trailing comment block continues past the map with other items, and one
#: of them -- ``cp=[0x11200-0x11200]``, the correct-path address range -- has
#: exactly the ``name=[...]`` shape the entry pattern looks for.  Terminating
#: on the SHAPE OF THE KEY rather than on the whitespace before ``prof:`` is
#: what makes that impossible: a register key is rendered with a ``%`` sigil
#: and the three slot families are spelled out, so ``cp`` cannot be mistaken
#: for either.  (The first version of this reader terminated on a two-space
#: run, and the line had already been whitespace-normalised by the time it
#: got here, so the guard was inert and ``cp`` was read as a destination.)
_SLOTKEY = re.compile(r'^(sdata|laddr|saddr)(\d+)$')


def _dep_entries(text):
    """The dependency entries of a deps annotation, in order.

    Stops at the first key that is neither a register reference nor a slot
    key, and returns what it had.  Nothing after the map is guessed at.
    """
    out = []
    for k, v in _ENTRY.findall(text):
        if not (k.startswith('%') or _SLOTKEY.match(k)):
            break
        out.append((k, v))
    return out

#: raw-view rows.
_RAW_TPL = re.compile(r'\btemplate_id=(\d+)\s+start_pc=0x([0-9a-f]+)')
_RAW_INSN = re.compile(r'\binsn\[(\d+)\]\s+pc=0x([0-9a-f]+)\b')
_RAW_REGS = re.compile(r'\bsrc=\[(.*?)\]\s+dst=\[(.*?)\]')
_RAW_NAME = re.compile(r'\((REG_[A-Z0-9_]+)\)')
_RAW_NSRC = re.compile(r'\bn_src=(\d+)\s+n_dst=(\d+)')


class MapRefusal(Exception):
    """A named reason the map could not be read.  Never a partial reading."""


class Insn(object):
    """One executed instruction's dependency map, in ``REG_*`` vocabulary.

    ``dst_deps`` maps a destination ``REG_*`` to the set of ELEMENTS feeding
    it.  An element is a ``REG_*`` name, ``'imm'``, or ``'ld<k>'`` -- the load
    slot, which is the thing that makes this map finer than a source list:
    ``dst=[ld0]`` with ``laddr0=[REG_GPR31]`` says the datum comes from memory
    and the address from a register, which no reference in this arc can say in
    one fact.
    """

    __slots__ = ('pc', 'bits', 'nbytes', 'seq', 'idx', 'mnemonic',
                 'dst_deps', 'sdata', 'laddr', 'saddr', 'n_src', 'n_dst',
                 'src_regs', 'dst_regs')

    def __init__(self, pc, bits, nbytes, seq, idx):
        self.pc = pc
        self.bits = bits
        self.nbytes = nbytes
        self.seq = seq
        self.idx = idx
        self.mnemonic = ''
        self.dst_deps = {}      # REG_* -> set(element)
        self.sdata = {}         # slot -> set(element)
        self.laddr = {}         # slot -> set(element)
        self.saddr = {}         # slot -> set(element)
        self.n_src = 0
        self.n_dst = 0
        self.src_regs = []      # REG_*, in slot order
        self.dst_regs = []      # REG_*, in slot order

    # ------------------------------------------------------------ closures
    def closure(self, dst):
        """Architectural registers reaching ``dst``, memops resolved through.

        A load slot in a destination's mask is not a register; it is a datum
        whose OWN provenance the map states separately, in ``laddr``.  A
        reference that cracks an instruction into micro-ops names the address
        register directly as a source of the value-producing micro-op, so the
        two are only comparable once the slot is resolved back through the
        address mask.  That resolution is what this does, and it is the ONLY
        place the two vocabularies are brought together.
        """
        out = set()
        for e in self.dst_deps.get(dst, ()):
            if e == 'imm':
                continue
            if e.startswith('ld'):
                k = int(e[2:])
                for a in self.laddr.get(k, ()):
                    if a != 'imm':
                        out.add(a)
                continue
            out.add(e)
        return out

    def src_union(self):
        """Every architectural register the map says this instruction reads.

        Includes the address masks: an address register is read by the
        instruction whether or not it reaches any register destination, and a
        store reaches none at all.
        """
        out = set()
        for d in self.dst_deps:
            out |= self.closure(d)
        for grp in (self.sdata, self.laddr, self.saddr):
            for s in grp.values():
                for e in s:
                    if e == 'imm':
                        continue
                    if e.startswith('ld'):
                        k = int(e[2:])
                        out |= {a for a in self.laddr.get(k, ())
                                if a != 'imm'}
                        continue
                    out.add(e)
        return out

    def __repr__(self):
        return 'map(pc=0x%x dst=%r laddr=%r saddr=%r sdata=%r)' % (
            self.pc, self.dst_deps, self.laddr, self.saddr, self.sdata)


def _run(decode, trace, *extra):
    p = subprocess.run([decode] + list(extra) + [trace],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise MapRefusal('cst_decode %s exit %d: %s'
                         % (' '.join(extra), p.returncode,
                            p.stderr.decode('utf-8', 'replace')[-800:]))
    return p.stdout.decode('utf-8', 'replace').splitlines()


def _insn_line(line):
    """``(pc, bits, nbytes, rest)`` for a disassembly line, else None."""
    m = _INSN_PC.match(line)
    if not m:
        return None
    pc = int(m.group(1), 16)
    body = m.group(2)
    toks = body.split()
    nb = 0
    while nb < len(toks) and _HEXBYTE.match(toks[nb]):
        nb += 1
    if nb == 0:
        return None
    bits = int.from_bytes(bytes(int(t, 16) for t in toks[:nb]), 'little')
    # The REMAINDER IS RETURNED VERBATIM, not re-joined from tokens.  The
    # renderer's column padding carries information -- it is what separates
    # the map from the profile block -- and normalising it away is how the
    # profile block's `cp=[...]` came to be read as a dependency entry.
    tail = body
    for t in toks[:nb]:
        tail = tail[tail.index(t) + len(t):]
    return pc, bits, nb, tail


def _raw_templates(decode, trace):
    """``(tid, idx) -> (src REG_* list, dst REG_* list, n_src, n_dst)``.

    Read from the RAW view, which states the wire's own slot lists.  This is
    the CHECK side: it never contributes an edge, only the vocabulary and the
    arity the rendered map is asserted against.
    """
    out = {}
    tid = None
    pending = None
    for line in _run(decode, trace, '--format=raw'):
        t = _RAW_TPL.search(line)
        if t:
            tid = int(t.group(1))
            pending = None
            continue
        i = _RAW_INSN.search(line)
        if i and tid is not None:
            pending = int(i.group(1))
            continue
        if pending is None or tid is None:
            continue
        n = _RAW_NSRC.search(line)
        if n:
            out.setdefault((tid, pending), [[], [], 0, 0])
            out[(tid, pending)][2] = int(n.group(1))
            out[(tid, pending)][3] = int(n.group(2))
            continue
        r = _RAW_REGS.search(line)
        if r:
            out.setdefault((tid, pending), [[], [], 0, 0])
            out[(tid, pending)][0] = _RAW_NAME.findall(r.group(1))
            out[(tid, pending)][1] = _RAW_NAME.findall(r.group(2))
    return out


def parse(decode, trace):
    """``([Insn], learned display-name map, notes)``.

    Refuses -- by name, with nothing returned -- when the trace carries
    wrong-path blocks, when a block's instruction-line count disagrees with
    the ``insns=`` it declares, when the rendered destination count disagrees
    with the wire's ``n_dst``, or when a display name is seen bound to two
    different ``REG_*`` ids.
    """
    tpl = _raw_templates(decode, trace)

    order, declared = [], []
    cur = None
    for line in _run(decode, trace, '--show-deps'):
        h = _BBHDR.match(line)
        if h:
            cur = (int(h.group(1)), int(h.group(4)), [])
            order.append(cur)
            declared.append(int(h.group(3)))
            continue
        if line.startswith(';'):
            if _WPHDR.match(line):
                raise MapRefusal(
                    'trace carries wrong-path blocks; the correct-path map is '
                    'the subject here.  Re-trace with wp=0.')
            continue
        if cur is None:
            continue
        rec = _insn_line(line)
        if rec is not None:
            cur[2].append(rec)

    for (tid, seq, lst), want in zip(order, declared):
        if len(lst) != want:
            raise MapRefusal(
                'BB %d (seq %d) declares insns=%d, %d instruction lines '
                'parsed.  Every edge after the missing line would be '
                'attributed to the wrong instruction; nothing is returned.'
                % (tid, seq, want, len(lst)))

    name2reg = {}          # display name -> REG_*
    raw_entries = []       # [(Insn, entries)] for the source-side pass
    conflicts = []
    notes = []
    no_annotation = 0
    out = []

    for tid, seq, lst in order:
        for i, (pc, bits, nb, rest) in enumerate(lst):
            ins = Insn(pc, bits, nb, seq, i)
            ins.mnemonic = rest.split()[0] if rest.split() else ''
            t = tpl.get((tid, i))
            if t is not None:
                ins.src_regs, ins.dst_regs, ins.n_src, ins.n_dst = \
                    t[0], t[1], t[2], t[3]
            d = _DEPS.search(rest)
            if not d:
                no_annotation += 1
                out.append(ins)
                continue

            entries = _dep_entries(d.group(1))
            dst_entries = [(k, v) for k, v in entries
                           if not (k.startswith('sdata') or
                                   k.startswith('laddr') or
                                   k.startswith('saddr'))]

            # THE ARITY GATE.  The renderer emits one entry per destination
            # slot, in slot order; the wire declares how many there are.  A
            # disagreement means the reading is misaligned, and a misaligned
            # reading does not lose one edge -- it moves every later one.
            if t is not None and len(dst_entries) != ins.n_dst:
                raise MapRefusal(
                    'pc=0x%x: the deps annotation names %d destinations, the '
                    'wire declares n_dst=%d.  The two are zipped to learn the '
                    'register vocabulary, so a mismatch would bind display '
                    'names to the wrong REG_* ids.'
                    % (pc, len(dst_entries), ins.n_dst))

            # ---- learn display name -> REG_*, from the destination zip
            if t is not None:
                for (disp, _), reg in zip(dst_entries, ins.dst_regs):
                    prev = name2reg.get(disp)
                    if prev is None:
                        name2reg[disp] = reg
                    elif prev != reg:
                        conflicts.append((disp, prev, reg, pc))

            for k, v in entries:
                elems = [x.strip() for x in v.split(',') if x.strip()]
                if k.startswith('sdata'):
                    ins.sdata[int(k[5:])] = set(elems)
                elif k.startswith('laddr'):
                    ins.laddr[int(k[5:])] = set(elems)
                elif k.startswith('saddr'):
                    ins.saddr[int(k[5:])] = set(elems)
                else:
                    ins.dst_deps[k] = set(elems)
            raw_entries.append((ins, entries))
            out.append(ins)

    # ---- SOURCE-SIDE LEARNING, by elimination
    #
    # A register that is never a destination anywhere in the corpus cannot be
    # taught by the destination zip -- `%zero` on riscv64 and mipsel is read
    # constantly and written never.  Leaving it unresolved would drop a real
    # source from the tracer side and read as a MISSING EDGE against a
    # reference that names it, so it is recovered by ELIMINATION instead:
    # where an instruction's annotation carries exactly one unknown source
    # display name and its wire slot list carries exactly one unaccounted
    # REG_*, the two are each other's only candidate.
    #
    # This is inference, so it is checked like inference: every binding it
    # proposes is asserted against every other sighting through the SAME
    # conflict test as the destination zip, and it never overwrites a name the
    # destination zip already taught.
    for _round in range(8):
        learned_this_round = 0
        for ins, entries in raw_entries:
            if not ins.src_regs:
                continue
            seen = set()
            for _k, v in entries:
                for e in [x.strip() for x in v.split(',') if x.strip()]:
                    if e != 'imm' and not e.startswith('ld'):
                        seen.add(e)
            unknown = [d for d in seen if d not in name2reg]
            known_regs = {name2reg[d] for d in seen if d in name2reg}
            remaining = [r for r in dict.fromkeys(ins.src_regs)
                         if r not in known_regs]
            if len(unknown) == 1 and len(remaining) == 1:
                prev = name2reg.get(unknown[0])
                if prev is None:
                    name2reg[unknown[0]] = remaining[0]
                    learned_this_round += 1
                elif prev != remaining[0]:
                    conflicts.append((unknown[0], prev, remaining[0], ins.pc))
        if not learned_this_round:
            break

    if conflicts:
        raise MapRefusal(
            'display name bound to two different REG_* ids: %s.  A silent '
            'winner here would put a register in the wrong family on both '
            'sides of the comparison and read as agreement.'
            % '; '.join('%s -> %s and %s (pc=0x%x)' % c for c in conflicts[:6]))

    # ---- rewrite every element into REG_* vocabulary
    unresolved = set()
    for ins in out:
        def conv(s):
            r = set()
            for e in s:
                if e == 'imm' or e.startswith('ld'):
                    r.add(e)
                elif e in name2reg:
                    r.add(name2reg[e])
                else:
                    unresolved.add(e)
                    r.add('UNRESOLVED:' + e)
            return r
        ins.dst_deps = {name2reg.get(k, 'UNRESOLVED:' + k): conv(v)
                        for k, v in ins.dst_deps.items()}
        for grp in ('sdata', 'laddr', 'saddr'):
            setattr(ins, grp, {k: conv(v)
                               for k, v in getattr(ins, grp).items()})
        for k in list(ins.dst_deps):
            if k.startswith('UNRESOLVED:'):
                unresolved.add(k.split(':', 1)[1])

    notes.append('display-name vocabulary learned from the raw view: '
                 '%d names' % len(name2reg))
    if no_annotation:
        notes.append('instructions with NO deps annotation: %d '
                     '(counted, not dropped)' % no_annotation)
    if unresolved:
        # NOT a refusal: a source-only register never appears as a destination
        # anywhere in the corpus, so the destination zip cannot teach its
        # name.  It is reported and the comparator treats it as unmapped --
        # never folded into agreement.
        notes.append('display names no destination sighting could resolve: '
                     '%s' % ', '.join(sorted(unresolved)))
    return out, name2reg, notes
