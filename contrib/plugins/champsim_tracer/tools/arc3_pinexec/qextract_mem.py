#!/usr/bin/env python3
"""Parse `cst_decode --format=disasm --objdump` into the linear CORRECT-PATH
instruction stream, one JSON object per line, carrying every field the PIN
cross-check needs.

Per record:
    i    linear CP index (0-based)
    pc   guest PC (hex, no 0x)
    b    raw instruction encoding, hex.  The byte-column parser works around
         cst_decode's 9-byte column width (a 10..15-byte x86 instruction is
         glued to the mnemonic) -- see syncexp/README.md.
    m    generic opcode mnemonic (the plugin's own classification)
    c    Capstone mnemonic (the --objdump column)
    nl   number of LOAD dynamic memops on the wire   (= `ld=` columns)
    ns   number of STORE dynamic memops on the wire  (= `st=` columns)
    la   load effective addresses that the renderer could place
    sa   store effective addresses that the renderer could place
    lw   load access widths, in dyn-param order
    sw   store access widths, in dyn-param order
    lv   load DATA values, in dyn-param order, as little-endian integers of
         the accessed bytes (`ld=0x<value>/w<size>` on the wire)
    sv   store DATA values, in dyn-param order, same encoding
    s    source register refs   (%gp0, %sp, %flags, ...)
    d    destination register refs
    t    branch direction on the entry's terminator instruction
    tg   branch target PC on the terminator

Memop model (from cst_decode_main.cc:emit_disasm_memops): the authoritative
per-instruction memop list is the dyn_params vector; with MEM_DATA *every*
dyn_param contributes one `ld=<value>/w<size>` or `st=...` column, so counting
those columns counts the memops the wire actually carries.  Addresses appear
either inline in the operand text (`ld[%base](0x..)`) when the operand renderer
covered the memop, or as a trailing `ld(0x..,w..)` when it did not.  An
instruction whose address count is short of its dyn-param count is one where
the operand model and the memop list disagree; those are reported separately
rather than silently dropped.

Register attribution:
  * a register inside `ld[...]` / `st[...]` brackets is an ADDRESS register and
    therefore a SOURCE (PIN's INS_RegR reports base/index registers too);
  * a register written as `%r[value/wN]` right of `->` is a DESTINATION;
  * everything else left of `->` is a SOURCE;
  * the renderer emits one instruction as one or more micro-operation groups
    separated by `  ;  ` (push = `%sp -> %sp[..]  ;  %fpr -> st[%sp](..)`), so
    every group is parsed and the results unioned.

usage: qextract.py <disasm.txt|-> [limit] [skip] > stream.jsonl
"""
import json
import re
import sys

re_entry = re.compile(r'entry pc=0x([0-9a-fA-F]+)\s+insns=(\d+).*?branch=(\S+)')
re_tgt = re.compile(r'target=0x([0-9a-fA-F]+)')
re_wp = re.compile(r';\s*\.\.\.\.\.\s*wp\[')
re_head = re.compile(r'^0x([0-9a-fA-F]+)(?:\s+<[^>]*>)?:\s+')
re_mem = re.compile(r'\b(ld|st)\[([^\]]*)\]\((0x[0-9a-fA-F]+)\)')
re_memnoea = re.compile(r'\b(ld|st)\[([^\]]*)\](?!\()')
re_untracked = re.compile(r'\b(ld|st)\((0x[0-9a-fA-F]+)(?:,w(\d+))?\)')
re_val = re.compile(r'\b(ld|st)=(0x[0-9a-fA-F]+)(?:/w(\d+))?')
re_dstreg = re.compile(r'(%[a-z][a-z0-9_]*)\[')
re_reg = re.compile(r'%[a-z][a-z0-9_]*')
re_grpsep = re.compile(r'\s\s;\s\s')
re_marker = re.compile(r'\s\s;\s[\w@]+\s*$')
HEX = set('0123456789abcdef')


def take_bytes(s, i):
    """Consume the objdump-style raw-byte column.

    Token rule: a byte is a hex run of *exactly* two characters, separated
    from the next by exactly one space.  Anything else ends the column.

    It has to be a token rule, not "two hex characters after a space".
    cst_decode's bytes column is sized for the <= 7-byte common case
    (BYTES_COL_PAD = 25); an x86 instruction of 9..16 bytes overflows it,
    and since a18790252b ("cst_decode: guarantee a separator when the
    disasm bytes column overflows") the overflow case is followed by
    exactly ONE space instead of running glued into the next column.  A
    character-pair rule then swallows the first two characters of any
    Capstone mnemonic that happens to be hex -- addq, adcq, decl, faddl:

        48 81 85 88 00 00 00 ff ff ff ff addq   ->  ...ffffffff + "ad"

    reporting an instruction one byte too long.  The token rule stops at
    `addq`, whose hex run is 5 characters, not 2.

    This parser is for decoder output at or after a18790252b: against the
    older *glued* column ("... ff 7fmovabsq") it would drop the last byte,
    which is what the pair rule was written to survive.
    """
    out = []
    while len(out) < 16:
        j = i
        while j < len(s) and s[j] in HEX:
            j += 1
        if j - i != 2:
            break
        out.append(s[i:j])
        i = j
        if i < len(s) and s[i] == ' ':
            i += 1
        else:
            break
    return ''.join(out), i


def split_ops(body):
    """Split one micro-operation group into (source text, destination text).

    The arrow is not always space-preceded: an instruction whose only operands
    are implicit destinations renders as `syscall  -> %ip[..], %gp1[..]`, whose
    group text begins with the arrow."""
    k = body.find('->')
    if k < 0:
        return body, ''
    return body[:k], body[k + 2:]


def parse_generic(gen):
    for cut in ('  prof:', '  # ', '\t'):
        p = gen.find(cut)
        if p >= 0:
            gen = gen[:p]
    gen = re_marker.sub('', gen)

    # --- memop dyn-param count and widths, from the MEM_DATA value columns ---
    lw, sw = [], []
    lv, sv = [], []
    for kind, val, w in re_val.findall(gen):
        (lw if kind == 'ld' else sw).append(int(w) if w else 0)
        (lv if kind == 'ld' else sv).append(int(val, 16))
    # --- untracked memops carry their own address (and width) ---
    la, sa = [], []
    for kind, addr, w in re_untracked.findall(gen):
        (la if kind == 'ld' else sa).append(int(addr, 16))
    ops = re_untracked.sub('', re_val.sub('', gen)).strip()

    # --- operand text: groups, registers, inline memop addresses ---
    src, dst = set(), set()
    ila, isa = [], []
    n_noea = 0
    for grp in re_grpsep.split(ops):
        mems = re_mem.findall(grp)
        for kind, inner, addr in mems:
            (ila if kind == 'ld' else isa).append(int(addr, 16))
            src.update(re_reg.findall(inner))
        for kind, inner in re_memnoea.findall(grp):
            n_noea += 1
            src.update(re_reg.findall(inner))
        src_txt, dst_txt = split_ops(grp)
        src.update(re_reg.findall(src_txt))
        dst.update(re_dstreg.findall(dst_txt))
    # %mflags is a plugin-internal alias of the condition-code register and has
    # no independent architectural meaning.
    src.discard('%mflags')
    dst.discard('%mflags')
    return (ila + la, isa + sa, lw, sw, lv, sv, sorted(src), sorted(dst), n_noea)


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 1 << 62
    skip = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    limit += skip
    f = sys.stdin if path == '-' else open(path)
    out = sys.stdout
    n = 0
    in_cp = False
    cur_insns = cur_seen = 0
    cur_branch = None
    cur_tgt = None
    for line in f:
        if line[0] == ';':
            if 'entry pc=' in line:
                m = re_entry.search(line)
                if m:
                    in_cp = True
                    cur_insns = int(m.group(2))
                    cur_branch = m.group(3)
                    mt = re_tgt.search(line)
                    cur_tgt = int(mt.group(1), 16) if mt else None
                    cur_seen = 0
                continue
            if re_wp.search(line):
                in_cp = False
            continue
        if not in_cp:
            continue
        mh = re_head.match(line)
        if not mh:
            continue
        b, k = take_bytes(line, mh.end())
        if not b:
            continue
        rest = line[k:]
        bar = rest.find('|')
        if bar >= 0:
            cap = rest[:bar].strip()
            gen = rest[bar + 1:].rstrip('\n')
        else:
            cap = ''
            gen = rest.rstrip('\n')
        gen = gen.strip()
        sp = gen.find(' ')
        if sp < 0:
            mnem, genops = gen, ''
        else:
            mnem, genops = gen[:sp], gen[sp:]
        la, sa, lw, sw, lv, sv, src, dst, noea = parse_generic(genops)
        cur_seen += 1
        term = (cur_seen == cur_insns)
        if n < skip:
            n += 1
            if term:
                in_cp = False
            continue
        rec = {'i': n - skip, 'pc': mh.group(1), 'b': b, 'm': mnem,
               'c': cap.split(' ')[0] if cap else '',
               'nl': len(lw), 'ns': len(sw),
               'la': la, 'sa': sa, 'lw': lw, 'sw': sw,
               'lv': lv, 'sv': sv,
               's': src, 'd': dst}
        if noea:
            rec['ne'] = noea
        if term:
            rec['t'] = cur_branch
            if cur_tgt is not None:
                rec['tg'] = cur_tgt
        out.write(json.dumps(rec, separators=(',', ':')))
        out.write('\n')
        n += 1
        if term:
            in_cp = False
        if n >= limit:
            break
    sys.stderr.write("# extracted %d CP instructions\n" % n)


main()
