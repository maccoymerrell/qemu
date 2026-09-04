"""FINDING 71-A: sink the hoisted gen_load_gpr() into the cases that use it.

THE DEFECT.  MIPS DSP instructions are dispatched through five functions whose
PROLOGUES load the rs/rt fields into temps before the switch that decides what
the instruction is.  For the register-operand forms that is a read; for the
IMMEDIATE forms -- `repl.ph $t0,imm`, `shll.ph`, `extr.w`, `shilo` and the rest
-- the same field is a CONSTANT, and the hoisted load states a read of the
general-purpose register whose NUMBER happens to equal the immediate.  1,373 of
33,160 DSP encodings published a source they do not have.

TCG's optimiser deletes the dead load before codegen, so the EMULATOR was
always right and no guest-visible behaviour changes.  What changes is the
TRANSLATION-TIME STATEMENT the dataflow extraction reads, which is the whole
of the wire's read side on these instructions.

BEHAVIOUR-PRESERVING BY CONSTRUCTION, and mechanically rather than by hand:
the temps are `tcg_temp_new()` and, in the immediate-form cases, never read --
so moving the load from above the switch to the top of each case that DOES
read it emits the same ops for every case that reads it and no ops at all for
the cases that do not.

Every insertion point is an INNERMOST case block, because inserting at an
outer case would leave the load hoisted above the inner switch and the
immediate-form opcodes still stating the read -- the exact bug, one level
down.

FIVE DISPATCHERS, NOT FOUR.  FINDING 71-A named four; `gen_mipsdsp_arith` is
the fifth, found by measurement rather than by reading, and it is where
`precr_sra.ph.w` and `precr_sra_r.ph.w` live -- two of the mnemonics the
finding's own list names.  With four patched those two did not move.

RE-RUN IT, DO NOT APPLY A DIFF.  This file is the artefact; a stale patch
against a moved translate.c is how a mechanical edit goes wrong quietly.  It
rewrites the file in place by default:

    python dsp_sink.py                        # edits target/mips/tcg/translate.c
    DSP_SINK_OUT=/tmp/out.c python dsp_sink.py   # or writes elsewhere

THE ACCEPTANCE BAR is the base-vs-sunk control over the DSP population:
GAINED must be 0 and the mnemonic list must be the same 22.  A 23rd mnemonic
means a case was misattributed; a V-form (register-operand) mnemonic in the
list means a real read was sunk out of a path that needed it.
"""
import os, re, sys

SRC = os.environ.get('DSP_SINK_SRC',
       '/mnt/md0/QEMU/qemu/target/mips/tcg/translate.c')
OUT = os.environ.get('DSP_SINK_OUT', SRC)
FNS = ['gen_mipsdsp_arith', 'gen_mipsdsp_shift', 'gen_mipsdsp_bitinsn',
       'gen_mipsdsp_add_cmp_pick', 'gen_mipsdsp_accinsn']

lines = open(SRC).read().split('\n')


def fn_span(name):
    for i, l in enumerate(lines):
        if l.startswith('static void %s(' % name):
            j = i
            while '{' not in lines[j]:
                j += 1
            depth, k = 0, j
            while True:
                depth += lines[k].count('{') - lines[k].count('}')
                if depth == 0 and k >= j:
                    return i, k
                k += 1
    raise SystemExit('not found ' + name)


def case_blocks(body, base):
    """(start, end, depth) for every `case X:` block, in file line numbers."""
    out, stack, depth = [], [], 0
    for i, l in enumerate(body):
        s = l.strip()
        if re.match(r'^(case\s+\S+\s*:|default\s*:)', s):
            # a case ends at the next case/default at the SAME depth, or at
            # the close of the switch that holds it
            stack.append((i, depth))
        depth += l.count('{') - l.count('}')
    # recompute ends: a case runs to the next case at the same depth or to
    # the line where depth drops below the case's depth
    depths, d = [], 0
    for l in body:
        depths.append(d)
        d += l.count('{') - l.count('}')
    starts = [i for i, l in enumerate(body)
              if re.match(r'^(case\s+\S+\s*:|default\s*:)', l.strip())]
    for n, i in enumerate(starts):
        di = depths[i]
        end = len(body) - 1
        for j in range(i + 1, len(body)):
            if depths[j] < di:
                end = j - 1
                break
            if depths[j] == di and re.match(
                    r'^(case\s+\S+\s*:|default\s*:)', body[j].strip()):
                end = j - 1
                break
        out.append((i, end, di))
    return out


changed = 0
for fn in FNS:
    a, b = fn_span(fn)
    body = lines[a:b + 1]
    blocks = case_blocks(body, a)
    # A HOISTED LOAD IS ONE OUTSIDE EVERY CASE BLOCK, and the distinction is
    # what makes this file safe to re-run.  The first version matched every
    # `gen_load_gpr(x_t, y);` in the function; on a file this script had
    # ALREADY transformed that matches the per-case copies it inserted, and a
    # second run sank each of them again -- 18,448 insertions and a file no
    # longer compilable.  A generator whose second run destroys its own output
    # is a generator nobody can re-run, and re-running it rather than applying
    # a banked diff is this transformation's whole containment rule.
    incase = set()
    for (cs, ce, _cd) in blocks:
        for k in range(cs, ce + 1):
            incase.add(k)
    loads = [(i, l) for i, l in enumerate(body)
             if re.match(r'\s*gen_load_gpr\(\w+_t,\s*\w+\);\s*$', l)
             and i not in incase]
    if not loads:
        # NOT A NO-OP AND NOT A SUCCESS.  Either the file is already sunk, or
        # the dispatcher was rewritten and this script no longer knows where
        # its prologue is.  Both are things to look at; neither is a run that
        # may report having done its job.
        raise SystemExit(
            'REFUSING: %s has no hoisted gen_load_gpr() outside its case '
            'blocks.  Either this file is already sunk -- the transformation '
            'is not idempotent and must not be applied twice -- or the '
            'dispatcher moved and this script cannot find its subject.  '
            'Nothing written.' % fn)
    for li, lt in loads:
        m = re.match(r'(\s*)gen_load_gpr\((\w+_t),\s*(\w+)\);', lt)
        indent, temp, src = m.group(1), m.group(2), m.group(3)
        # innermost case blocks that READ the temp
        targets = []
        for (s, e, d) in blocks:
            if not (s <= len(body) and e >= s):
                continue
            uses = any(re.search(r'\b%s\b' % temp, body[k])
                       and 'gen_load_gpr' not in body[k]
                       for k in range(s, e + 1))
            if not uses:
                continue
            # innermost: no other USING block strictly inside this one
            inner = any(s < s2 and e2 <= e and
                        any(re.search(r'\b%s\b' % temp, body[k])
                            and 'gen_load_gpr' not in body[k]
                            for k in range(s2, e2 + 1))
                        for (s2, e2, d2) in blocks)
            if not inner:
                targets.append((s, e, d))
        for (s, e, d) in targets:
            # The indent is the CASE BODY'S OWN, read off the first statement
            # after the label, not computed from the brace depth: the file
            # indents its inner switches by hand and a computed figure lands
            # four columns out on every one of them.
            ind = None
            for k in range(s + 1, e + 1):
                if body[k].strip():
                    ind = body[k][:len(body[k]) - len(body[k].lstrip())]
                    break
            if ind is None:
                ind = ' ' * ((d + 1) * 4)
            body[s] = body[s] + '\n' + ind + \
                'gen_load_gpr(%s, %s);' % (temp, src)
            changed += 1
        body[li] = '\x00DELETE\x00'
    lines[a:b + 1] = body

out = [l for l in lines if l != '\x00DELETE\x00']
open(OUT, 'w').write(
    '\n'.join(out))
print('inserted %d per-case load(s)' % changed)
