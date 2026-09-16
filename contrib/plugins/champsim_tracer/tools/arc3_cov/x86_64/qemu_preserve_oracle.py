#!/usr/bin/env python3
"""
ARC 3 -- IS THIS REGISTER READ TO PRESERVE BITS, OR READ ARCHITECTURALLY?

THE QUESTION AND WHY A REFERENCE CANNOT ANSWER IT
=================================================
R7.1 rules that a NARROW write acquires no source: `setz %al` preserves
RAX[63:8] and `inc` preserves CF, and neither register becomes an operand.
An 8- or 16-bit READ-MODIFY-WRITE is a different instruction with the same
shape -- the maintainer's own example, "an in-place ADD that doubles the
quantity of a single register" -- and its read of the destination IS
architectural.

gem5 cannot tell the two apart.  Both print a narrow destination with the
preserved register named in the slot it preserves:

    SETNBE_R   movi r13b, r13b, 0x1     DR=[integer:13] SR=[integer:13,...]
    ADD_R_R    add  bl,   bl,   al      DR=[integer:3]  SR=[integer:3,integer:0,...]

So a rule built on gem5's text alone must either excuse both -- which would
forgive a dropped architectural source -- or convict both, which R7.1
forbids.  THE INSTRUCTION'S OWN SEMANTICS DECIDE IT, and QEMU is the ground
truth for those: the translation either reads the destination into the
computation or it does not.

THE DISCRIMINATOR, READ OFF OBSERVED TCG
========================================
Per encoding, from `qemu-x86_64 -one-insn-per-tb -d op,in_asm` -- an
OBSERVED dump, never the switch in translate.c by eye (R8.7).  Each use of
an architectural TCG global is tainted forward through the op list, and the
set of architectural globals the tainted value reaches decides it:

  PRESERVE-DEPOSIT  the use is the BASE operand of a `deposit_*` whose
                    destination is that same global, and the value reaches
                    no other architectural global.  This is QEMU's merge of
                    a narrow result into a wide register and nothing else.

                      setb %r12b   call cc_compute_c,...,loc0,cc_*
                                   deposit_i64 r12,r12,loc0,$0x0,$0x8
                                   -- r12's ONLY use is the base.  PRESERVE.

                      add %al,%bl  mov_i64 loc0,rbx        <- a second use
                                   add_i64 loc0,loc0,loc1
                                   deposit_i64 rbx,rbx,loc0,$0x0,$0x8
                                   -- rbx is ALSO read into the adder, and
                                   the value reaches cc_dst.  ARCHITECTURAL.

  PRESERVE-FLAGS    the global is part of the x86 lazy-flags tuple
                    (cc_op/cc_dst/cc_src/cc_src2), the tainted value reaches
                    ONLY that tuple, and every op it passes through is a
                    plain move or the cc_compute_* call that read it.  That
                    is CF being carried across a partial flags write and
                    nothing else.

                      inc %r14     call cc_compute_c,...,loc1,cc_*
                                   mov_i64 cc_src,loc1     <- copied, only
                                   -- PRESERVE.

                      adc %dil,%r8b call cc_compute_c,...,loc11,cc_*
                                   add_i64 loc0,loc0,loc11
                                   deposit_i64 r8,r8,loc0  <- reaches a GPR
                                   -- ARCHITECTURAL.

                      cmc          call cc_compute_all,...,tN,cc_*
                                   xor_i64 cc_src,tN,$0x1  <- TRANSFORMED
                                   -- ARCHITECTURAL, which is why the
                                   "reaches only the flags tuple" test is
                                   not sufficient on its own.

  PREDICATION IS NEVER PRESERVE.  A value that passes through `movcond_*`
  is selected, not merged: `cmovcc`'s destination is a source (R4) even
  though the value reaches only itself.  The taint walk marks it and the
  answer is ARCHITECTURAL.

WHAT IT REFUSES, AND WHY REFUSING IS THE POINT
==============================================
The oracle answers only for state QEMU carries in a TCG GLOBAL: the sixteen
GPRs, RIP and the flags tuple.  x87, MXCSR and the vector file live at env
offsets reached inside helpers, and a read of those is invisible in this
dump -- so the answer is UNKNOWN, never `not-read`.  An encoding the dump
never contained is UNKNOWN as well.  A caller must treat UNKNOWN as a
REFUSAL to adjudicate the row, never as permission to excuse it.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import re
import subprocess
import sys

# ------------------------------------------------------------------ vocab
GLOBALS_GPR = {
    'rax': 'REG_GPR0', 'rcx': 'REG_GPR1', 'rdx': 'REG_GPR2',
    'rbx': 'REG_GPR3', 'rsp': 'REG_SP',   'rbp': 'REG_FP_REG',
    'rsi': 'REG_GPR4', 'rdi': 'REG_GPR5', 'r8':  'REG_GPR6',
    'r9':  'REG_GPR7', 'r10': 'REG_GPR8', 'r11': 'REG_GPR9',
    'r12': 'REG_GPR10', 'r13': 'REG_GPR11', 'r14': 'REG_GPR12',
    'r15': 'REG_GPR13',
}
FLAGS_GLOBALS = frozenset(('cc_op', 'cc_dst', 'cc_src', 'cc_src2'))
GLOBALS = dict(GLOBALS_GPR)
for _g in FLAGS_GLOBALS:
    GLOBALS[_g] = 'REG_FLAGS'
GLOBALS['rip'] = 'REG_PC'

# Bare words TCG prints that name a CONDITION or a memory-op descriptor
# rather than a value.  Anything else that is neither a temporary nor a
# constant nor one of these is an unrecognised token and the parse FAILS on
# it, rather than being silently dropped into the "not a register" bucket.
_CONDS = frozenset(('eq', 'ne', 'lt', 'ge', 'le', 'gt', 'ltu', 'geu', 'leu',
                    'gtu', 'tsteq', 'tstne', 'always', 'never'))
_TEMP = re.compile(r'^(loc|tmp)\d+$')
_MEMOP = re.compile(r'^[a-z0-9]+(\+[a-z0-9]+)*$')

_BLOCK = '----------------'
_IN = re.compile(r'^0x0*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(\S.*)?$')
_CONT = re.compile(r'^\s*((?:[0-9a-fA-F]{2}\s*)+)$')
_MARK = re.compile(r'^\s*----\s+([0-9a-fA-F]+)\s')


class ParseError(RuntimeError):
    pass


def _tokens(argstr):
    out, depth, cur = [], 0, ''
    for ch in argstr:
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
            continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def defs_uses(name, args):
    """(op name, [arg tokens]) -> ([defined tokens], [used tokens]).

    Only the shapes this dump actually produces are encoded, and an op whose
    shape is not encoded raises rather than defaulting -- a silent default
    here would decide rows.
    """
    if name == 'call':
        # call <helper>,$<flags>,$<nret>,<rets...>,<args...>
        if len(args) < 3:
            raise ParseError('call with %d args' % len(args))
        nret = int(args[2].lstrip('$'), 0)
        return list(args[3:3 + nret]), list(args[3 + nret:])
    if name == 'discard':
        return [args[0]], []
    if name in ('set_label', 'exit_tb', 'goto_tb', 'goto_ptr', 'br', 'mb'):
        return [], list(args)
    if name.startswith('brcond'):
        return [], list(args)
    if name.startswith('qemu_st'):
        # qemu_st_i64 <data>,<addr>,<memop>,<idx>
        return [], list(args[:2])
    if name.startswith('qemu_ld'):
        return [args[0]], list(args[1:2])
    if name.startswith('st'):
        # st_i32 <val>,<base>,<off>
        return [], list(args)
    if name.startswith('deposit'):
        # deposit_* <dst>,<base>,<val>,$pos,$len
        return [args[0]], list(args[1:3])
    if not args:
        return [], []
    return [args[0]], list(args[1:])


def _value(tok):
    """A token that names a VALUE (global or temp), else None."""
    if not tok or '$' in tok:
        # A constant: `$0x1`, a label `$L0`, or a typed vector immediate such
        # as `v128$0x0`.  None of them name a register.
        return None
    if tok == 'env':
        return None
    if _TEMP.match(tok):
        return tok
    if tok in GLOBALS:
        return tok
    if tok in _CONDS:
        return None
    if tok.isdigit():
        return None
    if _MEMOP.match(tok):
        return None                 # a memop descriptor such as noat+al+ub
    raise ParseError('unrecognised operand token %r' % tok)


class Encoding(object):
    """One architectural encoding and the TCG ops QEMU emitted for it."""

    __slots__ = ('enc', 'pc', 'disas', 'ops')

    def __init__(self, enc, pc, disas):
        self.enc = enc
        self.pc = pc
        self.disas = disas
        self.ops = []               # [(name, [args])]


def parse_dump(path):
    """(a -d in_asm,op log) -> {encoding hex: Encoding}."""
    out = {}
    cur = None
    pend = None                     # the IN: instruction awaiting its ops
    in_ops = False
    for raw in open(path, 'r', errors='replace'):
        line = raw.rstrip('\n')
        if line.startswith(_BLOCK):
            pend, cur, in_ops = None, None, False
            continue
        m = _IN.match(line.strip())
        if m and not in_ops:
            pc = int(m.group(1), 16)
            by = m.group(2).split()
            pend = (pc, by, (m.group(3) or '').strip())
            continue
        if pend is not None and not in_ops:
            m = _CONT.match(line)
            if m:
                pend[1].extend(m.group(1).split())
                continue
        if line.strip() == 'OP:':
            in_ops = True
            continue
        if not in_ops:
            continue
        m = _MARK.match(line)
        if m:
            if pend is None:
                cur = None
                continue
            pc, by, disas = pend
            if int(m.group(1), 16) != pc:
                cur = None
                continue
            enc = ''.join(by).lower()
            cur = out.setdefault(enc, Encoding(enc, pc, disas))
            if cur.ops:
                cur = None          # already have this encoding; keep the first
            continue
        if cur is None:
            continue
        s = line.strip()
        if not s:
            continue
        parts = s.split(None, 1)
        name = parts[0]
        args = _tokens(parts[1]) if len(parts) > 1 else []
        cur.ops.append((name, args))
    return out


# ------------------------------------------------------------- the analysis
ARCH = 'arch'
PRESERVE = 'preserve'
NOT_READ = 'not-read'
UNKNOWN = None

_COPY = re.compile(r'^mov_i(32|64)$')


CC_HELPER = re.compile(r'^cc_compute_')


def classify(encoding):
    """Encoding -> {generic register: 'arch'|'preserve'|'not-read'}.

    Raises ParseError when an op shape or an operand token is not recognised.

    A HELPER CALL BLINDS EVERY ANSWER EXCEPT `arch`.  A helper receives
    `env` and may read the architectural copy of ANY register out of it
    without that read appearing as a TCG global use -- x87, the vector file
    and the segment descriptors are reached exactly that way.  So an
    encoding that calls anything outside the cc_compute_* family keeps its
    positive findings (a read the dump SHOWS is real) and downgrades every
    `preserve` and `not-read` to UNKNOWN, which the caller must treat as a
    refusal.  Saying `not-read` there would be the reader's blindness
    published as a property of the machine.
    """
    ops = []
    for name, args in encoding.ops:
        d, u = defs_uses(name, args)
        d = [x for x in (_value(t) for t in d) if x]
        u = [x for x in (_value(t) for t in u) if x]
        ops.append((name, args, d, u))

    read_globals = set()
    for _n, _a, _d, u in ops:
        read_globals.update(g for g in u if g in GLOBALS)

    verdict = {}
    for g in sorted(read_globals):
        gen = GLOBALS[g]
        for k, (name, args, d, u) in enumerate(ops):
            if g not in u:
                continue
            v = _use_verdict(ops, k, g, name, args, u)
            if verdict.get(gen) != ARCH:
                verdict[gen] = v if verdict.get(gen) in (None, PRESERVE) \
                    else verdict[gen]
            if v == ARCH:
                verdict[gen] = ARCH
    for g, gen in GLOBALS.items():
        verdict.setdefault(gen, NOT_READ)

    opaque = sorted(set(a[0] for n, a, _d, _u in ops
                        if n == 'call' and a and not CC_HELPER.match(a[0])))
    if opaque:
        for k in list(verdict):
            if verdict[k] != ARCH:
                del verdict[k]
    return verdict


def _use_verdict(ops, k, g, name, args, uses):
    """Classify ONE use of global ``g`` at op index ``k``."""
    _n, _a, defs, _u = ops[k]
    is_base = (name.startswith('deposit') and defs == [g]
               and uses and uses[0] == g)

    # Forward taint from the value this op produces.
    taint = set(defs)
    reached = set(x for x in defs if x in GLOBALS)
    through = [name]
    if not taint:
        # A use whose op defines nothing (a store, a branch) publishes the
        # value outside the register file: architectural by construction.
        return ARCH
    for j in range(k + 1, len(ops)):
        nm, ar, dd, uu = ops[j]
        if not (taint & set(uu)):
            continue
        through.append(nm)
        if nm.startswith('qemu_st') or nm.startswith('st'):
            return ARCH             # the value leaves for memory
        taint.update(dd)
        reached.update(x for x in dd if x in GLOBALS)

    if any(t.startswith('movcond') for t in through):
        return ARCH                 # predication, not a width merge (R4)

    if is_base and reached <= {g}:
        return PRESERVE
    if g in FLAGS_GLOBALS and reached and reached <= FLAGS_GLOBALS:
        # Carried, not computed: every op on the path is a plain move or the
        # cc_compute_* call that read the tuple in the first place.
        ok = all(_COPY.match(t) or t == 'call' or t == 'discard'
                 for t in through)
        if ok:
            return PRESERVE
    return ARCH


# --------------------------------------------------------------- the oracle
class Oracle(object):
    """encoding hex -> per-generic-register verdict, or UNKNOWN."""

    def __init__(self):
        self.table = {}             # enc -> {generic: verdict}
        self.disas = {}
        self.refused = collections.Counter()

    def add_dump(self, path):
        for enc, e in parse_dump(path).items():
            if enc in self.table:
                continue
            try:
                self.table[enc] = classify(e)
            except ParseError as exc:
                self.refused['%s: %s' % (e.disas or enc, exc)] += 1
                continue
            self.disas[enc] = e.disas

    def ask(self, enc, generic):
        """'arch' | 'preserve' | 'not-read' | None (REFUSED)."""
        row = self.table.get(enc)
        if row is None:
            return UNKNOWN
        return row.get(generic, UNKNOWN)


def build(qemu, guests, outdir, extra_args=()):
    """Run each guest under `-one-insn-per-tb -d op,in_asm` and read it."""
    os.makedirs(outdir, exist_ok=True)
    o = Oracle()
    logs = []
    for g in guests:
        log = os.path.join(outdir, os.path.basename(g) + '.ops.log')
        cmd = [qemu, '-one-insn-per-tb', '-d', 'op,in_asm', '-D', log]
        cmd += list(extra_args)
        cmd.append(g)
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        if p.returncode != 0:
            raise RuntimeError('qemu op dump for %s exited %d'
                               % (g, p.returncode))
        if not os.path.exists(log):
            raise RuntimeError('no op dump produced for %s' % g)
        o.add_dump(log)
        logs.append(log)
    return o, logs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('guests', nargs='+')
    a = ap.parse_args()
    o, logs = build(a.qemu, a.guests, a.out)
    print('encodings understood: %d' % len(o.table))
    if o.refused:
        print('REFUSED (unparsed op shapes):')
        for k, n in o.refused.most_common():
            print('  %-60s %d' % (k, n))
    n_arch = n_pres = 0
    for enc in sorted(o.table):
        row = o.table[enc]
        pres = sorted(k for k, v in row.items() if v == PRESERVE)
        arch = sorted(k for k, v in row.items() if v == ARCH)
        n_arch += len(arch)
        n_pres += len(pres)
        print('%-18s %-28s preserve=%s arch=%s'
              % (enc, o.disas.get(enc, '')[:28], pres or '-', arch or '-'))
    print('TOTAL preserve-uses %d  architectural-uses %d' % (n_pres, n_arch))
    return 0


if __name__ == '__main__':
    sys.exit(main())
