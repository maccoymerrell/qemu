"""Pin which dependency-breaking idioms the IR extraction sees through.

A dependency-breaking idiom is an instruction whose result does not depend on
its inputs even though the encoding names them: `pxor %xmm0,%xmm0` is how a
compiler says "zero this register", and real out-of-order hardware
special-cases the family precisely so the chain is cut.  A consumer modelling
register renaming wants to know the chain was cut; recording a read there
manufactures a dependency on whatever last wrote the register.

The extraction reports this in two different ways depending on the register,
and the difference is not cosmetic:

  * For a TCG global -- a GPR, the flags -- the signal is the *provenance* of
    the write.  `xorq %r8,%r8` still reads r8 in the op stream, which is
    architecturally correct, but the value stored into r8 came from a
    constant, so the write's provenance is empty and the chain is cut.

  * For state no global names -- x86's whole vector file, reached by load and
    store at a constant env offset -- there is no provenance, so the only
    signal is whether a read of the field is present at all.  `pxor` has none
    because the gvec constructors folded it; `psubb %xmm2,%xmm2` has one
    because they did not.

Which idioms fall which way is decided by where TCG happens to fold, not by
anything architectural, so it is exactly the kind of property that changes
silently under a QEMU update.  This records the current answer for each and
fails if any of them moves.

**It fails in both directions, deliberately.** TCG starting to fold something
alters what dependencies a trace records just as much as TCG stopping, and
neither shows up in any other gate: the goldens would move, but they move for
many reasons and the cause would not be legible.  A change here should stop a
human and make them decide, not be absorbed.

What a post-optimize read would add, measured on this probe
----------------------------------------------------------
The extraction reads the op stream before tcg_optimize, because dead-store
elimination removes architecturally real writes and that is not negotiable.
Constant folding happens after, so some idioms are only visibly broken on the
far side of it.  Dumping both for this probe:

    pre-optimize   cut: pxor / xorps / vpxor family, xorq r,r        (2 of 5)
    post-optimize  cut: the above, plus subq r,r and psubb r,r       (4 of 5)
    neither        pcmpeqd r,r -- not folded at any layer

So a second pass over the optimized stream would recover exactly two idiom
families.  It is not taken, because it cannot be: tcg_optimize() runs inside
tcg_gen_code(), which setjmp_gen_code() calls only after translate_code() has
already fired the plugin's translate callback, so the result would arrive
after the consumer had been handed the instruction.  Buying it would mean
either moving the plugin callback past codegen -- a behaviour change for every
QEMU plugin -- or delivering provenance in a second phase before first
execution.  For two families whose absence errs pessimistic, neither is worth
it, and the pins below are what make the remaining gap explicit instead of
tacit.

The asymmetry worth keeping in mind while deciding: a recorded dependency that
does not exist is pessimistic -- a scheduler serialises where it need not --
while a missing one is wrong, because a consumer reorders across a real
dependency.  So a pin moving from "chain kept" to "chain cut" deserves more
scrutiny than the reverse.

Usage:

    python3 tests/oracle/check-idioms.py --build-dir build

Copyright (c) 2026 Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

PROBE = """
        .text
        .globl _start
_start:
        .globl oracle_begin
oracle_begin:
        pxor    %xmm0,%xmm0
        pcmpeqd %xmm1,%xmm1
        xorq    %r8,%r8
        subq    %r9,%r9
        psubb   %xmm2,%xmm2
        xorps   %xmm3,%xmm3
        vpxor   %xmm4,%xmm4,%xmm4
        pxor    %xmm5,%xmm6
        xorq    %r10,%r11
        .globl oracle_end
oracle_end:
        movq    $60, %rax
        xorq    %rdi, %rdi
        syscall
"""

# mnemonic -> (chain_cut, why).  chain_cut is what the extraction currently
# says, NOT what the architecture says: every same-register entry here is a
# dependency-breaking idiom in hardware, and the ones marked False are the ones
# the extraction does not see through.
#
# The last two entries are controls: different-register forms of the same
# opcodes, which must always keep their dependency.  If a control ever reports
# a cut chain the extraction has broken, not TCG.
# Keyed by position in the probe, not by disassembly text: objdump drops an
# operand-size suffix when it is unambiguous, so "xorq %r8,%r8" comes back as
# "xor %r8,%r8" and a text key silently stops matching.  A pin that stops being
# checked is worse than one that fails, so position is what they are keyed on
# and every one of them has to be reached.
EXPECT = [
    ("pxor    %xmm0,%xmm0",       True,  "gvec constructors fold same-reg xor to a constant store"),
    ("pcmpeqd %xmm1,%xmm1",       False, "all-ones idiom; not folded at any layer -- conservative"),
    ("xorq    %r8,%r8",           True,  "write provenance is empty: the value came from a constant"),
    ("subq    %r9,%r9",           False, "sub_i64 survives; provenance is the register itself"),
    ("psubb   %xmm2,%xmm2",       False, "gvec does not fold same-reg sub; the field read remains"),
    ("xorps   %xmm3,%xmm3",       True,  "same fold as pxor"),
    ("vpxor   %xmm4,%xmm4,%xmm4", True,  "same fold as pxor"),
    ("pxor    %xmm5,%xmm6",       False, "CONTROL: different registers, dependency is real"),
    ("xorq    %r10,%r11",         False, "CONTROL: different registers, dependency is real"),
]


def build(workdir):
    src = os.path.join(workdir, "idioms.S")
    with open(src, "w") as fh:
        fh.write(PROBE)
    elf = os.path.join(workdir, "idioms")
    subprocess.check_call(["gcc", "-nostdlib", "-static", "-o", elf, src])
    return elf


def sym(elf, name):
    for line in subprocess.check_output(["nm", elf], text=True).split("\n"):
        f = line.split()
        if len(f) >= 3 and f[2] == name:
            return int(f[0], 16)
    raise SystemExit("no symbol %s" % name)


def disas(elf, lo, hi):
    out = subprocess.check_output(["objdump", "-d", elf], text=True)
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*(\S+)\s*(.*)", line)
        if not m:
            continue
        pc = int(m.group(1), 16)
        if lo <= pc < hi:
            text = "%-7s %s" % (m.group(2), m.group(3).strip())
            rows.append((pc, " ".join(text.split(None, 1))))
    return rows


def extract(qemu, plugin, elf, workdir, lo, hi):
    """Per-pc (register reads, per-write provenance, field reads)."""
    dump = os.path.join(workdir, "idioms.df")
    env = dict(os.environ)
    env.update({"QEMU_DF_DUMP": dump, "QEMU_DF_PC_LO": hex(lo),
                "QEMU_DF_PC_HI": hex(hi)})
    cmd = [qemu]
    if plugin:
        cmd += ["-plugin", plugin + ",outfile=" +
                os.path.join(workdir, "idioms_trace")]
    cmd.append(elf)
    subprocess.check_call(cmd, env=env, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)

    reg_rd, fld_rd, wr_prov = {}, {}, {}
    for line in open(dump):
        m = re.match(r"^D (0x[0-9a-f]+) ([rwk]) reg=(\S+) off=(\d+)", line)
        if not m:
            continue
        pc, rw, reg = int(m.group(1), 16), m.group(2), m.group(3)
        name = reg if reg != "?" else "@" + m.group(4)
        if rw == "r":
            (fld_rd if reg == "?" else reg_rd).setdefault(pc, set()).add(name)
        elif rw == "w":
            p = re.search(r"from=(\S+)", line)
            if p:
                src = {x for x in p.group(1).split(",") if x not in ("-", "+")}
                wr_prov.setdefault(pc, {})[name] = src
    return reg_rd, fld_rd, wr_prov


def chain_cut(pc, reg_rd, fld_rd, wr_prov):
    """Does the extraction say this instruction's result is independent?

    One signal for both register classes: the provenance of what was written.
    A write whose value came from nowhere this instruction read is a broken
    dependency chain, whether the destination is a GPR or a slice of the
    vector file.

    This used to branch on the register class -- provenance for a global,
    absence-of-a-read for a field -- and the branch was the tell that the two
    classes were answering one question two ways.  The flag fields are still
    excluded, because their write is an artefact of how the flags are
    represented rather than of the idiom being asked about.
    """
    provs = wr_prov.get(pc, {})
    writes = [p for r, p in provs.items() if not r.startswith("cc_")]
    if not writes:
        return False
    return all(not p for p in writes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--workdir", default="/mnt/md0/QEMU/cst_runs/phase4")
    ap.add_argument("--plugin", default=None)
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    qemu = os.path.join(args.build_dir, "qemu-x86_64")
    plugin = args.plugin or os.path.join(
        args.build_dir, "contrib/plugins/libchampsim_tracer.so")
    if not os.path.exists(qemu):
        raise SystemExit("missing %s" % qemu)

    elf = build(args.workdir)
    lo, hi = sym(elf, "oracle_begin"), sym(elf, "oracle_end")
    rows = disas(elf, lo, hi)
    reg_rd, fld_rd, wr_prov = extract(qemu, plugin, elf, args.workdir, lo, hi)

    if len(rows) != len(EXPECT):
        print("probe has %d instructions, %d pins are written down -- the "
              "probe and the table have drifted apart" % (len(rows), len(EXPECT)))
        return 2

    def same_insn(pin, seen):
        """Is the probe's disassembly the instruction the pin was written for?

        objdump drops an operand-size suffix when the operands make it
        unambiguous, so the pin's "xorq" comes back as "xor".  The operands are
        not elided and are what actually identify the form -- same-register
        versus not is the whole point of the pin -- so they must match exactly
        while the mnemonic is allowed to have lost one size character.
        """
        pm, _, po = pin.partition(" ")
        sm, _, so = seen.partition(" ")
        if po.strip() != so.strip():
            return False
        return pm == sm or (pm.startswith(sm) and pm[len(sm):] in "bwlq")

    print("%-28s %-10s %-10s %s" % ("instruction", "expected", "got", ""))
    bad = []
    for (pc, text), (key, want, why) in zip(rows, EXPECT):
        # The probe is a fixed sequence, so position is the key; the text is
        # still checked so a probe edit cannot silently re-point a pin.
        if not same_insn(" ".join(key.split()), " ".join(text.split())):
            print("%-28s pin does not match the probe's %s at that position"
                  % (key, text))
            bad.append((key, want, None, why))
            continue
        got = chain_cut(pc, reg_rd, fld_rd, wr_prov)
        mark = "ok" if got == want else "CHANGED"
        if got != want:
            bad.append((key, want, got, why))
        print("%-28s %-10s %-10s %s  %s" %
              (key, "cut" if want else "kept", "cut" if got else "kept",
               mark, why if got == want else ""))

    if bad:
        print("\n%d idiom(s) changed how the extraction sees them:" % len(bad))
        for k, want, got, why in bad:
            if got is None:
                print("  %-28s pin no longer lines up with the probe" % k)
                continue
            direction = ("now CUT (was kept) -- TCG started folding this. A "
                         "dependency the trace used to record has disappeared; "
                         "check it is genuinely absent before accepting"
                         if got else
                         "now KEPT (was cut) -- TCG stopped folding this. The "
                         "trace has gained a dependency that does not exist, "
                         "which is pessimistic but not wrong")
            print("  %-28s %s" % (k, direction))
            print("  %-28s pinned because: %s" % ("", why))
        return 1
    print("\nall %d idiom pins hold" % len(EXPECT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
