"""Prove that the IR-derived dataflow does not depend on Capstone's operands.

Capstone is retained, permanently, for instruction identification.  What
changes is not whether it is called but what is asked of it and acted on:

    KEPT      decoding bytes to a mnemonic; the opcode taxonomy derived from
              that mnemonic; branch classification; instruction length and the
              boundary that follows from it -- everything the mnemonic table
              exists to do, which is translating an ISA-specific instruction
              into the generic format.

    REPLACED  register read and write sets; implicit operands; tied operands;
              memory operand directions; lane masks; and every boundary
              workaround whose purpose was repairing one of those.

So a wrong mnemonic from Capstone is still a defect that reaches the trace.
That is the one permitted coupling and it is deliberate, not residual.

The claim this checks is an absence: no path exists by which a Capstone
operand, access flag, or register-list error can reach the dependency model.
It is emphatically NOT a claim that Capstone was removed.

An absence cannot be established by reading the code, because the whole
failure mode is a path nobody remembered was there.  So it is established by
breaking the input: QEMU_CAP_MUTATE corrupts what the Capstone boundary hands
across -- see cap_mutate_detail() in disas/capstone.c -- and this runs each
mutation twice.

    positive control   the tracer's own answer for the same encodings MUST
                       move.  A mutation nothing notices proves nothing, and
                       a run where every mutation is silently inert would
                       otherwise look exactly like a pass.

    the claim          the oracle's IR-derived report must be byte-identical
                       to the unmutated one.

A mode passes when the control moved and the report did not.  ``mnem`` is the
exception and is asserted the other way round: the opcode class must move,
because that is the dependency the design keeps.

Usage:

    python3 tests/oracle/check-independence.py \
        --build-dir build-oracle --tracer-build build --workdir /mnt/md0/...

Copyright (c) 2026 Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# Every dataflow fact the boundary carries.  mnem is handled separately.
DATAFLOW_MODES = ("access", "drop", "addreg", "implicit", "memdir", "all")

# The lines of the report that state a dataflow fact.  The header lines carry
# an env address and the poison seed, neither of which is under test.
FACT = re.compile(r"^[DACYV] ")


# Cross prefixes, same map check-oracle.py uses.  x86_64 is native.
CROSS = {
    "x86_64": "",
    "riscv64": "riscv64-linux-gnu-",
    "mipsel": "mipsel-linux-gnu-",
    "aarch64": "aarch64-linux-gnu-",
}

# Per-ISA assembler flags, same values check-oracle.py uses.  The riscv64
# probe contains vsetvli, which needs the V extension enabled explicitly.
PROBE_CFLAGS = {
    "x86_64": [],
    "riscv64": ["-march=rv64gcv"],
    "mipsel": ["-mfp32", "-modd-spreg"],
    "aarch64": [],
}


def build_probe(workdir, isa):
    """Assemble the probe FOR THIS ISA.

    This used to default to probe_x86_64 and ignore --isa entirely, so
    `--isa aarch64` ran qemu-aarch64 on an x86_64 ELF and died at exit 255.
    The flag existed, the check could only ever run on one target, and the
    other three had never been exercised.
    """
    if isa not in CROSS:
        raise SystemExit("unknown isa %s (have %s)"
                         % (isa, ", ".join(sorted(CROSS))))
    name = "probe_" + isa
    src = os.path.join(HERE, name + ".S")
    if not os.path.exists(src):
        raise SystemExit("no probe source %s" % src)
    prefix = CROSS[isa]
    if prefix and shutil.which(prefix + "gcc") is None:
        raise SystemExit("no %sgcc -- install the cross toolchain for %s"
                         % (prefix, isa))
    elf = os.path.join(workdir, name)
    subprocess.check_call([prefix + "gcc"] + PROBE_CFLAGS[isa]
                          + ["-nostdlib", "-static", "-o", elf, src])
    return elf


def sym(elf, name, prefix=""):
    out = subprocess.check_output([prefix + "nm", elf], text=True)
    for line in out.split("\n"):
        f = line.split()
        if len(f) >= 3 and f[2] == name:
            return int(f[0], 16)
    raise SystemExit("no symbol %s in %s" % (name, elf))


def oracle_facts(qemu, elf, workdir, mutate, helper_reads, prefix=""):
    report = os.path.join(workdir, "indep-%s.oracle" % (mutate or "base"))
    env = dict(os.environ)
    env.update({"QEMU_ORACLE": report,
                "QEMU_ORACLE_PC_LO": hex(sym(elf, "oracle_begin", prefix)),
                "QEMU_ORACLE_PC_HI": hex(sym(elf, "oracle_end", prefix)),
                "QEMU_ORACLE_HELPER_READS": "1" if helper_reads else "0"})
    env.pop("QEMU_CAP_MUTATE", None)
    if mutate:
        env["QEMU_CAP_MUTATE"] = mutate
    subprocess.check_call([qemu, elf], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(report) as fh:
        return [ln for ln in fh if FACT.match(ln)]


def disas_encodings(elf, lo, hi, prefix=""):
    # The CROSS objdump, not the host one: a native objdump refuses a
    # foreign ELF outright, which is how --isa stayed unexercised.
    out = subprocess.check_output(
        [prefix + "objdump", "-d", "--insn-width=16", elf], text=True)
    # objdump renders the encoding two ways.  x86 prints space-separated
    # bytes in MEMORY order ("48 ff cb").  The fixed-width targets print the
    # instruction WORD ("8b010002"), which on these little-endian ISAs is the
    # memory bytes reversed -- so a word must be byte-swapped to become the
    # hex string every other tool here speaks.  Reading the word as if it
    # were already memory order is how three ISAs parsed zero encodings and
    # the check reported 0/0.  0/0 fails loudly rather than passing, which is
    # the only reason this was visible at all.
    seen, rows = set(), []
    row_re = re.compile(r"\s+([0-9a-f]+):\t([0-9a-f ]+?)\t+(.*)")
    for line in out.splitlines():
        m = row_re.match(line)
        if not m:
            continue
        if not lo <= int(m.group(1), 16) < hi:
            continue
        field = m.group(2).strip()
        if " " in field:
            hexb = field.replace(" ", "")            # already memory order
        else:
            if len(field) % 2:
                continue
            b = [field[i:i + 2] for i in range(0, len(field), 2)]
            hexb = "".join(reversed(b))              # word -> LE memory order
        if not hexb:
            continue
        if hexb not in seen:
            seen.add(hexb)
            rows.append((hexb, m.group(3).strip()))
    return rows


FIELDS = re.compile(r"^\s*(SRC|DST)\{([^}]*)\}")
OPCLASS = re.compile(r"^fields\s+ok=\d+\s+(\S+)\s+(\S+)")


def tracer_answer(tool, isa, hexb, mutate):
    """The tracer's own dataflow and opcode class for one encoding."""
    env = dict(os.environ)
    env.pop("QEMU_CAP_MUTATE", None)
    if mutate:
        env["QEMU_CAP_MUTATE"] = mutate
    out = subprocess.run([tool, "--isa=" + isa, "--hex=" + hexb],
                         capture_output=True, text=True, env=env).stdout
    src, dst, opclass, mem, fields = set(), set(), None, None, False
    for line in out.splitlines():
        m = OPCLASS.match(line)
        if m:
            opclass, fields = m.group(1), True
            continue
        if line.startswith("boundary-in-generic"):
            break
        if not fields:
            continue
        if "loads=" in line:
            mem = line.strip()
        m = FIELDS.match(line)
        if m:
            toks = frozenset(t.strip() for t in m.group(2).split(",")
                             if t.strip() and t.strip() != "-")
            if m.group(1) == "SRC":
                src = toks
            else:
                dst = toks
    return (frozenset(src), frozenset(dst), mem), opclass


# The translation units the DATAFLOW is derived in -- not the tracer as a
# whole, which calls Capstone on every newly translated instruction and always
# will.  Nothing Capstone defines may appear among the undefined symbols of
# these particular objects: that is the absence of the operand path, stated in
# a form the linker can be asked about.
DERIVATION_OBJS = (
    "libqemu-%s-linux-user.a.p/accel_tcg_oracle.c.o",
)
FORBIDDEN_SYM = re.compile(r"^(cs_|cap_disas|cap_fill|cap_get|capstone)")


def check_no_capstone_symbols(build_dir, isa):
    """Does the derivation link against the decoder at all?"""
    bad, checked = [], []
    for pat in DERIVATION_OBJS:
        obj = os.path.join(build_dir, pat % isa)
        if not os.path.exists(obj):
            continue
        checked.append(obj)
        out = subprocess.check_output(["nm", "-u", obj], text=True)
        for line in out.splitlines():
            name = line.split()[-1]
            if FORBIDDEN_SYM.match(name):
                bad.append((obj, name))
    return checked, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build-oracle")
    ap.add_argument("--tracer-build", default="build")
    ap.add_argument("--workdir", default="/mnt/md0/QEMU/cst_runs/oracle_p3")
    ap.add_argument("--isa", default="x86_64")
    ap.add_argument("--no-helper-reads", action="store_true",
                    help="skip the interior probes, which are slow")
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    qemu = os.path.join(args.build_dir, "qemu-" + args.isa)
    isax = os.path.join(args.tracer_build, "contrib/plugins/isaxcheck")
    for p in (qemu, isax):
        if not os.path.exists(p):
            raise SystemExit("missing %s" % p)

    elf = build_probe(args.workdir, args.isa)
    xprefix = CROSS[args.isa]
    lo, hi = (sym(elf, "oracle_begin", xprefix),
              sym(elf, "oracle_end", xprefix))
    encodings = disas_encodings(elf, lo, hi, xprefix)
    hr = not args.no_helper_reads

    checked, bad = check_no_capstone_symbols(args.build_dir, args.isa)
    if not checked:
        print("static: no derivation object found under %s (built?)"
              % args.build_dir)
    elif bad:
        print("static: FAIL -- %s references %s"
              % (bad[0][0], ", ".join(sorted({n for _, n in bad}))))
    else:
        print("static: %s has no undefined Capstone symbol"
              % ", ".join(os.path.basename(c) for c in checked))
    static_ok = bool(checked) and not bad

    base_facts = oracle_facts(qemu, elf, args.workdir, None, hr, xprefix)
    base_tracer = {h: tracer_answer(isax, args.isa, h, None)
                   for h, _ in encodings}
    print("probe: %d instructions, %d distinct encodings, "
          "%d IR-derived dataflow lines"
          % (len(encodings), len(base_tracer), len(base_facts)))

    ok = True
    print("\n%-9s %-28s %s" % ("mutation", "positive control", "IR-derived"))
    for mode in DATAFLOW_MODES + ("mnem",):
        moved = sum(1 for h, _ in encodings
                    if tracer_answer(isax, args.isa, h, mode)[0]
                    != base_tracer[h][0])
        classmoved = sum(1 for h, _ in encodings
                         if tracer_answer(isax, args.isa, h, mode)[1]
                         != base_tracer[h][1])
        facts = oracle_facts(qemu, elf, args.workdir, mode, hr, xprefix)
        drift = sum(1 for a, b in zip(base_facts, facts) if a != b)
        drift += abs(len(base_facts) - len(facts))

        if mode == "mnem":
            # The permitted dependency, asserted rather than forbidden.
            good = classmoved > 0 and drift == 0
            ctrl = "opcode class moved on %d/%d" % (classmoved, len(encodings))
        else:
            good = moved > 0 and drift == 0
            ctrl = "tracer dataflow moved on %d/%d" % (moved, len(encodings))
        print("%-9s %-28s %s%s" %
              (mode, ctrl,
               "unchanged" if drift == 0 else "MOVED on %d lines" % drift,
               "" if good else "   <-- FAIL"))
        ok = ok and good
    ok = ok and static_ok

    print("\n%s" % ("PASS: the IR-derived dataflow is indifferent to every "
                     "mutation, and the opcode class is not"
                     if ok else "FAIL"))
    print("scope: this establishes the property for the derivation.  The "
          "plugin still takes its\n       dataflow from Capstone; pointing "
          "the same check at a plugin-produced trace is\n       what will "
          "gate the rewiring.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
