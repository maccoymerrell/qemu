#!/usr/bin/env python3
"""Check the behavioural oracle against write sets we already know for certain.

Each probe program under this directory contains a run of instructions between
the symbols ``oracle_begin`` and ``oracle_end`` whose architectural effect on
the register file is not in doubt.  This script assembles a probe, runs it
under an oracle-enabled QEMU, and compares the reported write set against the
expectation recorded below.  A disagreement is either an oracle bug or a QEMU
bug; both are worth finding.

Usage:

    python3 tests/oracle/check-oracle.py --build-dir build-oracle

The build directory must have been configured with --enable-oracle.

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

# Expectations are keyed by position in the oracle_begin..oracle_end run so a
# change to the surrounding code cannot silently shift them.  Each entry is
# (mnemonic, {register names expected to change}).  "pc" is deliberately absent
# from every entry that is not a control transfer: QEMU materialises the guest
# pc lazily, so a plain arithmetic instruction never stores it.  "raw@N" names
# a byte range that no TCG global covers -- state the oracle can see but cannot
# yet name, which is what the interpretation layer has to resolve.
PROBES = {
    "probe_riscv64": {
        "arch": "riscv64",
        "cflags": ["-march=rv64gcv"],
        "expect": [
            ("nop",       set()),                       # writes nothing
            ("add",       {"x12/a2"}),
            ("sub",       {"x13/a3"}),
            ("addi",      set()),                       # rd = x0, discarded
            ("slli",      {"x14/a4"}),
            ("lui",       {"x15/a5"}),
            ("ld",        {"x16/a6"}),
            ("sd",        set()),                       # memory only
            ("mul",       {"x17/a7"}),
            ("div",       {"x5/t0"}),
            ("jal",       {"x1/ra", "pc"}),
            ("lr.d",      {"x6/t1", "load_res", "load_val"}),
            ("sc.d",      {"load_res"}),                # rd write is 0 == old
            ("amoadd.d",  {"x28/t3"}),
            ("fadd.d",    {"f10/fa0", "raw@4944"}),     # + fp_status flags
            ("fmul.d",    {"raw@4944"}),                # result underflows to 0
            ("fcvt.w.d",  set()),                       # 0 == old, flag already set
            ("rdcycle",   {"x30/t5", "pc"}),
            ("vsetvli",   {"x31/t6", "vl", "pc", "raw@4640", "raw@4648"}),
        ],
    },
    "probe_riscv64_poisoned": {
        "arch": "riscv64",
        "cflags": ["-march=rv64gcv"],
        "expect": [
            ("sc.d",      {"x7/t2", "load_res"}),       # now visible: rd = 0
            ("fmul.d",    {"f13/fa3"}),                 # 1.5 * 2.25, exact
            ("fcvt.w.d",  {"x29/t4", "raw@4944"}),      # 1.5 -> 2 (RNE), inexact
            ("slt",       {"x9/s1"}),
            ("sltu",      {"x18/s2"}),                  # now visible: 0
            ("addi",      set()),                       # rd = x0
            ("frcsr",     {"x5/t0", "pc"}),             # rs1 = x0: no CSR write
            ("fscsr",     {"pc", "raw@4944"}),          # rd = x0: no reg write
            ("vsetvli",   {"x19/s3", "vl", "pc", "raw@4640", "raw@4648"}),
            ("vadd.vv",   set()),                       # 0 + 0 into a zero vreg
        ],
    },
    "probe_riscv64_vector": {
        "arch": "riscv64",
        "cflags": ["-march=rv64gcv"],
        # vreg is not a TCG global; off = offsetof(vreg) + vd * vlenb.
        "expect": [
            ("vadd.vv",   {"raw@528"}),                 # vreg(512) + 1 * 16
            ("vmul.vv",   {"raw@576", "raw@584"}),      # vreg(512) + 4 * 16
        ],
    },
    "probe_mipsel": {
        "arch": "mipsel",
        "cflags": [],
        "expect": [
            ("addu",      {"a2"}),
            ("subu",      {"a3"}),
            ("addu",      set()),                       # rd = $0, discarded
            ("mult",      {"LO0"}),                     # HI0 result is 0 == old
            ("sll",       {"t0"}),
            ("slt",       {"t1"}),
        ],
    },
}

CROSS = {
    "riscv64": "riscv64-linux-gnu-",
    "mipsel": "mipsel-linux-gnu-",
}


def sym(elf, prefix, name):
    out = subprocess.check_output([prefix + "nm", elf], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == name:
            return int(parts[0], 16)
    raise SystemExit("symbol %s not found in %s" % (name, elf))


def disas_range(elf, prefix, lo, hi):
    out = subprocess.check_output([prefix + "objdump", "-d", elf], text=True)
    insns = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\s+[0-9a-f ]+\t\s*(\S+)", line)
        if not m:
            continue
        pc = int(m.group(1), 16)
        if lo <= pc < hi:
            insns.append((pc, m.group(2)))
    return insns


def run_probe(name, spec, build_dir, workdir, keep):
    prefix = CROSS[spec["arch"]]
    if shutil.which(prefix + "gcc") is None:
        print("SKIP %-24s (no %sgcc)" % (name, prefix))
        return None

    src = os.path.join(HERE, name + ".S")
    elf = os.path.join(workdir, name)
    subprocess.check_call([prefix + "gcc"] + spec["cflags"] +
                          ["-nostdlib", "-static", "-o", elf, src])

    lo = sym(elf, prefix, "oracle_begin")
    hi = sym(elf, prefix, "oracle_end")
    insns = disas_range(elf, prefix, lo, hi)

    report = os.path.join(workdir, name + ".oracle")
    qemu = os.path.join(build_dir, "qemu-" + spec["arch"])
    if not os.path.exists(qemu):
        print("SKIP %-24s (no %s)" % (name, qemu))
        return None
    env = dict(os.environ)
    env.update({
        "QEMU_ORACLE": report,
        "QEMU_ORACLE_PC_LO": hex(lo),
        "QEMU_ORACLE_PC_HI": hex(hi),
    })
    subprocess.check_call([qemu, elf], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    writes = {pc: set() for pc, _ in insns}
    with open(report) as fh:
        for line in fh:
            if not line.startswith("W "):
                continue
            f = line.split()
            pc = int(f[1], 16)
            if pc not in writes:
                continue
            if f[2].startswith("reg="):
                writes[pc].add(f[2][4:])
            elif f[2] == "raw":
                writes[pc].add("raw@" + f[3].split("=")[1])

    expect = spec["expect"]
    if len(expect) != len(insns):
        print("FAIL %-24s expectation covers %d insns, probe has %d"
              % (name, len(expect), len(insns)))
        return False

    ok = True
    for (pc, mnem), (emnem, eset) in zip(insns, expect):
        if not mnem.startswith(emnem.split(".")[0]) and mnem != emnem:
            print("FAIL %-24s 0x%x: expected mnemonic %s, disassembly says %s"
                  % (name, pc, emnem, mnem))
            ok = False
            continue
        got = writes[pc]
        if got != eset:
            print("FAIL %-24s 0x%x %-10s expected {%s} got {%s}"
                  % (name, pc, mnem,
                     ", ".join(sorted(eset)) or "-",
                     ", ".join(sorted(got)) or "-"))
            ok = False
    if ok:
        print("PASS %-24s %d instructions, write sets match the ISA manual"
              % (name, len(insns)))
    if not keep:
        os.remove(report)
        os.remove(elf)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build-oracle")
    ap.add_argument("--workdir", default=None,
                    help="where to put binaries and reports (default: tmpdir)")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--probe", action="append",
                    help="run only this probe (repeatable)")
    args = ap.parse_args()

    workdir = args.workdir
    if workdir is None:
        import tempfile
        workdir = tempfile.mkdtemp(prefix="oracle-check-")
    os.makedirs(workdir, exist_ok=True)

    results = []
    for name, spec in PROBES.items():
        if args.probe and name not in args.probe:
            continue
        results.append(run_probe(name, spec, args.build_dir, workdir,
                                 args.keep))

    ran = [r for r in results if r is not None]
    if not ran:
        print("no probes ran")
        return 2
    print("%d/%d probes passed" % (sum(1 for r in ran if r), len(ran)))
    return 0 if all(ran) else 1


if __name__ == "__main__":
    sys.exit(main())
