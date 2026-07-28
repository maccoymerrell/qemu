#!/usr/bin/env python3
"""Check what state randomisation recovers, and whether it may be believed.

A differ cannot see a write whose value equals what was already there.  The
oracle's answer is to spoil the destination first (QEMU_ORACLE_POISON), so the
write has to change something.  The catch is that spoiling architectural state
is only free if the instruction does not *read* it, and nothing in the oracle
knows which registers an instruction reads -- that is read detection, which
does not exist yet.

So a poisoned run is a hypothesis, not a measurement, and this script is what
turns it back into one.  It runs the program twice, once clean and once
poisoned, and asks two separate questions:

  recovered   which writes the poisoned run reports that the clean run missed
              -- the point of the exercise

  divergence  whether the poisoned run behaved differently anywhere the poison
              is not supposed to reach: a different exit status, a different
              instruction stream, or a different write at some *other* address.
              Any of those means the poison was read by something and the
              recovered writes are not trustworthy.

Usage:

    python3 tests/oracle/check-poison.py --build-dir build-oracle

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
INTERPRET = os.path.join(HERE, "oracle-interpret.py")

CROSS = {
    "riscv64": "riscv64-linux-gnu-",
    "mipsel": "mipsel-linux-gnu-",
    "aarch64": "aarch64-linux-gnu-",
}

# Each case is a blind spot the phase-1 report named, the poison aimed at it,
# and what the poison is expected to bring back.  "at" is a mnemonic; its pc is
# resolved from the probe's disassembly so the cases survive edits to the .S.
CASES = [
    {
        "name": "riscv64/sc.d writes rd",
        "probe": "probe_riscv64",
        "arch": "riscv64",
        "cflags": ["-march=rv64gcv"],
        "at": "sc.d",
        # rd is x7/t2.  A successful store-conditional writes 0, and rd was
        # already 0, so the clean run sees nothing at all.
        "poison": "{x7}:8:r",
        "expect": {"x7/t2"},
    },
    {
        "name": "riscv64/fcvt.w.d writes rd and raises inexact",
        "probe": "probe_riscv64",
        "arch": "riscv64",
        "cflags": ["-march=rv64gcv"],
        "at": "fcvt.w.d",
        # Both halves are invisible: rd receives 0 over 0, and inexact was
        # already set by the fadd.d earlier in the probe.
        "poison": "{x29}:8:r,{fflags}:1:o",
        "expect": {"x29/t4", "raw@{fflags}"},
    },
    {
        "name": "aarch64/fcmp writes all four flag words",
        "probe": "probe_aarch64",
        "arch": "aarch64",
        "cflags": [],
        "at": "fcmp",
        # A phase-2 find: fcmp d2, d3 sets N and clears Z, C and V -- but C
        # and V were already clear, so the clean run reports only two of the
        # four flag words the instruction actually writes.
        "poison": "{CF}:4:r,{VF}:4:r",
        "expect": {"CF", "VF"},
    },
    {
        "name": "riscv64/repeat fdiv.d raises inexact each time",
        "probe": "probe_riscv64_sticky",
        "arch": "riscv64",
        "cflags": ["-march=rv64gcv_zfa"],
        "at": "fdiv.d",
        "nth": 3,
        # The acute case.  Once inexact is set it stays set, so the second and
        # third fdiv.d write a value equal to the old one and are invisible for
        # the rest of the run.  Clearing the accumulator before each
        # instruction and OR-ing it back afterwards recovers them.
        "poison": "{fflags}:2:o",
        "everywhere": True,
        "expect": {"raw@{fflags}"},
    },
    {
        # Positive control.  A checker that has never fired is not evidence of
        # anything, so one case must poison something the instruction reads:
        # add a2, a0, a1 with a0 spoiled computes a different sum, and
        # everything downstream of it differs.  If this case stops reporting
        # divergence, the divergence check has gone blind and the cases above
        # stop meaning anything.
        "name": "riscv64/poisoning a source register (control)",
        "probe": "probe_riscv64",
        "arch": "riscv64",
        "cflags": ["-march=rv64gcv"],
        "at": "add",
        "poison": "{x10}:8:r",
        "expect_divergence": True,
    },
    {
        "name": "mipsel/mult writes the high half",
        "probe": "probe_mipsel",
        "arch": "mipsel",
        "cflags": [],
        "at": "mult",
        # The product fits in 32 bits, so HI is 0 and was already 0.
        "poison": "{HI0}:4:r",
        "expect": {"HI0"},
    },
]


def sym(elf, prefix, name):
    out = subprocess.check_output([prefix + "nm", elf], text=True)
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and f[2] == name:
            return int(f[0], 16)
    raise SystemExit("symbol %s not found in %s" % (name, elf))


def find_insn(elf, prefix, mnem, lo, hi, nth=1):
    out = subprocess.check_output([prefix + "objdump", "-d", elf], text=True)
    seen = 0
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\s+[0-9a-f ]+\t\s*(\S+)", line)
        if m and lo <= int(m.group(1), 16) < hi and m.group(2) == mnem:
            seen += 1
            if seen == nth:
                return int(m.group(1), 16)
    raise SystemExit("instruction %s #%d not found in %s" % (mnem, nth, elf))


def run(qemu, elf, report, lo, hi, poison=None):
    env = dict(os.environ)
    env.update({"QEMU_ORACLE": report,
                "QEMU_ORACLE_PC_LO": hex(lo), "QEMU_ORACLE_PC_HI": hex(hi)})
    if poison:
        env["QEMU_ORACLE_POISON"] = poison
    p = subprocess.run([qemu, elf], env=env, capture_output=True)
    return p.returncode, p.stdout, p.stderr


def parse(path):
    """Report -> (globals by name, per-pc write sets, pc stream, poisoned set)."""
    gmap, writes, stream, poisoned = {}, {}, [], set()
    with open(path) as fh:
        for line in fh:
            f = line.split()
            if not f:
                continue
            if f[0] == "G":
                gmap[f[3]] = (int(f[1]), int(f[2]))
            elif f[0] == "I":
                stream.append(int(f[1], 16))
            elif f[0] in ("P", "R"):
                off = int(f[2].split("=")[1])
                poisoned.add(off)
            elif f[0] == "W":
                pc = int(f[1], 16)
                if f[2].startswith("reg="):
                    what = f[2][4:]
                elif f[2] == "raw":
                    what = "raw@" + f[3].split("=")[1]
                else:
                    continue
                new = ""
                for tok in f:
                    if tok.startswith("new="):
                        new = tok[4:]
                writes.setdefault(pc, {})[what] = new
    return gmap, writes, stream, poisoned


def offset_of(gmap, token):
    """Resolve {name} in a poison spec to the offset TCG gave that global."""
    if token in gmap:
        return gmap[token][0]
    for name, (off, _size) in gmap.items():
        if name.split("/")[0] == token or token in name.split("/"):
            return off
    raise SystemExit("no TCG global named %s" % token)


def sticky_offset(build_dir, arch):
    """Offset of the sticky FP exception accumulator, from DWARF."""
    p = subprocess.run([sys.executable, INTERPRET, "--target", arch,
                        "--build-dir", build_dir, "--sticky"],
                       capture_output=True, text=True)
    spec = p.stdout.strip()
    if p.returncode != 0 or not spec:
        return None
    return int(spec.split(",")[0].split(":")[0])


def run_case(case, build_dir, workdir, keep):
    prefix = CROSS[case["arch"]]
    if shutil.which(prefix + "gcc") is None:
        print("SKIP %-44s (no %sgcc)" % (case["name"], prefix))
        return None
    qemu = os.path.join(build_dir, "qemu-" + case["arch"])
    if not os.path.exists(qemu):
        print("SKIP %-44s (no %s)" % (case["name"], qemu))
        return None

    src = os.path.join(HERE, case["probe"] + ".S")
    elf = os.path.join(workdir, case["probe"] + "-poison")
    subprocess.check_call([prefix + "gcc"] + case["cflags"] +
                          ["-nostdlib", "-static", "-o", elf, src])
    lo = sym(elf, prefix, "oracle_begin")
    hi = sym(elf, prefix, "oracle_end")
    pc = find_insn(elf, prefix, case["at"], lo, hi, case.get("nth", 1))

    clean_path = os.path.join(workdir, case["probe"] + ".clean")
    rc_c, out_c, _ = run(qemu, elf, clean_path, lo, hi)
    gmap, w_clean, s_clean, _ = parse(clean_path)

    # Calibrate.  Some values are not the poison's fault and never will be:
    # rdcycle reads a real cycle counter, so it differs between any two runs.
    # Rather than keep a list of those per target, run clean twice and treat
    # whatever moved on its own as out of scope.
    clean2_path = os.path.join(workdir, case["probe"] + ".clean2")
    run(qemu, elf, clean2_path, lo, hi)
    _, w_clean2, _, _ = parse(clean2_path)
    unstable = set()
    for opc, ws in w_clean.items():
        for what, val in ws.items():
            if w_clean2.get(opc, {}).get(what) != val:
                unstable.add((opc, what))

    # Resolve the {name} tokens once, then substitute into both the poison
    # spec and the expectation so they cannot disagree.  Everything resolves
    # through the TCG globals table except fflags, which is not a global on any
    # target -- it is the raw run the clean report already shows, so take its
    # offset from there rather than inventing one.
    tokens = set(re.findall(r"\{(\w+)\}", case["poison"] + " " +
                            " ".join(case.get("expect", ()))))
    subst = {}
    for token in tokens:
        if token == "fflags":
            # Not a TCG global on any target.  Ask the interpretation layer,
            # which reads it out of the build's own debug information, rather
            # than guessing from whichever raw run happens to be lowest.
            off = sticky_offset(build_dir, case["arch"])
            if off is None:
                print("SKIP %-44s (cannot locate the sticky FP flags)"
                      % case["name"])
                return None
            subst[token] = off
        else:
            subst[token] = offset_of(gmap, token)

    def fill(text):
        for token, off in subst.items():
            text = text.replace("{%s}" % token, str(off))
        return text

    spec = fill(case["poison"])
    expect = {fill(e) for e in case.get("expect", ())}

    if not case.get("everywhere"):
        spec = ",".join(s + "@" + hex(pc) for s in spec.split(","))
    dirty_path = os.path.join(workdir, case["probe"] + ".poisoned")
    rc_p, out_p, _ = run(qemu, elf, dirty_path, lo, hi, spec)
    _, w_dirty, s_dirty, poisoned = parse(dirty_path)

    recovered = set(w_dirty.get(pc, {})) - set(w_clean.get(pc, {}))

    # Divergence.  The poisoned run is only evidence if it behaved the same
    # everywhere the poison was not aimed.
    #
    # A poison applied at every instruction rather than at one is *expected* to
    # recover writes at other addresses too, so those recoveries are not
    # divergence.  Only the poisoned ranges themselves get that latitude:
    # anything else changing is the poison having been read.
    expected_gain = set()
    for part in spec.split(","):
        off = int(part.split(":")[0])
        expected_gain.add("raw@%d" % off)
        for name, (goff, _gsize) in gmap.items():
            if goff == off:
                expected_gain.add(name)

    problems = []
    if rc_c != rc_p or out_c != out_p:
        problems.append("guest behaved differently (rc %d vs %d)" % (rc_c, rc_p))
    if s_clean != s_dirty:
        problems.append("instruction stream diverged (%d vs %d marks)"
                        % (len(s_clean), len(s_dirty)))
    for other in set(w_clean) | set(w_dirty):
        a, b = w_clean.get(other, {}), w_dirty.get(other, {})
        if other != pc and \
                ((set(b) - set(a)) - expected_gain or (set(a) - set(b))):
            problems.append("0x%x write set changed: %s -> %s"
                            % (other, sorted(a) or "-", sorted(b) or "-"))
            continue
        # Membership matching is not enough.  Poisoning a register an
        # instruction *reads* leaves the write set alone and changes only the
        # value written, so a check that compares names alone reports nothing
        # at all -- which is what this one did until the control case caught
        # it.  Compare what was written, not just where.
        # The target instruction is checked too, minus the ranges that were
        # deliberately spoiled: poisoning a register it *reads* shows up as a
        # different value written to some *other* register of the same
        # instruction, and nowhere else at all.
        for what, val in b.items():
            if what in expected_gain or (other, what) in unstable:
                continue
            if what in a and a[what] != val:
                problems.append("0x%x %s value changed: %s -> %s"
                                % (other, what, a[what], val))

    if case.get("expect_divergence"):
        ok = bool(problems)
        print("%s %-44s divergence detected: %s" %
              ("PASS" if ok else "FAIL", case["name"],
               "yes (%d)" % len(problems) if problems else "NO -- check blind"))
        for p in problems[:3]:
            print("       %s" % p)
    else:
        ok = recovered == expect and not problems
        tag = "PASS" if ok else "FAIL"
        print("%s %-44s recovered {%s}" %
              (tag, case["name"], ", ".join(sorted(recovered)) or "-"))
        if recovered != expect:
            print("       expected {%s}" % (", ".join(sorted(expect)) or "-"))
        for p in problems:
            print("       DIVERGENCE: %s" % p)
    if not keep:
        for f in (clean_path, clean2_path, dirty_path, elf):
            if os.path.exists(f):
                os.remove(f)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build-oracle")
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    workdir = args.workdir
    if workdir is None:
        import tempfile
        workdir = tempfile.mkdtemp(prefix="oracle-poison-")
    os.makedirs(workdir, exist_ok=True)

    results = [run_case(c, args.build_dir, workdir, args.keep) for c in CASES]
    ran = [r for r in results if r is not None]
    if not ran:
        print("no cases ran")
        return 2
    print("%d/%d poison cases passed" % (sum(1 for r in ran if r), len(ran)))
    return 0 if all(ran) else 1


if __name__ == "__main__":
    sys.exit(main())
