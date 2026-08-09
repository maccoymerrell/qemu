#!/usr/bin/env python3
"""Turn the oracle's raw env offsets into architectural registers.

The oracle reports what an instruction changed in CPUArchState.  Where a target
registered the storage as a TCG global, the report already carries a name; the
rest -- vector files, FP status words, the flag words ARM keeps outside the
globals table -- arrives as a byte offset and a length, and phase 1 resolved
those by hand with gdb.  This does it automatically, and then does the part
that hand-resolution kept getting wrong: says which *architectural* register
the bytes belong to.

Three things stand between a field path and a register name, and they are not
the same thing:

  the offset -> field map    DWARF, read from the binary that produced the
                             report.  No target-specific code, and it cannot
                             drift from what it describes.

  the field -> register map  arithmetic, per target.  RISC-V vector registers
                             live at vreg_ofs(vd) = offsetof(vreg) + vd*vlenb,
                             so vd is recoverable by inverting it.

  the width and the lane     NOT recoverable from the map, and this is the
                             trap.  MIPS fpr_t is a sixteen-byte union and the
                             TCG globals name only its low eight bytes.  The
                             hardware aliases the odd single-precision
                             registers onto the upper halves of the even ones
                             when FR=0 -- but QEMU does not store them that
                             way, it gives every register its own slot in both
                             modes and emulates the aliasing by redirection.
                             So fpr[n] + 4 is never the odd single, and which
                             architectural register fpr[n] holds still depends
                             on the mode and on the width of the access.  A
                             byte range does not know either.  The annotation
                             says so instead of guessing.

Usage:

    python3 tests/oracle/oracle-interpret.py report.oracle --build-dir build-oracle
    python3 tests/oracle/oracle-interpret.py report.oracle --merge
    python3 tests/oracle/oracle-interpret.py --target riscv64 --sticky

Copyright (c) 2026 Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# The offset -> field map, from DWARF
# ---------------------------------------------------------------------------

def load_layout(build_dir, target, cache_dir):
    """Extract CPUArchState's layout from the oracle build's debug info."""
    binary = os.path.join(build_dir, "qemu-" + target)
    if not os.path.exists(binary):
        raise SystemExit("no %s (configure that target with --enable-oracle)"
                         % binary)
    os.makedirs(cache_dir, exist_ok=True)
    cache = os.path.join(cache_dir, "layout-%s.json" % target)
    if os.path.exists(cache) and \
            os.path.getmtime(cache) > os.path.getmtime(binary):
        with open(cache) as fh:
            return json.load(fh)

    script = os.path.join(HERE, "oracle_layout.py")
    p = subprocess.run(["gdb", "--batch", "-nx", binary, "-x", script,
                        "-ex", "python dump(%r)" % cache],
                       capture_output=True, text=True)
    if not os.path.exists(cache):
        raise SystemExit("gdb could not read the layout:\n%s\n%s"
                         % (p.stdout, p.stderr))
    with open(cache) as fh:
        return json.load(fh)


def resolve(node, off, base=0, path="", out=None, depth=0):
    """All field paths covering byte @off.  A union contributes every arm."""
    if out is None:
        out = []
    kind = node.get("kind")
    size = node.get("size", 0)
    if not (base <= off < base + size):
        return out

    if kind == "array":
        esz = node["elem_size"]
        i = (off - base) // esz
        resolve(node["elem"], off, base + i * esz,
                "%s[%d]" % (path, i), out, depth + 1)
        return out

    if kind in ("struct", "union"):
        for kid in node.get("children", []):
            kbase = base + kid["off"]
            name = kid.get("name", "?")
            kpath = ("%s.%s" % (path, name)) if path else name
            if kid.get("kind") == "bitfield":
                if kbase <= off < kbase + kid["size"]:
                    out.append({"path": kpath, "off": kbase,
                                "size": kid["size"], "type": kid["type"],
                                "bitfield": True})
                continue
            resolve(kid, off, kbase, kpath, out, depth + 1)
        return out

    out.append({"path": path or node.get("name", "?"), "off": base,
                "size": size, "type": node.get("type", "?")})
    return out


def containing(layout, off, size):
    """The scalar (or union arm) a byte run belongs to, widened to all of it.

    The oracle reports runs of *differing* bytes, so a vector register whose
    top half happened to be unchanged shows up as a short run at an odd
    offset.  Rounding out to the containing element is what makes two reports
    of the same register look like the same register.
    """
    cands = resolve(layout, off)
    if not cands:
        return None
    # Prefer the narrowest field that still covers the whole run; failing
    # that, the narrowest that covers its start.
    covering = [c for c in cands if c["off"] <= off and
                c["off"] + c["size"] >= off + size]
    pick = min(covering or cands, key=lambda c: c["size"])
    alts = [c["path"] for c in cands if c["path"] != pick["path"]]
    return {"path": pick["path"], "off": pick["off"], "size": pick["size"],
            "type": pick["type"], "alts": alts}


# ---------------------------------------------------------------------------
# The field -> architectural register map, per target
# ---------------------------------------------------------------------------

def base_of(layout, name):
    """Byte offset of a named top-level field of CPUArchState."""
    for kid in layout.get("children", []):
        if kid.get("name") == name:
            return kid["off"], kid.get("size", 0)
    return None, 0


def arch_name(target, layout, field, off, size, opts):
    """Name the architectural register a resolved field belongs to."""
    path = field["path"]

    if target.startswith("riscv"):
        # vreg_ofs(vd) = offsetof(CPURISCVState, vreg) + vd * vlenb.  QEMU
        # never stores vd anywhere, but the map is affine and therefore
        # invertible, which is the whole reason the offsets are usable.
        vbase, vsize = base_of(layout, "vreg")
        if vbase is not None and vbase <= off < vbase + vsize:
            vlenb = opts.vlenb
            vd = (off - vbase) // vlenb
            lane = (off - vbase) % vlenb
            return ("v%d" % vd,
                    "vreg+%d, vlenb=%d, byte %d of the register"
                    % (off - vbase, vlenb, lane))
        if "float_exception_flags" in path:
            return "fflags", "sticky FP exception accumulator"
        if path.endswith("vtype") or path.endswith("vill") or \
                path.endswith("vstart") or path.endswith("vl"):
            return path.split(".")[-1], "vector CSR"

    if target.startswith("aarch64") or target.startswith("arm"):
        # NZCV is four separate words, and ZF is stored inverted: the Z
        # condition holds when ZF is *zero*.  A differ that reported "ZF
        # changed 0 -> 1" without saying that would be actively misleading.
        flag = path.split(".")[-1]
        if flag in ("NF", "CF", "VF"):
            return flag[0], "condition flag, live in bit 31 of its own word"
        if flag == "ZF":
            return "Z", "condition flag, INVERTED: Z is set when ZF == 0"
        if "float_exception_flags" in path:
            return "FPSR.cumulative", "sticky FP exception accumulator"
        vbase, vsize = base_of(layout, "vfp")
        if vbase is not None and vbase <= off < vbase + vsize and \
                "zregs" in path:
            m = re.search(r"zregs\[(\d+)\]", path)
            if m:
                return "z%s/v%s" % (m.group(1), m.group(1)), \
                    "SVE register file; the lane depends on the instruction"

    if target.startswith("mips"):
        # fpr_t is a sixteen-byte union and the TCG globals name only its low
        # eight.  The tempting rule -- "with FR=0 the odd single-precision
        # register is the upper half of the even register's storage, so
        # fpr[n]+4 is $f(2n+1)" -- is how the *hardware* aliases them and is
        # not how QEMU stores them.  gen_store_fpr32h() sends the high half of
        # an even register to fpr[reg | 1] when F64 is clear, so QEMU keeps 32
        # separate slots in both modes and emulates the aliasing by
        # redirection.  Applying the hardware rule here would mis-name every
        # odd register.
        #
        # What is real: which architectural register fpr[n] holds depends on
        # the mode and the width of the access, not on the offset.  With FR=0
        # a 64-bit double is split across fpr[2n] and fpr[2n+1] -- two records
        # sixteen bytes apart, one architectural write.
        m = re.search(r"fpr\[(\d+)\]", path)
        if m:
            n = int(m.group(1))
            within = off - field["off"]
            note = ("fpr_t is a 16-byte union; width and lane come from the "
                    "instruction. FR=0 splits a double across fpr[%d] and "
                    "fpr[%d]" % (n & ~1, (n & ~1) + 1))
            if within >= 8:
                return "$f%d (MSA lane)" % n, \
                    "at +%d of fpr[%d]: above the 8 bytes TCG names, so this " \
                    "is MSA vector storage" % (within, n)
            if within >= 4:
                return "$f%d high half" % n, \
                    "at +%d of fpr[%d]: the top half of a FR=1 double. It is " \
                    "NOT the odd single -- QEMU puts that in fpr[%d]" \
                    % (within, n, n | 1)
            return "$f%d" % n, note
        if "fcr31" in path:
            return "FCSR", "FP control/status, cause and flag fields sticky"
        if "float_exception_flags" in path:
            return "fcr31.flags (softfloat side)", \
                "sticky FP exception accumulator"

    if target.startswith("x86"):
        # x86 registers almost none of its vector or FP state as TCG globals,
        # so nearly everything interesting here arrives as a bare offset.
        # xmm_regs[] is a flat array of ZMMReg, which makes the offset carry
        # the register number outright -- the same affine-and-therefore-
        # invertible property that makes a RISC-V vreg offset usable.
        m = re.match(r"xmm_regs\[(\d+)\]", path)
        if m:
            return "xmm%s" % m.group(1), \
                "xmm_regs[] is ZMMReg-strided; the offset carries the number"
        m = re.match(r"fpregs\[(\d+)\]", path)
        if m:
            return "st%s" % m.group(1), \
                "x87 stack slot; which architectural ST(n) it is depends on " \
                "fpstt, which is state and not layout"
        m = re.match(r"segs\[(\d+)\]", path)
        if m:
            return "seg%s" % m.group(1), "segment descriptor cache"
        root = path.split(".")[0].split("[")[0]
        if root in ("fpus", "fpuc", "fpstt", "fptags"):
            return "x87ctl", "x87 control/status"
        if root == "mxcsr":
            return "mxcsr", "SSE control/status"
        if "float_exception_flags" in path:
            return "mxcsr.flags (softfloat side)", \
                "sticky FP exception accumulator"

    return None, None


STICKY_HINTS = ("float_exception_flags",)


def sticky_fields(layout, node=None, base=0, path="", out=None):
    """Fields that accumulate rather than being assigned.

    These are what value-equality blindness hides permanently: once a bit is
    set it stays set, so every later instruction that raises it again writes a
    value equal to the old one and is invisible for the rest of the run.  They
    are the natural targets for an 'o' poison.
    """
    if out is None:
        out = []
    if node is None:
        node = layout
    kind = node.get("kind")
    if kind == "array":
        esz = node["elem_size"]
        for i in range(node.get("n", 0)):
            sticky_fields(layout, node["elem"], base + i * esz,
                          "%s[%d]" % (path, i), out)
        return out
    if kind in ("struct", "union"):
        for kid in node.get("children", []):
            name = kid.get("name", "?")
            kpath = ("%s.%s" % (path, name)) if path else name
            sticky_fields(layout, kid, base + kid["off"], kpath, out)
        return out
    if any(h in path for h in STICKY_HINTS):
        out.append({"path": path, "off": base, "size": node.get("size", 1)})
    return out


# ---------------------------------------------------------------------------
# Driving
# ---------------------------------------------------------------------------

RAW_RE = re.compile(r"raw off=(\d+) size=(\d+)")
REG_RE = re.compile(r"reg=(\S+) off=(-?\d+) size=(\d+)")


def header_target(path):
    with open(path) as fh:
        for line in fh:
            m = re.match(r"T target=(\S+)", line)
            if m:
                return m.group(1)
    raise SystemExit("%s has no 'T target=' line" % path)


def merged(args, target, layout):
    """One line per (instruction, architectural register).

    The oracle reports runs of *differing* bytes, so one write to a wide
    register arrives as several records -- vmul.vv into a 16-byte v4 whose
    two halves happen to differ in one byte each shows up as two one-byte
    runs sixteen bytes apart.  Naming the register is only half the job; the
    other half is saying it once.
    """
    order, groups = [], {}
    with open(args.report) as fh:
        for line in fh:
            if not line or line[0] not in "WH":
                continue
            f = line.split()
            pc = f[1]
            m = RAW_RE.search(line)
            if m:
                off, size = int(m.group(1)), int(m.group(2))
                field = containing(layout, off, size)
                if field is None:
                    name, why, path = "<outside CPUArchState>", None, "?"
                else:
                    name, why = arch_name(target, layout, field, off, size, args)
                    path = field["path"]
                    name = name or path
            else:
                m2 = REG_RE.search(line)
                if not m2:
                    continue
                off, size = int(m2.group(2)), int(m2.group(3))
                field = containing(layout, off, size)
                path = field["path"] if field else m2.group(1)
                name, why = (arch_name(target, layout, field, off, size, args)
                             if field else (None, None))
                name = name or m2.group(1)
            key = (pc, line[0], name)
            if key not in groups:
                order.append(key)
                groups[key] = {"runs": 0, "bytes": 0, "path": path, "why": why}
            groups[key]["runs"] += 1
            groups[key]["bytes"] += size

    for key in order:
        pc, tag, name = key
        g = groups[key]
        print("%s %s %-22s runs=%d bytes=%d field=%s%s"
              % (tag, pc, name, g["runs"], g["bytes"], g["path"],
                 "  (%s)" % g["why"] if g["why"] else ""))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", nargs="?")
    ap.add_argument("--build-dir", default="build-oracle")
    ap.add_argument("--target", help="override the report's target")
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--vlenb", type=int, default=16,
                    help="RISC-V bytes per vector register; a runtime cpu "
                         "property, so it cannot be read from DWARF (default "
                         "16, i.e. VLEN=128)")
    ap.add_argument("--merge", action="store_true",
                    help="collapse each instruction's runs into one line per "
                         "architectural register")
    ap.add_argument("--sticky", action="store_true",
                    help="print a QEMU_ORACLE_POISON spec for the "
                         "accumulator fields and exit")
    args = ap.parse_args()

    if args.report is None and not args.target:
        raise SystemExit("give a report, or --target with --sticky")
    target = args.target or header_target(args.report)
    cache = args.cache_dir or os.path.join(args.build_dir, "oracle-cache")
    layout = load_layout(args.build_dir, target, cache)

    if args.sticky:
        specs = sticky_fields(layout)
        for s in specs:
            print("# %s" % s["path"], file=sys.stderr)
        print(",".join("%d:%d:o" % (s["off"], s["size"]) for s in specs))
        return 0

    if args.merge:
        return merged(args, target, layout)

    with open(args.report) as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = RAW_RE.search(line)
            if m is None:
                m2 = REG_RE.search(line)
                if m2 and line[0] in "WH":
                    off, size = int(m2.group(2)), int(m2.group(3))
                    field = containing(layout, off, size)
                    if field:
                        line += "  field=%s" % field["path"]
                        # A named register still needs interpreting when the
                        # name is QEMU's storage rather than the architecture's
                        # register -- AArch64's ZF being the case in point.
                        name, why = arch_name(target, layout, field, off,
                                              size, args)
                        if name and name != m2.group(1):
                            line += " arch=%s" % name
                        if why:
                            line += "  (%s)" % why
                print(line)
                continue

            off, size = int(m.group(1)), int(m.group(2))
            field = containing(layout, off, size)
            if field is None:
                print(line + "  field=<outside CPUArchState>")
                continue
            name, why = arch_name(target, layout, field, off, size, args)
            extra = "  field=%s type=%s" % (field["path"], field["type"])
            if field["off"] != off or field["size"] != size:
                extra += " whole=%d+%d" % (field["off"], field["size"])
            if name:
                extra += " arch=%s" % name
            if why:
                extra += "  (%s)" % why
            if field["alts"]:
                extra += "  also=%s" % ",".join(field["alts"][:3])
            print(line + extra)
    return 0


if __name__ == "__main__":
    sys.exit(main())
