#!/usr/bin/env python3
"""DID THE ENCODING'S DATAPATH RUN AT ALL?  QEMU'S OWN OPS ANSWER.

WHY THIS EXISTS.

`srcwalk_worklist.py` asks, of every register the Capstone operand walk
publishes and QEMU does not, whether the ENCODING NAMES it -- and answers with
a disassembler.  That question is the right one only where the instruction
ACTUALLY EXECUTED ITS DATAPATH.  Where the machine took a trap instead, the
architectural operands of the instruction-that-would-have-run are not what the
machine read, and publishing them is the fabrication the mipsel decline-latch
exists to prevent (exec176: "publishing BRANCH_COND_DIRECT for a bz.w the
machine never evaluated is the fabrication that latch exists to prevent").

The srcenc corpora are swept by `srcenc_sled.py` on a guest whose state is
whatever the sled's ELF starts in.  On aarch64 that state has SME disabled and
PSTATE.ZA clear, so every SME encoding's translation is an access trap.  A
reading of "QEMU elides ZA" or "the tracer has no name for ZA" is then a
reading of a trap, and the remedy it proposes -- state the read at QEMU's
decode site -- would state a read that does not happen.

WHAT IT MEASURES, AND WHY IT IS AN INTERVENTION AND NOT AN INFERENCE.

For each encoding it builds a minimal static ELF with that word AT THE ENTRY
POINT, runs `qemu-<isa> -d op,in_asm`, and reads the TCG ops QEMU generated:

    TRAP-ONLY   the only thing the translation does with this instruction is
                set the PC and call an exception helper.  No operand was read.
    DATAPATH    the translation emits work -- a gvec call, a load, an
                arithmetic op -- so the instruction's operands were read.
    NO-OPS      the block exists and the instruction contributed NO ops at
                all.  That is QEMU deciding the instruction computes nothing
                -- an architectural hint or prefetch it models as a no-op.
                It is NOT a trap and it is NOT a datapath, and R16 is explicit
                that "a NOP semantic still has real dependencies", so this
                verdict must be kept apart from both.
    NO-TB       QEMU produced no translation block for the entry at all.
    REFUSED     the run produced no usable op dump; counted apart, never
                scored, because an instrument that cannot find its subject
                must abstain rather than pass.

This is QEMU's own lowering, read directly, at the same privilege and CPU
model the sweep used.  It does not infer the trap from the corpus's own
columns, which would be circular: the corpus is the thing under test.

MEASURED, aarch64, `-cpu max`:
    fmopa za0.s, p0/m, p0/m, z0.s, z0.s   ->  TRAP-ONLY
        mov_i64 pc,$0x400078
        call exception_with_syndrome,...,$0x76000002
    fadd v0.4s, v0.4s, v0.4s              ->  DATAPATH
        call gvec_fadd_s,...,tmp5,tmp6,tmp7,...

THE CONTROL IS MANDATORY AND IS RUN EVERY TIME.  A probe that answers
TRAP-ONLY for everything -- because the ELF is malformed, the entry is wrong,
or the emulator refuses the binary -- is the silent false success this tree
keeps relearning.  `--control` (default on) asserts that a known-DATAPATH
encoding for the ISA reads DATAPATH and a known-TRAP one reads TRAP-ONLY, and
REFUSES the whole run if either fails.

USAGE
    trapstate_probe.py --isa aarch64 --qemu build/qemu-aarch64
                       --encs enc.txt [--jobs 12] [--cpu max] [--out rows.tsv]
    trapstate_probe.py --selftest --qemu build/qemu-aarch64
"""
import argparse
import collections
import concurrent.futures as cf
import os
import re
import struct
import subprocess
import sys
import tempfile

# machine, entry-relative exit stub, and the two control encodings per ISA.
ISAS = {
    "aarch64": dict(
        machine=183, elfclass=64, post=[],
        exit_stub=[0xD2800BA8, 0xD2800000, 0xD4000001],   # mov x8,93; mov x0,0; svc 0
        datapath_ctl=0x4E20D400,   # fadd v0.4s, v0.4s, v0.4s
        trap_ctl=0x80800000,       # fmopa za0.s,... -- SME, ZA inactive
        cpu="max"),
    # mipsel.  THE TRAILING NOP IS LOAD-BEARING and is srcenc_sled.py's own
    # lesson: a MIPS branch owns the word after it, so without a benign delay
    # slot the exit stub's first instruction lands inside the encoding under
    # test and the probe measures a different architectural situation.
    "mipsel": dict(
        machine=8, elfclass=32,
        post=[0x00000000],
        exit_stub=[0x24020FA1, 0x24040000, 0x0000000C],  # li v0,4001; li a0,0; syscall
        datapath_ctl=0x00641021,   # addu $2, $3, $4
        trap_ctl=0x40020000,       # mfc0 $2, $0 -- CP0 unusable at user level
        cpu="24Kf"),
    # x86_64.  THE SUBJECT IS A BYTE STRING, NOT A WORD, and that is the whole
    # reason this arm did not exist: the two RISC arms above are 32 bits wide
    # by construction and the file was written around a `word`.  Every subject
    # here is the corpus's own hex spelling, which for the RISC arms is the
    # little-endian image and for x86 is simply the bytes, so one code path
    # serves all three.
    #
    # THE CPU MODEL IS THE EMULATOR'S DEFAULT, deliberately: `srcenc_sled.py`
    # sweeps with QEMU_CPU unset, so a probe run at `-cpu max` would answer
    # for a machine the corpus was never taken on -- which is the exact error
    # (a reading of a state that was not swept) this file exists to prevent.
    # riscv64.  Variable-length like x86 (16-bit compressed forms sit beside
    # 32-bit ones) and served by the same byte path.  The exit stub is
    # li a7,93; li a0,0; ecall.
    "riscv64": dict(
        machine=243, elfclass=64, post=[],
        exit_bytes="9308d0051305000073000000",
        datapath_ctl="13051500",   # addi a0,a0,1
        trap_ctl="0000",           # c.unimp
        cpu=None),
    "x86_64": dict(
        machine=62, elfclass=64, post=[],
        # mov $60,%eax; xor %edi,%edi; syscall
        exit_bytes="b83c00000031ff0f05",
        datapath_ctl="0f58c0",     # addps %xmm0,%xmm0
        trap_ctl="0f0b",           # ud2
        cpu=None),
}

_LOAD = 0x400000


def _entry_off(isa):
    return 84 + 32 if ISAS[isa]["elfclass"] == 32 else 64 + 56


def subject_bytes(isa, enc):
    """The corpus's hex spelling -> the bytes that go at the entry point.

       For the fixed-width arms the corpus writes the LITTLE-ENDIAN image, so
       the bytes are already in memory order and no unpack/repack is needed;
       for x86_64 the spelling is the instruction's bytes outright.  One path,
       and no place for an endian mistake to hide."""
    return bytes.fromhex(enc)


def build_elf(path, isa, enc):
    d = ISAS[isa]
    off = _entry_off(isa)
    if "exit_bytes" in d:
        tail = bytes.fromhex(d["exit_bytes"])
    else:
        tail = b"".join(struct.pack("<I", i)
                        for i in d.get("post", []) + d["exit_stub"])
    body = subject_bytes(isa, enc) + tail
    if d["elfclass"] == 32:
        e = struct.pack("<4sBBBBB7xHHIIIIIHHHHHH", b"\x7fELF", 1, 1, 1, 0, 0,
                        2, d["machine"], 1, _LOAD + off, 52, 0, 0, 52,
                        32, 1, 40, 0, 0)
        p = struct.pack("<IIIIIIII", 1, 0, _LOAD, _LOAD,
                        off + len(body), off + len(body), 5, 0x1000)
        blob = e + p + b"\0" * (off - 52 - 32) + body
    else:
        e = struct.pack("<4sBBBBB7xHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0,
                        2, d["machine"], 1, _LOAD + off, 64, 0, 0, 64,
                        56, 1, 64, 0, 0)
        p = struct.pack("<IIQQQQQQ", 1, 5, 0, _LOAD, _LOAD,
                        off + len(body), off + len(body), 0x1000)
        blob = e + p + body
    with open(path, "wb") as fh:
        fh.write(blob)
    os.chmod(path, 0o755)


_EXC = re.compile(r"\bcall (exception|raise_exception|raise_int|"
                  r"exception_with_syndrome|exception_internal)")
# The PC write that accompanies an exception.  The spelling is the TARGET's:
# aarch64 emits `mov_i64 pc,$0x...` and mipsel `mov_i32 PC,$0x...`, and a
# filter written for one silently scores every trap on the other as DATAPATH.
_PCSET = re.compile(r"^mov_i(32|64) (pc|PC|rip|eip),\$")
# THE EXCEPTION'S OWN ARGUMENT STORE.  riscv64's gen_exception_illegal() puts
# the faulting instruction word into env before it raises, so the block for an
# illegal encoding reads
#
#     st_i32 $0x0,env,$0x1370
#     mov_i64 pc,$0x400078
#     call raise_exception,$0x8,$0,env,$0x2
#
# and a filter that counts that store as work scores EVERY riscv trap as
# DATAPATH -- which is what the probe's own control caught the moment the
# riscv arm was added (c.unimp read DATAPATH).  It is trap machinery, not the
# instruction's datapath: the value is a CONSTANT the translator already knew,
# not anything read from the guest.  The pattern is deliberately narrow -- a
# constant store into env -- and it can only change a verdict in a block that
# ALSO writes the PC and calls an exception helper, which is the trap shape
# and nothing else.
_EXCARG = re.compile(r"^st(8|16|32|64)?_i(32|64) \$0x[0-9a-f]+,env,\$")


def classify(op_text, entry):
    """-> TRAP-ONLY | DATAPATH | NO-TB, from the ops of the ENTRY block."""
    # the ops for the entry instruction run from its `---- <pc>` marker to the
    # next marker; anything before the first marker is the TB prologue.
    marks = [m for m in re.finditer(r"^ ---- ([0-9a-f]+)", op_text, re.M)]
    if not marks:
        return "NO-TB"
    body = None
    for i, m in enumerate(marks):
        if int(m.group(1), 16) == entry:
            end = marks[i + 1].start() if i + 1 < len(marks) else len(op_text)
            # start at the END OF THE MARKER LINE, not the end of the matched
            # group: the marker line carries two more fields after the pc and
            # they are not ops.  Taking m.end() made every trap read DATAPATH.
            nl = op_text.find("\n", m.end())
            body = op_text[(nl + 1 if 0 <= nl < end else end):end]
            break
    if body is None:
        return "NO-TB"
    # the op list ends at the first BLANK LINE.  Anything after it belongs to
    # the emulator, not the block -- "qemu: uncaught target signal 4" sits
    # there on exactly the traps this probe is built to find, and counting it
    # as an op made every one of them read DATAPATH.
    lines = []
    for l in body.splitlines():
        if not l.strip():
            break
        lines.append(l.strip())
    ops = lines
    if not ops:
        return "NO-OPS"
    work = [o for o in ops
            if not _PCSET.match(o)
            and not o.startswith("set_label")
            and not o.startswith("exit_tb")
            and not _EXCARG.match(o)
            and not _EXC.search(o)]
    if not work and any(_EXC.search(o) for o in ops):
        return "TRAP-ONLY"
    return "DATAPATH"


def probe_one(args):
    qemu, isa, cpu, enc, d = args
    path = os.path.join(d, "%s.elf" % enc)
    build_elf(path, isa, enc)
    entry = _LOAD + _entry_off(isa)
    cmd = [qemu] + (["-cpu", cpu] if cpu else []) + ["-d", "op,in_asm", path]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return "REFUSED"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    txt = p.stderr + p.stdout
    if "OP:" not in txt:
        return "REFUSED"
    return classify(txt, entry)


def _ctl(v):
    """A control encoding, as the corpus would spell it.  The RISC arms carry
       theirs as a 32-bit word for readability against the ISA manual; x86
       carries bytes."""
    return v if isinstance(v, str) else struct.pack("<I", v).hex()


def run(qemu, isa, cpu, words, jobs, out, control=True, log=sys.stdout):
    if not words:
        sys.exit("REFUSING: the probe has no subject")
    d = ISAS[isa]
    tmp = tempfile.mkdtemp(prefix="trapstate-")
    try:
        if control:
            c1 = probe_one((qemu, isa, cpu, _ctl(d["datapath_ctl"]), tmp))
            c2 = probe_one((qemu, isa, cpu, _ctl(d["trap_ctl"]), tmp))
            print("CONTROL datapath(%s) = %s" % (_ctl(d["datapath_ctl"]), c1),
                  file=log)
            print("CONTROL trap    (%s) = %s" % (_ctl(d["trap_ctl"]), c2),
                  file=log)
            if c1 != "DATAPATH" or c2 != "TRAP-ONLY":
                sys.exit("REFUSING: the probe's own controls do not read "
                         "DATAPATH/TRAP-ONLY; every verdict below would be "
                         "unfalsifiable")
        res = {}
        with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(probe_one, (qemu, isa, cpu, w, tmp)): w
                    for w in words}
            for f in cf.as_completed(futs):
                res[futs[f]] = f.result()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    tal = collections.Counter(res.values())
    print("", file=log)
    print("SUBJECT ENCODINGS %d" % len(words), file=log)
    for k in sorted(tal):
        print("   %-12s %d" % (k, tal[k]), file=log)
    if out:
        with open(out, "w") as fh:
            fh.write("#enc\tverdict\n")
            for w in sorted(res):
                fh.write("%s\t%s\n" % (w, res[w]))
    return tal


def selftest(qemu):
    fails = []
    n = [0]

    def chk(name, cond):
        n[0] += 1
        print("  ARM %d %s %s" % (n[0], name, "ok" if cond else "FAILED"))
        if not cond:
            fails.append(name)

    tmp = tempfile.mkdtemp(prefix="trapstate-st-")
    try:
        chk("fadd v0.4s reads DATAPATH",
            probe_one((qemu, "aarch64", "max", "00d4204e", tmp)) == "DATAPATH")
        chk("fmopa (SME, ZA inactive) reads TRAP-ONLY",
            probe_one((qemu, "aarch64", "max", "00008080", tmp)) == "TRAP-ONLY")
        chk("add x0,x0,x0 reads DATAPATH",
            probe_one((qemu, "aarch64", "max", "0000008b", tmp)) == "DATAPATH")
        chk("an unallocated word does NOT read DATAPATH",
            probe_one((qemu, "aarch64", "max", "00000000", tmp)) != "DATAPATH")
        # SVE prfb #0, p0, [x0] -- QEMU models the prefetch as a no-op, so
        # the block exists and the instruction contributes nothing.
        chk("an SVE prefetch reads NO-OPS, not TRAP-ONLY",
            probe_one((qemu, "aarch64", "max", "0000c085", tmp)) == "NO-OPS")
        mq = qemu.replace("qemu-aarch64", "qemu-mipsel")
        if os.path.exists(mq):
            chk("mipsel addu reads DATAPATH",
                probe_one((mq, "mipsel", "24Kf", "21106400", tmp)) == "DATAPATH")
            chk("mipsel mfc0 reads TRAP-ONLY (its PC write is mov_i32 PC)",
                probe_one((mq, "mipsel", "24Kf", "00000240", tmp)) == "TRAP-ONLY")
        rq = qemu.replace("qemu-aarch64", "qemu-riscv64")
        if os.path.exists(rq):
            # THE riscv64 ARM.  Its trap control is the one that found the
            # exception-argument store: before _EXCARG existed, c.unimp read
            # DATAPATH and every riscv verdict would have been unfalsifiable.
            chk("riscv addi a0,a0,1 reads DATAPATH",
                probe_one((rq, "riscv64", None, "13051500", tmp)) == "DATAPATH")
            chk("riscv c.unimp reads TRAP-ONLY (its raise stores a constant "
                "into env first)",
                probe_one((rq, "riscv64", None, "0000", tmp)) == "TRAP-ONLY")
            chk("riscv ecall reads TRAP-ONLY",
                probe_one((rq, "riscv64", None, "73000000", tmp)) == "TRAP-ONLY")
            chk("riscv c.andi s0,0 reads DATAPATH (a fold is not a trap)",
                probe_one((rq, "riscv64", None, "0188", tmp)) == "DATAPATH")
        xq = qemu.replace("qemu-aarch64", "qemu-x86_64")
        if os.path.exists(xq):
            # THE x86 ARM.  addps is SSE and present on the default model;
            # ud2 is the architecture's own undefined instruction; and the
            # third arm is the one the whole x86 population turns on -- a VEX
            # encoding the default model refuses, which reads TRAP-ONLY while
            # its non-VEX sibling one line above reads DATAPATH.
            chk("x86 addps reads DATAPATH",
                probe_one((xq, "x86_64", None, "0f58c0", tmp)) == "DATAPATH")
            chk("x86 ud2 reads TRAP-ONLY",
                probe_one((xq, "x86_64", None, "0f0b", tmp)) == "TRAP-ONLY")
            chk("x86 vaddss at VEX.L=1 reads TRAP-ONLY on the default model",
                probe_one((xq, "x86_64", None, "c5065800", tmp)) == "TRAP-ONLY")
            chk("x86 nop reads NO-OPS, not TRAP-ONLY",
                probe_one((xq, "x86_64", None, "90", tmp)) == "NO-OPS")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    # the classifier itself, on planted text
    trap = (" ---- 0000000000400078 0 0\n mov_i64 pc,$0x400078\n"
            " call exception_with_syndrome,$0x8,$0,env,$0x1,$0x76000002\n"
            " set_label $L0\n exit_tb $0x1\n")
    work = (" ---- 0000000000400078 0 0\n add_i64 loc2,env,$0x2fca\n"
            " call gvec_fadd_s,$0x1,$0,tmp5,tmp6,tmp7,loc2,$0x107\n")
    chk("classifier: exception-only text is TRAP-ONLY",
        classify(trap, 0x400078) == "TRAP-ONLY")
    chk("classifier: the mipsel PC spelling is stripped too",
        classify(" ---- 0000000000400074 0 0\n mov_i32 PC,$0x400074\n"
                 " call raise_exception_err,$0x8,$0,env,$0x13,$0x0\n"
                 " set_label $L0\n exit_tb $0x1\n", 0x400074) == "TRAP-ONLY")
    chk("classifier: a gvec call is DATAPATH",
        classify(work, 0x400078) == "DATAPATH")
    chk("classifier: no marker for the entry is NO-TB",
        classify(work, 0x401000) == "NO-TB")
    chk("classifier: empty dump is NO-TB", classify("", 0x400078) == "NO-TB")
    chk("classifier: the x86 PC spelling is stripped too",
        classify(" ---- 0000000000400078 0 0\n mov_i64 rip,$0x400078\n"
                 " call raise_exception,$0xa,$0,env,$0x6\n"
                 " set_label $L0\n exit_tb $0x1\n", 0x400078) == "TRAP-ONLY")
    chk("classifier: an exception argument store is not datapath work",
        classify(" ---- 0000000000400078 0 0\n st_i32 $0x0,env,$0x1370\n"
                 " mov_i64 pc,$0x400078\n"
                 " call raise_exception,$0x8,$0,env,$0x2\n"
                 " set_label $L0\n exit_tb $0x1\n", 0x400078) == "TRAP-ONLY")
    chk("classifier: a store of a READ value is still datapath work",
        classify(" ---- 0000000000400078 0 0\n st_i32 x10,env,$0x1370\n"
                 " mov_i64 pc,$0x400078\n"
                 " call raise_exception,$0x8,$0,env,$0x2\n", 0x400078)
        == "DATAPATH")
    chk("classifier: a block whose entry contributes no ops is NO-OPS",
        classify(" ---- 0000000000400078 0 0\n\n add_i64 x0,x0,x0\n",
                 0x400078) == "NO-OPS")

    # the run-level control must REFUSE, not warn
    rc = subprocess.run([sys.executable, os.path.abspath(__file__),
                         "--selftest-nocontrol", "--qemu", "/bin/false"],
                        capture_output=True)
    chk("a broken emulator REFUSES the whole run", rc.returncode != 0)
    rc = subprocess.run([sys.executable, os.path.abspath(__file__),
                         "--selftest-empty", "--qemu", qemu],
                        capture_output=True)
    chk("an empty subject list REFUSES", rc.returncode != 0)

    print("\ntrapstate_probe selftest: %d check(s), %d failure(s)"
          % (n[0], len(fails)))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--isa", default="aarch64")
    ap.add_argument("--qemu", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "..", "..", "..", "..", "build", "qemu-aarch64"),
        help="emulator to read the ops from; defaults to the canonical build's "
             "qemu-aarch64 so a bare --selftest has a subject")
    ap.add_argument("--cpu", default=None)
    ap.add_argument("--encs", help="file of encodings, one per line, in the corpus's own hex spelling")
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--out")
    ap.add_argument("--no-control", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--selftest-nocontrol", action="store_true")
    ap.add_argument("--selftest-empty", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest(a.qemu))
    cpu = a.cpu or ISAS[a.isa]["cpu"]
    if a.selftest_nocontrol:
        run(a.qemu, a.isa, cpu, ["0000008b"], 1, None)
        sys.exit(0)
    if a.selftest_empty:
        run(a.qemu, a.isa, cpu, [], 1, None)
        sys.exit(0)
    words = []
    for line in open(a.encs):
        s = line.strip().lower()
        if s and not s.startswith("#"):
            # THE SUBJECT IS THE CORPUS'S OWN SPELLING and is kept that way
            # end to end -- through the ELF, through the verdict table, and
            # into whatever joins the two.  The word/%08x round trip this
            # replaced silently re-ordered the bytes on the way out, so a
            # join against the corpus matched nothing and read MISSING.
            bytes.fromhex(s)
            words.append(s)
    run(a.qemu, a.isa, cpu, words, a.jobs, a.out, control=not a.no_control)


if __name__ == "__main__":
    main()
