#!/usr/bin/env python3
"""THE x86 WHOLE-POPULATION EXTERNAL ARM FOR THE OPERAND WALK'S PRICE.

WHY IT EXISTS, AND WHY IT IS NOT THE mipsel ARM.

`srcwalk_worklist.py` beside it decomposes the exec171 deletion price --
540,798 encodings, 1,095,528 register instances -- into adjudication classes.
The fixed-width ISAs were answered by feeding the whole losing population to
`llvm-mc -disassemble` as ONE STREAM and zipping its output lines against the
input words: every mipsel word is four bytes, so line N of the output is word
N of the input and the join is free.

x86 IS VARIABLE LENGTH AND THAT JOIN IS UNSOUND.  If the encoding under test
is seven bytes and the reference consumes four, everything after it shifts and
the operand text read for row N belongs to some other row -- silently, with no
error, for the rest of the chunk.  exec174 therefore refused to score the four
x86 buckets (267,887 GPR + 112,641 VEC + 45,655 ABI + 33,072 PRED) and wrote
them OPEN with this arm named as owed.

HOW IT STAYS SOUND WHILE STILL BATCHING (batched by CHUNK, not by line).

  1. Each subject encoding is laid in its own FIXED 16-BYTE SLOT, padded with
     0x90 (a one-byte nop), so slot starts are at known offsets and a short
     decode cannot move the next subject.
  2. The chunk is disassembled by `objdump -D -b binary`, which PRINTS THE
     BYTE OFFSET AND THE BYTES IT CONSUMED on every line.  Attribution is
     therefore by explicit offset, not by counting -- there is no
     reconstruction to get wrong.
  3. A row is scored only if a line begins EXACTLY at its slot offset AND the
     bytes that line consumed are byte-for-byte the subject.  A short decode,
     a decode that ate the padding, a `(bad)`, or no line at the boundary at
     all is counted APART and scored as neither agreement nor disagreement.
     An instrument that cannot find its subject must abstain, not pass.

WHY NOT `llvm-mc -disassemble -show-encoding` FOR THE ACCOUNTING -- a real
trap, met and recorded rather than worked around quietly.  That combination
looks like it solves the length problem, because it prints an `# encoding:`
list per instruction.  IT DOES NOT: the bytes it prints are the ASSEMBLER's
re-encoding of the decoded instruction, not the bytes the disassembler
consumed.  `40 0f 00 10` (REX + lldt) prints `[0x0f,0x00,0x10]`, dropping the
redundant prefix, and `0f 16 8d 00 00 00 00` prints `[0x0f,0x16,0x4d,0x00]`,
a shorter modrm form with a DIFFERENT byte.  A cursor summed from those
diverges from the input immediately.  Measured on this population it would
have abstained on 42,396 of the first 56,016 rows and called the cause
"LLVM refused the encoding", which is false in every one of those rows.

LLVM IS STILL A REFERENCE HERE, driven the sound way: objdump's consumed
length per slot is used to build a SECOND stream that contains exactly those
bytes and no padding, so one llvm-mc line corresponds to one subject.  The
correspondence is CHECKED (line count == subject count) and a chunk that
fails the check is bisected rather than reported.  A row is scored only where
BOTH references decode it, and where they disagree about whether the register
is named the row abstains and is counted apart.

WHAT IT ASKS.  The same single question the table asks: DOES THE ENCODING NAME
THE REGISTER?  If the operand text names it, R7.3/R15/R16 bind and the loss is
REAL -- QEMU's lowering eliding a register the encoding names is never grounds
to drop it from the wire.  If the references decode the encoding and do NOT
name it, the walk over-named and the drop is a CORRECTION.

THE INSTRUMENT'S OWN LIMIT, STATED RATHER THAN HIDDEN.  AT&T disassembly text
prints architectural operands.  It NEVER prints EFLAGS, SSP, or an XCR
selected by ECX, so REG_FLAGS / REG_SSP / REG_SYS* rows are UNWITNESSABLE by
this arm and are reported as such -- not as "not named", which would read as a
SUPERSET verdict this arm has no power to give.  Those buckets need a source
citation, the way `rv-zext-zero` rests on the ISA's definition of the alias
rather than on a disassembler's printed text.

USAGE
    srcwalk_x86_arm.py --a <corpA/x86_64.tsv> --b <corpB/x86_64.tsv>
                       [--losers rows.tsv] [--objdump objdump] [--mc llvm-mc]
                       [--classes GPR,VEC,PRED,ABI] [--chunk 2000]
                       [--out rows.tsv]
    srcwalk_x86_arm.py --selftest
"""
import argparse
import collections
import io
import os
import re
import subprocess
import sys
import tempfile

SLOT = 16                      # bytes per subject slot
PAD = 0x90                     # one-byte nop; a short decode cannot straddle

# ---------------------------------------------------------------- vocabulary
#
# THE MAP IS THE TRACER'S, NOT THE ARCHITECTURE'S.
# champsim_tracer_qemu_regs_x86.h lifts rsp and rbp OUT of the GPR numbering
# (REG_SP and REG_FP_REG), so REG_GPR4 is rsi, not rsp.  Reading this off the
# architectural encoding order would mis-name eleven of the fourteen
# registers.  REG_FP_REG is rbp -- the frame pointer, NOT the x87 stack, which
# is REG_FPR0..7; exec174's x86-abi-operand note said otherwise and this map
# is where that is corrected.
_GPR = [
    ("rax", "eax", "ax", "al", "ah"),
    ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"),
    ("rbx", "ebx", "bx", "bl", "bh"),
    ("rsi", "esi", "si", "sil"),
    ("rdi", "edi", "di", "dil"),
    ("r8", "r8d", "r8w", "r8b"),
    ("r9", "r9d", "r9w", "r9b"),
    ("r10", "r10d", "r10w", "r10b"),
    ("r11", "r11d", "r11w", "r11b"),
    ("r12", "r12d", "r12w", "r12b"),
    ("r13", "r13d", "r13w", "r13b"),
    ("r14", "r14d", "r14w", "r14b"),
    ("r15", "r15d", "r15w", "r15b"),
]
_SEG = ["cs", "ds", "es", "fs", "gs", "ss"]

_UNWITNESSABLE = re.compile(r"^REG_(FLAGS|SSP|SYS)")


def spellings(reg):
    """-> (set_of_att_names, witnessable)."""
    m = re.match(r"^REG_GPR(\d+)$", reg)
    if m and int(m.group(1)) < len(_GPR):
        return set(_GPR[int(m.group(1))]), True
    m = re.match(r"^REG_VEC(\d+)$", reg)
    if m:
        n = m.group(1)
        return {"xmm" + n, "ymm" + n, "zmm" + n}, True
    m = re.match(r"^REG_PRED(\d+)$", reg)
    if m:
        return {"k" + m.group(1)}, True
    m = re.match(r"^REG_FPR(\d+)$", reg)
    if m:
        return {"st(%s)" % m.group(1), "st" + m.group(1)}, True
    m = re.match(r"^REG_SEG(\d+)$", reg)
    if m and int(m.group(1)) < len(_SEG):
        return {_SEG[int(m.group(1))]}, True
    if reg == "REG_SP":
        return {"rsp", "esp", "sp", "spl"}, True
    if reg == "REG_FP_REG":
        return {"rbp", "ebp", "bp", "bpl"}, True
    if reg == "REG_PC":
        return {"rip", "eip"}, True
    return set(), False


def bucket(reg):
    if re.match(r"^REG_GPR\d+$", reg):
        return "GPR"
    if re.match(r"^REG_VEC\d+$", reg):
        return "VEC"
    if re.match(r"^REG_PRED\d+$", reg):
        return "PRED"
    if reg in ("REG_SP", "REG_FP_REG", "REG_PC", "REG_TLS") or re.match(
            r"^REG_(SEG|BOUND|FPR)\d+$", reg):
        return "ABI"
    if reg == "REG_FLAGS":
        return "FLAGS"
    if reg == "REG_SSP":
        return "SSP"
    if reg.startswith("REG_SYS"):
        return "SYS"
    return "OTHER"


_TOK = re.compile(r"%([a-z0-9]+(?:\(\d\))?)")


def named(text, names):
    return bool(names & set(_TOK.findall(text)))


# --------------------------------------------------------- reference: objdump
_OD = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(.*)$")


def objdump_blob(binary, blob):
    """-> {offset: (nbytes, text)}.  Attribution is by PRINTED OFFSET."""
    d = tempfile.mkdtemp(prefix="srcwalk-")
    try:
        f = os.path.join(d, "a.bin")
        with open(f, "wb") as fh:
            fh.write(blob)
        p = subprocess.run([binary, "-D", "-b", "binary", "-m", "i386:x86-64",
                            "-M", "att", "--insn-width=16", f],
                           capture_output=True, text=True)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    at = {}
    for line in p.stdout.splitlines():
        m = _OD.match(line)
        if not m:
            continue
        off = int(m.group(1), 16)
        raw = [int(t, 16) for t in m.group(2).split()]
        at[off] = (raw, m.group(3).strip())
    return at


# --------------------------------------------------------- reference: llvm-mc
def llvm_texts(mc, byteseqs):
    """Decode a list of byte sequences, one line out per sequence.

    The stream carries EXACTLY those bytes -- no padding -- so one subject is
    one instruction when the two references agree on length.  The
    correspondence is checked by line count; a chunk that fails is bisected,
    never reported.  -> [text or None]
    """
    if not byteseqs:
        return []
    toks = []
    for b in byteseqs:
        toks += ["0x%02x" % x for x in b]
    p = subprocess.run([mc, "-triple=x86_64", "-disassemble"],
                       input=" ".join(toks), capture_output=True, text=True)
    lines = [l.split("#")[0].strip() for l in p.stdout.splitlines()
             if l.strip() and not l.strip().startswith(".")]
    if len(lines) == len(byteseqs):
        return lines
    if len(byteseqs) == 1:
        return [None]
    h = len(byteseqs) // 2
    return llvm_texts(mc, byteseqs[:h]) + llvm_texts(mc, byteseqs[h:])


# ------------------------------------------------------------------ the input
def _rows(path):
    for line in open(path, errors="replace"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 3:
            continue
        yield f


def load_losers(a_path, b_path):
    out, mm = [], 0
    for a, b in zip(_rows(a_path), _rows(b_path)):
        if a[1] != b[1]:
            mm += 1
            continue
        sa = set(r for r in (a[3] if len(a) > 3 else "").replace(" ", "").split(",")
                 if r and r != "-")
        sb = set(r for r in (b[3] if len(b) > 3 else "").replace(" ", "").split(",")
                 if r and r != "-")
        d = sa - sb
        if d:
            out.append((a[1], a[2], sorted(d)))
    return out, mm


def load_file(path):
    out = []
    for f in _rows(path):
        out.append((f[0], f[1], [r for r in f[2].split(",") if r]))
    return out, 0


# ----------------------------------------------------------------- the sweep
def run(subjects, objdump, mc, chunk, classes, out_rows, log=sys.stdout):
    if not subjects:
        sys.exit("REFUSING: the arm has no subject")
    wanted = set(classes.split(",")) if classes else None
    work = []
    for enc, mnem, regs in subjects:
        sel = [r for r in regs if wanted is None or bucket(r) in wanted]
        if sel:
            work.append((enc, mnem, sel))
    if not work:
        sys.exit("REFUSING: no subject in the requested classes")

    tally = collections.Counter()
    permn = collections.defaultdict(collections.Counter)
    abst = collections.Counter()
    abst_mn = collections.defaultdict(collections.Counter)
    rows_fh = open(out_rows, "w") if out_rows else None
    if rows_fh:
        rows_fh.write("#enc\tmnem\treg\tbucket\tverdict\tobjdump\tllvm\n")

    for base in range(0, len(work), chunk):
        part = work[base:base + chunk]
        blob = bytearray()
        for enc, _, _ in part:
            b = bytes.fromhex(enc)
            if len(b) > SLOT:
                raise SystemExit("REFUSING: encoding longer than the slot: " + enc)
            blob += b + bytes([PAD]) * (SLOT - len(b))
        at = objdump_blob(objdump, bytes(blob))

        # the second reference gets exactly the bytes the first consumed
        idx, seqs = [], []
        for i, (enc, _, _) in enumerate(part):
            hit = at.get(i * SLOT)
            if hit and bytes(hit[0]) == bytes.fromhex(enc) and "(bad)" not in hit[1]:
                idx.append(i)
                seqs.append(bytes(hit[0]))
        lt = llvm_texts(mc, seqs) if mc else [None] * len(seqs)
        llvm = dict(zip(idx, lt))

        for i, (enc, mnem, regs) in enumerate(part):
            hit = at.get(i * SLOT)
            why = None
            if hit is None:
                why = "NO-INSN-AT-SLOT"
            elif "(bad)" in hit[1]:
                why = "OBJDUMP-BAD"
            elif bytes(hit[0]) != bytes.fromhex(enc):
                why = "LENGTH-DISAGREE"
            elif llvm.get(i) is None:
                why = "LLVM-NO-DECODE"
            if why:
                for r in regs:
                    abst[(bucket(r), why)] += 1
                    abst_mn[(bucket(r), why)][mnem] += 1
                    if rows_fh:
                        rows_fh.write("%s\t%s\t%s\t%s\t%s\t%s\t\n"
                                      % (enc, mnem, r, bucket(r), why,
                                         hit[1] if hit else ""))
                continue
            otxt, ltxt = hit[1], llvm[i]
            for r in regs:
                names, witnessable = spellings(r)
                if not witnessable:
                    v = "UNWITNESSABLE"
                else:
                    o, l = named(otxt, names), named(ltxt, names)
                    if o and l:
                        v = "NAMES"
                    elif not o and not l:
                        v = "NOT-NAMED"
                    else:
                        v = "REFERENCES-DISAGREE"
                if v == "REFERENCES-DISAGREE":
                    abst[(bucket(r), v)] += 1
                    abst_mn[(bucket(r), v)][mnem] += 1
                else:
                    tally[(bucket(r), v)] += 1
                    if v == "NOT-NAMED":
                        permn[bucket(r)][mnem] += 1
                if rows_fh:
                    rows_fh.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\n"
                                  % (enc, mnem, r, bucket(r), v, otxt, ltxt))
    if rows_fh:
        rows_fh.close()

    print("SUBJECT ENCODINGS : %d" % len(work), file=log)
    print("SUBJECT REG-INSTS : %d" % sum(len(r) for _, _, r in work), file=log)
    print("", file=log)
    print("%-6s %-24s %10s" % ("bucket", "verdict", "reg-insts"), file=log)
    for b in sorted({k[0] for k in list(tally) + list(abst)}):
        for v in ("NAMES", "NOT-NAMED", "UNWITNESSABLE"):
            if tally[(b, v)]:
                print("%-6s %-24s %10d" % (b, v, tally[(b, v)]), file=log)
        for why in sorted({k[1] for k in abst if k[0] == b}):
            print("%-6s %-24s %10d" % (b, "abstain:" + why, abst[(b, why)]),
                  file=log)
    if permn:
        print("", file=log)
        print("NOT-NAMED mnemonics (top 20 per bucket):", file=log)
        for b in sorted(permn):
            for m, c in permn[b].most_common(20):
                print("   %-5s %-18s %d" % (b, m, c), file=log)
    if abst_mn:
        print("", file=log)
        print("abstained mnemonics (top 10 per reason):", file=log)
        for k in sorted(abst_mn):
            for m, c in abst_mn[k].most_common(10):
                print("   %-5s %-22s %-18s %d" % (k[0], k[1], m, c), file=log)
    return tally, abst


# ------------------------------------------------------------------ selftest
def selftest(objdump, mc):
    fails = []
    n = [0]

    def chk(name, cond):
        n[0] += 1
        print("  ARM %d %s %s" % (n[0], name, "ok" if cond else "FAILED"))
        if not cond:
            fails.append(name)

    # 1. the vocabulary is the TRACER's, not the architecture's
    chk("REG_GPR4 is rsi (not rsp)", "rsi" in spellings("REG_GPR4")[0])
    chk("REG_SP is rsp", "rsp" in spellings("REG_SP")[0])
    chk("REG_FP_REG is rbp, NOT the x87 stack",
        "rbp" in spellings("REG_FP_REG")[0]
        and "st(0)" not in spellings("REG_FP_REG")[0])
    chk("REG_FPR0 is st(0)", "st(0)" in spellings("REG_FPR0")[0])
    chk("REG_FLAGS unwitnessable", spellings("REG_FLAGS")[1] is False)
    chk("REG_SSP unwitnessable", spellings("REG_SSP")[1] is False)
    chk("REG_SYS* unwitnessable", spellings("REG_SYS0")[1] is False)

    # 2. the text matcher is exact, not a substring
    chk("names %rax for REG_GPR0", named("mov %rax,%rbx", spellings("REG_GPR0")[0]))
    chk("%r15 is not %rax", not named("mov %r15,%rbx", spellings("REG_GPR0")[0]))
    chk("a memory base register counts as named",
        named("lldt (%rax)", spellings("REG_GPR0")[0]))
    chk("k1 is not xmm1", not named("vaddps %xmm1,%xmm2,%xmm3",
                                    spellings("REG_PRED1")[0]))

    # 3. objdump attribution is by OFFSET and reports consumed bytes
    b = bytearray()
    for enc in ("f30f0128", "400f0010", "0f168d00000000"):
        bb = bytes.fromhex(enc)
        b += bb + bytes([PAD]) * (SLOT - len(bb))
    at = objdump_blob(objdump, bytes(b))
    chk("slot 0 consumed 4 bytes", at.get(0, ([], ""))[0] == [0xf3, 0x0f, 0x01, 0x28])
    chk("slot 1 consumed the REX prefix TOO (4 bytes)",
        len(at.get(16, ([], ""))[0]) == 4)
    chk("slot 2 consumed all 7 of its bytes (llvm's shorter re-encoding "
        "is llvm's, not the decode)", len(at.get(32, ([], ""))[0]) == 7)

    # 4. THE TRAP THIS FILE EXISTS FOR.  llvm-mc -show-encoding prints the
    #    RE-ENCODING: for slot 1 it drops the REX byte and for slot 2 it emits
    #    a different modrm.  Asserted here so the unsound route cannot be
    #    reintroduced by someone who thinks it would be simpler.
    p = subprocess.run([mc, "-triple=x86_64", "-disassemble", "-show-encoding"],
                       input=" ".join("0x%02x" % x for x in
                                      bytes.fromhex("400f0010")),
                       capture_output=True, text=True)
    chk("llvm-mc -show-encoding drops the REX byte (unsound for accounting)",
        "0x0f,0x00,0x10]" in p.stdout and "0x40," not in p.stdout)

    # 5. the length trap: a subject objdump does not consume WHOLE abstains
    #    and does NOT shift its neighbour
    subj = [("9090", "twonop", ["REG_GPR0"]),
            ("f30f0128", "rstorssp", ["REG_GPR0"])]
    buf = io.StringIO()
    t, a = run(subj, objdump, mc, 16, None, None, log=buf)
    chk("partial decode abstains, does not score",
        a[("GPR", "LENGTH-DISAGREE")] == 1)
    chk("its neighbour is still read correctly", t[("GPR", "NAMES")] == 1)

    # 6. both references must agree before a row is scored
    subj = [("400f0010", "lldtw", ["REG_GPR0"])]
    buf = io.StringIO()
    t, a = run(subj, objdump, mc, 16, None, None, log=buf)
    chk("a REX-prefixed subject both references decode IS scored",
        t[("GPR", "NAMES")] == 1)

    # 7. an empty subject list REFUSES rather than reporting a clean zero
    rc = subprocess.run([sys.executable, os.path.abspath(__file__),
                         "--selftest-empty", "--objdump", objdump, "--mc", mc],
                        capture_output=True)
    chk("empty subject list refuses (rc!=0)", rc.returncode != 0)

    print("\nsrcwalk_x86_arm selftest: %d check(s), %d failure(s)"
          % (n[0], len(fails)))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a")
    ap.add_argument("--b")
    ap.add_argument("--losers", help="precomputed enc/mnem/regs tsv")
    ap.add_argument("--objdump", default="objdump")
    ap.add_argument("--mc", default="/usr/lib/llvm-18/bin/llvm-mc")
    ap.add_argument("--chunk", type=int, default=2000)
    ap.add_argument("--classes", default=None)
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--selftest-empty", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest(a.objdump, a.mc))
    if a.selftest_empty:
        run([], a.objdump, a.mc, 16, None, None)
        sys.exit(0)
    subj, mm = load_file(a.losers) if a.losers else load_losers(a.a, a.b)
    if mm:
        sys.exit("REFUSING: %d order mismatches between the two corpora" % mm)
    run(subj, a.objdump, a.mc, a.chunk, a.classes, a.out)


if __name__ == "__main__":
    main()
