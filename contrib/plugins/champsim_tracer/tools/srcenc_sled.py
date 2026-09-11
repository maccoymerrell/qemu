#!/usr/bin/env python3
"""Build a TRANSLATE-ONLY ENCODING SLED and capture the per-encoding read-list
corpus from it.

WHY A SLED EXISTS AT ALL
------------------------
``isaxcheck`` scores the tracer's READ side by decoding an encoding in its own
process and asking the tracer's model what it makes of the result.  That is
sound exactly while the wire's source list comes from a decode a host tool can
perform.  It does not.  The wire's sources are QEMU's own ordered read list,
stated at TRANSLATION time inside the emulator for the encoding being
translated, plus the survivor rows for what QEMU does not state.  Neither is
reachable from outside the emulator.

With the Capstone operand walk's read arm removed, the gate's read classes did
not go red and did not go green: their SUBJECT vanished.  Every allowlist rule
justifying a read disagreement stopped matching, and the run failed on DEAD
RULES -- which is indistinguishable from the case the dead-rule detector
exists to catch, a decoder bump moving a signature out from under a rule.

So the subject is exported from the place that holds it.  This script writes a
guest image whose text is a run of fixed-stride SLOTS, one encoding per slot
followed by a terminator, and the plugin's ``CST_SLED`` driver asks QEMU to
TRANSLATE each slot without executing it.  Translation is the whole point: it
runs vcpu_tb_trans -> create_tb_template -> qdep_apply, which is where
``dump_src_enc_row()`` writes the corpus over the list the wire publishes.

NOTHING IS EXECUTED, and that is not caution.  An arbitrary 32-bit word is not
a runnable program; a sled that ran its slots could only ever reach the
encodings that happen not to fault, which is a biased sample of exactly the
wrong shape -- the undefined and privileged space is where decoder
disagreements live.

WHAT THE ELF IS
---------------
A hand-assembled static ELF with one PT_LOAD.  Not a compiler's output,
because the sled must place chosen BYTES at chosen ADDRESSES: an assembler
would refuse the undefined encodings, and a linker would be free to move them.
The entry stub is an immediate ``exit(0)`` in the guest ABI -- the guest is
here to give the plugin a live vCPU to drive translations from, and to do
nothing else.

REFUSALS
--------
Every step that can produce a short corpus without saying so refuses instead:
an ISA with no slot layout, an empty population, a slot whose encoding does not
fit its stride, a capture that produces no rows.  A corpus that is short for a
reason nothing records reads downstream as an encoding whose source list is
empty, which is the silent false success this tree keeps having to relearn.

Author: Maccoy Merrell.
"""

import argparse
import os
import re
import struct
import subprocess
import sys

# --------------------------------------------------------------------------
# Per-ISA slot layout.
#
# STRIDE AND TERMINATOR ARE PART OF THE MEASUREMENT, not packaging.  QEMU
# translates FORWARD from the slot address until a block terminator, so a slot
# without one would have the translator run on into the next slot and the
# corpus would carry rows for encodings at addresses the driver never named.
# That is not wrong -- a row is keyed on the encoding, not the address -- but
# it makes the sled's own accounting unreadable, and on MIPS it would place an
# encoding in a branch delay slot, where it is a different instruction.
#
# The terminator is repeated to fill the stride so that an encoding SHORTER
# than the sweep believed still meets one immediately.  Where QEMU reads a
# different length than the sweep did, the corpus row is keyed on different
# bytes and the encoding reads UNREACHED downstream -- the honest answer,
# rather than a comparison between two different instructions.
# --------------------------------------------------------------------------
#: Where QEMU may BEGIN an instruction inside a slot, in bytes.  Used to
#: enumerate the byte strings the slot's own PADDING can be decoded as -- see
#: terminator_collisions().
ALIGN = {"x86_64": 1, "riscv64": 2, "aarch64": 4, "mipsel": 4}


def capture_tip_line(build_dir):
    """The `#tip` header line: WHICH TREE'S EMULATOR PRODUCED THIS CORPUS.

    FINDING 76-C, THIRD PASS, AND THIS IS THE REMEDY IT ASKED FOR.  The
    `--srcenc` corpus is the wire's own source list for every encoding, read
    out of a running emulator.  It is therefore a statement about ONE BUILD,
    and the allowlist rows generated from it are statements about that same
    build.  Regenerating those rows against a corpus captured at an older tip
    produces a file that describes a tree that no longer exists -- which is
    exactly how PASS 81 landed nine wire statements and left twenty-nine
    allowlist rules matching nothing, and how PASS 76 and PASS 72 did the same
    before it.  Three passes is a habit, not an accident, so the corpus now
    says which tree it came from and the generator refuses one that does not
    say HEAD.

    A DIRTY TREE IS NOT A TIP.  A working tree with modified tracked files
    describes no commit at all, so the stamp records `dirty` and the consumer
    refuses that too rather than quoting a sha the corpus does not match.
    Untracked files are ignored: they cannot change what the emulator does.

    A tree git cannot answer for stamps `unknown`, which the consumer also
    refuses.  Every failure mode ends in a REFUSAL and none of them ends in a
    header line that reads like a clean capture.
    """
    import subprocess
    repo = os.path.dirname(os.path.abspath(build_dir)) or "."
    try:
        sha = subprocess.check_output(
            ["git", "-C", repo, "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL).decode().strip()
        dirt = subprocess.check_output(
            ["git", "-C", repo, "status", "--porcelain", "--untracked-files=no"],
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "#tip\tunknown\tunknown\n"
    if not sha:
        return "#tip\tunknown\tunknown\n"
    return "#tip\t%s\t%s\n" % (sha, "dirty" if dirt else "clean")


def capture_so_line(build_dir):
    """The `#so` header line: WHICH PLUGIN BINARY PRODUCED THIS CORPUS.

    FINDING 92-C, AND `#tip` IS NOT ENOUGH ON ITS OWN.  The corpus IS the
    wire's source list, so scoring a build against a corpus captured from a
    DIFFERENT build compares nothing: the gate reads the corpus's answers
    back to itself and reports whatever the corpus already said.  That is
    not hypothetical.  PASS 92's leg record for 5d9154d8c2 read
    `isaxunallowed srcenc 12` on a tree whose real answer was 26, because
    the corpus it scored against had been captured at the PARENT -- and
    6,000 x86 encodings had lost their whole published source list in
    between.  The gate could not see the regression it exists to catch.

    `#tip` cannot close that.  Legs are run on a WORKING TREE whose HEAD is
    still the parent -- the honest and normal order -- so the tip stamp of a
    stale corpus and of a fresh one are the SAME sha, and the fresh one is
    additionally marked `dirty`, which is not a difference a consumer can
    act on.  The durable binding is the artefact the sled actually ran: the
    plugin whose translation wrote every row.  Its sha256 prefix changes on
    any rebuild that changes behaviour, and does not change on one that does
    not.

    A build with no plugin, or one this process cannot read, stamps
    `unknown` -- which the consumer REFUSES, exactly as it refuses a corpus
    that carries no stamp at all.  A check that cannot find its subject is
    not a check.
    """
    import hashlib
    so = os.path.join(build_dir, "contrib/plugins/libchampsim_tracer.so")
    try:
        h = hashlib.sha256()
        with open(so, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return "#so\t%s\n" % h.hexdigest()[:16]
    except OSError:
        return "#so\tunknown\n"

ISAS = {
    "x86_64": dict(
        machine=62, elfclass=64, entry_stub=bytes.fromhex("b8e700000031ff0f05"),
        stride=16, term=b"\xc3",          # ret
        load=0x00400000,
    ),
    "aarch64": dict(
        machine=183, elfclass=64,
        entry_stub=struct.pack("<3I", 0xD2800BA8, 0xD2800000, 0xD4000001),
        stride=8, term=struct.pack("<I", 0xD65F03C0),   # ret
        load=0x00400000,
    ),
    "riscv64": dict(
        machine=243, elfclass=64,
        entry_stub=struct.pack("<3I", 0x05D00893, 0x00000513, 0x00000073),
        stride=8, term=struct.pack("<H", 0x8082),       # c.jr ra
        load=0x00400000,
    ),
    "mipsel": dict(
        machine=8, elfclass=32,
        entry_stub=struct.pack("<3I", 0x24020FA1, 0x24040000, 0x0000000C),
        # nop + jr $ra + nop.  THE LEADING NOP IS LOAD-BEARING and cost a
        # capture to learn: MIPS branches own the word after them, so a slot
        # laid out [enc][jr][nop] puts the terminator into the DELAY SLOT of
        # any encoding that is itself a branch -- and a jump in a jump's delay
        # slot is a Reserved Instruction, which QEMU translates as an
        # exception path.  The wide capture refused on `0800e003` (`jr $ra`)
        # carrying REG_LR at one address and REG_SYSEXC,REG_LR at another:
        # the same encoding, two read lists, because the sled had put it in
        # two different architectural situations.  With the nop first, every
        # encoding gets a benign delay slot and the terminator ends the block
        # behind it.
        stride=16, term=struct.pack("<3I", 0x00000000, 0x03E00008, 0x00000000),
        load=0x00400000,
    ),
}


def terminator_collisions(isa, lengths):
    """The byte strings a population encoding must NOT be, because the slot's
    own PADDING already decodes as them.

    WHY THE SLED CANNOT ANSWER FOR THEM.  A slot is `[encoding][terminator
    repeated to the stride]`, and the padding is translated too -- it is what
    ends the block.  An encoding that is also one of those padding
    instructions therefore reaches the translator in TWO architectural
    situations in the same sweep: at a slot start, where it is the subject,
    and inside the padding, where it is not.  On MIPS the second situation is
    a DELAY SLOT: the terminator is `nop; jr $ra; nop`, and the trailing nop's
    op range carries the branch's own ops, because gen_branch() emits them at
    the end of the delay slot's translate_insn().

    The two situations produce two different answers for one encoding.  That
    is not a defect in either answer -- it is QEMU correctly translating the
    same bytes in two contexts -- but the corpus's key is the encoding, so it
    has no way to hold both, and whichever the per-chunk deduplication saw
    first is the one that would be published.

    IT WAS ALREADY HAPPENING AND WAS ALREADY VISIBLE ONCE.  The first wide
    MIPS capture refused on `0800e003` (`jr $ra`, the terminator's own second
    word) carrying REG_LR at one address and REG_SYSEXC,REG_LR at another;
    that one was outside the population and was reported as incidental.
    `00000000` (`nop`, the terminator's first and third words) is INSIDE the
    population, and it was published from whichever context won -- silently,
    because the two contexts happened to state the same READ LIST and differed
    only in what the translation EMITTED, which no column carried until the
    XLAT column did.

    So they are removed from the population, NAMED and COUNTED.  Downstream
    reads them as UNREACHED, which is the sled's honest answer: an encoding
    whose measurement the layout decides is one the sled cannot measure.

    Enumerated STRUCTURALLY from the layout itself -- the padding stream is
    the terminator repeated, so it is periodic with the terminator's length,
    and the starts are the ISA's decode alignment.  Nothing here is a list of
    encodings."""
    spec = ISAS[isa]
    term = spec["term"]
    align = ALIGN[isa]
    stream = term * (2 + max(lengths) // max(1, len(term)) + 1)
    out = set()
    for i in range(0, len(term), align):
        for L in lengths:
            if i + L <= len(stream):
                out.add(stream[i:i + L])
    return out


#: e_flags for the 32-bit image.  Zero for every ISA except a mipsel sled
#: aimed at a CPU model whose FCR31.NAN2008 is fixed SET -- P5600 and the
#: other MSA-capable models -- where linux-user/mips/cpu_loop.c refuses an
#: image whose flags say legacy NaN and whose CPU cannot be moved.  An MSA
#: encoding is not reachable AT ALL on the default 24Kf, so a sled that means
#: to translate one has to say which CPU it means and carry the matching
#: ABI flag.
EF_MIPS_NAN2008 = 0x00000400


def build_elf(isa, encodings, path, elf_flags=0):
    """Write the sled image.  Returns (base, stride, count)."""
    spec = ISAS[isa]
    stride, term = spec["stride"], spec["term"]
    load = spec["load"]

    slots = bytearray()
    for enc in encodings:
        if len(enc) > stride - len(term):
            raise SystemExit(
                "srcenc_sled: %s encoding %s is %d bytes and does not leave "
                "room for a terminator in a %d-byte slot -- REFUSING rather "
                "than emitting a slot the translator runs off the end of"
                % (isa, enc.hex(), len(enc), stride))
        pad = stride - len(enc)
        n = (pad + len(term) - 1) // len(term)
        slots += enc + (term * n)[:pad]

    # The slots sit in the SAME PT_LOAD as the entry stub, immediately after
    # it, page-aligned.  An earlier draft gave the sled its own far-away
    # virtual address and left the gap in the file: the image was 800 MB of
    # zeroes, the mapping did not reach the slots, and QEMU declined all 200
    # translations while the script reported a corpus -- three rows, all of
    # them the entry stub.  A layout whose failure mode is a short corpus that
    # still looks like a corpus is the wrong layout.
    off = 0x1000                      # image bytes start one page in
    stub = spec["entry_stub"]
    pad = (-len(stub)) % 0x1000
    body = stub + b"\x00" * pad + bytes(slots)
    base = load + off + len(stub) + pad

    is64 = spec["elfclass"] == 64
    ehsz, phsz = (64, 56) if is64 else (52, 32)
    if is64:
        eh = struct.pack("<4sBBBBB7xHHIQQQIHHHHHH",
                         b"\x7fELF", 2, 1, 1, 0, 0,
                         2, spec["machine"], 1,
                         load + off, ehsz, 0, 0, ehsz, phsz, 1, 0, 0, 0)
        ph = struct.pack("<IIQQQQQQ", 1, 5, off, load + off, load + off,
                         len(body), len(body), 0x1000)
    else:
        eh = struct.pack("<4sBBBBB7xHHIIIIIHHHHHH",
                         b"\x7fELF", 1, 1, 1, 0, 0,
                         2, spec["machine"], 1,
                         load + off, ehsz, 0, elf_flags,
                         ehsz, phsz, 1, 0, 0, 0)
        ph = struct.pack("<IIIIIIII", 1, off, load + off, load + off,
                         len(body), len(body), 5, 0x1000)

    with open(path, "wb") as f:
        f.write(eh + ph)
        f.write(b"\x00" * (off - len(eh) - len(ph)))
        f.write(body)
    os.chmod(path, 0o755)
    return base, stride, len(encodings)


# How a compressed member is opened, keyed on the suffix the compressor
# left behind.  `gzip` and `lzma` are in the standard library; zstd is not,
# and the tree already shells out to the binary everywhere else, so this
# does too rather than adding a dependency a fresh checkout would not have.
_DECOMP = {
    ".zst":  ["zstd", "-dcq"],
    ".zstd": ["zstd", "-dcq"],
    ".xz":   ["xz", "-dcq"],
    ".gz":   ["gzip", "-dcq"],
}


def open_maybe_compressed(path):
    """Open a text file that a disk sweep may have compressed underneath us.

    The population files are ordinary evidence-root artefacts, which means
    the periodic text-bulk compression treats them as subjects -- and it
    should: they are large, they are text, and they compress twenty to one.
    What broke was only that this reader could not follow.  Two of
    exec100/pop's four members were left as `.tsv.zst` by such a pass and
    `open()` handed their frame bytes to `bytes.fromhex`, so the arm read a
    population of zero rather than failing loudly.

    Compressing evidence is right and this reader was wrong, so the reader
    is what changes.  The NAME a caller passes stays the uncompressed one --
    that name is what manifests, harnesses and run scripts carry -- and if
    only a compressed sibling exists it is used, so a sweep can compress a
    corpus without editing every consumer that names it.
    """
    if not os.path.exists(path):
        for suf, cmd in _DECOMP.items():
            if os.path.exists(path + suf):
                path = path + suf
                break
    root, ext = os.path.splitext(path)
    cmd = _DECOMP.get(ext.lower())
    if cmd is None:
        return open(path)
    try:
        pr = subprocess.run(cmd + [path], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    except FileNotFoundError:
        raise SystemExit("srcenc_sled: %s needs %s on PATH to read %s"
                         % (sys.argv[0], cmd[0], path))
    if pr.returncode != 0:
        # A decompressor's own exit status, never inferred from empty output:
        # a corpus that reads as zero rows is the silent false success this
        # whole path exists to have stopped.
        raise SystemExit("srcenc_sled: %s failed on %s (rc=%d): %s"
                         % (cmd[0], path, pr.returncode,
                            pr.stderr.decode("utf-8", "replace").strip()))
    import io
    return io.StringIO(pr.stdout.decode("utf-8", "replace"))


def landing_key(hx, landed, term, stride):
    """Where a slot's corpus row went, when it did not go under @hx.

    FINDING 96-A.  A row is keyed on the bytes the decoder CONSUMED, so a
    slot whose planted encoding QEMU read at a different length still
    produced a row -- under a different key.  The key is then either

      * a proper PREFIX of @hx (the decoder read SHORT and stopped inside
        the planted bytes), or
      * @hx followed by whole copies of the slot TERMINATOR (it read LONG,
        on into the padding, which is the only thing that follows).

    Both are looked up in @landed, the set of keys this capture actually
    produced -- population rows AND incidental ones, because a landing key
    that is not itself a population member is exactly what `incidental`
    holds, and that is why joining against the merged corpus alone finds
    nothing.

    Returns the landing key, or None when nothing in this capture explains
    the slot -- which leaves it UNATTRIBUTED, honestly.
    """
    for k in range(1, len(hx) // 2):
        if hx[:2 * k] in landed:
            return hx[:2 * k]
    pad = term.hex()
    for j in range(1, (stride - len(hx) // 2) // len(term) + 1):
        cand = hx + pad * j
        if cand in landed:
            return cand
    return None


def selftest_landing_key():
    """Both directions, and the refusal, on the x86_64 slot layout."""
    term, stride = ISAS["x86_64"]["term"], ISAS["x86_64"]["stride"]
    fails = []

    def chk(got, want, what):
        ok = got == want
        print("%-5s %s (got %r)" % ("PASS" if ok else "FAIL", what, got))
        if not ok:
            fails.append(what)

    # THE MEASURED SHAPE (2ff695368a, x86_64): the sweep planted four bytes
    # of VMWRITE-with-SIB and QEMU consumed three.
    chk(landing_key("0f790400", {"0f7904"}, term, stride), "0f7904",
        "a SHORT read is named by the prefix the row landed under")
    chk(landing_key("0f790400", {"0f790400c3"}, term, stride), "0f790400c3",
        "a LONG read is named by the planted bytes plus terminator")
    chk(landing_key("0f790400", set(), term, stride), None,
        "a slot nothing in the capture explains stays UNATTRIBUTED")
    chk(landing_key("0f790400", {"0f79040099"}, term, stride), None,
        "an extension that is not the terminator does not count")
    chk(landing_key("0f790400", {"1122"}, term, stride), None,
        "an unrelated key in the capture explains nothing")
    # The shortest prefix wins, because the decode is a function of the
    # bytes: two prefixes cannot both be the instruction QEMU read.
    chk(landing_key("0f790400", {"0f", "0f7904"}, term, stride), "0f",
        "the SHORTEST prefix present is the decode")
    # A one-byte encoding has no proper prefix; only the long route is open.
    chk(landing_key("90", {"90c3"}, term, stride), "90c3",
        "a one-byte slot has no prefix route and takes the long one")
    chk(landing_key("90", {"9090"}, term, stride), None,
        "a one-byte slot is not explained by a non-terminator extension")
    print("landing_key arms=8 failures=%d" % len(fails))
    return 1 if fails else 0


def read_pop(path, isa):
    """The population, de-duplicated, in first-seen order."""
    seen, out = set(), []
    with open_maybe_compressed(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 2 or c[0] != isa or not c[1]:
                continue
            if c[1] in seen:
                continue
            seen.add(c[1])
            out.append(bytes.fromhex(c[1]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--isa", required=True, choices=sorted(ISAS))
    ap.add_argument("--pop", required=True,
                    help="population file: <isa>\\t<hex>[\\t<mnem>] per line")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--wp", default="0")
    ap.add_argument("--chunk", type=int, default=200000,
                    help="slots per sled image; several images beat one huge "
                         "one because QEMU flushes its code buffer under a "
                         "sweep this dense and a flush mid-image is not a "
                         "failure this script should have to model")
    ap.add_argument("--cpu", default=None,
                    help="QEMU_CPU for the sled run.  The DEFAULT model is "
                         "what the banked corpora were captured with; a "
                         "different one measures a different machine and the "
                         "two must not be compared.  Needed to reach an "
                         "extension the default model does not implement -- "
                         "mipsel MSA is not translated at all on 24Kf.")
    ap.add_argument("--nan2008", action="store_true",
                    help="set EF_MIPS_NAN2008 in the mipsel image's e_flags, "
                         "which the MSA-capable CPU models require of an ELF "
                         "before linux-user will run it at all.")
    ap.add_argument("--selftest", action="store_true",
                    help="exercise the FINDING 96-A landing-key join "
                         "and exit; needs no build and no guest")
    ap.add_argument("--emit-only", action="store_true")
    ap.add_argument("--mech", action="store_true",
                    help="ALSO capture the per-encoding MECHANISM corpus "
                         "(CST_SRC_MECH_DUMP) into corpus_mech_<isa>.tsv.  "
                         "The read-list corpus says WHAT an encoding "
                         "publishes; this one says why QEMU did not supply "
                         "what it does not.  Captured in the SAME run, so "
                         "the two files describe one translation and cannot "
                         "drift apart between two sweeps.")
    a = ap.parse_args()
    if a.selftest:
        raise SystemExit(selftest_landing_key())

    os.makedirs(a.out, exist_ok=True)
    pop = read_pop(a.pop, a.isa)
    # THE LAYOUT'S OWN INSTRUCTIONS ARE NOT SUBJECTS.  See
    # terminator_collisions(): an encoding the padding also decodes as reaches
    # the translator in two architectural situations and the corpus can hold
    # only one row for it.  Removed here, named and counted, rather than
    # published from whichever context the deduplication saw first.
    if pop:
        bad = terminator_collisions(a.isa, {len(e) for e in pop})
        drop = [e for e in pop if e in bad]
        if drop:
            pop = [e for e in pop if e not in bad]
            print("srcenc_sled: %s -- %d population encoding(s) are also the "
                  "slot PADDING and cannot be measured free of the layout; "
                  "REMOVED from the population and reported UNREACHED: %s"
                  % (a.isa, len(drop), " ".join(e.hex() for e in drop)))
    if not pop:
        raise SystemExit("srcenc_sled: population file %s carries no %s row "
                         "-- REFUSING (an empty sled produces an empty corpus, "
                         "which downstream cannot tell from a complete one)"
                         % (a.pop, a.isa))

    so = os.path.join(a.build_dir, "contrib/plugins/libchampsim_tracer.so")
    qemu = os.path.join(a.build_dir, "qemu-" + a.isa)
    for p in (so, qemu):
        if not os.path.exists(p):
            raise SystemExit("srcenc_sled: %s does not exist -- REFUSING" % p)

    # THE DRIVER'S OWN COUNTERS, PARSED, because the cause of a short
    # corpus was being printed to a log one directory away and thrown out.
    #
    # sled_run_once() ends every run with
    #     # sled base=.. stride=.. slots=N translated=T declined=D no_chain=C
    # and the two failure counts mean completely different things:
    #
    #   no_chain  QEMU translated the slot and the plugin built no template
    #             chain for it -- a property of the ENCODING, identical in
    #             every arm that lays it out.
    #   declined  qemu_plugin_translate_at() returned false.  For a mapped,
    #             executable slot the reason is the TCG CODE BUFFER: a
    #             decode-on-demand that cannot get a TB "simply does not
    #             happen" (accel/tcg/translate-all.c, plugin_decode_only
    #             arm), because tb_flush there would longjmp out of the
    #             plugin callback frame the sweep is driven from.  It is a
    #             property of the RUN, not of the encoding.
    #
    # FINDING 80-C is what that cost.  200,000 slots in one process:
    # translated=193417 declined=6583 no_chain=4494, and 11,076 population
    # encodings with no row, reported as CAUSE NOT DETERMINED.  The same
    # 200,000 encodings at --chunk 25000: declined=0 in all eight arms, the
    # same 4,494 no_chain, and 4,494 missing.  `vmptrst 0fc738` and
    # `rdrand 0fc7f0` -- one undefined, one perfectly implemented -- were in
    # the 6,582 that differ, which is why the effect looked like a property
    # of two encodings.
    #
    # THE CODE BUFFER IS PER PROCESS, SO THE LEFTOVERS GET A NEW ONE.  A
    # chunk that declines any slot is followed by a pass over exactly the
    # encodings it produced no row for, in a fresh process with an empty
    # buffer, and that repeats while the set keeps shrinking.  Nothing is
    # detected and worked around: the resource is per-process and the retry
    # is another process, which is the only thing that replenishes it.
    _SLED_STATS_RE = re.compile(
        r"^# sled .* slots=(\d+) translated=(\d+) declined=(\d+) "
        r"no_chain=(\d+)", re.MULTILINE)
    #: WHICH SLOTS, not just how many (FINDING 93-A).  sled_translate_one()
    #: prints one of these per slot QEMU translated and the plugin built no
    #: chain for, and the PC maps back through THIS run's own layout -- the
    #: retry passes re-lay the leftovers, so base and stride are per-run and
    #: the mapping has to be done where they are known.
    _SLED_NOCHAIN_RE = re.compile(r"^# sled-nochain ([0-9a-f]+)$", re.MULTILINE)

    def run_slots(slots, img, label):
        """Lay @slots out, translate them, return (tsv, mtsv, rc, stats).

        `stats["nochain_enc"]` is the list of ENCODINGS (hex) the driver
        refused, recovered from its per-slot lines.
        """
        base, stride, n = build_elf(a.isa, slots, img,
                                    EF_MIPS_NAN2008 if a.nan2008 else 0)
        tsv = img + ".tsv"
        env = dict(os.environ)
        if a.cpu:
            env["QEMU_CPU"] = a.cpu
        env["CST_SRC_ENC_DUMP"] = tsv
        mtsv = img + ".mech.tsv"
        if a.mech:
            env["CST_SRC_MECH_DUMP"] = mtsv
        env["CST_SLED"] = "%x:%d:%d" % (base, stride, n)
        log = img + ".log"
        with open(log, "w") as lf:
            rc = subprocess.call(
                ["setarch", "-R", qemu, "-plugin",
                 so + ",outfile=" + img + ".t,wp=" + a.wp +
                 ",compress=zstd -T0 -3 -q -c", img],
                stdout=subprocess.DEVNULL, stderr=lf, env=env)
        for junk in (img + ".t.cst", img + ".t.stats.log",
                     img + ".t.unknown_warnings.log"):
            if os.path.exists(junk):
                os.remove(junk)
        logtext = open(log).read()
        m = _SLED_STATS_RE.search(logtext)
        if not m:
            raise SystemExit(
                "srcenc_sled: %s wrote no '# sled ... declined=' line -- "
                "REFUSING.  Without the driver's own counters a short "
                "corpus has no cause, which is the one thing this sweep "
                "may not report; see %s" % (label, log))
        stats = dict(zip(("slots", "translated", "declined", "no_chain"),
                         (int(x) for x in m.groups())))
        # THE NAMES, JOINED TO THIS RUN'S LAYOUT.  A PC outside the sled --
        # the entry stub, say -- is not a slot and must not be turned into
        # one by integer division, so the join is bounds-checked and the
        # arithmetic is required to land exactly on a slot boundary.
        nochain = []
        stray = 0
        for hx in _SLED_NOCHAIN_RE.findall(logtext):
            pc = int(hx, 16)
            if pc < base or (pc - base) % stride:
                stray += 1
                continue
            i = (pc - base) // stride
            if i >= n:
                stray += 1
                continue
            nochain.append(slots[i].hex())
        # THE TWO READINGS OF THE SAME FACT MUST AGREE.  The counter and the
        # per-slot lines are written by the same branch of the same function;
        # a disagreement means lines were lost (a truncated log, a full pipe)
        # and a refused SET that is short is worse than none -- it would let
        # a rule whose subject QEMU refuses be retired as dead.
        if len(nochain) + stray != stats["no_chain"]:
            raise SystemExit(
                "srcenc_sled: %s counted no_chain=%d but named %d slot(s) "
                "(+%d outside the sled) -- REFUSING.  A refused set that is "
                "short cannot be told from a complete one, and a consumer "
                "would read the difference as DEAD; see %s"
                % (label, stats["no_chain"], len(nochain), stray, log))
        if stray:
            print("%s: %d '# sled-nochain' line(s) named a PC outside the "
                  "sled's own slots and were NOT joined" % (label, stray))
        stats["nochain_enc"] = nochain
        return tsv, mtsv, rc, stats

    def count_rows(path):
        if not os.path.exists(path):
            return 0
        with open(path) as f:
            return sum(1 for L in f if not L.startswith("#"))

    def seen_encodings(path):
        out = set()
        if not os.path.exists(path):
            return out
        with open(path) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                c = line.split("\t")
                if len(c) > 1:
                    out.add(c[1])
        return out

    rows, parts, mparts = 0, [], []
    declined_total = no_chain_total = retry_passes = 0
    #: The union of every encoding any pass reported no_chain for.  A UNION
    #: and not a per-pass tally: a retry re-lays the leftovers, so the same
    #: encoding is refused again in every pass that sees it (which is why
    #: `no_chain_total` counts pass 0 only), while a slot a first pass
    #: DECLINED and a retry then refused is a genuine addition.
    nochain_enc = set()
    for k in range(0, len(pop), a.chunk):
        chunk = pop[k:k + a.chunk]
        cidx = k // a.chunk
        img = os.path.join(a.out, "sled_%s_%d" % (a.isa, cidx))
        if a.emit_only:
            base, stride, n = build_elf(a.isa, chunk, img,
                                        EF_MIPS_NAN2008 if a.nan2008 else 0)
            print("emitted %s slots=%d base=0x%x stride=%d"
                  % (img, n, base, stride))
            continue
        pending = chunk
        pass_no = 0
        chunk_parts, chunk_mparts = [], []
        while True:
            label = ("chunk %d" % cidx if pass_no == 0
                     else "chunk %d retry %d" % (cidx, pass_no))
            tag = img if pass_no == 0 else "%s.r%d" % (img, pass_no)
            tsv, mtsv, rc, stats = run_slots(pending, tag, label)
            got = count_rows(tsv)
            print("%s slots=%d rc=%d rows=%d declined=%d no_chain=%d"
                  % (label, stats["slots"], rc, got,
                     stats["declined"], stats["no_chain"]))
            if got == 0 and pass_no == 0:
                raise SystemExit(
                    "srcenc_sled: chunk %d produced no corpus row -- "
                    "REFUSING.  An empty capture is not a short one; see %s"
                    % (cidx, tag + ".log"))
            if a.mech:
                mgot = count_rows(mtsv)
                # THE TWO CORPORA MUST AGREE ROW FOR ROW.  Both are written
                # from the same loop over the same instructions and both
                # deduplicate on the same encoding key, so a difference is a
                # DROPPED mechanism row -- an encoding whose "why" the sweep
                # silently does not carry, which downstream reads as UNREACHED
                # rather than as a hole.  The plugin counts its own drops in
                # the sidecar; this is the second, independent reading of the
                # same fact.
                if mgot != got:
                    raise SystemExit(
                        "srcenc_sled: %s wrote %d read-list rows but %d "
                        "mechanism rows -- REFUSING.  The two corpora "
                        "describe the same translations and a shortfall is a "
                        "mechanism row dropped; see %s and the sidecar's "
                        "MECHANISM block" % (label, got, mgot,
                                             tag + ".log"))
                chunk_mparts.append(mtsv)
            chunk_parts.append(tsv)
            rows += got
            nochain_enc.update(stats["nochain_enc"])
            if pass_no == 0:
                no_chain_total += stats["no_chain"]
            declined_total += stats["declined"]
            if not stats["declined"]:
                break
            got_enc = seen_encodings(tsv)
            left = [e for e in pending if e.hex() not in got_enc]
            # A pass that declines and yet leaves no fewer slots than it was
            # given cannot be retried into progress: another process would
            # decline the same way.  Refuse rather than loop.
            if not left or len(left) >= len(pending):
                raise SystemExit(
                    "srcenc_sled: %s declined %d slot(s) and a retry pass "
                    "would not shrink the set (%d pending, %d left) -- "
                    "REFUSING rather than reporting a corpus that is short "
                    "for a reason the driver DID record; see %s"
                    % (label, stats["declined"], len(pending), len(left),
                       tag + ".log"))
            pending = left
            pass_no += 1
            retry_passes += 1
        parts.extend(chunk_parts)
        mparts.extend(chunk_mparts)

    if a.emit_only:
        return

    # ------------------------------------------------------------------
    # MERGE, SCOPED TO THE POPULATION THAT WAS ASKED ABOUT.
    #
    # A capture carries rows the sled did not ask for: the entry stub's three
    # instructions, and the SLOT TERMINATOR, which is translated once per slot
    # in every context the slots create.  Those are by-products of the layout,
    # not subjects, and admitting them lets a by-product decide the gate.
    #
    # That is not hypothetical.  The first wide MIPS capture refused on
    # `0800e003` -- `jr $ra`, the sled's own terminator -- carrying
    # `REG_LR` in one chunk and `REG_SYSEXC,REG_LR` in another.  The row is
    # real: QEMU's stated read list for that encoding depends on the
    # TRANSLATION CONTEXT it appears in, not on the encoding alone, which is
    # exactly what the corpus's own documented invariant says it does not.
    # The finding is reported here every time it happens, with both rows
    # printed; it is not silently dropped and it is not allowed to refuse a
    # capture on an encoding nobody asked about.
    #
    # A conflict on a POPULATION encoding still REFUSES.  That one has an
    # answer the gate would use, and two different answers means it has none.
    # ------------------------------------------------------------------
    wanted = set(e.hex() for e in pop)
    merged = os.path.join(a.out, "corpus_%s.tsv" % a.isa)
    seen, incidental = {}, {}
    conflicts, inc_conflicts, inc_rows = 0, 0, 0
    for t in parts:
        with open(t) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < 4:
                    continue
                if c[1] not in wanted:
                    inc_rows += 1
                    prev = incidental.get(c[1])
                    if prev is None:
                        incidental[c[1]] = line
                    elif prev != line:
                        inc_conflicts += 1
                        sys.stderr.write(
                            "INCIDENTAL-CONFLICT (outside the population; "
                            "QEMU's read list for this encoding is "
                            "translation-context dependent)\n  %s  %s"
                            % (prev, line))
                    continue
                prev = seen.get(c[1])
                if prev is None:
                    seen[c[1]] = line
                elif prev != line:
                    conflicts += 1
                    sys.stderr.write("CONFLICT %s\n  %s  %s" % (c[1], prev, line))
    if conflicts:
        raise SystemExit("srcenc_sled: %d POPULATION encoding(s) carry two "
                         "DIFFERENT source lists -- REFUSING (a corpus that "
                         "disagrees with itself has no answer to give)"
                         % conflicts)
    with open(merged, "w") as f:
        f.write(capture_tip_line(a.build_dir))
        f.write(capture_so_line(a.build_dir))
        f.write("#isa\tencoding\tmnem\tsrc\n")
        for line in seen.values():
            f.write(line)

    # ------------------------------------------------------------------
    # THE REFUSED SET, WRITTEN OUT (FINDING 93-A).
    #
    # A corpus says what the wire publishes for the encodings it carries.
    # It is silent about the encodings it does NOT carry, and that silence
    # has two completely different causes:
    #
    #   REFUSED    QEMU translated the bytes and this plugin's admission
    #              gate built no template chain, so nothing is published.
    #              A property of the encoding, and the answer to a
    #              question that IS being asked.
    #   UNREACHED  the sweep produced no row for a reason nothing recorded.
    #
    # A consumer that cannot tell them apart cannot adjudicate its own
    # allowlist.  An allow rule whose every subject encoding is REFUSED is
    # not dead -- the comparison it excuses never runs at this tree -- and
    # retiring it as dead writes a false reason on a rule that is right.
    # Measured at the poison-gate flip: 1,692 such rules across three ISAs.
    #
    # So the set is named, in a file stamped with the SAME `#tip`/`#so` as
    # the corpus it belongs to, and the consumer binds the two by that
    # stamp.  The header also carries the residue arithmetic, because the
    # refused set being exact does not make the residue attributed: on
    # x86_64 the population encodings with no row exceed the refused set,
    # and that remainder is a separate open question, not a refusal.
    # ------------------------------------------------------------------
    #
    # BOTH HALVES OF THE SILENCE ARE NAMED, and that is what makes the file
    # usable.  A consumer deciding whether a rule's subject was removed by
    # the admission gate needs to know not only which encodings WERE refused
    # but which ones went missing for a reason nobody recorded -- otherwise
    # a mnemonic with one refused representative and one unexplained hole
    # reads as wholly refused, and the hole gets excused by a mechanism that
    # did not cause it.
    #
    # Encodings OUTSIDE the population are not listed and are not the file's
    # business: the corpus never carried them, so no comparison could ever
    # have used them, and a consumer must ignore them rather than count them
    # as either kind of silence.  (Measured: the riscv64 sweep decodes
    # 16,842,752 encodings against a population of 87,657.  Treating the
    # difference as unexplained silence vetoes every mnemonic there is.)
    #
    seen_hex = set(seen)
    refused = sorted(e for e in nochain_enc if e not in seen_hex)
    rset = set(refused)
    #
    # THE THIRD CAUSE OF SILENCE, AND FINDING 96-A IS WHY IT HAS A NAME
    # (it used to be pooled into UNATTRIBUTED, whose whole definition is
    # "a reason nothing recorded" -- and this reason IS recorded, twice
    # over, by the two files this function already has in hand).
    #
    #   DECODED-AT-ANOTHER-LENGTH   QEMU translated the slot and the plugin
    #                               DID write a row -- under a DIFFERENT
    #                               encoding key, because the decoder
    #                               consumed a different number of bytes
    #                               than the sweep planted.
    #
    # This is the module docstring's own contract arriving at the refused
    # set: "Where QEMU reads a different length than the sweep did, the
    # corpus row is keyed on different bytes and the encoding reads UNREACHED
    # downstream -- the honest answer, rather than a comparison between two
    # different instructions."  Keying the row on the decoded length is
    # therefore RIGHT and is not changed here; emitting a second row under
    # the slot key would publish one instruction's source list under another
    # instruction's name, which is the one thing the contract forbids.  What
    # was wrong was the LABEL on the slot afterwards.
    #
    # THE JOIN IS EXACT AND LOCAL.  A slot's row lands under the bytes the
    # decoder consumed, so the landing key is either a proper PREFIX of the
    # planted encoding (it read short) or the planted encoding followed by
    # slot terminator bytes (it read long, into the padding).  Both are
    # looked up in the keys this capture actually produced -- `seen` for the
    # population's own, `incidental` for everything else, which is where a
    # landing key ends up when it is not itself a population member, and is
    # why joining against the merged corpus alone finds nothing.
    #
    # MEASURED at 2ff695368a, x86_64: all 35,919 residue encodings land on a
    # prefix, 0 on an extension, 0 unexplained -- and x86_64 is the only ISA
    # of the four whose residue moved when block admission flipped, which is
    # what a length-dependent mechanism can do and a length-independent one
    # cannot.
    #
    landed = seen_hex | set(incidental)
    term = ISAS[a.isa]["term"]
    stride = ISAS[a.isa]["stride"]
    key_of = lambda hx: landing_key(hx, landed, term, stride)

    residue = [e.hex() for e in pop
               if e.hex() not in seen_hex and e.hex() not in rset]
    elsewhere, unattr = [], []
    for hx in residue:
        (elsewhere if key_of(hx) else unattr).append(hx)
    elsewhere.sort()
    unattr.sort()
    refused_path = os.path.join(a.out, "refused_%s.tsv" % a.isa)
    missing_n = len(pop) - len(seen)
    with open(refused_path, "w") as f:
        f.write(capture_tip_line(a.build_dir))
        f.write(capture_so_line(a.build_dir))
        f.write("#refused\tisa=%s\tencodings=%d\tno_chain_pass0=%d\t"
                "population=%d\tpopulation_without_row=%d\t"
                "residue_unattributed=%d\tresidue_decoded_elsewhere=%d\n"
                % (a.isa, len(refused), no_chain_total, len(pop), missing_n,
                   len(unattr), len(elsewhere)))
        f.write("#isa\tencoding\tsilence\n")
        for e in refused:
            f.write("%s\t%s\tREFUSED\n" % (a.isa, e))
        for e in elsewhere:
            f.write("%s\t%s\tDECODED-AT-ANOTHER-LENGTH\t%s\n"
                    % (a.isa, e, key_of(e)))
        for e in unattr:
            f.write("%s\t%s\tUNATTRIBUTED\n" % (a.isa, e))
    print("refused %s encodings=%d decoded-at-another-length=%d "
          "unattributed=%d (population %d, population without a row %d)"
          % (refused_path, len(refused), len(elsewhere), len(unattr),
             len(pop), missing_n))
    if a.mech:
        # THE SAME SCOPING as the read-list merge above, for the same reason:
        # the entry stub and the slot terminator are by-products of the
        # layout, not subjects.  A mechanism conflict on a POPULATION
        # encoding refuses here too -- QEMU's read list being
        # translation-context dependent (see above) makes its MECHANISM
        # context dependent as well, and two answers is no answer.
        mmerged = os.path.join(a.out, "corpus_mech_%s.tsv" % a.isa)
        mseen, mhdr, mconf = {}, None, 0
        for t in mparts:
            with open(t) as f:
                for line in f:
                    if line.startswith("#"):
                        mhdr = mhdr or line
                        continue
                    c = line.split("\t")
                    if len(c) < 4 or c[1] not in wanted:
                        continue
                    prev = mseen.get(c[1])
                    if prev is None:
                        mseen[c[1]] = line
                    elif prev != line:
                        mconf += 1
                        sys.stderr.write("MECH-CONFLICT %s\n  %s  %s"
                                         % (c[1], prev, line))
        if mconf:
            raise SystemExit(
                "srcenc_sled: %d POPULATION encoding(s) carry two DIFFERENT "
                "mechanism rows -- REFUSING" % mconf)
        with open(mmerged, "w") as f:
            f.write(mhdr or "#\n")
            for line in mseen.values():
                f.write(line)
        print("mech-corpus %s encodings=%d" % (a.isa, len(mseen)))
        if len(mseen) != len(seen):
            raise SystemExit(
                "srcenc_sled: the merged read-list corpus carries %d "
                "encodings and the merged mechanism corpus %d -- REFUSING "
                "(one encoding, two files, one row each)"
                % (len(seen), len(mseen)))

    print("corpus %s encodings=%d (raw rows %d) population=%d "
          "incidental_rows=%d incidental_encodings=%d "
          "incidental_conflicts=%d"
          % (merged, len(seen), rows, len(pop), inc_rows, len(incidental),
             inc_conflicts))
    if len(seen) < len(pop):
        # THE CAUSE IS NOT KNOWN HERE AND THIS LINE USED TO CLAIM IT WAS.
        # It read "(QEMU read a different length, or declined the slot)",
        # which names two causes the sled has no evidence for, and exec119
        # measured a third that it fits neither: eight encodings absent from
        # a 200,000-slot sweep were PRESENT, on the SAME BUILD, in a
        # 10,000-slot tail of the same population and in a 9-slot population.
        # Whether an encoding produces a row is in part a function of the
        # SLOT LAYOUT, and a sentence that explains it away as the guest's
        # answer cost that finding a day.
        #
        # So the count is reported as a count and the cause is left open,
        # with the one thing the sled DOES know printed beside it: which
        # chunk each missing encoding was laid out in.  A layout-dependent
        # drop clusters; a per-encoding one does not.
        # `pop` holds the encodings as BYTES (build_elf lays them out) and
        # `seen` is keyed on the corpus's HEX spelling, so the membership test
        # is done in hex.  The first cut compared the two directly, every test
        # said "missing", and the arm reported the whole population absent.
        missing = [e.hex() for e in pop if e.hex() not in seen]
        by_chunk = {}
        for i, e in enumerate(pop):
            if e.hex() in seen:
                continue
            by_chunk[i // a.chunk] = by_chunk.get(i // a.chunk, 0) + 1
        # THE CAUSE IS DETERMINED NOW, and it was always in reach: the
        # driver's own counters said so and this script threw them away.
        # A residue equal to the no_chain total is fully attributed -- QEMU
        # translated every one of those slots and the plugin built no
        # template chain, which is a property of the encoding.  Anything
        # beyond it is NOT attributed and says so in those words.
        print("  population encodings the sled did NOT produce a row for: %d"
              % len(missing))
        print("    the driver's own counters: no_chain=%d (translated, the "
              "plugin built no chain -- a property of the encoding), "
              "declined=%d over %d retry pass(es) (the per-process code "
              "buffer; every declined slot was re-run in a fresh process)"
              % (no_chain_total, declined_total, retry_passes))
        #
        # AND THE LENGTH JOIN, COUNTED HERE TOO (FINDING 96-A).  This block
        # used to know only about `no_chain`, so every slot whose row landed
        # under the bytes the decoder consumed rather than the bytes the
        # sweep planted was printed as having "no cause recorded" -- a false
        # negative in the honest direction, but a false one.  Measured at
        # 2ff695368a: all 35,919 x86_64 residue encodings are this class and
        # NONE of them was unexplained.
        #
        n_else = len(elsewhere)
        if len(missing) == no_chain_total + n_else:
            print("    ATTRIBUTED IN FULL: %d no_chain + %d decoded at "
                  "another length (the row went to the key the decoder's "
                  "own length names)" % (no_chain_total, n_else))
        else:
            print("    NOT ATTRIBUTED: %d encoding(s) beyond the no_chain "
                  "count (%d) and the decoded-at-another-length count (%d) "
                  "have no cause recorded"
                  % (len(missing) - no_chain_total - n_else,
                     no_chain_total, n_else))
        print("    by chunk (chunk size %d, %d chunk(s)): %s"
              % (a.chunk, (len(pop) + a.chunk - 1) // a.chunk,
                 ", ".join("%d=%d" % (c, n)
                           for c, n in sorted(by_chunk.items()))))
        print("    first 8: %s" % " ".join(missing[:8]))


if __name__ == "__main__":
    main()
