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


def build_elf(isa, encodings, path):
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
                         load + off, ehsz, 0, 0, ehsz, phsz, 1, 0, 0, 0)
        ph = struct.pack("<IIIIIIII", 1, off, load + off, load + off,
                         len(body), len(body), 5, 0x1000)

    with open(path, "wb") as f:
        f.write(eh + ph)
        f.write(b"\x00" * (off - len(eh) - len(ph)))
        f.write(body)
    os.chmod(path, 0o755)
    return base, stride, len(encodings)


def read_pop(path, isa):
    """The population, de-duplicated, in first-seen order."""
    seen, out = set(), []
    with open(path) as f:
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
    ap.add_argument("--emit-only", action="store_true")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    pop = read_pop(a.pop, a.isa)
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

    rows, parts = 0, []
    for k in range(0, len(pop), a.chunk):
        chunk = pop[k:k + a.chunk]
        img = os.path.join(a.out, "sled_%s_%d" % (a.isa, k // a.chunk))
        base, stride, n = build_elf(a.isa, chunk, img)
        if a.emit_only:
            print("emitted %s slots=%d base=0x%x stride=%d" % (img, n, base, stride))
            continue
        tsv = img + ".tsv"
        env = dict(os.environ)
        env["CST_SRC_ENC_DUMP"] = tsv
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
        got = 0
        if os.path.exists(tsv):
            with open(tsv) as f:
                got = sum(1 for L in f if not L.startswith("#"))
        print("chunk %d slots=%d rc=%d rows=%d" % (k // a.chunk, n, rc, got))
        if got == 0:
            raise SystemExit(
                "srcenc_sled: chunk %d produced no corpus row -- REFUSING.  "
                "An empty capture is not a short one; see %s"
                % (k // a.chunk, log))
        rows += got
        parts.append(tsv)

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
        f.write("#isa\tencoding\tmnem\tsrc\n")
        for line in seen.values():
            f.write(line)
    print("corpus %s encodings=%d (raw rows %d) population=%d "
          "incidental_rows=%d incidental_encodings=%d "
          "incidental_conflicts=%d"
          % (merged, len(seen), rows, len(pop), inc_rows, len(incidental),
             inc_conflicts))
    if len(seen) < len(pop):
        print("  population encodings the sled did NOT produce a row for: %d "
              "(QEMU read a different length, or declined the slot)"
              % (len(pop) - len(seen)))


if __name__ == "__main__":
    main()
