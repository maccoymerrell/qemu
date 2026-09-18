#!/usr/bin/env python3
"""ONE CANDIDATE WORD PER aarch64 DECODE ROW, BUILT FROM THE TREE'S OWN PATTERNS.

The census (`a64_row_census.py`) names 1,303 decode rows a user-mode aarch64
trace can reach.  Naming them is not reaching them: to exercise a row something
has to place a 32-bit word in a guest that QEMU's decoder will route to that
row's `trans_` function.  This file produces the candidate words.

WHY THE WORDS ARE GENERATED AND NOT WRITTEN DOWN
------------------------------------------------
The obvious alternative is a hand table of one assembler line per row.  1,303
hand-written lines is exactly the maintained-by-hand artefact this tree keeps
paying for: it goes stale the first time a `.decode` file gains a pattern, and
nothing says so.  The patterns are already stated, machine-readable, in
`target/arm/tcg/*.decode`, and `scripts/decodetree.py` -- the SAME parser that
built the decoder -- hands over each pattern's `fixedbits` and `fixedmask`.  A
word built as `fixedbits | <anything inside the free bits>` satisfies that
pattern's match condition by construction.

WHY SEVERAL VARIANTS PER PATTERN, AND WHY THE FREE BITS ARE NOT LEFT AT ZERO
----------------------------------------------------------------------------
Satisfying a pattern's mask is necessary and not sufficient, for two reasons
that pull in opposite directions:

  * decodetree matches patterns IN ORDER.  A word that satisfies a general
    pattern's mask may also satisfy an earlier, more specific one and be
    routed there instead -- `orr zd, zn, zn` is decoded as `mov`.  So the word
    a generator believes reaches row R can genuinely reach row R'.
  * a `trans_` function may REFUSE the word after decodetree routed it: an
    unallocated size field, a register pair that must differ, an immediate
    the architecture reserves.  All-zero free bits walk into that constantly
    (`size=00` is the reserved encoding of a great many SVE rows).

Neither is decidable from the decode file, so this file does not decide it.
It emits several variants per pattern -- the free bits filled per FIELD, with
small distinct values, so register numbers and immediates differ -- and leaves
the arbitration to QEMU itself.  The sled (`srcenc_sled.py --mech`) translates
every candidate and reports which row QEMU's decoder actually reached; the
exercise pass then uses only words QEMU agreed were that row's.

A ROW WITH NO CANDIDATE IS NOT SILENTLY DROPPED.  A reachable row whose
patterns are all in decode files the census did not scope to it, or that yields
no word at all, is written to the output with an empty word list and counted,
because a row that vanished between the census and the exercise pass would
make the coverage denominator shrink without anybody seeing it.

Author: Maccoy Merrell.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import a64_row_census as cen                               # noqa: E402


def patterns_with_fields(root, groups):
    """{rule: [(decode-file, fixedbits, fixedmask, {name: field}), ...]}.

    The census parses the same files and keeps only the field NAMES, because a
    census counts patterns and does not build words.  This keeps decodetree's
    own field objects, whose `.mask` says which bits of the word each field
    occupies -- the only thing that makes a per-field value assignment possible
    rather than a blind fill of the free bits.
    """
    parser = os.path.join(root, "scripts/decodetree.py")
    if not os.path.exists(parser):
        raise cen.Refusal("%s: absent.  The words are built from the tree's "
                          "OWN parse of the patterns; a second parser written "
                          "here could disagree with the one that built the "
                          "decoder" % parser)
    spec = importlib.util.spec_from_file_location("decodetree", parser)
    if spec is None or spec.loader is None:
        raise cen.Refusal("%s: cannot be loaded as a module" % parser)
    dt = importlib.util.module_from_spec(spec)
    sys.modules["decodetree"] = dt
    spec.loader.exec_module(dt)

    out = {}
    for dfile in sorted(groups):
        src = os.path.join(root, "target/arm/tcg", dfile)
        if not os.path.exists(src):
            raise cen.Refusal("%s: meson names this decode file and the tree "
                              "does not have it" % src)
        dt.fields = {}
        dt.arguments = {}
        dt.formats = {}
        dt.allpatterns = []
        dt.anyextern = False
        dt.insnwidth = 16 if dfile == "t16.decode" else 32
        dt.insnmask = (1 << dt.insnwidth) - 1
        dt.variablewidth = False
        dt.input_file = src
        top = dt.ExcMultiPattern(0)
        with open(src, "rt", encoding="utf-8") as fh:
            dt.parse_file(fh, top)
        for p in top.pats:
            p.prop_masks()
        for p in dt.allpatterns:
            # A PATTERN'S FIELDS ARE MOSTLY ITS FORMAT'S.  decodetree leaves
            # `Pattern.fields` empty whenever the pattern was written against a
            # `@format`, which is nearly all of aarch64: the field objects live
            # on the format it inherits.  Reading only the pattern's own dict
            # yields no fields, every variant collapses onto the all-zero word,
            # and the generator quietly produces one candidate per pattern --
            # measured, it did exactly that before this merge.
            flds = {}
            base = getattr(p, "base", None)
            if base is not None and isinstance(getattr(base, "fields", None),
                                               dict):
                flds.update(base.fields)
            if isinstance(getattr(p, "fields", None), dict):
                flds.update(p.fields)
            out.setdefault(p.name, []).append(
                (dfile, p.fixedbits, p.fixedmask, flds))
    if not out:
        raise cen.Refusal("the decode sources yielded no patterns at all")
    return out


#: Values dealt out to the pattern's fields.  Small and DISTINCT per field --
#: `add zd, zn, zm` with every field 0 is `add z0, z0, z0`, which is a fine
#: instruction and a poor probe: a row whose trans_ function refuses a repeated
#: register, or whose size field reserves 0, needs a word that does not use
#: them.  Each bank is (per-field constant, per-field stride): field i of the
#: pattern gets `const + i * stride`, truncated to the field's width.
BANKS = [
    (0, 0),        # everything 0 -- the smallest legal thing there is
    (1, 1),        # 1, 2, 3, ... -- distinct registers, size=01
    (2, 1),        # 2, 3, 4, ... -- size=10
    (3, 1),        # 3, 4, 5, ... -- size=11
    (1, 0),        # everything 1
    (5, 3),        # 5, 8, 11, ... -- spreads over the wider fields
]


def scatter(value, mask):
    """Deposit the low bits of `value` into the SET bits of `mask`, LSB first.

    A decodetree field can be discontiguous (`MultiField` splits an immediate
    across the word), so a plain shift is wrong.  This walks the mask.
    """
    out = 0
    bit = 0
    m = mask
    while m:
        low = m & -m
        if (value >> bit) & 1:
            out |= low
        m ^= low
        bit += 1
    return out


def slot_masks(fixedbits, fixedmask, fields):
    """The free-bit groups of one pattern, as disjoint masks in bit order.

    TWO FIELDS CAN OCCUPY THE SAME BITS and routinely do: SVE's destructive
    forms declare `rd` and `rn` over 0x1f, because the destination IS the first
    source.  Assigning those two "fields" different values would write one over
    the other and the word would be neither.  So the unit is the distinct BIT
    GROUP, not the field name.

    The pattern's own fixed bits are removed from every group first: a field
    bit the pattern fixes belongs to the pattern, and overwriting it would
    leave the match condition unsatisfied -- the word would decode as something
    else entirely, which is the one failure this generator must not produce
    silently.

    Bits inside no field at all are collected as a final group so that a
    pattern decodetree declares with no format still gets its registers varied.
    """
    groups = []
    covered = 0
    for _n, f in sorted(fields.items()):
        m = getattr(f, "mask", 0) & ~fixedmask & 0xFFFFFFFF
        if m and m not in groups:
            groups.append(m)
        covered |= m
    rest = ~fixedmask & ~covered & 0xFFFFFFFF
    if rest:
        groups.append(rest)
    return sorted(groups)


def words_for_pattern(fixedbits, fixedmask, fields, extra=0, seed=0):
    """Every variant word for one pattern, in bank order, de-duplicated.

    `extra` appends that many further variants with the free bits filled from a
    reproducible pseudo-random stream.  THE SIX BANKS ARE A GOOD FIRST TRY AND
    NOT A PROOF: a row whose size field reserves every value the banks happen to
    deal it comes back with no candidate at all, and "no candidate" would then
    be read as a fact about QEMU rather than about this generator's arithmetic.
    Widening is therefore a MEASUREMENT step -- run it for the rows the banks
    missed, and whatever still has no candidate has been looked for.
    """
    groups = slot_masks(fixedbits, fixedmask, fields)
    seen = []
    for const, stride in BANKS:
        word = fixedbits & 0xFFFFFFFF
        for i, gmask in enumerate(groups):
            word |= scatter(const + i * stride, gmask)
        word &= 0xFFFFFFFF
        if word not in seen:
            seen.append(word)
    if extra:
        # A plain LCG rather than `random`: the words a coverage number rests on
        # must be the same words the next run generates, and a module-level RNG
        # is shared state a caller can perturb.
        state = (seed ^ fixedbits ^ (fixedmask << 1)) & 0xFFFFFFFF or 1
        for _ in range(extra):
            word = fixedbits & 0xFFFFFFFF
            for gmask in groups:
                state = (1103515245 * state + 12345) & 0xFFFFFFFF
                word |= scatter(state >> 8, gmask)
            word &= 0xFFFFFFFF
            if word not in seen:
                seen.append(word)
    return seen


def generate(root, build, census_path, only=None, extra=0, seed=0):
    """{rule: [word, ...]} for every reachable-candidate row of the census."""
    groups = cen.decoder_groups(root)
    pats = patterns_with_fields(root, groups)

    rows = []
    stamp = None
    for line in open(census_path, "r", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("#emulator "):
            stamp = line.split(None, 1)[1].strip()
            continue
        if line.startswith("#") or not line:
            continue
        p = line.split("\t")
        if len(p) < 5:
            continue
        if p[1] != "reachable-candidate":
            continue
        if only is not None and p[0] not in only:
            continue
        rows.append((p[0], set(p[2].split(","))))
    if not stamp:
        raise cen.Refusal("%s: no #emulator stamp -- the candidate words would "
                          "describe no particular decoder" % census_path)
    if not rows:
        raise cen.Refusal("%s: no reachable-candidate row.  Generating "
                          "candidates for nothing would report a complete "
                          "sweep of an empty space" % census_path)

    out = []
    for rule, scoped in rows:
        if rule not in pats:
            raise cen.Refusal("%s: the census states rule %s and the decode "
                              "sources have no pattern for it -- the census "
                              "and this checkout are not the same tree"
                              % (census_path, rule))
        words = []
        npat = 0
        for (dfile, fixedbits, fixedmask, fields) in pats[rule]:
            if dfile not in scoped:
                continue
            npat += 1
            for w in words_for_pattern(fixedbits, fixedmask, fields,
                                       extra=extra, seed=seed):
                if w not in words:
                    words.append(w)
        out.append((rule, npat, words))
    return stamp, out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=os.path.abspath(
        os.path.join(_HERE, "..", "..", "..", "..", "..", "..")))
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--census", required=True)
    ap.add_argument("-o", "--out", required=True,
                    help="TSV: rule, patterns, variant index, word")
    ap.add_argument("--pop", default=None,
                    help="also write the sled population (isa<TAB>encoding)")
    ap.add_argument("--only", default=None,
                    help="file of rule names: widen only these rows")
    ap.add_argument("--extra", type=int, default=0,
                    help="pseudo-random variants per pattern, on top of the "
                         "six banks (reproducible; see words_for_pattern)")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    only = None
    if a.only:
        only = {ln.strip() for ln in open(a.only) if ln.strip()
                and not ln.startswith("#")}
        if not only:
            print("a64_row_encodings: REFUSED: --only names no rule",
                  file=sys.stderr)
            return 1

    try:
        stamp, rows = generate(a.root, a.build_dir, a.census, only,
                               a.extra, a.seed)
    except cen.Refusal as e:
        print("a64_row_encodings: REFUSED: %s" % e, file=sys.stderr)
        return 1

    empty = [r for r, _n, w in rows if not w]
    allwords = set()
    with open(a.out, "w") as f:
        f.write("#emulator %s\n" % stamp)
        f.write("#rule\tpatterns\tvariant\tword\n")
        for rule, npat, words in rows:
            if not words:
                f.write("%s\t%d\t-\t-\n" % (rule, npat))
                continue
            for i, w in enumerate(words):
                f.write("%s\t%d\t%d\t%08x\n" % (rule, npat, i, w))
                allwords.add(w)

    if a.pop:
        with open(a.pop, "w") as f:
            for w in sorted(allwords):
                # The sled reads little-endian BYTES; aarch64 words are stored
                # little-endian, so the population spells the bytes, not the
                # architectural word.  Getting this backwards is how the
                # riscv64 pass first scored a corpus against words no guest
                # ever held.
                b = w.to_bytes(4, "little")
                f.write("aarch64\t%s\n" % b.hex())

    print("rules %d   candidate words %d   rows with no word %d"
          % (len(rows), len(allwords), len(empty)))
    if empty:
        print("rows with no candidate word: %s" % " ".join(empty[:20]))
    print("written to %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
