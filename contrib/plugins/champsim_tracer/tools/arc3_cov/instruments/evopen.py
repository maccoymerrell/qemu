"""Open an evidence file that a disk sweep may have compressed underneath.

WHY THIS IS A TREE MODULE AND NOT A COPY IN EACH SCRIPT.

Evidence roots are swept: text bulk over 64 KiB is compressed in place with
`xz -1`, and sled corpora are written with `compress=zstd` in the first
place.  Both are correct -- these files are large, they are text, and they
compress twenty to one.  What is NOT correct is a consumer that names the
uncompressed path and gets a decompression frame handed to its parser.

That failure is quiet in the worst way.  `bytes.fromhex` on frame bytes
raises, but a line-oriented reader that filters on a leading field simply
matches nothing, and the arm reports a population of ZERO as though the
corpus said so.  Measured: two of exec100/pop's four members were left as
`.tsv.zst` by a sweep and read as empty populations; the verify50 sled
corpora are `.tsv.zst` by construction and the bar arms named `.tsv`.

So the readers follow the sweep, in one place.  A caller keeps naming the
UNCOMPRESSED path -- that name is what manifests, harnesses and run scripts
carry, and rewriting every one of them each time a sweep runs is how a
corpus and its consumers drift apart.

Author: Maccoy Merrell.
"""
import io
import os
import subprocess
import sys

#: Suffix -> the decompressor that reads it to stdout.  `gzip` and `lzma`
#: are in the standard library; zstd is not, and the tree already shells to
#: the binary everywhere else, so this does too rather than adding a
#: dependency a fresh checkout would not have.
DECOMPRESSORS = {
    ".zst":  ["zstd", "-dcq"],
    ".zstd": ["zstd", "-dcq"],
    ".xz":   ["xz", "-dcq"],
    ".gz":   ["gzip", "-dcq"],
}


def resolve(path):
    """The path that actually exists: the one named, or a compressed sibling."""
    if os.path.exists(path):
        return path
    for suf in DECOMPRESSORS:
        if os.path.exists(path + suf):
            return path + suf
    return path


def evopen(path, errors="strict"):
    """Open `path` as text, transparently decompressing a compressed sibling.

    Raises on a decompressor's own non-zero exit status.  It is never
    inferred from empty output: a corpus that reads as zero rows because
    the decompressor failed is exactly the silent false success this
    module exists to have stopped.
    """
    path = resolve(path)
    cmd = DECOMPRESSORS.get(os.path.splitext(path)[1].lower())
    if cmd is None:
        return open(path, errors=errors)
    try:
        pr = subprocess.run(cmd + [path], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    except FileNotFoundError:
        raise SystemExit("evopen: %s is needed on PATH to read %s"
                         % (cmd[0], path))
    if pr.returncode != 0:
        raise SystemExit("evopen: %s failed on %s (rc=%d): %s"
                         % (cmd[0], path, pr.returncode,
                            pr.stderr.decode("utf-8", "replace").strip()))
    return io.StringIO(pr.stdout.decode("utf-8", errors
                                        if errors != "strict" else "strict"))


def selftest():
    """Prove each arm of the opener, including the refusal."""
    import tempfile
    fails = 0
    d = tempfile.mkdtemp()
    plain = os.path.join(d, "a.tsv")
    with open(plain, "w") as f:
        f.write("x86_64\t9090\tnop\n")
    if evopen(plain).read() == "x86_64\t9090\tnop\n":
        print("PASS  A a plain file reads")
    else:
        print("FAIL  A"); fails += 1
    for suf, comp in ((".zst", ["zstd", "-q"]), (".xz", ["xz"]),
                      (".gz", ["gzip"])):
        src = os.path.join(d, "b%s.tsv" % suf.replace(".", ""))
        with open(src, "w") as f:
            f.write("x86_64\t9090\tnop\n")
        if subprocess.run(comp + [src], capture_output=True).returncode:
            print("SKIP  %s compressor absent" % suf); continue
        # named WITHOUT the suffix -- the case every caller actually hits
        if evopen(src).read() == "x86_64\t9090\tnop\n":
            print("PASS  B%s a %s sibling is found and decompressed" % (suf, suf))
        else:
            print("FAIL  B%s" % suf); fails += 1
    bad = os.path.join(d, "c.tsv.zst")
    with open(bad, "wb") as f:
        f.write(b"not a zstd frame at all, not even close\n")
    try:
        evopen(os.path.join(d, "c.tsv"))
        print("FAIL  C a corrupt member read as success"); fails += 1
    except SystemExit:
        print("PASS  C a corrupt member RAISES, never reads as empty")
    print("evopen selftest: %d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(selftest())
