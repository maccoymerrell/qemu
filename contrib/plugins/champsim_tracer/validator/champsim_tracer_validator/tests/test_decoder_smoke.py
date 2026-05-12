"""Locate where two .cst files actually differ.

The .cst container is a POSIX ustar archive holding two members,
``body.cst[.<codec>]`` and ``header.cst[.<codec>]``.  This script
extracts both members from each file, compares them member-by-member,
and decodes the traces structurally for an end-to-end equivalence
check.
"""
import io
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import _cst_decode_runner as dec


def first_diffs(a: bytes, b: bytes, n: int = 5) -> list[int]:
    out = []
    L = min(len(a), len(b))
    for i in range(L):
        if a[i] != b[i]:
            out.append(i)
            if len(out) >= n:
                break
    return out


CODEC_DECODE = {
    "zst": ["zstd", "-d", "-c"],
    "xz":  ["xz",   "-d", "-c"],
    "gz":  ["gzip", "-d", "-c"],
    "bz2": ["bzip2", "-d", "-c"],
    "lz4": ["lz4",  "-d", "-c"],
}


def _decompress(member_name: str, payload: bytes) -> bytes:
    suffix = member_name.rsplit(".", 1)[-1]
    if suffix in CODEC_DECODE:
        cp = subprocess.run(CODEC_DECODE[suffix], input=payload,
                            check=True, capture_output=True)
        return cp.stdout
    return payload


def extract_members(path: Path) -> tuple[bytes, bytes]:
    """Return (body_bytes, header_bytes) for the .cst at @path."""
    body = header = None
    with tarfile.open(path, mode="r") as t:
        for m in t.getmembers():
            if m.name.startswith("body.cst"):
                body = _decompress(m.name, t.extractfile(m).read())
            elif m.name.startswith("header.cst"):
                header = _decompress(m.name, t.extractfile(m).read())
    if body is None or header is None:
        raise SystemExit(f"{path}: missing body.cst or header.cst member")
    return body, header


def main(p1: str, p2: str) -> None:
    body_a, hdr_a = extract_members(Path(p1))
    body_b, hdr_b = extract_members(Path(p2))
    print(f"file_a header={len(hdr_a)} body={len(body_a)}")
    print(f"file_b header={len(hdr_b)} body={len(body_b)}")

    hdr_diffs = first_diffs(hdr_a, hdr_b, 8)
    body_diffs = first_diffs(body_a, body_b, 8)
    if not hdr_diffs and not body_diffs and len(hdr_a) == len(hdr_b) \
            and len(body_a) == len(body_b):
        print("BYTE-EQUIVALENT (header+body)")
    else:
        if hdr_diffs:
            print(f"  header diffs at offsets: {hdr_diffs}")
        if body_diffs:
            print(f"  body diffs at offsets: {body_diffs}")
        if len(hdr_a) != len(hdr_b):
            print(f"  header size differs: {len(hdr_a)} vs {len(hdr_b)}")
        if len(body_a) != len(body_b):
            print(f"  body size differs: {len(body_a)} vs {len(body_b)}")

    # Decode and compare structurally
    ma, _, ea = dec.decode_champsim_tracer(Path(p1))
    mb, _, eb = dec.decode_champsim_tracer(Path(p2))
    print(f"datetime a={ma['datetime']!r}  b={mb['datetime']!r}")
    print(f"command  a={ma['command']!r}")
    print(f"command  b={mb['command']!r}")
    print(f"entries equal: {ea == eb}  ({len(ea)} vs {len(eb)})")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
