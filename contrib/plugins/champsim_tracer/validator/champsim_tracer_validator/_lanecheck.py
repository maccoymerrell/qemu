"""Memop -> register / lane association, checked against the architecture.

The wire says which register each memory access of a vector structure
access belongs to (the load's bit in a destination's dependency mask, the
store's source bit in its store-data mask) and which lanes of that register
it moves (LOAD/STORE_DATA_LANE_MASK).  Nothing else in the validator reads
those two facts together, so a writer that put the right accesses on the
wire under the wrong registers or lanes -- an unstable sort that permuted the
slots of one instruction, a statement whose datum stopped reaching the
seating -- passed every cell.  This is the check that reads them.

It reads the disassembly `cst_decode --show-deps --show-lanes` prints,
streamed a line at a time (the trace is never held whole), and scores each
published access of a SUBJECT instruction against the mapping the
architecture defines for it:

  aarch64  LD2/LD3/LD4 and ST2/ST3/ST4 (multiple structures, with or without
           post-index): element k of the region (k = offset / esize) belongs
           to register rt + k % selem, lane k // selem.
  riscv64  unit-stride vle<eew>.v / vse<eew>.v with nf == 1: element k
           belongs to the group named by vd, lane k.  Only the lanes of the
           base register are checkable, because the wire names the group by
           its base register.

Both correct-path and wrong-path renderings are scored.  An access that the
renderer placed under no register is WRONG, not skipped: an unassociated
access is exactly the defect this check exists to see.

A check without a subject fails where the program is known to carry one
(the generator's --coverage programs execute every family above); elsewhere
the result is reported as having no subject and is not scored.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ISAS = ("aarch64", "riscv64")

_LD = re.compile(r'ld\[[^\]]*\]\((0x[0-9a-f]+)\)(\{[0-9.,]*\})?')
_ST = re.compile(r'st\[[^\]]*\]\((0x[0-9a-f]+)\)(\{[0-9.,]*\})?')
_HEAD = re.compile(r'^0x([0-9a-f]+)(?: <[^>]*>)?:\s+((?:[0-9a-f]{2} )+)\s')


def _lanes(tok: str | None) -> set[int] | None:
    if not tok:
        return None
    out: set[int] = set()
    for part in tok.strip('{}').split(','):
        if '..' in part:
            a, b = part.split('..')
            out.update(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return out


def _a64_subject(word: int) -> dict | None:
    if (word & 0xbfa00000) not in (0x0c000000, 0x0c800000):
        return None
    selem = {0: 4, 4: 3, 8: 2}.get((word >> 12) & 0xf)
    if selem is None:
        return None
    return dict(rt=word & 31, selem=selem, esize=1 << ((word >> 10) & 3),
                load=bool((word >> 22) & 1), rv=False)


def _rv_subject(word: int) -> dict | None:
    op = word & 0x7f
    if op not in (0x07, 0x27):
        return None
    eew = {0: 1, 5: 2, 6: 4, 7: 8}.get((word >> 12) & 7)
    mop = (word >> 26) & 3
    lumop = (word >> 20) & 0x1f
    nf = ((word >> 29) & 7) + 1
    if eew is None or mop != 0 or lumop != 0 or nf != 1:
        return None
    return dict(rt=(word >> 7) & 31, selem=1, esize=eew, load=(op == 0x07),
                rv=True)


def _groups(body: str, sub: dict) -> list[tuple[int, list]]:
    """(register, [(addr, lanes)]) for each rendered operand group."""
    out = []
    for seg in body.split('  ;  '):
        if '->' not in seg:
            continue
        lhs, rhs = seg.split('->', 1)
        if sub['load']:
            m = re.search(r'%v(\d+)', rhs)
            mems = [(int(a, 16), _lanes(l)) for a, l in _LD.findall(lhs)]
        else:
            m = re.search(r'%v(\d+)', lhs)
            mems = [(int(a, 16), _lanes(l)) for a, l in _ST.findall(rhs)]
        if m and mems:
            out.append((int(m.group(1)), mems))
    return out


@dataclass
class LaneReport:
    isa: str
    subjects: int = 0
    memops: int = 0
    wrong: int = 0
    per_encoding: dict = field(default_factory=dict)
    examples: list = field(default_factory=list)

    def line(self) -> str:
        return (f"lanecheck[{self.isa}]: subjects={self.subjects} "
                f"memops={self.memops} wrong={self.wrong}")


def score_lines(lines, isa: str) -> LaneReport:
    rep = LaneReport(isa)
    subject_of = _a64_subject if isa == 'aarch64' else _rv_subject
    for line in lines:
        m = _HEAD.match(line)
        if not m:
            continue
        bs = bytes.fromhex(m.group(2).replace(' ', ''))
        if len(bs) != 4:
            continue
        sub = subject_of(int.from_bytes(bs, 'little'))
        if not sub:
            continue
        body = line.split('  ; deps:')[0]
        gs = _groups(body, sub)
        placed = [a for _, ms in gs for a, _ in ms]
        every = {int(a, 16)
                 for a, _ in (_LD if sub['load'] else _ST).findall(body)}
        if not placed and not every:
            continue
        rep.subjects += 1
        key = bs.hex()
        per = rep.per_encoding.setdefault(key, [0, 0, 0])
        per[0] += 1
        base = min(every | set(placed))
        nl_rv = 16 // sub['esize']

        def bad(msg: str) -> None:
            rep.wrong += 1
            per[2] += 1
            if len(rep.examples) < 20:
                rep.examples.append(f"pc=0x{m.group(1)} bytes={key} {msg}")

        for a in sorted(every - set(placed)):
            k = (a - base) // sub['esize']
            if sub['rv'] and k >= nl_rv:
                continue
            rep.memops += 1
            per[1] += 1
            bad(f"addr=0x{a:x} k={k} associated with no register")
        for reg, ms in gs:
            for a, ln in ms:
                k = (a - base) // sub['esize']
                if sub['rv']:
                    if k >= nl_rv:
                        continue
                    want_reg, want_lane = sub['rt'], k
                else:
                    want_reg = (sub['rt'] + k % sub['selem']) % 32
                    want_lane = k // sub['selem']
                rep.memops += 1
                per[1] += 1
                if reg != want_reg or ln != {want_lane}:
                    bad(f"addr=0x{a:x} k={k} on %v{reg} lanes="
                        f"{sorted(ln) if ln else None} want %v{want_reg} "
                        f"lane {want_lane}")
    return rep


def check_trace(trace: Path, isa: str, decode: Path) -> LaneReport:
    """Stream `cst_decode --show-deps --show-lanes` over @trace and score
    it.  Raises on a decoder failure: a check whose input could not be read
    has not run."""
    proc = subprocess.Popen(
        [str(decode), "--show-deps", "--show-lanes", str(trace)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        errors="replace", bufsize=1 << 20)
    try:
        rep = score_lines(proc.stdout, isa)
    finally:
        proc.stdout.close()
        rc = proc.wait()
    if rc != 0:
        raise RuntimeError(f"cst_decode rc={rc} on {trace}")
    return rep


def verdict(rep: LaneReport, subject_required: bool) -> int:
    """0 clean, 1 failing.  Prints the report."""
    print(rep.line())
    for ex in rep.examples:
        print(f"  WRONG {ex}")
    for key in sorted(rep.per_encoding):
        r, n, w = rep.per_encoding[key]
        print(f"  {key} renderings={r} memops={n} wrong={w}")
    if rep.subjects == 0:
        if subject_required:
            print(f"lanecheck[{rep.isa}]: FAIL  no subject -- the program "
                  f"carries structure accesses and none reached the wire")
            return 1
        print(f"lanecheck[{rep.isa}]: no subject in this program "
              f"(not scored)")
        return 0
    if rep.wrong:
        print(f"lanecheck[{rep.isa}]: FAIL  {rep.wrong} of {rep.memops} "
              f"accesses carry the wrong register or lanes")
        return 1
    print(f"lanecheck[{rep.isa}]: ok")
    return 0


if __name__ == "__main__":
    from ._cst_decode_runner import _find_cst_decode
    if len(sys.argv) < 3:
        print("usage: python -m champsim_tracer_validator._lanecheck "
              "<trace.cst> <aarch64|riscv64> [--require-subject]")
        sys.exit(2)
    r = check_trace(Path(sys.argv[1]), sys.argv[2], _find_cst_decode())
    sys.exit(verdict(r, "--require-subject" in sys.argv))
