"""Locate where two .cst files actually differ."""
import sys, struct
from pathlib import Path
sys.path.insert(0, "..")
import champsim_tracer_decode as dec


def first_diffs(a: bytes, b: bytes, n: int = 5) -> list[int]:
    out = []
    L = min(len(a), len(b))
    for i in range(L):
        if a[i] != b[i]:
            out.append(i)
            if len(out) >= n:
                break
    return out


def header_layout(buf: bytes) -> dict:
    """Replay the header parser and return the byte offset of every field."""
    o = 0
    layout = {"magic@0": (0, 4)}
    o = 4
    layout["isa@%d" % o] = (o, 1); o += 1
    layout["flags@%d" % o] = (o, 1); o += 1
    def uleb(off):
        v = 0; s = 0; i = off
        while True:
            b = buf[i]; v |= (b & 0x7F) << s; i += 1
            if (b & 0x80) == 0: return v, i
            s += 7
    cmd_len, o2 = uleb(o); layout["cmd_len@%d" % o] = (o, o2 - o); o = o2
    layout["cmd@%d" % o] = (o, cmd_len); o += cmd_len
    dt_len, o2 = uleb(o); layout["dt_len@%d" % o] = (o, o2 - o); o = o2
    layout["dt@%d" % o] = (o, dt_len); o += dt_len
    cm_len, o2 = uleb(o); layout["cm_len@%d" % o] = (o, o2 - o); o = o2
    layout["cm@%d" % o] = (o, cm_len); o += cm_len
    tg_len, o2 = uleb(o); layout["tg_len@%d" % o] = (o, o2 - o); o = o2
    layout["tg@%d" % o] = (o, tg_len); o += tg_len
    tid, o2 = uleb(o); layout["tid@%d" % o] = (o, o2 - o); o = o2
    layout["__body_off"] = (o, 0)
    return layout


def field_at(layout: dict, off: int) -> str:
    for k, (start, ln) in layout.items():
        if k == "__body_off":
            continue
        if start <= off < start + max(ln, 1):
            return k
    return "(after-header)"


def main(p1: str, p2: str) -> None:
    a = Path(p1).read_bytes()
    b = Path(p2).read_bytes()
    print(f"sizes: {len(a)} vs {len(b)}")

    diffs = first_diffs(a, b, 8)
    print(f"first {len(diffs)} differing offsets: {diffs}")
    if not diffs:
        print("BYTE-EQUIVALENT")
        return

    la = header_layout(a)
    lb = header_layout(b)
    body_off_a = la["__body_off"][0]
    body_off_b = lb["__body_off"][0]
    print(f"header end (body_off): file_a={body_off_a}, file_b={body_off_b}")

    for off in diffs:
        if off < body_off_a and off < body_off_b:
            print(f"  byte {off}: in header field {field_at(la, off)} "
                  f"(a=0x{a[off]:02x} {chr(a[off]) if 32<=a[off]<127 else '?'} | "
                  f"b=0x{b[off]:02x} {chr(b[off]) if 32<=b[off]<127 else '?'})")
        else:
            print(f"  byte {off}: in body/templates region "
                  f"(a=0x{a[off]:02x} | b=0x{b[off]:02x})")

    # Compare body slice and templates slice using each file's own trailer.
    def trailer(buf):
        return struct.unpack("<5Q", buf[-64:][:40])
    ta_tr = trailer(a); tb_tr = trailer(b)
    body_a = a[ta_tr[2]:ta_tr[2] + ta_tr[3]]
    body_b = b[tb_tr[2]:tb_tr[2] + tb_tr[3]]
    print(f"body slice: equal={body_a == body_b}  len_a={len(body_a)} len_b={len(body_b)}")
    tmpl_a = a[ta_tr[0]:-64]
    tmpl_b = b[tb_tr[0]:-64]
    print(f"tmpl slice: equal={tmpl_a == tmpl_b}  len_a={len(tmpl_a)} len_b={len(tmpl_b)}")

    # Decode and compare structurally
    ma, _, ea = dec.decode_champsim_tracer(Path(p1))
    mb, _, eb = dec.decode_champsim_tracer(Path(p2))
    print(f"datetime a={ma['datetime']!r}  b={mb['datetime']!r}")
    print(f"command  a={ma['command']!r}")
    print(f"command  b={mb['command']!r}")
    print(f"entries equal: {ea == eb}  ({len(ea)} vs {len(eb)})")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
