"""Diff two decoded traces structurally."""
import sys
from pathlib import Path
sys.path.insert(0, "../champsim_tracer")
import champsim_tracer_decode as dec


def diff_lists(a, b, label, max_show=3):
    if a == b:
        print(f"  {label}: equal ({len(a)} items)")
        return
    if len(a) != len(b):
        print(f"  {label}: LEN {len(a)} != {len(b)}")
    n = 0
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            print(f"  {label}[{i}]:")
            print(f"    a={x}")
            print(f"    b={y}")
            n += 1
            if n >= max_show:
                return


def main(p1, p2):
    _, _, ea = dec.decode_champsim_tracer(Path(p1))
    _, _, eb = dec.decode_champsim_tracer(Path(p2))
    print(f"entries a={len(ea)} b={len(eb)}")
    if len(ea) != len(eb):
        return
    n = 0
    for i, (x, y) in enumerate(zip(ea, eb)):
        if x == y:
            continue
        n += 1
        if n > 3:
            print(f"... and {sum(1 for u,v in zip(ea,eb) if u != v) - 3} more differing entries")
            break
        print(f"--- entry {i} differs (template_id={x['template_id']}) ---")
        for k in sorted(set(x) | set(y)):
            xv = x.get(k); yv = y.get(k)
            if xv == yv:
                continue
            if isinstance(xv, list) and isinstance(yv, list):
                diff_lists(xv, yv, k, max_show=2)
            else:
                print(f"  {k}: a={xv!r}   b={yv!r}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
