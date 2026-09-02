#!/usr/bin/env python3
"""R17.3 oracle: the enumerated source/destination sets of a STATIC
instruction are context-invariant.  A raw dump lists every template; the
same (pc, encoding) reached through different chains must state the same
src=[] and dst=[].  Variance across those occurrences is the bug R17.3
names.  Reports the population it checked, so a vacuous pass is visible."""
import re, sys, collections
INSN = re.compile(r"insn\[\d+\] pc=(0x[0-9a-f]+)\s")
SRC  = re.compile(r"^\s+@\S+\s+[0-9a-f ]*\+?\s*src=\[(.*?)\]\s+dst=\[(.*?)\]\s*$")
BYTES= re.compile(r"bytes=([0-9a-f]+)")
def scan(path):
    per=collections.defaultdict(set); pc=None; by=None; sd=None
    for line in open(path, errors="replace"):
        m=INSN.search(line)
        if m:
            if pc is not None and sd is not None and by is not None:
                per[(pc,by)].add(sd)
            pc=m.group(1); by=None; sd=None; continue
        m=SRC.match(line)
        if m and pc: sd=(m.group(1).strip(), m.group(2).strip()); continue
        m=BYTES.search(line)
        if m and pc and by is None: by=m.group(1)
    if pc is not None and sd is not None and by is not None:
        per[(pc,by)].add(sd)
    return per
rc=0
for path in sys.argv[1:]:
    per=scan(path)
    multi={k:v for k,v in per.items() if len(v)>1}
    reached=sum(1 for v in per.values() if True)
    dup=sum(1 for k,v in per.items())
    print("%-56s static insns=%d  VARIANT=%d" % (path.split('/')[-1], dup, len(multi)))
    for k,v in list(multi.items())[:10]:
        print("    VARIANT pc=%s bytes=%s -> %r" % (k[0],k[1],sorted(v)))
    if multi: rc=1
sys.exit(rc)
