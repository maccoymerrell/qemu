#!/usr/bin/env python3
"""Negative control for the memop cross-check.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

  usage: negative_control.py --in q.jsonl --out mutated.jsonl
                             --mutation {addr,value,width,drop,extra}
                             [--n 200] [--seed 1]

A comparison that reports 0 defects is worth nothing until the instrument
that reported it has been shown to FIRE.  This injects ONE named defect
class into a champsim_tracer extraction and prints how many instructions it
touched; re-running cmp_memop.py against the mutated stream must turn the
corresponding row red.  A mutation that measures as INERT is itself a
finding: it means the comparison is blind to that defect class.

  addr    move one load address by 8 bytes      -> ADDRESS must go red
  value   flip a bit in one load value          -> DATA must go red
  width   halve one store width                 -> WIDTH must go red
  drop    delete one load memop                 -> COUNT must go red
  extra   duplicate one store memop             -> COUNT must go red
"""
import argparse
import json
import random

AP = argparse.ArgumentParser()
AP.add_argument('--in', dest='inp', required=True)
AP.add_argument('--out', required=True)
AP.add_argument('--mutation', required=True,
                choices=['addr', 'value', 'width', 'drop', 'extra'])
AP.add_argument('--n', type=int, default=200)
AP.add_argument('--seed', type=int, default=1)
A = AP.parse_args()

rows = [json.loads(l) for l in open(A.inp)]
rng = random.Random(A.seed)

if A.mutation in ('addr', 'value', 'drop'):
    cand = [i for i, j in enumerate(rows) if j['nl'] > 0 and len(j['la']) > 0]
else:
    cand = [i for i, j in enumerate(rows) if j['ns'] > 0 and len(j['sa']) > 0]
pick = rng.sample(cand, min(A.n, len(cand)))

hit = 0
for i in pick:
    j = rows[i]
    if A.mutation == 'addr':
        j['la'] = [j['la'][0] + 8] + j['la'][1:]
    elif A.mutation == 'value':
        j['lv'] = [j['lv'][0] ^ 1] + j['lv'][1:]
    elif A.mutation == 'width':
        w = j['sw'][0]
        if w < 2:
            continue
        j['sw'] = [w // 2] + j['sw'][1:]
    elif A.mutation == 'drop':
        j['la'] = j['la'][1:]
        j['lw'] = j['lw'][1:]
        j['lv'] = j['lv'][1:]
        j['nl'] = len(j['lw'])
    elif A.mutation == 'extra':
        j['sa'] = j['sa'] + [j['sa'][-1] + 4096]
        j['sw'] = j['sw'] + [j['sw'][-1]]
        j['sv'] = j['sv'] + [j['sv'][-1]]
        j['ns'] = len(j['sw'])
    hit += 1

with open(A.out, 'w') as f:
    for j in rows:
        f.write(json.dumps(j, separators=(',', ':')) + '\n')
print("mutation=%s injected into %d instructions of %d" % (A.mutation, hit, len(rows)))
