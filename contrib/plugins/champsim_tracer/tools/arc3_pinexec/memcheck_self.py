#!/usr/bin/env python3
"""Store-to-load self-consistency of a memop stream, x86_64 user mode.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

  usage: memcheck_self.py --qemu q.jsonl [...]      one champsim_tracer stream
         memcheck_self.py --pin  memop.bin [...]    one PIN reference stream

WHY THIS EXISTS

Comparing memop DATA against an execution reference answers "do the two runs
hold the same bytes", which is not the same question as "is our DATA right".
Two runs of the same program with different auxv, environment and mappings
legitimately hold different bytes, so a raw cross-run value mismatch cannot
by itself convict either instrument.

This check needs no reference at all.  It replays the stream's own stores
into a byte-level shadow memory and, for every subsequent load whose bytes
are ALL already known, asserts that the value the stream recorded for the
load is the value the stream itself last stored there.  A tracer that
mis-attributes an address, a width, or a value breaks that invariant against
its own record; a tracer that is merely tracing a different process does not.

A load whose bytes are not all known is UNCHECKED and reported as such --
the window opens mid-execution, so most early loads read memory written
before the window.  Silence is not agreement here either.

THE KERNEL WRITES USER MEMORY AND NO INSTRUCTION RECORDS IT

A memop stream is a record of what INSTRUCTIONS did.  A syscall that takes
an output pointer has the kernel write the buffer, and no instruction memop
exists for that write, so the shadow's copy of those bytes is stale from the
moment the syscall returns.  Scoring such a load against the shadow convicts
the tracer of a store it was never able to see.

Measured, and this is why the rule below exists: `prlimit64(0, RLIMIT_STACK,
NULL, &lim)` at CP index 4038 of the x86_64 register-arm workload writes
`rlim_cur = 0x800000` into a stack slot last written by a `rep stosq` at
index 97; the reload at index 4045 then reads 0x800000 where the shadow
still holds 0.  That single row was the whole VIOLATED population of three
consecutive banks.

So a load is CHECKED only when every one of its bytes was stored SINCE the
most recent syscall.  Bytes older than that are UNCHECKED-ACROSS-SYSCALL --
a named bucket, counted, and reported together with how many of them WOULD
have scored as violations, so the exclusion can never quietly absorb a real
defect.
"""
import argparse
import collections
import json
import sys

AP = argparse.ArgumentParser()
AP.add_argument('--qemu')
AP.add_argument('--pin')
AP.add_argument('--limit', type=int, default=None)
AP.add_argument('--out', default=None)
AP.add_argument('--maxreport', type=int, default=25)
A = AP.parse_args()
if bool(A.qemu) == bool(A.pin):
    sys.exit('exactly one of --qemu / --pin')

#: x86_64 `syscall`.  This tool is x86_64 user mode by construction (see the
#: module docstring), so the encoding is stated here rather than decoded.
SYSCALL_ENC = '0f05'

OUT = open(A.out, 'w') if A.out else sys.stdout


def say(*a):
    print(*a, file=OUT)
    OUT.flush()


def q_stream(path, limit):
    """(index, tag, addr, width, value) memops in program order.

    Loads before stores within one instruction: a read-modify-write reads the
    old value and then writes the new one, and the shadow has to see them in
    that order or every RMW would look like a violation."""
    for n, line in enumerate(open(path)):
        if limit is not None and n >= limit:
            return
        j = json.loads(line)
        if j['b'] == SYSCALL_ENC:
            yield n, 'sc', 0, 0, 0
        for tag, ak, wk, vk in (('ld', 'la', 'lw', 'lv'),
                                ('st', 'sa', 'sw', 'sv')):
            addrs = list(dict.fromkeys(j[ak]))
            widths, vals = j[wk], j[vk]
            if len(addrs) != len(widths) or len(vals) != len(widths):
                continue
            for a_, w_, v_ in zip(addrs, widths, vals):
                yield n, tag, a_, w_, v_


def p_stream(path, limit):
    import pinmemlib
    P = pinmemlib.read_memop(path, nrec=limit)
    for n in range(len(P)):
        r = P[n]
        if bytes(r['bytes'][:int(r['len'])]).hex() == SYSCALL_ENC:
            yield n, 'sc', 0, 0, 0
        if r['n_ld'] > r['ld_rec'] or r['n_st'] > r['st_rec']:
            continue
        for tag, ek, sk, dk, gk, ck in (
                ('ld', 'ld_ea', 'ld_sz', 'ld_data', 'ld_got', 'ld_rec'),
                ('st', 'st_ea', 'st_sz', 'st_data', 'st_got', 'st_rec')):
            for k in range(int(r[ck])):
                yield (n, tag, int(r[ek][k]), int(r[sk][k]),
                       pinmemlib.memop_value(r[dk][k], int(r[gk][k])))


src = q_stream(A.qemu, A.limit) if A.qemu else p_stream(A.pin, A.limit)
label = A.qemu or A.pin

shadow = {}          # addr -> (byte, syscall epoch the byte was stored in)
epoch = 0            # bumped by every syscall instruction in the stream
st = collections.Counter()
mism = collections.Counter()
sample = {}
LOAD_W_MAX = 64

for n, tag, addr, w, val in src:
    if tag == 'sc':
        # Everything the shadow holds is now potentially stale: the kernel
        # may have written any of it on this syscall's behalf, and no memop
        # records that.  Bytes are not erased -- an older byte stays
        # readable and is reported in its own bucket -- so the loss of
        # coverage is counted rather than hidden.
        epoch += 1
        st['syscalls'] += 1
        continue
    if w <= 0 or w > LOAD_W_MAX:
        st['skipped_width'] += 1
        continue
    if tag == 'st':
        st['stores'] += 1
        for k in range(w):
            shadow[addr + k] = ((val >> (8 * k)) & 0xff, epoch)
        continue
    st['loads'] += 1
    known = True
    stale = False
    exp = 0
    for k in range(w):
        b = shadow.get(addr + k)
        if b is None:
            known = False
            break
        exp |= b[0] << (8 * k)
        if b[1] < epoch:
            stale = True
    if not known:
        st['loads_unchecked'] += 1
        continue
    if stale:
        st['loads_unchecked_syscall'] += 1
        if exp != val:
            st['stale_would_have_violated'] += 1
        continue
    st['loads_checked'] += 1
    if exp == val:
        st['loads_match'] += 1
    else:
        st['loads_mismatch'] += 1
        sig = (w,)
        mism[sig] += 1
        sample.setdefault(sig, (n, addr, w, val, exp))

say("store-to-load self-consistency: %s" % label)
say("  stores replayed          %10d" % st['stores'])
say("  loads seen               %10d" % st['loads'])
say("  syscalls seen            %10d" % st['syscalls'])
say("  loads UNCHECKED          %10d   (bytes not written inside the window)"
    % st['loads_unchecked'])
say("  loads UNCHECKED-SYSCALL  %10d   (bytes last written before the most "
    "recent syscall; the kernel may have overwritten them and no memop "
    "would record it)" % st['loads_unchecked_syscall'])
say("    of those, value != shadow %7d   (NOT scored: excluded because the "
    "shadow is stale, not because the tracer agreed)"
    % st['stale_would_have_violated'])
say("  loads CHECKED            %10d" % st['loads_checked'])
say("  loads MATCHED            %10d" % st['loads_match'])
say("  loads VIOLATED           %10d" % st['loads_mismatch'])
if st['loads_checked']:
    say("  self-consistency         %12.6f%%"
        % (100.0 * st['loads_match'] / st['loads_checked']))
if st['skipped_width']:
    say("  memops skipped for width %10d" % st['skipped_width'])
for sig, c in mism.most_common(A.maxreport):
    n, addr, w, val, exp = sample[sig]
    say("  VIOLATION w=%d x%d  first at insn %d addr 0x%x  recorded 0x%x "
        "last-stored 0x%x" % (sig[0], c, n, addr, val, exp))
