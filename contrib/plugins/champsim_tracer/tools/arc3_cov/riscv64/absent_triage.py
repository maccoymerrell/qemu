#!/usr/bin/env python3
"""Ask, of every encoding the wire did NOT return, whether QEMU ran it.

WHY THIS EXISTS.  The exercise pass credits a decode ROW when any one of its
encodings comes back off the wire, and 803 of 803 reachable rows did.  431
individual encodings did not, and "every row is covered" would be a silent
false success if some of those 431 are encodings QEMU EXECUTES and the plugin
DROPS -- which is precisely the hole the whole coverage pass exists to find.

The discriminator is the bare prober: the same guest, the same bytes, no
plugin attached.  If QEMU refuses the encoding (SIGILL) then the operand
values this generator chose made it illegal -- a fact about the generator's
value banks, not about the tracer -- and its absence from the wire is
correct.  If QEMU RUNS it and the wire has no line for the probe address,
that is a tracer defect and it is reported by name.

Author: Maccoy Merrell.
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import qemu_reach_probe as probe                            # noqa: E402

_ap = argparse.ArgumentParser(description=__doc__)
_ap.add_argument("--qemu", required=True)
_ap.add_argument("--cst-decode", required=True)
_ap.add_argument("--dir", required=True,
                 help="the exercise run directory: holds corpus_riscv64_rows"
                      ".tsv and cells/")
_ap.add_argument("--jobs", type=int, default=12)
_ap.add_argument("--timeout", type=float, default=25.0)
_args = _ap.parse_args()

QEMU = _args.qemu
CST_DECODE = _args.cst_decode
D = _args.dir
probe.ELF_DIR = os.path.join(D, "triage_elfs")

arm_of = {"plain": 0}
for i, a in enumerate(probe.VSETVLI_ARMS):
    arm_of["vsetvli%d" % i] = a

jobs = []
with open(os.path.join(D, "corpus_riscv64_rows.tsv"), "rt") as fh:
    for line in fh:
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 7 or f[6] == "EXERCISED":
            continue
        name, fn, ln, aname, enc, verd = f[0], f[1], f[2], f[4], f[5], f[6]
        width = 16 if len(enc) == 4 else 32
        jobs.append((name, fn, ln, aname, enc, verd, width,
                     arm_of.get(aname, 0), int(enc, 16)))

if not jobs:
    sys.exit("REFUSING: no non-EXERCISED encodings found -- this triage has no "
             "subject, which is not the same as there being nothing wrong")


def run(j):
    (name, fn, ln, aname, enc, verd, width, arm, word) = j
    rc = probe.run_probe((QEMU, word, width, arm, _args.timeout))
    return (name, fn, ln, aname, enc, verd, rc, probe.verdict(rc))


rows = []
with concurrent.futures.ThreadPoolExecutor(max_workers=_args.jobs) as ex:
    for r in ex.map(run, jobs):
        rows.append(r)

# THE CONTROL: an encoding everyone agrees runs must come back RAN here, or
# this triage cannot separate "QEMU refused it" from "the probe frame broke".
ctl = probe.verdict(probe.run_probe((QEMU, probe.addi(10, 10, 1), 32, 0, _args.timeout)))
print("triage control (addi a0,a0,1): %s" % ctl)
if ctl != "RAN":
    sys.exit("REFUSING: the triage frame cannot run a legal encoding")

#: DECODED IS NOT RETIRED, AND THE FIRST VERSION OF THIS FILE CONFLATED THEM.
#: The prober's "RAN" means QEMU got far enough to decode the encoding and
#: compute its effects -- a SIGSEGV counts, because the address it failed on
#: had to be computed first.  The WIRE carries RETIRED instructions.  An
#: encoding that faults has decoded and has not retired, and its absence from
#: the trace is the contract, not a hole.
#:
#: The two are separated by MEASUREMENT rather than by that paragraph: the
#: probe sits at a known address with a run of `c.nop` in front of it, so if
#: the tracer followed the guest right up to the halfword BEFORE the probe and
#: stopped there, the tracer was not blind -- the instruction did not complete.
#: A row whose trace stops EARLIER than that is a different animal and is
#: reported as one.
LAST_BEFORE_PROBE = probe.BASE + probe.OFF_PROBE - 2


def wire_tail(name, fn, ln, enc):
    cell = os.path.join(D, "cells", "%s_%s_%s_%s"
                        % (name, fn.replace(".decode", ""), ln, enc))
    trace = None
    try:
        for c in os.listdir(cell):
            if c.startswith("t.cst"):
                trace = os.path.join(cell, c)
                break
    except OSError:
        return None
    if trace is None:
        return None
    try:
        out = subprocess.run(
            [CST_DECODE, trace],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    except Exception:
        return None
    last = None
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("0x"):
            try:
                last = int(line.split(":")[0], 16)
            except ValueError:
                pass
    return last


out = os.path.join(D, "absent_triage.tsv")
n_ill = n_ran = n_to = 0
adjudicated = []
with open(out, "wt") as fh:
    fh.write("#name\tfile\tline\tarm\tencoding\twire\tprobe_rc\tprobe\tclass\n")
    for (name, fn, ln, aname, enc, verd, rc, pv) in sorted(rows):
        if pv == "SIGILL":
            n_ill += 1
            cls = "REFUSED-AT-THESE-OPERANDS"
        elif pv == "TIMEOUT":
            n_to += 1
            cls = "GUEST-DOES-NOT-TERMINATE"
        else:
            n_ran += 1
            tail = wire_tail(name, fn, ln, enc)
            if tail == LAST_BEFORE_PROBE:
                cls = "DECODED-BUT-DID-NOT-RETIRE"
            elif tail is None:
                cls = "NO-TRACE-TO-READ"
            else:
                cls = "WIRE-STOPS-EARLY-0x%x" % tail
            adjudicated.append((name, fn, ln, enc, rc, cls, tail))
        fh.write("%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n"
                 % (name, fn, ln, aname, enc, verd, rc, pv, cls))

print("encodings absent from the wire: %d" % len(rows))
print("  QEMU REFUSED at these operands (SIGILL): %d  -- generator value banks"
      % n_ill)
print("  guest does not terminate (TIMEOUT)     : %d  -- no trace is written"
      % n_to)
print("  QEMU decoded them, wire has no line    : %d  -- adjudicated below"
      % n_ran)
n_ok = sum(1 for a in adjudicated if a[5] == "DECODED-BUT-DID-NOT-RETIRE")
for (name, fn, ln, enc, rc, cls, tail) in adjudicated:
    print("    %-26s %-12s %s:%s  %s  rc=%d  wire ends 0x%x"
          % (cls, name, fn, ln, enc, rc, tail or 0))
print("  of those, tracer followed the guest to the instruction before the "
      "probe and stopped: %d of %d" % (n_ok, len(adjudicated)))
if n_ok != len(adjudicated):
    print("  REMAINDER IS A TRACER QUESTION, NOT AN ARTEFACT -- see the rows "
          "above whose wire stops early")
print("wrote %s" % out)
