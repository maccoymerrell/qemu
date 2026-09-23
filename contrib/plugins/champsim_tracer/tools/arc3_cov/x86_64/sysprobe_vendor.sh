#!/bin/bash
# ARC 3 -- the CPU-VENDOR arm of the CPL0 reachability probe.
#
# usage: sysprobe_vendor.sh <evidence-dir>
# writes <evidence-dir>/cpl0_vendor.tsv   hex -> vector under each vendor
#
# WHY THERE IS A SECOND CPL0 ARM AT ALL.
#
# Every other reachability leg in this corpus runs `-cpu max`, and QEMU's
# max_x86_cpu_initfn sets that model's vendor to AMD.  decode-new.c.inc gates a
# small set of entries on `chk(i64_amd)`, which in 64-bit mode refuses the
# instruction unless env->cpuid_vendor1 is Intel's.  Those rows therefore take
# #UD in every leg this corpus runs -- and an #UD produced by a VENDOR TEST is
# not the same fact as an #UD produced by an absent table entry.  The purpose
# statement is that every instruction REACHABLE IN QEMU is classified, and the
# standing per-model ruling says a difference between CPU models is a fact
# about QEMU's modelling, not about tracer scope.  So the honest measurement
# is the same encodings under a model whose vendor is Intel, and that is this.
#
# THE SUBJECT SET IS DERIVED FROM THE TREE, NEVER WRITTEN DOWN.  The arm probes
# exactly the entries that carry i64_amd in decode-new.c.inc as it stands; if
# that set is empty the arm has lost its subject and REFUSES rather than
# reporting a clean run over nothing.
#
# BOTH DIRECTIONS ARE CONTROLLED.  Two encodings that carry no vendor gate ride
# along: `0f 0b` (UD2), which must take #UD under both vendors, and `0f 31`
# (RDTSC), which must run under both.  A control that MOVES means the two arms
# differ for some reason other than the vendor and the measurement says nothing
# about i64_amd; a subject that does NOT move means this arm is inert.  Either
# is fatal here.
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}

V="$E/vendor"
rm -rf "$V"; mkdir -p "$V/amd" "$V/intel"

$PY - "$Q/target/i386/tcg/decode-new.c.inc" "$V/subjects.txt" <<'EOF' || exit 2
import re
import sys

src, out = open(sys.argv[1]).read(), sys.argv[2]


def table(decl):
    i = src.index('static const X86OpEntry %s = {' % decl)
    return src[i:src.index('\n};', i)]


subj = []
for decl, prefix in (('opcodes_root[256]', ''), ('opcodes_0F[256]', '0f')):
    for m in re.finditer(r'^\s*\[(0x[0-9a-fA-F]+)\]\s*=\s*([^\n]*)$',
                         table(decl), re.M):
        if 'i64_amd' in m.group(2):
            subj.append(prefix + '%02x' % int(m.group(1), 16))
if not subj:
    sys.exit('sysprobe_vendor: no decode-new.c.inc entry carries i64_amd any '
             'more.  This arm exists to measure exactly those rows, and a '
             'clean run over an empty subject set is not a measurement -- '
             'REFUSING')
open(out, 'w').write('\n'.join(subj) + '\n')
print('vendor-arm subjects derived from the tree: %s' % ' '.join(subj))
EOF

# The controls carry no vendor gate and must read the same under both arms.
CTL_UD=0f0b          # UD2      -- #UD (vector 6) under either vendor
CTL_RUN=0f31         # RDTSC    -- runs (255) under either vendor
{ cat "$V/subjects.txt"; printf '%s\n%s\n' "$CTL_UD" "$CTL_RUN"; } \
    | sort -u > "$V/amd/reach_in.hex"
cp "$V/amd/reach_in.hex" "$V/intel/reach_in.hex"

"$T"/sysprobe_run.sh "$V/amd"   max                      > "$V/amd.log"   2>&1
amd_rc=$?
"$T"/sysprobe_run.sh "$V/intel" "max,vendor=GenuineIntel" > "$V/intel.log" 2>&1
int_rc=$?
[ $amd_rc = 0 ] && [ $int_rc = 0 ] || {
  echo "sysprobe_vendor: an arm did not complete (amd rc=$amd_rc intel" >&2
  echo "  rc=$int_rc); see $V/amd.log and $V/intel.log" >&2; exit 2; }

$PY - "$V" "$E/cpl0_vendor.tsv" "$CTL_UD" "$CTL_RUN" <<'EOF'
import csv
import os
import sys

v, out, ctl_ud, ctl_run = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
subj = [L.strip() for L in open(os.path.join(v, 'subjects.txt')) if L.strip()]


def vecs(arm):
    p = os.path.join(v, arm, 'cpl0.tsv')
    if not os.path.exists(p):
        sys.exit('sysprobe_vendor: %s has no cpl0.tsv -- REFUSING' % arm)
    return {r['hex']: int(r['cpl0_vec'])
            for r in csv.DictReader(open(p), delimiter='\t')}


amd, intel = vecs('amd'), vecs('intel')
rows, moved, bad = [], 0, []
for h in sorted(set(amd) | set(intel)):
    a, i = amd.get(h), intel.get(h)
    if a is None or i is None:
        bad.append('%s was measured under only one vendor (amd=%s intel=%s)'
                   % (h, a, i))
        continue
    role = 'SUBJECT' if h in subj else 'CONTROL'
    mv = int(a != i)
    if role == 'SUBJECT':
        moved += mv
        if mv and a != 6:
            bad.append('%s moved but its AMD-vendor vector is %d, not the #UD '
                       'the vendor test produces' % (h, a))
    elif mv:
        bad.append('CONTROL %s MOVED (amd=%d intel=%d): the two arms differ '
                   'for some reason other than the vendor, so nothing here '
                   'measures i64_amd' % (h, a, i))
    rows.append((h, str(a), str(i), role, str(mv)))

if not subj:
    bad.append('the subject list is empty')
elif not moved:
    bad.append('NO SUBJECT MOVED: every i64_amd row reads the same vector '
               'under both vendors, so this arm is INERT and its zero proves '
               'nothing about the vendor gate')
for h in (ctl_ud, ctl_run):
    if h not in amd:
        bad.append('control %s produced no row' % h)
if amd.get(ctl_ud) != 6:
    bad.append('control %s (UD2) read vector %s, not 6' % (ctl_ud,
                                                           amd.get(ctl_ud)))
if amd.get(ctl_run) != 255:
    bad.append('control %s (RDTSC) read vector %s, not 255 (ran)'
               % (ctl_run, amd.get(ctl_run)))

with open(out, 'w') as f:
    f.write('hex\tvec_amd\tvec_intel\trole\tmoved\n')
    for r in rows:
        f.write('\t'.join(r) + '\n')
for r in rows:
    print('  %-14s amd=%-4s intel=%-4s %-8s moved=%s' % r)
print('vendor arm: %d subject(s), %d moved, %d control(s) all steady'
      % (len(subj), moved, len(rows) - len(subj)))
if bad:
    sys.exit('sysprobe_vendor REFUSED:\n  ' + '\n  '.join(bad))
EOF
