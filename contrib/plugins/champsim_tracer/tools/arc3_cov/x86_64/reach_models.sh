#!/bin/bash
# ARC 3 -- reachability across EVERY QEMU x86_64 CPU model, and with EVERY
# CPUID flag forced on.
#
# usage: reach_models.sh <evidence-dir>
# reads  <evidence-dir>/reach_in.hex and <evidence-dir>/reach_probe
# writes r_max_postfix.tsv, r_maxall_postfix.tsv, model_matrix.tsv,
#        illopc.tsv, cpuid/<model>.tsv
#
# "-cpu max cannot execute it" is NOT "no QEMU CPU model can execute it", and
# the difference is the maintainer's question: a model that advertises the
# feature is a model the row belongs PROBED under.  So every 64-bit-capable
# model in `-cpu help` gets the whole encoding set, and the per-encoding
# signal is compared ACROSS models -- one model differing from the rest is a
# finding, not a footnote.  Then every CPUID flag QEMU recognises is forced on
# at once, which is the strongest configuration a TCG guest can be given.
#
# The last leg is the one that says WHERE QEMU refused.  gen_unknown_opcode()
# in target/i386/tcg/translate.c logs "ILLOPC" under -d unimp and is reached
# only when the decode tables have no entry at all; its ABSENCE means QEMU
# decoded something and refused it later -- a feature gate, an i64 check, a
# CPL check, an operand form -- or ran it.  One process per encoding, because
# a batched log cannot be attributed to the encoding that produced it.
set -u
E="$(cd "$1" && pwd)"
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}
U=$Q/build/qemu-x86_64
cd "$E"
[ -f reach_in.hex ] || { echo "no reach_in.hex in $E"; exit 2; }
gcc -O0 -Wall -static -o reach_probe "$T"/reach_probe.c || exit 2
gcc -O2 -static -o cpuiddump "$T"/cpuiddump.c || exit 2

"$U" -cpu max ./reach_probe < reach_in.hex > r_max_postfix.tsv || exit 2

$U -cpu help 2>&1 | sed -n '/^Available CPUs:/,/^$/p' | tail -n +2 \
    | awk '{print $1}' | grep -v '^$' | sort -u > models.txt
$U -cpu help 2>&1 | sed -n '/^Recognized CPUID flags:/,$p' | tail -n +2 \
    | tr ' ' '\n' | grep -v '^$' | sort -u > flags.all

rm -rf permodel cpuid; mkdir -p permodel cpuid
: > models.64.txt; : > models.no64.txt
while read -r m; do
    # A model that cannot enter long mode is not a configuration this ISA can
    # be reached under, and it says so itself.
    if $U -cpu "$m" ./reach_probe < reach_in.hex > permodel/"$m".tsv 2>/dev/null
    then
        echo "$m" >> models.64.txt
        $U -cpu "$m" ./cpuiddump > cpuid/"$m".tsv 2>/dev/null
    else
        echo "$m" >> models.no64.txt
        rm -f permodel/"$m".tsv
    fi
done < models.txt
echo "models: $(wc -l < models.64.txt) 64-bit-capable, \
$(wc -l < models.no64.txt) 32-bit-only"

ACC=$(sed 's/^/,+/' flags.all | tr -d '\n')
$U -cpu "max$ACC" ./reach_probe < reach_in.hex > r_maxall_postfix.tsv \
    2> r_maxall_postfix.err || exit 2
$U -cpu "max$ACC" ./cpuiddump > cpuid/__maxallflags.tsv 2>/dev/null
echo "CPUID flags forced: $(wc -l < flags.all), of which TCG refuses \
$(wc -l < r_maxall_postfix.err)"

# ILLOPC, one process per encoding
rm -rf unimp; mkdir -p unimp
cat > .one.sh <<'ONE'
#!/bin/bash
echo "$2" | "$1" -cpu max -d unimp -D unimp/"$2".log ./reach_probe >/dev/null 2>&1
ONE
chmod +x .one.sh
# HOST LOAD CEILING (2026-08-25 ruling): never -P $(nproc).  This host has
# 144 cores and the maintainer can hear it; concurrent agents compose, so
# the default is 12 and CST_JOBS raises it deliberately or not at all.
xargs -P "${CST_JOBS:-12}" -I{} ./.one.sh "$U" {} < reach_in.hex
: > illopc.tsv
while read -r h; do
    if grep -q ILLOPC unimp/"$h".log; then echo -e "$h\t1"; else echo -e "$h\t0"; fi
done < reach_in.hex >> illopc.tsv

${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python} - <<'EOF'
import csv, glob, os, collections, sys
ran, sigs = collections.defaultdict(list), collections.defaultdict(set)
files = sorted(glob.glob('permodel/*.tsv'))
for f in files:
    m = os.path.basename(f)[:-4]
    for r in csv.DictReader(open(f), delimiter='\t'):
        if r['exec'] == 'yes':
            ran[r['hex']].append(m)
        sigs[r['hex']].add(int(r['signal']))
split = [h for h, s in sigs.items() if len(s) > 1]
with open('model_matrix.tsv', 'w') as fh:
    fh.write('hex\tmodels_probed\tmodels_ran\tsignals_seen\n')
    for h in sorted(sigs):
        fh.write('%s\t%d\t%d\t%s\n' % (h, len(files), len(ran.get(h, [])),
                 ','.join(str(x) for x in sorted(sigs[h]))))
print('encodings %d, ran under at least one model: %d, signal differs '
      'between models on: %d %s'
      % (len(sigs), len(ran), len(split), ' '.join(split[:8])))
EOF
