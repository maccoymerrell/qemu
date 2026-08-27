#!/usr/bin/env bash
# plugin_abi_gate.sh — every emulator in a build tree must still ACCEPT the
# plugin that tree just built.
#
# Usage: plugin_abi_gate.sh <build-dir> [<plugin.so>] [<results-file>]
#
# WHY THIS EXISTS.  `ninja contrib-plugins` builds the plugin and nothing
# else.  When a plugin API change moves QEMU_PLUGIN_VERSION, the freshly
# built plugin declares the NEW version and every emulator binary still
# sitting in build/ from before the change declares the old one -- so QEMU
# refuses to load the plugin, with a message nobody was looking at.  Two
# commits shipped that way (API v25 against v24 binaries) and no gate saw
# it, because the smoke path only ever exercised the four user targets that
# happened to have been rebuilt.
#
# WHAT IT ACTUALLY TESTS, and it is the load itself rather than a version
# number read off a shelf: each emulator is asked to load the plugin with
# one deliberately invalid plugin argument.  Three outcomes, and only one
# of them passes:
#
#   the plugin INSTALLED and rejected the argument   -> PASS.  Positive
#       evidence: install ran, so the binary accepted the ABI.  The
#       champsim_tracer banner on stderr is that evidence.
#   QEMU refused the plugin                          -> FAIL, with the
#       refusal quoted: a version floor/ceiling ("plugin requires API
#       version N"), or a missing entry point ("undefined symbol"), which
#       is the same staleness one API generation further back.
#   neither                                          -> FAIL.  The probe
#       could not find its subject and a check that cannot find its
#       subject must fail, never pass.
#
# The emulator list comes from the per-target *_tls_guard.ok markers meson
# emits, so it is the set of targets THIS build configured -- not a glob
# over build/, which also matches qemu-img and hand-copied binaries.  Zero
# markers is a failure for the same reason as above.
set -u
build=${1:?usage: plugin_abi_gate.sh <build-dir> [plugin.so] [results-file]}
plugin=${2:-$build/contrib/plugins/libchampsim_tracer.so}
results=${3:-}

if [ ! -f "$plugin" ]; then
    echo "plugin_abi_gate: FAIL — no plugin at $plugin"
    exit 1
fi

markers=$(cd "$build" && ls -1 ./*_tls_guard.ok 2>/dev/null)
if [ -z "$markers" ]; then
    echo "plugin_abi_gate: FAIL — no *_tls_guard.ok markers in $build, so the"
    echo "  emulator set cannot be established.  A check that cannot find its"
    echo "  subject fails."
    exit 1
fi

rows=0 bad=0
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
[ -n "$results" ] && : > "$results"

for m in $markers; do
    exe=${m%_tls_guard.ok}; exe=${exe#./}
    bin="$build/$exe"
    [ -x "$bin" ] || continue
    # linux-user parses its argv before loading plugins and needs a program
    # name to get that far, so it is given one that does not exist: the load
    # is what is being tested and the guest never has to run.  softmmu is
    # given the null machine, which never starts either.
    case "$exe" in
        qemu-system-*) extra="-M none -display none -nodefaults" ;;
        *)             extra="$tmp/no-such-guest-binary" ;;
    esac
    # shellcheck disable=SC2086
    timeout 60 "$bin" -plugin "$plugin,__abi_gate_probe__=1" $extra \
        > "$tmp/out" 2> "$tmp/err"
    rc=$?
    rows=$((rows + 1))
    verdict=UNKNOWN
    detail=""
    if grep -q "plugin requires API version" "$tmp/err"; then
        verdict=STALE_VERSION
        detail=$(grep -m1 "plugin requires API version" "$tmp/err")
    elif grep -q "undefined symbol" "$tmp/err"; then
        verdict=STALE_SYMBOL
        detail=$(grep -m1 "undefined symbol" "$tmp/err")
    elif grep -q "champsim_tracer" "$tmp/err"; then
        verdict=OK
        detail="plugin installed (ABI accepted)"
    fi
    [ "$verdict" = OK ] || bad=$((bad + 1))
    line="$exe verdict=$verdict rc=$rc :: $detail"
    echo "$line"
    [ -n "$results" ] && echo "$line" >> "$results"
done

echo "plugin_abi_gate: $rows emulators probed, $bad refused"
if [ "$rows" -eq 0 ] || [ "$bad" -ne 0 ]; then
    echo "plugin_abi_gate: FAIL — rebuild the emulators (a plain"
    echo "  \`ninja contrib-plugins\` does not), then re-run."
    exit 1
fi
echo "plugin_abi_gate: PASS — every emulator in $build accepts the plugin"
