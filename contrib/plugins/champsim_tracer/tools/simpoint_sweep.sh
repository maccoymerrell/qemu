#!/usr/bin/env bash
#
# End-to-end SimPoint sweep: BBV -> SimPoint clustering -> CST tracing
# (CP-only and CP+WP+regdata+memdata) -> cst_visualize plots.
#
# Usage:
#   simpoint_sweep.sh --name SLUG --bin PATH [flags] -- arg1 arg2 ...
#
# Anything after `--` is forwarded verbatim as guest argv.  Numeric
# flags accept k/M/B/G suffixes (e.g. --bbv-interval 100M).
#
# Required:
#   --name SLUG              output-dir slug (filenames use this)
#   --bin PATH               guest binary
#   --qemu-build DIR         QEMU build directory.  Expected layout:
#                              DIR/qemu-<ISA>
#                              DIR/contrib/plugins/libbbv.so
#                              DIR/contrib/plugins/libchampsim_tracer.so
#                              DIR/contrib/plugins/cst_visualize
#   --simpoint PATH          path to the SimPoint clustering binary
#   --isa ISA                guest ISA: x86_64 | aarch64 | riscv64 | mipsel
#                            (selects which qemu-<ISA> binary to use;
#                            must match what the guest binary is built for)
#
# Optional:
#   --cwd DIR                guest working directory (default: $PWD)
#   --out-dir DIR            sweep output dir
#                            (default: $OUT_BASE/$SLUG, where
#                            OUT_BASE defaults to $PWD/sweeps)
#   --bbv-interval N         instructions per BBV interval & simpoint
#                            cluster width (default 100M)
#   --sim-insns N            insns to trace AT each simpoint
#                            (default 100M)
#   --warmup-insns N         insns to trace BEFORE each simpoint
#                            (default 300M)
#   --maxk N                 simpoint -maxK ceiling (default 10)
#   --rob-size N             cst_visualize --rob-size for ilp/dep_depth
#                            (default 1024)
#
# Output tree (under --out-dir):
#   bbv/             basic-block vectors from libbbv
#   simpoints/       .simpoints + .weights from simpoint
#   traces_cp/       CST traces (CP only, no regdata/memdata)
#   traces_full/     CST traces (CP+WP+regdata+memdata)
#   plots/           SVGs per trace per metric
#   logs/            per-stage stdout+stderr
#   progress.log     overall timeline
#
# Existing outputs are reused; rerun is incremental.  Force a full
# rebuild with FORCE=1.

set -euo pipefail
set -o errtrace

# --- Tool paths (set from --qemu-build / --simpoint / --isa) ------

QEMU_BUILD=
SIMPOINT=
ISA=
# Set of supported guest ISAs.  Each must have a matching
# qemu-<ISA> binary in QEMU_BUILD and be handled by the
# champsim_tracer plugin.
SUPPORTED_ISAS="x86_64 aarch64 riscv64 mipsel"
# Filled in by main() once the above are known.
QEMU_BIN=
PLUGIN_BBV=
PLUGIN_CST=
CST_VISUALIZE=

OUT_BASE=${OUT_BASE:-$PWD/sweeps}

# --- Defaults ------------------------------------------------------

# All values are settable via CLI flags.  Defaults are tuned for a
# SPEC-scale workload; small workloads need explicit smaller intervals.
WORKLOAD_NAME=
WORKLOAD_BIN=
WORKLOAD_ARGV=()
WORKLOAD_CWD=
OUT_DIR_OVERRIDE=
BBV_INTERVAL=100000000   # 100M
SIM_INSNS=100000000      # 100M
WARMUP_INSNS=300000000   # 300M
SIMPOINT_MAXK=10
ROB_SIZE=1024

# Parse "100M" / "1B" / "2G" / "500k" suffixes into raw integer
# instructions.  Bare digits pass through unchanged.
parse_count() {
    local v=$1
    if [[ "$v" =~ ^([0-9]+)([kKmMbBgG]?)$ ]]; then
        local n=${BASH_REMATCH[1]}
        local s=${BASH_REMATCH[2]}
        case "$s" in
        k|K) echo $((n * 1000)) ;;
        m|M) echo $((n * 1000000)) ;;
        b|B|g|G) echo $((n * 1000000000)) ;;
        *) echo "$n" ;;
        esac
    else
        echo "bad count: $v (want digits, optional k/M/B suffix)" >&2
        exit 1
    fi
}

# --- Helpers -------------------------------------------------------

log_progress() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    # Write to stderr so $(stage_bbv) captures only the file path.
    # Also append a copy to the progress log for offline review.
    local line="[$ts] $*"
    echo "$line" >&2
    echo "$line" >>"$PROGRESS_LOG"
}

need_file() {
    if [[ ! -e "$1" ]]; then
        echo "missing prerequisite: $1" >&2
        exit 1
    fi
}

# Stage skip predicate: outputs exist AND non-empty AND FORCE not set.
stage_done() {
    [[ -z "${FORCE:-}" && -s "$1" ]]
}

# --- Stages --------------------------------------------------------

stage_bbv() {
    local out_bb=${BBV_DIR}/${WORKLOAD_NAME}.0.bb
    if stage_done "$out_bb"; then
        log_progress "bbv: reuse ${out_bb}"
        echo "$out_bb"
        return 0
    fi
    log_progress "bbv: running qemu+libbbv (interval=${BBV_INTERVAL})"
    mkdir -p "$BBV_DIR"
    # cd into guest CWD so guest-relative argv (e.g. inp.in) resolves.
    (
        cd "$WORKLOAD_CWD"
        "$QEMU_BIN" \
            -plugin "${PLUGIN_BBV},interval=${BBV_INTERVAL},outfile=${BBV_DIR}/${WORKLOAD_NAME}" \
            -d plugin \
            -- "$WORKLOAD_BIN" "${WORKLOAD_ARGV[@]}"
    ) >"${LOGS_DIR}/bbv.log" 2>&1
    need_file "$out_bb"
    log_progress "bbv: $(wc -l <"$out_bb") intervals captured"
    echo "$out_bb"
}

stage_simpoint() {
    local bb_file=$1
    local sp_out=${SP_DIR}/${WORKLOAD_NAME}.simpoints
    local w_out=${SP_DIR}/${WORKLOAD_NAME}.weights
    if stage_done "$sp_out" && stage_done "$w_out"; then
        log_progress "simpoint: reuse ${sp_out}"
        return 0
    fi
    log_progress "simpoint: clustering (maxK=${SIMPOINT_MAXK})"
    mkdir -p "$SP_DIR"
    "$SIMPOINT" \
        -loadFVFile "$bb_file" \
        -maxK "$SIMPOINT_MAXK" \
        -saveSimpoints "$sp_out" \
        -saveSimpointWeights "$w_out" \
        >"${LOGS_DIR}/simpoint.log" 2>&1
    need_file "$sp_out"
    need_file "$w_out"
    log_progress "simpoint: chose $(wc -l <"$sp_out") simpoints"
}

# Run the champsim_tracer with a given variant config (CP only vs full).
#   $1  variant tag (cp | full)
#   $2  output dir
#   $3+ extra k=v plugin options
stage_trace() {
    local variant=$1
    local out_dir=$2
    shift 2
    local extra_opts=("$@")
    local outbase=${out_dir}/${WORKLOAD_NAME}_${variant}.cst
    # Trace files are named <base>-<NNNB>.cst (one per simpoint).
    # Reuse if any matching file already exists.
    local existing
    existing=$(compgen -G "${out_dir}/${WORKLOAD_NAME}_${variant}-*.cst" || true)
    if [[ -z "${FORCE:-}" && -n "$existing" ]]; then
        log_progress "trace[$variant]: reuse $(echo "$existing" | wc -l) traces"
        return 0
    fi
    log_progress "trace[$variant]: running champsim_tracer"
    mkdir -p "$out_dir"
    # Wipe any prior simpoint-named traces in this dir — a rerun with
    # a re-clustered simpoints file may choose different intervals, so
    # stale files from a previous run must not stick around.
    rm -f "${out_dir}/${WORKLOAD_NAME}_${variant}-"*.cst \
          "${out_dir}/${WORKLOAD_NAME}_${variant}.cst.unknown_warnings.log"
    local opts="outfile=${outbase}"
    opts+=",trace_window=simpoint:file=${SP_DIR}/${WORKLOAD_NAME}.simpoints"
    opts+="+interval=${BBV_INTERVAL}+simulation=${SIM_INSNS}+warmup=${WARMUP_INSNS}"
    for kv in "${extra_opts[@]}"; do
        opts+=",${kv}"
    done
    (
        cd "$WORKLOAD_CWD"
        "$QEMU_BIN" \
            -plugin "${PLUGIN_CST},${opts}" \
            -d plugin \
            -- "$WORKLOAD_BIN" "${WORKLOAD_ARGV[@]}"
    ) >"${LOGS_DIR}/trace_${variant}.log" 2>&1 || {
        # The plugin calls exit(0) on simpoint exhaustion which is not
        # an error; but qemu may also propagate the guest's own exit.
        # Treat any non-zero status as failure only if no traces landed.
        existing=$(compgen -G "${out_dir}/${WORKLOAD_NAME}_${variant}-*.cst" || true)
        if [[ -z "$existing" ]]; then
            echo "trace[$variant] failed; see ${LOGS_DIR}/trace_${variant}.log" >&2
            exit 1
        fi
    }
    local n
    n=$(compgen -G "${out_dir}/${WORKLOAD_NAME}_${variant}-*.cst" | wc -l)
    log_progress "trace[$variant]: produced ${n} traces"
}

# Plot a single .cst with a metric -> SVG.
plot_one() {
    local cst=$1
    local metric=$2
    local extra=("${@:3}")
    local base
    base=$(basename "$cst" .cst)
    local svg=${PLOTS_DIR}/${base}__${metric}.svg
    if stage_done "$svg"; then return 0; fi
    "$CST_VISUALIZE" -m "$metric" "--rob-size=${ROB_SIZE}" \
        "${extra[@]}" -o "$svg" "$cst" \
        >>"${LOGS_DIR}/plot.log" 2>&1 || {
        echo "    plot $metric failed for $base (see plot.log)" \
            >>"$PROGRESS_LOG"
        rm -f "$svg"
        return 0
    }
}

stage_plot() {
    log_progress "plot: rendering SVGs"
    mkdir -p "$PLOTS_DIR"
    : >"${LOGS_DIR}/plot.log"

    # Metrics computable from a CP-only trace.  memdata gates the load/
    # store *values*, but addresses are always emitted, so the
    # address-driven metrics (mem_pat / cache_miss / working_set /
    # reuse_distance) work on CP traces too — only the WP metrics need a
    # full (wp=1) trace.  On a CP trace the WP/“corrupted” second pane of
    # the dual-pane metrics is simply empty, same as branch_mpki/btb_miss.
    local cp_metrics=(
        branch_mpki btb_miss bb_length indirect_targets
        branch_entropy dep_depth ilp gen_op gen_reg branch_dir
        mem_pat cache_miss working_set reuse_distance
    )
    # Metrics that genuinely need wrong-path data — only on the full trace.
    local full_extra=(
        wp_insns wp_memops wp_divergence
    )

    local cst
    for cst in "${TR_CP_DIR}/${WORKLOAD_NAME}_cp-"*.cst; do
        [[ -e "$cst" ]] || continue
        for m in "${cp_metrics[@]}"; do
            plot_one "$cst" "$m"
        done
    done

    for cst in "${TR_FULL_DIR}/${WORKLOAD_NAME}_full-"*.cst; do
        [[ -e "$cst" ]] || continue
        for m in "${cp_metrics[@]}" "${full_extra[@]}"; do
            plot_one "$cst" "$m"
        done
    done

    local n
    n=$(compgen -G "${PLOTS_DIR}/*.svg" | wc -l)
    log_progress "plot: produced ${n} SVGs"
}

# --- Driver --------------------------------------------------------

usage() {
    sed -n '2,/^$/{/^#/{s/^# \{0,1\}//;p}}' "$0" >&2
    exit "${1:-1}"
}

main() {
    while (( $# > 0 )); do
        case "$1" in
        --name)           WORKLOAD_NAME=$2; shift 2 ;;
        --bin)            WORKLOAD_BIN=$2; shift 2 ;;
        --cwd)            WORKLOAD_CWD=$2; shift 2 ;;
        --qemu-build)     QEMU_BUILD=$2; shift 2 ;;
        --simpoint)       SIMPOINT=$2; shift 2 ;;
        --isa)            ISA=$2; shift 2 ;;
        --out-dir)        OUT_DIR_OVERRIDE=$2; shift 2 ;;
        --bbv-interval)   BBV_INTERVAL=$(parse_count "$2"); shift 2 ;;
        --sim-insns)      SIM_INSNS=$(parse_count "$2"); shift 2 ;;
        --warmup-insns)   WARMUP_INSNS=$(parse_count "$2"); shift 2 ;;
        --maxk)           SIMPOINT_MAXK=$2; shift 2 ;;
        --rob-size)       ROB_SIZE=$2; shift 2 ;;
        --help|-h)        usage 0 ;;
        --)
            shift
            WORKLOAD_ARGV=("$@")
            break
            ;;
        *)
            echo "unknown flag: $1" >&2
            usage 1
            ;;
        esac
    done

    WORKLOAD_CWD=${WORKLOAD_CWD:-$PWD}

    if [[ -z "$WORKLOAD_NAME" ]]; then
        echo "missing --name" >&2; exit 1
    fi
    if [[ -z "$WORKLOAD_BIN" ]]; then
        echo "missing --bin" >&2; exit 1
    fi
    if [[ -z "$QEMU_BUILD" ]]; then
        echo "missing --qemu-build" >&2; exit 1
    fi
    if [[ -z "$SIMPOINT" ]]; then
        echo "missing --simpoint" >&2; exit 1
    fi
    if [[ -z "$ISA" ]]; then
        echo "missing --isa (one of: $SUPPORTED_ISAS)" >&2; exit 1
    fi
    # Validate ISA against the supported set via word-boundary match.
    case " $SUPPORTED_ISAS " in
    *" $ISA "*) ;;
    *)
        echo "unsupported --isa $ISA (want one of: $SUPPORTED_ISAS)" >&2
        exit 1
        ;;
    esac

    # Derive tool paths from --qemu-build / --isa.
    QEMU_BIN=${QEMU_BUILD}/qemu-${ISA}
    PLUGIN_BBV=${QEMU_BUILD}/contrib/plugins/libbbv.so
    PLUGIN_CST=${QEMU_BUILD}/contrib/plugins/libchampsim_tracer.so
    CST_VISUALIZE=${QEMU_BUILD}/contrib/plugins/cst_visualize

    OUT_DIR=${OUT_DIR_OVERRIDE:-${OUT_BASE}/${WORKLOAD_NAME}}
    BBV_DIR=${OUT_DIR}/bbv
    SP_DIR=${OUT_DIR}/simpoints
    TR_CP_DIR=${OUT_DIR}/traces_cp
    TR_FULL_DIR=${OUT_DIR}/traces_full
    PLOTS_DIR=${OUT_DIR}/plots
    LOGS_DIR=${OUT_DIR}/logs
    PROGRESS_LOG=${OUT_DIR}/progress.log
    mkdir -p "$OUT_DIR" "$LOGS_DIR"

    # Sanity-check prerequisites once, up front.
    need_file "$QEMU_BIN"
    need_file "$PLUGIN_BBV"
    need_file "$PLUGIN_CST"
    need_file "$CST_VISUALIZE"
    need_file "$SIMPOINT"
    need_file "$WORKLOAD_BIN"
    [[ -d "$WORKLOAD_CWD" ]] || { echo "no cwd: $WORKLOAD_CWD" >&2; exit 1; }

    log_progress "=== sweep start: name=${WORKLOAD_NAME}"
    log_progress "    binary=${WORKLOAD_BIN}"
    log_progress "    cwd=${WORKLOAD_CWD}"
    log_progress "    argv=(${WORKLOAD_ARGV[*]})"
    log_progress "    bbv_interval=${BBV_INTERVAL} sim=${SIM_INSNS} warmup=${WARMUP_INSNS}"
    log_progress "    maxK=${SIMPOINT_MAXK} rob_size=${ROB_SIZE}"

    local bb_file
    bb_file=$(stage_bbv)
    stage_simpoint "$bb_file"

    # Both variants pipe each tarball member (body, header) through
    # multi-threaded xz.  -T 0 = use every available core for that
    # compressor invocation; members compress serially but each gets
    # the whole CPU.
    local COMPRESS="compress=xz -T 0"

    # CP-only: no WP, no regdata, no memdata.
    stage_trace cp  "$TR_CP_DIR"  \
        "wp=0" "memdata=0" "regdata=0" "$COMPRESS"

    # Full: WP on for both reads & writes, regdata+memdata on both
    # CP and WP sides.
    stage_trace full "$TR_FULL_DIR" \
        "wp=1" "memdata=1" "regdata=1" \
        "wp_memdata=1" "wp_regdata=1" "$COMPRESS"

    stage_plot
    log_progress "=== sweep done"
}

main "$@"
