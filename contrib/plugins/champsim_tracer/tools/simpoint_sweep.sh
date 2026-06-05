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
#   --parallel N             max concurrent cst_visualize jobs in the plot
#                            and aggregate stages (default: nproc).  Plotting
#                            is the sweep's wall-clock bottleneck (dozens of
#                            minutes-long renders), so this is the main knob.
#   --stage all|trace|plot   which stages to run (default all).  trace =
#                            BBV+SimPoint+CST tracing (the qemu phase); plot =
#                            per-simpoint plots + whole-program aggregates (the
#                            cst_visualize phase).  Lets an orchestrator run
#                            the qemu phase across sweeps in parallel, then
#                            give each sweep's plot phase the full core budget.
#
# Output tree (under --out-dir):
#   bbv/             basic-block vectors from libbbv
#   simpoints/       .simpoints + .weights from simpoint
#   traces_cp/       CST traces (CP only, no regdata/memdata)
#   traces_full/     CST traces (CP+WP+regdata+memdata)
#   plots/           <slug>_<variant>-<NNNB>__<metric>.svg per simpoint, plus
#                    <slug>_<variant>__AGG__<metric>.svg whole-program aggregates
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
# Max concurrent cst_visualize jobs in the plot / aggregate stages.
# cst_visualize is single-threaded but each run is minutes-long and there
# are dozens (metrics × simpoints), so plotting them serially is the sweep's
# wall-clock bottleneck.  Default to all cores; the orchestrator passes a
# per-sweep budget so the total across sweeps stays bounded.
PARALLEL=$(nproc 2>/dev/null || echo 4)
# Which stages to run: all | trace | plot.  "trace" = bbv+simpoint+trace
# (the qemu phase); "plot" = plot+aggregate (the cst_visualize phase).  Lets
# an orchestrator run the qemu phase across sweeps in parallel, then give
# each sweep's plot phase the full core budget in turn.
STAGE=all

# Which trace variant(s) to produce: cp | full | both (default both).
# Lets an orchestrator drive CP once and full once per wpprune level.
VARIANT_SEL=both
# Wrong-path pruning level for the full variant (empty = unset/0).  When
# set, the full trace gets wpprune=<N>, is tagged full_p<N>, and lands in
# traces_full_p<N>/ — so several prune levels coexist in one sweep dir.
WPPRUNE=

# Metrics computable from a CP-only trace.  memdata gates the load/store
# *values*, but addresses are always emitted, so the address-driven metrics
# (mem_pat / cache_miss / working_set / reuse_distance) work on CP traces
# too — only the WP metrics need a full (wp=1) trace.
CP_METRICS=(
    branch_mpki btb_miss bb_length indirect_targets
    branch_entropy dep_depth ilp gen_op gen_reg branch_dir
    mem_pat cache_miss working_set reuse_distance
)
# Metrics that genuinely need wrong-path data — only on the full trace.
FULL_EXTRA=(
    wp_insns wp_memops wp_divergence
)

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

# Block until fewer than $PARALLEL background jobs are running, so the
# caller can launch the next one.  `wait -n || true` keeps set -e from
# tripping on a plot job's nonzero exit (those are handled in-job).
pool_gate() {
    while (( $(jobs -r | wc -l) >= PARALLEL )); do wait -n 2>/dev/null || true; done
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

# Aggregate every per-simpoint trace of one variant into a single weighted
# whole-program SVG per metric (cst_visualize aggregate mode; weights come
# from each trace's header simpoint_weight).
agg_one() {
    local variant=$1
    local metric=$2
    shift 2
    local csts=("$@")
    local svg=${PLOTS_DIR}/${WORKLOAD_NAME}_${variant}__AGG__${metric}.svg
    if stage_done "$svg"; then return 0; fi
    "$CST_VISUALIZE" -m "$metric" "--rob-size=${ROB_SIZE}" --aggregate \
        --name "${WORKLOAD_NAME}_${variant}" -o "$svg" "${csts[@]}" \
        >>"${LOGS_DIR}/plot.log" 2>&1 || {
        echo "    aggregate $metric failed for ${WORKLOAD_NAME}_${variant}" \
            "(see plot.log)" >>"$PROGRESS_LOG"
        rm -f "$svg"
        return 0
    }
}

# Per-simpoint plots, up to $PARALLEL cst_visualize runs at once.
stage_plot() {
    log_progress "plot: rendering per-simpoint SVGs (parallel=${PARALLEL})"
    mkdir -p "$PLOTS_DIR"
    : >"${LOGS_DIR}/plot.log"

    local cst m
    for cst in "${TR_CP_DIR}/${WORKLOAD_NAME}_cp-"*.cst; do
        [[ -e "$cst" ]] || continue
        for m in "${CP_METRICS[@]}"; do
            pool_gate; plot_one "$cst" "$m" &
        done
    done
    for cst in "${TR_FULL_DIR}/${WORKLOAD_NAME}_full-"*.cst; do
        [[ -e "$cst" ]] || continue
        for m in "${CP_METRICS[@]}" "${FULL_EXTRA[@]}"; do
            pool_gate; plot_one "$cst" "$m" &
        done
    done
    wait

    local n
    n=$(compgen -G "${PLOTS_DIR}/*.svg" | wc -l)
    log_progress "plot: produced ${n} per-simpoint SVGs"
}

# One weighted whole-program SVG per metric per variant, also up to
# $PARALLEL at once.
stage_aggregate() {
    log_progress "aggregate: rendering whole-program SVGs (parallel=${PARALLEL})"
    mkdir -p "$PLOTS_DIR"

    local cp_csts full_csts m
    mapfile -t cp_csts   < <(compgen -G "${TR_CP_DIR}/${WORKLOAD_NAME}_cp-*.cst"     || true)
    mapfile -t full_csts < <(compgen -G "${TR_FULL_DIR}/${WORKLOAD_NAME}_full-*.cst" || true)

    if (( ${#cp_csts[@]} > 0 )); then
        for m in "${CP_METRICS[@]}"; do
            pool_gate; agg_one cp "$m" "${cp_csts[@]}" &
        done
    fi
    if (( ${#full_csts[@]} > 0 )); then
        for m in "${CP_METRICS[@]}" "${FULL_EXTRA[@]}"; do
            pool_gate; agg_one full "$m" "${full_csts[@]}" &
        done
    fi
    wait

    local n
    n=$(compgen -G "${PLOTS_DIR}/${WORKLOAD_NAME}_*__AGG__*.svg" | wc -l)
    log_progress "aggregate: produced ${n} whole-program SVGs"
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
        --parallel)       PARALLEL=$2; shift 2 ;;
        --stage)          STAGE=$2; shift 2 ;;
        --variant)        VARIANT_SEL=$2; shift 2 ;;
        --wpprune)        WPPRUNE=$2; shift 2 ;;
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

    case "$STAGE" in
        all|trace|plot) ;;
        *) echo "bad --stage $STAGE (want: all | trace | plot)" >&2; exit 1 ;;
    esac
    if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]] || (( PARALLEL < 1 )); then
        echo "bad --parallel $PARALLEL (want a positive integer)" >&2; exit 1
    fi

    log_progress "=== sweep start: name=${WORKLOAD_NAME} stage=${STAGE}"
    log_progress "    binary=${WORKLOAD_BIN}"
    log_progress "    cwd=${WORKLOAD_CWD}"
    log_progress "    argv=(${WORKLOAD_ARGV[*]})"
    log_progress "    bbv_interval=${BBV_INTERVAL} sim=${SIM_INSNS} warmup=${WARMUP_INSNS}"
    log_progress "    maxK=${SIMPOINT_MAXK} rob_size=${ROB_SIZE} parallel=${PARALLEL}"

    # Trace (qemu) phase: BBV -> SimPoint clustering -> CST traces.
    if [[ "$STAGE" == all || "$STAGE" == trace ]]; then
        local bb_file
        bb_file=$(stage_bbv)
        stage_simpoint "$bb_file"

        # Both variants pipe each tarball member (body, header) through
        # multi-threaded xz.  -T 0 = use every available core for that
        # compressor invocation; members compress serially but each gets
        # the whole CPU.
        # xz threads per compressor.  Default 0 (= all cores); an
        # orchestrator running many sweeps concurrently should bound this
        # (XZ_THREADS=4) to avoid 16x all-core compressor storms.
        local COMPRESS="compress=xz -T ${XZ_THREADS:-0}"

        # CP-only: no WP, no regdata, no memdata.
        if [[ "$VARIANT_SEL" == cp || "$VARIANT_SEL" == both ]]; then
            stage_trace cp  "$TR_CP_DIR"  \
                "wp=0" "memdata=0" "regdata=0" "$COMPRESS"
        fi

        # Full: WP on for both reads & writes, regdata+memdata on both
        # CP and WP sides.  With --wpprune N the full variant is tagged
        # full_p<N> and lands in traces_full_p<N>/ with wpprune=<N>.
        if [[ "$VARIANT_SEL" == full || "$VARIANT_SEL" == both ]]; then
            local full_tag=full full_dir=$TR_FULL_DIR
            local -a prune_opt=()
            if [[ -n "$WPPRUNE" ]]; then
                full_tag="full_p${WPPRUNE}"
                full_dir="${OUT_DIR}/traces_full_p${WPPRUNE}"
                prune_opt=("wpprune=${WPPRUNE}")
            fi
            stage_trace "$full_tag" "$full_dir" \
                "wp=1" "memdata=1" "regdata=1" \
                "wp_memdata=1" "wp_regdata=1" "${prune_opt[@]}" "$COMPRESS"
        fi
    fi

    # Plot (cst_visualize) phase: per-simpoint SVGs + whole-program
    # aggregates.  Split out so an orchestrator can run the qemu phase
    # across sweeps in parallel, then hand each sweep's plot phase the
    # full core budget in turn.
    if [[ "$STAGE" == all || "$STAGE" == plot ]]; then
        stage_plot
        stage_aggregate
    fi

    log_progress "=== sweep done (stage=${STAGE})"
}

main "$@"
