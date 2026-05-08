#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
cst_audit.py - byte-composition audit of a .cst trace.

Streams a .cst file (mmap'd, so multi-GB OK) and reports a
single-screen breakdown of where the bytes go. Categories mirror the
writer's logical regions so the report directly identifies shrinkage
targets.

Usage:
  python3 cst_audit.py path/to/trace.cst
  xz -dc trace.cst.xz > /tmp/trace.cst && python3 cst_audit.py /tmp/trace.cst

Compressed input is not supported directly: the trailer is read by
seek-from-end.  Decompress first.
"""
from __future__ import annotations

import argparse
import dataclasses
import mmap
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import champsim_tracer_decode as dec  # noqa: E402

try:
    from tqdm import tqdm as _tqdm  # type: ignore
except ImportError:
    _tqdm = None

# Per-insn template flag bits (subset we need to parse the body).
_INSN_FLAG_HAS_IMM           = 0x02

# Body-walker progress update granularity. Updating the tqdm bar costs a
# Python call; we batch updates so the inner record loop stays tight.
_PROGRESS_CHUNK_BYTES = 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# Optional C accelerator (cffi).
#
# The body walker is the audit's hot loop. CPython taps out around
# ~10 MB/s for this style of byte-stream record dispatch; a small C
# implementation hits ~500 MB/s.  We compile it on first use (cached
# under ``__cffi_cache__`` next to this file) and import it dynamically.
# If cffi is missing or compilation fails, the pure-Python walker
# downstream remains the canonical fallback.
# ---------------------------------------------------------------------------

_CFFI_CACHE_DIR = _HERE / "__cffi_cache__"
_C_SOURCE_PATH  = _HERE / "_cst_audit_walker.c"
_C_MODULE_NAME  = "_cst_audit_walker_c"

_CFFI_CDEF = r"""
typedef struct {
    int64_t cp_entries;
    int64_t wp_entries_total;
    int64_t cp_total_insns;
    int64_t wp_total_insns;
    int64_t cp_entry_framing_b;
    int64_t cp_field_delta_b;
    int64_t thread_switch_b;
    int64_t thread_switch_c;
    int64_t wp_chain_envelope_b;
    int64_t wp_entry_framing_b;
    int64_t wp_entry_framing_c;
    int64_t wp_field_delta_b;
    int64_t wp_events_b;
    int64_t iframe_count;
    int64_t iframe_bytes_b;
    int64_t body_terminator;
    int64_t cp_fd_bytes[10];
    int64_t cp_fd_count[10];
    int64_t wp_fd_bytes[10];
    int64_t wp_fd_count[10];
    int64_t error_offset;
    int32_t error_code;
    int32_t error_aux;
    int64_t final_p;
} cst_audit_result_t;

typedef void (*progress_cb_t)(int64_t);

int walk_body_c(
    const uint8_t *m,
    int64_t body_off,
    const int64_t *tinfo_arr,
    int64_t tinfo_len,
    const uint8_t *fid_bucket,
    const uint8_t *is_extra_vec,
    cst_audit_result_t *out,
    progress_cb_t progress,
    int64_t progress_chunk
);
"""

_c_walker = None  # lazy: ((ffi, lib) | False)


def _build_c_walker_module():
    """Compile the C accelerator into ``_CFFI_CACHE_DIR``. Raises on failure."""
    import cffi
    ffi = cffi.FFI()
    ffi.cdef(_CFFI_CDEF)
    c_source = _C_SOURCE_PATH.read_text()
    ffi.set_source(
        _C_MODULE_NAME,
        c_source,
        extra_compile_args=["-O3", "-fno-strict-aliasing"],
    )
    _CFFI_CACHE_DIR.mkdir(exist_ok=True)
    ffi.compile(tmpdir=str(_CFFI_CACHE_DIR), verbose=False)


def _load_c_walker():
    """Return ``(ffi, lib)`` or ``None`` if the C accelerator is unavailable.

    Tries the cached extension first; builds it on demand if missing.
    Memoized so the build/load decision happens at most once per process.
    """
    global _c_walker
    if _c_walker is not None:
        return _c_walker if _c_walker is not False else None

    if str(_CFFI_CACHE_DIR) not in sys.path:
        sys.path.insert(0, str(_CFFI_CACHE_DIR))

    def _import():
        # Re-import safely: invalidate caches in case the .so just appeared.
        import importlib
        importlib.invalidate_caches()
        mod = importlib.import_module(_C_MODULE_NAME)
        return mod.ffi, mod.lib

    try:
        _c_walker = _import()
        return _c_walker
    except ImportError:
        pass

    try:
        _build_c_walker_module()
    except Exception as exc:
        msg = (f"cst_audit: C accelerator unavailable "
               f"({type(exc).__name__}: {exc}); using Python walker.")
        if sys.stderr.isatty():
            print(msg, file=sys.stderr)
        _c_walker = False
        return None

    try:
        _c_walker = _import()
        return _c_walker
    except ImportError as exc:
        if sys.stderr.isatty():
            print(f"cst_audit: built C accelerator but failed to import "
                  f"({exc}); using Python walker.", file=sys.stderr)
        _c_walker = False
        return None


# ---------------------------------------------------------------------------
# Field-delta bucket dispatch tables.
#
# The body walker is the hot path: each field-delta record needs to be
# bucketed by FID. We precompute a 256-entry table mapping every possible
# FID byte to a small integer index in [0, 9] so the inner loop is just
# `idx = _FID_BUCKET_IDX[fid]` instead of a chained-if comparison.
# ---------------------------------------------------------------------------

_BUCKET_NAMES = ("overhead", "mem_counts", "load_addr", "store_addr",
                 "load_data", "store_data", "dst_reg", "insn_meta",
                 "extended", "other")
_BUCKET_NAME_TO_IDX = {n: i for i, n in enumerate(_BUCKET_NAMES)}
_NUM_BUCKETS = len(_BUCKET_NAMES)

_BIDX_OVERHEAD   = 0
_BIDX_MEM_COUNTS = 1
_BIDX_LOAD_ADDR  = 2
_BIDX_STORE_ADDR = 3
_BIDX_LOAD_DATA  = 4
_BIDX_STORE_DATA = 5
_BIDX_DST_REG    = 6
_BIDX_INSN_META  = 7
_BIDX_EXTENDED   = 8
_BIDX_OTHER      = 9


def _build_fid_tables():
    bucket = [_BIDX_OTHER] * 256
    is_extra_vec = [False] * 256

    bucket[dec.FID_N_LOADS]  = _BIDX_MEM_COUNTS
    bucket[dec.FID_N_STORES] = _BIDX_MEM_COUNTS
    for i in range(dec.FID_SLOT_COUNT):
        bucket[dec.FID_LOAD_ADDR_BASE  + i] = _BIDX_LOAD_ADDR
        bucket[dec.FID_STORE_ADDR_BASE + i] = _BIDX_STORE_ADDR
        bucket[dec.FID_LOAD_DATA_BASE  + i] = _BIDX_LOAD_DATA
        bucket[dec.FID_STORE_DATA_BASE + i] = _BIDX_STORE_DATA
        bucket[dec.FID_DST_REG_BASE    + i] = _BIDX_DST_REG
    bucket[dec.FID_EXTRA_LOAD_ADDR]  = _BIDX_LOAD_ADDR
    bucket[dec.FID_EXTRA_STORE_ADDR] = _BIDX_STORE_ADDR
    bucket[dec.FID_EXTRA_LOAD_DATA]  = _BIDX_LOAD_DATA
    bucket[dec.FID_EXTRA_STORE_DATA] = _BIDX_STORE_DATA
    for fid in range(dec.FID_INSN_BYTES_LO, dec.FID_INSN_SIZE + 1):
        bucket[fid] = _BIDX_INSN_META
    bucket[dec.FID_EXTENDED] = _BIDX_EXTENDED

    for fid in dec.EXTRA_VECTOR_FIDS:
        is_extra_vec[fid] = True

    return bucket, is_extra_vec


_FID_BUCKET_IDX, _FID_IS_EXTRA_VECTOR = _build_fid_tables()


# ---------------------------------------------------------------------------
# mmap-backed cursor with ULEB/SLEB helpers (cool-path: header/templates).
# ---------------------------------------------------------------------------

class _R:
    __slots__ = ("m", "p", "end")

    def __init__(self, m, p: int = 0, end: int | None = None):
        self.m = m
        self.p = p
        self.end = len(m) if end is None else end

    def u8(self) -> int:
        v = self.m[self.p]
        self.p += 1
        return v

    def u32_le(self) -> int:
        v = int.from_bytes(self.m[self.p:self.p + 4], "little")
        self.p += 4
        return v

    def u64_le(self) -> int:
        v = int.from_bytes(self.m[self.p:self.p + 8], "little")
        self.p += 8
        return v

    def uleb(self) -> int:
        result, shift = 0, 0
        while True:
            b = self.m[self.p]
            self.p += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7

    def sleb(self) -> int:
        result, shift = 0, 0
        while True:
            b = self.m[self.p]
            self.p += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if (b & 0x40) and shift < 64:
                    result |= -(1 << shift)
                return result

    def skip(self, n: int) -> None:
        self.p += n

    def slice(self, n: int) -> "_R":
        sub = _R(self.m, self.p, self.p + n)
        self.p += n
        return sub

    def string_len(self) -> int:
        st = self.p
        n = self.uleb()
        self.skip(n)
        return self.p - st


# ---------------------------------------------------------------------------
# Stat buckets.
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Bucket:
    bytes: int = 0
    count: int = 0

    def add(self, n: int) -> None:
        self.bytes += n
        self.count += 1

    def add_bucket(self, other: "_Bucket") -> None:
        self.bytes += other.bytes
        self.count += other.count


class _FieldDeltaBreakdown:
    """List-backed breakdown.

    Hot-path code mutates ``bytes_arr`` / ``count_arr`` directly (parallel
    int lists indexed by ``_BIDX_*``). The named attributes
    (``overhead``, ``mem_counts``, ...) are exposed via ``__getattr__``
    for ``report()``'s benefit and yield a ``_Bucket`` snapshot.
    """
    __slots__ = ("bytes_arr", "count_arr")

    def __init__(self) -> None:
        self.bytes_arr = [0] * _NUM_BUCKETS
        self.count_arr = [0] * _NUM_BUCKETS

    def __getattr__(self, name):
        idx = _BUCKET_NAME_TO_IDX.get(name)
        if idx is None:
            raise AttributeError(name)
        # __getattr__ is only consulted when slot lookup misses, so this
        # cannot recurse for the slot names themselves.
        return _Bucket(self.bytes_arr[idx], self.count_arr[idx])

    def add(self, other: "_FieldDeltaBreakdown") -> None:
        ba, ca = self.bytes_arr, self.count_arr
        oba, oca = other.bytes_arr, other.count_arr
        for i in range(_NUM_BUCKETS):
            ba[i] += oba[i]
            ca[i] += oca[i]


@dataclasses.dataclass
class _Stats:
    file_size: int = 0
    header: int = 0
    templates_section: int = 0
    templates_count: int = 0
    trailer: int = 0
    body_total: int = 0
    body_terminator: int = 0
    cp_entries: int = 0
    wp_entries_total: int = 0
    cp_total_insns: int = 0
    wp_total_insns: int = 0

    cp_entry_framing: _Bucket = dataclasses.field(default_factory=_Bucket)
    cp_field_delta: _Bucket = dataclasses.field(default_factory=_Bucket)
    cp_field_delta_detail: _FieldDeltaBreakdown = dataclasses.field(
        default_factory=_FieldDeltaBreakdown)
    thread_switch: _Bucket = dataclasses.field(default_factory=_Bucket)

    wp_chain_envelope: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_entry_framing: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_field_delta: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_field_delta_detail: _FieldDeltaBreakdown = dataclasses.field(
        default_factory=_FieldDeltaBreakdown)

    wp_events: _Bucket = dataclasses.field(default_factory=_Bucket)

    # IFRAME redundancy.  An IFRAME is a self-contained re-emit of the
    # immediately-preceding ENTRY (CP + WP chain + WP events), encoded
    # against template-default baselines.  Tracked as a single bucket
    # since the size cost of the validation feature is the most useful
    # number to surface; per-section IFRAME breakdowns mirror the
    # normal ENTRY breakdowns and add little signal.
    iframe_count: int = 0
    iframe_bytes: _Bucket = dataclasses.field(default_factory=_Bucket)


# ---------------------------------------------------------------------------
# Audit walker.
# ---------------------------------------------------------------------------

def _walk_templates(r: _R, expected: int) -> tuple[int, dict[int, int]]:
    start = r.p
    n = r.uleb()
    if n != expected:
        raise ValueError(f"template count mismatch: header={n} "
                         f"trailer={expected}")
    tinfo: dict[int, int] = {}
    for _ in range(n):
        tlen = r.uleb()
        tend = r.p + tlen
        tid = r.uleb()
        r.uleb()                     # start_pc
        n_insns = r.uleb()
        r.uleb()                     # fall_through
        sname = r.uleb()
        r.skip(sname)
        for _i in range(n_insns):
            r.uleb()                 # pc_delta
            r.u8()                   # opcode
            r.u8()                   # branch_type
            iflags = r.u8()
            n_src = r.u8()
            n_dst = r.u8()
            r.skip(n_src + n_dst)
            r.u8()                   # n_loads
            r.u8()                   # n_stores
            if iflags & _INSN_FLAG_HAS_IMM:
                r.sleb()
            isize = r.u8()
            r.skip(isize)
        if r.p != tend:
            raise ValueError(f"template {tid}: declared len {tlen} "
                             f"!= actual {r.p - (tend - tlen)}")
        tinfo[tid] = n_insns
    return r.p - start, tinfo


# ---------------------------------------------------------------------------
# Body walker: hot path.
#
# Operates directly on the mmap (passed as ``m``) without an ``_R``
# cursor object so the inner loops avoid method-dispatch overhead. Two
# key structural optimizations vs. the obvious port of the cool-path
# parser:
#
#   1. ULEB/SLEB values that are only used to advance the read pointer
#      are skipped via a tight ``while m[p] & 0x80: p += 1; p += 1``
#      loop instead of being decoded into Python ints.
#
#   2. The per-section ``_FieldDeltaBreakdown`` allocation is removed.
#      The scanner mutates the caller-provided ``bytes_arr`` /
#      ``count_arr`` lists in place, so the per-CP-entry "merge-into-
#      stats" step disappears entirely.
# ---------------------------------------------------------------------------

def _skip_lp_section(m, p):
    """Advance past a length-prefixed section without touching its body.
    Returns ``(new_p, used_bytes)``. Used by the IFRAME branch only;
    the per-CP-entry sections inline this in ``_walk_body``.
    """
    sec_st = p
    b = m[p]; p += 1
    if b < 0x80:
        n = b
    else:
        n = b & 0x7F; shift = 7
        while True:
            b = m[p]; p += 1
            n |= (b & 0x7F) << shift
            if b < 0x80:
                break
            shift += 7
    new_p = p + n
    return new_p, new_p - sec_st


def _walk_body(m, p, s, tinfo_arr, tinfo_len, progress=None,
               progress_chunk=_PROGRESS_CHUNK_BYTES):
    """Walk the body, updating ``s`` in place.

    Performance-sensitive: the previous version split the field-delta
    scanner into its own function, but at ~60 M calls per multi-GB
    trace the call/return overhead dwarfed the actual scanning work.
    The scanner is therefore inlined twice here (once for the CP
    field-delta and once for the WP field-delta inside the WP chain).
    Code duplication is intentional and the format is documented in
    ``champsim_tracer_format.md``.
    """
    cp_fd_b = s.cp_field_delta_detail.bytes_arr
    cp_fd_c = s.cp_field_delta_detail.count_arr
    wp_fd_b = s.wp_field_delta_detail.bytes_arr
    wp_fd_c = s.wp_field_delta_detail.count_arr
    progress_update = progress.update if progress is not None else None
    last_progress_p = p

    fid_bucket   = _FID_BUCKET_IDX
    is_extra_vec = _FID_IS_EXTRA_VECTOR
    ext_fid      = dec.FID_EXTENDED
    BIDX_OVH     = _BIDX_OVERHEAD

    BODY_END    = dec.BODY_TAG_END
    BODY_ENTRY  = dec.BODY_TAG_ENTRY
    BODY_TS     = dec.BODY_TAG_THREAD_SWITCH
    BODY_IFRAME = dec.BODY_TAG_IFRAME

    cp_entries = 0
    wp_entries_total = 0
    cp_total_insns = 0
    wp_total_insns = 0
    cp_entry_framing_b = 0
    cp_field_delta_b = 0
    thread_switch_b = 0
    thread_switch_c = 0
    wp_chain_envelope_b = 0
    wp_entry_framing_b = 0
    wp_entry_framing_c = 0
    wp_field_delta_b = 0
    wp_events_b = 0
    iframe_count = 0
    iframe_bytes_b = 0
    body_terminator = 0
    prev_cp_tid = 0

    while True:
        if progress_update is not None and (p - last_progress_p) >= progress_chunk:
            progress_update(p - last_progress_p)
            last_progress_p = p

        tag_pos = p
        tag = m[p]; p += 1

        if tag == BODY_ENTRY:
            # ENTRY: SLEB template_id delta. Need the value for tinfo lookup.
            val = 0; shift = 0
            while True:
                b = m[p]; p += 1
                val |= (b & 0x7F) << shift
                shift += 7
                if b < 0x80:
                    if (b & 0x40) and shift < 64:
                        val |= -(1 << shift)
                    break
            prev_cp_tid += val
            cp_entry_framing_b += p - tag_pos
            cp_entries += 1
            if 0 <= prev_cp_tid < tinfo_len:
                cp_total_insns += tinfo_arr[prev_cp_tid]

            # ----- inline: CP field-delta section -----
            sec_st = p
            b = m[p]; p += 1
            if b < 0x80:
                n = b
            else:
                n = b & 0x7F; shift = 7
                while True:
                    b = m[p]; p += 1
                    n |= (b & 0x7F) << shift
                    if b < 0x80:
                        break
                    shift += 7
            payload_st = p
            payload_end = payload_st + n
            cp_field_delta_b += payload_end - sec_st
            cp_fd_b[BIDX_OVH] += payload_st - sec_st
            cp_fd_c[BIDX_OVH] += 1

            rec_st = p
            b = m[p]; p += 1
            if b < 0x80:
                n_records = b
            else:
                n_records = b & 0x7F; shift = 7
                while True:
                    b = m[p]; p += 1
                    n_records |= (b & 0x7F) << shift
                    if b < 0x80:
                        break
                    shift += 7
            cp_fd_b[BIDX_OVH] += p - rec_st
            cp_fd_c[BIDX_OVH] += 1

            for _ in range(n_records):
                rec_p0 = p
                while m[p] & 0x80:
                    p += 1
                p += 1
                fid = m[p]; p += 1
                if is_extra_vec[fid]:
                    b = m[p]; p += 1
                    if b < 0x80:
                        n_values = b
                    else:
                        n_values = b & 0x7F; shift = 7
                        while True:
                            b = m[p]; p += 1
                            n_values |= (b & 0x7F) << shift
                            if b < 0x80:
                                break
                            shift += 7
                    for _ in range(n_values):
                        while m[p] & 0x80:
                            p += 1
                        p += 1
                else:
                    while m[p] & 0x80:
                        p += 1
                    p += 1
                if fid == ext_fid:
                    while m[p] & 0x80:
                        p += 1
                    p += 1
                idx = fid_bucket[fid]
                cp_fd_b[idx] += p - rec_p0
                cp_fd_c[idx] += 1

            if p != payload_end:
                raise ValueError("CP field-delta had trailing bytes")
            # ----- end inline -----

            # WP chain envelope: length prefix, then num_wp ULEB, then
            # num_wp WP entries (each: SLEB tid delta + field-delta).
            wp_st = p
            b = m[p]; p += 1
            if b < 0x80:
                wp_n = b
            else:
                wp_n = b & 0x7F; shift = 7
                while True:
                    b = m[p]; p += 1
                    wp_n |= (b & 0x7F) << shift
                    if b < 0x80:
                        break
                    shift += 7
            wp_payload_end = p + wp_n
            wp_chain_envelope_b += wp_payload_end - wp_st

            b = m[p]; p += 1
            if b < 0x80:
                num_wp = b
            else:
                num_wp = b & 0x7F; shift = 7
                while True:
                    b = m[p]; p += 1
                    num_wp |= (b & 0x7F) << shift
                    if b < 0x80:
                        break
                    shift += 7

            prev_wp_template = 0
            for _ in range(num_wp):
                wfs = p
                val = 0; shift = 0
                while True:
                    b = m[p]; p += 1
                    val |= (b & 0x7F) << shift
                    shift += 7
                    if b < 0x80:
                        if (b & 0x40) and shift < 64:
                            val |= -(1 << shift)
                        break
                prev_wp_template += val
                wp_entry_framing_b += p - wfs
                wp_entry_framing_c += 1
                if 0 <= prev_wp_template < tinfo_len:
                    wp_total_insns += tinfo_arr[prev_wp_template]

                # ----- inline: WP field-delta section -----
                sec_st = p
                b = m[p]; p += 1
                if b < 0x80:
                    n = b
                else:
                    n = b & 0x7F; shift = 7
                    while True:
                        b = m[p]; p += 1
                        n |= (b & 0x7F) << shift
                        if b < 0x80:
                            break
                        shift += 7
                payload_st = p
                payload_end = payload_st + n
                wp_field_delta_b += payload_end - sec_st
                wp_fd_b[BIDX_OVH] += payload_st - sec_st
                wp_fd_c[BIDX_OVH] += 1

                rec_st = p
                b = m[p]; p += 1
                if b < 0x80:
                    n_records = b
                else:
                    n_records = b & 0x7F; shift = 7
                    while True:
                        b = m[p]; p += 1
                        n_records |= (b & 0x7F) << shift
                        if b < 0x80:
                            break
                        shift += 7
                wp_fd_b[BIDX_OVH] += p - rec_st
                wp_fd_c[BIDX_OVH] += 1

                for _ in range(n_records):
                    rec_p0 = p
                    while m[p] & 0x80:
                        p += 1
                    p += 1
                    fid = m[p]; p += 1
                    if is_extra_vec[fid]:
                        b = m[p]; p += 1
                        if b < 0x80:
                            n_values = b
                        else:
                            n_values = b & 0x7F; shift = 7
                            while True:
                                b = m[p]; p += 1
                                n_values |= (b & 0x7F) << shift
                                if b < 0x80:
                                    break
                                shift += 7
                        for _ in range(n_values):
                            while m[p] & 0x80:
                                p += 1
                            p += 1
                    else:
                        while m[p] & 0x80:
                            p += 1
                        p += 1
                    if fid == ext_fid:
                        while m[p] & 0x80:
                            p += 1
                        p += 1
                    idx = fid_bucket[fid]
                    wp_fd_b[idx] += p - rec_p0
                    wp_fd_c[idx] += 1

                if p != payload_end:
                    raise ValueError("WP field-delta had trailing bytes")
                # ----- end inline -----
            wp_entries_total += num_wp

            if p != wp_payload_end:
                raise ValueError("WP chain had trailing bytes")

            # WP events section — opaque to audit; inline the LP skip.
            ev_st = p
            b = m[p]; p += 1
            if b < 0x80:
                n = b
            else:
                n = b & 0x7F; shift = 7
                while True:
                    b = m[p]; p += 1
                    n |= (b & 0x7F) << shift
                    if b < 0x80:
                        break
                    shift += 7
            p += n
            wp_events_b += p - ev_st
            continue

        if tag == BODY_TS:
            while m[p] & 0x80:
                p += 1
            p += 1
            thread_switch_b += p - tag_pos
            thread_switch_c += 1
            continue

        if tag == BODY_IFRAME:
            p, _ = _skip_lp_section(m, p)
            p, _ = _skip_lp_section(m, p)
            p, _ = _skip_lp_section(m, p)
            iframe_count += 1
            iframe_bytes_b += p - tag_pos
            continue

        if tag == BODY_END:
            while m[p] & 0x80:
                p += 1
            p += 1
            body_terminator = p - tag_pos
            break

        raise ValueError(f"unknown body tag {tag} at offset {tag_pos}")

    if progress_update is not None and p != last_progress_p:
        progress_update(p - last_progress_p)

    s.cp_entries = cp_entries
    s.wp_entries_total = wp_entries_total
    s.cp_total_insns = cp_total_insns
    s.wp_total_insns = wp_total_insns
    s.cp_entry_framing.bytes = cp_entry_framing_b
    s.cp_entry_framing.count = cp_entries
    s.cp_field_delta.bytes = cp_field_delta_b
    s.cp_field_delta.count = cp_entries
    s.thread_switch.bytes = thread_switch_b
    s.thread_switch.count = thread_switch_c
    s.wp_chain_envelope.bytes = wp_chain_envelope_b
    s.wp_chain_envelope.count = cp_entries
    s.wp_entry_framing.bytes = wp_entry_framing_b
    s.wp_entry_framing.count = wp_entry_framing_c
    s.wp_field_delta.bytes = wp_field_delta_b
    s.wp_field_delta.count = wp_entries_total
    s.wp_events.bytes = wp_events_b
    s.wp_events.count = cp_entries
    s.iframe_count = iframe_count
    s.iframe_bytes.bytes = iframe_bytes_b
    s.iframe_bytes.count = iframe_count
    s.body_terminator = body_terminator


def _read_lp_sub(rr: _R) -> tuple[_R, int]:
    st = rr.p
    n = rr.uleb()
    prefix = rr.p - st
    sub = rr.slice(n)
    return sub, prefix + n


_ERR_NAMES = {
    1: "CP field-delta section had trailing bytes",
    2: "WP chain had trailing bytes",
    3: "WP field-delta section had trailing bytes",
}


def _walk_body_c(m, body_off, s, tinfo_arr, tinfo_len, progress, ffi_lib):
    """Run the C accelerator and copy the result struct back into ``s``.

    Mirrors the Python ``_walk_body`` semantics exactly.
    """
    ffi, lib = ffi_lib

    out = ffi.new("cst_audit_result_t *")
    fid_bucket_c = ffi.new("uint8_t[256]", bytes(_FID_BUCKET_IDX))
    is_extra_vec_c = ffi.new(
        "uint8_t[256]",
        bytes(1 if v else 0 for v in _FID_IS_EXTRA_VECTOR),
    )
    if tinfo_len > 0:
        tinfo_buf = ffi.new("int64_t[]", tinfo_arr)
    else:
        tinfo_buf = ffi.NULL

    m_buf = ffi.from_buffer("uint8_t[]", m)

    if progress is not None:
        # Keep a strong reference to the cffi callback for the duration of
        # the call — letting it get GC'd would dangle the C function pointer.
        @ffi.callback("void(int64_t)")
        def _progress_cb(n):
            progress.update(n)
        cb = _progress_cb
    else:
        cb = ffi.NULL

    rc = lib.walk_body_c(
        m_buf, body_off,
        tinfo_buf, tinfo_len,
        fid_bucket_c, is_extra_vec_c,
        out, cb, _PROGRESS_CHUNK_BYTES,
    )

    if rc != 0:
        code = out.error_code
        off  = out.error_offset
        if code == 4:
            raise ValueError(
                f"unknown body tag {out.error_aux} at offset {off}")
        raise ValueError(
            f"{_ERR_NAMES.get(code, f'walker error {code}')} at offset {off}")

    s.cp_entries          = out.cp_entries
    s.wp_entries_total    = out.wp_entries_total
    s.cp_total_insns      = out.cp_total_insns
    s.wp_total_insns      = out.wp_total_insns
    s.cp_entry_framing.bytes  = out.cp_entry_framing_b
    s.cp_entry_framing.count  = out.cp_entries
    s.cp_field_delta.bytes    = out.cp_field_delta_b
    s.cp_field_delta.count    = out.cp_entries
    s.thread_switch.bytes     = out.thread_switch_b
    s.thread_switch.count     = out.thread_switch_c
    s.wp_chain_envelope.bytes = out.wp_chain_envelope_b
    s.wp_chain_envelope.count = out.cp_entries
    s.wp_entry_framing.bytes  = out.wp_entry_framing_b
    s.wp_entry_framing.count  = out.wp_entry_framing_c
    s.wp_field_delta.bytes    = out.wp_field_delta_b
    s.wp_field_delta.count    = out.wp_entries_total
    s.wp_events.bytes         = out.wp_events_b
    s.wp_events.count         = out.cp_entries
    s.iframe_count            = out.iframe_count
    s.iframe_bytes.bytes      = out.iframe_bytes_b
    s.iframe_bytes.count      = out.iframe_count
    s.body_terminator         = out.body_terminator

    cp_b = s.cp_field_delta_detail.bytes_arr
    cp_c = s.cp_field_delta_detail.count_arr
    wp_b = s.wp_field_delta_detail.bytes_arr
    wp_c = s.wp_field_delta_detail.count_arr
    for i in range(_NUM_BUCKETS):
        cp_b[i] = out.cp_fd_bytes[i]
        cp_c[i] = out.cp_fd_count[i]
        wp_b[i] = out.wp_fd_bytes[i]
        wp_c[i] = out.wp_fd_count[i]


def audit(path: Path, show_progress: bool = False) -> _Stats:
    fd = os.open(path, os.O_RDONLY)
    try:
        m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
    finally:
        os.close(fd)

    s = _Stats()
    s.file_size = len(m)

    # Trailer
    if len(m) < dec.CST_TRAILER_SIZE:
        raise ValueError("file too small for trailer")
    tr = _R(m, len(m) - dec.CST_TRAILER_SIZE)
    templates_off   = tr.u64_le()
    templates_count = tr.u64_le()
    body_off        = tr.u64_le()
    body_byte_count = tr.u64_le()
    trailer_magic   = tr.u64_le()
    if trailer_magic not in (dec.CST_TRAILER_MAGIC_V17,
                             dec.CST_TRAILER_MAGIC_V18,
                             dec.CST_TRAILER_MAGIC_V19):
        raise ValueError(f"bad trailer magic 0x{trailer_magic:016x}")
    s.trailer = dec.CST_TRAILER_SIZE
    s.body_total = body_byte_count

    # Header
    hr = _R(m, 0)
    magic = hr.u32_le()
    if magic not in (dec.CST_MAGIC_V17, dec.CST_MAGIC_V18, dec.CST_MAGIC_V19):
        raise ValueError("bad header magic")
    expected_trailer = {
        dec.CST_MAGIC_V17: dec.CST_TRAILER_MAGIC_V17,
        dec.CST_MAGIC_V18: dec.CST_TRAILER_MAGIC_V18,
        dec.CST_MAGIC_V19: dec.CST_TRAILER_MAGIC_V19,
    }[magic]
    if trailer_magic != expected_trailer:
        raise ValueError("header/trailer CST version mismatch")
    hr.u8()                  # isa
    hr.u8()                  # flags
    hr.uleb()                # start_insn
    hr.uleb()                # warmup_insns
    hr.uleb()                # total_target_insns
    hr.string_len()          # command
    hr.string_len()          # datetime
    hr.string_len()          # comment
    hr.string_len()          # target_name
    if hr.p < body_off:
        _read_lp_sub(hr)     # encoding maps
    if hr.p != body_off:
        raise ValueError(f"header/body offset mismatch: parsed={hr.p} "
                         f"trailer={body_off}")
    s.header = hr.p
    # Templates
    tr2 = _R(m, templates_off)
    s.templates_section, tinfo = _walk_templates(tr2, templates_count)
    s.templates_count = templates_count
    # Flatten tinfo dict to a list indexed by template id. Template ids
    # are sparse but bounded (typically a few thousand, max under 100k),
    # so the wasted slots cost a few KB while ``arr[tid]`` is meaningfully
    # faster than ``dict.get(tid, 0)`` — and we hit it once per CP entry
    # plus once per WP entry, i.e. tens of millions of times on large
    # traces.
    tinfo_len = (max(tinfo) + 1) if tinfo else 0
    tinfo_arr = [0] * tinfo_len
    for tid, n_insns in tinfo.items():
        tinfo_arr[tid] = n_insns

    # Body
    bar = None
    if show_progress and _tqdm is not None and body_byte_count > 0:
        bar = _tqdm(total=body_byte_count, unit="B", unit_scale=True,
                    unit_divisor=1024, desc=f"audit {path.name}",
                    leave=False, disable=None)
    try:
        c = _load_c_walker()
        if c is not None:
            _walk_body_c(m, body_off, s, tinfo_arr, tinfo_len,
                         progress=bar, ffi_lib=c)
        else:
            _walk_body(m, body_off, s, tinfo_arr, tinfo_len, progress=bar)
    finally:
        if bar is not None:
            bar.close()

    return s


# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------

def _human(n: float) -> str:
    if n < 1024:
        return f"{int(n)} B"
    for u in ("KiB", "MiB", "GiB", "TiB", "PiB"):
        n /= 1024
        if n < 1024:
            return f"{n:.2f} {u}"
    return f"{n:.2f} PiB"


def _row(label: str, b: int, total: int,
         count: int | None = None, per: str | None = None) -> str:
    pct = (100.0 * b / total) if total else 0.0
    extra = ""
    if count:
        extra = f"  [{count:>10,} {per or 'evt'}, avg {b / count:6.1f} B]"
    return f"  {label:<34} {_human(b):>14}  {pct:6.2f}%{extra}"


def _fd_row(label: str, cp: _Bucket, wp: _Bucket, total: int) -> str:
    b = cp.bytes + wp.bytes
    pct = (100.0 * b / total) if total else 0.0
    count = cp.count + wp.count
    avg = (b / count) if count else 0.0
    return (f"  {label:<20} {_human(b):>12}  {pct:6.2f}%"
            f"  cp={_human(cp.bytes):>10}  wp={_human(wp.bytes):>10}"
            f"  [{count:>10,} rec, avg {avg:5.1f} B]")


def report(s: _Stats) -> str:
    lines: list[str] = []
    out = lines.append
    total = s.file_size

    out(f"FILE                                {_human(total):>14}  100.00%")
    out("")
    out("=== TOP-LEVEL SECTIONS ===")
    out(_row("HEADER", s.header, total))
    out(_row("TEMPLATES", s.templates_section, total,
             count=s.templates_count, per="tmpl"))
    out(_row("BODY", s.body_total, total))
    out(_row("TRAILER", s.trailer, total))

    body = s.body_total
    out("")
    out(f"=== BODY BREAKDOWN ({_human(body)}) ===")
    out(_row("CP entry framing",
             s.cp_entry_framing.bytes, body,
             count=s.cp_entries, per="entry"))
    out(_row("CP field-delta section",
             s.cp_field_delta.bytes, body,
             count=s.cp_entries, per="entry"))
    out(_row("thread-switch records",
             s.thread_switch.bytes, body,
             count=s.thread_switch.count, per="switch"))

    out(_row("WP chain envelope (incl. inner)",
             s.wp_chain_envelope.bytes, body,
             count=s.cp_entries, per="entry"))
    out("    expanded:")
    out(_row("    WP entry framing",
             s.wp_entry_framing.bytes, body,
             count=s.wp_entry_framing.count, per="WP"))
    out(_row("    WP field-delta section",
             s.wp_field_delta.bytes, body,
             count=s.wp_entries_total, per="WP"))

    out(_row("WP events", s.wp_events.bytes, body,
             count=s.cp_entries, per="entry"))
    out(_row("IFRAME records (validation redundancy)",
             s.iframe_bytes.bytes, body,
             count=s.iframe_count, per="iframe"))
    out(_row("BODY terminator", s.body_terminator, body))

    fd_total = s.cp_field_delta.bytes + s.wp_field_delta.bytes
    out("")
    out(f"=== FIELD-DELTA RECORD BREAKDOWN ({_human(fd_total)}) ===")
    out(_fd_row("section overhead", s.cp_field_delta_detail.overhead,
                s.wp_field_delta_detail.overhead, fd_total))
    out(_fd_row("memop counts", s.cp_field_delta_detail.mem_counts,
                s.wp_field_delta_detail.mem_counts, fd_total))
    out(_fd_row("load addresses", s.cp_field_delta_detail.load_addr,
                s.wp_field_delta_detail.load_addr, fd_total))
    out(_fd_row("store addresses", s.cp_field_delta_detail.store_addr,
                s.wp_field_delta_detail.store_addr, fd_total))
    out(_fd_row("load data", s.cp_field_delta_detail.load_data,
                s.wp_field_delta_detail.load_data, fd_total))
    out(_fd_row("store data", s.cp_field_delta_detail.store_data,
                s.wp_field_delta_detail.store_data, fd_total))
    out(_fd_row("dest registers", s.cp_field_delta_detail.dst_reg,
                s.wp_field_delta_detail.dst_reg, fd_total))
    out(_fd_row("instruction metadata", s.cp_field_delta_detail.insn_meta,
                s.wp_field_delta_detail.insn_meta, fd_total))
    out(_fd_row("extended", s.cp_field_delta_detail.extended,
                s.wp_field_delta_detail.extended, fd_total))
    out(_fd_row("other", s.cp_field_delta_detail.other,
                s.wp_field_delta_detail.other, fd_total))

    out("")
    out("=== ENTRIES & INSNS ===")
    out(f"  CP entries           {s.cp_entries:>14,}")
    out(f"  WP entries (total)   {s.wp_entries_total:>14,}")
    out(f"  CP insns (total)     {s.cp_total_insns:>14,}")
    out(f"  WP insns (total)     {s.wp_total_insns:>14,}")
    if s.cp_total_insns:
        out(f"  bytes / CP insn      {body / s.cp_total_insns:>14.2f}")
    all_insns = s.cp_total_insns + s.wp_total_insns
    if all_insns:
        out(f"  bytes / any insn     {body / all_insns:>14.2f}")
    if s.cp_entries:
        out(f"  WPs / CP entry       "
            f"{s.wp_entries_total / s.cp_entries:>14.2f}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audit byte composition of an (uncompressed) .cst trace.")
    ap.add_argument("trace", type=Path,
                    help="Path to a decompressed .cst file.")
    ap.add_argument("--no-progress", action="store_true",
                    help="Suppress the tqdm progress bar (auto-disabled "
                         "when stderr is not a tty or tqdm is missing).")
    args = ap.parse_args()
    if args.no_progress:
        show_progress = False
    elif _tqdm is None:
        show_progress = False
        if sys.stderr.isatty():
            print("cst_audit: tqdm not installed; running without "
                  "a progress bar (pip install tqdm to enable).",
                  file=sys.stderr)
    else:
        show_progress = True
    s = audit(args.trace, show_progress=show_progress)
    print(report(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
