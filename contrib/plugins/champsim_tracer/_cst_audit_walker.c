/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * cst_audit body walker (C accelerator).
 *
 * Mirrors the pure-Python `_walk_body` in cst_audit.py.  Built on first
 * use via cffi; cst_audit.py falls back to the Python walker when this
 * module is unavailable.
 */
#include <stdint.h>
#include <stddef.h>

#define BODY_TAG_END            0
#define BODY_TAG_ENTRY          1
#define BODY_TAG_THREAD_SWITCH  2
#define BODY_TAG_IFRAME         3

#define FID_EXTENDED            0xFF

#define BIDX_OVERHEAD           0
#define NUM_BUCKETS             10

/* Result/output struct.  Field layout MUST match the cdef in cst_audit.py. */
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
    int64_t cp_fd_bytes[NUM_BUCKETS];
    int64_t cp_fd_count[NUM_BUCKETS];
    int64_t wp_fd_bytes[NUM_BUCKETS];
    int64_t wp_fd_count[NUM_BUCKETS];
    int64_t error_offset;
    int32_t error_code;
    int32_t error_aux;       /* unknown-tag byte etc. */
    int64_t final_p;         /* last p reached, for diagnostics */
} cst_audit_result_t;

/* Error codes returned in result.error_code (0 = success). */
#define ERR_OK                   0
#define ERR_CP_FD_TRAILING       1
#define ERR_WP_CHAIN_TRAILING    2
#define ERR_WP_FD_TRAILING       3
#define ERR_UNKNOWN_TAG          4

typedef void (*progress_cb_t)(int64_t);

/* Force-inline-able varlen helpers.  Hot path. */

static inline uint64_t read_uleb(const uint8_t *m, int64_t *pp) {
    int64_t p = *pp;
    uint8_t b = m[p++];
    if (b < 0x80) { *pp = p; return b; }
    uint64_t v = b & 0x7f;
    int shift = 7;
    do {
        b = m[p++];
        v |= ((uint64_t)(b & 0x7f)) << shift;
        shift += 7;
    } while (b & 0x80);
    *pp = p;
    return v;
}

static inline int64_t read_sleb(const uint8_t *m, int64_t *pp) {
    int64_t p = *pp;
    int64_t v = 0;
    int shift = 0;
    uint8_t b;
    do {
        b = m[p++];
        v |= ((int64_t)(b & 0x7f)) << shift;
        shift += 7;
    } while (b & 0x80);
    if ((b & 0x40) && shift < 64) {
        v |= -((int64_t)1 << shift);
    }
    *pp = p;
    return v;
}

/* Skip a varlen (ULEB or SLEB share the same termination rule). */
static inline void skip_varlen(const uint8_t *m, int64_t *pp) {
    int64_t p = *pp;
    while (m[p++] & 0x80) { /* nothing */ }
    *pp = p;
}

/* Skip a length-prefixed section.  Returns the total used bytes. */
static inline int64_t skip_lp_section(const uint8_t *m, int64_t *pp) {
    int64_t st = *pp;
    uint64_t n = read_uleb(m, pp);
    *pp += (int64_t)n;
    return *pp - st;
}

/* Walk a length-prefixed field-delta section and bucket each record into
 * the caller's parallel int64 arrays.  Returns 0 on success. */
static int scan_fd_section(
    const uint8_t *m, int64_t *pp,
    int64_t bytes_arr[NUM_BUCKETS],
    int64_t count_arr[NUM_BUCKETS],
    const uint8_t fid_bucket[256],
    const uint8_t is_extra_vec[256],
    int64_t *used_out
) {
    int64_t sec_st = *pp;
    int64_t prefix_st = *pp;
    uint64_t n = read_uleb(m, pp);
    int64_t payload_st = *pp;
    int64_t payload_end = payload_st + (int64_t)n;
    *used_out = payload_end - sec_st;

    bytes_arr[BIDX_OVERHEAD] += payload_st - prefix_st;
    count_arr[BIDX_OVERHEAD] += 1;

    int64_t rec_st = *pp;
    uint64_t n_records = read_uleb(m, pp);
    bytes_arr[BIDX_OVERHEAD] += *pp - rec_st;
    count_arr[BIDX_OVERHEAD] += 1;

    for (uint64_t i = 0; i < n_records; ++i) {
        int64_t rec_p0 = *pp;
        skip_varlen(m, pp);                      /* gap ULEB */
        uint8_t fid = m[(*pp)++];
        if (is_extra_vec[fid]) {
            uint64_t n_values = read_uleb(m, pp);
            for (uint64_t j = 0; j < n_values; ++j) {
                skip_varlen(m, pp);
            }
        } else {
            skip_varlen(m, pp);                  /* SLEB delta */
        }
        if (fid == FID_EXTENDED) {
            skip_varlen(m, pp);                  /* extended fid ULEB */
        }
        int idx = fid_bucket[fid];
        bytes_arr[idx] += *pp - rec_p0;
        count_arr[idx] += 1;
    }

    if (*pp != payload_end) {
        return -1;                               /* trailing bytes */
    }
    return 0;
}

/* Public entry point. */
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
) {
    int64_t p = body_off;
    int64_t last_progress_p = p;
    int64_t prev_cp_tid = 0;

    while (1) {
        if (progress && (p - last_progress_p) >= progress_chunk) {
            progress(p - last_progress_p);
            last_progress_p = p;
        }

        int64_t tag_pos = p;
        uint8_t tag = m[p++];

        if (tag == BODY_TAG_ENTRY) {
            int64_t delta = read_sleb(m, &p);
            prev_cp_tid += delta;
            out->cp_entry_framing_b += p - tag_pos;
            out->cp_entries += 1;
            if (prev_cp_tid >= 0 && prev_cp_tid < tinfo_len) {
                out->cp_total_insns += tinfo_arr[prev_cp_tid];
            }

            int64_t used = 0;
            if (scan_fd_section(m, &p,
                                out->cp_fd_bytes, out->cp_fd_count,
                                fid_bucket, is_extra_vec, &used) != 0) {
                out->error_code = ERR_CP_FD_TRAILING;
                out->error_offset = p;
                out->final_p = p;
                return -1;
            }
            out->cp_field_delta_b += used;

            /* WP chain envelope. */
            int64_t wp_st = p;
            uint64_t wp_n = read_uleb(m, &p);
            int64_t wp_payload_end = p + (int64_t)wp_n;
            out->wp_chain_envelope_b += wp_payload_end - wp_st;

            uint64_t num_wp = read_uleb(m, &p);
            int64_t prev_wp_template = 0;
            for (uint64_t i = 0; i < num_wp; ++i) {
                int64_t wfs = p;
                int64_t wd = read_sleb(m, &p);
                prev_wp_template += wd;
                out->wp_entry_framing_b += p - wfs;
                out->wp_entry_framing_c += 1;
                if (prev_wp_template >= 0 &&
                    prev_wp_template < tinfo_len) {
                    out->wp_total_insns += tinfo_arr[prev_wp_template];
                }
                int64_t used2 = 0;
                if (scan_fd_section(m, &p,
                                    out->wp_fd_bytes, out->wp_fd_count,
                                    fid_bucket, is_extra_vec,
                                    &used2) != 0) {
                    out->error_code = ERR_WP_FD_TRAILING;
                    out->error_offset = p;
                    out->final_p = p;
                    return -1;
                }
                out->wp_field_delta_b += used2;
            }
            out->wp_entries_total += (int64_t)num_wp;

            if (p != wp_payload_end) {
                out->error_code = ERR_WP_CHAIN_TRAILING;
                out->error_offset = p;
                out->final_p = p;
                return -1;
            }

            /* WP events section: opaque, just skip. */
            int64_t ev_used = skip_lp_section(m, &p);
            out->wp_events_b += ev_used;
            continue;
        }

        if (tag == BODY_TAG_THREAD_SWITCH) {
            skip_varlen(m, &p);
            out->thread_switch_b += p - tag_pos;
            out->thread_switch_c += 1;
            continue;
        }

        if (tag == BODY_TAG_IFRAME) {
            skip_lp_section(m, &p);
            skip_lp_section(m, &p);
            skip_lp_section(m, &p);
            out->iframe_count += 1;
            out->iframe_bytes_b += p - tag_pos;
            continue;
        }

        if (tag == BODY_TAG_END) {
            skip_varlen(m, &p);
            out->body_terminator = p - tag_pos;
            break;
        }

        out->error_code = ERR_UNKNOWN_TAG;
        out->error_offset = tag_pos;
        out->error_aux = (int32_t)tag;
        out->final_p = p;
        return -1;
    }

    if (progress && p != last_progress_p) {
        progress(p - last_progress_p);
    }
    out->final_p = p;
    return 0;
}
