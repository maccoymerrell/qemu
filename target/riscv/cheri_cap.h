/*
 * CHERI Capability Type and Operations for RISC-V
 *
 * Adapted from the CTSRD-CHERI/qemu implementation.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2023 University of Cambridge
 * Copyright (c) 2020-2023 SRI International
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TARGET_RISCV_CHERI_CAP_H
#define TARGET_RISCV_CHERI_CAP_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* ---------- constants ---------- */

#define CHERI_CAP_SIZE 16  /* bytes: 128-bit capability */

/*
 * Permission bitmask values (CHERI-RISC-V spec).
 * Stored in the upper 16 bits of pesbt.
 */
#define CAP_PERM_EXECUTE    (1u << 0)   /* 0x001 */
#define CAP_PERM_LOAD       (1u << 1)   /* 0x002 */
#define CAP_PERM_STORE      (1u << 2)   /* 0x004 */
#define CAP_PERM_LOAD_CAP   (1u << 3)   /* 0x008 */
#define CAP_PERM_STORE_CAP  (1u << 4)   /* 0x010 */
#define CAP_PERM_SEAL       (1u << 5)   /* 0x020 */
#define CAP_PERM_UNSEAL     (1u << 6)   /* 0x040 */
#define CAP_PERM_SYSTEM     (1u << 7)   /* 0x080 */
#define CAP_PERM_SETCID     (1u << 8)   /* 0x100 */

/*
 * CAP_ACCESS_SYS_REGS is the CHERI permission that gates access to
 * system registers (sret/mret/CSpecialRW).  Per the CHERI specification,
 * this maps to CAP_PERM_SYSTEM (bit 7) on RISC-V.
 */
#define CAP_ACCESS_SYS_REGS  CAP_PERM_SYSTEM

#define CAP_PERMS_ALL       0x1FFu      /* bits [8:0] */

/* Object type constants. */
#define CAP_OTYPE_UNSEALED  0u
#define CAP_OTYPE_SENTRY    1u
#define CAP_OTYPE_SENTRY_ID 3u  /* Interrupt-disabled sentry */
#define CAP_OTYPE_SENTRY_IE 4u  /* Interrupt-enabled sentry */

/*
 * CHERI-128 (CC128 / Morello-style) compressed capability format.
 *
 * pesbt layout:
 *   [63:48]  permissions  (16 bits)
 *   [47:32]  object type  (16 bits)
 *   [31:27]  exponent E   (5 bits, 0 = exact, 1..24 = compressed)
 *   [26:18]  encoded top  T (9 bits — top mantissa)
 *   [17:9]   encoded bot  B (9 bits — base mantissa)
 *   [8]      internal exponent flag IE (1 bit)
 *   [7:0]    reserved     (8 bits)
 *
 * When IE=0 (internal-exponent mode off / exact), E=0 and the full
 * base/top are stored in the cached fields.  When IE=1, the exponent
 * is extracted from bits [31:27] and T/B are mantissas that, shifted
 * left by E, reconstruct approximate bounds.
 *
 * The cached _base/_top fields always hold the decompressed values so
 * that bounds checks are O(1).
 */
#define CAP_PESBT_PERMS_SHIFT   48
#define CAP_PESBT_PERMS_MASK    UINT64_C(0xFFFF000000000000)
#define CAP_PESBT_OTYPE_SHIFT   32
#define CAP_PESBT_OTYPE_MASK    UINT64_C(0x0000FFFF00000000)

/* CC128 compression constants */
#define CC128_EXP_SHIFT         27
#define CC128_EXP_MASK          UINT64_C(0x00000000F8000000)
#define CC128_TOP_SHIFT         18
#define CC128_TOP_MASK          UINT64_C(0x0000000007FC0000)
#define CC128_BOT_SHIFT         9
#define CC128_BOT_MASK          UINT64_C(0x000000000003FE00)
#define CC128_IE_BIT            UINT64_C(0x0000000000000100)
#define CC128_MANTISSA_BITS     9
#define CC128_MAX_EXPONENT      24

/* ---------- capability type ---------- */

/*
 * 128-bit CHERI capability register.
 *
 * Stored as the compressed pesbt word plus a 64-bit cursor (virtual
 * address).  The tag bit lives out-of-band.  Decompressed base and top
 * are cached so that bounds checks and field queries are O(1).
 *
 * The pesbt lower 32 bits encode the CC128 compressed bounds.  The
 * cached _base/_top fields are kept in sync by every mutator so that
 * compression/decompression is transparent to the rest of the emulator.
 */
typedef struct cap_register {
    uint64_t pesbt;         /* packed permissions / otype / bounds metadata */
    uint64_t _cursor;       /* current virtual address                     */

    /* Cached decompressed bounds — kept in sync by every mutator. */
    uint64_t _base;
    uint64_t _top;          /* one past the last accessible byte           */

    uint8_t  flags;         /* architectural flags (RISC-V: 1-bit)         */
    bool     tag;           /* validity tag (out-of-band in hardware)      */
} cap_register_t;

/* ---------- pesbt helpers (internal) ---------- */

static inline uint64_t cap_pesbt_build(uint32_t perms, uint32_t otype)
{
    return ((uint64_t)(perms & 0xFFFFu) << CAP_PESBT_PERMS_SHIFT) |
           ((uint64_t)(otype & 0xFFFFu) << CAP_PESBT_OTYPE_SHIFT);
}

static inline uint32_t cap_pesbt_get_perms(uint64_t pesbt)
{
    return (uint32_t)((pesbt & CAP_PESBT_PERMS_MASK) >> CAP_PESBT_PERMS_SHIFT);
}

static inline uint32_t cap_pesbt_get_otype(uint64_t pesbt)
{
    return (uint32_t)((pesbt & CAP_PESBT_OTYPE_MASK) >> CAP_PESBT_OTYPE_SHIFT);
}

/* ---------- creation / initialisation ---------- */

/* Return a null (all-zeroes, untagged) capability. */
static inline cap_register_t cap_mk_null(void)
{
    cap_register_t c;
    memset(&c, 0, sizeof(c));
    return c;
}

/*
 * Build a capability from explicit field values.
 * The tag is set to @p tagged; bounds are [base, base + length).
 */
static inline cap_register_t cap_mk(uint64_t base, uint64_t length,
                                     uint64_t cursor, uint32_t perms,
                                     uint32_t otype, bool tagged)
{
    cap_register_t c;
    c._base   = base;
    c._top    = base + length;
    c._cursor = cursor;
    c.pesbt   = cap_pesbt_build(perms, otype);
    c.flags   = 0;
    c.tag     = tagged;
    return c;
}

/*
 * The "almighty" root capability: full address space, all permissions,
 * unsealed, tagged.
 */
static inline cap_register_t cap_mk_root(void)
{
    cap_register_t c;
    c._base   = 0;
    c._top    = UINT64_MAX;
    c._cursor = 0;
    c.pesbt   = cap_pesbt_build(CAP_PERMS_ALL, CAP_OTYPE_UNSEALED);
    c.flags   = 0;
    c.tag     = true;
    return c;
}

/* ---------- field accessors ---------- */

static inline uint64_t cap_get_base(const cap_register_t *c)
{
    return c->_base;
}

/*
 * Top is one past the last accessible byte.
 * For a full-address-space capability top may equal UINT64_MAX.
 */
static inline uint64_t cap_get_top(const cap_register_t *c)
{
    return c->_top;
}

static inline uint64_t cap_get_length(const cap_register_t *c)
{
    return c->_top - c->_base;
}

static inline uint64_t cap_get_offset(const cap_register_t *c)
{
    return c->_cursor - c->_base;
}

static inline uint32_t cap_get_perms(const cap_register_t *c)
{
    return cap_pesbt_get_perms(c->pesbt);
}

static inline uint32_t cap_get_otype(const cap_register_t *c)
{
    return cap_pesbt_get_otype(c->pesbt);
}

static inline bool cap_is_sealed(const cap_register_t *c)
{
    return cap_get_otype(c) != CAP_OTYPE_UNSEALED;
}

/**
 * Return true if @p c is a sentry capability (sealed with sentry otype).
 * Sentries can be used as indirect jump targets but not modified.
 */
static inline bool cap_is_sealed_entry(const cap_register_t *c)
{
    uint32_t ot = cap_get_otype(c);
    return ot == CAP_OTYPE_SENTRY ||
           ot == CAP_OTYPE_SENTRY_ID ||
           ot == CAP_OTYPE_SENTRY_IE;
}

static inline bool cap_get_tag(const cap_register_t *c)
{
    return c->tag;
}

static inline uint64_t cap_get_cursor(const cap_register_t *c)
{
    return c->_cursor;
}

static inline uint8_t cap_get_flags(const cap_register_t *c)
{
    return c->flags;
}

/*
 * Return the "high half" of the in-memory representation — i.e. the
 * pesbt word.  Useful when storing a capability to memory as two
 * 64-bit halves (pesbt ∥ cursor).
 */
static inline uint64_t cap_get_high(const cap_register_t *c)
{
    return c->pesbt;
}

/* ---------- field modifiers ---------- */

/*
 * Set the bounds of a capability to [cursor, cursor + req_length).
 *
 * In hardware the resulting bounds may be rounded (widened) due to the
 * compressed CC128 representation.  Returns true if the bounds were set
 * exactly, false if they had to be rounded.
 *
 * When rounding occurs, base is rounded DOWN and top is rounded UP, so
 * the resulting bounds are always a superset of the requested bounds.
 *
 * Precondition: the capability must be unsealed and tagged.
 */
static inline bool cap_set_bounds(cap_register_t *c, uint64_t req_length)
{
    c->_base = c->_cursor;
    c->_top  = c->_cursor + req_length;

    /* Compute whether CC128 encoding is exact */
    unsigned e = cc128_compute_exponent(req_length);
    bool exact = (e == 0);

    /* Encode bounds into pesbt */
    cc128_compress(c);

    return exact;
}

/*
 * Replace the offset (cursor − base) with @p offset.
 * Returns false if the new cursor falls outside representable bounds.
 */
static inline bool cap_set_offset(cap_register_t *c, uint64_t offset)
{
    uint64_t new_cursor = c->_base + offset;
    if (!cc128_is_representable(c, new_cursor)) {
        return false;
    }
    c->_cursor = new_cursor;
    return true;
}

/*
 * Set the cursor to an absolute address.
 * Returns false if the address is not representable.
 */
static inline bool cap_set_addr(cap_register_t *c, uint64_t addr)
{
    if (!cc128_is_representable(c, addr)) {
        return false;
    }
    c->_cursor = addr;
    return true;
}

/*
 * Increment the cursor by a signed delta.
 * Returns false if the result is not representable.
 */
static inline bool cap_inc_offset(cap_register_t *c, int64_t delta)
{
    uint64_t new_cursor = (uint64_t)((int64_t)c->_cursor + delta);
    if (!cc128_is_representable(c, new_cursor)) {
        return false;
    }
    c->_cursor = new_cursor;
    return true;
}

/* Mask (AND) the permission bits — can only remove permissions. */
static inline void cap_and_perms(cap_register_t *c, uint32_t mask)
{
    uint32_t perms = cap_get_perms(c) & mask;
    uint32_t otype = cap_get_otype(c);
    c->pesbt = cap_pesbt_build(perms, otype);
}

static inline void cap_set_flags(cap_register_t *c, uint8_t flags)
{
    c->flags = flags & 0x1u;  /* RISC-V: single-bit flag */
}

static inline void cap_clear_tag(cap_register_t *c)
{
    c->tag = false;
}

/*
 * Seal with a given object type.
 * The caller must have verified that the sealing capability carries
 * CAP_PERM_SEAL and that @p otype is within its range.
 */
static inline void cap_seal(cap_register_t *c, uint32_t otype)
{
    uint32_t perms = cap_get_perms(c);
    c->pesbt = cap_pesbt_build(perms, otype);
}

/* Unseal (set otype back to UNSEALED). */
static inline void cap_unseal(cap_register_t *c)
{
    cap_seal(c, CAP_OTYPE_UNSEALED);
}

/* Seal as a sentry (otype = CAP_OTYPE_SENTRY). */
static inline void cap_seal_entry(cap_register_t *c)
{
    cap_seal(c, CAP_OTYPE_SENTRY);
}

/* ---------- comparison ---------- */

/*
 * Return true if @p inner is a subset of @p outer:
 *   - inner's tag implies outer's tag
 *   - inner's bounds are within outer's bounds
 *   - inner's permissions are a subset of outer's
 */
static inline bool cap_is_subset(const cap_register_t *outer,
                                 const cap_register_t *inner)
{
    if (inner->tag && !outer->tag) {
        return false;
    }
    if (inner->_base < outer->_base) {
        return false;
    }
    if (inner->_top > outer->_top) {
        return false;
    }
    if ((cap_get_perms(inner) & ~cap_get_perms(outer)) != 0) {
        return false;
    }
    return true;
}

/* Exact structural equality (includes tag, flags, pesbt, cursor, bounds). */
static inline bool cap_is_equal(const cap_register_t *a,
                                const cap_register_t *b)
{
    return a->pesbt   == b->pesbt   &&
           a->_cursor == b->_cursor &&
           a->_base   == b->_base   &&
           a->_top    == b->_top    &&
           a->flags   == b->flags   &&
           a->tag     == b->tag;
}

/* ---------- bounds checking ---------- */

/*
 * Check whether an access of @p size bytes at address @p addr is within
 * the capability's bounds.
 *
 * The access range is [addr, addr + size) and must satisfy:
 *   base <= addr  &&  addr + size <= top
 *
 * @p size must be >= 1.  Returns true if the access is in bounds.
 */
static inline bool cap_in_bounds(const cap_register_t *c, uint64_t addr,
                                 uint64_t size)
{
    if (addr < c->_base) {
        return false;
    }
    /*
     * Check addr + size <= top.
     * Rewrite as: size <= top - addr (safe because addr >= base >= 0).
     * But we must also handle the case where top < addr (empty range or
     * null capability where top == 0 and addr > 0).
     */
    if (c->_top < addr) {
        return false; /* addr is already past the top */
    }
    if (size > c->_top - addr) {
        return false;
    }
    return true;
}

/* ==========================================================================
 * CC128 Compressed Capability Encoding / Decoding
 *
 * These functions convert between the in-register (decompressed) format
 * with explicit _base/_top and the in-memory 128-bit format (pesbt ∥ cursor)
 * where bounds are encoded as mantissa+exponent in the pesbt lower 32 bits.
 *
 * The encoding follows the CHERI Concentrate scheme (CC128):
 *   - Find the smallest exponent E such that the length fits in
 *     CC128_MANTISSA_BITS bits when shifted right by E.
 *   - Encode base and top mantissas as the top MANTISSA_BITS bits of
 *     the respective addresses, right-shifted by E.
 *   - Round base DOWN and top UP so the encoded bounds are a superset
 *     of the requested bounds.
 * ========================================================================== */

/*
 * Count leading zeros for 64-bit value.
 */
static inline int cc128_clz64(uint64_t val)
{
    if (val == 0) {
        return 64;
    }
    return __builtin_clzll(val);
}

/*
 * Compute the CC128 exponent for a given length.
 * Returns the number of bits to shift so that length fits in
 * CC128_MANTISSA_BITS bits.  Returns 0 for lengths that fit exactly.
 */
static inline unsigned cc128_compute_exponent(uint64_t length)
{
    if (length == 0) {
        return 0;
    }
    int msb = 63 - cc128_clz64(length);
    if (msb < CC128_MANTISSA_BITS) {
        return 0;  /* fits exactly */
    }
    unsigned e = (unsigned)(msb - (CC128_MANTISSA_BITS - 1));
    if (e > CC128_MAX_EXPONENT) {
        e = CC128_MAX_EXPONENT;
    }
    return e;
}

/*
 * Compute the "representable length" — the smallest length >= @req_len
 * that can be exactly encoded at the exponent needed for @req_len.
 *
 * This is the CRRL instruction.
 */
static inline uint64_t cc128_representable_length(uint64_t req_len)
{
    unsigned e = cc128_compute_exponent(req_len);
    if (e == 0) {
        return req_len;  /* exact */
    }
    uint64_t mask = (UINT64_C(1) << e) - 1;
    /* Round up */
    return (req_len + mask) & ~mask;
}

/*
 * Compute the "representable alignment mask" — the mask that, when ANDed
 * with an address, gives the closest representable-aligned base.
 *
 * This is the CRAM instruction.
 */
static inline uint64_t cc128_representable_alignment_mask(uint64_t req_len)
{
    unsigned e = cc128_compute_exponent(req_len);
    if (e == 0) {
        return UINT64_MAX;  /* no alignment needed */
    }
    return ~((UINT64_C(1) << e) - 1);
}

/*
 * Check whether @new_cursor is representable given the cap's current bounds.
 * A cursor is representable if decoding the compressed bounds at the new
 * cursor would yield the same base/top.  For our caching scheme this
 * simplifies to: the encoded mantissas + exponent still decode to the
 * same _base and _top.
 *
 * In practice, for E>0 the cursor must not change so much that the
 * "correction" bits in the top differ.  A simple conservative check:
 * the new cursor must be within [base - 2^(E+MANTISSA), top + 2^(E+MANTISSA)).
 */
static inline bool cc128_is_representable(const cap_register_t *c,
                                          uint64_t new_cursor)
{
    uint64_t length = c->_top - c->_base;
    unsigned e = cc128_compute_exponent(length);
    if (e == 0) {
        return true;  /* exact bounds — always representable */
    }
    /* The representable region is [base - R, base + R) where R = 2^(E+M) */
    uint64_t rep_range = UINT64_C(1) << (e + CC128_MANTISSA_BITS);
    int64_t delta = (int64_t)(new_cursor - c->_base);
    /* Within [-rep_range/2, top + rep_range/2) is representable */
    if (delta < -(int64_t)(rep_range / 2)) {
        return false;
    }
    if (delta > (int64_t)(c->_top - c->_base + rep_range / 2)) {
        return false;
    }
    return true;
}

/*
 * Encode bounds into the lower 32 bits of pesbt (CC128 format).
 * Updates c->pesbt with the compressed bounds encoding.
 * The cached _base/_top are also updated to reflect the (possibly
 * rounded) encoded bounds.
 */
static inline void cc128_compress(cap_register_t *c)
{
    uint64_t base = c->_base;
    uint64_t length = c->_top - base;
    unsigned e = cc128_compute_exponent(length);

    uint64_t lower32;

    if (e == 0) {
        /* Exact encoding — IE=0, E=0 */
        uint64_t b_enc = base & ((UINT64_C(1) << CC128_MANTISSA_BITS) - 1);
        uint64_t t_enc = c->_top & ((UINT64_C(1) << CC128_MANTISSA_BITS) - 1);
        lower32 = ((uint64_t)e << CC128_EXP_SHIFT)   |
                  (t_enc << CC128_TOP_SHIFT)          |
                  (b_enc << CC128_BOT_SHIFT)          |
                  0;  /* IE = 0 */
    } else {
        /* Compressed encoding — IE=1 */
        uint64_t b_enc = (base >> e) & ((UINT64_C(1) << CC128_MANTISSA_BITS) - 1);
        uint64_t t_enc = (c->_top >> e) &
                         ((UINT64_C(1) << CC128_MANTISSA_BITS) - 1);

        /* Round: base down, top up */
        uint64_t round_base = b_enc << e;
        uint64_t round_top  = (t_enc + 1) << e;
        if (round_top < c->_top) {
            t_enc++;
            round_top = (t_enc + 1) << e;
        }

        lower32 = ((uint64_t)e << CC128_EXP_SHIFT)   |
                  (t_enc << CC128_TOP_SHIFT)           |
                  (b_enc << CC128_BOT_SHIFT)           |
                  CC128_IE_BIT;

        /* Update cached bounds to match encoded (rounded) values */
        c->_base = round_base;
        c->_top  = round_top;
    }

    /* Preserve upper 32 bits (perms + otype), replace lower 32 */
    c->pesbt = (c->pesbt & UINT64_C(0xFFFFFFFF00000000)) | lower32;
}

/*
 * Decode bounds from the lower 32 bits of pesbt + cursor.
 * Updates c->_base and c->_top from the compressed encoding.
 */
static inline void cc128_decompress(cap_register_t *c)
{
    uint64_t lower32 = c->pesbt & UINT64_C(0x00000000FFFFFFFF);
    unsigned e  = (unsigned)((lower32 & CC128_EXP_MASK) >> CC128_EXP_SHIFT);
    uint64_t te = (lower32 & CC128_TOP_MASK) >> CC128_TOP_SHIFT;
    uint64_t be = (lower32 & CC128_BOT_MASK) >> CC128_BOT_SHIFT;
    bool ie     = (lower32 & CC128_IE_BIT) != 0;

    if (!ie || e == 0) {
        /* Exact / uncompressed: base and top are just the mantissa values */
        /* But we need to reconstruct full addresses from the cursor region */
        uint64_t cursor = c->_cursor;
        uint64_t mask = (UINT64_C(1) << CC128_MANTISSA_BITS) - 1;
        c->_base = (cursor & ~mask) | be;
        c->_top  = (cursor & ~mask) | te;

        /* Correct for wrap-around */
        if (c->_base > cursor) {
            c->_base -= (UINT64_C(1) << CC128_MANTISSA_BITS);
        }
        if (c->_top < c->_base) {
            c->_top += (UINT64_C(1) << CC128_MANTISSA_BITS);
        }
    } else {
        /* Compressed: shift mantissas by exponent */
        c->_base = be << e;
        c->_top  = (te + 1) << e;  /* top is exclusive */
    }
}

#endif /* TARGET_RISCV_CHERI_CAP_H */
