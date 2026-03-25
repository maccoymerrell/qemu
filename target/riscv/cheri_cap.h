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

#define CAP_PERMS_ALL       0x1FFu      /* bits [8:0] */

/* Object type constants. */
#define CAP_OTYPE_UNSEALED  0u
#define CAP_OTYPE_SENTRY    1u

/*
 * pesbt layout (simplified compressed format)
 *   [63:48]  permissions  (16 bits)
 *   [47:32]  object type  (16 bits)
 *   [31:16]  exponent + encoded top  (16 bits, reserved)
 *   [15: 0]  encoded bottom          (16 bits, reserved)
 *
 * The lower 32 bits are reserved for a future full CHERI-128 compressed
 * encoding.  For now, decompressed base/top are carried alongside pesbt
 * so that all operations remain exact.
 */
#define CAP_PESBT_PERMS_SHIFT   48
#define CAP_PESBT_PERMS_MASK    UINT64_C(0xFFFF000000000000)
#define CAP_PESBT_OTYPE_SHIFT   32
#define CAP_PESBT_OTYPE_MASK    UINT64_C(0x0000FFFF00000000)

/* ---------- capability type ---------- */

/*
 * 128-bit CHERI capability register.
 *
 * Stored as the compressed pesbt word plus a 64-bit cursor (virtual
 * address).  The tag bit lives out-of-band.  Decompressed base and top
 * are cached so that bounds checks and field queries are O(1) without
 * having to implement the full cc128 decompression logic.
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
 * In real hardware the resulting bounds may be rounded (widened) due to
 * the compressed representation; here we store exact bounds.  Returns
 * true if the bounds were set exactly, false if they had to be rounded
 * (currently always true).
 *
 * Precondition: the capability must be unsealed and tagged.
 */
static inline bool cap_set_bounds(cap_register_t *c, uint64_t req_length)
{
    c->_base = c->_cursor;
    c->_top  = c->_cursor + req_length;
    return true;
}

/*
 * Replace the offset (cursor − base) with @p offset.
 * Returns false if the new cursor falls outside representable bounds
 * (currently always succeeds).
 */
static inline bool cap_set_offset(cap_register_t *c, uint64_t offset)
{
    c->_cursor = c->_base + offset;
    return true;
}

/*
 * Set the cursor to an absolute address.
 * Returns false if the address is not representable (always true here).
 */
static inline bool cap_set_addr(cap_register_t *c, uint64_t addr)
{
    c->_cursor = addr;
    return true;
}

/*
 * Increment the cursor by a signed delta.
 * Returns false if the result is not representable (always true here).
 */
static inline bool cap_inc_offset(cap_register_t *c, int64_t delta)
{
    c->_cursor = (uint64_t)((int64_t)c->_cursor + delta);
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
 * Check whether an access of @p size bytes at the capability's cursor
 * is within the capability's bounds.
 *
 * The access range is [cursor, cursor + size) and must satisfy:
 *   base <= cursor  &&  cursor + size <= top
 *
 * @p size must be >= 1.  Returns true if the access is in bounds.
 */
static inline bool cap_in_bounds(const cap_register_t *c, uint64_t size)
{
    uint64_t cursor = c->_cursor;

    if (cursor < c->_base) {
        return false;
    }
    /* Guard against overflow: if cursor + size wraps, it is out of bounds. */
    if (size > c->_top - cursor) {
        return false;
    }
    return true;
}

#endif /* TARGET_RISCV_CHERI_CAP_H */
