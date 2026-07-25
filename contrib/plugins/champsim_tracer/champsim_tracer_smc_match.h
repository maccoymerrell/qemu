/*
 * Wrong-Path Tracing Plugin — self-modifying-code match discriminator.
 *
 * The pure function that decides how a freshly-assembled true BB relates to
 * the template already committed at the same (asid_root, start_pc): unchanged
 * code, self-modified code (which mints a template revision), or the same code
 * assembled over a different extent (which mints nothing).
 *
 * It lives in its own dependency-light header — <cstdint> / <cstring> only —
 * so the decision can be exercised directly by a host-side truth-table test
 * (validator ``features.smc`` / ``smc_discriminator``).  The extent-artifact
 * branch is not reachable from a user-mode guest program, so a runtime
 * workload cannot cover it; the truth table can.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_SMC_MATCH_H
#define CHAMPSIM_TRACER_SMC_MATCH_H

#include <cstdint>
#include <cstring>

/*
 * How incoming canonical arrays relate to an already-committed template at the
 * same (asid_root, start_pc).  The discriminator is the OVERLAPPING PREFIX:
 * the first min(old_n, new_n) instructions, compared at PC-aligned positions.
 *
 *   EXACT        — identical instruction sequence AND byte-identical (the
 *                  non-SMC reuse; the overwhelmingly common case).
 *   SMC          — an overlapping instruction's SIZE or BYTE IMAGE differs:
 *                  genuine self-modification.  This test is SHAPE-AGNOSTIC.
 *                  The rewrite may keep the block's instruction boundaries (an
 *                  in-place immediate/opcode patch), move them (kernel
 *                  alternatives and static-key patching, JIT re-emission), or
 *                  change the instruction count outright.  A revision is just
 *                  a new template id, and the wire represents that fine
 *                  whatever the new block's shape is (smc_plan.md §1).
 *   EXTENT_ONLY  — every overlapping instruction agrees byte for byte and only
 *                  the block's EXTENT differs: the chain was finalised over a
 *                  different run of the same code (BB folding sealed at a
 *                  different terminator, a page-split fragment, a chain
 *                  force-committed by the fault machinery).  That is an
 *                  assembly artifact, not a code change, so it mints nothing
 *                  and the committed template is kept.
 *
 * Why the prefix walk catches every boundary move: a template's byte image is
 * a ZERO-PADDED fixed-stride copy of the instruction's real bytes, so an
 * instruction whose length changed cannot compare equal to the instruction
 * previously recorded at the same PC.  The first instruction a rewrite touches
 * therefore always shows a byte-image difference, however the boundaries
 * downstream of it land.
 *
 * Why a PC divergence past a byte-identical prefix is never SMC: the
 * instructions of a true BB are contiguous, so pcs[i] is determined by
 * pcs[i - 1] + sizes[i - 1].  If every overlapping instruction up to i matched
 * in PC, size and bytes, position i must match in PC too — a divergence there
 * means the two arrays stopped covering the same run of code, i.e. an extent
 * artifact.  Position 0 is the one exception (both arrays are anchored at
 * start_pc, but a caller could re-anchor): there the byte comparison at the
 * shared start_pc decides.
 *
 * @stride is the fixed per-instruction byte-image stride of both arrays
 * (MAX_INSN_BYTES for the plugin's templates).
 */
enum class BBMatch { EXACT, SMC, EXTENT_ONLY };

static inline BBMatch cst_classify_bb_match(
    uint32_t old_n, const uint64_t *old_pcs,
    const uint8_t *old_sizes, const uint8_t *old_bytes,
    uint32_t new_n, const uint64_t *new_pcs,
    const uint8_t *new_sizes, const uint8_t *new_bytes,
    uint32_t stride)
{
    const uint32_t common = old_n < new_n ? old_n : new_n;
    bool pcs_aligned = true;

    for (uint32_t i = 0; i < common; i++) {
        if (i > 0 && old_pcs[i] != new_pcs[i]) {
            pcs_aligned = false;      /* re-anchored past a matching prefix */
            break;
        }
        if (old_sizes[i] != new_sizes[i] ||
            memcmp(&old_bytes[(size_t)i * stride],
                   &new_bytes[(size_t)i * stride], stride) != 0) {
            return BBMatch::SMC;
        }
        if (i == 0 && old_pcs[0] != new_pcs[0]) {
            /* Same bytes at a re-anchored start: not a code change. */
            pcs_aligned = false;
            break;
        }
    }

    if (pcs_aligned && old_n == new_n) {
        return BBMatch::EXACT;
    }
    return BBMatch::EXTENT_ONLY;
}

#endif /* CHAMPSIM_TRACER_SMC_MATCH_H */
