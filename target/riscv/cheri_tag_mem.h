/*
 * CHERI Tag Memory Subsystem for RISC-V
 *
 * Each capability-sized (16-byte) aligned granule in physical memory has an
 * associated 1-bit tag.  Tags are stored in a hash table keyed by the
 * physical page number, with one bit per CHERI_CAP_SIZE-aligned slot inside
 * the page.
 *
 * When a capability store (SC) writes 16 bytes and the stored value is
 * tagged, the corresponding tag bit is set.  Any non-capability store that
 * overlaps a capability-aligned granule clears its tag bit.  Capability
 * loads (LC) read the tag bit back.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2023 University of Cambridge
 * Copyright (c) 2020-2023 SRI International
 */

#ifndef TARGET_RISCV_CHERI_TAG_MEM_H
#define TARGET_RISCV_CHERI_TAG_MEM_H

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "exec/hwaddr.h"
#include "cheri_cap.h"

/*
 * Number of capability slots per page.
 * For 4 KiB pages and 16-byte capabilities: 4096 / 16 = 256 slots.
 * We store 256 bits = 32 bytes per page.
 */
#define CHERI_PAGE_BITS       12
#define CHERI_PAGE_SIZE       (1 << CHERI_PAGE_BITS)
#define CHERI_TAGS_PER_PAGE   (CHERI_PAGE_SIZE / CHERI_CAP_SIZE)
#define CHERI_TAG_BYTES       (CHERI_TAGS_PER_PAGE / 8)  /* 32 */

/*
 * Tag page: stores CHERI_TAGS_PER_PAGE bits (one per cap-aligned slot).
 */
typedef struct CheriTagPage {
    uint8_t tags[CHERI_TAG_BYTES];
} CheriTagPage;

/*
 * Initialise the global tag memory hash table.
 * Called once during CPU initialisation if CHERI is enabled.
 */
void cheri_tag_init(void);

/*
 * Get the tag bit for a capability-aligned physical address.
 * @paddr must be CHERI_CAP_SIZE-aligned.
 * Returns true if the tag is set, false otherwise.
 */
bool cheri_tag_get(hwaddr paddr);

/*
 * Set the tag bit for a capability-aligned physical address.
 * @paddr must be CHERI_CAP_SIZE-aligned.
 */
void cheri_tag_set(hwaddr paddr);

/*
 * Clear the tag bit for the granule containing @paddr.
 * Used when a non-capability store overlaps a capability-aligned region.
 */
void cheri_tag_clear(hwaddr paddr);

/*
 * Clear all tag bits for a whole page.
 * @page_paddr must be page-aligned.
 */
void cheri_tag_clear_page(hwaddr page_paddr);

#endif /* TARGET_RISCV_CHERI_TAG_MEM_H */
