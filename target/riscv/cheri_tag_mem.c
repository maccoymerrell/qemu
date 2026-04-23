/*
 * CHERI Tag Memory Subsystem for RISC-V — Implementation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2023 University of Cambridge
 * Copyright (c) 2020-2023 SRI International
 */

#include "qemu/osdep.h"
#include "cheri_tag_mem.h"

/*
 * We use a simple GHashTable keyed by page-frame number (paddr >> 12).
 * The value is a heap-allocated CheriTagPage.
 * Pages that have never been written with a capability are not present
 * in the table (implicit all-zero tags).
 *
 * A lock protects concurrent access from multiple vCPU threads.
 */
static GHashTable *tag_table;
static QemuMutex  tag_lock;

void cheri_tag_init(void)
{
    if (!tag_table) {
        qemu_mutex_init(&tag_lock);
        tag_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                          NULL, g_free);
    }
}

static inline uint64_t page_key(hwaddr paddr)
{
    return paddr >> CHERI_PAGE_BITS;
}

static inline unsigned slot_index(hwaddr paddr)
{
    return (paddr & (CHERI_PAGE_SIZE - 1)) / CHERI_CAP_SIZE;
}

/* Look up or create a tag page. Caller must hold tag_lock. */
static CheriTagPage *get_or_create_page(hwaddr paddr)
{
    uint64_t key = page_key(paddr);
    CheriTagPage *tp = g_hash_table_lookup(tag_table,
                                           GUINT_TO_POINTER(key));
    if (!tp) {
        tp = g_new0(CheriTagPage, 1);
        g_hash_table_insert(tag_table, GUINT_TO_POINTER(key), tp);
    }
    return tp;
}

bool cheri_tag_get(hwaddr paddr)
{
    bool result = false;
    uint64_t key = page_key(paddr);
    unsigned slot = slot_index(paddr);

    qemu_mutex_lock(&tag_lock);
    CheriTagPage *tp = g_hash_table_lookup(tag_table,
                                           GUINT_TO_POINTER(key));
    if (tp) {
        result = (tp->tags[slot / 8] >> (slot % 8)) & 1;
    }
    qemu_mutex_unlock(&tag_lock);
    return result;
}

void cheri_tag_set(hwaddr paddr)
{
    unsigned slot = slot_index(paddr);

    qemu_mutex_lock(&tag_lock);
    CheriTagPage *tp = get_or_create_page(paddr);
    tp->tags[slot / 8] |= (1u << (slot % 8));
    qemu_mutex_unlock(&tag_lock);
}

void cheri_tag_clear(hwaddr paddr)
{
    uint64_t key = page_key(paddr);
    unsigned slot = slot_index(paddr);

    /* Align down to capability granule */
    qemu_mutex_lock(&tag_lock);
    CheriTagPage *tp = g_hash_table_lookup(tag_table,
                                           GUINT_TO_POINTER(key));
    if (tp) {
        tp->tags[slot / 8] &= ~(1u << (slot % 8));
    }
    qemu_mutex_unlock(&tag_lock);
}

void cheri_tag_clear_page(hwaddr page_paddr)
{
    uint64_t key = page_key(page_paddr);

    qemu_mutex_lock(&tag_lock);
    CheriTagPage *tp = g_hash_table_lookup(tag_table,
                                           GUINT_TO_POINTER(key));
    if (tp) {
        memset(tp->tags, 0, CHERI_TAG_BYTES);
    }
    qemu_mutex_unlock(&tag_lock);
}
