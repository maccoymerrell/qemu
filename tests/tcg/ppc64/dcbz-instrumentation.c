/*
 * DCBZ memory instrumentation test.
 *
 * DCBZ clears a whole cache block, and QEMU implements it with a host
 * memset() over a pointer obtained without going through a qemu_st TCG op.
 * A plugin therefore sees those stores only if the target reports them
 * explicitly, and a target that does not report them shows a program's
 * block-clearing traffic as no memory traffic at all.
 *
 * Every access this program makes to its test region is a DCBZ.  It states
 * how many accesses that is; validate-memory-counts.py fails when the mem
 * plugin saw a different number.
 *
 * Author: Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdint.h>

#define TEST_SIZE (16 * 1024)

/*
 * Aligned to its own size so the mem plugin's region rows line up with the
 * bounds printed below, the same arrangement the multiarch memory test uses.
 * Nothing but the measured loop touches it.
 */
static uint8_t test_data[TEST_SIZE] __attribute__((aligned(TEST_SIZE)));

/* A separate arena, outside the measured region, for discovering the block. */
static uint8_t probe_data[512] __attribute__((aligned(512)));

static unsigned long test_read_count;
static unsigned long test_write_count;

/*
 * The block DCBZ clears is implementation-defined, so read it off the
 * machine rather than assuming one.
 */
static unsigned probe_block_size(void)
{
    unsigned i;

    for (i = 0; i < sizeof(probe_data); i++) {
        probe_data[i] = 0xff;
    }
    __asm__ __volatile__("dcbz 0,%0" :: "r"(&probe_data[0]) : "memory");

    for (i = 0; i < sizeof(probe_data); i++) {
        if (probe_data[i] != 0) {
            return i;
        }
    }
    return 0;
}

int main(void)
{
    unsigned block = probe_block_size();
    unsigned pieces;
    unsigned long off;

    if (block == 0 || block > TEST_SIZE || (block & (block - 1)) != 0) {
        printf("bad DCBZ block size %u\n", block);
        return 1;
    }

    /*
     * A bulk transfer is reported as naturally aligned power-of-two pieces
     * of at most 16 bytes, that being the widest access the plugin memory
     * API can describe.  The region is block-aligned and the block is a
     * power of two, so the count is exact rather than an estimate.
     */
    pieces = block >= 16 ? block / 16 : 1;

    printf("Test data start: 0x%lx\n", (unsigned long)&test_data[0]);
    printf("Test data end: 0x%lx\n", (unsigned long)&test_data[TEST_SIZE]);

    for (off = 0; off + block <= TEST_SIZE; off += block) {
        __asm__ __volatile__("dcbz 0,%0" :: "r"(&test_data[off]) : "memory");
        test_write_count += pieces;
    }

    printf("Test data read: %lu\n", test_read_count);
    printf("Test data write: %lu\n", test_write_count);
    printf("dcbz block=%u pieces_per_block=%u\n", block, pieces);
    return 0;
}
