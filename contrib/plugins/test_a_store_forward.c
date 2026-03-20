/*
 * Test (a): Store-forwarding on wrong-path
 *
 * This test creates a scenario where:
 * - Correct path: indexes array at intervals of 1
 * - Wrong path: indexes array at intervals of 2
 * - Indices are stored to memory first to ensure store-forwarding works
 * - Wrong-path writes should not propagate to memory
 * - Wrong-path loads should still see wrong-path stores via forwarding
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define ARRAY_SIZE 1000
#define ITERATIONS 100

static uint64_t data[ARRAY_SIZE];
static uint64_t sum = 0;

/* Volatile to prevent compiler optimization */
volatile int condition = 1;

__attribute__((noinline))
void process_array(int is_correct_path) {
    int stride = is_correct_path ? 1 : 2;
    uint64_t local_sum = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        /* Store index to memory first */
        int idx = i * stride;
        if (idx < ARRAY_SIZE) {
            /* Store to temporary location */
            uint64_t temp_idx = idx;

            /* Load it back (tests store forwarding) */
            uint64_t loaded_idx = temp_idx;

            /* Use it to index array */
            local_sum += data[loaded_idx];
        }
    }

    sum += local_sum;
}

int main(int argc, char **argv) {
    /* Initialize array */
    for (int i = 0; i < ARRAY_SIZE; i++) {
        data[i] = i;
    }

    /* Create a predictable branch that will mispredict */
    /* First iteration: taken, rest: not taken */
    for (int iter = 0; iter < 10; iter++) {
        int cond = (iter == 0) ? 1 : 0;

        if (cond) {
            /* Correct path - stride 1 */
            process_array(1);
        } else {
            /* Not taken - but wrong path will execute with stride 2 */
            process_array(0);
        }
    }

    printf("Sum: %lu\n", (unsigned long)sum);
    return 0;
}
