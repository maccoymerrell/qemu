/*
 * Test (d): 20 basic blocks with value-change optimization
 *
 * This test creates a program with exactly 20 basic blocks where:
 * - Dynamic parameters (memory addresses, branch targets) only change
 *   every OTHER invocation of each basic block
 * - This tests the value-change-only optimization of the trace format
 * - Trace should only output dynamic parameters when they actually changed
 */

#include <stdio.h>
#include <stdint.h>

#define ARRAY_SIZE 100

volatile uint64_t data[ARRAY_SIZE];
volatile int selector = 0;

__attribute__((noinline))
void twenty_block_function(int iteration) {
    /* Use iteration to determine which blocks execute */
    /* Dynamic parameters alternate every other iteration */
    int idx = (iteration / 2) % ARRAY_SIZE;  /* Changes every 2 iterations */

    /* Block 1 */
    if (iteration % 20 == 0) {
        data[idx]++;
    }
    /* Block 2 */
    else if (iteration % 20 == 1) {
        data[idx] += 2;
    }
    /* Block 3 */
    else if (iteration % 20 == 2) {
        data[idx] += 3;
    }
    /* Block 4 */
    else if (iteration % 20 == 3) {
        data[idx] += 4;
    }
    /* Block 5 */
    else if (iteration % 20 == 4) {
        data[idx] += 5;
    }
    /* Block 6 */
    else if (iteration % 20 == 5) {
        data[idx] += 6;
    }
    /* Block 7 */
    else if (iteration % 20 == 7) {
        data[idx] += 7;
    }
    /* Block 8 */
    else if (iteration % 20 == 8) {
        data[idx] += 8;
    }
    /* Block 9 */
    else if (iteration % 20 == 9) {
        data[idx] += 9;
    }
    /* Block 10 */
    else if (iteration % 20 == 10) {
        data[idx] += 10;
    }
    /* Block 11 */
    else if (iteration % 20 == 11) {
        data[idx] += 11;
    }
    /* Block 12 */
    else if (iteration % 20 == 12) {
        data[idx] += 12;
    }
    /* Block 13 */
    else if (iteration % 20 == 13) {
        data[idx] += 13;
    }
    /* Block 14 */
    else if (iteration % 20 == 14) {
        data[idx] += 14;
    }
    /* Block 15 */
    else if (iteration % 20 == 15) {
        data[idx] += 15;
    }
    /* Block 16 */
    else if (iteration % 20 == 16) {
        data[idx] += 16;
    }
    /* Block 17 */
    else if (iteration % 20 == 17) {
        data[idx] += 17;
    }
    /* Block 18 */
    else if (iteration % 20 == 18) {
        data[idx] += 18;
    }
    /* Block 19 */
    else if (iteration % 20 == 19) {
        data[idx] += 19;
    }
    /* Block 20: default */
    else {
        data[idx] += 20;
    }

    selector = idx;
}

int main(int argc, char **argv) {
    /* Initialize data */
    for (int i = 0; i < ARRAY_SIZE; i++) {
        data[i] = 0;
    }

    /* Run function many times
     * Each block executed multiple times
     * Dynamic parameters (idx) change every 2 iterations
     */
    for (int i = 0; i < 200; i++) {
        twenty_block_function(i);
    }

    /* Output result */
    uint64_t sum = 0;
    for (int i = 0; i < ARRAY_SIZE; i++) {
        sum += data[i];
    }

    printf("Sum: %lu, Selector: %d\n", (unsigned long)sum, selector);
    return 0;
}
