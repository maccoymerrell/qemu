/*
 * Test (c): Basic block loop of 5 total basic blocks
 *
 * This test creates a scenario with exactly 5 basic blocks in a loop:
 * - Block 1: Loop header
 * - Block 2: First branch target
 * - Block 3: Second branch target
 * - Block 4: Third branch target
 * - Block 5: Loop exit
 *
 * The wrong-path should follow the loop structure (smith predictor test).
 * Unless exiting upon the block, wrong-path should remain in loop.
 */

#include <stdio.h>
#include <stdint.h>

#define ITERATIONS 100

volatile int counter = 0;

__attribute__((noinline))
void five_block_loop() {
    int i = 0;

    while (i < ITERATIONS) {  /* Block 1: Loop header */
        counter++;

        if (i % 4 == 0) {      /* Block 2 */
            counter += 1;
        } else if (i % 4 == 1) {  /* Block 3 */
            counter += 2;
        } else if (i % 4 == 2) {  /* Block 4 */
            counter += 3;
        } else {                  /* Block 5: else case */
            counter += 4;
        }

        i++;  /* Increment and loop back */
    }
    /* Block 5 alternative: Loop exit */
}

int main(int argc, char **argv) {
    /* Run the loop multiple times to establish pattern */
    for (int run = 0; run < 10; run++) {
        five_block_loop();
    }

    printf("Counter: %d\n", counter);
    return 0;
}
