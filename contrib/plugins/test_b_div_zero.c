/*
 * Test (b): Integer divide-by-zero on wrong-path
 *
 * This test creates a scenario where:
 * - Correct path: never divides by zero
 * - Wrong path: attempts divide by zero, leading to exception
 * - Large loop to test smith predictor behavior
 * - If wrong-path doesn't exit loop on first block, it should stay in loop
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define LOOP_SIZE 1000

volatile int result = 0;
volatile int condition = 1;

__attribute__((noinline))
int safe_divide(int a, int b) {
    if (b == 0) {
        return 0;  /* Safe fallback */
    }
    return a / b;
}

__attribute__((noinline))
int unsafe_divide(int a, int b) {
    /* This will cause exception if b is 0 */
    return a / b;
}

int main(int argc, char **argv) {
    int sum = 0;

    /* Large loop for smith predictor testing */
    for (int i = 0; i < LOOP_SIZE; i++) {
        /* Predictable branch - usually taken */
        int cond = (i < LOOP_SIZE - 1) ? 1 : 0;

        if (cond) {
            /* Correct path - safe division */
            sum += safe_divide(i, i + 1);
        } else {
            /* Wrong path - divide by zero! */
            sum += unsafe_divide(i, 0);
        }

        /* Loop continues - smith predictor should keep wrong-path in loop */
        result = sum;
    }

    printf("Result: %d\n", result);
    return 0;
}
