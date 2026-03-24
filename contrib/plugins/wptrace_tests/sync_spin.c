/*
 * sync_spin.c — Pure spinlock test
 *
 * Tests spin-acquire detection.  Two threads contend on an
 * atomic_flag spinlock with enough iterations to reliably
 * produce consecutive same-address atomic segments (spin runs).
 *
 * Expected classifier output:
 *   - SYNC_REGION_SPIN_ACQUIRE regions with iteration_count >= 2
 *   - SEG_FLAG_SPIN_WAIT on retry segments
 *   - SEG_FLAG_ACQUIRE on success segment
 *   - SEG_FLAG_RELEASE on atomic_flag_clear
 *
 * Compiled with: -static -pthread
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>

#define ITERATIONS 50

static atomic_flag lock = ATOMIC_FLAG_INIT;
static volatile uint64_t counter = 0;

static void spin_lock(void)
{
    while (atomic_flag_test_and_set_explicit(&lock, memory_order_acquire)) {
        sched_yield();
    }
}

static void spin_unlock(void)
{
    atomic_flag_clear_explicit(&lock, memory_order_release);
}

static void *worker(void *arg)
{
    (void)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        spin_lock();
        counter++;
        spin_unlock();
    }
    return NULL;
}

int main(void)
{
    pthread_t t1, t2;
    pthread_create(&t1, NULL, worker, NULL);
    pthread_create(&t2, NULL, worker, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return (int)(counter != ITERATIONS * 2);
}
