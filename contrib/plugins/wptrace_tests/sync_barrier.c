/*
 * sync_barrier.c — Barrier synchronization test
 *
 * N threads all increment a shared atomic counter then spin-wait
 * until all N have arrived.  This is a manual sense-reversing
 * barrier — identical to what pthread_barrier_wait does internally
 * but kept explicit so the atomic pattern is guaranteed regardless
 * of the C library implementation.
 *
 * The classifier should detect:
 *   - Multiple threads spin-waiting on the same atomic address
 *   - Cluster span within BARRIER_MAX_CLUSTER_SPAN
 *   - Distinct thread count >= BARRIER_MIN_THREADS
 *   → Reclassified from SPIN_ACQUIRE to BARRIER_WAIT
 *   → HB_BARRIER edges between post-barrier segments
 *
 * Compiled with: -static -pthread
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>

#define NUM_THREADS 2
#define NUM_ROUNDS  3

static atomic_uint barrier_count = 0;
static atomic_uint barrier_sense = 0;

static volatile uint64_t work_result[NUM_THREADS];

static void barrier_wait(unsigned my_sense)
{
    unsigned arrived = atomic_fetch_add_explicit(
        &barrier_count, 1, memory_order_acq_rel);

    if (arrived + 1 == NUM_THREADS) {
        /* Last to arrive: reset count and flip sense */
        atomic_store_explicit(&barrier_count, 0, memory_order_relaxed);
        atomic_store_explicit(&barrier_sense, my_sense, memory_order_release);
    } else {
        /* Spin until the sense flag flips */
        while (atomic_load_explicit(&barrier_sense, memory_order_acquire)
               != my_sense) {
            sched_yield();
        }
    }
}

static void *worker(void *arg)
{
    unsigned id = (unsigned)(uintptr_t)arg;
    unsigned sense = 1;

    for (int round = 0; round < NUM_ROUNDS; round++) {
        /* Phase 1: independent work */
        work_result[id] = (uint64_t)(id + 1) * (uint64_t)(round + 1);

        /* Phase 2: barrier — all threads must arrive before continuing */
        barrier_wait(sense);
        sense = !sense;

        /* Phase 3: read another thread's result (inter-thread dependency) */
        volatile uint64_t peer = work_result[(id + 1) % NUM_THREADS];
        (void)peer;
    }

    return NULL;
}

int main(void)
{
    pthread_t threads[NUM_THREADS];

    for (unsigned i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, (void *)(uintptr_t)i);
    }

    for (unsigned i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
