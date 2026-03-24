/*
 * sync_rwlock.c — Read-write lock test
 *
 * Multiple readers and one writer contend on a simple spin-based
 * read-write lock implemented with atomics.  The RWLock uses an
 * atomic int: positive = reader count, -1 = writer held, 0 = free.
 *
 * This tests a more complex sync pattern than a simple mutex:
 *   - Multiple readers can hold the lock simultaneously
 *   - Writer must wait for all readers to release
 *   - Reader-acquire is an atomic CAS loop (spin)
 *   - Writer-acquire is an atomic CAS loop (spin)
 *   - Release is an atomic decrement (readers) or store (writer)
 *
 * Expected classifier output:
 *   - SYNC_REGION_SPIN_ACQUIRE for both reader and writer contention
 *   - SYNC_REGION_CRITICAL_SECTION while lock is held
 *   - SYNC_REGION_RELEASE on lock release
 *   - Multiple concurrent reader critical sections (different threads,
 *     overlapping in trace order)
 *
 * Compiled with: -static -pthread
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>

#define NUM_READERS  3
#define NUM_WRITERS  1
#define READ_ITERS   20
#define WRITE_ITERS  10

/* Atomic lock state: 0=free, >0=reader count, -1=writer held */
static atomic_int rwlock_state = 0;

static volatile unsigned long shared_data = 0;
static volatile unsigned long read_sum = 0;

static void read_lock(void)
{
    for (;;) {
        int expected = atomic_load_explicit(&rwlock_state,
                                            memory_order_relaxed);
        if (expected >= 0) {
            if (atomic_compare_exchange_weak_explicit(
                    &rwlock_state, &expected, expected + 1,
                    memory_order_acquire, memory_order_relaxed)) {
                return;
            }
        }
        sched_yield();
    }
}

static void read_unlock(void)
{
    atomic_fetch_sub_explicit(&rwlock_state, 1, memory_order_release);
}

static void write_lock(void)
{
    for (;;) {
        int expected = 0;
        if (atomic_compare_exchange_weak_explicit(
                &rwlock_state, &expected, -1,
                memory_order_acquire, memory_order_relaxed)) {
            return;
        }
        sched_yield();
    }
}

static void write_unlock(void)
{
    atomic_store_explicit(&rwlock_state, 0, memory_order_release);
}

static void *reader(void *arg)
{
    (void)arg;
    unsigned long local_sum = 0;
    for (int i = 0; i < READ_ITERS; i++) {
        read_lock();
        local_sum += shared_data;
        read_unlock();
        sched_yield();
    }
    atomic_fetch_add((_Atomic unsigned long *)&read_sum, local_sum);
    return NULL;
}

static void *writer(void *arg)
{
    (void)arg;
    for (int i = 0; i < WRITE_ITERS; i++) {
        write_lock();
        shared_data = (unsigned long)(i + 1);
        write_unlock();
        sched_yield();
    }
    return NULL;
}

int main(void)
{
    pthread_t readers[NUM_READERS];
    pthread_t writers[NUM_WRITERS];

    for (int i = 0; i < NUM_WRITERS; i++) {
        pthread_create(&writers[i], NULL, writer, NULL);
    }
    for (int i = 0; i < NUM_READERS; i++) {
        pthread_create(&readers[i], NULL, reader, NULL);
    }

    for (int i = 0; i < NUM_WRITERS; i++) {
        pthread_join(writers[i], NULL);
    }
    for (int i = 0; i < NUM_READERS; i++) {
        pthread_join(readers[i], NULL);
    }

    return 0;
}
