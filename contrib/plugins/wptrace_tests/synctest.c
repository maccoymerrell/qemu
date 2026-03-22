/*
 * synctest.c — wptrace synchronization tracing test
 *
 * Exercises inter-thread synchronization primitives to validate that
 * the trace emits the information a simulator needs to infer
 * dependencies between threads:
 *
 *   - C11 atomic flag (spinlock) → sync=ATOMIC on load/store instructions
 *   - Atomic counter increment   → sync=ATOMIC with shared address
 *   - pthread_mutex_lock/unlock  → FUTEX_WAKE sync events
 *   - sched_yield                → YIELD sync events
 *   - THREAD_SWITCH              → thread interleaving markers
 *
 * A consuming simulator uses sync=ATOMIC annotations plus memory
 * addresses from MEMDATA records to track synchronization objects.
 * Two threads touching the same sync address implies a dependency;
 * between sync points, threads may execute in parallel.
 *
 * Compiled with: -static -pthread
 * Used with plugin option: threads=1
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>

#define ITERATIONS 10

/* Atomic flag used as a simple spinlock */
static atomic_flag spinlock = ATOMIC_FLAG_INIT;

/* Shared counter protected by the spinlock */
static volatile uint64_t shared_counter = 0;

/* Atomic sequence number for producer-consumer ordering */
static atomic_uint seq_num = 0;

/* Data buffer: producer writes, consumer reads after sync */
static volatile uint64_t data_buf[ITERATIONS];

static void spin_lock(void)
{
    while (atomic_flag_test_and_set_explicit(&spinlock, memory_order_acquire)) {
        /* spin */
    }
}

static void spin_unlock(void)
{
    atomic_flag_clear_explicit(&spinlock, memory_order_release);
}

/*
 * Producer: writes data_buf[i] then atomically publishes seq_num.
 * The atomic store to seq_num is the synchronization point.
 */
static void *producer(void *arg)
{
    (void)arg;
    for (unsigned i = 0; i < ITERATIONS; i++) {
        spin_lock();
        shared_counter++;
        spin_unlock();

        data_buf[i] = (uint64_t)(i + 1) * 0x100;
        atomic_store_explicit(&seq_num, i + 1, memory_order_release);
        sched_yield();
    }
    return NULL;
}

/*
 * Consumer: waits for seq_num to advance then reads data_buf[i].
 * The atomic load from seq_num is the synchronization point.
 */
static void *consumer(void *arg)
{
    (void)arg;
    for (unsigned i = 0; i < ITERATIONS; i++) {
        while (atomic_load_explicit(&seq_num, memory_order_acquire) <= i) {
            sched_yield();
        }
        /* Read the published data (will appear in MEMDATA if enabled) */
        volatile uint64_t val = data_buf[i];
        (void)val;

        spin_lock();
        shared_counter++;
        spin_unlock();
    }
    return NULL;
}

int main(void)
{
    pthread_t t1, t2;
    pthread_create(&t1, NULL, producer, NULL);
    pthread_create(&t2, NULL, consumer, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
