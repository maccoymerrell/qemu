/*
 * sync_spsc.c — Lock-free single-producer single-consumer (SPSC) queue
 *
 * Tests store-release / load-acquire ordering without any spin-lock.
 * The producer writes a data slot then publishes it with an atomic
 * store-release to a sequence counter.  The consumer spin-reads the
 * counter with atomic load-acquire, then reads the data.
 *
 * This is the minimal lock-free pattern: no CAS, no RMW — just
 * ordered loads and stores.  The classifier should detect:
 *
 *   - SYNC_REGION_SPIN_ACQUIRE on the consumer's polling loop
 *     (repeated atomic load of seq_num, same address)
 *   - SYNC_REGION_RELEASE on the producer's atomic store
 *   - HB_RELEASE_ACQUIRE edge from producer's store to consumer's
 *     successful load
 *
 * Compiled with: -static -pthread
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>

#define QUEUE_SIZE 16
#define NUM_ITEMS  40

/* Ring buffer */
static volatile uint64_t ring[QUEUE_SIZE];

/* Published write index (store-release / load-acquire) */
static atomic_uint write_idx = 0;

/* Consumer read index — producer polls this for backpressure */
static atomic_uint read_idx = 0;

static volatile uint64_t consumed_sum = 0;

static void *producer(void *arg)
{
    (void)arg;
    for (unsigned i = 0; i < NUM_ITEMS; i++) {
        /* Wait for space: stall while ring is full */
        while (i - atomic_load_explicit(&read_idx, memory_order_acquire)
               >= QUEUE_SIZE) {
            sched_yield();
        }

        ring[i % QUEUE_SIZE] = (uint64_t)(i + 1) * 0x100;

        /* Publish — this is the store-release sync point */
        atomic_store_explicit(&write_idx, i + 1, memory_order_release);
    }
    return NULL;
}

static void *consumer(void *arg)
{
    (void)arg;
    uint64_t sum = 0;
    for (unsigned i = 0; i < NUM_ITEMS; i++) {
        /* Spin-poll until producer publishes slot i */
        while (atomic_load_explicit(&write_idx, memory_order_acquire) <= i) {
            sched_yield();
        }

        sum += ring[i % QUEUE_SIZE];

        /* Notify producer that slot is consumed */
        atomic_store_explicit(&read_idx, i + 1, memory_order_release);
    }
    consumed_sum = sum;
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
