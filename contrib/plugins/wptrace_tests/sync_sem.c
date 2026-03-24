/*
 * sync_sem.c — POSIX counting semaphore test
 *
 * Tests both contended (spinning) and uncontended semaphore paths.
 * POSIX sem_wait internally performs an atomic decrement/compare loop;
 * under contention this manifests as repeated atomic accesses to the
 * same address — a spin-wait.
 *
 * The test uses a semaphore initialized to 1 (binary), so producer
 * and consumer alternate.  Under single-vCPU QEMU tracing, the
 * atomic decrement loop in the glibc sem_wait implementation should
 * produce detectable spin runs.
 *
 * Expected classifier output:
 *   - SYNC_REGION_SPIN_ACQUIRE where sem_wait retries
 *   - SYNC_REGION_CRITICAL_SECTION between wait and post
 *   - SYNC_REGION_RELEASE on sem_post
 *
 * Compiled with: -static -pthread
 */

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>

#define ITERATIONS 30

static sem_t sem;
static volatile uint64_t shared_data = 0;

static void *producer(void *arg)
{
    (void)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        sem_wait(&sem);
        shared_data = (uint64_t)(i + 1);
        sem_post(&sem);
    }
    return NULL;
}

static void *consumer(void *arg)
{
    (void)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        sem_wait(&sem);
        volatile uint64_t val = shared_data;
        (void)val;
        sem_post(&sem);
    }
    return NULL;
}

int main(void)
{
    sem_init(&sem, 0, 1);

    pthread_t t1, t2;
    pthread_create(&t1, NULL, producer, NULL);
    pthread_create(&t2, NULL, consumer, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    sem_destroy(&sem);
    return 0;
}
