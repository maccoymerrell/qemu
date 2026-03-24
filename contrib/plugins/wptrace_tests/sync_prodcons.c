/*
 * sync_prodcons.c — Producer-consumer with condition variable
 *
 * Classic bounded-buffer (size 1) using pthread_mutex + pthread_cond.
 * Under the hood, glibc implements pthread_cond_wait/signal using
 * futex and atomic operations.  The classifier should detect:
 *
 *   - Spin-acquire regions from mutex lock contention
 *   - Critical sections between lock and unlock
 *   - Release regions from mutex unlock
 *   - Happens-before edges between producer unlock and consumer lock
 *
 * The condition variable wakeup path contains atomics on the
 * internal futex word, which appear as additional atomic segments.
 *
 * Expected classifier output:
 *   - SYNC_REGION_SPIN_ACQUIRE on contended mutex
 *   - SYNC_REGION_CRITICAL_SECTION between lock/unlock
 *   - SYNC_REGION_RELEASE on unlock
 *   - HB_RELEASE_ACQUIRE edges across threads on the mutex address
 *
 * Compiled with: -static -pthread
 */

#include <pthread.h>
#include <stdint.h>

#define ITERATIONS 20

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cond_produced = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  cond_consumed = PTHREAD_COND_INITIALIZER;

static volatile int    ready = 0;
static volatile uint64_t buffer = 0;

static void *producer(void *arg)
{
    (void)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&mtx);
        while (ready) {
            pthread_cond_wait(&cond_consumed, &mtx);
        }
        buffer = (uint64_t)(i + 1) * 0x10;
        ready = 1;
        pthread_cond_signal(&cond_produced);
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

static void *consumer(void *arg)
{
    (void)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&mtx);
        while (!ready) {
            pthread_cond_wait(&cond_produced, &mtx);
        }
        volatile uint64_t val = buffer;
        (void)val;
        ready = 0;
        pthread_cond_signal(&cond_consumed);
        pthread_mutex_unlock(&mtx);
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
