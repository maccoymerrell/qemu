/*
 * multithreaded.c — wptrace multi-thread tracing test
 *
 * Spawns two worker threads that share a mutex-protected counter.
 * Exercises:
 *   - Thread creation (pthread_create → clone syscall)
 *   - Mutex lock/unlock (futex FUTEX_WAIT / FUTEX_WAKE round-trips)
 *   - sched_yield (voluntary scheduling)
 *   - Thread join (pthread_join → futex)
 *
 * Compiled with: -static -pthread
 * Used with plugin option: threads=1
 */

#include <pthread.h>
#include <sched.h>
#include <stdint.h>

#define ITERATIONS 20

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile uint64_t shared_sum = 0;

static void *worker(void *arg)
{
    uint64_t id = (uint64_t)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&lock);
        shared_sum += id + (uint64_t)i;
        pthread_mutex_unlock(&lock);
        sched_yield();
    }
    return NULL;
}

int main(void)
{
    pthread_t t1, t2;
    pthread_create(&t1, NULL, worker, (void *)(uintptr_t)1);
    pthread_create(&t2, NULL, worker, (void *)(uintptr_t)2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
