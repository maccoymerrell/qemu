/* Integer / string / control-flow workload: broad libc reach. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int cmp(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}
int main(void)
{
    enum { N = 4096 };
    int *v = malloc(N * sizeof(int));
    char buf[256], acc[4096];
    unsigned long h = 1469598103934665603UL;
    for (int i = 0; i < N; i++) {
        v[i] = (i * 1103515245 + 12345) & 0x7fffffff;
    }
    qsort(v, N, sizeof(int), cmp);
    acc[0] = 0;
    for (int i = 0; i < 64; i++) {
        snprintf(buf, sizeof buf, "%d:%08x:%s", v[i], v[N - 1 - i], "tag");
        if (strlen(acc) + strlen(buf) + 1 < sizeof acc) {
            strcat(acc, buf);
        }
        for (const char *p = buf; *p; p++) {
            h = (h ^ (unsigned char)*p) * 1099511628211UL;
        }
    }
    memmove(acc + 1, acc, strlen(acc));
    printf("int %lx %zu %d\n", h, strlen(acc), v[N / 2]);
    free(v);
    return 0;
}
