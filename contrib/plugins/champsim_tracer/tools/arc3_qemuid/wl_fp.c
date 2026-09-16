/* Floating point / vectorizable workload. */
#include <stdio.h>
#include <math.h>
double a[2048], b[2048], c[2048];
int main(void)
{
    double s = 0.0;
    float f = 0.0f;
    for (int i = 0; i < 2048; i++) {
        a[i] = i * 0.5;
        b[i] = 1.0 / (i + 1.0);
    }
    for (int r = 0; r < 32; r++) {
        for (int i = 0; i < 2048; i++) {
            c[i] = a[i] * b[i] + c[i];
        }
    }
    for (int i = 0; i < 2048; i++) {
        s += sqrt(fabs(c[i])) + sin(b[i]) * log(a[i] + 1.0);
        f += (float)(c[i] * 0.25);
    }
    printf("fp %.6f %.6f %ld\n", s, (double)f, lrint(s));
    return 0;
}
