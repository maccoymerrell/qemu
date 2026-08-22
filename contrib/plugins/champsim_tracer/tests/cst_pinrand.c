/*
 * cst_pinrand — equalize guest randomness across tracing instruments.
 *
 * A PIN/QEMU validation pair only means something if both instruments ran the
 * SAME guest instruction stream.  They do not by default: qemu-user's -seed
 * serves the guest's getrandom(2) from its own pinned PRNG (see the #105
 * reproducibility ruling), while a native run under PIN gets real kernel
 * entropy that differs on every execution.  Measured on this host: native
 * getrandom returns fresh bytes per run, -seed 1 returns 3c344c41... every
 * time, -seed 2 returns d1b21186... — three different streams for one guest.
 *
 * This preload makes the guest's randomness a property of the HARNESS rather
 * than of the instrument: it answers getrandom()/getentropy() from a fixed
 * keystream, so both halves of a pair see identical bytes.  It is loaded into
 * the GUEST on both sides, so the QEMU half never reaches qemu's syscall path
 * and the PIN half never reaches the kernel's.
 *
 * CST_PINRAND_HEX supplies the seed material (hex).  The keystream is a
 * counter-mode expansion of it, so a caller asking for 4 bytes and a caller
 * asking for 4096 both get a reproducible stream, and two calls do not repeat.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

static uint64_t s0 = 0x243f6a8885a308d3ULL, s1 = 0x13198a2e03707344ULL;
static int inited;

static void init_from_env(void)
{
    const char *h = getenv("CST_PINRAND_HEX");
    if (h) {
        uint64_t a = 1469598103934665603ULL;   /* FNV-1a over the hex text */
        for (const char *p = h; *p; p++) {
            a ^= (unsigned char)*p;
            a *= 1099511628211ULL;
        }
        s0 ^= a;
        s1 ^= a * 6364136223846793005ULL + 1442695040888963407ULL;
    }
    inited = 1;
}

static uint64_t next(void)
{
    /* xorshift128+ — deterministic, portable, no libc dependency. */
    uint64_t x = s0, y = s1;
    s0 = y;
    x ^= x << 23;
    s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s1 + y;
}

static void fill(void *buf, size_t len)
{
    unsigned char *p = buf;
    if (!inited) {
        init_from_env();
    }
    while (len) {
        uint64_t v = next();
        size_t n = len < sizeof v ? len : sizeof v;
        memcpy(p, &v, n);
        p += n;
        len -= n;
    }
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    (void)flags;
    fill(buf, buflen);
    return (ssize_t)buflen;
}

int getentropy(void *buf, size_t buflen)
{
    if (buflen > 256) {
        errno = EIO;
        return -1;
    }
    fill(buf, buflen);
    return 0;
}

/*
 * WHAT THIS DOES NOT COVER, measured rather than assumed.
 *
 * AT_RANDOM is out of reach.  The dynamic loader reads it to seed the stack
 * guard and the pointer guard before any preloaded object's constructor
 * exists, so a preload cannot answer for it.  Measured on this host with the
 * shim active: two native runs gave 4c985188... and ee4c8d51..., qemu -seed 1
 * gave f5b16522... and -seed 2 gave 439123a3... -- still four different
 * answers where getrandom now gives one.
 *
 * That residual is expected to move DATA and not the instruction stream: the
 * canary and the mangled pointers differ in value, but the compare-and-branch
 * around a canary takes the same edge and a demangled pointer resolves to the
 * same address.  The PIN pairing bar is alignment agreement plus raw-byte
 * agreement of the executed instructions, which that residual does not touch.
 * It has NOT been proven by measurement, and the experiment that would settle
 * it is a pair run with the shim on both halves, comparing the instruction
 * bytes and separately the register values.  Until that runs, treat "AT_RANDOM
 * does not matter" as an expectation with a stated reason, not a result.
 */
