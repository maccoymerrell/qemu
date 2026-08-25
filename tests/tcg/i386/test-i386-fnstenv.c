/*
 * FSTENV / FNSTENV mask every floating-point exception after the save.
 *
 * SDM Vol.1 8.1.10: the instruction saves the environment and then sets
 * all six exception-mask bits in the FPU control word.  The image it
 * writes still carries the control word as it was, so FLDENV of that
 * image puts the guest's masks back.
 *
 * The negative control is FXSAVE, which saves the same control word and
 * is documented NOT to mask.  Without it a test that only checked "the
 * masks are set afterwards" would also pass on a machine that masked
 * unconditionally, and would not be evidence about FNSTENV at all.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CW_MASKS   0x3f     /* IM ZM DM OM UM PM                        */
#define CW_ALL_ON  0x037f   /* every exception masked, PC=extended      */
#define CW_ALL_OFF 0x0340   /* every exception UNMASKED, PC=extended    */

static uint16_t get_cw(void)
{
    uint16_t cw;
    __asm__ volatile ("fnstcw %0" : "=m" (cw));
    return cw;
}

static void set_cw(uint16_t cw)
{
    __asm__ volatile ("fldcw %0" : : "m" (cw));
}

int main(void)
{
    /*
     * 28 bytes is the 32-bit protected-mode environment; the buffer is
     * oversized so the 16-bit form could not run off the end either.
     */
    uint8_t env_image[32];
    uint8_t fx_image[512] __attribute__((aligned(16)));
    uint16_t saved_cw, cw;
    int ret = 0;

    set_cw(CW_ALL_OFF);
    memset(env_image, 0xa5, sizeof(env_image));
    __asm__ volatile ("fnstenv %0" : "=m" (env_image) : : "memory");
    cw = get_cw();
    saved_cw = env_image[0] | ((uint16_t)env_image[1] << 8);

    if ((cw & CW_MASKS) != CW_MASKS) {
        printf("FAIL: fnstenv left cw=0x%04x, masks not set\n", cw);
        ret = 1;
    }
    if (cw != CW_ALL_ON) {
        printf("FAIL: fnstenv left cw=0x%04x, expected 0x%04x\n",
               cw, CW_ALL_ON);
        ret = 1;
    }
    if (saved_cw != CW_ALL_OFF) {
        printf("FAIL: fnstenv saved cw=0x%04x, expected the pre-save "
               "0x%04x\n", saved_cw, CW_ALL_OFF);
        ret = 1;
    }

    /* FLDENV of that image must put the unmasked control word back. */
    __asm__ volatile ("fldenv %0" : : "m" (env_image) : "memory");
    cw = get_cw();
    if (cw != CW_ALL_OFF) {
        printf("FAIL: fldenv restored cw=0x%04x, expected 0x%04x\n",
               cw, CW_ALL_OFF);
        ret = 1;
    }

    /* Negative control: FXSAVE saves the same word and masks nothing. */
    set_cw(CW_ALL_OFF);
    __asm__ volatile ("fxsave %0" : "=m" (fx_image) : : "memory");
    cw = get_cw();
    if (cw != CW_ALL_OFF) {
        printf("FAIL: fxsave changed cw to 0x%04x, expected 0x%04x\n",
               cw, CW_ALL_OFF);
        ret = 1;
    }

    set_cw(CW_ALL_ON);
    return ret;
}
