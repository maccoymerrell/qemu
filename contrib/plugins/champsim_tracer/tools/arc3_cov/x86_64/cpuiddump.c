/* dump the CPUID leaves a QEMU x86_64 TCG guest is shown, for one -cpu model */
#include <stdio.h>
#include <stdint.h>
static void cid(uint32_t l, uint32_t s, uint32_t r[4])
{ __asm__ volatile("cpuid" : "=a"(r[0]),"=b"(r[1]),"=c"(r[2]),"=d"(r[3])
                   : "a"(l),"c"(s)); }
int main(void)
{
    uint32_t r[4], max, xmax;
    cid(0,0,r); max = r[0];
    cid(0x80000000,0,r); xmax = r[0];
    for (uint32_t l = 0; l <= max && l < 0x40; l++)
        for (uint32_t s = 0; s < 4; s++) {
            cid(l,s,r);
            printf("%x\t%x\t%08x\t%08x\t%08x\t%08x\n", l,s,r[0],r[1],r[2],r[3]);
            if (l != 7 && l != 0xd && l != 0x12 && l != 0x14 && l != 0x1d) break;
        }
    for (uint32_t l = 0x80000000; l <= xmax && l <= 0x80000030; l++) {
        cid(l,0,r);
        printf("%x\t0\t%08x\t%08x\t%08x\t%08x\n", l,r[0],r[1],r[2],r[3]);
    }
    return 0;
}
