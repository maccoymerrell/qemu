/* Per-hex XED iform + length + immediate width, for verifying that a
 * re-encoded field variant still names the SAME opcode.  ARC 3 x86_64
 * attribution sweep.
 *
 * The immediate width is here because mkprobe.py needs to know whether the
 * trailing byte of a probe IS an immediate before it may re-seat it.  Asking
 * the reference decoder is the only honest way to know: guessing from the
 * opcode byte would re-seat a ModRM or a displacement and silently probe a
 * different instruction.  Width is in BYTES and is the width of the FIRST
 * immediate, so an ENTER-shaped `imm16, imm8` reports 2 and is thereby
 * excluded from single-immediate handling by the same number.
 * Author: Maccoy Merrell. */
#include <stdio.h>
#include "xed/xed-interface.h"
static int hn(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
                       if(c>='A'&&c<='F')return c-'A'+10; return -1; }
int main(int argc,char**argv){
    xed_tables_init();
    FILE* f = argc>1 ? fopen(argv[1],"r") : stdin;
    if(!f){ perror("open"); return 2; }
    char line[128];
    printf("hex\tok\tlen\timmw\tiform\n");
    while(fgets(line,sizeof line,f)){
        xed_uint8_t buf[32]; unsigned m=0;
        for(size_t i=0;line[i]&&line[i+1]&&m<32;i+=2){ int a=hn(line[i]),b=hn(line[i+1]);
            if(a<0||b<0)break; buf[m++]=(xed_uint8_t)((a<<4)|b); }
        if(!m) continue;
        char hx[80]; for(unsigned i=0;i<m;i++) sprintf(hx+2*i,"%02x",buf[i]);
        xed_decoded_inst_t d; xed_decoded_inst_zero(&d);
        xed_decoded_inst_set_mode(&d,XED_MACHINE_MODE_LONG_64,XED_ADDRESS_WIDTH_64b);
        xed3_operand_set_cet(&d,1);
        if(xed_decode(&d,buf,m)!=XED_ERROR_NONE){ printf("%s\t0\t0\t0\t-\n",hx); continue; }
        printf("%s\t1\t%u\t%u\t%s\n",hx,xed_decoded_inst_get_length(&d),
               xed_decoded_inst_get_immediate_width(&d),
               xed_iform_enum_t2str(xed_decoded_inst_get_iform_enum(&d)));
    }
    return 0;
}
