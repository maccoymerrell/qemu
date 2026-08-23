#include <stdio.h>
#include "sysdep.h"
#include "opcode/mips.h"
int main(void){
  int isa_r2=ISA_MIPS32R2, isa_r6=ISA_MIPS32R6, isa64=ISA_MIPS64R2;
  int ase=(ASE_DSP|ASE_DSPR2|ASE_DSPR3|ASE_MSA|ASE_MT|ASE_EVA|ASE_VIRT|ASE_GINV|ASE_CRC|ASE_MIPS3D);
  int aseall=(ASE_DSP|ASE_DSP64|ASE_DSPR2|ASE_DSPR3|ASE_MSA|ASE_MSA64|ASE_MT|ASE_EVA|ASE_VIRT|ASE_VIRT64|
              ASE_GINV|ASE_CRC|ASE_CRC64|ASE_MIPS3D|ASE_MCU|ASE_XPA|ASE_XPA_VIRT|ASE_SMARTMIPS|ASE_MDMX|ASE_EVA_R6);
  int tot=0,mac=0,r2=0,r6only=0,m64only=0,none=0,r2mac=0;
  for(int i=0;i<bfd_mips_num_opcodes;i++){
    const struct mips_opcode*o=&mips_opcodes[i];
    if(!o->name) continue; tot++;
    int m=(o->pinfo==INSN_MACRO);
    int a=opcode_is_member(o,isa_r2,ase,0);
    int b=opcode_is_member(o,isa_r6,aseall,0);
    int c=opcode_is_member(o,isa64,aseall,0);
    if(m){mac++; if(a)r2mac++; continue;}
    if(a){r2++;continue;}
    if(b){r6only++;continue;}
    if(c){m64only++;continue;}
    none++;
  }
  printf("mips_opcodes rows            = %d\n",tot);
  printf("  assembler macros           = %d  (of which mipsel-scope %d)\n",mac,r2mac);
  printf("  mipsel-scope (r2+ASEs)     = %d\n",r2);
  printf("  r6-only (not r2)           = %d\n",r6only);
  printf("  mips64-only (not r2/r6)    = %d\n",m64only);
  printf("  other cpu/ase-only         = %d\n",none);
  return 0;
}
