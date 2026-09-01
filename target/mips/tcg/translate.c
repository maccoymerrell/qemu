/*
 *  MIPS emulation for QEMU - main translation routines
 *
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *  Copyright (c) 2006 Marius Groeger (FPU operations)
 *  Copyright (c) 2006 Thiemo Seufer (MIPS32R2 support)
 *  Copyright (c) 2009 CodeSourcery (MIPS16 and microMIPS support)
 *  Copyright (c) 2012 Jia Liu & Dongxue Zhang (MIPS ASE DSP support)
 *  Copyright (c) 2020 Philippe Mathieu-Daudé
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "translate.h"
#include "internal.h"
#include "exec/helper-proto.h"
#include "exec/plugin-gen.h"
#include "exec/insn-dataflow.h"
#include "exec/translation-block.h"
#include "semihosting/semihost.h"
#include "trace.h"
#include "fpu_helper.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef  HELPER_H


/*
 * Many system-only helpers are not reachable for user-only.
 * Define stub generators here, so that we need not either sprinkle
 * ifdefs through the translator, nor provide the helper function.
 */
#define STUB_HELPER(NAME, ...) \
    static inline void gen_helper_##NAME(__VA_ARGS__) \
    { g_assert_not_reached(); }

#ifdef CONFIG_USER_ONLY
STUB_HELPER(cache, TCGv_env env, TCGv val, TCGv_i32 reg)
#endif

enum {
    /* indirect opcode tables */
    OPC_SPECIAL  = (0x00 << 26),
    OPC_REGIMM   = (0x01 << 26),
    OPC_CP0      = (0x10 << 26),
    OPC_CP2      = (0x12 << 26),
    OPC_CP3      = (0x13 << 26),
    OPC_SPECIAL2 = (0x1C << 26),
    OPC_SPECIAL3 = (0x1F << 26),
    /* arithmetic with immediate */
    OPC_ADDI     = (0x08 << 26),
    OPC_ADDIU    = (0x09 << 26),
    OPC_SLTI     = (0x0A << 26),
    OPC_SLTIU    = (0x0B << 26),
    /* logic with immediate */
    OPC_ANDI     = (0x0C << 26),
    OPC_ORI      = (0x0D << 26),
    OPC_XORI     = (0x0E << 26),
    OPC_LUI      = (0x0F << 26),
    /* arithmetic with immediate */
    OPC_DADDI    = (0x18 << 26),
    OPC_DADDIU   = (0x19 << 26),
    /* Jump and branches */
    OPC_J        = (0x02 << 26),
    OPC_JAL      = (0x03 << 26),
    OPC_BEQ      = (0x04 << 26),  /* Unconditional if rs = rt = 0 (B) */
    OPC_BEQL     = (0x14 << 26),
    OPC_BNE      = (0x05 << 26),
    OPC_BNEL     = (0x15 << 26),
    OPC_BLEZ     = (0x06 << 26),
    OPC_BLEZL    = (0x16 << 26),
    OPC_BGTZ     = (0x07 << 26),
    OPC_BGTZL    = (0x17 << 26),
    OPC_JALX     = (0x1D << 26),
    OPC_DAUI     = (0x1D << 26),
    /* Load and stores */
    OPC_LDL      = (0x1A << 26),
    OPC_LDR      = (0x1B << 26),
    OPC_LB       = (0x20 << 26),
    OPC_LH       = (0x21 << 26),
    OPC_LWL      = (0x22 << 26),
    OPC_LW       = (0x23 << 26),
    OPC_LWPC     = OPC_LW | 0x5,
    OPC_LBU      = (0x24 << 26),
    OPC_LHU      = (0x25 << 26),
    OPC_LWR      = (0x26 << 26),
    OPC_LWU      = (0x27 << 26),
    OPC_SB       = (0x28 << 26),
    OPC_SH       = (0x29 << 26),
    OPC_SWL      = (0x2A << 26),
    OPC_SW       = (0x2B << 26),
    OPC_SDL      = (0x2C << 26),
    OPC_SDR      = (0x2D << 26),
    OPC_SWR      = (0x2E << 26),
    OPC_LL       = (0x30 << 26),
    OPC_LLD      = (0x34 << 26),
    OPC_LD       = (0x37 << 26),
    OPC_LDPC     = OPC_LD | 0x5,
    OPC_SC       = (0x38 << 26),
    OPC_SCD      = (0x3C << 26),
    OPC_SD       = (0x3F << 26),
    /* Floating point load/store */
    OPC_LWC1     = (0x31 << 26),
    OPC_LWC2     = (0x32 << 26),
    OPC_LDC1     = (0x35 << 26),
    OPC_LDC2     = (0x36 << 26),
    OPC_SWC1     = (0x39 << 26),
    OPC_SWC2     = (0x3A << 26),
    OPC_SDC1     = (0x3D << 26),
    OPC_SDC2     = (0x3E << 26),
    /* Compact Branches */
    OPC_BLEZALC  = (0x06 << 26),
    OPC_BGEZALC  = (0x06 << 26),
    OPC_BGEUC    = (0x06 << 26),
    OPC_BGTZALC  = (0x07 << 26),
    OPC_BLTZALC  = (0x07 << 26),
    OPC_BLTUC    = (0x07 << 26),
    OPC_BOVC     = (0x08 << 26),
    OPC_BEQZALC  = (0x08 << 26),
    OPC_BEQC     = (0x08 << 26),
    OPC_BLEZC    = (0x16 << 26),
    OPC_BGEZC    = (0x16 << 26),
    OPC_BGEC     = (0x16 << 26),
    OPC_BGTZC    = (0x17 << 26),
    OPC_BLTZC    = (0x17 << 26),
    OPC_BLTC     = (0x17 << 26),
    OPC_BNVC     = (0x18 << 26),
    OPC_BNEZALC  = (0x18 << 26),
    OPC_BNEC     = (0x18 << 26),
    OPC_BC       = (0x32 << 26),
    OPC_BEQZC    = (0x36 << 26),
    OPC_JIC      = (0x36 << 26),
    OPC_BALC     = (0x3A << 26),
    OPC_BNEZC    = (0x3E << 26),
    OPC_JIALC    = (0x3E << 26),
    /* MDMX ASE specific */
    OPC_MDMX     = (0x1E << 26),
    /* Cache and prefetch */
    OPC_CACHE    = (0x2F << 26),
    OPC_PREF     = (0x33 << 26),
    /* PC-relative address computation / loads */
    OPC_PCREL    = (0x3B << 26),
};

/* PC-relative address computation / loads  */
#define MASK_OPC_PCREL_TOP2BITS(op) (MASK_OP_MAJOR(op) | (op & (3 << 19)))
#define MASK_OPC_PCREL_TOP5BITS(op) (MASK_OP_MAJOR(op) | (op & (0x1f << 16)))
enum {
    /* Instructions determined by bits 19 and 20 */
    OPC_ADDIUPC = OPC_PCREL | (0 << 19),
    R6_OPC_LWPC = OPC_PCREL | (1 << 19),
    OPC_LWUPC   = OPC_PCREL | (2 << 19),

    /* Instructions determined by bits 16 ... 20 */
    OPC_AUIPC   = OPC_PCREL | (0x1e << 16),
    OPC_ALUIPC  = OPC_PCREL | (0x1f << 16),

    /* Other */
    R6_OPC_LDPC = OPC_PCREL | (6 << 18),
};

/* MIPS special opcodes */
#define MASK_SPECIAL(op)            (MASK_OP_MAJOR(op) | (op & 0x3F))

enum {
    /* Shifts */
    OPC_SLL      = 0x00 | OPC_SPECIAL,
    /* NOP is SLL r0, r0, 0   */
    /* SSNOP is SLL r0, r0, 1 */
    /* EHB is SLL r0, r0, 3 */
    OPC_SRL      = 0x02 | OPC_SPECIAL, /* also ROTR */
    OPC_ROTR     = OPC_SRL | (1 << 21),
    OPC_SRA      = 0x03 | OPC_SPECIAL,
    OPC_SLLV     = 0x04 | OPC_SPECIAL,
    OPC_SRLV     = 0x06 | OPC_SPECIAL, /* also ROTRV */
    OPC_ROTRV    = OPC_SRLV | (1 << 6),
    OPC_SRAV     = 0x07 | OPC_SPECIAL,
    OPC_DSLLV    = 0x14 | OPC_SPECIAL,
    OPC_DSRLV    = 0x16 | OPC_SPECIAL, /* also DROTRV */
    OPC_DROTRV   = OPC_DSRLV | (1 << 6),
    OPC_DSRAV    = 0x17 | OPC_SPECIAL,
    OPC_DSLL     = 0x38 | OPC_SPECIAL,
    OPC_DSRL     = 0x3A | OPC_SPECIAL, /* also DROTR */
    OPC_DROTR    = OPC_DSRL | (1 << 21),
    OPC_DSRA     = 0x3B | OPC_SPECIAL,
    OPC_DSLL32   = 0x3C | OPC_SPECIAL,
    OPC_DSRL32   = 0x3E | OPC_SPECIAL, /* also DROTR32 */
    OPC_DROTR32  = OPC_DSRL32 | (1 << 21),
    OPC_DSRA32   = 0x3F | OPC_SPECIAL,
    /* Multiplication / division */
    OPC_MULT     = 0x18 | OPC_SPECIAL,
    OPC_MULTU    = 0x19 | OPC_SPECIAL,
    OPC_DIV      = 0x1A | OPC_SPECIAL,
    OPC_DIVU     = 0x1B | OPC_SPECIAL,
    OPC_DMULT    = 0x1C | OPC_SPECIAL,
    OPC_DMULTU   = 0x1D | OPC_SPECIAL,
    OPC_DDIV     = 0x1E | OPC_SPECIAL,
    OPC_DDIVU    = 0x1F | OPC_SPECIAL,

    /* 2 registers arithmetic / logic */
    OPC_ADD      = 0x20 | OPC_SPECIAL,
    OPC_ADDU     = 0x21 | OPC_SPECIAL,
    OPC_SUB      = 0x22 | OPC_SPECIAL,
    OPC_SUBU     = 0x23 | OPC_SPECIAL,
    OPC_AND      = 0x24 | OPC_SPECIAL,
    OPC_OR       = 0x25 | OPC_SPECIAL,
    OPC_XOR      = 0x26 | OPC_SPECIAL,
    OPC_NOR      = 0x27 | OPC_SPECIAL,
    OPC_SLT      = 0x2A | OPC_SPECIAL,
    OPC_SLTU     = 0x2B | OPC_SPECIAL,
    OPC_DADD     = 0x2C | OPC_SPECIAL,
    OPC_DADDU    = 0x2D | OPC_SPECIAL,
    OPC_DSUB     = 0x2E | OPC_SPECIAL,
    OPC_DSUBU    = 0x2F | OPC_SPECIAL,
    /* Jumps */
    OPC_JR       = 0x08 | OPC_SPECIAL, /* Also JR.HB */
    OPC_JALR     = 0x09 | OPC_SPECIAL, /* Also JALR.HB */
    /* Traps */
    OPC_TGE      = 0x30 | OPC_SPECIAL,
    OPC_TGEU     = 0x31 | OPC_SPECIAL,
    OPC_TLT      = 0x32 | OPC_SPECIAL,
    OPC_TLTU     = 0x33 | OPC_SPECIAL,
    OPC_TEQ      = 0x34 | OPC_SPECIAL,
    OPC_TNE      = 0x36 | OPC_SPECIAL,
    /* HI / LO registers load & stores */
    OPC_MFHI     = 0x10 | OPC_SPECIAL,
    OPC_MTHI     = 0x11 | OPC_SPECIAL,
    OPC_MFLO     = 0x12 | OPC_SPECIAL,
    OPC_MTLO     = 0x13 | OPC_SPECIAL,
    /* Conditional moves */
    OPC_MOVZ     = 0x0A | OPC_SPECIAL,
    OPC_MOVN     = 0x0B | OPC_SPECIAL,

    OPC_SELEQZ   = 0x35 | OPC_SPECIAL,
    OPC_SELNEZ   = 0x37 | OPC_SPECIAL,

    OPC_MOVCI    = 0x01 | OPC_SPECIAL,

    /* Special */
    OPC_PMON     = 0x05 | OPC_SPECIAL, /* unofficial */
    OPC_SYSCALL  = 0x0C | OPC_SPECIAL,
    OPC_BREAK    = 0x0D | OPC_SPECIAL,
    OPC_SPIM     = 0x0E | OPC_SPECIAL, /* unofficial */
    OPC_SYNC     = 0x0F | OPC_SPECIAL,

    OPC_SPECIAL28_RESERVED = 0x28 | OPC_SPECIAL,
    OPC_SPECIAL29_RESERVED = 0x29 | OPC_SPECIAL,
    OPC_SPECIAL39_RESERVED = 0x39 | OPC_SPECIAL,
    OPC_SPECIAL3D_RESERVED = 0x3D | OPC_SPECIAL,
};

/*
 * R6 Multiply and Divide instructions have the same opcode
 * and function field as legacy OPC_MULT[U]/OPC_DIV[U]
 */
#define MASK_R6_MULDIV(op)          (MASK_SPECIAL(op) | (op & (0x7ff)))

enum {
    R6_OPC_MUL   = OPC_MULT  | (2 << 6),
    R6_OPC_MUH   = OPC_MULT  | (3 << 6),
    R6_OPC_MULU  = OPC_MULTU | (2 << 6),
    R6_OPC_MUHU  = OPC_MULTU | (3 << 6),
    R6_OPC_DIV   = OPC_DIV   | (2 << 6),
    R6_OPC_MOD   = OPC_DIV   | (3 << 6),
    R6_OPC_DIVU  = OPC_DIVU  | (2 << 6),
    R6_OPC_MODU  = OPC_DIVU  | (3 << 6),

    R6_OPC_DMUL   = OPC_DMULT  | (2 << 6),
    R6_OPC_DMUH   = OPC_DMULT  | (3 << 6),
    R6_OPC_DMULU  = OPC_DMULTU | (2 << 6),
    R6_OPC_DMUHU  = OPC_DMULTU | (3 << 6),
    R6_OPC_DDIV   = OPC_DDIV   | (2 << 6),
    R6_OPC_DMOD   = OPC_DDIV   | (3 << 6),
    R6_OPC_DDIVU  = OPC_DDIVU  | (2 << 6),
    R6_OPC_DMODU  = OPC_DDIVU  | (3 << 6),

    R6_OPC_CLZ      = 0x10 | OPC_SPECIAL,
    R6_OPC_CLO      = 0x11 | OPC_SPECIAL,
    R6_OPC_DCLZ     = 0x12 | OPC_SPECIAL,
    R6_OPC_DCLO     = 0x13 | OPC_SPECIAL,
    R6_OPC_SDBBP    = 0x0e | OPC_SPECIAL,
};

/* REGIMM (rt field) opcodes */
#define MASK_REGIMM(op)             (MASK_OP_MAJOR(op) | (op & (0x1F << 16)))

enum {
    OPC_BLTZ     = (0x00 << 16) | OPC_REGIMM,
    OPC_BLTZL    = (0x02 << 16) | OPC_REGIMM,
    OPC_BGEZ     = (0x01 << 16) | OPC_REGIMM,
    OPC_BGEZL    = (0x03 << 16) | OPC_REGIMM,
    OPC_BLTZAL   = (0x10 << 16) | OPC_REGIMM,
    OPC_BLTZALL  = (0x12 << 16) | OPC_REGIMM,
    OPC_BGEZAL   = (0x11 << 16) | OPC_REGIMM,
    OPC_BGEZALL  = (0x13 << 16) | OPC_REGIMM,
    OPC_TGEI     = (0x08 << 16) | OPC_REGIMM,
    OPC_TGEIU    = (0x09 << 16) | OPC_REGIMM,
    OPC_TLTI     = (0x0A << 16) | OPC_REGIMM,
    OPC_TLTIU    = (0x0B << 16) | OPC_REGIMM,
    OPC_TEQI     = (0x0C << 16) | OPC_REGIMM,
    OPC_TNEI     = (0x0E << 16) | OPC_REGIMM,
    OPC_SIGRIE   = (0x17 << 16) | OPC_REGIMM,
    OPC_SYNCI    = (0x1F << 16) | OPC_REGIMM,

    OPC_DAHI     = (0x06 << 16) | OPC_REGIMM,
    OPC_DATI     = (0x1e << 16) | OPC_REGIMM,
};

/* Special2 opcodes */
#define MASK_SPECIAL2(op)           (MASK_OP_MAJOR(op) | (op & 0x3F))

enum {
    /* Multiply & xxx operations */
    OPC_MADD     = 0x00 | OPC_SPECIAL2,
    OPC_MADDU    = 0x01 | OPC_SPECIAL2,
    OPC_MUL      = 0x02 | OPC_SPECIAL2,
    OPC_MSUB     = 0x04 | OPC_SPECIAL2,
    OPC_MSUBU    = 0x05 | OPC_SPECIAL2,
    /* Misc */
    OPC_CLZ      = 0x20 | OPC_SPECIAL2,
    OPC_CLO      = 0x21 | OPC_SPECIAL2,
    OPC_DCLZ     = 0x24 | OPC_SPECIAL2,
    OPC_DCLO     = 0x25 | OPC_SPECIAL2,
    /* Special */
    OPC_SDBBP    = 0x3F | OPC_SPECIAL2,
};

/* Special3 opcodes */
#define MASK_SPECIAL3(op)           (MASK_OP_MAJOR(op) | (op & 0x3F))

enum {
    OPC_EXT      = 0x00 | OPC_SPECIAL3,
    OPC_DEXTM    = 0x01 | OPC_SPECIAL3,
    OPC_DEXTU    = 0x02 | OPC_SPECIAL3,
    OPC_DEXT     = 0x03 | OPC_SPECIAL3,
    OPC_INS      = 0x04 | OPC_SPECIAL3,
    OPC_DINSM    = 0x05 | OPC_SPECIAL3,
    OPC_DINSU    = 0x06 | OPC_SPECIAL3,
    OPC_DINS     = 0x07 | OPC_SPECIAL3,
    OPC_FORK     = 0x08 | OPC_SPECIAL3,
    OPC_YIELD    = 0x09 | OPC_SPECIAL3,
    OPC_BSHFL    = 0x20 | OPC_SPECIAL3,
    OPC_DBSHFL   = 0x24 | OPC_SPECIAL3,
    OPC_RDHWR    = 0x3B | OPC_SPECIAL3,
    OPC_GINV     = 0x3D | OPC_SPECIAL3,

    /* MIPS DSP Load */
    OPC_LX_DSP         = 0x0A | OPC_SPECIAL3,
    /* MIPS DSP Arithmetic */
    OPC_ADDU_QB_DSP    = 0x10 | OPC_SPECIAL3,
    OPC_ADDU_OB_DSP    = 0x14 | OPC_SPECIAL3,
    OPC_ABSQ_S_PH_DSP  = 0x12 | OPC_SPECIAL3,
    OPC_ABSQ_S_QH_DSP  = 0x16 | OPC_SPECIAL3,
    OPC_ADDUH_QB_DSP   = 0x18 | OPC_SPECIAL3,
    OPC_CMPU_EQ_QB_DSP = 0x11 | OPC_SPECIAL3,
    OPC_CMPU_EQ_OB_DSP = 0x15 | OPC_SPECIAL3,
    /* MIPS DSP GPR-Based Shift Sub-class */
    OPC_SHLL_QB_DSP    = 0x13 | OPC_SPECIAL3,
    OPC_SHLL_OB_DSP    = 0x17 | OPC_SPECIAL3,
    /* MIPS DSP Multiply Sub-class insns */
    OPC_MUL_PH_DSP     = 0x18 | OPC_SPECIAL3,
    OPC_DPA_W_PH_DSP   = 0x30 | OPC_SPECIAL3,
    OPC_DPAQ_W_QH_DSP  = 0x34 | OPC_SPECIAL3,
    /* DSP Bit/Manipulation Sub-class */
    OPC_INSV_DSP       = 0x0C | OPC_SPECIAL3,
    OPC_DINSV_DSP      = 0x0D | OPC_SPECIAL3,
    /* MIPS DSP Append Sub-class */
    OPC_APPEND_DSP     = 0x31 | OPC_SPECIAL3,
    OPC_DAPPEND_DSP    = 0x35 | OPC_SPECIAL3,
    /* MIPS DSP Accumulator and DSPControl Access Sub-class */
    OPC_EXTR_W_DSP     = 0x38 | OPC_SPECIAL3,
    OPC_DEXTR_W_DSP    = 0x3C | OPC_SPECIAL3,

    /* EVA */
    OPC_LWLE           = 0x19 | OPC_SPECIAL3,
    OPC_LWRE           = 0x1A | OPC_SPECIAL3,
    OPC_CACHEE         = 0x1B | OPC_SPECIAL3,
    OPC_SBE            = 0x1C | OPC_SPECIAL3,
    OPC_SHE            = 0x1D | OPC_SPECIAL3,
    OPC_SCE            = 0x1E | OPC_SPECIAL3,
    OPC_SWE            = 0x1F | OPC_SPECIAL3,
    OPC_SWLE           = 0x21 | OPC_SPECIAL3,
    OPC_SWRE           = 0x22 | OPC_SPECIAL3,
    OPC_PREFE          = 0x23 | OPC_SPECIAL3,
    OPC_LBUE           = 0x28 | OPC_SPECIAL3,
    OPC_LHUE           = 0x29 | OPC_SPECIAL3,
    OPC_LBE            = 0x2C | OPC_SPECIAL3,
    OPC_LHE            = 0x2D | OPC_SPECIAL3,
    OPC_LLE            = 0x2E | OPC_SPECIAL3,
    OPC_LWE            = 0x2F | OPC_SPECIAL3,

    /* R6 */
    R6_OPC_PREF        = 0x35 | OPC_SPECIAL3,
    R6_OPC_CACHE       = 0x25 | OPC_SPECIAL3,
    R6_OPC_LL          = 0x36 | OPC_SPECIAL3,
    R6_OPC_SC          = 0x26 | OPC_SPECIAL3,
    R6_OPC_LLD         = 0x37 | OPC_SPECIAL3,
    R6_OPC_SCD         = 0x27 | OPC_SPECIAL3,
};

/* Loongson EXT load/store quad word opcodes */
#define MASK_LOONGSON_GSLSQ(op)           (MASK_OP_MAJOR(op) | (op & 0x8020))
enum {
    OPC_GSLQ        = 0x0020 | OPC_LWC2,
    OPC_GSLQC1      = 0x8020 | OPC_LWC2,
    OPC_GSSHFL      = OPC_LWC2,
    OPC_GSSQ        = 0x0020 | OPC_SWC2,
    OPC_GSSQC1      = 0x8020 | OPC_SWC2,
    OPC_GSSHFS      = OPC_SWC2,
};

/* Loongson EXT shifted load/store opcodes */
#define MASK_LOONGSON_GSSHFLS(op)         (MASK_OP_MAJOR(op) | (op & 0xc03f))
enum {
    OPC_GSLWLC1     = 0x4 | OPC_GSSHFL,
    OPC_GSLWRC1     = 0x5 | OPC_GSSHFL,
    OPC_GSLDLC1     = 0x6 | OPC_GSSHFL,
    OPC_GSLDRC1     = 0x7 | OPC_GSSHFL,
    OPC_GSSWLC1     = 0x4 | OPC_GSSHFS,
    OPC_GSSWRC1     = 0x5 | OPC_GSSHFS,
    OPC_GSSDLC1     = 0x6 | OPC_GSSHFS,
    OPC_GSSDRC1     = 0x7 | OPC_GSSHFS,
};

/* Loongson EXT LDC2/SDC2 opcodes */
#define MASK_LOONGSON_LSDC2(op)           (MASK_OP_MAJOR(op) | (op & 0x7))

enum {
    OPC_GSLBX      = 0x0 | OPC_LDC2,
    OPC_GSLHX      = 0x1 | OPC_LDC2,
    OPC_GSLWX      = 0x2 | OPC_LDC2,
    OPC_GSLDX      = 0x3 | OPC_LDC2,
    OPC_GSLWXC1    = 0x6 | OPC_LDC2,
    OPC_GSLDXC1    = 0x7 | OPC_LDC2,
    OPC_GSSBX      = 0x0 | OPC_SDC2,
    OPC_GSSHX      = 0x1 | OPC_SDC2,
    OPC_GSSWX      = 0x2 | OPC_SDC2,
    OPC_GSSDX      = 0x3 | OPC_SDC2,
    OPC_GSSWXC1    = 0x6 | OPC_SDC2,
    OPC_GSSDXC1    = 0x7 | OPC_SDC2,
};

/* BSHFL opcodes */
#define MASK_BSHFL(op)              (MASK_SPECIAL3(op) | (op & (0x1F << 6)))

enum {
    OPC_WSBH      = (0x02 << 6) | OPC_BSHFL,
    OPC_SEB       = (0x10 << 6) | OPC_BSHFL,
    OPC_SEH       = (0x18 << 6) | OPC_BSHFL,
    OPC_ALIGN     = (0x08 << 6) | OPC_BSHFL, /* 010.bp (010.00 to 010.11) */
    OPC_ALIGN_1   = (0x09 << 6) | OPC_BSHFL,
    OPC_ALIGN_2   = (0x0A << 6) | OPC_BSHFL,
    OPC_ALIGN_3   = (0x0B << 6) | OPC_BSHFL,
    OPC_BITSWAP   = (0x00 << 6) | OPC_BSHFL  /* 00000 */
};

/* DBSHFL opcodes */
#define MASK_DBSHFL(op)             (MASK_SPECIAL3(op) | (op & (0x1F << 6)))

enum {
    OPC_DSBH       = (0x02 << 6) | OPC_DBSHFL,
    OPC_DSHD       = (0x05 << 6) | OPC_DBSHFL,
    OPC_DALIGN     = (0x08 << 6) | OPC_DBSHFL, /* 01.bp (01.000 to 01.111) */
    OPC_DALIGN_1   = (0x09 << 6) | OPC_DBSHFL,
    OPC_DALIGN_2   = (0x0A << 6) | OPC_DBSHFL,
    OPC_DALIGN_3   = (0x0B << 6) | OPC_DBSHFL,
    OPC_DALIGN_4   = (0x0C << 6) | OPC_DBSHFL,
    OPC_DALIGN_5   = (0x0D << 6) | OPC_DBSHFL,
    OPC_DALIGN_6   = (0x0E << 6) | OPC_DBSHFL,
    OPC_DALIGN_7   = (0x0F << 6) | OPC_DBSHFL,
    OPC_DBITSWAP   = (0x00 << 6) | OPC_DBSHFL, /* 00000 */
};

/* MIPS DSP REGIMM opcodes */
enum {
    OPC_BPOSGE32 = (0x1C << 16) | OPC_REGIMM,
    OPC_BPOSGE64 = (0x1D << 16) | OPC_REGIMM,
};

#define MASK_LX(op)                 (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
/* MIPS DSP Load */
enum {
    OPC_LBUX = (0x06 << 6) | OPC_LX_DSP,
    OPC_LHX  = (0x04 << 6) | OPC_LX_DSP,
    OPC_LWX  = (0x00 << 6) | OPC_LX_DSP,
    OPC_LDX = (0x08 << 6) | OPC_LX_DSP,
};

#define MASK_ADDU_QB(op)            (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Arithmetic Sub-class */
    OPC_ADDQ_PH        = (0x0A << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDQ_S_PH      = (0x0E << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDQ_S_W       = (0x16 << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDU_QB        = (0x00 << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDU_S_QB      = (0x04 << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDU_PH        = (0x08 << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDU_S_PH      = (0x0C << 6) | OPC_ADDU_QB_DSP,
    OPC_SUBQ_PH        = (0x0B << 6) | OPC_ADDU_QB_DSP,
    OPC_SUBQ_S_PH      = (0x0F << 6) | OPC_ADDU_QB_DSP,
    OPC_SUBQ_S_W       = (0x17 << 6) | OPC_ADDU_QB_DSP,
    OPC_SUBU_QB        = (0x01 << 6) | OPC_ADDU_QB_DSP,
    OPC_SUBU_S_QB      = (0x05 << 6) | OPC_ADDU_QB_DSP,
    OPC_SUBU_PH        = (0x09 << 6) | OPC_ADDU_QB_DSP,
    OPC_SUBU_S_PH      = (0x0D << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDSC          = (0x10 << 6) | OPC_ADDU_QB_DSP,
    OPC_ADDWC          = (0x11 << 6) | OPC_ADDU_QB_DSP,
    OPC_MODSUB         = (0x12 << 6) | OPC_ADDU_QB_DSP,
    OPC_RADDU_W_QB     = (0x14 << 6) | OPC_ADDU_QB_DSP,
    /* MIPS DSP Multiply Sub-class insns */
    OPC_MULEU_S_PH_QBL = (0x06 << 6) | OPC_ADDU_QB_DSP,
    OPC_MULEU_S_PH_QBR = (0x07 << 6) | OPC_ADDU_QB_DSP,
    OPC_MULQ_RS_PH     = (0x1F << 6) | OPC_ADDU_QB_DSP,
    OPC_MULEQ_S_W_PHL  = (0x1C << 6) | OPC_ADDU_QB_DSP,
    OPC_MULEQ_S_W_PHR  = (0x1D << 6) | OPC_ADDU_QB_DSP,
    OPC_MULQ_S_PH      = (0x1E << 6) | OPC_ADDU_QB_DSP,
};

#define MASK_ADDUH_QB(op)           (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Arithmetic Sub-class */
    OPC_ADDUH_QB   = (0x00 << 6) | OPC_ADDUH_QB_DSP,
    OPC_ADDUH_R_QB = (0x02 << 6) | OPC_ADDUH_QB_DSP,
    OPC_ADDQH_PH   = (0x08 << 6) | OPC_ADDUH_QB_DSP,
    OPC_ADDQH_R_PH = (0x0A << 6) | OPC_ADDUH_QB_DSP,
    OPC_ADDQH_W    = (0x10 << 6) | OPC_ADDUH_QB_DSP,
    OPC_ADDQH_R_W  = (0x12 << 6) | OPC_ADDUH_QB_DSP,
    OPC_SUBUH_QB   = (0x01 << 6) | OPC_ADDUH_QB_DSP,
    OPC_SUBUH_R_QB = (0x03 << 6) | OPC_ADDUH_QB_DSP,
    OPC_SUBQH_PH   = (0x09 << 6) | OPC_ADDUH_QB_DSP,
    OPC_SUBQH_R_PH = (0x0B << 6) | OPC_ADDUH_QB_DSP,
    OPC_SUBQH_W    = (0x11 << 6) | OPC_ADDUH_QB_DSP,
    OPC_SUBQH_R_W  = (0x13 << 6) | OPC_ADDUH_QB_DSP,
    /* MIPS DSP Multiply Sub-class insns */
    OPC_MUL_PH     = (0x0C << 6) | OPC_ADDUH_QB_DSP,
    OPC_MUL_S_PH   = (0x0E << 6) | OPC_ADDUH_QB_DSP,
    OPC_MULQ_S_W   = (0x16 << 6) | OPC_ADDUH_QB_DSP,
    OPC_MULQ_RS_W  = (0x17 << 6) | OPC_ADDUH_QB_DSP,
};

#define MASK_ABSQ_S_PH(op)          (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Arithmetic Sub-class */
    OPC_ABSQ_S_QB       = (0x01 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_ABSQ_S_PH       = (0x09 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_ABSQ_S_W        = (0x11 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEQ_W_PHL    = (0x0C << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEQ_W_PHR    = (0x0D << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEQU_PH_QBL  = (0x04 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEQU_PH_QBR  = (0x05 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEQU_PH_QBLA = (0x06 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEQU_PH_QBRA = (0x07 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEU_PH_QBL   = (0x1C << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEU_PH_QBR   = (0x1D << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEU_PH_QBLA  = (0x1E << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_PRECEU_PH_QBRA  = (0x1F << 6) | OPC_ABSQ_S_PH_DSP,
    /* DSP Bit/Manipulation Sub-class */
    OPC_BITREV          = (0x1B << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_REPL_QB         = (0x02 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_REPLV_QB        = (0x03 << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_REPL_PH         = (0x0A << 6) | OPC_ABSQ_S_PH_DSP,
    OPC_REPLV_PH        = (0x0B << 6) | OPC_ABSQ_S_PH_DSP,
};

#define MASK_CMPU_EQ_QB(op)         (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Arithmetic Sub-class */
    OPC_PRECR_QB_PH      = (0x0D << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PRECRQ_QB_PH     = (0x0C << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PRECR_SRA_PH_W   = (0x1E << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PRECR_SRA_R_PH_W = (0x1F << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PRECRQ_PH_W      = (0x14 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PRECRQ_RS_PH_W   = (0x15 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PRECRQU_S_QB_PH  = (0x0F << 6) | OPC_CMPU_EQ_QB_DSP,
    /* DSP Compare-Pick Sub-class */
    OPC_CMPU_EQ_QB       = (0x00 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPU_LT_QB       = (0x01 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPU_LE_QB       = (0x02 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPGU_EQ_QB      = (0x04 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPGU_LT_QB      = (0x05 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPGU_LE_QB      = (0x06 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPGDU_EQ_QB     = (0x18 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPGDU_LT_QB     = (0x19 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMPGDU_LE_QB     = (0x1A << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMP_EQ_PH        = (0x08 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMP_LT_PH        = (0x09 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_CMP_LE_PH        = (0x0A << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PICK_QB          = (0x03 << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PICK_PH          = (0x0B << 6) | OPC_CMPU_EQ_QB_DSP,
    OPC_PACKRL_PH        = (0x0E << 6) | OPC_CMPU_EQ_QB_DSP,
};

#define MASK_SHLL_QB(op)            (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP GPR-Based Shift Sub-class */
    OPC_SHLL_QB    = (0x00 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHLLV_QB   = (0x02 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHLL_PH    = (0x08 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHLLV_PH   = (0x0A << 6) | OPC_SHLL_QB_DSP,
    OPC_SHLL_S_PH  = (0x0C << 6) | OPC_SHLL_QB_DSP,
    OPC_SHLLV_S_PH = (0x0E << 6) | OPC_SHLL_QB_DSP,
    OPC_SHLL_S_W   = (0x14 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHLLV_S_W  = (0x16 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRL_QB    = (0x01 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRLV_QB   = (0x03 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRL_PH    = (0x19 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRLV_PH   = (0x1B << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRA_QB    = (0x04 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRA_R_QB  = (0x05 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRAV_QB   = (0x06 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRAV_R_QB = (0x07 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRA_PH    = (0x09 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRAV_PH   = (0x0B << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRA_R_PH  = (0x0D << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRAV_R_PH = (0x0F << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRA_R_W   = (0x15 << 6) | OPC_SHLL_QB_DSP,
    OPC_SHRAV_R_W  = (0x17 << 6) | OPC_SHLL_QB_DSP,
};

#define MASK_DPA_W_PH(op)           (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Multiply Sub-class insns */
    OPC_DPAU_H_QBL    = (0x03 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPAU_H_QBR    = (0x07 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPSU_H_QBL    = (0x0B << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPSU_H_QBR    = (0x0F << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPA_W_PH      = (0x00 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPAX_W_PH     = (0x08 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPAQ_S_W_PH   = (0x04 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPAQX_S_W_PH  = (0x18 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPAQX_SA_W_PH = (0x1A << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPS_W_PH      = (0x01 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPSX_W_PH     = (0x09 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPSQ_S_W_PH   = (0x05 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPSQX_S_W_PH  = (0x19 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPSQX_SA_W_PH = (0x1B << 6) | OPC_DPA_W_PH_DSP,
    OPC_MULSAQ_S_W_PH = (0x06 << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPAQ_SA_L_W   = (0x0C << 6) | OPC_DPA_W_PH_DSP,
    OPC_DPSQ_SA_L_W   = (0x0D << 6) | OPC_DPA_W_PH_DSP,
    OPC_MAQ_S_W_PHL   = (0x14 << 6) | OPC_DPA_W_PH_DSP,
    OPC_MAQ_S_W_PHR   = (0x16 << 6) | OPC_DPA_W_PH_DSP,
    OPC_MAQ_SA_W_PHL  = (0x10 << 6) | OPC_DPA_W_PH_DSP,
    OPC_MAQ_SA_W_PHR  = (0x12 << 6) | OPC_DPA_W_PH_DSP,
    OPC_MULSA_W_PH    = (0x02 << 6) | OPC_DPA_W_PH_DSP,
};

#define MASK_INSV(op)               (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* DSP Bit/Manipulation Sub-class */
    OPC_INSV = (0x00 << 6) | OPC_INSV_DSP,
};

#define MASK_APPEND(op)             (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Append Sub-class */
    OPC_APPEND  = (0x00 << 6) | OPC_APPEND_DSP,
    OPC_PREPEND = (0x01 << 6) | OPC_APPEND_DSP,
    OPC_BALIGN  = (0x10 << 6) | OPC_APPEND_DSP,
};

#define MASK_EXTR_W(op)             (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Accumulator and DSPControl Access Sub-class */
    OPC_EXTR_W     = (0x00 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTR_R_W   = (0x04 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTR_RS_W  = (0x06 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTR_S_H   = (0x0E << 6) | OPC_EXTR_W_DSP,
    OPC_EXTRV_S_H  = (0x0F << 6) | OPC_EXTR_W_DSP,
    OPC_EXTRV_W    = (0x01 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTRV_R_W  = (0x05 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTRV_RS_W = (0x07 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTP       = (0x02 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTPV      = (0x03 << 6) | OPC_EXTR_W_DSP,
    OPC_EXTPDP     = (0x0A << 6) | OPC_EXTR_W_DSP,
    OPC_EXTPDPV    = (0x0B << 6) | OPC_EXTR_W_DSP,
    OPC_SHILO      = (0x1A << 6) | OPC_EXTR_W_DSP,
    OPC_SHILOV     = (0x1B << 6) | OPC_EXTR_W_DSP,
    OPC_MTHLIP     = (0x1F << 6) | OPC_EXTR_W_DSP,
    OPC_WRDSP      = (0x13 << 6) | OPC_EXTR_W_DSP,
    OPC_RDDSP      = (0x12 << 6) | OPC_EXTR_W_DSP,
};

#define MASK_ABSQ_S_QH(op)          (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Arithmetic Sub-class */
    OPC_PRECEQ_L_PWL    = (0x14 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQ_L_PWR    = (0x15 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQ_PW_QHL   = (0x0C << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQ_PW_QHR   = (0x0D << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQ_PW_QHLA  = (0x0E << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQ_PW_QHRA  = (0x0F << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQU_QH_OBL  = (0x04 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQU_QH_OBR  = (0x05 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQU_QH_OBLA = (0x06 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEQU_QH_OBRA = (0x07 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEU_QH_OBL   = (0x1C << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEU_QH_OBR   = (0x1D << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEU_QH_OBLA  = (0x1E << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_PRECEU_QH_OBRA  = (0x1F << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_ABSQ_S_OB       = (0x01 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_ABSQ_S_PW       = (0x11 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_ABSQ_S_QH       = (0x09 << 6) | OPC_ABSQ_S_QH_DSP,
    /* DSP Bit/Manipulation Sub-class */
    OPC_REPL_OB         = (0x02 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_REPL_PW         = (0x12 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_REPL_QH         = (0x0A << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_REPLV_OB        = (0x03 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_REPLV_PW        = (0x13 << 6) | OPC_ABSQ_S_QH_DSP,
    OPC_REPLV_QH        = (0x0B << 6) | OPC_ABSQ_S_QH_DSP,
};

#define MASK_ADDU_OB(op)            (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Multiply Sub-class insns */
    OPC_MULEQ_S_PW_QHL = (0x1C << 6) | OPC_ADDU_OB_DSP,
    OPC_MULEQ_S_PW_QHR = (0x1D << 6) | OPC_ADDU_OB_DSP,
    OPC_MULEU_S_QH_OBL = (0x06 << 6) | OPC_ADDU_OB_DSP,
    OPC_MULEU_S_QH_OBR = (0x07 << 6) | OPC_ADDU_OB_DSP,
    OPC_MULQ_RS_QH     = (0x1F << 6) | OPC_ADDU_OB_DSP,
    /* MIPS DSP Arithmetic Sub-class */
    OPC_RADDU_L_OB     = (0x14 << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBQ_PW        = (0x13 << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBQ_S_PW      = (0x17 << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBQ_QH        = (0x0B << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBQ_S_QH      = (0x0F << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBU_OB        = (0x01 << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBU_S_OB      = (0x05 << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBU_QH        = (0x09 << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBU_S_QH      = (0x0D << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBUH_OB       = (0x19 << 6) | OPC_ADDU_OB_DSP,
    OPC_SUBUH_R_OB     = (0x1B << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDQ_PW        = (0x12 << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDQ_S_PW      = (0x16 << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDQ_QH        = (0x0A << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDQ_S_QH      = (0x0E << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDU_OB        = (0x00 << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDU_S_OB      = (0x04 << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDU_QH        = (0x08 << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDU_S_QH      = (0x0C << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDUH_OB       = (0x18 << 6) | OPC_ADDU_OB_DSP,
    OPC_ADDUH_R_OB     = (0x1A << 6) | OPC_ADDU_OB_DSP,
};

#define MASK_CMPU_EQ_OB(op)         (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* DSP Compare-Pick Sub-class */
    OPC_CMP_EQ_PW         = (0x10 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMP_LT_PW         = (0x11 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMP_LE_PW         = (0x12 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMP_EQ_QH         = (0x08 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMP_LT_QH         = (0x09 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMP_LE_QH         = (0x0A << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPGDU_EQ_OB      = (0x18 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPGDU_LT_OB      = (0x19 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPGDU_LE_OB      = (0x1A << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPGU_EQ_OB       = (0x04 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPGU_LT_OB       = (0x05 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPGU_LE_OB       = (0x06 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPU_EQ_OB        = (0x00 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPU_LT_OB        = (0x01 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_CMPU_LE_OB        = (0x02 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PACKRL_PW         = (0x0E << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PICK_OB           = (0x03 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PICK_PW           = (0x13 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PICK_QH           = (0x0B << 6) | OPC_CMPU_EQ_OB_DSP,
    /* MIPS DSP Arithmetic Sub-class */
    OPC_PRECR_OB_QH       = (0x0D << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PRECR_SRA_QH_PW   = (0x1E << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PRECR_SRA_R_QH_PW = (0x1F << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PRECRQ_OB_QH      = (0x0C << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PRECRQ_PW_L       = (0x1C << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PRECRQ_QH_PW      = (0x14 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PRECRQ_RS_QH_PW   = (0x15 << 6) | OPC_CMPU_EQ_OB_DSP,
    OPC_PRECRQU_S_OB_QH   = (0x0F << 6) | OPC_CMPU_EQ_OB_DSP,
};

#define MASK_DAPPEND(op)            (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* DSP Append Sub-class */
    OPC_DAPPEND  = (0x00 << 6) | OPC_DAPPEND_DSP,
    OPC_PREPENDD = (0x03 << 6) | OPC_DAPPEND_DSP,
    OPC_PREPENDW = (0x01 << 6) | OPC_DAPPEND_DSP,
    OPC_DBALIGN  = (0x10 << 6) | OPC_DAPPEND_DSP,
};

#define MASK_DEXTR_W(op)            (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Accumulator and DSPControl Access Sub-class */
    OPC_DMTHLIP     = (0x1F << 6) | OPC_DEXTR_W_DSP,
    OPC_DSHILO      = (0x1A << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTP       = (0x02 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTPDP     = (0x0A << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTPDPV    = (0x0B << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTPV      = (0x03 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTR_L     = (0x10 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTR_R_L   = (0x14 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTR_RS_L  = (0x16 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTR_W     = (0x00 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTR_R_W   = (0x04 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTR_RS_W  = (0x06 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTR_S_H   = (0x0E << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTRV_L    = (0x11 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTRV_R_L  = (0x15 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTRV_RS_L = (0x17 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTRV_S_H  = (0x0F << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTRV_W    = (0x01 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTRV_R_W  = (0x05 << 6) | OPC_DEXTR_W_DSP,
    OPC_DEXTRV_RS_W = (0x07 << 6) | OPC_DEXTR_W_DSP,
    OPC_DSHILOV     = (0x1B << 6) | OPC_DEXTR_W_DSP,
};

#define MASK_DINSV(op)              (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* DSP Bit/Manipulation Sub-class */
    OPC_DINSV = (0x00 << 6) | OPC_DINSV_DSP,
};

#define MASK_DPAQ_W_QH(op)          (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP Multiply Sub-class insns */
    OPC_DMADD         = (0x19 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DMADDU        = (0x1D << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DMSUB         = (0x1B << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DMSUBU        = (0x1F << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPA_W_QH      = (0x00 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPAQ_S_W_QH   = (0x04 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPAQ_SA_L_PW  = (0x0C << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPAU_H_OBL    = (0x03 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPAU_H_OBR    = (0x07 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPS_W_QH      = (0x01 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPSQ_S_W_QH   = (0x05 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPSQ_SA_L_PW  = (0x0D << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPSU_H_OBL    = (0x0B << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_DPSU_H_OBR    = (0x0F << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_S_L_PWL   = (0x1C << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_S_L_PWR   = (0x1E << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_S_W_QHLL  = (0x14 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_SA_W_QHLL = (0x10 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_S_W_QHLR  = (0x15 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_SA_W_QHLR = (0x11 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_S_W_QHRL  = (0x16 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_SA_W_QHRL = (0x12 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_S_W_QHRR  = (0x17 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MAQ_SA_W_QHRR = (0x13 << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MULSAQ_S_L_PW = (0x0E << 6) | OPC_DPAQ_W_QH_DSP,
    OPC_MULSAQ_S_W_QH = (0x06 << 6) | OPC_DPAQ_W_QH_DSP,
};

#define MASK_SHLL_OB(op)            (MASK_SPECIAL3(op) | (op & (0x1F << 6)))
enum {
    /* MIPS DSP GPR-Based Shift Sub-class */
    OPC_SHLL_PW    = (0x10 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLL_S_PW  = (0x14 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLLV_OB   = (0x02 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLLV_PW   = (0x12 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLLV_S_PW = (0x16 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLLV_QH   = (0x0A << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLLV_S_QH = (0x0E << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRA_PW    = (0x11 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRA_R_PW  = (0x15 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRAV_OB   = (0x06 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRAV_R_OB = (0x07 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRAV_PW   = (0x13 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRAV_R_PW = (0x17 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRAV_QH   = (0x0B << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRAV_R_QH = (0x0F << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRLV_OB   = (0x03 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRLV_QH   = (0x1B << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLL_OB    = (0x00 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLL_QH    = (0x08 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHLL_S_QH  = (0x0C << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRA_OB    = (0x04 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRA_R_OB  = (0x05 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRA_QH    = (0x09 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRA_R_QH  = (0x0D << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRL_OB    = (0x01 << 6) | OPC_SHLL_OB_DSP,
    OPC_SHRL_QH    = (0x19 << 6) | OPC_SHLL_OB_DSP,
};

/* Coprocessor 0 (rs field) */
#define MASK_CP0(op)                (MASK_OP_MAJOR(op) | (op & (0x1F << 21)))

enum {
    OPC_MFC0     = (0x00 << 21) | OPC_CP0,
    OPC_DMFC0    = (0x01 << 21) | OPC_CP0,
    OPC_MFHC0    = (0x02 << 21) | OPC_CP0,
    OPC_MTC0     = (0x04 << 21) | OPC_CP0,
    OPC_DMTC0    = (0x05 << 21) | OPC_CP0,
    OPC_MTHC0    = (0x06 << 21) | OPC_CP0,
    OPC_MFTR     = (0x08 << 21) | OPC_CP0,
    OPC_RDPGPR   = (0x0A << 21) | OPC_CP0,
    OPC_MFMC0    = (0x0B << 21) | OPC_CP0,
    OPC_MTTR     = (0x0C << 21) | OPC_CP0,
    OPC_WRPGPR   = (0x0E << 21) | OPC_CP0,
    OPC_C0       = (0x10 << 21) | OPC_CP0,
    OPC_C0_1     = (0x11 << 21) | OPC_CP0,
    OPC_C0_2     = (0x12 << 21) | OPC_CP0,
    OPC_C0_3     = (0x13 << 21) | OPC_CP0,
    OPC_C0_4     = (0x14 << 21) | OPC_CP0,
    OPC_C0_5     = (0x15 << 21) | OPC_CP0,
    OPC_C0_6     = (0x16 << 21) | OPC_CP0,
    OPC_C0_7     = (0x17 << 21) | OPC_CP0,
    OPC_C0_8     = (0x18 << 21) | OPC_CP0,
    OPC_C0_9     = (0x19 << 21) | OPC_CP0,
    OPC_C0_A     = (0x1A << 21) | OPC_CP0,
    OPC_C0_B     = (0x1B << 21) | OPC_CP0,
    OPC_C0_C     = (0x1C << 21) | OPC_CP0,
    OPC_C0_D     = (0x1D << 21) | OPC_CP0,
    OPC_C0_E     = (0x1E << 21) | OPC_CP0,
    OPC_C0_F     = (0x1F << 21) | OPC_CP0,
};

/* MFMC0 opcodes */
#define MASK_MFMC0(op)              (MASK_CP0(op) | (op & 0xFFFF))

enum {
    OPC_DMT      = 0x01 | (0 << 5) | (0x0F << 6) | (0x01 << 11) | OPC_MFMC0,
    OPC_EMT      = 0x01 | (1 << 5) | (0x0F << 6) | (0x01 << 11) | OPC_MFMC0,
    OPC_DVPE     = 0x01 | (0 << 5) | OPC_MFMC0,
    OPC_EVPE     = 0x01 | (1 << 5) | OPC_MFMC0,
    OPC_DI       = (0 << 5) | (0x0C << 11) | OPC_MFMC0,
    OPC_EI       = (1 << 5) | (0x0C << 11) | OPC_MFMC0,
    OPC_DVP      = 0x04 | (0 << 3) | (1 << 5) | (0 << 11) | OPC_MFMC0,
    OPC_EVP      = 0x04 | (0 << 3) | (0 << 5) | (0 << 11) | OPC_MFMC0,
};

/* Coprocessor 0 (with rs == C0) */
#define MASK_C0(op)                 (MASK_CP0(op) | (op & 0x3F))

enum {
    OPC_TLBR     = 0x01 | OPC_C0,
    OPC_TLBWI    = 0x02 | OPC_C0,
    OPC_TLBINV   = 0x03 | OPC_C0,
    OPC_TLBINVF  = 0x04 | OPC_C0,
    OPC_TLBWR    = 0x06 | OPC_C0,
    OPC_TLBP     = 0x08 | OPC_C0,
    OPC_RFE      = 0x10 | OPC_C0,
    OPC_ERET     = 0x18 | OPC_C0,
    OPC_DERET    = 0x1F | OPC_C0,
    OPC_WAIT     = 0x20 | OPC_C0,
};

#define MASK_CP2(op)                (MASK_OP_MAJOR(op) | (op & (0x1F << 21)))

enum {
    OPC_MFC2    = (0x00 << 21) | OPC_CP2,
    OPC_DMFC2   = (0x01 << 21) | OPC_CP2,
    OPC_CFC2    = (0x02 << 21) | OPC_CP2,
    OPC_MFHC2   = (0x03 << 21) | OPC_CP2,
    OPC_MTC2    = (0x04 << 21) | OPC_CP2,
    OPC_DMTC2   = (0x05 << 21) | OPC_CP2,
    OPC_CTC2    = (0x06 << 21) | OPC_CP2,
    OPC_MTHC2   = (0x07 << 21) | OPC_CP2,
    OPC_BC2     = (0x08 << 21) | OPC_CP2,
    OPC_BC2EQZ  = (0x09 << 21) | OPC_CP2,
    OPC_BC2NEZ  = (0x0D << 21) | OPC_CP2,
};

#define MASK_LMMI(op)    (MASK_OP_MAJOR(op) | (op & (0x1F << 21)) | (op & 0x1F))

enum {
    OPC_PADDSH      = (24 << 21) | (0x00) | OPC_CP2,
    OPC_PADDUSH     = (25 << 21) | (0x00) | OPC_CP2,
    OPC_PADDH       = (26 << 21) | (0x00) | OPC_CP2,
    OPC_PADDW       = (27 << 21) | (0x00) | OPC_CP2,
    OPC_PADDSB      = (28 << 21) | (0x00) | OPC_CP2,
    OPC_PADDUSB     = (29 << 21) | (0x00) | OPC_CP2,
    OPC_PADDB       = (30 << 21) | (0x00) | OPC_CP2,
    OPC_PADDD       = (31 << 21) | (0x00) | OPC_CP2,

    OPC_PSUBSH      = (24 << 21) | (0x01) | OPC_CP2,
    OPC_PSUBUSH     = (25 << 21) | (0x01) | OPC_CP2,
    OPC_PSUBH       = (26 << 21) | (0x01) | OPC_CP2,
    OPC_PSUBW       = (27 << 21) | (0x01) | OPC_CP2,
    OPC_PSUBSB      = (28 << 21) | (0x01) | OPC_CP2,
    OPC_PSUBUSB     = (29 << 21) | (0x01) | OPC_CP2,
    OPC_PSUBB       = (30 << 21) | (0x01) | OPC_CP2,
    OPC_PSUBD       = (31 << 21) | (0x01) | OPC_CP2,

    OPC_PSHUFH      = (24 << 21) | (0x02) | OPC_CP2,
    OPC_PACKSSWH    = (25 << 21) | (0x02) | OPC_CP2,
    OPC_PACKSSHB    = (26 << 21) | (0x02) | OPC_CP2,
    OPC_PACKUSHB    = (27 << 21) | (0x02) | OPC_CP2,
    OPC_XOR_CP2     = (28 << 21) | (0x02) | OPC_CP2,
    OPC_NOR_CP2     = (29 << 21) | (0x02) | OPC_CP2,
    OPC_AND_CP2     = (30 << 21) | (0x02) | OPC_CP2,
    OPC_PANDN       = (31 << 21) | (0x02) | OPC_CP2,

    OPC_PUNPCKLHW   = (24 << 21) | (0x03) | OPC_CP2,
    OPC_PUNPCKHHW   = (25 << 21) | (0x03) | OPC_CP2,
    OPC_PUNPCKLBH   = (26 << 21) | (0x03) | OPC_CP2,
    OPC_PUNPCKHBH   = (27 << 21) | (0x03) | OPC_CP2,
    OPC_PINSRH_0    = (28 << 21) | (0x03) | OPC_CP2,
    OPC_PINSRH_1    = (29 << 21) | (0x03) | OPC_CP2,
    OPC_PINSRH_2    = (30 << 21) | (0x03) | OPC_CP2,
    OPC_PINSRH_3    = (31 << 21) | (0x03) | OPC_CP2,

    OPC_PAVGH       = (24 << 21) | (0x08) | OPC_CP2,
    OPC_PAVGB       = (25 << 21) | (0x08) | OPC_CP2,
    OPC_PMAXSH      = (26 << 21) | (0x08) | OPC_CP2,
    OPC_PMINSH      = (27 << 21) | (0x08) | OPC_CP2,
    OPC_PMAXUB      = (28 << 21) | (0x08) | OPC_CP2,
    OPC_PMINUB      = (29 << 21) | (0x08) | OPC_CP2,

    OPC_PCMPEQW     = (24 << 21) | (0x09) | OPC_CP2,
    OPC_PCMPGTW     = (25 << 21) | (0x09) | OPC_CP2,
    OPC_PCMPEQH     = (26 << 21) | (0x09) | OPC_CP2,
    OPC_PCMPGTH     = (27 << 21) | (0x09) | OPC_CP2,
    OPC_PCMPEQB     = (28 << 21) | (0x09) | OPC_CP2,
    OPC_PCMPGTB     = (29 << 21) | (0x09) | OPC_CP2,

    OPC_PSLLW       = (24 << 21) | (0x0A) | OPC_CP2,
    OPC_PSLLH       = (25 << 21) | (0x0A) | OPC_CP2,
    OPC_PMULLH      = (26 << 21) | (0x0A) | OPC_CP2,
    OPC_PMULHH      = (27 << 21) | (0x0A) | OPC_CP2,
    OPC_PMULUW      = (28 << 21) | (0x0A) | OPC_CP2,
    OPC_PMULHUH     = (29 << 21) | (0x0A) | OPC_CP2,

    OPC_PSRLW       = (24 << 21) | (0x0B) | OPC_CP2,
    OPC_PSRLH       = (25 << 21) | (0x0B) | OPC_CP2,
    OPC_PSRAW       = (26 << 21) | (0x0B) | OPC_CP2,
    OPC_PSRAH       = (27 << 21) | (0x0B) | OPC_CP2,
    OPC_PUNPCKLWD   = (28 << 21) | (0x0B) | OPC_CP2,
    OPC_PUNPCKHWD   = (29 << 21) | (0x0B) | OPC_CP2,

    OPC_ADDU_CP2    = (24 << 21) | (0x0C) | OPC_CP2,
    OPC_OR_CP2      = (25 << 21) | (0x0C) | OPC_CP2,
    OPC_ADD_CP2     = (26 << 21) | (0x0C) | OPC_CP2,
    OPC_DADD_CP2    = (27 << 21) | (0x0C) | OPC_CP2,
    OPC_SEQU_CP2    = (28 << 21) | (0x0C) | OPC_CP2,
    OPC_SEQ_CP2     = (29 << 21) | (0x0C) | OPC_CP2,

    OPC_SUBU_CP2    = (24 << 21) | (0x0D) | OPC_CP2,
    OPC_PASUBUB     = (25 << 21) | (0x0D) | OPC_CP2,
    OPC_SUB_CP2     = (26 << 21) | (0x0D) | OPC_CP2,
    OPC_DSUB_CP2    = (27 << 21) | (0x0D) | OPC_CP2,
    OPC_SLTU_CP2    = (28 << 21) | (0x0D) | OPC_CP2,
    OPC_SLT_CP2     = (29 << 21) | (0x0D) | OPC_CP2,

    OPC_SLL_CP2     = (24 << 21) | (0x0E) | OPC_CP2,
    OPC_DSLL_CP2    = (25 << 21) | (0x0E) | OPC_CP2,
    OPC_PEXTRH      = (26 << 21) | (0x0E) | OPC_CP2,
    OPC_PMADDHW     = (27 << 21) | (0x0E) | OPC_CP2,
    OPC_SLEU_CP2    = (28 << 21) | (0x0E) | OPC_CP2,
    OPC_SLE_CP2     = (29 << 21) | (0x0E) | OPC_CP2,

    OPC_SRL_CP2     = (24 << 21) | (0x0F) | OPC_CP2,
    OPC_DSRL_CP2    = (25 << 21) | (0x0F) | OPC_CP2,
    OPC_SRA_CP2     = (26 << 21) | (0x0F) | OPC_CP2,
    OPC_DSRA_CP2    = (27 << 21) | (0x0F) | OPC_CP2,
    OPC_BIADD       = (28 << 21) | (0x0F) | OPC_CP2,
    OPC_PMOVMSKB    = (29 << 21) | (0x0F) | OPC_CP2,
};


#define MASK_CP3(op)                (MASK_OP_MAJOR(op) | (op & 0x3F))

enum {
    OPC_LWXC1       = 0x00 | OPC_CP3,
    OPC_LDXC1       = 0x01 | OPC_CP3,
    OPC_LUXC1       = 0x05 | OPC_CP3,
    OPC_SWXC1       = 0x08 | OPC_CP3,
    OPC_SDXC1       = 0x09 | OPC_CP3,
    OPC_SUXC1       = 0x0D | OPC_CP3,
    OPC_PREFX       = 0x0F | OPC_CP3,
    OPC_ALNV_PS     = 0x1E | OPC_CP3,
    OPC_MADD_S      = 0x20 | OPC_CP3,
    OPC_MADD_D      = 0x21 | OPC_CP3,
    OPC_MADD_PS     = 0x26 | OPC_CP3,
    OPC_MSUB_S      = 0x28 | OPC_CP3,
    OPC_MSUB_D      = 0x29 | OPC_CP3,
    OPC_MSUB_PS     = 0x2E | OPC_CP3,
    OPC_NMADD_S     = 0x30 | OPC_CP3,
    OPC_NMADD_D     = 0x31 | OPC_CP3,
    OPC_NMADD_PS    = 0x36 | OPC_CP3,
    OPC_NMSUB_S     = 0x38 | OPC_CP3,
    OPC_NMSUB_D     = 0x39 | OPC_CP3,
    OPC_NMSUB_PS    = 0x3E | OPC_CP3,
};

/*
 *     MMI (MultiMedia Instruction) encodings
 *     ======================================
 *
 * MMI instructions encoding table keys:
 *
 *     *   This code is reserved for future use. An attempt to execute it
 *         causes a Reserved Instruction exception.
 *     %   This code indicates an instruction class. The instruction word
 *         must be further decoded by examining additional tables that show
 *         the values for other instruction fields.
 *     #   This code is reserved for the unsupported instructions DMULT,
 *         DMULTU, DDIV, DDIVU, LL, LLD, SC, SCD, LWC2 and SWC2. An attempt
 *         to execute it causes a Reserved Instruction exception.
 *
 * MMI instructions encoded by opcode field (MMI, LQ, SQ):
 *
 *  31    26                                        0
 * +--------+----------------------------------------+
 * | opcode |                                        |
 * +--------+----------------------------------------+
 *
 *   opcode  bits 28..26
 *     bits |   0   |   1   |   2   |   3   |   4   |   5   |   6   |   7
 *   31..29 |  000  |  001  |  010  |  011  |  100  |  101  |  110  |  111
 *   -------+-------+-------+-------+-------+-------+-------+-------+-------
 *    0 000 |SPECIAL| REGIMM|   J   |  JAL  |  BEQ  |  BNE  |  BLEZ |  BGTZ
 *    1 001 |  ADDI | ADDIU |  SLTI | SLTIU |  ANDI |  ORI  |  XORI |  LUI
 *    2 010 |  COP0 |  COP1 |   *   |   *   |  BEQL |  BNEL | BLEZL | BGTZL
 *    3 011 | DADDI | DADDIU|  LDL  |  LDR  |  MMI% |   *   |   LQ  |   SQ
 *    4 100 |   LB  |   LH  |  LWL  |   LW  |  LBU  |  LHU  |  LWR  |  LWU
 *    5 101 |   SB  |   SH  |  SWL  |   SW  |  SDL  |  SDR  |  SWR  | CACHE
 *    6 110 |   #   |  LWC1 |   #   |  PREF |   #   |  LDC1 |   #   |   LD
 *    7 111 |   #   |  SWC1 |   #   |   *   |   #   |  SDC1 |   #   |   SD
 */

enum {
    MMI_OPC_CLASS_MMI = 0x1C << 26,    /* Same as OPC_SPECIAL2 */
    MMI_OPC_SQ        = 0x1F << 26,    /* Same as OPC_SPECIAL3 */
};

/*
 * MMI instructions with opcode field = MMI:
 *
 *  31    26                                 5      0
 * +--------+-------------------------------+--------+
 * |   MMI  |                               |function|
 * +--------+-------------------------------+--------+
 *
 * function  bits 2..0
 *     bits |   0   |   1   |   2   |   3   |   4   |   5   |   6   |   7
 *     5..3 |  000  |  001  |  010  |  011  |  100  |  101  |  110  |  111
 *   -------+-------+-------+-------+-------+-------+-------+-------+-------
 *    0 000 |  MADD | MADDU |   *   |   *   | PLZCW |   *   |   *   |   *
 *    1 001 | MMI0% | MMI2% |   *   |   *   |   *   |   *   |   *   |   *
 *    2 010 | MFHI1 | MTHI1 | MFLO1 | MTLO1 |   *   |   *   |   *   |   *
 *    3 011 | MULT1 | MULTU1|  DIV1 | DIVU1 |   *   |   *   |   *   |   *
 *    4 100 | MADD1 | MADDU1|   *   |   *   |   *   |   *   |   *   |   *
 *    5 101 | MMI1% | MMI3% |   *   |   *   |   *   |   *   |   *   |   *
 *    6 110 | PMFHL | PMTHL |   *   |   *   | PSLLH |   *   | PSRLH | PSRAH
 *    7 111 |   *   |   *   |   *   |   *   | PSLLW |   *   | PSRLW | PSRAW
 */

#define MASK_MMI(op) (MASK_OP_MAJOR(op) | ((op) & 0x3F))
enum {
    MMI_OPC_MADD       = 0x00 | MMI_OPC_CLASS_MMI, /* Same as OPC_MADD */
    MMI_OPC_MADDU      = 0x01 | MMI_OPC_CLASS_MMI, /* Same as OPC_MADDU */
    MMI_OPC_MULT1      = 0x18 | MMI_OPC_CLASS_MMI, /* Same minor as OPC_MULT */
    MMI_OPC_MULTU1     = 0x19 | MMI_OPC_CLASS_MMI, /* Same min. as OPC_MULTU */
    MMI_OPC_DIV1       = 0x1A | MMI_OPC_CLASS_MMI, /* Same minor as OPC_DIV  */
    MMI_OPC_DIVU1      = 0x1B | MMI_OPC_CLASS_MMI, /* Same minor as OPC_DIVU */
    MMI_OPC_MADD1      = 0x20 | MMI_OPC_CLASS_MMI,
    MMI_OPC_MADDU1     = 0x21 | MMI_OPC_CLASS_MMI,
};

/* global register indices */
TCGv cpu_gpr[32], cpu_PC;
/*
 * For CPUs using 128-bit GPR registers, we put the lower halves in cpu_gpr[])
 * and the upper halves in cpu_gpr_hi[].
 */
TCGv_i64 cpu_gpr_hi[32];
TCGv cpu_HI[MIPS_DSP_ACC], cpu_LO[MIPS_DSP_ACC];
static TCGv cpu_dspctrl, btarget;
TCGv bcond;
static TCGv cpu_lladdr, cpu_llval;
static TCGv_i32 hflags;
TCGv_i32 fpu_fcr0, fpu_fcr31;
TCGv_i64 fpu_f64[32];

static const char regnames_HI[][4] = {
    "HI0", "HI1", "HI2", "HI3",
};

static const char regnames_LO[][4] = {
    "LO0", "LO1", "LO2", "LO3",
};

/* General purpose registers moves. */
void gen_load_gpr(TCGv t, int reg)
{
    assert(reg >= 0 && reg <= ARRAY_SIZE(cpu_gpr));
    if (reg == 0) {
        tcg_gen_movi_tl(t, 0);
        /*
         * CP-M, the zero-register half.  $zero has no TCG global -- cpu_gpr[0]
         * is deliberately NULL -- so `sw $zero, 0($a0)` would state a data
         * provenance of nothing at all, when the encoding names $zero as its
         * data operand exactly the way it would name $t0.  The register NUMBER
         * is known here and nowhere later.  Capture only.
         */
        insn_dataflow_note_zero_reg(tcgv_tl_temp(t));
    } else {
        tcg_gen_mov_tl(t, cpu_gpr[reg]);
    }
}

void gen_store_gpr(TCGv t, int reg)
{
    assert(reg >= 0 && reg <= ARRAY_SIZE(cpu_gpr));
    if (reg != 0) {
        tcg_gen_mov_tl(cpu_gpr[reg], t);
    }
}

/*
 * A GENERAL REGISTER THE ENCODING NAMES AS A SOURCE THAT NO OP READS.
 *
 * MIPS' translator folds an operand away wherever the architecture makes
 * the result independent of it, and it does so in three shapes: an early
 * return when the destination is $zero ("If no destination, treat it as a
 * NOP"), a fold arm when a source is $zero (`andi rt,$zero,imm` is `li
 * rt,0`), and a comparison the branch code answers statically (`beq $t0,$t0`
 * is always taken).  All three are decisions about what the EMULATOR needs
 * to compute.  None of them is a statement about what the INSTRUCTION reads:
 * R7.3 says a register the encoding names is not the emulator's to drop and
 * R15 says a lowering decision is not architectural truth, which is why the
 * zero register is expressed here rather than folded with the value.
 *
 * gen_load_gpr() takes the zero note for the paths that DO call it; this is
 * for the paths that call nothing, where there is no temp to hang a note on
 * and calling the accessor to make one would emit a dead constant.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void note_gpr_folded_read(int reg)
{
    if (reg == 0) {
        insn_dataflow_note_folded_read_zero();
    } else {
        insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[reg]));
    }
}

#if defined(TARGET_MIPS64)
void gen_load_gpr_hi(TCGv_i64 t, int reg)
{
    assert(reg >= 0 && reg <= ARRAY_SIZE(cpu_gpr_hi));
    if (reg == 0) {
        tcg_gen_movi_i64(t, 0);
        /* CP-M, the zero-register half.  See gen_load_gpr() above. */
        insn_dataflow_note_zero_reg(tcgv_i64_temp(t));
    } else {
        tcg_gen_mov_i64(t, cpu_gpr_hi[reg]);
    }
}

void gen_store_gpr_hi(TCGv_i64 t, int reg)
{
    assert(reg >= 0 && reg <= ARRAY_SIZE(cpu_gpr_hi));
    if (reg != 0) {
        tcg_gen_mov_i64(cpu_gpr_hi[reg], t);
    }
}
#endif /* TARGET_MIPS64 */

/* Moves to/from shadow registers. */
static inline void gen_load_srsgpr(int from, int to)
{
    TCGv t0 = tcg_temp_new();

    if (from == 0) {
        tcg_gen_movi_tl(t0, 0);
    } else {
        TCGv_i32 t2 = tcg_temp_new_i32();
        TCGv_ptr addr = tcg_temp_new_ptr();

        tcg_gen_ld_i32(t2, tcg_env, offsetof(CPUMIPSState, CP0_SRSCtl));
        tcg_gen_shri_i32(t2, t2, CP0SRSCtl_PSS);
        tcg_gen_andi_i32(t2, t2, 0xf);
        tcg_gen_muli_i32(t2, t2, sizeof(target_ulong) * 32);
        tcg_gen_ext_i32_ptr(addr, t2);
        tcg_gen_add_ptr(addr, tcg_env, addr);

        tcg_gen_ld_tl(t0, addr, sizeof(target_ulong) * from);
    }
    gen_store_gpr(t0, to);
}

static inline void gen_store_srsgpr(int from, int to)
{
    if (to != 0) {
        TCGv t0 = tcg_temp_new();
        TCGv_i32 t2 = tcg_temp_new_i32();
        TCGv_ptr addr = tcg_temp_new_ptr();

        gen_load_gpr(t0, from);
        tcg_gen_ld_i32(t2, tcg_env, offsetof(CPUMIPSState, CP0_SRSCtl));
        tcg_gen_shri_i32(t2, t2, CP0SRSCtl_PSS);
        tcg_gen_andi_i32(t2, t2, 0xf);
        tcg_gen_muli_i32(t2, t2, sizeof(target_ulong) * 32);
        tcg_gen_ext_i32_ptr(addr, t2);
        tcg_gen_add_ptr(addr, tcg_env, addr);

        tcg_gen_st_tl(t0, addr, sizeof(target_ulong) * to);
    }
}

/* Tests */
static inline void gen_save_pc(target_ulong pc)
{
    tcg_gen_movi_tl(cpu_PC, pc);
}

static inline void save_cpu_state(DisasContext *ctx, int do_save_pc)
{
    LOG_DISAS("hflags %08x saved %08x\n", ctx->hflags, ctx->saved_hflags);
    if (do_save_pc && ctx->base.pc_next != ctx->saved_pc) {
        gen_save_pc(ctx->base.pc_next);
        ctx->saved_pc = ctx->base.pc_next;
    }
    if (ctx->hflags != ctx->saved_hflags) {
        tcg_gen_movi_i32(hflags, ctx->hflags);
        ctx->saved_hflags = ctx->hflags;
        switch (ctx->hflags & MIPS_HFLAG_BMASK_BASE) {
        case MIPS_HFLAG_BR:
            break;
        case MIPS_HFLAG_BC:
        case MIPS_HFLAG_BL:
        case MIPS_HFLAG_B:
            tcg_gen_movi_tl(btarget, ctx->btarget);
            break;
        }
    }
}

static inline void restore_cpu_state(CPUMIPSState *env, DisasContext *ctx)
{
    ctx->saved_hflags = ctx->hflags;
    switch (ctx->hflags & MIPS_HFLAG_BMASK_BASE) {
    case MIPS_HFLAG_BR:
        break;
    case MIPS_HFLAG_BC:
    case MIPS_HFLAG_BL:
    case MIPS_HFLAG_B:
        ctx->btarget = env->btarget;
        break;
    }
}

/*
 * QEMU's own decode identity, for the decoder decodetree cannot reach.
 *
 * The MIPS32/64 base ISA is not in decodetree.  It is a nest of
 * hand-written switch statements, so the identity export that
 * scripts/decodetree.py plants at every generated dispatch site reaches
 * the vendor extensions and none of the base ISA -- measured 0.000%
 * identified over 42,885 translated instructions on a workload that
 * identifies 100% on aarch64 and riscv64.  The identity is nevertheless
 * here: it is the `case OPC_*` label the switch dispatched on.
 *
 * scripts/mips_ident_instrument.py states it, mechanically, at every
 * such label -- selecting the row FROM THE SWITCH'S OWN CONTROLLING
 * EXPRESSION, so a case covering several labels says which one it
 * committed to, and a fallthrough into a later case selects nothing
 * rather than that case's first label.  The table it emits is
 * translate_ident.c.inc.
 *
 * The row is held here and published once, at the end of the
 * instruction, rather than at the moment it is chosen.  Two properties
 * of this decoder force that:
 *
 *  - the decode is nested (major opcode -> function -> sub-opcode ->
 *    generator), so several labels are committed to for one
 *    instruction and the innermost one is the identity;
 *
 *  - a MIPS availability check does not decline the way a decodetree
 *    trans_ function declines.  check_insn() and its siblings generate
 *    the exception and translation CONTINUES, generating dead code from
 *    labels further in.  Publishing eagerly would therefore publish a
 *    decision the emulator did not take.  mips_ident_fault() poisons the
 *    slot instead, and the poison is sticky for the rest of the
 *    instruction.
 */
#include "translate_ident.c.inc"

static void mips_ident(DisasContext *ctx, MipsIdent id)
{
    if (id != MIPS_ID_NONE && ctx->decode_ident != MIPS_ID_FAULTED) {
        ctx->decode_ident = id;
    }
}

/*
 * The exceptions below are the ones raised at translation time because
 * the encoding is not available on this CPU in this state -- the
 * instruction faults instead of executing, so QEMU made no decode and
 * none may be published.  Every other exception this translator raises
 * is what a correctly decoded instruction DOES: EXCP_SYSCALL,
 * EXCP_BREAK, EXCP_TRAP, EXCP_OVERFLOW, EXCP_SEMIHOST, EXCP_DBp.
 */
static void mips_ident_fault(DisasContext *ctx, int excp)
{
    switch (excp) {
    case EXCP_RI:
    case EXCP_CpU:
    case EXCP_DSPDIS:
    case EXCP_MSADIS:
        ctx->decode_ident = MIPS_ID_FAULTED;
        break;
    default:
        break;
    }
}

static void mips_ident_publish(DisasContext *ctx)
{
    uint16_t id = ctx->decode_ident;

    if (id != MIPS_ID_NONE && id != MIPS_ID_FAULTED) {
        plugin_gen_record_insn_identity(mips_ident_tab[id].id,
                                        mips_ident_tab[id].name);
    }
}

void generate_exception_err(DisasContext *ctx, int excp, int err)
{
    mips_ident_fault(ctx, excp);
    save_cpu_state(ctx, 1);
    gen_helper_raise_exception_err(tcg_env, tcg_constant_i32(excp),
                                   tcg_constant_i32(err));
    ctx->base.is_jmp = DISAS_NORETURN;
}

void generate_exception(DisasContext *ctx, int excp)
{
    mips_ident_fault(ctx, excp);
    gen_helper_raise_exception(tcg_env, tcg_constant_i32(excp));
}

void generate_exception_end(DisasContext *ctx, int excp)
{
    generate_exception_err(ctx, excp, 0);
}

void generate_exception_break(DisasContext *ctx, int code)
{
    /*
     * CP-M, the encoded-immediate half, VALUE-STATING form -- `break`'s
     * 20-bit code, the sibling of the trap code stated in gen_trap().  The
     * architecture leaves it entirely to software: the breakpoint exception
     * it raises has its Cause.ExcCode fixed by the opcode, and no state the
     * instruction writes depends on the field.  See
     * insn_dataflow_note_encoded_imm_value().
     */
    insn_dataflow_note_encoded_imm_value((uint64_t)(uint32_t)code,
                                         INSN_DF_IMM_ROLE_NON_DATAFLOW);
#ifdef CONFIG_USER_ONLY
    /* Pass the break code along to cpu_loop. */
    tcg_gen_st_i32(tcg_constant_i32(code), tcg_env,
                   offsetof(CPUMIPSState, error_code));
#endif
    generate_exception_end(ctx, EXCP_BREAK);
}

void gen_reserved_instruction(DisasContext *ctx)
{
    generate_exception_end(ctx, EXCP_RI);
}

/* Floating point register moves. */
void gen_load_fpr32(DisasContext *ctx, TCGv_i32 t, int reg)
{
    if (ctx->hflags & MIPS_HFLAG_FRE) {
        generate_exception(ctx, EXCP_RI);
    }
    tcg_gen_extrl_i64_i32(t, fpu_f64[reg]);
}

void gen_store_fpr32(DisasContext *ctx, TCGv_i32 t, int reg)
{
    TCGv_i64 t64;
    const void *mark;

    if (ctx->hflags & MIPS_HFLAG_FRE) {
        generate_exception(ctx, EXCP_RI);
    }
    t64 = tcg_temp_new_i64();
    tcg_gen_extu_i32_i64(t64, t);
    mark = insn_dataflow_mark();
    tcg_gen_deposit_i64(fpu_f64[reg], fpu_f64[reg], t64, 0, 32);
    /*
     * The deposit read the register only to carry the half it did not write
     * -- R7.1's narrow write, and `mtc1 rt,$f0` names no FP source at all.
     * Where the instruction genuinely reads the register the operand came
     * through gen_load_fpr32/64 in a different op, which this note, keyed on
     * the consuming op, does not touch.
     */
    insn_dataflow_note_preserve_read(tcgv_i64_temp(fpu_f64[reg]), mark);
}

static void gen_load_fpr32h(DisasContext *ctx, TCGv_i32 t, int reg)
{
    if (ctx->hflags & MIPS_HFLAG_F64) {
        tcg_gen_extrh_i64_i32(t, fpu_f64[reg]);
    } else {
        gen_load_fpr32(ctx, t, reg | 1);
    }
}

static void gen_store_fpr32h(DisasContext *ctx, TCGv_i32 t, int reg)
{
    if (ctx->hflags & MIPS_HFLAG_F64) {
        TCGv_i64 t64 = tcg_temp_new_i64();
        const void *mark;

        tcg_gen_extu_i32_i64(t64, t);
        mark = insn_dataflow_mark();
        tcg_gen_deposit_i64(fpu_f64[reg], fpu_f64[reg], t64, 32, 32);
        /* The upper half's writeback; see gen_store_fpr32(). */
        insn_dataflow_note_preserve_read(tcgv_i64_temp(fpu_f64[reg]), mark);
    } else {
        gen_store_fpr32(ctx, t, reg | 1);
    }
}

void gen_load_fpr64(DisasContext *ctx, TCGv_i64 t, int reg)
{
    if (ctx->hflags & MIPS_HFLAG_F64) {
        tcg_gen_mov_i64(t, fpu_f64[reg]);
    } else {
        tcg_gen_concat32_i64(t, fpu_f64[reg & ~1], fpu_f64[reg | 1]);
    }
}

void gen_store_fpr64(DisasContext *ctx, TCGv_i64 t, int reg)
{
    if (ctx->hflags & MIPS_HFLAG_F64) {
        tcg_gen_mov_i64(fpu_f64[reg], t);
    } else {
        TCGv_i64 t0;
        tcg_gen_deposit_i64(fpu_f64[reg & ~1], fpu_f64[reg & ~1], t, 0, 32);
        t0 = tcg_temp_new_i64();
        tcg_gen_shri_i64(t0, t, 32);
        tcg_gen_deposit_i64(fpu_f64[reg | 1], fpu_f64[reg | 1], t0, 0, 32);
    }
}

int get_fp_bit(int cc)
{
    if (cc) {
        return 24 + cc;
    } else {
        return 23;
    }
}

/* Addresses computation */
void gen_op_addr_add(DisasContext *ctx, TCGv ret, TCGv arg0, TCGv arg1)
{
    tcg_gen_add_tl(ret, arg0, arg1);

#if defined(TARGET_MIPS64)
    if (ctx->hflags & MIPS_HFLAG_AWRAP) {
        tcg_gen_ext32s_i64(ret, ret);
    }
#endif
}

void gen_op_addr_addi(DisasContext *ctx, TCGv ret, TCGv base, target_long ofs)
{
    tcg_gen_addi_tl(ret, base, ofs);

#if defined(TARGET_MIPS64)
    if (ctx->hflags & MIPS_HFLAG_AWRAP) {
        tcg_gen_ext32s_i64(ret, ret);
    }
#endif
}

/* Addresses computation (translation time) */
static target_long addr_add(DisasContext *ctx, target_long base,
                            target_long offset)
{
    target_long sum = base + offset;

#if defined(TARGET_MIPS64)
    if (ctx->hflags & MIPS_HFLAG_AWRAP) {
        sum = (int32_t)sum;
    }
#endif
    return sum;
}

/* Sign-extract the low 32-bits to a target_long.  */
void gen_move_low32(TCGv ret, TCGv_i64 arg)
{
#if defined(TARGET_MIPS64)
    tcg_gen_ext32s_i64(ret, arg);
#else
    tcg_gen_extrl_i64_i32(ret, arg);
#endif
}

/* Sign-extract the high 32-bits to a target_long.  */
void gen_move_high32(TCGv ret, TCGv_i64 arg)
{
#if defined(TARGET_MIPS64)
    tcg_gen_sari_i64(ret, arg, 32);
#else
    tcg_gen_extrh_i64_i32(ret, arg);
#endif
}

bool check_cp0_enabled(DisasContext *ctx)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_CP0))) {
        generate_exception_end(ctx, EXCP_CpU);
        return false;
    }
    return true;
}

void check_cp1_enabled(DisasContext *ctx)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_FPU))) {
        generate_exception_err(ctx, EXCP_CpU, 1);
    }
}

/*
 * Verify that the processor is running with COP1X instructions enabled.
 * This is associated with the nabla symbol in the MIPS32 and MIPS64
 * opcode tables.
 */
void check_cop1x(DisasContext *ctx)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_COP1X))) {
        gen_reserved_instruction(ctx);
    }
}

/*
 * Verify that the processor is running with 64-bit floating-point
 * operations enabled.
 */
void check_cp1_64bitmode(DisasContext *ctx)
{
    if (unlikely(~ctx->hflags & MIPS_HFLAG_F64)) {
        gen_reserved_instruction(ctx);
    }
}

/*
 * Verify if floating point register is valid; an operation is not defined
 * if bit 0 of any register specification is set and the FR bit in the
 * Status register equals zero, since the register numbers specify an
 * even-odd pair of adjacent coprocessor general registers. When the FR bit
 * in the Status register equals one, both even and odd register numbers
 * are valid. This limitation exists only for 64 bit wide (d,l,ps) registers.
 *
 * Multiple 64 bit wide registers can be checked by calling
 * gen_op_cp1_registers(freg1 | freg2 | ... | fregN);
 */
void check_cp1_registers(DisasContext *ctx, int regs)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_F64) && (regs & 1))) {
        gen_reserved_instruction(ctx);
    }
}

/*
 * Verify that the processor is running with DSP instructions enabled.
 * This is enabled by CP0 Status register MX(24) bit.
 */
static inline void check_dsp(DisasContext *ctx)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_DSP))) {
        if (ctx->insn_flags & ASE_DSP) {
            generate_exception_end(ctx, EXCP_DSPDIS);
        } else {
            gen_reserved_instruction(ctx);
        }
    }
}

static inline void check_dsp_r2(DisasContext *ctx)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_DSP_R2))) {
        if (ctx->insn_flags & ASE_DSP) {
            generate_exception_end(ctx, EXCP_DSPDIS);
        } else {
            gen_reserved_instruction(ctx);
        }
    }
}

static inline void check_dsp_r3(DisasContext *ctx)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_DSP_R3))) {
        if (ctx->insn_flags & ASE_DSP) {
            generate_exception_end(ctx, EXCP_DSPDIS);
        } else {
            gen_reserved_instruction(ctx);
        }
    }
}

/*
 * This code generates a "reserved instruction" exception if the
 * CPU does not support the instruction set corresponding to flags.
 */
void check_insn(DisasContext *ctx, uint64_t flags)
{
    if (unlikely(!(ctx->insn_flags & flags))) {
        gen_reserved_instruction(ctx);
    }
}

/*
 * This code generates a "reserved instruction" exception if the
 * CPU has corresponding flag set which indicates that the instruction
 * has been removed.
 */
static inline void check_insn_opc_removed(DisasContext *ctx, uint64_t flags)
{
    if (unlikely(ctx->insn_flags & flags)) {
        gen_reserved_instruction(ctx);
    }
}

/*
 * The Linux kernel traps certain reserved instruction exceptions to
 * emulate the corresponding instructions. QEMU is the kernel in user
 * mode, so those traps are emulated by accepting the instructions.
 *
 * A reserved instruction exception is generated for flagged CPUs if
 * QEMU runs in system mode.
 */
static inline void check_insn_opc_user_only(DisasContext *ctx, uint64_t flags)
{
#ifndef CONFIG_USER_ONLY
    check_insn_opc_removed(ctx, flags);
#endif
}

/*
 * This code generates a "reserved instruction" exception if the
 * CPU does not support 64-bit paired-single (PS) floating point data type.
 */
static inline void check_ps(DisasContext *ctx)
{
    if (unlikely(!ctx->ps)) {
        generate_exception(ctx, EXCP_RI);
    }
    check_cp1_64bitmode(ctx);
}

bool decode_64bit_enabled(DisasContext *ctx)
{
    return ctx->hflags & MIPS_HFLAG_64;
}

/*
 * This code generates a "reserved instruction" exception if cpu is not
 * 64-bit or 64-bit instructions are not enabled.
 */
void check_mips_64(DisasContext *ctx)
{
    if (unlikely((TARGET_LONG_BITS != 64) || !decode_64bit_enabled(ctx))) {
        gen_reserved_instruction(ctx);
    }
}

#ifndef CONFIG_USER_ONLY
static inline void check_mvh(DisasContext *ctx)
{
    if (unlikely(!ctx->mvh)) {
        generate_exception(ctx, EXCP_RI);
    }
}
#endif

/*
 * This code generates a "reserved instruction" exception if the
 * Config5 XNP bit is set.
 */
static inline void check_xnp(DisasContext *ctx)
{
    if (unlikely(ctx->CP0_Config5 & (1 << CP0C5_XNP))) {
        gen_reserved_instruction(ctx);
    }
}

#ifndef CONFIG_USER_ONLY
/*
 * This code generates a "reserved instruction" exception if the
 * Config3 PW bit is NOT set.
 */
static inline void check_pw(DisasContext *ctx)
{
    if (unlikely(!(ctx->CP0_Config3 & (1 << CP0C3_PW)))) {
        gen_reserved_instruction(ctx);
    }
}
#endif

/*
 * This code generates a "reserved instruction" exception if the
 * Config3 MT bit is NOT set.
 */
static inline void check_mt(DisasContext *ctx)
{
    if (unlikely(!(ctx->CP0_Config3 & (1 << CP0C3_MT)))) {
        gen_reserved_instruction(ctx);
    }
}

#ifndef CONFIG_USER_ONLY
/*
 * This code generates a "coprocessor unusable" exception if CP0 is not
 * available, and, if that is not the case, generates a "reserved instruction"
 * exception if the Config5 MT bit is NOT set. This is needed for availability
 * control of some of MT ASE instructions.
 */
static inline void check_cp0_mt(DisasContext *ctx)
{
    if (unlikely(!(ctx->hflags & MIPS_HFLAG_CP0))) {
        generate_exception_end(ctx, EXCP_CpU);
    } else {
        if (unlikely(!(ctx->CP0_Config3 & (1 << CP0C3_MT)))) {
            gen_reserved_instruction(ctx);
        }
    }
}
#endif

/*
 * This code generates a "reserved instruction" exception if the
 * Config5 NMS bit is set.
 */
static inline void check_nms(DisasContext *ctx)
{
    if (unlikely(ctx->CP0_Config5 & (1 << CP0C5_NMS))) {
        gen_reserved_instruction(ctx);
    }
}

/*
 * This code generates a "reserved instruction" exception if the
 * Config5 NMS bit is set, and Config1 DL, Config1 IL, Config2 SL,
 * Config2 TL, and Config5 L2C are unset.
 */
static inline void check_nms_dl_il_sl_tl_l2c(DisasContext *ctx)
{
    if (unlikely((ctx->CP0_Config5 & (1 << CP0C5_NMS)) &&
                 !(ctx->CP0_Config1 & (1 << CP0C1_DL)) &&
                 !(ctx->CP0_Config1 & (1 << CP0C1_IL)) &&
                 !(ctx->CP0_Config2 & (1 << CP0C2_SL)) &&
                 !(ctx->CP0_Config2 & (1 << CP0C2_TL)) &&
                 !(ctx->CP0_Config5 & (1 << CP0C5_L2C)))) {
        gen_reserved_instruction(ctx);
    }
}

/*
 * This code generates a "reserved instruction" exception if the
 * Config5 EVA bit is NOT set.
 */
static inline void check_eva(DisasContext *ctx)
{
    if (unlikely(!(ctx->CP0_Config5 & (1 << CP0C5_EVA)))) {
        gen_reserved_instruction(ctx);
    }
}


/*
 * Define small wrappers for gen_load_fpr* so that we have a uniform
 * calling interface for 32 and 64-bit FPRs.  No sense in changing
 * all callers for gen_load_fpr32 when we need the CTX parameter for
 * this one use.
 */
#define gen_ldcmp_fpr32(ctx, x, y) gen_load_fpr32(ctx, x, y)
#define gen_ldcmp_fpr64(ctx, x, y) gen_load_fpr64(ctx, x, y)
#define FOP_CONDS(type, abs, fmt, ifmt, bits)                                 \
static inline void gen_cmp ## type ## _ ## fmt(DisasContext *ctx, int n,      \
                                               int ft, int fs, int cc)        \
{                                                                             \
    TCGv_i##bits fp0 = tcg_temp_new_i##bits();                                \
    TCGv_i##bits fp1 = tcg_temp_new_i##bits();                                \
    switch (ifmt) {                                                           \
    case FMT_PS:                                                              \
        check_ps(ctx);                                                        \
        break;                                                                \
    case FMT_D:                                                               \
        if (abs) {                                                            \
            check_cop1x(ctx);                                                 \
        }                                                                     \
        check_cp1_registers(ctx, fs | ft);                                    \
        break;                                                                \
    case FMT_S:                                                               \
        if (abs) {                                                            \
            check_cop1x(ctx);                                                 \
        }                                                                     \
        break;                                                                \
    }                                                                         \
    gen_ldcmp_fpr##bits(ctx, fp0, fs);                                        \
    gen_ldcmp_fpr##bits(ctx, fp1, ft);                                        \
    switch (n) {                                                              \
    case  0:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _f, fp0, fp1, cc);         \
    break;                                                                    \
    case  1:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _un, fp0, fp1, cc);        \
    break;                                                                    \
    case  2:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _eq, fp0, fp1, cc);        \
    break;                                                                    \
    case  3:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _ueq, fp0, fp1, cc);       \
    break;                                                                    \
    case  4:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _olt, fp0, fp1, cc);       \
    break;                                                                    \
    case  5:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _ult, fp0, fp1, cc);       \
    break;                                                                    \
    case  6:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _ole, fp0, fp1, cc);       \
    break;                                                                    \
    case  7:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _ule, fp0, fp1, cc);       \
    break;                                                                    \
    case  8:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _sf, fp0, fp1, cc);        \
    break;                                                                    \
    case  9:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _ngle, fp0, fp1, cc);      \
    break;                                                                    \
    case 10:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _seq, fp0, fp1, cc);       \
    break;                                                                    \
    case 11:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _ngl, fp0, fp1, cc);       \
    break;                                                                    \
    case 12:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _lt, fp0, fp1, cc);        \
    break;                                                                    \
    case 13:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _nge, fp0, fp1, cc);       \
    break;                                                                    \
    case 14:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _le, fp0, fp1, cc);        \
    break;                                                                    \
    case 15:                                                                  \
        gen_helper_0e2i(cmp ## type ## _ ## fmt ## _ngt, fp0, fp1, cc);       \
    break;                                                                    \
    default:                                                                  \
        abort();                                                              \
    }                                                                         \
}

FOP_CONDS(, 0, d, FMT_D, 64)
FOP_CONDS(abs, 1, d, FMT_D, 64)
FOP_CONDS(, 0, s, FMT_S, 32)
FOP_CONDS(abs, 1, s, FMT_S, 32)
FOP_CONDS(, 0, ps, FMT_PS, 64)
FOP_CONDS(abs, 1, ps, FMT_PS, 64)
#undef FOP_CONDS

#define FOP_CONDNS(fmt, ifmt, bits, STORE)                              \
static inline void gen_r6_cmp_ ## fmt(DisasContext *ctx, int n,         \
                                      int ft, int fs, int fd)           \
{                                                                       \
    TCGv_i ## bits fp0 = tcg_temp_new_i ## bits();                      \
    TCGv_i ## bits fp1 = tcg_temp_new_i ## bits();                      \
    if (ifmt == FMT_D) {                                                \
        check_cp1_registers(ctx, fs | ft | fd);                         \
    }                                                                   \
    gen_ldcmp_fpr ## bits(ctx, fp0, fs);                                \
    gen_ldcmp_fpr ## bits(ctx, fp1, ft);                                \
    switch (n) {                                                        \
    case  0:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _af(fp0, tcg_env, fp0, fp1);       \
        break;                                                          \
    case  1:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _un(fp0, tcg_env, fp0, fp1);       \
        break;                                                          \
    case  2:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _eq(fp0, tcg_env, fp0, fp1);       \
        break;                                                          \
    case  3:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _ueq(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case  4:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _lt(fp0, tcg_env, fp0, fp1);       \
        break;                                                          \
    case  5:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _ult(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case  6:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _le(fp0, tcg_env, fp0, fp1);       \
        break;                                                          \
    case  7:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _ule(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case  8:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _saf(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case  9:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sun(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case 10:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _seq(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case 11:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sueq(fp0, tcg_env, fp0, fp1);     \
        break;                                                          \
    case 12:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _slt(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case 13:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sult(fp0, tcg_env, fp0, fp1);     \
        break;                                                          \
    case 14:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sle(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case 15:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sule(fp0, tcg_env, fp0, fp1);     \
        break;                                                          \
    case 17:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _or(fp0, tcg_env, fp0, fp1);       \
        break;                                                          \
    case 18:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _une(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case 19:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _ne(fp0, tcg_env, fp0, fp1);       \
        break;                                                          \
    case 25:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sor(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    case 26:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sune(fp0, tcg_env, fp0, fp1);     \
        break;                                                          \
    case 27:                                                            \
        gen_helper_r6_cmp_ ## fmt ## _sne(fp0, tcg_env, fp0, fp1);      \
        break;                                                          \
    default:                                                            \
        abort();                                                        \
    }                                                                   \
    STORE;                                                              \
}

FOP_CONDNS(d, FMT_D, 64, gen_store_fpr64(ctx, fp0, fd))
FOP_CONDNS(s, FMT_S, 32, gen_store_fpr32(ctx, fp0, fd))
#undef FOP_CONDNS
#undef gen_ldcmp_fpr32
#undef gen_ldcmp_fpr64

/* load/store instructions. */
#ifdef CONFIG_USER_ONLY
#define OP_LD_ATOMIC(insn, memop)                                          \
static inline void op_ld_##insn(TCGv ret, TCGv arg1, int mem_idx,          \
                                DisasContext *ctx)                         \
{                                                                          \
    TCGv t0 = tcg_temp_new();                                              \
    tcg_gen_mov_tl(t0, arg1);                                              \
    tcg_gen_qemu_ld_tl(ret, arg1, ctx->mem_idx, memop);                    \
    tcg_gen_st_tl(t0, tcg_env, offsetof(CPUMIPSState, lladdr));            \
    tcg_gen_st_tl(ret, tcg_env, offsetof(CPUMIPSState, llval));            \
}
#else
#define OP_LD_ATOMIC(insn, ignored_memop)                                  \
static inline void op_ld_##insn(TCGv ret, TCGv arg1, int mem_idx,          \
                                DisasContext *ctx)                         \
{                                                                          \
    gen_helper_##insn(ret, tcg_env, arg1, tcg_constant_i32(mem_idx));      \
}
#endif
OP_LD_ATOMIC(ll, mo_endian(ctx) | MO_SL);
#if defined(TARGET_MIPS64)
OP_LD_ATOMIC(lld, mo_endian(ctx) | MO_UQ);
#endif
#undef OP_LD_ATOMIC

void gen_base_offset_addr(DisasContext *ctx, TCGv addr, int base, int offset)
{
    if (base == 0) {
        tcg_gen_movi_tl(addr, offset);
    } else if (offset == 0) {
        gen_load_gpr(addr, base);
    } else {
        tcg_gen_movi_tl(addr, offset);
        gen_op_addr_add(ctx, addr, cpu_gpr[base], addr);
    }
}

static target_ulong pc_relative_pc(DisasContext *ctx)
{
    target_ulong pc = ctx->base.pc_next;

    if (ctx->hflags & MIPS_HFLAG_BMASK) {
        int branch_bytes = ctx->hflags & MIPS_HFLAG_BDS16 ? 2 : 4;

        pc -= branch_bytes;
    }

    pc &= ~(target_ulong)3;
    return pc;
}

/* LWL or LDL, depending on MemOp. */
static void gen_lxl(DisasContext *ctx, TCGv reg, TCGv addr,
                     int mem_idx, MemOp mop)
{
    int sizem1 = memop_size(mop) - 1;
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();

    /*
     * Do a byte access to possibly trigger a page
     * fault with the unaligned address.
     */
    tcg_gen_qemu_ld_tl(t1, addr, mem_idx, MO_UB);
    tcg_gen_andi_tl(t1, addr, sizem1);
    if (!disas_is_bigendian(ctx)) {
        tcg_gen_xori_tl(t1, t1, sizem1);
    }
    tcg_gen_shli_tl(t1, t1, 3);
    tcg_gen_andi_tl(t0, addr, ~sizem1);
    tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mop);
    tcg_gen_shl_tl(t0, t0, t1);
    tcg_gen_shl_tl(t1, tcg_constant_tl(-1), t1);
    tcg_gen_andc_tl(t1, reg, t1);
    tcg_gen_or_tl(reg, t0, t1);
}

/* LWR or LDR, depending on MemOp. */
static void gen_lxr(DisasContext *ctx, TCGv reg, TCGv addr,
                     int mem_idx, MemOp mop)
{
    int size = memop_size(mop);
    int sizem1 = size - 1;
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();

    /*
     * Do a byte access to possibly trigger a page
     * fault with the unaligned address.
     */
    tcg_gen_qemu_ld_tl(t1, addr, mem_idx, MO_UB);
    tcg_gen_andi_tl(t1, addr, sizem1);
    if (disas_is_bigendian(ctx)) {
        tcg_gen_xori_tl(t1, t1, sizem1);
    }
    tcg_gen_shli_tl(t1, t1, 3);
    tcg_gen_andi_tl(t0, addr, ~sizem1);
    tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mop);
    tcg_gen_shr_tl(t0, t0, t1);
    tcg_gen_xori_tl(t1, t1, size * 8 - 1);
    tcg_gen_shl_tl(t1, tcg_constant_tl(~1), t1);
    tcg_gen_and_tl(t1, reg, t1);
    tcg_gen_or_tl(reg, t0, t1);
}

/* Load */
static void gen_ld(DisasContext *ctx, uint32_t opc,
                   int rt, int base, int offset)
{
    TCGv t0, t1;
    int mem_idx = ctx->mem_idx;

    if (rt == 0 && ctx->insn_flags & (INSN_LOONGSON2E | INSN_LOONGSON2F |
                                      INSN_LOONGSON3A)) {
        /*
         * Loongson CPU uses a load to zero register for prefetch.
         * We emulate it as a NOP. On other CPU we must perform the
         * actual memory access.
         */
        return;
    }

    t0 = tcg_temp_new();
    gen_base_offset_addr(ctx, t0, base, offset);

    switch (opc) {
#if defined(TARGET_MIPS64)
    case OPC_LWU:
        mips_ident(ctx,
            opc == OPC_LWU ? MIPS_ID_OPC_LWU :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mo_endian(ctx) | MO_UL |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LD:
        mips_ident(ctx,
            opc == OPC_LD ? MIPS_ID_OPC_LD :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LLD:
    case R6_OPC_LLD:
        mips_ident(ctx,
            opc == OPC_LLD ? MIPS_ID_OPC_LLD :
            opc == R6_OPC_LLD ? MIPS_ID_R6_OPC_LLD :
            MIPS_ID_NONE);
        op_ld_lld(t0, t0, mem_idx, ctx);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LDL:
        mips_ident(ctx,
            opc == OPC_LDL ? MIPS_ID_OPC_LDL :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        gen_lxl(ctx, t1, t0, mem_idx, mo_endian(ctx) | MO_UQ);
        gen_store_gpr(t1, rt);
        break;
    case OPC_LDR:
        mips_ident(ctx,
            opc == OPC_LDR ? MIPS_ID_OPC_LDR :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        gen_lxr(ctx, t1, t0, mem_idx, mo_endian(ctx) | MO_UQ);
        gen_store_gpr(t1, rt);
        break;
    case OPC_LDPC:
        mips_ident(ctx,
            opc == OPC_LDPC ? MIPS_ID_OPC_LDPC :
            MIPS_ID_NONE);
        t1 = tcg_constant_tl(pc_relative_pc(ctx));
        gen_op_addr_add(ctx, t0, t0, t1);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mo_endian(ctx) | MO_UQ);
        gen_store_gpr(t0, rt);
        break;
#endif
    case OPC_LWPC:
        mips_ident(ctx,
            opc == OPC_LWPC ? MIPS_ID_OPC_LWPC :
            MIPS_ID_NONE);
        t1 = tcg_constant_tl(pc_relative_pc(ctx));
        gen_op_addr_add(ctx, t0, t0, t1);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mo_endian(ctx) | MO_SL);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LWE:
        mips_ident(ctx,
            opc == OPC_LWE ? MIPS_ID_OPC_LWE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LW:
        mips_ident(ctx,
            opc == OPC_LW ? MIPS_ID_OPC_LW :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mo_endian(ctx) | MO_SL |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LHE:
        mips_ident(ctx,
            opc == OPC_LHE ? MIPS_ID_OPC_LHE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LH:
        mips_ident(ctx,
            opc == OPC_LH ? MIPS_ID_OPC_LH :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mo_endian(ctx) | MO_SW |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LHUE:
        mips_ident(ctx,
            opc == OPC_LHUE ? MIPS_ID_OPC_LHUE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LHU:
        mips_ident(ctx,
            opc == OPC_LHU ? MIPS_ID_OPC_LHU :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, mo_endian(ctx) | MO_UW |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LBE:
        mips_ident(ctx,
            opc == OPC_LBE ? MIPS_ID_OPC_LBE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LB:
        mips_ident(ctx,
            opc == OPC_LB ? MIPS_ID_OPC_LB :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, MO_SB);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LBUE:
        mips_ident(ctx,
            opc == OPC_LBUE ? MIPS_ID_OPC_LBUE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LBU:
        mips_ident(ctx,
            opc == OPC_LBU ? MIPS_ID_OPC_LBU :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, mem_idx, MO_UB);
        gen_store_gpr(t0, rt);
        break;
    case OPC_LWLE:
        mips_ident(ctx,
            opc == OPC_LWLE ? MIPS_ID_OPC_LWLE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LWL:
        mips_ident(ctx,
            opc == OPC_LWL ? MIPS_ID_OPC_LWL :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        gen_lxl(ctx, t1, t0, mem_idx, mo_endian(ctx) | MO_UL);
        tcg_gen_ext32s_tl(t1, t1);
        gen_store_gpr(t1, rt);
        break;
    case OPC_LWRE:
        mips_ident(ctx,
            opc == OPC_LWRE ? MIPS_ID_OPC_LWRE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LWR:
        mips_ident(ctx,
            opc == OPC_LWR ? MIPS_ID_OPC_LWR :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        gen_lxr(ctx, t1, t0, mem_idx, mo_endian(ctx) | MO_UL);
        tcg_gen_ext32s_tl(t1, t1);
        gen_store_gpr(t1, rt);
        break;
    case OPC_LLE:
        mips_ident(ctx,
            opc == OPC_LLE ? MIPS_ID_OPC_LLE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_LL:
    case R6_OPC_LL:
        mips_ident(ctx,
            opc == OPC_LL ? MIPS_ID_OPC_LL :
            opc == R6_OPC_LL ? MIPS_ID_R6_OPC_LL :
            MIPS_ID_NONE);
        op_ld_ll(t0, t0, mem_idx, ctx);
        gen_store_gpr(t0, rt);
        break;
    }
}

/* Store */
static void gen_st(DisasContext *ctx, uint32_t opc, int rt,
                   int base, int offset)
{
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();
    int mem_idx = ctx->mem_idx;

    gen_base_offset_addr(ctx, t0, base, offset);
    gen_load_gpr(t1, rt);
    switch (opc) {
#if defined(TARGET_MIPS64)
    case OPC_SD:
        mips_ident(ctx,
            opc == OPC_SD ? MIPS_ID_OPC_SD :
            MIPS_ID_NONE);
        tcg_gen_qemu_st_tl(t1, t0, mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        break;
    case OPC_SDL:
        mips_ident(ctx,
            opc == OPC_SDL ? MIPS_ID_OPC_SDL :
            MIPS_ID_NONE);
        gen_helper_0e2i(sdl, t1, t0, mem_idx);
        break;
    case OPC_SDR:
        mips_ident(ctx,
            opc == OPC_SDR ? MIPS_ID_OPC_SDR :
            MIPS_ID_NONE);
        gen_helper_0e2i(sdr, t1, t0, mem_idx);
        break;
#endif
    case OPC_SWE:
        mips_ident(ctx,
            opc == OPC_SWE ? MIPS_ID_OPC_SWE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_SW:
        mips_ident(ctx,
            opc == OPC_SW ? MIPS_ID_OPC_SW :
            MIPS_ID_NONE);
        tcg_gen_qemu_st_tl(t1, t0, mem_idx, mo_endian(ctx) | MO_UL |
                           ctx->default_tcg_memop_mask);
        break;
    case OPC_SHE:
        mips_ident(ctx,
            opc == OPC_SHE ? MIPS_ID_OPC_SHE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_SH:
        mips_ident(ctx,
            opc == OPC_SH ? MIPS_ID_OPC_SH :
            MIPS_ID_NONE);
        tcg_gen_qemu_st_tl(t1, t0, mem_idx, mo_endian(ctx) | MO_UW |
                           ctx->default_tcg_memop_mask);
        break;
    case OPC_SBE:
        mips_ident(ctx,
            opc == OPC_SBE ? MIPS_ID_OPC_SBE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_SB:
        mips_ident(ctx,
            opc == OPC_SB ? MIPS_ID_OPC_SB :
            MIPS_ID_NONE);
        tcg_gen_qemu_st_tl(t1, t0, mem_idx, MO_8);
        break;
    case OPC_SWLE:
        mips_ident(ctx,
            opc == OPC_SWLE ? MIPS_ID_OPC_SWLE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_SWL:
        mips_ident(ctx,
            opc == OPC_SWL ? MIPS_ID_OPC_SWL :
            MIPS_ID_NONE);
        gen_helper_0e2i(swl, t1, t0, mem_idx);
        break;
    case OPC_SWRE:
        mips_ident(ctx,
            opc == OPC_SWRE ? MIPS_ID_OPC_SWRE :
            MIPS_ID_NONE);
        mem_idx = MIPS_HFLAG_UM;
        /* fall through */
    case OPC_SWR:
        mips_ident(ctx,
            opc == OPC_SWR ? MIPS_ID_OPC_SWR :
            MIPS_ID_NONE);
        gen_helper_0e2i(swr, t1, t0, mem_idx);
        break;
    }
}


/* Store conditional */
/*
 * The base register a PREFETCH computes its effective address from.
 *
 * Every PREF form QEMU implements is "Treat as NOP" -- a prefetch has no
 * architectural effect a functional emulator has to model, so the arms below
 * emit no op at all and QEMU's ordered read list for the instruction is
 * EMPTY.  The instruction still READS the base register: the encoding names
 * it and the architecture defines the effective address as base + offset.
 * R2 records ARCHITECTURAL dependencies and R15 says a lowering choice --
 * here, the choice to lower a prefetch to nothing -- is not architectural
 * truth, so the read is stated here, where the register number is known.
 *
 * PREFX indexes with a register instead of an immediate and therefore reads
 * TWO: @index is that second register, or -1 for the immediate-offset forms.
 *
 * A $zero operand takes the zero note for the same reason gen_logic()'s
 * folding arms do: cpu_gpr[0] is not a real global and calling the accessor
 * for a temp to hang a note on would emit a dead constant.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_pref_note_operands(int base, int index)
{
    if (base == 0) {
        insn_dataflow_note_folded_read_zero();
    } else {
        insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[base]));
    }
    if (index < 0) {
        return;
    }
    if (index == 0) {
        insn_dataflow_note_folded_read_zero();
    } else {
        insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[index]));
    }
}

static void gen_st_cond(DisasContext *ctx, int rt, int base, int offset,
                        MemOp tcg_mo, bool eva)
{
    TCGv addr, t0, val;
    TCGLabel *l1 = gen_new_label();
    TCGLabel *done = gen_new_label();

    t0 = tcg_temp_new();
    addr = tcg_temp_new();
    /* compare the address against that of the preceding LL */
    gen_base_offset_addr(ctx, addr, base, offset);
    tcg_gen_brcond_tl(TCG_COND_EQ, addr, cpu_lladdr, l1);
    gen_store_gpr(tcg_constant_tl(0), rt);
    tcg_gen_br(done);

    gen_set_label(l1);
    /*
     * This label is reached only when addr and cpu_lladdr hold the same
     * address -- that is what the brcond above tested -- and the cmpxchg
     * below is handed cpu_lladdr, so the access would state its address
     * provenance as the LL monitor, which no guest instruction writes,
     * instead of as the base register.  The equality is proved on the way
     * in, so it is stated on the way in.
     */
    insn_dataflow_note_addr_alias(tcgv_tl_temp(cpu_lladdr),
                                  tcgv_tl_temp(addr));

    /* generate cmpxchg */
    val = tcg_temp_new();
    gen_load_gpr(val, rt);
    /*
     * THE DATUM REGISTER IS A SOURCE, and the walk cannot see that it is.
     *
     * `sc rt,off(base)` READS rt -- the word to be stored -- and WRITES rt
     * -- the success flag.  Both are architectural and the read is the one
     * QEMU's op stream loses, because the FAIL path above already wrote
     * cpu_gpr[rt] (the zero the failure returns) before this line reads it.
     * The extractor's standing rule is that a read of a register the
     * instruction has already written is a read of the instruction's own
     * intermediate value and not an input edge -- which is right for a
     * lowering that computes into a register and reads it back, and wrong
     * here, because the write above and this read are on MUTUALLY EXCLUSIVE
     * paths and no execution performs both.
     *
     * The emitter is the only party that knows the two sites cannot both
     * run, so it states the read.  Stated even when rt is $zero: R7.3 keeps
     * the zero register on the wire, and gen_load_gpr() hands back a
     * constant there with no global to name.
     */
    if (rt == 0) {
        insn_dataflow_note_folded_read_zero();
    } else {
        insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[rt]));
    }
    tcg_gen_atomic_cmpxchg_tl(t0, cpu_lladdr, cpu_llval, val,
                              eva ? MIPS_HFLAG_UM : ctx->mem_idx, tcg_mo);
    tcg_gen_setcond_tl(TCG_COND_EQ, t0, t0, cpu_llval);
    gen_store_gpr(t0, rt);

    gen_set_label(done);
}

/* Load and store */
static void gen_flt_ldst(DisasContext *ctx, uint32_t opc, int ft,
                         TCGv t0)
{
    /*
     * Don't do NOP if destination is zero: we must perform the actual
     * memory access.
     */
    switch (opc) {
    case OPC_LWC1:
        mips_ident(ctx,
            opc == OPC_LWC1 ? MIPS_ID_OPC_LWC1 :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            tcg_gen_qemu_ld_i32(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_SL |
                                ctx->default_tcg_memop_mask);
            gen_store_fpr32(ctx, fp0, ft);
        }
        break;
    case OPC_SWC1:
        mips_ident(ctx,
            opc == OPC_SWC1 ? MIPS_ID_OPC_SWC1 :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, ft);
            tcg_gen_qemu_st_i32(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UL |
                                ctx->default_tcg_memop_mask);
        }
        break;
    case OPC_LDC1:
        mips_ident(ctx,
            opc == OPC_LDC1 ? MIPS_ID_OPC_LDC1 :
            MIPS_ID_NONE);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            tcg_gen_qemu_ld_i64(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                                ctx->default_tcg_memop_mask);
            gen_store_fpr64(ctx, fp0, ft);
        }
        break;
    case OPC_SDC1:
        mips_ident(ctx,
            opc == OPC_SDC1 ? MIPS_ID_OPC_SDC1 :
            MIPS_ID_NONE);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, ft);
            tcg_gen_qemu_st_i64(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                                ctx->default_tcg_memop_mask);
        }
        break;
    default:
        MIPS_INVAL("flt_ldst");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void gen_cop1_ldst(DisasContext *ctx, uint32_t op, int rt,
                          int rs, int16_t imm)
{
    TCGv t0 = tcg_temp_new();

    if (ctx->CP0_Config1 & (1 << CP0C1_FP)) {
        check_cp1_enabled(ctx);
        switch (op) {
        case OPC_LDC1:
        case OPC_SDC1:
            mips_ident(ctx,
                op == OPC_LDC1 ? MIPS_ID_OPC_LDC1 :
                op == OPC_SDC1 ? MIPS_ID_OPC_SDC1 :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS2);
            /* Fallthrough */
        default:
            gen_base_offset_addr(ctx, t0, rs, imm);
            gen_flt_ldst(ctx, op, rt, t0);
        }
    } else {
        generate_exception_err(ctx, EXCP_CpU, 1);
    }
}

/* Arithmetic with immediate operand */
static void gen_arith_imm(DisasContext *ctx, uint32_t opc,
                          int rt, int rs, int imm)
{
    target_ulong uimm = (target_long)imm; /* Sign extend to 32/64 bits */

    if (rt == 0 && opc != OPC_ADDI && opc != OPC_DADDI) {
        /*
         * If no destination, treat it as a NOP.
         * For addi, we must generate the overflow exception when needed.
         */
        /* The operands the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rs);
        return;
    }

    /*
     * CP-M, the ENCODED-IMMEDIATE half.  `uimm` is this instruction's encoded immediate
     * field, sign- or zero-extended exactly as the emitters below will use
     * it, so naming it here names the interned temp TCG will hand them.
     * Capture only; no op is emitted, altered or suppressed.  See
     * insn_dataflow_note_encoded_imm().
     */
    insn_dataflow_note_encoded_imm(tcgv_tl_temp(tcg_constant_tl(uimm)));

    switch (opc) {
    case OPC_ADDI:
        mips_ident(ctx,
            opc == OPC_ADDI ? MIPS_ID_OPC_ADDI :
            MIPS_ID_NONE);
        {
            TCGv t0 = tcg_temp_new();
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_temp_new();
            TCGLabel *l1 = gen_new_label();

            gen_load_gpr(t1, rs);
            tcg_gen_addi_tl(t0, t1, uimm);
            tcg_gen_ext32s_tl(t0, t0);

            tcg_gen_xori_tl(t1, t1, ~uimm);
            tcg_gen_xori_tl(t2, t0, uimm);
            tcg_gen_and_tl(t1, t1, t2);
            tcg_gen_brcondi_tl(TCG_COND_GE, t1, 0, l1);
            /* operands of same sign, result different sign */
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(l1);
            tcg_gen_ext32s_tl(t0, t0);
            gen_store_gpr(t0, rt);
        }
        break;
    case OPC_ADDIU:
        mips_ident(ctx,
            opc == OPC_ADDIU ? MIPS_ID_OPC_ADDIU :
            MIPS_ID_NONE);
        if (rs != 0) {
            tcg_gen_addi_tl(cpu_gpr[rt], cpu_gpr[rs], uimm);
            tcg_gen_ext32s_tl(cpu_gpr[rt], cpu_gpr[rt]);
        } else {
            /*
             * `addiu rt,$zero,imm` IS `li rt,imm`, and this arm folds the
             * source away: gen_load_gpr() is never called, so no
             * zero-register note is taken and no op reads the operand.  R7.3
             * rules the register the encoding names is not the emulator's to
             * drop, so it is said here, where the register number is known.
             * Calling the accessor to get a temp to hang a note on would emit
             * a dead constant, which the capture discipline forbids.
             * Capture only; no op is emitted, altered or suppressed.
             */
            insn_dataflow_note_folded_read_zero();
            tcg_gen_movi_tl(cpu_gpr[rt], uimm);
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DADDI:
        mips_ident(ctx,
            opc == OPC_DADDI ? MIPS_ID_OPC_DADDI :
            MIPS_ID_NONE);
        {
            TCGv t0 = tcg_temp_new();
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_temp_new();
            TCGLabel *l1 = gen_new_label();

            gen_load_gpr(t1, rs);
            tcg_gen_addi_tl(t0, t1, uimm);

            tcg_gen_xori_tl(t1, t1, ~uimm);
            tcg_gen_xori_tl(t2, t0, uimm);
            tcg_gen_and_tl(t1, t1, t2);
            tcg_gen_brcondi_tl(TCG_COND_GE, t1, 0, l1);
            /* operands of same sign, result different sign */
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(l1);
            gen_store_gpr(t0, rt);
        }
        break;
    case OPC_DADDIU:
        mips_ident(ctx,
            opc == OPC_DADDIU ? MIPS_ID_OPC_DADDIU :
            MIPS_ID_NONE);
        if (rs != 0) {
            tcg_gen_addi_tl(cpu_gpr[rt], cpu_gpr[rs], uimm);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rt], uimm);
        }
        break;
#endif
    }
}

/* Logic with immediate operand */
static void gen_logic_imm(DisasContext *ctx, uint32_t opc,
                          int rt, int rs, int16_t imm)
{
    target_ulong uimm;

    if (rt == 0) {
        /*
         * If no destination, treat it as a NOP.
         *
         * The operand the NOP erases; see note_gpr_folded_read().  LUI is
         * the exception and it is a REAL one: before MIPS32R6 `lui rt,imm`
         * has no source register at all -- bits 25:21 are a reserved field
         * the architecture requires to be zero, not a register the encoding
         * names -- and only R6's AUI makes them an operand.  The same test
         * the emitter itself uses below decides it.  Measured: stating it
         * unconditionally put REG_ZERO on 2,304 `lui` encodings that read
         * nothing, which is the fabrication R15/R16 call a defect.
         */
        if (opc != OPC_LUI || (ctx->insn_flags & ISA_MIPS_R6)) {
            note_gpr_folded_read(rs);
        }
        return;
    }
    uimm = (uint16_t)imm;

    /*
     * CP-M, the ENCODED-IMMEDIATE half.  `uimm` is this instruction's encoded immediate
     * field, sign- or zero-extended exactly as the emitters below will use
     * it, so naming it here names the interned temp TCG will hand them.
     * Capture only; no op is emitted, altered or suppressed.  See
     * insn_dataflow_note_encoded_imm().
     */
    insn_dataflow_note_encoded_imm(tcgv_tl_temp(tcg_constant_tl(uimm)));

    switch (opc) {
    case OPC_ANDI:
        mips_ident(ctx,
            opc == OPC_ANDI ? MIPS_ID_OPC_ANDI :
            MIPS_ID_NONE);
        /* `andi rt,$zero,imm` IS `li rt,0`; see note_gpr_folded_read(). */
        if (rs == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (likely(rs != 0)) {
            tcg_gen_andi_tl(cpu_gpr[rt], cpu_gpr[rs], uimm);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rt], 0);
        }
        break;
    case OPC_ORI:
        mips_ident(ctx,
            opc == OPC_ORI ? MIPS_ID_OPC_ORI :
            MIPS_ID_NONE);
        /*
         * `ori rt,$zero,imm` IS `li rt,imm`, and the else arm below folds
         * the source away: cpu_gpr[0] is never touched, gen_load_gpr() is
         * never called, so no zero-register note is taken and no op reads
         * the operand.  R7.3/R15 rule the register the encoding names is
         * not the emulator's to drop, so it is said here, where the
         * register number is known.  Calling the accessor to get a temp to
         * hang a note on would emit a dead constant, which the capture
         * discipline forbids.
         * Capture only; no op is emitted, altered or suppressed.
         */
        if (rs == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (rs != 0) {
            tcg_gen_ori_tl(cpu_gpr[rt], cpu_gpr[rs], uimm);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rt], uimm);
        }
        break;
    case OPC_XORI:
        mips_ident(ctx,
            opc == OPC_XORI ? MIPS_ID_OPC_XORI :
            MIPS_ID_NONE);
        /* `xori rt,$zero,imm` IS `li rt,imm`; see note_gpr_folded_read(). */
        if (rs == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (likely(rs != 0)) {
            tcg_gen_xori_tl(cpu_gpr[rt], cpu_gpr[rs], uimm);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rt], uimm);
        }
        break;
    case OPC_LUI:
        mips_ident(ctx,
            opc == OPC_LUI ? MIPS_ID_OPC_LUI :
            MIPS_ID_NONE);
        /*
         * `lui` is `aui rt,$zero,imm` on R6 and a distinct instruction
         * before it; on the R6 encoding the source register IS named and
         * the else arm folds it away.  See note_gpr_folded_read().
         */
        if (rs == 0 && (ctx->insn_flags & ISA_MIPS_R6)) {
            insn_dataflow_note_folded_read_zero();
        }
        if (rs != 0 && (ctx->insn_flags & ISA_MIPS_R6)) {
            /* OPC_AUI */
            tcg_gen_addi_tl(cpu_gpr[rt], cpu_gpr[rs], imm << 16);
            tcg_gen_ext32s_tl(cpu_gpr[rt], cpu_gpr[rt]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rt], imm << 16);
        }
        break;

    default:
        break;
    }
}

/* Set on less than with immediate operand */
static void gen_slt_imm(DisasContext *ctx, uint32_t opc,
                        int rt, int rs, int16_t imm)
{
    target_ulong uimm = (target_long)imm; /* Sign extend to 32/64 bits */
    TCGv t0;

    if (rt == 0) {
        /* If no destination, treat it as a NOP. */
        /* The operands the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rs);
        return;
    }
    t0 = tcg_temp_new();
    gen_load_gpr(t0, rs);

    /*
     * CP-M, the ENCODED-IMMEDIATE half.  `uimm` is this instruction's encoded immediate
     * field, sign- or zero-extended exactly as the emitters below will use
     * it, so naming it here names the interned temp TCG will hand them.
     * Capture only; no op is emitted, altered or suppressed.  See
     * insn_dataflow_note_encoded_imm().
     */
    insn_dataflow_note_encoded_imm(tcgv_tl_temp(tcg_constant_tl(uimm)));

    switch (opc) {
    case OPC_SLTI:
        mips_ident(ctx,
            opc == OPC_SLTI ? MIPS_ID_OPC_SLTI :
            MIPS_ID_NONE);
        tcg_gen_setcondi_tl(TCG_COND_LT, cpu_gpr[rt], t0, uimm);
        break;
    case OPC_SLTIU:
        mips_ident(ctx,
            opc == OPC_SLTIU ? MIPS_ID_OPC_SLTIU :
            MIPS_ID_NONE);
        tcg_gen_setcondi_tl(TCG_COND_LTU, cpu_gpr[rt], t0, uimm);
        break;
    }
}

/* Shifts with immediate operand */
static void gen_shift_imm(DisasContext *ctx, uint32_t opc,
                          int rt, int rs, int16_t imm)
{
    target_ulong uimm = ((uint16_t)imm) & 0x1f;
    TCGv t0;

    if (rt == 0) {
        /* If no destination, treat it as a NOP. */
        return;
    }

    t0 = tcg_temp_new();
    gen_load_gpr(t0, rs);

    /*
     * CP-M, the ENCODED-IMMEDIATE half.  `uimm` is this instruction's encoded shift-amount
     * field, sign- or zero-extended exactly as the emitters below will use
     * it, so naming it here names the interned temp TCG will hand them.
     * Capture only; no op is emitted, altered or suppressed.  See
     * insn_dataflow_note_encoded_imm().
     */
    insn_dataflow_note_encoded_imm(tcgv_tl_temp(tcg_constant_tl(uimm)));

    switch (opc) {
    case OPC_SLL:
        mips_ident(ctx,
            opc == OPC_SLL ? mips_ident_q_OPC_SLL(ctx->opcode) :
            MIPS_ID_NONE);
        tcg_gen_shli_tl(t0, t0, uimm);
        tcg_gen_ext32s_tl(cpu_gpr[rt], t0);
        break;
    case OPC_SRA:
        mips_ident(ctx,
            opc == OPC_SRA ? MIPS_ID_OPC_SRA :
            MIPS_ID_NONE);
        tcg_gen_sari_tl(cpu_gpr[rt], t0, uimm);
        break;
    case OPC_SRL:
        mips_ident(ctx,
            opc == OPC_SRL ? MIPS_ID_OPC_SRL :
            MIPS_ID_NONE);
        if (uimm != 0) {
            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_shri_tl(cpu_gpr[rt], t0, uimm);
        } else {
            tcg_gen_ext32s_tl(cpu_gpr[rt], t0);
        }
        break;
    case OPC_ROTR:
        mips_ident(ctx,
            opc == OPC_ROTR ? MIPS_ID_OPC_ROTR :
            MIPS_ID_NONE);
        if (uimm != 0) {
            TCGv_i32 t1 = tcg_temp_new_i32();

            tcg_gen_trunc_tl_i32(t1, t0);
            tcg_gen_rotri_i32(t1, t1, uimm);
            tcg_gen_ext_i32_tl(cpu_gpr[rt], t1);
        } else {
            tcg_gen_ext32s_tl(cpu_gpr[rt], t0);
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DSLL:
        mips_ident(ctx,
            opc == OPC_DSLL ? MIPS_ID_OPC_DSLL :
            MIPS_ID_NONE);
        tcg_gen_shli_tl(cpu_gpr[rt], t0, uimm);
        break;
    case OPC_DSRA:
        mips_ident(ctx,
            opc == OPC_DSRA ? MIPS_ID_OPC_DSRA :
            MIPS_ID_NONE);
        tcg_gen_sari_tl(cpu_gpr[rt], t0, uimm);
        break;
    case OPC_DSRL:
        mips_ident(ctx,
            opc == OPC_DSRL ? MIPS_ID_OPC_DSRL :
            MIPS_ID_NONE);
        tcg_gen_shri_tl(cpu_gpr[rt], t0, uimm);
        break;
    case OPC_DROTR:
        mips_ident(ctx,
            opc == OPC_DROTR ? MIPS_ID_OPC_DROTR :
            MIPS_ID_NONE);
        if (uimm != 0) {
            tcg_gen_rotri_tl(cpu_gpr[rt], t0, uimm);
        } else {
            tcg_gen_mov_tl(cpu_gpr[rt], t0);
        }
        break;
    case OPC_DSLL32:
        mips_ident(ctx,
            opc == OPC_DSLL32 ? MIPS_ID_OPC_DSLL32 :
            MIPS_ID_NONE);
        tcg_gen_shli_tl(cpu_gpr[rt], t0, uimm + 32);
        break;
    case OPC_DSRA32:
        mips_ident(ctx,
            opc == OPC_DSRA32 ? MIPS_ID_OPC_DSRA32 :
            MIPS_ID_NONE);
        tcg_gen_sari_tl(cpu_gpr[rt], t0, uimm + 32);
        break;
    case OPC_DSRL32:
        mips_ident(ctx,
            opc == OPC_DSRL32 ? MIPS_ID_OPC_DSRL32 :
            MIPS_ID_NONE);
        tcg_gen_shri_tl(cpu_gpr[rt], t0, uimm + 32);
        break;
    case OPC_DROTR32:
        mips_ident(ctx,
            opc == OPC_DROTR32 ? MIPS_ID_OPC_DROTR32 :
            MIPS_ID_NONE);
        tcg_gen_rotri_tl(cpu_gpr[rt], t0, uimm + 32);
        break;
#endif
    }
}

/* Arithmetic */
static void gen_arith(DisasContext *ctx, uint32_t opc,
                      int rd, int rs, int rt)
{
    if (rd == 0 && opc != OPC_ADD && opc != OPC_SUB
       && opc != OPC_DADD && opc != OPC_DSUB) {
        /*
         * If no destination, treat it as a NOP.
         * For add & sub, we must generate the overflow exception when needed.
         *
         * AND THE READS, which that NOP erases.  `addu $zero,$t0,$t1` is a
         * real instruction whose encoding names $t0 and $t1 as sources; the
         * emulator may drop the WRITE, because nothing can read $zero back,
         * but R7.3/R15 do not let it drop the operands with it.  With no op
         * emitted the walk sees nothing at all, so the read set for the whole
         * instruction is empty while the wire publishes the registers the
         * encoding named.  gen_logic()'s own rd == 0 arm has said exactly
         * this since be84cc6598; this is the arithmetic half of it, and it
         * adds the zero-register operand of a two-operand form, which the
         * wire DOES carry here (`addu $zero,$zero,$zero`).
         *
         * Capture only; no op is emitted, altered or suppressed.
         */
        note_gpr_folded_read(rs);
        note_gpr_folded_read(rt);
        return;
    }

    switch (opc) {
    case OPC_ADD:
        mips_ident(ctx,
            opc == OPC_ADD ? MIPS_ID_OPC_ADD :
            MIPS_ID_NONE);
        {
            TCGv t0 = tcg_temp_new();
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_temp_new();
            TCGLabel *l1 = gen_new_label();

            gen_load_gpr(t1, rs);
            gen_load_gpr(t2, rt);
            tcg_gen_add_tl(t0, t1, t2);
            tcg_gen_ext32s_tl(t0, t0);
            tcg_gen_xor_tl(t1, t1, t2);
            tcg_gen_xor_tl(t2, t0, t2);
            tcg_gen_andc_tl(t1, t2, t1);
            tcg_gen_brcondi_tl(TCG_COND_GE, t1, 0, l1);
            /* operands of same sign, result different sign */
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(l1);
            gen_store_gpr(t0, rd);
        }
        break;
    case OPC_ADDU:
        mips_ident(ctx,
            opc == OPC_ADDU ? MIPS_ID_OPC_ADDU :
            MIPS_ID_NONE);
        /*
         * `move rd,rs` IS `addu rd,rs,$zero`, and every arm below with a
         * zero operand folds it away -- cpu_gpr[0] is never touched, so no
         * op reads it and QEMU's ordered read list is short by a register
         * the ENCODING names.  R7.3/R15 rule that absence the emulator's
         * lowering choice and not the machine's, and gen_logic()'s NOR arm
         * already says exactly this about `not rd,rs`.  One statement even
         * when BOTH operands are $zero: the read set is a set and they are
         * the same register.
         *
         * IT IS SAID HERE AND NOT IN A TABLE, and that is the whole point.
         * A survivor table is keyed on the DECODE IDENTITY, which is the
         * same for `addu $v0,$a0,$a1` and `addu $v0,$a0,$zero`; a constant
         * row would hand the three-register form a REG_ZERO source it does
         * not have.  Measured before this note existed: 493 fabricated rows
         * on the w19 corpus, 609 on w3_coverage, 49 on the validator's own
         * mipsel workload.  The condition is a property of the ENCODING and
         * only the decoder can test it.
         *
         * Capture only; no op is emitted, altered or suppressed.
         */
        if (rs == 0 || rt == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        /*
         * AND THE SURVIVING OPERAND, when `move rd,rd` erases it too.
         *
         * The two mov arms below go through `tcg_gen_mov_tl(cpu_gpr[rd],
         * cpu_gpr[rX])`, which emits NOTHING when rd == rX.  `move $t0,$t0`
         * -- `addu $t0,$t0,$zero` -- therefore leaves NO op at all: the zero
         * note above is the entire ordered read list, and rX, which the
         * encoding names as plainly as it does on `move $t0,$t1`, is gone
         * with the write.  R7.3/R15: that absence is the emulator's lowering
         * choice, not the machine's.
         *
         * Guarded on the elision, like the zero fold above it: every other
         * path here emits an op that reads rX and the op walk states it.
         *
         * Capture only; no op is emitted, altered or suppressed.
         */
        if (rd != 0 && rs == 0 && rt == rd) {
            insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[rt]));
        }
        if (rd != 0 && rt == 0 && rs == rd) {
            insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[rs]));
        }
        if (rs != 0 && rt != 0) {
            tcg_gen_add_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        } else if (rs == 0 && rt != 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rt]);
        } else if (rs != 0 && rt == 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rs]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        break;
    case OPC_SUB:
        mips_ident(ctx,
            opc == OPC_SUB ? MIPS_ID_OPC_SUB :
            MIPS_ID_NONE);
        {
            TCGv t0 = tcg_temp_new();
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_temp_new();
            TCGLabel *l1 = gen_new_label();

            gen_load_gpr(t1, rs);
            gen_load_gpr(t2, rt);
            tcg_gen_sub_tl(t0, t1, t2);
            tcg_gen_ext32s_tl(t0, t0);
            tcg_gen_xor_tl(t2, t1, t2);
            tcg_gen_xor_tl(t1, t0, t1);
            tcg_gen_and_tl(t1, t1, t2);
            tcg_gen_brcondi_tl(TCG_COND_GE, t1, 0, l1);
            /*
             * operands of different sign, first operand and the result
             * of different sign
             */
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(l1);
            gen_store_gpr(t0, rd);
        }
        break;
    case OPC_SUBU:
        mips_ident(ctx,
            opc == OPC_SUBU ? MIPS_ID_OPC_SUBU :
            MIPS_ID_NONE);
        if (rs != 0 && rt != 0) {
            tcg_gen_sub_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        } else if (rs == 0 && rt != 0) {
            tcg_gen_neg_tl(cpu_gpr[rd], cpu_gpr[rt]);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        } else if (rs != 0 && rt == 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rs]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DADD:
        mips_ident(ctx,
            opc == OPC_DADD ? MIPS_ID_OPC_DADD :
            MIPS_ID_NONE);
        {
            TCGv t0 = tcg_temp_new();
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_temp_new();
            TCGLabel *l1 = gen_new_label();

            gen_load_gpr(t1, rs);
            gen_load_gpr(t2, rt);
            tcg_gen_add_tl(t0, t1, t2);
            tcg_gen_xor_tl(t1, t1, t2);
            tcg_gen_xor_tl(t2, t0, t2);
            tcg_gen_andc_tl(t1, t2, t1);
            tcg_gen_brcondi_tl(TCG_COND_GE, t1, 0, l1);
            /* operands of same sign, result different sign */
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(l1);
            gen_store_gpr(t0, rd);
        }
        break;
    case OPC_DADDU:
        mips_ident(ctx,
            opc == OPC_DADDU ? MIPS_ID_OPC_DADDU :
            MIPS_ID_NONE);
        if (rs != 0 && rt != 0) {
            tcg_gen_add_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
        } else if (rs == 0 && rt != 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rt]);
        } else if (rs != 0 && rt == 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rs]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        break;
    case OPC_DSUB:
        mips_ident(ctx,
            opc == OPC_DSUB ? MIPS_ID_OPC_DSUB :
            MIPS_ID_NONE);
        {
            TCGv t0 = tcg_temp_new();
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_temp_new();
            TCGLabel *l1 = gen_new_label();

            gen_load_gpr(t1, rs);
            gen_load_gpr(t2, rt);
            tcg_gen_sub_tl(t0, t1, t2);
            tcg_gen_xor_tl(t2, t1, t2);
            tcg_gen_xor_tl(t1, t0, t1);
            tcg_gen_and_tl(t1, t1, t2);
            tcg_gen_brcondi_tl(TCG_COND_GE, t1, 0, l1);
            /*
             * Operands of different sign, first operand and result different
             * sign.
             */
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(l1);
            gen_store_gpr(t0, rd);
        }
        break;
    case OPC_DSUBU:
        mips_ident(ctx,
            opc == OPC_DSUBU ? MIPS_ID_OPC_DSUBU :
            MIPS_ID_NONE);
        if (rs != 0 && rt != 0) {
            tcg_gen_sub_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
        } else if (rs == 0 && rt != 0) {
            tcg_gen_neg_tl(cpu_gpr[rd], cpu_gpr[rt]);
        } else if (rs != 0 && rt == 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rs]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        break;
#endif
    case OPC_MUL:
        mips_ident(ctx,
            opc == OPC_MUL ? MIPS_ID_OPC_MUL :
            MIPS_ID_NONE);
        /* `mul rd,rs,$zero` IS `li rd,0`; see note_gpr_folded_read(). */
        if (rs == 0 || rt == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (likely(rs != 0 && rt != 0)) {
            tcg_gen_mul_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        /*
         * CP-M, the DISCARDED-WRITE half.  MIPS32 defines HI and LO as
         * UNPREDICTABLE after MUL, which is the architecture saying the
         * multiplier ran and destroyed them; QEMU correctly emits no write,
         * because nothing may read the result back.  The destruction is
         * still a WAW hazard against the next `mfhi`/`mflo` and a consumer
         * keeping a scoreboard has to see it (R2).  The value is the one the
         * multiply produced, so cpu_gpr[rd] -- which the ops just gave the
         * multiply's own provenance -- is what the note names.  Capture
         * only; no op is emitted, altered or suppressed.
         */
        insn_dataflow_note_discarded_write(tcgv_tl_temp(cpu_gpr[rd]), "hi");
        insn_dataflow_note_discarded_write(tcgv_tl_temp(cpu_gpr[rd]), "lo");
        break;
    }
}

/* Conditional move */
static void gen_cond_move(DisasContext *ctx, uint32_t opc,
                          int rd, int rs, int rt)
{
    TCGv t0, t1, t2;

    if (rd == 0) {
        /* If no destination, treat it as a NOP. */
        /* The operands the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rs);
        note_gpr_folded_read(rt);
        return;
    }

    t0 = tcg_temp_new();
    gen_load_gpr(t0, rt);
    t1 = tcg_constant_tl(0);
    t2 = tcg_temp_new();
    gen_load_gpr(t2, rs);
    switch (opc) {
    case OPC_MOVN:
        mips_ident(ctx,
            opc == OPC_MOVN ? MIPS_ID_OPC_MOVN :
            MIPS_ID_NONE);
        tcg_gen_movcond_tl(TCG_COND_NE, cpu_gpr[rd], t0, t1, t2, cpu_gpr[rd]);
        break;
    case OPC_MOVZ:
        mips_ident(ctx,
            opc == OPC_MOVZ ? MIPS_ID_OPC_MOVZ :
            MIPS_ID_NONE);
        tcg_gen_movcond_tl(TCG_COND_EQ, cpu_gpr[rd], t0, t1, t2, cpu_gpr[rd]);
        break;
    case OPC_SELNEZ:
        mips_ident(ctx,
            opc == OPC_SELNEZ ? MIPS_ID_OPC_SELNEZ :
            MIPS_ID_NONE);
        tcg_gen_movcond_tl(TCG_COND_NE, cpu_gpr[rd], t0, t1, t2, t1);
        break;
    case OPC_SELEQZ:
        mips_ident(ctx,
            opc == OPC_SELEQZ ? MIPS_ID_OPC_SELEQZ :
            MIPS_ID_NONE);
        tcg_gen_movcond_tl(TCG_COND_EQ, cpu_gpr[rd], t0, t1, t2, t1);
        break;
    }
}

/* Logic */
static void gen_logic(DisasContext *ctx, uint32_t opc,
                      int rd, int rs, int rt)
{
    if (rd == 0) {
        /*
         * If no destination, treat it as a NOP.
         *
         * CP-M, the DISCARDED-WRITE half.  A NOP is what the EMULATOR may
         * do -- nothing can read $zero back -- and not what the instruction
         * is: `move $zero,$ra` is `or $0,$31,$0`, and the encoding names
         * $zero as the destination exactly the way it would name $t0
         * (R7.3).  With no op emitted the walk sees no write at all, so the
         * fact is stated here, where the register numbers are still in hand.
         * One statement per source operand; they merge into one row whose
         * provenance is their union.  Capture only.
         */
        if (rs != 0) {
            insn_dataflow_note_discarded_zero_write(tcgv_tl_temp(cpu_gpr[rs]));
        }
        if (rt != 0) {
            insn_dataflow_note_discarded_zero_write(tcgv_tl_temp(cpu_gpr[rt]));
        }
        /*
         * AND THE READS, which the discarded-write notes above do NOT say.
         *
         * A discarded write states a WRITE and where its value came from;
         * the provenance is not the instruction's READ SET, and this arm
         * emits no op at all, so QEMU's ordered read list for `move
         * $zero,$ra` is EMPTY while the encoding plainly names $ra as a
         * source.  R7.3/R15: a source the emulator resolved at translation
         * time -- here, resolved into nothing, because nothing can read
         * $zero back -- is not the emulator's to drop.
         *
         * The zero-register operand IS stated, which reverses an earlier
         * reading of this arm.  It was deferred as "a source the wire does
         * not carry today"; measured at PASS 49 the wire carries it --
         * `and $zero,$zero,$zero` loses REG_ZERO when the operand walk goes
         * -- and R15 rules the zero register expressed.
         *
         * Capture only; no op is emitted, altered or suppressed.
         */
        note_gpr_folded_read(rs);
        note_gpr_folded_read(rt);
        return;
    }

    switch (opc) {
    case OPC_AND:
        mips_ident(ctx,
            opc == OPC_AND ? MIPS_ID_OPC_AND :
            MIPS_ID_NONE);
        /* `and rd,rs,$zero` IS `li rd,0`; see note_gpr_folded_read(). */
        if (rs == 0 || rt == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (likely(rs != 0 && rt != 0)) {
            tcg_gen_and_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        break;
    case OPC_NOR:
        mips_ident(ctx,
            opc == OPC_NOR ? MIPS_ID_OPC_NOR :
            MIPS_ID_NONE);
        /*
         * `not rd,rs` IS `nor rd,rs,$zero`, and every arm below with a zero
         * operand folds it away -- cpu_gpr[0] is never touched, so no
         * zero-register note is taken and no op reads the operand.
         * R7.3/R15 rule the register the encoding names is not the
         * emulator's to drop, so it is said here, where the register
         * numbers are known.  One statement even when BOTH operands are
         * $zero: the read set is a set and they are the same register.
         * Capture only; no op is emitted, altered or suppressed.
         */
        if (rs == 0 || rt == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (rs != 0 && rt != 0) {
            tcg_gen_nor_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
        } else if (rs == 0 && rt != 0) {
            tcg_gen_not_tl(cpu_gpr[rd], cpu_gpr[rt]);
        } else if (rs != 0 && rt == 0) {
            tcg_gen_not_tl(cpu_gpr[rd], cpu_gpr[rs]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], ~((target_ulong)0));
        }
        break;
    case OPC_OR:
        mips_ident(ctx,
            opc == OPC_OR ? MIPS_ID_OPC_OR :
            MIPS_ID_NONE);
        /*
         * `move rd,rs` IS `or rd,rs,$zero` -- the assembler's idiom and the
         * one the compiler emits -- and every arm below with a zero operand
         * folds it away: cpu_gpr[0] is never touched, so no op reads it and
         * QEMU's ordered read list is short by a register the ENCODING
         * names.  R7.3/R15 rule that absence the emulator's lowering choice
         * and not the machine's; OPC_NOR above and OPC_ADDU in gen_arith()
         * already say exactly this about `not rd,rs` and `move rd,rs`'s
         * other spelling.  One statement even when BOTH operands are $zero:
         * the read set is a set and they are the same register.
         *
         * IT IS SAID HERE AND NOT IN A TABLE.  A survivor table is keyed on
         * the DECODE IDENTITY, and `or $v0,$a0,$a1` and `or $v0,$a0,$zero`
         * share it, so a constant row would hand the three-register form a
         * REG_ZERO source it does not have.  The condition is a property of
         * the ENCODING and only the decoder can test it.
         *
         * Capture only; no op is emitted, altered or suppressed.
         */
        if (rs == 0 || rt == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        /*
         * AND THE SURVIVING OPERAND, when `move rd,rd` erases it too.
         *
         * The two mov arms below go through `tcg_gen_mov_tl(cpu_gpr[rd],
         * cpu_gpr[rX])`, which emits NOTHING when rd == rX.  `move $t0,$t0`
         * -- `or $t0,$t0,$zero` -- therefore leaves NO op at all: the zero
         * note above is the entire ordered read list, and rX, which the
         * encoding names as plainly as it does on `move $t0,$t1`, is gone
         * with the write.  R7.3/R15: that absence is the emulator's lowering
         * choice, not the machine's.
         *
         * Guarded on the elision, like the zero fold above it: every other
         * path here emits an op that reads rX and the op walk states it.
         *
         * Capture only; no op is emitted, altered or suppressed.
         */
        if (rd != 0 && rs == 0 && rt == rd) {
            insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[rt]));
        }
        if (rd != 0 && rt == 0 && rs == rd) {
            insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_gpr[rs]));
        }
        if (likely(rs != 0 && rt != 0)) {
            tcg_gen_or_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
        } else if (rs == 0 && rt != 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rt]);
        } else if (rs != 0 && rt == 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rs]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        break;
    case OPC_XOR:
        mips_ident(ctx,
            opc == OPC_XOR ? MIPS_ID_OPC_XOR :
            MIPS_ID_NONE);
        /* `xor rd,rs,$zero` IS `move rd,rs`; see note_gpr_folded_read(). */
        if (rs == 0 || rt == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (likely(rs != 0 && rt != 0)) {
            tcg_gen_xor_tl(cpu_gpr[rd], cpu_gpr[rs], cpu_gpr[rt]);
        } else if (rs == 0 && rt != 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rt]);
        } else if (rs != 0 && rt == 0) {
            tcg_gen_mov_tl(cpu_gpr[rd], cpu_gpr[rs]);
        } else {
            tcg_gen_movi_tl(cpu_gpr[rd], 0);
        }
        break;
    }
}

/* Set on lower than */
static void gen_slt(DisasContext *ctx, uint32_t opc,
                    int rd, int rs, int rt)
{
    TCGv t0, t1;

    if (rd == 0) {
        /* If no destination, treat it as a NOP. */
        /* The operands the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rs);
        note_gpr_folded_read(rt);
        return;
    }

    t0 = tcg_temp_new();
    t1 = tcg_temp_new();
    gen_load_gpr(t0, rs);
    gen_load_gpr(t1, rt);
    switch (opc) {
    case OPC_SLT:
        mips_ident(ctx,
            opc == OPC_SLT ? MIPS_ID_OPC_SLT :
            MIPS_ID_NONE);
        tcg_gen_setcond_tl(TCG_COND_LT, cpu_gpr[rd], t0, t1);
        break;
    case OPC_SLTU:
        mips_ident(ctx,
            opc == OPC_SLTU ? MIPS_ID_OPC_SLTU :
            MIPS_ID_NONE);
        tcg_gen_setcond_tl(TCG_COND_LTU, cpu_gpr[rd], t0, t1);
        break;
    }
}

/* Shifts */
static void gen_shift(DisasContext *ctx, uint32_t opc,
                      int rd, int rs, int rt)
{
    TCGv t0, t1;

    if (rd == 0) {
        /*
         * If no destination, treat it as a NOP.
         * For add & sub, we must generate the overflow exception when needed.
         */
        /* The operands the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rs);
        note_gpr_folded_read(rt);
        return;
    }

    t0 = tcg_temp_new();
    t1 = tcg_temp_new();
    gen_load_gpr(t0, rs);
    gen_load_gpr(t1, rt);
    switch (opc) {
    case OPC_SLLV:
        mips_ident(ctx,
            opc == OPC_SLLV ? MIPS_ID_OPC_SLLV :
            MIPS_ID_NONE);
        tcg_gen_andi_tl(t0, t0, 0x1f);
        tcg_gen_shl_tl(t0, t1, t0);
        tcg_gen_ext32s_tl(cpu_gpr[rd], t0);
        break;
    case OPC_SRAV:
        mips_ident(ctx,
            opc == OPC_SRAV ? MIPS_ID_OPC_SRAV :
            MIPS_ID_NONE);
        tcg_gen_andi_tl(t0, t0, 0x1f);
        tcg_gen_sar_tl(cpu_gpr[rd], t1, t0);
        break;
    case OPC_SRLV:
        mips_ident(ctx,
            opc == OPC_SRLV ? MIPS_ID_OPC_SRLV :
            MIPS_ID_NONE);
        tcg_gen_ext32u_tl(t1, t1);
        tcg_gen_andi_tl(t0, t0, 0x1f);
        tcg_gen_shr_tl(t0, t1, t0);
        tcg_gen_ext32s_tl(cpu_gpr[rd], t0);
        break;
    case OPC_ROTRV:
        mips_ident(ctx,
            opc == OPC_ROTRV ? MIPS_ID_OPC_ROTRV :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();

            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_andi_i32(t2, t2, 0x1f);
            tcg_gen_rotr_i32(t2, t3, t2);
            tcg_gen_ext_i32_tl(cpu_gpr[rd], t2);
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DSLLV:
        mips_ident(ctx,
            opc == OPC_DSLLV ? MIPS_ID_OPC_DSLLV :
            MIPS_ID_NONE);
        tcg_gen_andi_tl(t0, t0, 0x3f);
        tcg_gen_shl_tl(cpu_gpr[rd], t1, t0);
        break;
    case OPC_DSRAV:
        mips_ident(ctx,
            opc == OPC_DSRAV ? MIPS_ID_OPC_DSRAV :
            MIPS_ID_NONE);
        tcg_gen_andi_tl(t0, t0, 0x3f);
        tcg_gen_sar_tl(cpu_gpr[rd], t1, t0);
        break;
    case OPC_DSRLV:
        mips_ident(ctx,
            opc == OPC_DSRLV ? MIPS_ID_OPC_DSRLV :
            MIPS_ID_NONE);
        tcg_gen_andi_tl(t0, t0, 0x3f);
        tcg_gen_shr_tl(cpu_gpr[rd], t1, t0);
        break;
    case OPC_DROTRV:
        mips_ident(ctx,
            opc == OPC_DROTRV ? MIPS_ID_OPC_DROTRV :
            MIPS_ID_NONE);
        tcg_gen_andi_tl(t0, t0, 0x3f);
        tcg_gen_rotr_tl(cpu_gpr[rd], t1, t0);
        break;
#endif
    }
}

/* Arithmetic on HI/LO registers */
static void gen_HILO(DisasContext *ctx, uint32_t opc, int acc, int reg)
{
    if (reg == 0 && (opc == OPC_MFHI || opc == OPC_MFLO)) {
        /* Treat as NOP. */
        return;
    }

    if (acc != 0) {
        check_dsp(ctx);
    }

    switch (opc) {
    case OPC_MFHI:
        mips_ident(ctx,
            opc == OPC_MFHI ? MIPS_ID_OPC_MFHI :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        if (acc != 0) {
            tcg_gen_ext32s_tl(cpu_gpr[reg], cpu_HI[acc]);
        } else
#endif
        {
            tcg_gen_mov_tl(cpu_gpr[reg], cpu_HI[acc]);
        }
        break;
    case OPC_MFLO:
        mips_ident(ctx,
            opc == OPC_MFLO ? MIPS_ID_OPC_MFLO :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        if (acc != 0) {
            tcg_gen_ext32s_tl(cpu_gpr[reg], cpu_LO[acc]);
        } else
#endif
        {
            tcg_gen_mov_tl(cpu_gpr[reg], cpu_LO[acc]);
        }
        break;
    case OPC_MTHI:
        mips_ident(ctx,
            opc == OPC_MTHI ? MIPS_ID_OPC_MTHI :
            MIPS_ID_NONE);
        if (reg != 0) {
#if defined(TARGET_MIPS64)
            if (acc != 0) {
                tcg_gen_ext32s_tl(cpu_HI[acc], cpu_gpr[reg]);
            } else
#endif
            {
                tcg_gen_mov_tl(cpu_HI[acc], cpu_gpr[reg]);
            }
        } else {
            tcg_gen_movi_tl(cpu_HI[acc], 0);
        }
        break;
    case OPC_MTLO:
        mips_ident(ctx,
            opc == OPC_MTLO ? MIPS_ID_OPC_MTLO :
            MIPS_ID_NONE);
        if (reg != 0) {
#if defined(TARGET_MIPS64)
            if (acc != 0) {
                tcg_gen_ext32s_tl(cpu_LO[acc], cpu_gpr[reg]);
            } else
#endif
            {
                tcg_gen_mov_tl(cpu_LO[acc], cpu_gpr[reg]);
            }
        } else {
            tcg_gen_movi_tl(cpu_LO[acc], 0);
        }
        break;
    }
}

static inline void gen_r6_ld(target_long addr, int reg, int memidx,
                             MemOp memop)
{
    TCGv t0 = tcg_temp_new();
    tcg_gen_qemu_ld_tl(t0, tcg_constant_tl(addr), memidx, memop);
    gen_store_gpr(t0, reg);
}

static inline void gen_pcrel(DisasContext *ctx, int opc, target_ulong pc,
                             int rs)
{
    target_long offset;
    target_long addr;

    switch (MASK_OPC_PCREL_TOP2BITS(opc)) {
    case OPC_ADDIUPC:
        mips_ident(ctx,
            MASK_OPC_PCREL_TOP2BITS(opc) == OPC_ADDIUPC ? MIPS_ID_OPC_ADDIUPC :
            MIPS_ID_NONE);
        if (rs != 0) {
            offset = sextract32(ctx->opcode << 2, 0, 21);
            addr = addr_add(ctx, pc, offset);
            tcg_gen_movi_tl(cpu_gpr[rs], addr);
        }
        break;
    case R6_OPC_LWPC:
        mips_ident(ctx,
            MASK_OPC_PCREL_TOP2BITS(opc) == R6_OPC_LWPC ? MIPS_ID_R6_OPC_LWPC :
            MIPS_ID_NONE);
        offset = sextract32(ctx->opcode << 2, 0, 21);
        addr = addr_add(ctx, pc, offset);
        gen_r6_ld(addr, rs, ctx->mem_idx, mo_endian(ctx) | MO_SL);
        break;
#if defined(TARGET_MIPS64)
    case OPC_LWUPC:
        mips_ident(ctx,
            MASK_OPC_PCREL_TOP2BITS(opc) == OPC_LWUPC ? MIPS_ID_OPC_LWUPC :
            MIPS_ID_NONE);
        check_mips_64(ctx);
        offset = sextract32(ctx->opcode << 2, 0, 21);
        addr = addr_add(ctx, pc, offset);
        gen_r6_ld(addr, rs, ctx->mem_idx, mo_endian(ctx) | MO_UL);
        break;
#endif
    default:
        switch (MASK_OPC_PCREL_TOP5BITS(opc)) {
        case OPC_AUIPC:
            mips_ident(ctx,
                MASK_OPC_PCREL_TOP5BITS(opc) == OPC_AUIPC ? MIPS_ID_OPC_AUIPC :
                MIPS_ID_NONE);
            if (rs != 0) {
                offset = sextract32(ctx->opcode, 0, 16) << 16;
                addr = addr_add(ctx, pc, offset);
                tcg_gen_movi_tl(cpu_gpr[rs], addr);
            }
            break;
        case OPC_ALUIPC:
            mips_ident(ctx,
                MASK_OPC_PCREL_TOP5BITS(opc) == OPC_ALUIPC ?
                    MIPS_ID_OPC_ALUIPC :
                MIPS_ID_NONE);
            if (rs != 0) {
                offset = sextract32(ctx->opcode, 0, 16) << 16;
                addr = ~0xFFFF & addr_add(ctx, pc, offset);
                tcg_gen_movi_tl(cpu_gpr[rs], addr);
            }
            break;
#if defined(TARGET_MIPS64)
        case R6_OPC_LDPC: /* bits 16 and 17 are part of immediate */
        case R6_OPC_LDPC + (1 << 16):
        case R6_OPC_LDPC + (2 << 16):
        case R6_OPC_LDPC + (3 << 16):
            mips_ident(ctx,
                MASK_OPC_PCREL_TOP5BITS(opc) == R6_OPC_LDPC ?
                    MIPS_ID_R6_OPC_LDPC :
                MASK_OPC_PCREL_TOP5BITS(opc) == R6_OPC_LDPC + (1 << 16) ?
                    MIPS_ID_R6_OPC_LDPC :
                MASK_OPC_PCREL_TOP5BITS(opc) == R6_OPC_LDPC + (2 << 16) ?
                    MIPS_ID_R6_OPC_LDPC :
                MASK_OPC_PCREL_TOP5BITS(opc) == R6_OPC_LDPC + (3 << 16) ?
                    MIPS_ID_R6_OPC_LDPC :
                MIPS_ID_NONE);
            check_mips_64(ctx);
            offset = sextract32(ctx->opcode << 3, 0, 21);
            addr = addr_add(ctx, (pc & ~0x7), offset);
            gen_r6_ld(addr, rs, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
            break;
#endif
        default:
            MIPS_INVAL("OPC_PCREL");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    }
}

static void gen_r6_muldiv(DisasContext *ctx, int opc, int rd, int rs, int rt)
{
    TCGv t0, t1;

    if (rd == 0) {
        /* Treat as NOP. */
        return;
    }

    t0 = tcg_temp_new();
    t1 = tcg_temp_new();

    gen_load_gpr(t0, rs);
    gen_load_gpr(t1, rt);

    switch (opc) {
    case R6_OPC_DIV:
        mips_ident(ctx,
            opc == R6_OPC_DIV ? MIPS_ID_R6_OPC_DIV :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            TCGv t3 = tcg_temp_new();
            tcg_gen_ext32s_tl(t0, t0);
            tcg_gen_ext32s_tl(t1, t1);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t2, t0, INT_MIN);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, -1);
            tcg_gen_and_tl(t2, t2, t3);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, 0);
            tcg_gen_or_tl(t2, t2, t3);
            tcg_gen_movcond_tl(TCG_COND_NE, t1, t2, tcg_constant_tl(0), t2, t1);
            tcg_gen_div_tl(cpu_gpr[rd], t0, t1);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        }
        break;
    case R6_OPC_MOD:
        mips_ident(ctx,
            opc == R6_OPC_MOD ? MIPS_ID_R6_OPC_MOD :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            TCGv t3 = tcg_temp_new();
            tcg_gen_ext32s_tl(t0, t0);
            tcg_gen_ext32s_tl(t1, t1);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t2, t0, INT_MIN);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, -1);
            tcg_gen_and_tl(t2, t2, t3);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, 0);
            tcg_gen_or_tl(t2, t2, t3);
            tcg_gen_movcond_tl(TCG_COND_NE, t1, t2, tcg_constant_tl(0), t2, t1);
            tcg_gen_rem_tl(cpu_gpr[rd], t0, t1);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        }
        break;
    case R6_OPC_DIVU:
        mips_ident(ctx,
            opc == R6_OPC_DIVU ? MIPS_ID_R6_OPC_DIVU :
            MIPS_ID_NONE);
        {
            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_ext32u_tl(t1, t1);
            tcg_gen_movcond_tl(TCG_COND_EQ, t1, t1,
                               tcg_constant_tl(0), tcg_constant_tl(1), t1);
            tcg_gen_divu_tl(cpu_gpr[rd], t0, t1);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        }
        break;
    case R6_OPC_MODU:
        mips_ident(ctx,
            opc == R6_OPC_MODU ? MIPS_ID_R6_OPC_MODU :
            MIPS_ID_NONE);
        {
            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_ext32u_tl(t1, t1);
            tcg_gen_movcond_tl(TCG_COND_EQ, t1, t1,
                               tcg_constant_tl(0), tcg_constant_tl(1), t1);
            tcg_gen_remu_tl(cpu_gpr[rd], t0, t1);
            tcg_gen_ext32s_tl(cpu_gpr[rd], cpu_gpr[rd]);
        }
        break;
    case R6_OPC_MUL:
        mips_ident(ctx,
            opc == R6_OPC_MUL ? MIPS_ID_R6_OPC_MUL :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_mul_i32(t2, t2, t3);
            tcg_gen_ext_i32_tl(cpu_gpr[rd], t2);
        }
        break;
    case R6_OPC_MUH:
        mips_ident(ctx,
            opc == R6_OPC_MUH ? MIPS_ID_R6_OPC_MUH :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_muls2_i32(t2, t3, t2, t3);
            tcg_gen_ext_i32_tl(cpu_gpr[rd], t3);
        }
        break;
    case R6_OPC_MULU:
        mips_ident(ctx,
            opc == R6_OPC_MULU ? MIPS_ID_R6_OPC_MULU :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_mul_i32(t2, t2, t3);
            tcg_gen_ext_i32_tl(cpu_gpr[rd], t2);
        }
        break;
    case R6_OPC_MUHU:
        mips_ident(ctx,
            opc == R6_OPC_MUHU ? MIPS_ID_R6_OPC_MUHU :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_mulu2_i32(t2, t3, t2, t3);
            tcg_gen_ext_i32_tl(cpu_gpr[rd], t3);
        }
        break;
#if defined(TARGET_MIPS64)
    case R6_OPC_DDIV:
        mips_ident(ctx,
            opc == R6_OPC_DDIV ? MIPS_ID_R6_OPC_DDIV :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            TCGv t3 = tcg_temp_new();
            tcg_gen_setcondi_tl(TCG_COND_EQ, t2, t0, -1LL << 63);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, -1LL);
            tcg_gen_and_tl(t2, t2, t3);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, 0);
            tcg_gen_or_tl(t2, t2, t3);
            tcg_gen_movcond_tl(TCG_COND_NE, t1, t2, tcg_constant_tl(0), t2, t1);
            tcg_gen_div_tl(cpu_gpr[rd], t0, t1);
        }
        break;
    case R6_OPC_DMOD:
        mips_ident(ctx,
            opc == R6_OPC_DMOD ? MIPS_ID_R6_OPC_DMOD :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            TCGv t3 = tcg_temp_new();
            tcg_gen_setcondi_tl(TCG_COND_EQ, t2, t0, -1LL << 63);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, -1LL);
            tcg_gen_and_tl(t2, t2, t3);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, 0);
            tcg_gen_or_tl(t2, t2, t3);
            tcg_gen_movcond_tl(TCG_COND_NE, t1, t2, tcg_constant_tl(0), t2, t1);
            tcg_gen_rem_tl(cpu_gpr[rd], t0, t1);
        }
        break;
    case R6_OPC_DDIVU:
        mips_ident(ctx,
            opc == R6_OPC_DDIVU ? MIPS_ID_R6_OPC_DDIVU :
            MIPS_ID_NONE);
        {
            tcg_gen_movcond_tl(TCG_COND_EQ, t1, t1,
                               tcg_constant_tl(0), tcg_constant_tl(1), t1);
            tcg_gen_divu_i64(cpu_gpr[rd], t0, t1);
        }
        break;
    case R6_OPC_DMODU:
        mips_ident(ctx,
            opc == R6_OPC_DMODU ? MIPS_ID_R6_OPC_DMODU :
            MIPS_ID_NONE);
        {
            tcg_gen_movcond_tl(TCG_COND_EQ, t1, t1,
                               tcg_constant_tl(0), tcg_constant_tl(1), t1);
            tcg_gen_remu_i64(cpu_gpr[rd], t0, t1);
        }
        break;
    case R6_OPC_DMUL:
        mips_ident(ctx,
            opc == R6_OPC_DMUL ? MIPS_ID_R6_OPC_DMUL :
            MIPS_ID_NONE);
        tcg_gen_mul_i64(cpu_gpr[rd], t0, t1);
        break;
    case R6_OPC_DMUH:
        mips_ident(ctx,
            opc == R6_OPC_DMUH ? MIPS_ID_R6_OPC_DMUH :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            tcg_gen_muls2_i64(t2, cpu_gpr[rd], t0, t1);
        }
        break;
    case R6_OPC_DMULU:
        mips_ident(ctx,
            opc == R6_OPC_DMULU ? MIPS_ID_R6_OPC_DMULU :
            MIPS_ID_NONE);
        tcg_gen_mul_i64(cpu_gpr[rd], t0, t1);
        break;
    case R6_OPC_DMUHU:
        mips_ident(ctx,
            opc == R6_OPC_DMUHU ? MIPS_ID_R6_OPC_DMUHU :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            tcg_gen_mulu2_i64(t2, cpu_gpr[rd], t0, t1);
        }
        break;
#endif
    default:
        MIPS_INVAL("r6 mul/div");
        gen_reserved_instruction(ctx);
        break;
    }
}

#if defined(TARGET_MIPS64)
static void gen_div1_tx79(DisasContext *ctx, uint32_t opc, int rs, int rt)
{
    TCGv t0, t1;

    t0 = tcg_temp_new();
    t1 = tcg_temp_new();

    gen_load_gpr(t0, rs);
    gen_load_gpr(t1, rt);

    switch (opc) {
    case MMI_OPC_DIV1:
        mips_ident(ctx,
            opc == MMI_OPC_DIV1 ? MIPS_ID_MMI_OPC_DIV1 :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            TCGv t3 = tcg_temp_new();
            tcg_gen_ext32s_tl(t0, t0);
            tcg_gen_ext32s_tl(t1, t1);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t2, t0, INT_MIN);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, -1);
            tcg_gen_and_tl(t2, t2, t3);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, 0);
            tcg_gen_or_tl(t2, t2, t3);
            tcg_gen_movcond_tl(TCG_COND_NE, t1, t2, tcg_constant_tl(0), t2, t1);
            tcg_gen_div_tl(cpu_LO[1], t0, t1);
            tcg_gen_rem_tl(cpu_HI[1], t0, t1);
            tcg_gen_ext32s_tl(cpu_LO[1], cpu_LO[1]);
            tcg_gen_ext32s_tl(cpu_HI[1], cpu_HI[1]);
        }
        break;
    case MMI_OPC_DIVU1:
        mips_ident(ctx,
            opc == MMI_OPC_DIVU1 ? MIPS_ID_MMI_OPC_DIVU1 :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_constant_tl(0);
            TCGv t3 = tcg_constant_tl(1);
            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_ext32u_tl(t1, t1);
            tcg_gen_movcond_tl(TCG_COND_EQ, t1, t1, t2, t3, t1);
            tcg_gen_divu_tl(cpu_LO[1], t0, t1);
            tcg_gen_remu_tl(cpu_HI[1], t0, t1);
            tcg_gen_ext32s_tl(cpu_LO[1], cpu_LO[1]);
            tcg_gen_ext32s_tl(cpu_HI[1], cpu_HI[1]);
        }
        break;
    default:
        MIPS_INVAL("div1 TX79");
        gen_reserved_instruction(ctx);
        break;
    }
}
#endif

static void gen_muldiv(DisasContext *ctx, uint32_t opc,
                       int acc, int rs, int rt)
{
    TCGv t0, t1;

    t0 = tcg_temp_new();
    t1 = tcg_temp_new();

    gen_load_gpr(t0, rs);
    gen_load_gpr(t1, rt);

    if (acc != 0) {
        check_dsp(ctx);
    }

    switch (opc) {
    case OPC_DIV:
        mips_ident(ctx,
            opc == OPC_DIV ? MIPS_ID_OPC_DIV :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            TCGv t3 = tcg_temp_new();
            tcg_gen_ext32s_tl(t0, t0);
            tcg_gen_ext32s_tl(t1, t1);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t2, t0, INT_MIN);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, -1);
            tcg_gen_and_tl(t2, t2, t3);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, 0);
            tcg_gen_or_tl(t2, t2, t3);
            tcg_gen_movcond_tl(TCG_COND_NE, t1, t2, tcg_constant_tl(0), t2, t1);
            tcg_gen_div_tl(cpu_LO[acc], t0, t1);
            tcg_gen_rem_tl(cpu_HI[acc], t0, t1);
            tcg_gen_ext32s_tl(cpu_LO[acc], cpu_LO[acc]);
            tcg_gen_ext32s_tl(cpu_HI[acc], cpu_HI[acc]);
        }
        break;
    case OPC_DIVU:
        mips_ident(ctx,
            opc == OPC_DIVU ? MIPS_ID_OPC_DIVU :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_constant_tl(0);
            TCGv t3 = tcg_constant_tl(1);
            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_ext32u_tl(t1, t1);
            tcg_gen_movcond_tl(TCG_COND_EQ, t1, t1, t2, t3, t1);
            tcg_gen_divu_tl(cpu_LO[acc], t0, t1);
            tcg_gen_remu_tl(cpu_HI[acc], t0, t1);
            tcg_gen_ext32s_tl(cpu_LO[acc], cpu_LO[acc]);
            tcg_gen_ext32s_tl(cpu_HI[acc], cpu_HI[acc]);
        }
        break;
    case OPC_MULT:
        mips_ident(ctx,
            opc == OPC_MULT ? MIPS_ID_OPC_MULT :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_muls2_i32(t2, t3, t2, t3);
            tcg_gen_ext_i32_tl(cpu_LO[acc], t2);
            tcg_gen_ext_i32_tl(cpu_HI[acc], t3);
        }
        break;
    case OPC_MULTU:
        mips_ident(ctx,
            opc == OPC_MULTU ? MIPS_ID_OPC_MULTU :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_mulu2_i32(t2, t3, t2, t3);
            tcg_gen_ext_i32_tl(cpu_LO[acc], t2);
            tcg_gen_ext_i32_tl(cpu_HI[acc], t3);
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DDIV:
        mips_ident(ctx,
            opc == OPC_DDIV ? MIPS_ID_OPC_DDIV :
            MIPS_ID_NONE);
        {
            TCGv t2 = tcg_temp_new();
            TCGv t3 = tcg_temp_new();
            tcg_gen_setcondi_tl(TCG_COND_EQ, t2, t0, -1LL << 63);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, -1LL);
            tcg_gen_and_tl(t2, t2, t3);
            tcg_gen_setcondi_tl(TCG_COND_EQ, t3, t1, 0);
            tcg_gen_or_tl(t2, t2, t3);
            tcg_gen_movcond_tl(TCG_COND_NE, t1, t2, tcg_constant_tl(0), t2, t1);
            tcg_gen_div_tl(cpu_LO[acc], t0, t1);
            tcg_gen_rem_tl(cpu_HI[acc], t0, t1);
        }
        break;
    case OPC_DDIVU:
        mips_ident(ctx,
            opc == OPC_DDIVU ? MIPS_ID_OPC_DDIVU :
            MIPS_ID_NONE);
        {
            tcg_gen_movcond_tl(TCG_COND_EQ, t1, t1,
                               tcg_constant_tl(0), tcg_constant_tl(1), t1);
            tcg_gen_divu_i64(cpu_LO[acc], t0, t1);
            tcg_gen_remu_i64(cpu_HI[acc], t0, t1);
        }
        break;
    case OPC_DMULT:
        mips_ident(ctx,
            opc == OPC_DMULT ? MIPS_ID_OPC_DMULT :
            MIPS_ID_NONE);
        tcg_gen_muls2_i64(cpu_LO[acc], cpu_HI[acc], t0, t1);
        break;
    case OPC_DMULTU:
        mips_ident(ctx,
            opc == OPC_DMULTU ? MIPS_ID_OPC_DMULTU :
            MIPS_ID_NONE);
        tcg_gen_mulu2_i64(cpu_LO[acc], cpu_HI[acc], t0, t1);
        break;
#endif
    case OPC_MADD:
        mips_ident(ctx,
            opc == OPC_MADD ? MIPS_ID_OPC_MADD :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGv_i64 t3 = tcg_temp_new_i64();

            tcg_gen_ext_tl_i64(t2, t0);
            tcg_gen_ext_tl_i64(t3, t1);
            tcg_gen_mul_i64(t2, t2, t3);
            tcg_gen_concat_tl_i64(t3, cpu_LO[acc], cpu_HI[acc]);
            tcg_gen_add_i64(t2, t2, t3);
            gen_move_low32(cpu_LO[acc], t2);
            gen_move_high32(cpu_HI[acc], t2);
        }
        break;
    case OPC_MADDU:
        mips_ident(ctx,
            opc == OPC_MADDU ? MIPS_ID_OPC_MADDU :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGv_i64 t3 = tcg_temp_new_i64();

            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_ext32u_tl(t1, t1);
            tcg_gen_extu_tl_i64(t2, t0);
            tcg_gen_extu_tl_i64(t3, t1);
            tcg_gen_mul_i64(t2, t2, t3);
            tcg_gen_concat_tl_i64(t3, cpu_LO[acc], cpu_HI[acc]);
            tcg_gen_add_i64(t2, t2, t3);
            gen_move_low32(cpu_LO[acc], t2);
            gen_move_high32(cpu_HI[acc], t2);
        }
        break;
    case OPC_MSUB:
        mips_ident(ctx,
            opc == OPC_MSUB ? MIPS_ID_OPC_MSUB :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGv_i64 t3 = tcg_temp_new_i64();

            tcg_gen_ext_tl_i64(t2, t0);
            tcg_gen_ext_tl_i64(t3, t1);
            tcg_gen_mul_i64(t2, t2, t3);
            tcg_gen_concat_tl_i64(t3, cpu_LO[acc], cpu_HI[acc]);
            tcg_gen_sub_i64(t2, t3, t2);
            gen_move_low32(cpu_LO[acc], t2);
            gen_move_high32(cpu_HI[acc], t2);
        }
        break;
    case OPC_MSUBU:
        mips_ident(ctx,
            opc == OPC_MSUBU ? MIPS_ID_OPC_MSUBU :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGv_i64 t3 = tcg_temp_new_i64();

            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_ext32u_tl(t1, t1);
            tcg_gen_extu_tl_i64(t2, t0);
            tcg_gen_extu_tl_i64(t3, t1);
            tcg_gen_mul_i64(t2, t2, t3);
            tcg_gen_concat_tl_i64(t3, cpu_LO[acc], cpu_HI[acc]);
            tcg_gen_sub_i64(t2, t3, t2);
            gen_move_low32(cpu_LO[acc], t2);
            gen_move_high32(cpu_HI[acc], t2);
        }
        break;
    default:
        MIPS_INVAL("mul/div");
        gen_reserved_instruction(ctx);
        break;
    }
}

/*
 * These MULT[U] and MADD[U] instructions implemented in for example
 * the Toshiba/Sony R5900 and the Toshiba TX19, TX39 and TX79 core
 * architectures are special three-operand variants with the syntax
 *
 *     MULT[U][1] rd, rs, rt
 *
 * such that
 *
 *     (rd, LO, HI) <- rs * rt
 *
 * and
 *
 *     MADD[U][1] rd, rs, rt
 *
 * such that
 *
 *     (rd, LO, HI) <- (LO, HI) + rs * rt
 *
 * where the low-order 32-bits of the result is placed into both the
 * GPR rd and the special register LO. The high-order 32-bits of the
 * result is placed into the special register HI.
 *
 * If the GPR rd is omitted in assembly language, it is taken to be 0,
 * which is the zero register that always reads as 0.
 */
static void gen_mul_txx9(DisasContext *ctx, uint32_t opc,
                         int rd, int rs, int rt)
{
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();
    int acc = 0;

    gen_load_gpr(t0, rs);
    gen_load_gpr(t1, rt);

    switch (opc) {
    case MMI_OPC_MULT1:
        mips_ident(ctx,
            opc == MMI_OPC_MULT1 ? MIPS_ID_MMI_OPC_MULT1 :
            MIPS_ID_NONE);
        acc = 1;
        /* Fall through */
    case OPC_MULT:
        mips_ident(ctx,
            opc == OPC_MULT ? MIPS_ID_OPC_MULT :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_muls2_i32(t2, t3, t2, t3);
            if (rd) {
                tcg_gen_ext_i32_tl(cpu_gpr[rd], t2);
            }
            tcg_gen_ext_i32_tl(cpu_LO[acc], t2);
            tcg_gen_ext_i32_tl(cpu_HI[acc], t3);
        }
        break;
    case MMI_OPC_MULTU1:
        mips_ident(ctx,
            opc == MMI_OPC_MULTU1 ? MIPS_ID_MMI_OPC_MULTU1 :
            MIPS_ID_NONE);
        acc = 1;
        /* Fall through */
    case OPC_MULTU:
        mips_ident(ctx,
            opc == OPC_MULTU ? MIPS_ID_OPC_MULTU :
            MIPS_ID_NONE);
        {
            TCGv_i32 t2 = tcg_temp_new_i32();
            TCGv_i32 t3 = tcg_temp_new_i32();
            tcg_gen_trunc_tl_i32(t2, t0);
            tcg_gen_trunc_tl_i32(t3, t1);
            tcg_gen_mulu2_i32(t2, t3, t2, t3);
            if (rd) {
                tcg_gen_ext_i32_tl(cpu_gpr[rd], t2);
            }
            tcg_gen_ext_i32_tl(cpu_LO[acc], t2);
            tcg_gen_ext_i32_tl(cpu_HI[acc], t3);
        }
        break;
    case MMI_OPC_MADD1:
        mips_ident(ctx,
            opc == MMI_OPC_MADD1 ? MIPS_ID_MMI_OPC_MADD1 :
            MIPS_ID_NONE);
        acc = 1;
        /* Fall through */
    case MMI_OPC_MADD:
        mips_ident(ctx,
            opc == MMI_OPC_MADD ? MIPS_ID_MMI_OPC_MADD :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGv_i64 t3 = tcg_temp_new_i64();

            tcg_gen_ext_tl_i64(t2, t0);
            tcg_gen_ext_tl_i64(t3, t1);
            tcg_gen_mul_i64(t2, t2, t3);
            tcg_gen_concat_tl_i64(t3, cpu_LO[acc], cpu_HI[acc]);
            tcg_gen_add_i64(t2, t2, t3);
            gen_move_low32(cpu_LO[acc], t2);
            gen_move_high32(cpu_HI[acc], t2);
            if (rd) {
                gen_move_low32(cpu_gpr[rd], t2);
            }
        }
        break;
    case MMI_OPC_MADDU1:
        mips_ident(ctx,
            opc == MMI_OPC_MADDU1 ? MIPS_ID_MMI_OPC_MADDU1 :
            MIPS_ID_NONE);
        acc = 1;
        /* Fall through */
    case MMI_OPC_MADDU:
        mips_ident(ctx,
            opc == MMI_OPC_MADDU ? MIPS_ID_MMI_OPC_MADDU :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGv_i64 t3 = tcg_temp_new_i64();

            tcg_gen_ext32u_tl(t0, t0);
            tcg_gen_ext32u_tl(t1, t1);
            tcg_gen_extu_tl_i64(t2, t0);
            tcg_gen_extu_tl_i64(t3, t1);
            tcg_gen_mul_i64(t2, t2, t3);
            tcg_gen_concat_tl_i64(t3, cpu_LO[acc], cpu_HI[acc]);
            tcg_gen_add_i64(t2, t2, t3);
            gen_move_low32(cpu_LO[acc], t2);
            gen_move_high32(cpu_HI[acc], t2);
            if (rd) {
                gen_move_low32(cpu_gpr[rd], t2);
            }
        }
        break;
    default:
        MIPS_INVAL("mul/madd TXx9");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void gen_cl(DisasContext *ctx, uint32_t opc,
                   int rd, int rs)
{
    TCGv t0;

    if (rd == 0) {
        /* Treat as NOP. */
        /* The operand the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rs);
        return;
    }
    t0 = cpu_gpr[rd];
    gen_load_gpr(t0, rs);

    switch (opc) {
    case OPC_CLO:
    case R6_OPC_CLO:
        mips_ident(ctx,
            opc == OPC_CLO ? MIPS_ID_OPC_CLO :
            opc == R6_OPC_CLO ? MIPS_ID_R6_OPC_CLO :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        QEMU_FALLTHROUGH;  /* mips_ident */
    case OPC_DCLO:
    case R6_OPC_DCLO:
        mips_ident(ctx,
            opc == OPC_DCLO ? MIPS_ID_OPC_DCLO :
            opc == R6_OPC_DCLO ? MIPS_ID_R6_OPC_DCLO :
            MIPS_ID_NONE);
#endif
        tcg_gen_not_tl(t0, t0);
        break;
    }

    switch (opc) {
    case OPC_CLO:
    case R6_OPC_CLO:
    case OPC_CLZ:
    case R6_OPC_CLZ:
        mips_ident(ctx,
            opc == OPC_CLO ? MIPS_ID_OPC_CLO :
            opc == R6_OPC_CLO ? MIPS_ID_R6_OPC_CLO :
            opc == OPC_CLZ ? MIPS_ID_OPC_CLZ :
            opc == R6_OPC_CLZ ? MIPS_ID_R6_OPC_CLZ :
            MIPS_ID_NONE);
        tcg_gen_ext32u_tl(t0, t0);
        tcg_gen_clzi_tl(t0, t0, TARGET_LONG_BITS);
        tcg_gen_subi_tl(t0, t0, TARGET_LONG_BITS - 32);
        break;
#if defined(TARGET_MIPS64)
    case OPC_DCLO:
    case R6_OPC_DCLO:
    case OPC_DCLZ:
    case R6_OPC_DCLZ:
        mips_ident(ctx,
            opc == OPC_DCLO ? MIPS_ID_OPC_DCLO :
            opc == R6_OPC_DCLO ? MIPS_ID_R6_OPC_DCLO :
            opc == OPC_DCLZ ? MIPS_ID_OPC_DCLZ :
            opc == R6_OPC_DCLZ ? MIPS_ID_R6_OPC_DCLZ :
            MIPS_ID_NONE);
        tcg_gen_clzi_i64(t0, t0, 64);
        break;
#endif
    }
}

/* Loongson multimedia instructions */
static void gen_loongson_multimedia(DisasContext *ctx, int rd, int rs, int rt)
{
    uint32_t opc, shift_max;
    TCGv_i64 t0, t1;
    TCGCond cond;

    opc = MASK_LMMI(ctx->opcode);
    check_cp1_enabled(ctx);

    t0 = tcg_temp_new_i64();
    t1 = tcg_temp_new_i64();
    gen_load_fpr64(ctx, t0, rs);
    gen_load_fpr64(ctx, t1, rt);

    switch (opc) {
    case OPC_PADDSH:
        mips_ident(ctx,
            opc == OPC_PADDSH ? MIPS_ID_OPC_PADDSH :
            MIPS_ID_NONE);
        gen_helper_paddsh(t0, t0, t1);
        break;
    case OPC_PADDUSH:
        mips_ident(ctx,
            opc == OPC_PADDUSH ? MIPS_ID_OPC_PADDUSH :
            MIPS_ID_NONE);
        gen_helper_paddush(t0, t0, t1);
        break;
    case OPC_PADDH:
        mips_ident(ctx,
            opc == OPC_PADDH ? MIPS_ID_OPC_PADDH :
            MIPS_ID_NONE);
        gen_helper_paddh(t0, t0, t1);
        break;
    case OPC_PADDW:
        mips_ident(ctx,
            opc == OPC_PADDW ? MIPS_ID_OPC_PADDW :
            MIPS_ID_NONE);
        gen_helper_paddw(t0, t0, t1);
        break;
    case OPC_PADDSB:
        mips_ident(ctx,
            opc == OPC_PADDSB ? MIPS_ID_OPC_PADDSB :
            MIPS_ID_NONE);
        gen_helper_paddsb(t0, t0, t1);
        break;
    case OPC_PADDUSB:
        mips_ident(ctx,
            opc == OPC_PADDUSB ? MIPS_ID_OPC_PADDUSB :
            MIPS_ID_NONE);
        gen_helper_paddusb(t0, t0, t1);
        break;
    case OPC_PADDB:
        mips_ident(ctx,
            opc == OPC_PADDB ? MIPS_ID_OPC_PADDB :
            MIPS_ID_NONE);
        gen_helper_paddb(t0, t0, t1);
        break;

    case OPC_PSUBSH:
        mips_ident(ctx,
            opc == OPC_PSUBSH ? MIPS_ID_OPC_PSUBSH :
            MIPS_ID_NONE);
        gen_helper_psubsh(t0, t0, t1);
        break;
    case OPC_PSUBUSH:
        mips_ident(ctx,
            opc == OPC_PSUBUSH ? MIPS_ID_OPC_PSUBUSH :
            MIPS_ID_NONE);
        gen_helper_psubush(t0, t0, t1);
        break;
    case OPC_PSUBH:
        mips_ident(ctx,
            opc == OPC_PSUBH ? MIPS_ID_OPC_PSUBH :
            MIPS_ID_NONE);
        gen_helper_psubh(t0, t0, t1);
        break;
    case OPC_PSUBW:
        mips_ident(ctx,
            opc == OPC_PSUBW ? MIPS_ID_OPC_PSUBW :
            MIPS_ID_NONE);
        gen_helper_psubw(t0, t0, t1);
        break;
    case OPC_PSUBSB:
        mips_ident(ctx,
            opc == OPC_PSUBSB ? MIPS_ID_OPC_PSUBSB :
            MIPS_ID_NONE);
        gen_helper_psubsb(t0, t0, t1);
        break;
    case OPC_PSUBUSB:
        mips_ident(ctx,
            opc == OPC_PSUBUSB ? MIPS_ID_OPC_PSUBUSB :
            MIPS_ID_NONE);
        gen_helper_psubusb(t0, t0, t1);
        break;
    case OPC_PSUBB:
        mips_ident(ctx,
            opc == OPC_PSUBB ? MIPS_ID_OPC_PSUBB :
            MIPS_ID_NONE);
        gen_helper_psubb(t0, t0, t1);
        break;

    case OPC_PSHUFH:
        mips_ident(ctx,
            opc == OPC_PSHUFH ? MIPS_ID_OPC_PSHUFH :
            MIPS_ID_NONE);
        gen_helper_pshufh(t0, t0, t1);
        break;
    case OPC_PACKSSWH:
        mips_ident(ctx,
            opc == OPC_PACKSSWH ? MIPS_ID_OPC_PACKSSWH :
            MIPS_ID_NONE);
        gen_helper_packsswh(t0, t0, t1);
        break;
    case OPC_PACKSSHB:
        mips_ident(ctx,
            opc == OPC_PACKSSHB ? MIPS_ID_OPC_PACKSSHB :
            MIPS_ID_NONE);
        gen_helper_packsshb(t0, t0, t1);
        break;
    case OPC_PACKUSHB:
        mips_ident(ctx,
            opc == OPC_PACKUSHB ? MIPS_ID_OPC_PACKUSHB :
            MIPS_ID_NONE);
        gen_helper_packushb(t0, t0, t1);
        break;

    case OPC_PUNPCKLHW:
        mips_ident(ctx,
            opc == OPC_PUNPCKLHW ? MIPS_ID_OPC_PUNPCKLHW :
            MIPS_ID_NONE);
        gen_helper_punpcklhw(t0, t0, t1);
        break;
    case OPC_PUNPCKHHW:
        mips_ident(ctx,
            opc == OPC_PUNPCKHHW ? MIPS_ID_OPC_PUNPCKHHW :
            MIPS_ID_NONE);
        gen_helper_punpckhhw(t0, t0, t1);
        break;
    case OPC_PUNPCKLBH:
        mips_ident(ctx,
            opc == OPC_PUNPCKLBH ? MIPS_ID_OPC_PUNPCKLBH :
            MIPS_ID_NONE);
        gen_helper_punpcklbh(t0, t0, t1);
        break;
    case OPC_PUNPCKHBH:
        mips_ident(ctx,
            opc == OPC_PUNPCKHBH ? MIPS_ID_OPC_PUNPCKHBH :
            MIPS_ID_NONE);
        gen_helper_punpckhbh(t0, t0, t1);
        break;
    case OPC_PUNPCKLWD:
        mips_ident(ctx,
            opc == OPC_PUNPCKLWD ? MIPS_ID_OPC_PUNPCKLWD :
            MIPS_ID_NONE);
        gen_helper_punpcklwd(t0, t0, t1);
        break;
    case OPC_PUNPCKHWD:
        mips_ident(ctx,
            opc == OPC_PUNPCKHWD ? MIPS_ID_OPC_PUNPCKHWD :
            MIPS_ID_NONE);
        gen_helper_punpckhwd(t0, t0, t1);
        break;

    case OPC_PAVGH:
        mips_ident(ctx,
            opc == OPC_PAVGH ? MIPS_ID_OPC_PAVGH :
            MIPS_ID_NONE);
        gen_helper_pavgh(t0, t0, t1);
        break;
    case OPC_PAVGB:
        mips_ident(ctx,
            opc == OPC_PAVGB ? MIPS_ID_OPC_PAVGB :
            MIPS_ID_NONE);
        gen_helper_pavgb(t0, t0, t1);
        break;
    case OPC_PMAXSH:
        mips_ident(ctx,
            opc == OPC_PMAXSH ? MIPS_ID_OPC_PMAXSH :
            MIPS_ID_NONE);
        gen_helper_pmaxsh(t0, t0, t1);
        break;
    case OPC_PMINSH:
        mips_ident(ctx,
            opc == OPC_PMINSH ? MIPS_ID_OPC_PMINSH :
            MIPS_ID_NONE);
        gen_helper_pminsh(t0, t0, t1);
        break;
    case OPC_PMAXUB:
        mips_ident(ctx,
            opc == OPC_PMAXUB ? MIPS_ID_OPC_PMAXUB :
            MIPS_ID_NONE);
        gen_helper_pmaxub(t0, t0, t1);
        break;
    case OPC_PMINUB:
        mips_ident(ctx,
            opc == OPC_PMINUB ? MIPS_ID_OPC_PMINUB :
            MIPS_ID_NONE);
        gen_helper_pminub(t0, t0, t1);
        break;

    case OPC_PCMPEQW:
        mips_ident(ctx,
            opc == OPC_PCMPEQW ? MIPS_ID_OPC_PCMPEQW :
            MIPS_ID_NONE);
        gen_helper_pcmpeqw(t0, t0, t1);
        break;
    case OPC_PCMPGTW:
        mips_ident(ctx,
            opc == OPC_PCMPGTW ? MIPS_ID_OPC_PCMPGTW :
            MIPS_ID_NONE);
        gen_helper_pcmpgtw(t0, t0, t1);
        break;
    case OPC_PCMPEQH:
        mips_ident(ctx,
            opc == OPC_PCMPEQH ? MIPS_ID_OPC_PCMPEQH :
            MIPS_ID_NONE);
        gen_helper_pcmpeqh(t0, t0, t1);
        break;
    case OPC_PCMPGTH:
        mips_ident(ctx,
            opc == OPC_PCMPGTH ? MIPS_ID_OPC_PCMPGTH :
            MIPS_ID_NONE);
        gen_helper_pcmpgth(t0, t0, t1);
        break;
    case OPC_PCMPEQB:
        mips_ident(ctx,
            opc == OPC_PCMPEQB ? MIPS_ID_OPC_PCMPEQB :
            MIPS_ID_NONE);
        gen_helper_pcmpeqb(t0, t0, t1);
        break;
    case OPC_PCMPGTB:
        mips_ident(ctx,
            opc == OPC_PCMPGTB ? MIPS_ID_OPC_PCMPGTB :
            MIPS_ID_NONE);
        gen_helper_pcmpgtb(t0, t0, t1);
        break;

    case OPC_PSLLW:
        mips_ident(ctx,
            opc == OPC_PSLLW ? MIPS_ID_OPC_PSLLW :
            MIPS_ID_NONE);
        gen_helper_psllw(t0, t0, t1);
        break;
    case OPC_PSLLH:
        mips_ident(ctx,
            opc == OPC_PSLLH ? MIPS_ID_OPC_PSLLH :
            MIPS_ID_NONE);
        gen_helper_psllh(t0, t0, t1);
        break;
    case OPC_PSRLW:
        mips_ident(ctx,
            opc == OPC_PSRLW ? MIPS_ID_OPC_PSRLW :
            MIPS_ID_NONE);
        gen_helper_psrlw(t0, t0, t1);
        break;
    case OPC_PSRLH:
        mips_ident(ctx,
            opc == OPC_PSRLH ? MIPS_ID_OPC_PSRLH :
            MIPS_ID_NONE);
        gen_helper_psrlh(t0, t0, t1);
        break;
    case OPC_PSRAW:
        mips_ident(ctx,
            opc == OPC_PSRAW ? MIPS_ID_OPC_PSRAW :
            MIPS_ID_NONE);
        gen_helper_psraw(t0, t0, t1);
        break;
    case OPC_PSRAH:
        mips_ident(ctx,
            opc == OPC_PSRAH ? MIPS_ID_OPC_PSRAH :
            MIPS_ID_NONE);
        gen_helper_psrah(t0, t0, t1);
        break;

    case OPC_PMULLH:
        mips_ident(ctx,
            opc == OPC_PMULLH ? MIPS_ID_OPC_PMULLH :
            MIPS_ID_NONE);
        gen_helper_pmullh(t0, t0, t1);
        break;
    case OPC_PMULHH:
        mips_ident(ctx,
            opc == OPC_PMULHH ? MIPS_ID_OPC_PMULHH :
            MIPS_ID_NONE);
        gen_helper_pmulhh(t0, t0, t1);
        break;
    case OPC_PMULHUH:
        mips_ident(ctx,
            opc == OPC_PMULHUH ? MIPS_ID_OPC_PMULHUH :
            MIPS_ID_NONE);
        gen_helper_pmulhuh(t0, t0, t1);
        break;
    case OPC_PMADDHW:
        mips_ident(ctx,
            opc == OPC_PMADDHW ? MIPS_ID_OPC_PMADDHW :
            MIPS_ID_NONE);
        gen_helper_pmaddhw(t0, t0, t1);
        break;

    case OPC_PASUBUB:
        mips_ident(ctx,
            opc == OPC_PASUBUB ? MIPS_ID_OPC_PASUBUB :
            MIPS_ID_NONE);
        gen_helper_pasubub(t0, t0, t1);
        break;
    case OPC_BIADD:
        mips_ident(ctx,
            opc == OPC_BIADD ? MIPS_ID_OPC_BIADD :
            MIPS_ID_NONE);
        gen_helper_biadd(t0, t0);
        break;
    case OPC_PMOVMSKB:
        mips_ident(ctx,
            opc == OPC_PMOVMSKB ? MIPS_ID_OPC_PMOVMSKB :
            MIPS_ID_NONE);
        gen_helper_pmovmskb(t0, t0);
        break;

    case OPC_PADDD:
        mips_ident(ctx,
            opc == OPC_PADDD ? MIPS_ID_OPC_PADDD :
            MIPS_ID_NONE);
        tcg_gen_add_i64(t0, t0, t1);
        break;
    case OPC_PSUBD:
        mips_ident(ctx,
            opc == OPC_PSUBD ? MIPS_ID_OPC_PSUBD :
            MIPS_ID_NONE);
        tcg_gen_sub_i64(t0, t0, t1);
        break;
    case OPC_XOR_CP2:
        mips_ident(ctx,
            opc == OPC_XOR_CP2 ? MIPS_ID_OPC_XOR_CP2 :
            MIPS_ID_NONE);
        tcg_gen_xor_i64(t0, t0, t1);
        break;
    case OPC_NOR_CP2:
        mips_ident(ctx,
            opc == OPC_NOR_CP2 ? MIPS_ID_OPC_NOR_CP2 :
            MIPS_ID_NONE);
        tcg_gen_nor_i64(t0, t0, t1);
        break;
    case OPC_AND_CP2:
        mips_ident(ctx,
            opc == OPC_AND_CP2 ? MIPS_ID_OPC_AND_CP2 :
            MIPS_ID_NONE);
        tcg_gen_and_i64(t0, t0, t1);
        break;
    case OPC_OR_CP2:
        mips_ident(ctx,
            opc == OPC_OR_CP2 ? MIPS_ID_OPC_OR_CP2 :
            MIPS_ID_NONE);
        tcg_gen_or_i64(t0, t0, t1);
        break;

    case OPC_PANDN:
        mips_ident(ctx,
            opc == OPC_PANDN ? MIPS_ID_OPC_PANDN :
            MIPS_ID_NONE);
        tcg_gen_andc_i64(t0, t1, t0);
        break;

    case OPC_PINSRH_0:
        mips_ident(ctx,
            opc == OPC_PINSRH_0 ? MIPS_ID_OPC_PINSRH_0 :
            MIPS_ID_NONE);
        tcg_gen_deposit_i64(t0, t0, t1, 0, 16);
        break;
    case OPC_PINSRH_1:
        mips_ident(ctx,
            opc == OPC_PINSRH_1 ? MIPS_ID_OPC_PINSRH_1 :
            MIPS_ID_NONE);
        tcg_gen_deposit_i64(t0, t0, t1, 16, 16);
        break;
    case OPC_PINSRH_2:
        mips_ident(ctx,
            opc == OPC_PINSRH_2 ? MIPS_ID_OPC_PINSRH_2 :
            MIPS_ID_NONE);
        tcg_gen_deposit_i64(t0, t0, t1, 32, 16);
        break;
    case OPC_PINSRH_3:
        mips_ident(ctx,
            opc == OPC_PINSRH_3 ? MIPS_ID_OPC_PINSRH_3 :
            MIPS_ID_NONE);
        tcg_gen_deposit_i64(t0, t0, t1, 48, 16);
        break;

    case OPC_PEXTRH:
        mips_ident(ctx,
            opc == OPC_PEXTRH ? MIPS_ID_OPC_PEXTRH :
            MIPS_ID_NONE);
        tcg_gen_andi_i64(t1, t1, 3);
        tcg_gen_shli_i64(t1, t1, 4);
        tcg_gen_shr_i64(t0, t0, t1);
        tcg_gen_ext16u_i64(t0, t0);
        break;

    case OPC_ADDU_CP2:
        mips_ident(ctx,
            opc == OPC_ADDU_CP2 ? MIPS_ID_OPC_ADDU_CP2 :
            MIPS_ID_NONE);
        tcg_gen_add_i64(t0, t0, t1);
        tcg_gen_ext32s_i64(t0, t0);
        break;
    case OPC_SUBU_CP2:
        mips_ident(ctx,
            opc == OPC_SUBU_CP2 ? MIPS_ID_OPC_SUBU_CP2 :
            MIPS_ID_NONE);
        tcg_gen_sub_i64(t0, t0, t1);
        tcg_gen_ext32s_i64(t0, t0);
        break;

    case OPC_SLL_CP2:
        mips_ident(ctx,
            opc == OPC_SLL_CP2 ? MIPS_ID_OPC_SLL_CP2 :
            MIPS_ID_NONE);
        shift_max = 32;
        goto do_shift;
    case OPC_SRL_CP2:
        mips_ident(ctx,
            opc == OPC_SRL_CP2 ? MIPS_ID_OPC_SRL_CP2 :
            MIPS_ID_NONE);
        shift_max = 32;
        goto do_shift;
    case OPC_SRA_CP2:
        mips_ident(ctx,
            opc == OPC_SRA_CP2 ? MIPS_ID_OPC_SRA_CP2 :
            MIPS_ID_NONE);
        shift_max = 32;
        goto do_shift;
    case OPC_DSLL_CP2:
        mips_ident(ctx,
            opc == OPC_DSLL_CP2 ? MIPS_ID_OPC_DSLL_CP2 :
            MIPS_ID_NONE);
        shift_max = 64;
        goto do_shift;
    case OPC_DSRL_CP2:
        mips_ident(ctx,
            opc == OPC_DSRL_CP2 ? MIPS_ID_OPC_DSRL_CP2 :
            MIPS_ID_NONE);
        shift_max = 64;
        goto do_shift;
    case OPC_DSRA_CP2:
        mips_ident(ctx,
            opc == OPC_DSRA_CP2 ? MIPS_ID_OPC_DSRA_CP2 :
            MIPS_ID_NONE);
        shift_max = 64;
        goto do_shift;
    do_shift:
        /* Make sure shift count isn't TCG undefined behaviour.  */
        tcg_gen_andi_i64(t1, t1, shift_max - 1);

        switch (opc) {
        case OPC_SLL_CP2:
        case OPC_DSLL_CP2:
            mips_ident(ctx,
                opc == OPC_SLL_CP2 ? MIPS_ID_OPC_SLL_CP2 :
                opc == OPC_DSLL_CP2 ? MIPS_ID_OPC_DSLL_CP2 :
                MIPS_ID_NONE);
            tcg_gen_shl_i64(t0, t0, t1);
            break;
        case OPC_SRA_CP2:
        case OPC_DSRA_CP2:
            mips_ident(ctx,
                opc == OPC_SRA_CP2 ? MIPS_ID_OPC_SRA_CP2 :
                opc == OPC_DSRA_CP2 ? MIPS_ID_OPC_DSRA_CP2 :
                MIPS_ID_NONE);
            /*
             * Since SRA is UndefinedResult without sign-extended inputs,
             * we can treat SRA and DSRA the same.
             */
            tcg_gen_sar_i64(t0, t0, t1);
            break;
        case OPC_SRL_CP2:
            mips_ident(ctx,
                opc == OPC_SRL_CP2 ? MIPS_ID_OPC_SRL_CP2 :
                MIPS_ID_NONE);
            /* We want to shift in zeros for SRL; zero-extend first.  */
            tcg_gen_ext32u_i64(t0, t0);
            /* FALLTHRU */
        case OPC_DSRL_CP2:
            mips_ident(ctx,
                opc == OPC_DSRL_CP2 ? MIPS_ID_OPC_DSRL_CP2 :
                MIPS_ID_NONE);
            tcg_gen_shr_i64(t0, t0, t1);
            break;
        }

        if (shift_max == 32) {
            tcg_gen_ext32s_i64(t0, t0);
        }

        /* Shifts larger than MAX produce zero.  */
        tcg_gen_setcondi_i64(TCG_COND_LTU, t1, t1, shift_max);
        tcg_gen_neg_i64(t1, t1);
        tcg_gen_and_i64(t0, t0, t1);
        break;

    case OPC_ADD_CP2:
    case OPC_DADD_CP2:
        mips_ident(ctx,
            opc == OPC_ADD_CP2 ? MIPS_ID_OPC_ADD_CP2 :
            opc == OPC_DADD_CP2 ? MIPS_ID_OPC_DADD_CP2 :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGLabel *lab = gen_new_label();

            tcg_gen_mov_i64(t2, t0);
            tcg_gen_add_i64(t0, t1, t2);
            if (opc == OPC_ADD_CP2) {
                tcg_gen_ext32s_i64(t0, t0);
            }
            tcg_gen_xor_i64(t1, t1, t2);
            tcg_gen_xor_i64(t2, t2, t0);
            tcg_gen_andc_i64(t1, t2, t1);
            tcg_gen_brcondi_i64(TCG_COND_GE, t1, 0, lab);
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(lab);
            break;
        }

    case OPC_SUB_CP2:
    case OPC_DSUB_CP2:
        mips_ident(ctx,
            opc == OPC_SUB_CP2 ? MIPS_ID_OPC_SUB_CP2 :
            opc == OPC_DSUB_CP2 ? MIPS_ID_OPC_DSUB_CP2 :
            MIPS_ID_NONE);
        {
            TCGv_i64 t2 = tcg_temp_new_i64();
            TCGLabel *lab = gen_new_label();

            tcg_gen_mov_i64(t2, t0);
            tcg_gen_sub_i64(t0, t1, t2);
            if (opc == OPC_SUB_CP2) {
                tcg_gen_ext32s_i64(t0, t0);
            }
            tcg_gen_xor_i64(t1, t1, t2);
            tcg_gen_xor_i64(t2, t2, t0);
            tcg_gen_and_i64(t1, t1, t2);
            tcg_gen_brcondi_i64(TCG_COND_GE, t1, 0, lab);
            generate_exception(ctx, EXCP_OVERFLOW);
            gen_set_label(lab);
            break;
        }

    case OPC_PMULUW:
        mips_ident(ctx,
            opc == OPC_PMULUW ? MIPS_ID_OPC_PMULUW :
            MIPS_ID_NONE);
        tcg_gen_ext32u_i64(t0, t0);
        tcg_gen_ext32u_i64(t1, t1);
        tcg_gen_mul_i64(t0, t0, t1);
        break;

    case OPC_SEQU_CP2:
    case OPC_SEQ_CP2:
        mips_ident(ctx,
            opc == OPC_SEQU_CP2 ? MIPS_ID_OPC_SEQU_CP2 :
            opc == OPC_SEQ_CP2 ? MIPS_ID_OPC_SEQ_CP2 :
            MIPS_ID_NONE);
        cond = TCG_COND_EQ;
        goto do_cc_cond;
        break;
    case OPC_SLTU_CP2:
        mips_ident(ctx,
            opc == OPC_SLTU_CP2 ? MIPS_ID_OPC_SLTU_CP2 :
            MIPS_ID_NONE);
        cond = TCG_COND_LTU;
        goto do_cc_cond;
        break;
    case OPC_SLT_CP2:
        mips_ident(ctx,
            opc == OPC_SLT_CP2 ? MIPS_ID_OPC_SLT_CP2 :
            MIPS_ID_NONE);
        cond = TCG_COND_LT;
        goto do_cc_cond;
        break;
    case OPC_SLEU_CP2:
        mips_ident(ctx,
            opc == OPC_SLEU_CP2 ? MIPS_ID_OPC_SLEU_CP2 :
            MIPS_ID_NONE);
        cond = TCG_COND_LEU;
        goto do_cc_cond;
        break;
    case OPC_SLE_CP2:
        mips_ident(ctx,
            opc == OPC_SLE_CP2 ? MIPS_ID_OPC_SLE_CP2 :
            MIPS_ID_NONE);
        cond = TCG_COND_LE;
    do_cc_cond:
        {
            int cc = (ctx->opcode >> 8) & 0x7;
            TCGv_i64 t64 = tcg_temp_new_i64();
            TCGv_i32 t32 = tcg_temp_new_i32();

            tcg_gen_setcond_i64(cond, t64, t0, t1);
            tcg_gen_extrl_i64_i32(t32, t64);
            tcg_gen_deposit_i32(fpu_fcr31, fpu_fcr31, t32,
                                get_fp_bit(cc), 1);
        }
        return;
    default:
        MIPS_INVAL("loongson_cp2");
        gen_reserved_instruction(ctx);
        return;
    }

    gen_store_fpr64(ctx, t0, rd);
}

static void gen_loongson_lswc2(DisasContext *ctx, int rt,
                               int rs, int rd)
{
    TCGv t0, t1;
    TCGv_i32 fp0;
#if defined(TARGET_MIPS64)
    int lsq_rt1 = ctx->opcode & 0x1f;
    int lsq_offset = sextract32(ctx->opcode, 6, 9) << 4;
#endif
    int shf_offset = sextract32(ctx->opcode, 6, 8);

    t0 = tcg_temp_new();

    switch (MASK_LOONGSON_GSLSQ(ctx->opcode)) {
#if defined(TARGET_MIPS64)
    case OPC_GSLQ:
        mips_ident(ctx,
            MASK_LOONGSON_GSLSQ(ctx->opcode) == OPC_GSLQ ? MIPS_ID_OPC_GSLQ :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_base_offset_addr(ctx, t0, rs, lsq_offset);
        tcg_gen_qemu_ld_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_base_offset_addr(ctx, t0, rs, lsq_offset + 8);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t1, rt);
        gen_store_gpr(t0, lsq_rt1);
        break;
    case OPC_GSLQC1:
        mips_ident(ctx,
            MASK_LOONGSON_GSLSQ(ctx->opcode) == OPC_GSLQC1 ?
                MIPS_ID_OPC_GSLQC1 :
            MIPS_ID_NONE);
        check_cp1_enabled(ctx);
        t1 = tcg_temp_new();
        gen_base_offset_addr(ctx, t0, rs, lsq_offset);
        tcg_gen_qemu_ld_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_base_offset_addr(ctx, t0, rs, lsq_offset + 8);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_store_fpr64(ctx, t1, rt);
        gen_store_fpr64(ctx, t0, lsq_rt1);
        break;
    case OPC_GSSQ:
        mips_ident(ctx,
            MASK_LOONGSON_GSLSQ(ctx->opcode) == OPC_GSSQ ? MIPS_ID_OPC_GSSQ :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_base_offset_addr(ctx, t0, rs, lsq_offset);
        gen_load_gpr(t1, rt);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_base_offset_addr(ctx, t0, rs, lsq_offset + 8);
        gen_load_gpr(t1, lsq_rt1);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        break;
    case OPC_GSSQC1:
        mips_ident(ctx,
            MASK_LOONGSON_GSLSQ(ctx->opcode) == OPC_GSSQC1 ?
                MIPS_ID_OPC_GSSQC1 :
            MIPS_ID_NONE);
        check_cp1_enabled(ctx);
        t1 = tcg_temp_new();
        gen_base_offset_addr(ctx, t0, rs, lsq_offset);
        gen_load_fpr64(ctx, t1, rt);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_base_offset_addr(ctx, t0, rs, lsq_offset + 8);
        gen_load_fpr64(ctx, t1, lsq_rt1);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        break;
#endif
    case OPC_GSSHFL:
        mips_ident(ctx,
            MASK_LOONGSON_GSLSQ(ctx->opcode) == OPC_GSSHFL ?
                MIPS_ID_OPC_GSSHFL :
            MIPS_ID_NONE);
        switch (MASK_LOONGSON_GSSHFLS(ctx->opcode)) {
        case OPC_GSLWLC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSLWLC1 ?
                    MIPS_ID_OPC_GSLWLC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, rt);
            t1 = tcg_temp_new();
            tcg_gen_ext_i32_tl(t1, fp0);
            gen_lxl(ctx, t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UL);
            tcg_gen_trunc_tl_i32(fp0, t1);
            gen_store_fpr32(ctx, fp0, rt);
            break;
        case OPC_GSLWRC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSLWRC1 ?
                    MIPS_ID_OPC_GSLWRC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, rt);
            t1 = tcg_temp_new();
            tcg_gen_ext_i32_tl(t1, fp0);
            gen_lxr(ctx, t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UL);
            tcg_gen_trunc_tl_i32(fp0, t1);
            gen_store_fpr32(ctx, fp0, rt);
            break;
#if defined(TARGET_MIPS64)
        case OPC_GSLDLC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSLDLC1 ?
                    MIPS_ID_OPC_GSLDLC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            t1 = tcg_temp_new();
            gen_load_fpr64(ctx, t1, rt);
            gen_lxl(ctx, t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
            gen_store_fpr64(ctx, t1, rt);
            break;
        case OPC_GSLDRC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSLDRC1 ?
                    MIPS_ID_OPC_GSLDRC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            t1 = tcg_temp_new();
            gen_load_fpr64(ctx, t1, rt);
            gen_lxr(ctx, t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
            gen_store_fpr64(ctx, t1, rt);
            break;
#endif
        default:
            MIPS_INVAL("loongson_gsshfl");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_GSSHFS:
        mips_ident(ctx,
            MASK_LOONGSON_GSLSQ(ctx->opcode) == OPC_GSSHFS ?
                MIPS_ID_OPC_GSSHFS :
            MIPS_ID_NONE);
        switch (MASK_LOONGSON_GSSHFLS(ctx->opcode)) {
        case OPC_GSSWLC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSSWLC1 ?
                    MIPS_ID_OPC_GSSWLC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            t1 = tcg_temp_new();
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, rt);
            tcg_gen_ext_i32_tl(t1, fp0);
            gen_helper_0e2i(swl, t1, t0, ctx->mem_idx);
            break;
        case OPC_GSSWRC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSSWRC1 ?
                    MIPS_ID_OPC_GSSWRC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            t1 = tcg_temp_new();
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, rt);
            tcg_gen_ext_i32_tl(t1, fp0);
            gen_helper_0e2i(swr, t1, t0, ctx->mem_idx);
            break;
#if defined(TARGET_MIPS64)
        case OPC_GSSDLC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSSDLC1 ?
                    MIPS_ID_OPC_GSSDLC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            t1 = tcg_temp_new();
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            gen_load_fpr64(ctx, t1, rt);
            gen_helper_0e2i(sdl, t1, t0, ctx->mem_idx);
            break;
        case OPC_GSSDRC1:
            mips_ident(ctx,
                MASK_LOONGSON_GSSHFLS(ctx->opcode) == OPC_GSSDRC1 ?
                    MIPS_ID_OPC_GSSDRC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            t1 = tcg_temp_new();
            gen_base_offset_addr(ctx, t0, rs, shf_offset);
            gen_load_fpr64(ctx, t1, rt);
            gen_helper_0e2i(sdr, t1, t0, ctx->mem_idx);
            break;
#endif
        default:
            MIPS_INVAL("loongson_gsshfs");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    default:
        MIPS_INVAL("loongson_gslsq");
        gen_reserved_instruction(ctx);
        break;
    }
}

/* Loongson EXT LDC2/SDC2 */
static void gen_loongson_lsdc2(DisasContext *ctx, int rt,
                               int rs, int rd)
{
    int offset = sextract32(ctx->opcode, 3, 8);
    uint32_t opc = MASK_LOONGSON_LSDC2(ctx->opcode);
    TCGv t0, t1;
    TCGv_i32 fp0;

    /* Pre-conditions */
    switch (opc) {
    case OPC_GSLBX:
    case OPC_GSLHX:
    case OPC_GSLWX:
    case OPC_GSLDX:
        mips_ident(ctx,
            opc == OPC_GSLBX ? MIPS_ID_OPC_GSLBX :
            opc == OPC_GSLHX ? MIPS_ID_OPC_GSLHX :
            opc == OPC_GSLWX ? MIPS_ID_OPC_GSLWX :
            opc == OPC_GSLDX ? MIPS_ID_OPC_GSLDX :
            MIPS_ID_NONE);
        /* prefetch, implement as NOP */
        if (rt == 0) {
            return;
        }
        break;
    case OPC_GSSBX:
    case OPC_GSSHX:
    case OPC_GSSWX:
    case OPC_GSSDX:
        mips_ident(ctx,
            opc == OPC_GSSBX ? MIPS_ID_OPC_GSSBX :
            opc == OPC_GSSHX ? MIPS_ID_OPC_GSSHX :
            opc == OPC_GSSWX ? MIPS_ID_OPC_GSSWX :
            opc == OPC_GSSDX ? MIPS_ID_OPC_GSSDX :
            MIPS_ID_NONE);
        break;
    case OPC_GSLWXC1:
        mips_ident(ctx,
            opc == OPC_GSLWXC1 ? MIPS_ID_OPC_GSLWXC1 :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        QEMU_FALLTHROUGH;  /* mips_ident */
    case OPC_GSLDXC1:
        mips_ident(ctx,
            opc == OPC_GSLDXC1 ? MIPS_ID_OPC_GSLDXC1 :
            MIPS_ID_NONE);
#endif
        check_cp1_enabled(ctx);
        /* prefetch, implement as NOP */
        if (rt == 0) {
            return;
        }
        break;
    case OPC_GSSWXC1:
        mips_ident(ctx,
            opc == OPC_GSSWXC1 ? MIPS_ID_OPC_GSSWXC1 :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        QEMU_FALLTHROUGH;  /* mips_ident */
    case OPC_GSSDXC1:
        mips_ident(ctx,
            opc == OPC_GSSDXC1 ? MIPS_ID_OPC_GSSDXC1 :
            MIPS_ID_NONE);
#endif
        check_cp1_enabled(ctx);
        break;
    default:
        MIPS_INVAL("loongson_lsdc2");
        gen_reserved_instruction(ctx);
        return;
        break;
    }

    t0 = tcg_temp_new();

    gen_base_offset_addr(ctx, t0, rs, offset);
    gen_op_addr_add(ctx, t0, cpu_gpr[rd], t0);

    switch (opc) {
    case OPC_GSLBX:
        mips_ident(ctx,
            opc == OPC_GSLBX ? MIPS_ID_OPC_GSLBX :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, MO_SB);
        gen_store_gpr(t0, rt);
        break;
    case OPC_GSLHX:
        mips_ident(ctx,
            opc == OPC_GSLHX ? MIPS_ID_OPC_GSLHX :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_SW |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
    case OPC_GSLWX:
        mips_ident(ctx,
            opc == OPC_GSLWX ? MIPS_ID_OPC_GSLWX :
            MIPS_ID_NONE);
        gen_base_offset_addr(ctx, t0, rs, offset);
        if (rd) {
            gen_op_addr_add(ctx, t0, cpu_gpr[rd], t0);
        }
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_SL |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
#if defined(TARGET_MIPS64)
    case OPC_GSLDX:
        mips_ident(ctx,
            opc == OPC_GSLDX ? MIPS_ID_OPC_GSLDX :
            MIPS_ID_NONE);
        gen_base_offset_addr(ctx, t0, rs, offset);
        if (rd) {
            gen_op_addr_add(ctx, t0, cpu_gpr[rd], t0);
        }
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_store_gpr(t0, rt);
        break;
#endif
    case OPC_GSLWXC1:
        mips_ident(ctx,
            opc == OPC_GSLWXC1 ? MIPS_ID_OPC_GSLWXC1 :
            MIPS_ID_NONE);
        gen_base_offset_addr(ctx, t0, rs, offset);
        if (rd) {
            gen_op_addr_add(ctx, t0, cpu_gpr[rd], t0);
        }
        fp0 = tcg_temp_new_i32();
        tcg_gen_qemu_ld_i32(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_SL |
                            ctx->default_tcg_memop_mask);
        gen_store_fpr32(ctx, fp0, rt);
        break;
#if defined(TARGET_MIPS64)
    case OPC_GSLDXC1:
        mips_ident(ctx,
            opc == OPC_GSLDXC1 ? MIPS_ID_OPC_GSLDXC1 :
            MIPS_ID_NONE);
        gen_base_offset_addr(ctx, t0, rs, offset);
        if (rd) {
            gen_op_addr_add(ctx, t0, cpu_gpr[rd], t0);
        }
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        gen_store_fpr64(ctx, t0, rt);
        break;
#endif
    case OPC_GSSBX:
        mips_ident(ctx,
            opc == OPC_GSSBX ? MIPS_ID_OPC_GSSBX :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, MO_SB);
        break;
    case OPC_GSSHX:
        mips_ident(ctx,
            opc == OPC_GSSHX ? MIPS_ID_OPC_GSSHX :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UW |
                           ctx->default_tcg_memop_mask);
        break;
    case OPC_GSSWX:
        mips_ident(ctx,
            opc == OPC_GSSWX ? MIPS_ID_OPC_GSSWX :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UL |
                           ctx->default_tcg_memop_mask);
        break;
#if defined(TARGET_MIPS64)
    case OPC_GSSDX:
        mips_ident(ctx,
            opc == OPC_GSSDX ? MIPS_ID_OPC_GSSDX :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_gpr(t1, rt);
        tcg_gen_qemu_st_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                           ctx->default_tcg_memop_mask);
        break;
#endif
    case OPC_GSSWXC1:
        mips_ident(ctx,
            opc == OPC_GSSWXC1 ? MIPS_ID_OPC_GSSWXC1 :
            MIPS_ID_NONE);
        fp0 = tcg_temp_new_i32();
        gen_load_fpr32(ctx, fp0, rt);
        tcg_gen_qemu_st_i32(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UL |
                            ctx->default_tcg_memop_mask);
        break;
#if defined(TARGET_MIPS64)
    case OPC_GSSDXC1:
        mips_ident(ctx,
            opc == OPC_GSSDXC1 ? MIPS_ID_OPC_GSSDXC1 :
            MIPS_ID_NONE);
        t1 = tcg_temp_new();
        gen_load_fpr64(ctx, t1, rt);
        tcg_gen_qemu_st_i64(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ |
                            ctx->default_tcg_memop_mask);
        break;
#endif
    default:
        break;
    }
}

/* Traps */
static void gen_trap(DisasContext *ctx, uint32_t opc,
                     int rs, int rt, int16_t imm, int code)
{
    int cond;
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();

    cond = 0;
    /* Load needed operands */
    switch (opc) {
    case OPC_TEQ:
    case OPC_TGE:
    case OPC_TGEU:
    case OPC_TLT:
    case OPC_TLTU:
    case OPC_TNE:
        mips_ident(ctx,
            opc == OPC_TEQ ? MIPS_ID_OPC_TEQ :
            opc == OPC_TGE ? MIPS_ID_OPC_TGE :
            opc == OPC_TGEU ? MIPS_ID_OPC_TGEU :
            opc == OPC_TLT ? MIPS_ID_OPC_TLT :
            opc == OPC_TLTU ? MIPS_ID_OPC_TLTU :
            opc == OPC_TNE ? MIPS_ID_OPC_TNE :
            MIPS_ID_NONE);
        /*
         * CP-M, the encoded-immediate half, VALUE-STATING form.  The
         * register-form traps carry a 10-bit CODE field, and MIPS defines it
         * as a value for software to read back out of the instruction word:
         * the exception the trap raises has its Cause.ExcCode fixed by the
         * OPCODE, so nothing the instruction writes depends on the code.  It
         * is an encoded field that is not a dataflow operand, which is a
         * fact only a decoder can state -- the op list cannot distinguish it
         * from an immediate the emulator folded away, and those two want
         * opposite answers.  See insn_dataflow_note_encoded_imm_value().
         *
         * The register-form cases only: the Txx-immediate forms below have
         * no code field at all (their caller passes 0), and stating a field
         * the encoding does not carry would be a fabrication.
         *
         * The user-mode store of @code into CPUMIPSState::error_code a few
         * lines down is QEMU's own path for handing the code to cpu_loop,
         * not an architectural read -- error_code is already on file as an
         * emulation artefact.
         */
        insn_dataflow_note_encoded_imm_value((uint64_t)(uint32_t)code,
                                             INSN_DF_IMM_ROLE_NON_DATAFLOW);
        /*
         * Compare two registers.  `teq $t0,$t0` and `teq $zero,$zero` are
         * answered statically and QEMU loads neither operand, but the
         * encoding names both.  See note_gpr_folded_read().
         */
        if (rs == rt) {
            note_gpr_folded_read(rs);
            note_gpr_folded_read(rt);
        }
        if (rs != rt) {
            gen_load_gpr(t0, rs);
            gen_load_gpr(t1, rt);
            cond = 1;
        }
        break;
    case OPC_TEQI:
    case OPC_TGEI:
    case OPC_TGEIU:
    case OPC_TLTI:
    case OPC_TLTIU:
    case OPC_TNEI:
        mips_ident(ctx,
            opc == OPC_TEQI ? MIPS_ID_OPC_TEQI :
            opc == OPC_TGEI ? MIPS_ID_OPC_TGEI :
            opc == OPC_TGEIU ? MIPS_ID_OPC_TGEIU :
            opc == OPC_TLTI ? MIPS_ID_OPC_TLTI :
            opc == OPC_TLTIU ? MIPS_ID_OPC_TLTIU :
            opc == OPC_TNEI ? MIPS_ID_OPC_TNEI :
            MIPS_ID_NONE);
        /*
         * Compare register to immediate.  `tgei $zero,0` is answered
         * statically; the register is still named.  See
         * note_gpr_folded_read().
         */
        if (rs == 0 && imm == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (rs != 0 || imm != 0) {
            gen_load_gpr(t0, rs);
            tcg_gen_movi_tl(t1, (int32_t)imm);
            cond = 1;
        }
        break;
    }
    if (cond == 0) {
        switch (opc) {
        case OPC_TEQ:   /* rs == rs */
        case OPC_TEQI:  /* r0 == 0  */
        case OPC_TGE:   /* rs >= rs */
        case OPC_TGEI:  /* r0 >= 0  */
        case OPC_TGEU:  /* rs >= rs unsigned */
        case OPC_TGEIU: /* r0 >= 0  unsigned */
            mips_ident(ctx,
                opc == OPC_TEQ ? MIPS_ID_OPC_TEQ :
                opc == OPC_TEQI ? MIPS_ID_OPC_TEQI :
                opc == OPC_TGE ? MIPS_ID_OPC_TGE :
                opc == OPC_TGEI ? MIPS_ID_OPC_TGEI :
                opc == OPC_TGEU ? MIPS_ID_OPC_TGEU :
                opc == OPC_TGEIU ? MIPS_ID_OPC_TGEIU :
                MIPS_ID_NONE);
            /* Always trap */
#ifdef CONFIG_USER_ONLY
            /* Pass the break code along to cpu_loop. */
            tcg_gen_st_i32(tcg_constant_i32(code), tcg_env,
                           offsetof(CPUMIPSState, error_code));
#endif
            generate_exception_end(ctx, EXCP_TRAP);
            break;
        case OPC_TLT:   /* rs < rs           */
        case OPC_TLTI:  /* r0 < 0            */
        case OPC_TLTU:  /* rs < rs unsigned  */
        case OPC_TLTIU: /* r0 < 0  unsigned  */
        case OPC_TNE:   /* rs != rs          */
        case OPC_TNEI:  /* r0 != 0           */
            mips_ident(ctx,
                opc == OPC_TLT ? MIPS_ID_OPC_TLT :
                opc == OPC_TLTI ? MIPS_ID_OPC_TLTI :
                opc == OPC_TLTU ? MIPS_ID_OPC_TLTU :
                opc == OPC_TLTIU ? MIPS_ID_OPC_TLTIU :
                opc == OPC_TNE ? MIPS_ID_OPC_TNE :
                opc == OPC_TNEI ? MIPS_ID_OPC_TNEI :
                MIPS_ID_NONE);
            /* Never trap: treat as NOP. */
            break;
        }
    } else {
        TCGLabel *l1 = gen_new_label();

        switch (opc) {
        case OPC_TEQ:
        case OPC_TEQI:
            mips_ident(ctx,
                opc == OPC_TEQ ? MIPS_ID_OPC_TEQ :
                opc == OPC_TEQI ? MIPS_ID_OPC_TEQI :
                MIPS_ID_NONE);
            tcg_gen_brcond_tl(TCG_COND_NE, t0, t1, l1);
            break;
        case OPC_TGE:
        case OPC_TGEI:
            mips_ident(ctx,
                opc == OPC_TGE ? MIPS_ID_OPC_TGE :
                opc == OPC_TGEI ? MIPS_ID_OPC_TGEI :
                MIPS_ID_NONE);
            tcg_gen_brcond_tl(TCG_COND_LT, t0, t1, l1);
            break;
        case OPC_TGEU:
        case OPC_TGEIU:
            mips_ident(ctx,
                opc == OPC_TGEU ? MIPS_ID_OPC_TGEU :
                opc == OPC_TGEIU ? MIPS_ID_OPC_TGEIU :
                MIPS_ID_NONE);
            tcg_gen_brcond_tl(TCG_COND_LTU, t0, t1, l1);
            break;
        case OPC_TLT:
        case OPC_TLTI:
            mips_ident(ctx,
                opc == OPC_TLT ? MIPS_ID_OPC_TLT :
                opc == OPC_TLTI ? MIPS_ID_OPC_TLTI :
                MIPS_ID_NONE);
            tcg_gen_brcond_tl(TCG_COND_GE, t0, t1, l1);
            break;
        case OPC_TLTU:
        case OPC_TLTIU:
            mips_ident(ctx,
                opc == OPC_TLTU ? MIPS_ID_OPC_TLTU :
                opc == OPC_TLTIU ? MIPS_ID_OPC_TLTIU :
                MIPS_ID_NONE);
            tcg_gen_brcond_tl(TCG_COND_GEU, t0, t1, l1);
            break;
        case OPC_TNE:
        case OPC_TNEI:
            mips_ident(ctx,
                opc == OPC_TNE ? MIPS_ID_OPC_TNE :
                opc == OPC_TNEI ? MIPS_ID_OPC_TNEI :
                MIPS_ID_NONE);
            tcg_gen_brcond_tl(TCG_COND_EQ, t0, t1, l1);
            break;
        }
#ifdef CONFIG_USER_ONLY
        /* Pass the break code along to cpu_loop. */
        tcg_gen_st_i32(tcg_constant_i32(code), tcg_env,
                       offsetof(CPUMIPSState, error_code));
#endif
        /* Like save_cpu_state, only don't update saved values. */
        if (ctx->base.pc_next != ctx->saved_pc) {
            gen_save_pc(ctx->base.pc_next);
        }
        if (ctx->hflags != ctx->saved_hflags) {
            tcg_gen_movi_i32(hflags, ctx->hflags);
        }
        generate_exception(ctx, EXCP_TRAP);
        gen_set_label(l1);
    }
}

static void gen_goto_tb(DisasContext *ctx, int n, target_ulong dest)
{
    if (translator_use_goto_tb(&ctx->base, dest)) {
        tcg_gen_goto_tb(n);
        gen_save_pc(dest);
        tcg_gen_exit_tb(ctx->base.tb, n);
    } else {
        gen_save_pc(dest);
        tcg_gen_lookup_and_goto_ptr();
    }
}

/* Branches (before delay slot) */
static void gen_compute_branch(DisasContext *ctx, uint32_t opc,
                               int insn_bytes,
                               int rs, int rt, int32_t offset,
                               int delayslot_size)
{
    target_ulong btgt = -1;
    int blink = 0;
    int bcond_compute = 0;
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();

    if (ctx->hflags & MIPS_HFLAG_BMASK) {
#ifdef MIPS_DEBUG_DISAS
        LOG_DISAS("Branch in delay / forbidden slot at PC 0x%016"
                  VADDR_PRIx "\n", ctx->base.pc_next);
#endif
        gen_reserved_instruction(ctx);
        goto out;
    }

    /* Load needed operands */
    switch (opc) {
    case OPC_BEQ:
    case OPC_BEQL:
    case OPC_BNE:
    case OPC_BNEL:
        mips_ident(ctx,
            opc == OPC_BEQ ? MIPS_ID_OPC_BEQ :
            opc == OPC_BEQL ? MIPS_ID_OPC_BEQL :
            opc == OPC_BNE ? MIPS_ID_OPC_BNE :
            opc == OPC_BNEL ? MIPS_ID_OPC_BNEL :
            MIPS_ID_NONE);
        /*
         * Compare two registers.  When they are the SAME register the
         * comparison is statically known and QEMU loads neither, but the
         * encoding names both -- `beqz $t0` is `beq $t0,$zero`, and `b` is
         * `beq $zero,$zero`, whose two operands the wire carries.  See
         * note_gpr_folded_read().
         */
        if (rs == rt) {
            note_gpr_folded_read(rs);
            note_gpr_folded_read(rt);
        }
        if (rs != rt) {
            gen_load_gpr(t0, rs);
            gen_load_gpr(t1, rt);
            bcond_compute = 1;
        }
        btgt = ctx->base.pc_next + insn_bytes + offset;
        break;
    case OPC_BGEZ:
    case OPC_BGEZAL:
    case OPC_BGEZALL:
    case OPC_BGEZL:
    case OPC_BGTZ:
    case OPC_BGTZL:
    case OPC_BLEZ:
    case OPC_BLEZL:
    case OPC_BLTZ:
    case OPC_BLTZAL:
    case OPC_BLTZALL:
    case OPC_BLTZL:
        mips_ident(ctx,
            opc == OPC_BGEZ ? MIPS_ID_OPC_BGEZ :
            opc == OPC_BGEZAL ? MIPS_ID_OPC_BGEZAL :
            opc == OPC_BGEZALL ? MIPS_ID_OPC_BGEZALL :
            opc == OPC_BGEZL ? MIPS_ID_OPC_BGEZL :
            opc == OPC_BGTZ ? MIPS_ID_OPC_BGTZ :
            opc == OPC_BGTZL ? MIPS_ID_OPC_BGTZL :
            opc == OPC_BLEZ ? MIPS_ID_OPC_BLEZ :
            opc == OPC_BLEZL ? MIPS_ID_OPC_BLEZL :
            opc == OPC_BLTZ ? MIPS_ID_OPC_BLTZ :
            opc == OPC_BLTZAL ? MIPS_ID_OPC_BLTZAL :
            opc == OPC_BLTZALL ? MIPS_ID_OPC_BLTZALL :
            opc == OPC_BLTZL ? MIPS_ID_OPC_BLTZL :
            MIPS_ID_NONE);
        /*
         * Compare to zero.  `bltz $zero` is a branch never taken and `bgez
         * $zero` one always taken, so QEMU loads nothing -- but the encoding
         * names the register.  See note_gpr_folded_read().
         */
        if (rs == 0) {
            insn_dataflow_note_folded_read_zero();
        }
        if (rs != 0) {
            gen_load_gpr(t0, rs);
            bcond_compute = 1;
        }
        btgt = ctx->base.pc_next + insn_bytes + offset;
        break;
    case OPC_BPOSGE32:
        mips_ident(ctx,
            opc == OPC_BPOSGE32 ? MIPS_ID_OPC_BPOSGE32 :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        QEMU_FALLTHROUGH;  /* mips_ident */
    case OPC_BPOSGE64:
        mips_ident(ctx,
            opc == OPC_BPOSGE64 ? MIPS_ID_OPC_BPOSGE64 :
            MIPS_ID_NONE);
        tcg_gen_andi_tl(t0, cpu_dspctrl, 0x7F);
#else
        tcg_gen_andi_tl(t0, cpu_dspctrl, 0x3F);
#endif
        bcond_compute = 1;
        btgt = ctx->base.pc_next + insn_bytes + offset;
        break;
    case OPC_J:
    case OPC_JAL:
        mips_ident(ctx,
            opc == OPC_J ? MIPS_ID_OPC_J :
            opc == OPC_JAL ? MIPS_ID_OPC_JAL :
            MIPS_ID_NONE);
        {
            /* Jump to immediate */
            int jal_mask = ctx->hflags & MIPS_HFLAG_M16 ? 0xF8000000
                                                        : 0xF0000000;
            btgt = ((ctx->base.pc_next + insn_bytes) & jal_mask)
                   | (uint32_t)offset;
            break;
        }
    case OPC_JALX:
        mips_ident(ctx,
            opc == OPC_JALX ? MIPS_ID_OPC_JALX :
            MIPS_ID_NONE);
        /* Jump to immediate */
        btgt = ((ctx->base.pc_next + insn_bytes) & (int32_t)0xF0000000) |
            (uint32_t)offset;
        break;
    case OPC_JR:
    case OPC_JALR:
        mips_ident(ctx,
            opc == OPC_JR ? MIPS_ID_OPC_JR :
            opc == OPC_JALR ? MIPS_ID_OPC_JALR :
            MIPS_ID_NONE);
        /* Jump to register */
        if (offset != 0 && offset != 16) {
            /*
             * Hint = 0 is JR/JALR, hint 16 is JR.HB/JALR.HB, the
             * others are reserved.
             */
            MIPS_INVAL("jump hint");
            gen_reserved_instruction(ctx);
            goto out;
        }
        gen_load_gpr(btarget, rs);
        break;
    default:
        MIPS_INVAL("branch/jump");
        gen_reserved_instruction(ctx);
        goto out;
    }
    if (bcond_compute == 0) {
        /* No condition to be computed */
        switch (opc) {
        case OPC_BEQ:     /* rx == rx        */
        case OPC_BEQL:    /* rx == rx likely */
        case OPC_BGEZ:    /* 0 >= 0          */
        case OPC_BGEZL:   /* 0 >= 0 likely   */
        case OPC_BLEZ:    /* 0 <= 0          */
        case OPC_BLEZL:   /* 0 <= 0 likely   */
            mips_ident(ctx,
                opc == OPC_BEQ ? MIPS_ID_OPC_BEQ :
                opc == OPC_BEQL ? MIPS_ID_OPC_BEQL :
                opc == OPC_BGEZ ? MIPS_ID_OPC_BGEZ :
                opc == OPC_BGEZL ? MIPS_ID_OPC_BGEZL :
                opc == OPC_BLEZ ? MIPS_ID_OPC_BLEZ :
                opc == OPC_BLEZL ? MIPS_ID_OPC_BLEZL :
                MIPS_ID_NONE);
            /* Always take */
            ctx->hflags |= MIPS_HFLAG_B;
            break;
        case OPC_BGEZAL:  /* 0 >= 0          */
        case OPC_BGEZALL: /* 0 >= 0 likely   */
            mips_ident(ctx,
                opc == OPC_BGEZAL ? MIPS_ID_OPC_BGEZAL :
                opc == OPC_BGEZALL ? MIPS_ID_OPC_BGEZALL :
                MIPS_ID_NONE);
            /* Always take and link */
            blink = 31;
            ctx->hflags |= MIPS_HFLAG_B;
            break;
        case OPC_BNE:     /* rx != rx        */
        case OPC_BGTZ:    /* 0 > 0           */
        case OPC_BLTZ:    /* 0 < 0           */
            mips_ident(ctx,
                opc == OPC_BNE ? MIPS_ID_OPC_BNE :
                opc == OPC_BGTZ ? MIPS_ID_OPC_BGTZ :
                opc == OPC_BLTZ ? MIPS_ID_OPC_BLTZ :
                MIPS_ID_NONE);
            /* Treat as NOP. */
            goto out;
        case OPC_BLTZAL:  /* 0 < 0           */
            mips_ident(ctx,
                opc == OPC_BLTZAL ? MIPS_ID_OPC_BLTZAL :
                MIPS_ID_NONE);
            /*
             * Handle as an unconditional branch to get correct delay
             * slot checking.
             */
            blink = 31;
            btgt = ctx->base.pc_next + insn_bytes + delayslot_size;
            ctx->hflags |= MIPS_HFLAG_B;
            break;
        case OPC_BLTZALL: /* 0 < 0 likely */
            mips_ident(ctx,
                opc == OPC_BLTZALL ? MIPS_ID_OPC_BLTZALL :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(cpu_gpr[31], ctx->base.pc_next + 8);
            /* Skip the instruction in the delay slot */
            ctx->base.pc_next += 4;
            goto out;
        case OPC_BNEL:    /* rx != rx likely */
        case OPC_BGTZL:   /* 0 > 0 likely */
        case OPC_BLTZL:   /* 0 < 0 likely */
            mips_ident(ctx,
                opc == OPC_BNEL ? MIPS_ID_OPC_BNEL :
                opc == OPC_BGTZL ? MIPS_ID_OPC_BGTZL :
                opc == OPC_BLTZL ? MIPS_ID_OPC_BLTZL :
                MIPS_ID_NONE);
            /* Skip the instruction in the delay slot */
            ctx->base.pc_next += 4;
            goto out;
        case OPC_J:
            mips_ident(ctx,
                opc == OPC_J ? MIPS_ID_OPC_J :
                MIPS_ID_NONE);
            ctx->hflags |= MIPS_HFLAG_B;
            break;
        case OPC_JALX:
            mips_ident(ctx,
                opc == OPC_JALX ? MIPS_ID_OPC_JALX :
                MIPS_ID_NONE);
            ctx->hflags |= MIPS_HFLAG_BX;
            /* Fallthrough */
        case OPC_JAL:
            mips_ident(ctx,
                opc == OPC_JAL ? MIPS_ID_OPC_JAL :
                MIPS_ID_NONE);
            blink = 31;
            ctx->hflags |= MIPS_HFLAG_B;
            break;
        case OPC_JR:
            mips_ident(ctx,
                opc == OPC_JR ? MIPS_ID_OPC_JR :
                MIPS_ID_NONE);
            ctx->hflags |= MIPS_HFLAG_BR;
            break;
        case OPC_JALR:
            mips_ident(ctx,
                opc == OPC_JALR ? MIPS_ID_OPC_JALR :
                MIPS_ID_NONE);
            blink = rt;
            ctx->hflags |= MIPS_HFLAG_BR;
            break;
        default:
            MIPS_INVAL("branch/jump");
            gen_reserved_instruction(ctx);
            goto out;
        }
    } else {
        switch (opc) {
        case OPC_BEQ:
            mips_ident(ctx,
                opc == OPC_BEQ ? MIPS_ID_OPC_BEQ :
                MIPS_ID_NONE);
            tcg_gen_setcond_tl(TCG_COND_EQ, bcond, t0, t1);
            goto not_likely;
        case OPC_BEQL:
            mips_ident(ctx,
                opc == OPC_BEQL ? MIPS_ID_OPC_BEQL :
                MIPS_ID_NONE);
            tcg_gen_setcond_tl(TCG_COND_EQ, bcond, t0, t1);
            goto likely;
        case OPC_BNE:
            mips_ident(ctx,
                opc == OPC_BNE ? MIPS_ID_OPC_BNE :
                MIPS_ID_NONE);
            tcg_gen_setcond_tl(TCG_COND_NE, bcond, t0, t1);
            goto not_likely;
        case OPC_BNEL:
            mips_ident(ctx,
                opc == OPC_BNEL ? MIPS_ID_OPC_BNEL :
                MIPS_ID_NONE);
            tcg_gen_setcond_tl(TCG_COND_NE, bcond, t0, t1);
            goto likely;
        case OPC_BGEZ:
            mips_ident(ctx,
                opc == OPC_BGEZ ? MIPS_ID_OPC_BGEZ :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GE, bcond, t0, 0);
            goto not_likely;
        case OPC_BGEZL:
            mips_ident(ctx,
                opc == OPC_BGEZL ? MIPS_ID_OPC_BGEZL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GE, bcond, t0, 0);
            goto likely;
        case OPC_BGEZAL:
            mips_ident(ctx,
                opc == OPC_BGEZAL ? MIPS_ID_OPC_BGEZAL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GE, bcond, t0, 0);
            blink = 31;
            goto not_likely;
        case OPC_BGEZALL:
            mips_ident(ctx,
                opc == OPC_BGEZALL ? MIPS_ID_OPC_BGEZALL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GE, bcond, t0, 0);
            blink = 31;
            goto likely;
        case OPC_BGTZ:
            mips_ident(ctx,
                opc == OPC_BGTZ ? MIPS_ID_OPC_BGTZ :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GT, bcond, t0, 0);
            goto not_likely;
        case OPC_BGTZL:
            mips_ident(ctx,
                opc == OPC_BGTZL ? MIPS_ID_OPC_BGTZL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GT, bcond, t0, 0);
            goto likely;
        case OPC_BLEZ:
            mips_ident(ctx,
                opc == OPC_BLEZ ? MIPS_ID_OPC_BLEZ :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_LE, bcond, t0, 0);
            goto not_likely;
        case OPC_BLEZL:
            mips_ident(ctx,
                opc == OPC_BLEZL ? MIPS_ID_OPC_BLEZL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_LE, bcond, t0, 0);
            goto likely;
        case OPC_BLTZ:
            mips_ident(ctx,
                opc == OPC_BLTZ ? MIPS_ID_OPC_BLTZ :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_LT, bcond, t0, 0);
            goto not_likely;
        case OPC_BLTZL:
            mips_ident(ctx,
                opc == OPC_BLTZL ? MIPS_ID_OPC_BLTZL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_LT, bcond, t0, 0);
            goto likely;
        case OPC_BPOSGE32:
            mips_ident(ctx,
                opc == OPC_BPOSGE32 ? MIPS_ID_OPC_BPOSGE32 :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GE, bcond, t0, 32);
            goto not_likely;
#if defined(TARGET_MIPS64)
        case OPC_BPOSGE64:
            mips_ident(ctx,
                opc == OPC_BPOSGE64 ? MIPS_ID_OPC_BPOSGE64 :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_GE, bcond, t0, 64);
            goto not_likely;
#endif
        case OPC_BLTZAL:
            mips_ident(ctx,
                opc == OPC_BLTZAL ? MIPS_ID_OPC_BLTZAL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_LT, bcond, t0, 0);
            blink = 31;
        not_likely:
            ctx->hflags |= MIPS_HFLAG_BC;
            break;
        case OPC_BLTZALL:
            mips_ident(ctx,
                opc == OPC_BLTZALL ? MIPS_ID_OPC_BLTZALL :
                MIPS_ID_NONE);
            tcg_gen_setcondi_tl(TCG_COND_LT, bcond, t0, 0);
            blink = 31;
        likely:
            ctx->hflags |= MIPS_HFLAG_BL;
            break;
        default:
            MIPS_INVAL("conditional branch/jump");
            gen_reserved_instruction(ctx);
            goto out;
        }
    }

    ctx->btarget = btgt;
    /*
     * Surface the resolved static target to plugins for wrong-path
     * tracing.  Indirect branches (OPC_JR/OPC_JALR) leave btgt at
     * its -1 sentinel above — those rely on the plugin's observed-
     * target history instead, signalled by branch_target_pc == 0.
     */
    if (btgt != (target_ulong)-1) {
        plugin_gen_record_branch_target((uint64_t)btgt);
    }

    switch (delayslot_size) {
    case 2:
        ctx->hflags |= MIPS_HFLAG_BDS16;
        break;
    case 4:
        ctx->hflags |= MIPS_HFLAG_BDS32;
        break;
    }

    if (blink > 0) {
        int post_delay = insn_bytes + delayslot_size;
        int lowbit = !!(ctx->hflags & MIPS_HFLAG_M16);

        tcg_gen_movi_tl(cpu_gpr[blink],
                        ctx->base.pc_next + post_delay + lowbit);
    }

 out:
    if (insn_bytes == 2) {
        ctx->hflags |= MIPS_HFLAG_B16;
    }
}


/* special3 bitfield operations */
static void gen_bitops(DisasContext *ctx, uint32_t opc, int rt,
                       int rs, int lsb, int msb)
{
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();

    gen_load_gpr(t1, rs);
    switch (opc) {
    case OPC_EXT:
        mips_ident(ctx,
            opc == OPC_EXT ? MIPS_ID_OPC_EXT :
            MIPS_ID_NONE);
        if (lsb + msb > 31) {
            goto fail;
        }
        if (msb != 31) {
            tcg_gen_extract_tl(t0, t1, lsb, msb + 1);
        } else {
            /*
             * The two checks together imply that lsb == 0,
             * so this is a simple sign-extension.
             */
            tcg_gen_ext32s_tl(t0, t1);
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DEXTU:
        mips_ident(ctx,
            opc == OPC_DEXTU ? MIPS_ID_OPC_DEXTU :
            MIPS_ID_NONE);
        lsb += 32;
        goto do_dext;
    case OPC_DEXTM:
        mips_ident(ctx,
            opc == OPC_DEXTM ? MIPS_ID_OPC_DEXTM :
            MIPS_ID_NONE);
        msb += 32;
        goto do_dext;
    case OPC_DEXT:
        mips_ident(ctx,
            opc == OPC_DEXT ? MIPS_ID_OPC_DEXT :
            MIPS_ID_NONE);
    do_dext:
        if (lsb + msb > 63) {
            goto fail;
        }
        tcg_gen_extract_tl(t0, t1, lsb, msb + 1);
        break;
#endif
    case OPC_INS:
        mips_ident(ctx,
            opc == OPC_INS ? MIPS_ID_OPC_INS :
            MIPS_ID_NONE);
        if (lsb > msb) {
            goto fail;
        }
        gen_load_gpr(t0, rt);
        tcg_gen_deposit_tl(t0, t0, t1, lsb, msb - lsb + 1);
        tcg_gen_ext32s_tl(t0, t0);
        break;
#if defined(TARGET_MIPS64)
    case OPC_DINSU:
        mips_ident(ctx,
            opc == OPC_DINSU ? MIPS_ID_OPC_DINSU :
            MIPS_ID_NONE);
        lsb += 32;
        /* FALLTHRU */
    case OPC_DINSM:
        mips_ident(ctx,
            opc == OPC_DINSM ? MIPS_ID_OPC_DINSM :
            MIPS_ID_NONE);
        msb += 32;
        /* FALLTHRU */
    case OPC_DINS:
        mips_ident(ctx,
            opc == OPC_DINS ? MIPS_ID_OPC_DINS :
            MIPS_ID_NONE);
        if (lsb > msb) {
            goto fail;
        }
        gen_load_gpr(t0, rt);
        tcg_gen_deposit_tl(t0, t0, t1, lsb, msb - lsb + 1);
        break;
#endif
    default:
fail:
        MIPS_INVAL("bitops");
        gen_reserved_instruction(ctx);
        return;
    }
    /*
     * CP-M, the encoded-immediate half, VALUE-STATING form.  `ext`/`ins` and
     * their 64-bit siblings encode the field POSITION and SIZE, and the
     * lowering hands them to tcg_gen_extract_tl()/tcg_gen_deposit_tl() as OP
     * ARGUMENTS -- there is no temp for the temp-stating form to name, and
     * the argument walk cannot see them.  The result depends on them exactly
     * as it depends on rs, so the note goes in with the OPERAND role and its
     * anchor is the op just emitted, which is the one that consumed them.
     *
     * @lsb alone is stated: it and @msb are two halves of one encoded
     * position-and-extent operand and the wire carries a single immediate
     * slot, so a second note would say the same thing twice.
     */
    insn_dataflow_note_encoded_imm_value((uint64_t)(uint32_t)lsb,
                                         INSN_DF_IMM_ROLE_OPERAND);
    gen_store_gpr(t0, rt);
}

static void gen_bshfl(DisasContext *ctx, uint32_t op2, int rt, int rd)
{
    TCGv t0;

    if (rd == 0) {
        /* If no destination, treat it as a NOP. */
        /* The operands the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rt);
        return;
    }

    t0 = tcg_temp_new();
    gen_load_gpr(t0, rt);
    switch (op2) {
    case OPC_WSBH:
        mips_ident(ctx,
            op2 == OPC_WSBH ? MIPS_ID_OPC_WSBH :
            MIPS_ID_NONE);
        {
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_constant_tl(0x00FF00FF);

            tcg_gen_shri_tl(t1, t0, 8);
            tcg_gen_and_tl(t1, t1, t2);
            tcg_gen_and_tl(t0, t0, t2);
            tcg_gen_shli_tl(t0, t0, 8);
            tcg_gen_or_tl(t0, t0, t1);
            tcg_gen_ext32s_tl(cpu_gpr[rd], t0);
        }
        break;
    case OPC_SEB:
        mips_ident(ctx,
            op2 == OPC_SEB ? MIPS_ID_OPC_SEB :
            MIPS_ID_NONE);
        tcg_gen_ext8s_tl(cpu_gpr[rd], t0);
        break;
    case OPC_SEH:
        mips_ident(ctx,
            op2 == OPC_SEH ? MIPS_ID_OPC_SEH :
            MIPS_ID_NONE);
        tcg_gen_ext16s_tl(cpu_gpr[rd], t0);
        break;
#if defined(TARGET_MIPS64)
    case OPC_DSBH:
        mips_ident(ctx,
            op2 == OPC_DSBH ? MIPS_ID_OPC_DSBH :
            MIPS_ID_NONE);
        {
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_constant_tl(0x00FF00FF00FF00FFULL);

            tcg_gen_shri_tl(t1, t0, 8);
            tcg_gen_and_tl(t1, t1, t2);
            tcg_gen_and_tl(t0, t0, t2);
            tcg_gen_shli_tl(t0, t0, 8);
            tcg_gen_or_tl(cpu_gpr[rd], t0, t1);
        }
        break;
    case OPC_DSHD:
        mips_ident(ctx,
            op2 == OPC_DSHD ? MIPS_ID_OPC_DSHD :
            MIPS_ID_NONE);
        {
            TCGv t1 = tcg_temp_new();
            TCGv t2 = tcg_constant_tl(0x0000FFFF0000FFFFULL);

            tcg_gen_shri_tl(t1, t0, 16);
            tcg_gen_and_tl(t1, t1, t2);
            tcg_gen_and_tl(t0, t0, t2);
            tcg_gen_shli_tl(t0, t0, 16);
            tcg_gen_or_tl(t0, t0, t1);
            tcg_gen_shri_tl(t1, t0, 32);
            tcg_gen_shli_tl(t0, t0, 32);
            tcg_gen_or_tl(cpu_gpr[rd], t0, t1);
        }
        break;
#endif
    default:
        MIPS_INVAL("bsfhl");
        gen_reserved_instruction(ctx);
        return;
    }
}

static void gen_align_bits(DisasContext *ctx, int wordsz, int rd, int rs,
                           int rt, int bits)
{
    TCGv t0;
    if (rd == 0) {
        /* Treat as NOP. */
        return;
    }
    t0 = tcg_temp_new();
    if (bits == 0 || bits == wordsz) {
        if (bits == 0) {
            gen_load_gpr(t0, rt);
        } else {
            gen_load_gpr(t0, rs);
        }
        switch (wordsz) {
        case 32:
            tcg_gen_ext32s_tl(cpu_gpr[rd], t0);
            break;
#if defined(TARGET_MIPS64)
        case 64:
            tcg_gen_mov_tl(cpu_gpr[rd], t0);
            break;
#endif
        }
    } else {
        TCGv t1 = tcg_temp_new();
        gen_load_gpr(t0, rt);
        gen_load_gpr(t1, rs);
        switch (wordsz) {
        case 32:
            {
                TCGv_i64 t2 = tcg_temp_new_i64();
                tcg_gen_concat_tl_i64(t2, t1, t0);
                tcg_gen_shri_i64(t2, t2, 32 - bits);
                gen_move_low32(cpu_gpr[rd], t2);
            }
            break;
#if defined(TARGET_MIPS64)
        case 64:
            tcg_gen_shli_tl(t0, t0, bits);
            tcg_gen_shri_tl(t1, t1, 64 - bits);
            tcg_gen_or_tl(cpu_gpr[rd], t1, t0);
            break;
#endif
        }
    }
}

void gen_align(DisasContext *ctx, int wordsz, int rd, int rs, int rt, int bp)
{
    gen_align_bits(ctx, wordsz, rd, rs, rt, bp * 8);
}

static void gen_bitswap(DisasContext *ctx, int opc, int rd, int rt)
{
    TCGv t0;
    if (rd == 0) {
        /* Treat as NOP. */
        return;
    }
    t0 = tcg_temp_new();
    gen_load_gpr(t0, rt);
    switch (opc) {
    case OPC_BITSWAP:
        mips_ident(ctx,
            opc == OPC_BITSWAP ? MIPS_ID_OPC_BITSWAP :
            MIPS_ID_NONE);
        gen_helper_bitswap(cpu_gpr[rd], t0);
        break;
#if defined(TARGET_MIPS64)
    case OPC_DBITSWAP:
        mips_ident(ctx,
            opc == OPC_DBITSWAP ? MIPS_ID_OPC_DBITSWAP :
            MIPS_ID_NONE);
        gen_helper_dbitswap(cpu_gpr[rd], t0);
        break;
#endif
    }
}

#ifndef CONFIG_USER_ONLY
/* CP0 (MMU and control) */
static inline void gen_mthc0_entrylo(TCGv arg, target_ulong off)
{
    TCGv_i64 t0 = tcg_temp_new_i64();
    TCGv_i64 t1 = tcg_temp_new_i64();

    tcg_gen_ext_tl_i64(t0, arg);
    tcg_gen_ld_i64(t1, tcg_env, off);
#if defined(TARGET_MIPS64)
    tcg_gen_deposit_i64(t1, t1, t0, 30, 32);
#else
    tcg_gen_concat32_i64(t1, t1, t0);
#endif
    tcg_gen_st_i64(t1, tcg_env, off);
}

static inline void gen_mthc0_store64(TCGv arg, target_ulong off)
{
    TCGv_i64 t0 = tcg_temp_new_i64();
    TCGv_i64 t1 = tcg_temp_new_i64();

    tcg_gen_ext_tl_i64(t0, arg);
    tcg_gen_ld_i64(t1, tcg_env, off);
    tcg_gen_concat32_i64(t1, t1, t0);
    tcg_gen_st_i64(t1, tcg_env, off);
}

static inline void gen_mfhc0_entrylo(TCGv arg, target_ulong off)
{
    TCGv_i64 t0 = tcg_temp_new_i64();

    tcg_gen_ld_i64(t0, tcg_env, off);
#if defined(TARGET_MIPS64)
    tcg_gen_shri_i64(t0, t0, 30);
#else
    tcg_gen_shri_i64(t0, t0, 32);
#endif
    gen_move_low32(arg, t0);
}

static inline void gen_mfhc0_load64(TCGv arg, target_ulong off, int shift)
{
    TCGv_i64 t0 = tcg_temp_new_i64();

    tcg_gen_ld_i64(t0, tcg_env, off);
    tcg_gen_shri_i64(t0, t0, 32 + shift);
    gen_move_low32(arg, t0);
}

static inline void gen_mfc0_load32(TCGv arg, target_ulong off)
{
    TCGv_i32 t0 = tcg_temp_new_i32();

    tcg_gen_ld_i32(t0, tcg_env, off);
    tcg_gen_ext_i32_tl(arg, t0);
}

static inline void gen_mfc0_load64(TCGv arg, target_ulong off)
{
    tcg_gen_ld_tl(arg, tcg_env, off);
    tcg_gen_ext32s_tl(arg, arg);
}

static inline void gen_mtc0_store32(TCGv arg, target_ulong off)
{
    TCGv_i32 t0 = tcg_temp_new_i32();

    tcg_gen_trunc_tl_i32(t0, arg);
    tcg_gen_st_i32(t0, tcg_env, off);
}

#define CP0_CHECK(c)                            \
    do {                                        \
        if (!(c)) {                             \
            goto cp0_unimplemented;             \
        }                                       \
    } while (0)

static void gen_mfhc0(DisasContext *ctx, TCGv arg, int reg, int sel)
{
    const char *register_name = "invalid";

    switch (reg) {
    case CP0_REGISTER_02:
        switch (sel) {
        case 0:
            CP0_CHECK(ctx->hflags & MIPS_HFLAG_ELPA);
            gen_mfhc0_entrylo(arg, offsetof(CPUMIPSState, CP0_EntryLo0));
            register_name = "EntryLo0";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_03:
        switch (sel) {
        case CP0_REG03__ENTRYLO1:
            CP0_CHECK(ctx->hflags & MIPS_HFLAG_ELPA);
            gen_mfhc0_entrylo(arg, offsetof(CPUMIPSState, CP0_EntryLo1));
            register_name = "EntryLo1";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_17:
        switch (sel) {
        case CP0_REG17__LLADDR:
            gen_mfhc0_load64(arg, offsetof(CPUMIPSState, CP0_LLAddr),
                             ctx->CP0_LLAddr_shift);
            register_name = "LLAddr";
            break;
        case CP0_REG17__MAAR:
            CP0_CHECK(ctx->mrp);
            gen_helper_mfhc0_maar(arg, tcg_env);
            register_name = "MAAR";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_19:
        switch (sel) {
        case CP0_REG19__WATCHHI0:
        case CP0_REG19__WATCHHI1:
        case CP0_REG19__WATCHHI2:
        case CP0_REG19__WATCHHI3:
        case CP0_REG19__WATCHHI4:
        case CP0_REG19__WATCHHI5:
        case CP0_REG19__WATCHHI6:
        case CP0_REG19__WATCHHI7:
            /* upper 32 bits are only available when Config5MI != 0 */
            CP0_CHECK(ctx->mi);
            gen_mfhc0_load64(arg, offsetof(CPUMIPSState, CP0_WatchHi[sel]), 0);
            register_name = "WatchHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_28:
        switch (sel) {
        case 0:
        case 2:
        case 4:
        case 6:
            gen_mfhc0_load64(arg, offsetof(CPUMIPSState, CP0_TagLo), 0);
            register_name = "TagLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    default:
        goto cp0_unimplemented;
    }
    trace_mips_translate_c0("mfhc0", register_name, reg, sel);
    return;

cp0_unimplemented:
    qemu_log_mask(LOG_UNIMP, "mfhc0 %s (reg %d sel %d)\n",
                  register_name, reg, sel);
    tcg_gen_movi_tl(arg, 0);
}

static void gen_mthc0(DisasContext *ctx, TCGv arg, int reg, int sel)
{
    const char *register_name = "invalid";
    uint64_t mask = ctx->PAMask >> 36;

    switch (reg) {
    case CP0_REGISTER_02:
        switch (sel) {
        case 0:
            CP0_CHECK(ctx->hflags & MIPS_HFLAG_ELPA);
            tcg_gen_andi_tl(arg, arg, mask);
            gen_mthc0_entrylo(arg, offsetof(CPUMIPSState, CP0_EntryLo0));
            register_name = "EntryLo0";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_03:
        switch (sel) {
        case CP0_REG03__ENTRYLO1:
            CP0_CHECK(ctx->hflags & MIPS_HFLAG_ELPA);
            tcg_gen_andi_tl(arg, arg, mask);
            gen_mthc0_entrylo(arg, offsetof(CPUMIPSState, CP0_EntryLo1));
            register_name = "EntryLo1";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_17:
        switch (sel) {
        case CP0_REG17__LLADDR:
            /*
             * LLAddr is read-only (the only exception is bit 0 if LLB is
             * supported); the CP0_LLAddr_rw_bitmask does not seem to be
             * relevant for modern MIPS cores supporting MTHC0, therefore
             * treating MTHC0 to LLAddr as NOP.
             */
            register_name = "LLAddr";
            break;
        case CP0_REG17__MAAR:
            CP0_CHECK(ctx->mrp);
            gen_helper_mthc0_maar(tcg_env, arg);
            register_name = "MAAR";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_19:
        switch (sel) {
        case CP0_REG19__WATCHHI0:
        case CP0_REG19__WATCHHI1:
        case CP0_REG19__WATCHHI2:
        case CP0_REG19__WATCHHI3:
        case CP0_REG19__WATCHHI4:
        case CP0_REG19__WATCHHI5:
        case CP0_REG19__WATCHHI6:
        case CP0_REG19__WATCHHI7:
            /* upper 32 bits are only available when Config5MI != 0 */
            CP0_CHECK(ctx->mi);
            gen_helper_0e1i(mthc0_watchhi, arg, sel);
            register_name = "WatchHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_28:
        switch (sel) {
        case 0:
        case 2:
        case 4:
        case 6:
            tcg_gen_andi_tl(arg, arg, mask);
            gen_mthc0_store64(arg, offsetof(CPUMIPSState, CP0_TagLo));
            register_name = "TagLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    default:
        goto cp0_unimplemented;
    }
    trace_mips_translate_c0("mthc0", register_name, reg, sel);
    return;

cp0_unimplemented:
    qemu_log_mask(LOG_UNIMP, "mthc0 %s (reg %d sel %d)\n",
                  register_name, reg, sel);
}

static inline void gen_mfc0_unimplemented(DisasContext *ctx, TCGv arg)
{
    if (ctx->insn_flags & ISA_MIPS_R6) {
        tcg_gen_movi_tl(arg, 0);
    } else {
        tcg_gen_movi_tl(arg, ~0);
    }
}

static void gen_mfc0(DisasContext *ctx, TCGv arg, int reg, int sel)
{
    const char *register_name = "invalid";

    if (sel != 0) {
        check_insn(ctx, ISA_MIPS_R1);
    }

    switch (reg) {
    case CP0_REGISTER_00:
        switch (sel) {
        case CP0_REG00__INDEX:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Index));
            register_name = "Index";
            break;
        case CP0_REG00__MVPCONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_mvpcontrol(arg, tcg_env);
            register_name = "MVPControl";
            break;
        case CP0_REG00__MVPCONF0:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_mvpconf0(arg, tcg_env);
            register_name = "MVPConf0";
            break;
        case CP0_REG00__MVPCONF1:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_mvpconf1(arg, tcg_env);
            register_name = "MVPConf1";
            break;
        case CP0_REG00__VPCONTROL:
            CP0_CHECK(ctx->vp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPControl));
            register_name = "VPControl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_01:
        switch (sel) {
        case CP0_REG01__RANDOM:
            CP0_CHECK(!(ctx->insn_flags & ISA_MIPS_R6));
            gen_helper_mfc0_random(arg, tcg_env);
            register_name = "Random";
            break;
        case CP0_REG01__VPECONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEControl));
            register_name = "VPEControl";
            break;
        case CP0_REG01__VPECONF0:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEConf0));
            register_name = "VPEConf0";
            break;
        case CP0_REG01__VPECONF1:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEConf1));
            register_name = "VPEConf1";
            break;
        case CP0_REG01__YQMASK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load64(arg, offsetof(CPUMIPSState, CP0_YQMask));
            register_name = "YQMask";
            break;
        case CP0_REG01__VPESCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load64(arg, offsetof(CPUMIPSState, CP0_VPESchedule));
            register_name = "VPESchedule";
            break;
        case CP0_REG01__VPESCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load64(arg, offsetof(CPUMIPSState, CP0_VPEScheFBack));
            register_name = "VPEScheFBack";
            break;
        case CP0_REG01__VPEOPT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEOpt));
            register_name = "VPEOpt";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_02:
        switch (sel) {
        case CP0_REG02__ENTRYLO0:
            {
                TCGv_i64 tmp = tcg_temp_new_i64();
                tcg_gen_ld_i64(tmp, tcg_env,
                               offsetof(CPUMIPSState, CP0_EntryLo0));
#if defined(TARGET_MIPS64)
                if (ctx->rxi) {
                    /* Move RI/XI fields to bits 31:30 */
                    tcg_gen_shri_tl(arg, tmp, CP0EnLo_XI);
                    tcg_gen_deposit_tl(tmp, tmp, arg, 30, 2);
                }
#endif
                gen_move_low32(arg, tmp);
            }
            register_name = "EntryLo0";
            break;
        case CP0_REG02__TCSTATUS:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tcstatus(arg, tcg_env);
            register_name = "TCStatus";
            break;
        case CP0_REG02__TCBIND:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tcbind(arg, tcg_env);
            register_name = "TCBind";
            break;
        case CP0_REG02__TCRESTART:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tcrestart(arg, tcg_env);
            register_name = "TCRestart";
            break;
        case CP0_REG02__TCHALT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tchalt(arg, tcg_env);
            register_name = "TCHalt";
            break;
        case CP0_REG02__TCCONTEXT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tccontext(arg, tcg_env);
            register_name = "TCContext";
            break;
        case CP0_REG02__TCSCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tcschedule(arg, tcg_env);
            register_name = "TCSchedule";
            break;
        case CP0_REG02__TCSCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tcschefback(arg, tcg_env);
            register_name = "TCScheFBack";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_03:
        switch (sel) {
        case CP0_REG03__ENTRYLO1:
            {
                TCGv_i64 tmp = tcg_temp_new_i64();
                tcg_gen_ld_i64(tmp, tcg_env,
                               offsetof(CPUMIPSState, CP0_EntryLo1));
#if defined(TARGET_MIPS64)
                if (ctx->rxi) {
                    /* Move RI/XI fields to bits 31:30 */
                    tcg_gen_shri_tl(arg, tmp, CP0EnLo_XI);
                    tcg_gen_deposit_tl(tmp, tmp, arg, 30, 2);
                }
#endif
                gen_move_low32(arg, tmp);
            }
            register_name = "EntryLo1";
            break;
        case CP0_REG03__GLOBALNUM:
            CP0_CHECK(ctx->vp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_GlobalNumber));
            register_name = "GlobalNumber";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_04:
        switch (sel) {
        case CP0_REG04__CONTEXT:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_Context));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "Context";
            break;
        case CP0_REG04__CONTEXTCONFIG:
            /* SmartMIPS ASE */
            /* gen_helper_mfc0_contextconfig(arg); */
            register_name = "ContextConfig";
            goto cp0_unimplemented;
        case CP0_REG04__USERLOCAL:
            CP0_CHECK(ctx->ulri);
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "UserLocal";
            break;
        case CP0_REG04__MMID:
            CP0_CHECK(ctx->mi);
            gen_helper_mtc0_memorymapid(tcg_env, arg);
            register_name = "MMID";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_05:
        switch (sel) {
        case CP0_REG05__PAGEMASK:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PageMask));
            register_name = "PageMask";
            break;
        case CP0_REG05__PAGEGRAIN:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PageGrain));
            register_name = "PageGrain";
            break;
        case CP0_REG05__SEGCTL0:
            CP0_CHECK(ctx->sc);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_SegCtl0));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "SegCtl0";
            break;
        case CP0_REG05__SEGCTL1:
            CP0_CHECK(ctx->sc);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_SegCtl1));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "SegCtl1";
            break;
        case CP0_REG05__SEGCTL2:
            CP0_CHECK(ctx->sc);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_SegCtl2));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "SegCtl2";
            break;
        case CP0_REG05__PWBASE:
            check_pw(ctx);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PWBase));
            register_name = "PWBase";
            break;
        case CP0_REG05__PWFIELD:
            check_pw(ctx);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PWField));
            register_name = "PWField";
            break;
        case CP0_REG05__PWSIZE:
            check_pw(ctx);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PWSize));
            register_name = "PWSize";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_06:
        switch (sel) {
        case CP0_REG06__WIRED:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Wired));
            register_name = "Wired";
            break;
        case CP0_REG06__SRSCONF0:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf0));
            register_name = "SRSConf0";
            break;
        case CP0_REG06__SRSCONF1:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf1));
            register_name = "SRSConf1";
            break;
        case CP0_REG06__SRSCONF2:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf2));
            register_name = "SRSConf2";
            break;
        case CP0_REG06__SRSCONF3:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf3));
            register_name = "SRSConf3";
            break;
        case CP0_REG06__SRSCONF4:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf4));
            register_name = "SRSConf4";
            break;
        case CP0_REG06__PWCTL:
            check_pw(ctx);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PWCtl));
            register_name = "PWCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_07:
        switch (sel) {
        case CP0_REG07__HWRENA:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_HWREna));
            register_name = "HWREna";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_08:
        switch (sel) {
        case CP0_REG08__BADVADDR:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_BadVAddr));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "BadVAddr";
            break;
        case CP0_REG08__BADINSTR:
            CP0_CHECK(ctx->bi);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_BadInstr));
            register_name = "BadInstr";
            break;
        case CP0_REG08__BADINSTRP:
            CP0_CHECK(ctx->bp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_BadInstrP));
            register_name = "BadInstrP";
            break;
        case CP0_REG08__BADINSTRX:
            CP0_CHECK(ctx->bi);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_BadInstrX));
            tcg_gen_andi_tl(arg, arg, ~0xffff);
            register_name = "BadInstrX";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_09:
        switch (sel) {
        case CP0_REG09__COUNT:
            /* Mark as an IO operation because we read the time.  */
            translator_io_start(&ctx->base);

            gen_helper_mfc0_count(arg, tcg_env);
            /*
             * Break the TB to be able to take timer interrupts immediately
             * after reading count. DISAS_STOP isn't sufficient, we need to
             * ensure we break completely out of translated code.
             */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Count";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_10:
        switch (sel) {
        case CP0_REG10__ENTRYHI:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EntryHi));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "EntryHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_11:
        switch (sel) {
        case CP0_REG11__COMPARE:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Compare));
            register_name = "Compare";
            break;
        /* 6,7 are implementation dependent */
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_12:
        switch (sel) {
        case CP0_REG12__STATUS:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Status));
            register_name = "Status";
            break;
        case CP0_REG12__INTCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_IntCtl));
            register_name = "IntCtl";
            break;
        case CP0_REG12__SRSCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSCtl));
            register_name = "SRSCtl";
            break;
        case CP0_REG12__SRSMAP:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSMap));
            register_name = "SRSMap";
            break;
        default:
            goto cp0_unimplemented;
       }
        break;
    case CP0_REGISTER_13:
        switch (sel) {
        case CP0_REG13__CAUSE:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Cause));
            register_name = "Cause";
            break;
        default:
            goto cp0_unimplemented;
       }
        break;
    case CP0_REGISTER_14:
        switch (sel) {
        case CP0_REG14__EPC:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EPC));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "EPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_15:
        switch (sel) {
        case CP0_REG15__PRID:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PRid));
            register_name = "PRid";
            break;
        case CP0_REG15__EBASE:
            check_insn(ctx, ISA_MIPS_R2);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EBase));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "EBase";
            break;
        case CP0_REG15__CMGCRBASE:
            check_insn(ctx, ISA_MIPS_R2);
            CP0_CHECK(ctx->cmgcr);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_CMGCRBase));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "CMGCRBase";
            break;
        default:
            goto cp0_unimplemented;
       }
        break;
    case CP0_REGISTER_16:
        switch (sel) {
        case CP0_REG16__CONFIG:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config0));
            register_name = "Config";
            break;
        case CP0_REG16__CONFIG1:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config1));
            register_name = "Config1";
            break;
        case CP0_REG16__CONFIG2:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config2));
            register_name = "Config2";
            break;
        case CP0_REG16__CONFIG3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config3));
            register_name = "Config3";
            break;
        case CP0_REG16__CONFIG4:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config4));
            register_name = "Config4";
            break;
        case CP0_REG16__CONFIG5:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config5));
            register_name = "Config5";
            break;
        /* 6,7 are implementation dependent */
        case CP0_REG16__CONFIG6:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config6));
            register_name = "Config6";
            break;
        case CP0_REG16__CONFIG7:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config7));
            register_name = "Config7";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_17:
        switch (sel) {
        case CP0_REG17__LLADDR:
            gen_helper_mfc0_lladdr(arg, tcg_env);
            register_name = "LLAddr";
            break;
        case CP0_REG17__MAAR:
            CP0_CHECK(ctx->mrp);
            gen_helper_mfc0_maar(arg, tcg_env);
            register_name = "MAAR";
            break;
        case CP0_REG17__MAARI:
            CP0_CHECK(ctx->mrp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_MAARI));
            register_name = "MAARI";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_18:
        switch (sel) {
        case CP0_REG18__WATCHLO0:
        case CP0_REG18__WATCHLO1:
        case CP0_REG18__WATCHLO2:
        case CP0_REG18__WATCHLO3:
        case CP0_REG18__WATCHLO4:
        case CP0_REG18__WATCHLO5:
        case CP0_REG18__WATCHLO6:
        case CP0_REG18__WATCHLO7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_1e0i(mfc0_watchlo, arg, sel);
            register_name = "WatchLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_19:
        switch (sel) {
        case CP0_REG19__WATCHHI0:
        case CP0_REG19__WATCHHI1:
        case CP0_REG19__WATCHHI2:
        case CP0_REG19__WATCHHI3:
        case CP0_REG19__WATCHHI4:
        case CP0_REG19__WATCHHI5:
        case CP0_REG19__WATCHHI6:
        case CP0_REG19__WATCHHI7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_1e0i(mfc0_watchhi, arg, sel);
            register_name = "WatchHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_20:
        switch (sel) {
        case CP0_REG20__XCONTEXT:
#if defined(TARGET_MIPS64)
            check_insn(ctx, ISA_MIPS3);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_XContext));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "XContext";
            break;
#endif
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_21:
       /* Officially reserved, but sel 0 is used for R1x000 framemask */
        CP0_CHECK(!(ctx->insn_flags & ISA_MIPS_R6));
        switch (sel) {
        case 0:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Framemask));
            register_name = "Framemask";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_22:
        tcg_gen_movi_tl(arg, 0); /* unimplemented */
        register_name = "'Diagnostic"; /* implementation dependent */
        break;
    case CP0_REGISTER_23:
        switch (sel) {
        case CP0_REG23__DEBUG:
            gen_helper_mfc0_debug(arg, tcg_env); /* EJTAG support */
            register_name = "Debug";
            break;
        case CP0_REG23__TRACECONTROL:
            /* PDtrace support */
            /* gen_helper_mfc0_tracecontrol(arg);  */
            register_name = "TraceControl";
            goto cp0_unimplemented;
        case CP0_REG23__TRACECONTROL2:
            /* PDtrace support */
            /* gen_helper_mfc0_tracecontrol2(arg); */
            register_name = "TraceControl2";
            goto cp0_unimplemented;
        case CP0_REG23__USERTRACEDATA1:
            /* PDtrace support */
            /* gen_helper_mfc0_usertracedata1(arg);*/
            register_name = "UserTraceData1";
            goto cp0_unimplemented;
        case CP0_REG23__TRACEIBPC:
            /* PDtrace support */
            /* gen_helper_mfc0_traceibpc(arg);     */
            register_name = "TraceIBPC";
            goto cp0_unimplemented;
        case CP0_REG23__TRACEDBPC:
            /* PDtrace support */
            /* gen_helper_mfc0_tracedbpc(arg);     */
            register_name = "TraceDBPC";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_24:
        switch (sel) {
        case CP0_REG24__DEPC:
            /* EJTAG support */
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_DEPC));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "DEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_25:
        switch (sel) {
        case CP0_REG25__PERFCTL0:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Performance0));
            register_name = "Performance0";
            break;
        case CP0_REG25__PERFCNT0:
            /* gen_helper_mfc0_performance1(arg); */
            register_name = "Performance1";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL1:
            /* gen_helper_mfc0_performance2(arg); */
            register_name = "Performance2";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT1:
            /* gen_helper_mfc0_performance3(arg); */
            register_name = "Performance3";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL2:
            /* gen_helper_mfc0_performance4(arg); */
            register_name = "Performance4";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT2:
            /* gen_helper_mfc0_performance5(arg); */
            register_name = "Performance5";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL3:
            /* gen_helper_mfc0_performance6(arg); */
            register_name = "Performance6";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT3:
            /* gen_helper_mfc0_performance7(arg); */
            register_name = "Performance7";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_26:
        switch (sel) {
        case CP0_REG26__ERRCTL:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_ErrCtl));
            register_name = "ErrCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_27:
        switch (sel) {
        case CP0_REG27__CACHERR:
            tcg_gen_movi_tl(arg, 0); /* unimplemented */
            register_name = "CacheErr";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_28:
        switch (sel) {
        case CP0_REG28__TAGLO:
        case CP0_REG28__TAGLO1:
        case CP0_REG28__TAGLO2:
        case CP0_REG28__TAGLO3:
            {
                TCGv_i64 tmp = tcg_temp_new_i64();
                tcg_gen_ld_i64(tmp, tcg_env, offsetof(CPUMIPSState, CP0_TagLo));
                gen_move_low32(arg, tmp);
            }
            register_name = "TagLo";
            break;
        case CP0_REG28__DATALO:
        case CP0_REG28__DATALO1:
        case CP0_REG28__DATALO2:
        case CP0_REG28__DATALO3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_DataLo));
            register_name = "DataLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_29:
        switch (sel) {
        case CP0_REG29__TAGHI:
        case CP0_REG29__TAGHI1:
        case CP0_REG29__TAGHI2:
        case CP0_REG29__TAGHI3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_TagHi));
            register_name = "TagHi";
            break;
        case CP0_REG29__DATAHI:
        case CP0_REG29__DATAHI1:
        case CP0_REG29__DATAHI2:
        case CP0_REG29__DATAHI3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_DataHi));
            register_name = "DataHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_30:
        switch (sel) {
        case CP0_REG30__ERROREPC:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_ErrorEPC));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "ErrorEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_31:
        switch (sel) {
        case CP0_REG31__DESAVE:
            /* EJTAG support */
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_DESAVE));
            register_name = "DESAVE";
            break;
        case CP0_REG31__KSCRATCH1:
        case CP0_REG31__KSCRATCH2:
        case CP0_REG31__KSCRATCH3:
        case CP0_REG31__KSCRATCH4:
        case CP0_REG31__KSCRATCH5:
        case CP0_REG31__KSCRATCH6:
            CP0_CHECK(ctx->kscrexist & (1 << sel));
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_KScratch[sel - 2]));
            tcg_gen_ext32s_tl(arg, arg);
            register_name = "KScratch";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    default:
       goto cp0_unimplemented;
    }
    trace_mips_translate_c0("mfc0", register_name, reg, sel);
    return;

cp0_unimplemented:
    qemu_log_mask(LOG_UNIMP, "mfc0 %s (reg %d sel %d)\n",
                  register_name, reg, sel);
    gen_mfc0_unimplemented(ctx, arg);
}

static void gen_mtc0(DisasContext *ctx, TCGv arg, int reg, int sel)
{
    const char *register_name = "invalid";
    bool icount;

    if (sel != 0) {
        check_insn(ctx, ISA_MIPS_R1);
    }

    icount = translator_io_start(&ctx->base);

    switch (reg) {
    case CP0_REGISTER_00:
        switch (sel) {
        case CP0_REG00__INDEX:
            gen_helper_mtc0_index(tcg_env, arg);
            register_name = "Index";
            break;
        case CP0_REG00__MVPCONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_mvpcontrol(tcg_env, arg);
            register_name = "MVPControl";
            break;
        case CP0_REG00__MVPCONF0:
            CP0_CHECK(disas_mt_available(ctx));
            /* ignored */
            register_name = "MVPConf0";
            break;
        case CP0_REG00__MVPCONF1:
            CP0_CHECK(disas_mt_available(ctx));
            /* ignored */
            register_name = "MVPConf1";
            break;
        case CP0_REG00__VPCONTROL:
            CP0_CHECK(ctx->vp);
            /* ignored */
            register_name = "VPControl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_01:
        switch (sel) {
        case CP0_REG01__RANDOM:
            /* ignored */
            register_name = "Random";
            break;
        case CP0_REG01__VPECONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpecontrol(tcg_env, arg);
            register_name = "VPEControl";
            break;
        case CP0_REG01__VPECONF0:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpeconf0(tcg_env, arg);
            register_name = "VPEConf0";
            break;
        case CP0_REG01__VPECONF1:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpeconf1(tcg_env, arg);
            register_name = "VPEConf1";
            break;
        case CP0_REG01__YQMASK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_yqmask(tcg_env, arg);
            register_name = "YQMask";
            break;
        case CP0_REG01__VPESCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_VPESchedule));
            register_name = "VPESchedule";
            break;
        case CP0_REG01__VPESCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_VPEScheFBack));
            register_name = "VPEScheFBack";
            break;
        case CP0_REG01__VPEOPT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpeopt(tcg_env, arg);
            register_name = "VPEOpt";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_02:
        switch (sel) {
        case CP0_REG02__ENTRYLO0:
            gen_helper_mtc0_entrylo0(tcg_env, arg);
            register_name = "EntryLo0";
            break;
        case CP0_REG02__TCSTATUS:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcstatus(tcg_env, arg);
            register_name = "TCStatus";
            break;
        case CP0_REG02__TCBIND:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcbind(tcg_env, arg);
            register_name = "TCBind";
            break;
        case CP0_REG02__TCRESTART:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcrestart(tcg_env, arg);
            register_name = "TCRestart";
            break;
        case CP0_REG02__TCHALT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tchalt(tcg_env, arg);
            register_name = "TCHalt";
            break;
        case CP0_REG02__TCCONTEXT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tccontext(tcg_env, arg);
            register_name = "TCContext";
            break;
        case CP0_REG02__TCSCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcschedule(tcg_env, arg);
            register_name = "TCSchedule";
            break;
        case CP0_REG02__TCSCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcschefback(tcg_env, arg);
            register_name = "TCScheFBack";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_03:
        switch (sel) {
        case CP0_REG03__ENTRYLO1:
            gen_helper_mtc0_entrylo1(tcg_env, arg);
            register_name = "EntryLo1";
            break;
        case CP0_REG03__GLOBALNUM:
            CP0_CHECK(ctx->vp);
            /* ignored */
            register_name = "GlobalNumber";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_04:
        switch (sel) {
        case CP0_REG04__CONTEXT:
            gen_helper_mtc0_context(tcg_env, arg);
            register_name = "Context";
            break;
        case CP0_REG04__CONTEXTCONFIG:
            /* SmartMIPS ASE */
            /* gen_helper_mtc0_contextconfig(arg); */
            register_name = "ContextConfig";
            goto cp0_unimplemented;
        case CP0_REG04__USERLOCAL:
            CP0_CHECK(ctx->ulri);
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
            register_name = "UserLocal";
            break;
        case CP0_REG04__MMID:
            CP0_CHECK(ctx->mi);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_MemoryMapID));
            register_name = "MMID";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_05:
        switch (sel) {
        case CP0_REG05__PAGEMASK:
            gen_helper_mtc0_pagemask(tcg_env, arg);
            register_name = "PageMask";
            break;
        case CP0_REG05__PAGEGRAIN:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_pagegrain(tcg_env, arg);
            register_name = "PageGrain";
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG05__SEGCTL0:
            CP0_CHECK(ctx->sc);
            gen_helper_mtc0_segctl0(tcg_env, arg);
            register_name = "SegCtl0";
            break;
        case CP0_REG05__SEGCTL1:
            CP0_CHECK(ctx->sc);
            gen_helper_mtc0_segctl1(tcg_env, arg);
            register_name = "SegCtl1";
            break;
        case CP0_REG05__SEGCTL2:
            CP0_CHECK(ctx->sc);
            gen_helper_mtc0_segctl2(tcg_env, arg);
            register_name = "SegCtl2";
            break;
        case CP0_REG05__PWBASE:
            check_pw(ctx);
            /* Q13 v4 default, maintainer-vetoable: EntryHi ASID_WRITE is
             * the sole gate-refresh event; PWBase is stored inline (its
             * committed-write event push retired with the identity
             * apparatus). */
            gen_mtc0_store32(arg, offsetof(CPUMIPSState, CP0_PWBase));
            register_name = "PWBase";
            break;
        case CP0_REG05__PWFIELD:
            check_pw(ctx);
            gen_helper_mtc0_pwfield(tcg_env, arg);
            register_name = "PWField";
            break;
        case CP0_REG05__PWSIZE:
            check_pw(ctx);
            gen_helper_mtc0_pwsize(tcg_env, arg);
            register_name = "PWSize";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_06:
        switch (sel) {
        case CP0_REG06__WIRED:
            gen_helper_mtc0_wired(tcg_env, arg);
            register_name = "Wired";
            break;
        case CP0_REG06__SRSCONF0:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf0(tcg_env, arg);
            register_name = "SRSConf0";
            break;
        case CP0_REG06__SRSCONF1:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf1(tcg_env, arg);
            register_name = "SRSConf1";
            break;
        case CP0_REG06__SRSCONF2:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf2(tcg_env, arg);
            register_name = "SRSConf2";
            break;
        case CP0_REG06__SRSCONF3:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf3(tcg_env, arg);
            register_name = "SRSConf3";
            break;
        case CP0_REG06__SRSCONF4:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf4(tcg_env, arg);
            register_name = "SRSConf4";
            break;
        case CP0_REG06__PWCTL:
            check_pw(ctx);
            gen_helper_mtc0_pwctl(tcg_env, arg);
            register_name = "PWCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_07:
        switch (sel) {
        case CP0_REG07__HWRENA:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_hwrena(tcg_env, arg);
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "HWREna";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_08:
        switch (sel) {
        case CP0_REG08__BADVADDR:
            /* ignored */
            register_name = "BadVAddr";
            break;
        case CP0_REG08__BADINSTR:
            /* ignored */
            register_name = "BadInstr";
            break;
        case CP0_REG08__BADINSTRP:
            /* ignored */
            register_name = "BadInstrP";
            break;
        case CP0_REG08__BADINSTRX:
            /* ignored */
            register_name = "BadInstrX";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_09:
        switch (sel) {
        case CP0_REG09__COUNT:
            gen_helper_mtc0_count(tcg_env, arg);
            register_name = "Count";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_10:
        switch (sel) {
        case CP0_REG10__ENTRYHI:
            gen_helper_mtc0_entryhi(tcg_env, arg);
            register_name = "EntryHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_11:
        switch (sel) {
        case CP0_REG11__COMPARE:
            gen_helper_mtc0_compare(tcg_env, arg);
            register_name = "Compare";
            break;
        /* 6,7 are implementation dependent */
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_12:
        switch (sel) {
        case CP0_REG12__STATUS:
            save_cpu_state(ctx, 1);
            gen_helper_mtc0_status(tcg_env, arg);
            /* DISAS_STOP isn't good enough here, hflags may have changed. */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Status";
            break;
        case CP0_REG12__INTCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_intctl(tcg_env, arg);
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "IntCtl";
            break;
        case CP0_REG12__SRSCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsctl(tcg_env, arg);
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "SRSCtl";
            break;
        case CP0_REG12__SRSMAP:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mtc0_store32(arg, offsetof(CPUMIPSState, CP0_SRSMap));
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "SRSMap";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_13:
        switch (sel) {
        case CP0_REG13__CAUSE:
            save_cpu_state(ctx, 1);
            gen_helper_mtc0_cause(tcg_env, arg);
            /*
             * Stop translation as we may have triggered an interrupt.
             * DISAS_STOP isn't sufficient, we need to ensure we break out of
             * translated code to check for pending interrupts.
             */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Cause";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_14:
        switch (sel) {
        case CP0_REG14__EPC:
            tcg_gen_st_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EPC));
            register_name = "EPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_15:
        switch (sel) {
        case CP0_REG15__PRID:
            /* ignored */
            register_name = "PRid";
            break;
        case CP0_REG15__EBASE:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_ebase(tcg_env, arg);
            register_name = "EBase";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_16:
        switch (sel) {
        case CP0_REG16__CONFIG:
            gen_helper_mtc0_config0(tcg_env, arg);
            register_name = "Config";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG16__CONFIG1:
            /* ignored, read only */
            register_name = "Config1";
            break;
        case CP0_REG16__CONFIG2:
            gen_helper_mtc0_config2(tcg_env, arg);
            register_name = "Config2";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG16__CONFIG3:
            gen_helper_mtc0_config3(tcg_env, arg);
            register_name = "Config3";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG16__CONFIG4:
            gen_helper_mtc0_config4(tcg_env, arg);
            register_name = "Config4";
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG16__CONFIG5:
            gen_helper_mtc0_config5(tcg_env, arg);
            register_name = "Config5";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        /* 6,7 are implementation dependent */
        case CP0_REG16__CONFIG6:
            /* ignored */
            register_name = "Config6";
            break;
        case CP0_REG16__CONFIG7:
            /* ignored */
            register_name = "Config7";
            break;
        default:
            register_name = "Invalid config selector";
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_17:
        switch (sel) {
        case CP0_REG17__LLADDR:
            gen_helper_mtc0_lladdr(tcg_env, arg);
            register_name = "LLAddr";
            break;
        case CP0_REG17__MAAR:
            CP0_CHECK(ctx->mrp);
            gen_helper_mtc0_maar(tcg_env, arg);
            register_name = "MAAR";
            break;
        case CP0_REG17__MAARI:
            CP0_CHECK(ctx->mrp);
            gen_helper_mtc0_maari(tcg_env, arg);
            register_name = "MAARI";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_18:
        switch (sel) {
        case CP0_REG18__WATCHLO0:
        case CP0_REG18__WATCHLO1:
        case CP0_REG18__WATCHLO2:
        case CP0_REG18__WATCHLO3:
        case CP0_REG18__WATCHLO4:
        case CP0_REG18__WATCHLO5:
        case CP0_REG18__WATCHLO6:
        case CP0_REG18__WATCHLO7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_0e1i(mtc0_watchlo, arg, sel);
            register_name = "WatchLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_19:
        switch (sel) {
        case CP0_REG19__WATCHHI0:
        case CP0_REG19__WATCHHI1:
        case CP0_REG19__WATCHHI2:
        case CP0_REG19__WATCHHI3:
        case CP0_REG19__WATCHHI4:
        case CP0_REG19__WATCHHI5:
        case CP0_REG19__WATCHHI6:
        case CP0_REG19__WATCHHI7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_0e1i(mtc0_watchhi, arg, sel);
            register_name = "WatchHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_20:
        switch (sel) {
        case CP0_REG20__XCONTEXT:
#if defined(TARGET_MIPS64)
            check_insn(ctx, ISA_MIPS3);
            gen_helper_mtc0_xcontext(tcg_env, arg);
            register_name = "XContext";
            break;
#endif
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_21:
       /* Officially reserved, but sel 0 is used for R1x000 framemask */
        CP0_CHECK(!(ctx->insn_flags & ISA_MIPS_R6));
        switch (sel) {
        case 0:
            gen_helper_mtc0_framemask(tcg_env, arg);
            register_name = "Framemask";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_22:
        /* ignored */
        register_name = "Diagnostic"; /* implementation dependent */
        break;
    case CP0_REGISTER_23:
        switch (sel) {
        case CP0_REG23__DEBUG:
            gen_helper_mtc0_debug(tcg_env, arg); /* EJTAG support */
            /* DISAS_STOP isn't good enough here, hflags may have changed. */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Debug";
            break;
        case CP0_REG23__TRACECONTROL:
            /* PDtrace support */
            /* gen_helper_mtc0_tracecontrol(tcg_env, arg);  */
            register_name = "TraceControl";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            goto cp0_unimplemented;
        case CP0_REG23__TRACECONTROL2:
            /* PDtrace support */
            /* gen_helper_mtc0_tracecontrol2(tcg_env, arg); */
            register_name = "TraceControl2";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            goto cp0_unimplemented;
        case CP0_REG23__USERTRACEDATA1:
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            /* PDtrace support */
            /* gen_helper_mtc0_usertracedata1(tcg_env, arg);*/
            register_name = "UserTraceData";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            goto cp0_unimplemented;
        case CP0_REG23__TRACEIBPC:
            /* PDtrace support */
            /* gen_helper_mtc0_traceibpc(tcg_env, arg);     */
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "TraceIBPC";
            goto cp0_unimplemented;
        case CP0_REG23__TRACEDBPC:
            /* PDtrace support */
            /* gen_helper_mtc0_tracedbpc(tcg_env, arg);     */
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "TraceDBPC";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_24:
        switch (sel) {
        case CP0_REG24__DEPC:
            /* EJTAG support */
            tcg_gen_st_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_DEPC));
            register_name = "DEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_25:
        switch (sel) {
        case CP0_REG25__PERFCTL0:
            gen_helper_mtc0_performance0(tcg_env, arg);
            register_name = "Performance0";
            break;
        case CP0_REG25__PERFCNT0:
            /* gen_helper_mtc0_performance1(arg); */
            register_name = "Performance1";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL1:
            /* gen_helper_mtc0_performance2(arg); */
            register_name = "Performance2";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT1:
            /* gen_helper_mtc0_performance3(arg); */
            register_name = "Performance3";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL2:
            /* gen_helper_mtc0_performance4(arg); */
            register_name = "Performance4";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT2:
            /* gen_helper_mtc0_performance5(arg); */
            register_name = "Performance5";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL3:
            /* gen_helper_mtc0_performance6(arg); */
            register_name = "Performance6";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT3:
            /* gen_helper_mtc0_performance7(arg); */
            register_name = "Performance7";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
       break;
    case CP0_REGISTER_26:
        switch (sel) {
        case CP0_REG26__ERRCTL:
            gen_helper_mtc0_errctl(tcg_env, arg);
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "ErrCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_27:
        switch (sel) {
        case CP0_REG27__CACHERR:
            /* ignored */
            register_name = "CacheErr";
            break;
        default:
            goto cp0_unimplemented;
        }
       break;
    case CP0_REGISTER_28:
        switch (sel) {
        case CP0_REG28__TAGLO:
        case CP0_REG28__TAGLO1:
        case CP0_REG28__TAGLO2:
        case CP0_REG28__TAGLO3:
            gen_helper_mtc0_taglo(tcg_env, arg);
            register_name = "TagLo";
            break;
        case CP0_REG28__DATALO:
        case CP0_REG28__DATALO1:
        case CP0_REG28__DATALO2:
        case CP0_REG28__DATALO3:
            gen_helper_mtc0_datalo(tcg_env, arg);
            register_name = "DataLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_29:
        switch (sel) {
        case CP0_REG29__TAGHI:
        case CP0_REG29__TAGHI1:
        case CP0_REG29__TAGHI2:
        case CP0_REG29__TAGHI3:
            gen_helper_mtc0_taghi(tcg_env, arg);
            register_name = "TagHi";
            break;
        case CP0_REG29__DATAHI:
        case CP0_REG29__DATAHI1:
        case CP0_REG29__DATAHI2:
        case CP0_REG29__DATAHI3:
            gen_helper_mtc0_datahi(tcg_env, arg);
            register_name = "DataHi";
            break;
        default:
            register_name = "invalid sel";
            goto cp0_unimplemented;
        }
       break;
    case CP0_REGISTER_30:
        switch (sel) {
        case CP0_REG30__ERROREPC:
            tcg_gen_st_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_ErrorEPC));
            register_name = "ErrorEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_31:
        switch (sel) {
        case CP0_REG31__DESAVE:
            /* EJTAG support */
            gen_mtc0_store32(arg, offsetof(CPUMIPSState, CP0_DESAVE));
            register_name = "DESAVE";
            break;
        case CP0_REG31__KSCRATCH1:
        case CP0_REG31__KSCRATCH2:
        case CP0_REG31__KSCRATCH3:
        case CP0_REG31__KSCRATCH4:
        case CP0_REG31__KSCRATCH5:
        case CP0_REG31__KSCRATCH6:
            CP0_CHECK(ctx->kscrexist & (1 << sel));
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_KScratch[sel - 2]));
            register_name = "KScratch";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    default:
       goto cp0_unimplemented;
    }
    trace_mips_translate_c0("mtc0", register_name, reg, sel);

    /* For simplicity assume that all writes can cause interrupts.  */
    if (icount) {
        /*
         * DISAS_STOP isn't sufficient, we need to ensure we break out of
         * translated code to check for pending interrupts.
         */
        gen_save_pc(ctx->base.pc_next + 4);
        ctx->base.is_jmp = DISAS_EXIT;
    }
    return;

cp0_unimplemented:
    qemu_log_mask(LOG_UNIMP, "mtc0 %s (reg %d sel %d)\n",
                  register_name, reg, sel);
}

#if defined(TARGET_MIPS64)
static void gen_dmfc0(DisasContext *ctx, TCGv arg, int reg, int sel)
{
    const char *register_name = "invalid";

    if (sel != 0) {
        check_insn(ctx, ISA_MIPS_R1);
    }

    switch (reg) {
    case CP0_REGISTER_00:
        switch (sel) {
        case CP0_REG00__INDEX:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Index));
            register_name = "Index";
            break;
        case CP0_REG00__MVPCONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_mvpcontrol(arg, tcg_env);
            register_name = "MVPControl";
            break;
        case CP0_REG00__MVPCONF0:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_mvpconf0(arg, tcg_env);
            register_name = "MVPConf0";
            break;
        case CP0_REG00__MVPCONF1:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_mvpconf1(arg, tcg_env);
            register_name = "MVPConf1";
            break;
        case CP0_REG00__VPCONTROL:
            CP0_CHECK(ctx->vp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPControl));
            register_name = "VPControl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_01:
        switch (sel) {
        case CP0_REG01__RANDOM:
            CP0_CHECK(!(ctx->insn_flags & ISA_MIPS_R6));
            gen_helper_mfc0_random(arg, tcg_env);
            register_name = "Random";
            break;
        case CP0_REG01__VPECONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEControl));
            register_name = "VPEControl";
            break;
        case CP0_REG01__VPECONF0:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEConf0));
            register_name = "VPEConf0";
            break;
        case CP0_REG01__VPECONF1:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEConf1));
            register_name = "VPEConf1";
            break;
        case CP0_REG01__YQMASK:
            CP0_CHECK(disas_mt_available(ctx));
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_YQMask));
            register_name = "YQMask";
            break;
        case CP0_REG01__VPESCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_VPESchedule));
            register_name = "VPESchedule";
            break;
        case CP0_REG01__VPESCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_VPEScheFBack));
            register_name = "VPEScheFBack";
            break;
        case CP0_REG01__VPEOPT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_VPEOpt));
            register_name = "VPEOpt";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_02:
        switch (sel) {
        case CP0_REG02__ENTRYLO0:
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_EntryLo0));
            register_name = "EntryLo0";
            break;
        case CP0_REG02__TCSTATUS:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tcstatus(arg, tcg_env);
            register_name = "TCStatus";
            break;
        case CP0_REG02__TCBIND:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mfc0_tcbind(arg, tcg_env);
            register_name = "TCBind";
            break;
        case CP0_REG02__TCRESTART:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_dmfc0_tcrestart(arg, tcg_env);
            register_name = "TCRestart";
            break;
        case CP0_REG02__TCHALT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_dmfc0_tchalt(arg, tcg_env);
            register_name = "TCHalt";
            break;
        case CP0_REG02__TCCONTEXT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_dmfc0_tccontext(arg, tcg_env);
            register_name = "TCContext";
            break;
        case CP0_REG02__TCSCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_dmfc0_tcschedule(arg, tcg_env);
            register_name = "TCSchedule";
            break;
        case CP0_REG02__TCSCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_dmfc0_tcschefback(arg, tcg_env);
            register_name = "TCScheFBack";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_03:
        switch (sel) {
        case CP0_REG03__ENTRYLO1:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EntryLo1));
            register_name = "EntryLo1";
            break;
        case CP0_REG03__GLOBALNUM:
            CP0_CHECK(ctx->vp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_GlobalNumber));
            register_name = "GlobalNumber";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_04:
        switch (sel) {
        case CP0_REG04__CONTEXT:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_Context));
            register_name = "Context";
            break;
        case CP0_REG04__CONTEXTCONFIG:
            /* SmartMIPS ASE */
            /* gen_helper_dmfc0_contextconfig(arg); */
            register_name = "ContextConfig";
            goto cp0_unimplemented;
        case CP0_REG04__USERLOCAL:
            CP0_CHECK(ctx->ulri);
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
            register_name = "UserLocal";
            break;
        case CP0_REG04__MMID:
            CP0_CHECK(ctx->mi);
            gen_helper_mtc0_memorymapid(tcg_env, arg);
            register_name = "MMID";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_05:
        switch (sel) {
        case CP0_REG05__PAGEMASK:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PageMask));
            register_name = "PageMask";
            break;
        case CP0_REG05__PAGEGRAIN:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PageGrain));
            register_name = "PageGrain";
            break;
        case CP0_REG05__SEGCTL0:
            CP0_CHECK(ctx->sc);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_SegCtl0));
            register_name = "SegCtl0";
            break;
        case CP0_REG05__SEGCTL1:
            CP0_CHECK(ctx->sc);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_SegCtl1));
            register_name = "SegCtl1";
            break;
        case CP0_REG05__SEGCTL2:
            CP0_CHECK(ctx->sc);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_SegCtl2));
            register_name = "SegCtl2";
            break;
        case CP0_REG05__PWBASE:
            check_pw(ctx);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_PWBase));
            register_name = "PWBase";
            break;
        case CP0_REG05__PWFIELD:
            check_pw(ctx);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_PWField));
            register_name = "PWField";
            break;
        case CP0_REG05__PWSIZE:
            check_pw(ctx);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_PWSize));
            register_name = "PWSize";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_06:
        switch (sel) {
        case CP0_REG06__WIRED:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Wired));
            register_name = "Wired";
            break;
        case CP0_REG06__SRSCONF0:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf0));
            register_name = "SRSConf0";
            break;
        case CP0_REG06__SRSCONF1:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf1));
            register_name = "SRSConf1";
            break;
        case CP0_REG06__SRSCONF2:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf2));
            register_name = "SRSConf2";
            break;
        case CP0_REG06__SRSCONF3:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf3));
            register_name = "SRSConf3";
            break;
        case CP0_REG06__SRSCONF4:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSConf4));
            register_name = "SRSConf4";
            break;
        case CP0_REG06__PWCTL:
            check_pw(ctx);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PWCtl));
            register_name = "PWCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_07:
        switch (sel) {
        case CP0_REG07__HWRENA:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_HWREna));
            register_name = "HWREna";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_08:
        switch (sel) {
        case CP0_REG08__BADVADDR:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_BadVAddr));
            register_name = "BadVAddr";
            break;
        case CP0_REG08__BADINSTR:
            CP0_CHECK(ctx->bi);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_BadInstr));
            register_name = "BadInstr";
            break;
        case CP0_REG08__BADINSTRP:
            CP0_CHECK(ctx->bp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_BadInstrP));
            register_name = "BadInstrP";
            break;
        case CP0_REG08__BADINSTRX:
            CP0_CHECK(ctx->bi);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_BadInstrX));
            tcg_gen_andi_tl(arg, arg, ~0xffff);
            register_name = "BadInstrX";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_09:
        switch (sel) {
        case CP0_REG09__COUNT:
            /* Mark as an IO operation because we read the time.  */
            translator_io_start(&ctx->base);
            gen_helper_mfc0_count(arg, tcg_env);
            /*
             * Break the TB to be able to take timer interrupts immediately
             * after reading count. DISAS_STOP isn't sufficient, we need to
             * ensure we break completely out of translated code.
             */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Count";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_10:
        switch (sel) {
        case CP0_REG10__ENTRYHI:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EntryHi));
            register_name = "EntryHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_11:
        switch (sel) {
        case CP0_REG11__COMPARE:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Compare));
            register_name = "Compare";
            break;
        /* 6,7 are implementation dependent */
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_12:
        switch (sel) {
        case CP0_REG12__STATUS:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Status));
            register_name = "Status";
            break;
        case CP0_REG12__INTCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_IntCtl));
            register_name = "IntCtl";
            break;
        case CP0_REG12__SRSCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSCtl));
            register_name = "SRSCtl";
            break;
        case CP0_REG12__SRSMAP:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_SRSMap));
            register_name = "SRSMap";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_13:
        switch (sel) {
        case CP0_REG13__CAUSE:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Cause));
            register_name = "Cause";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_14:
        switch (sel) {
        case CP0_REG14__EPC:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EPC));
            register_name = "EPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_15:
        switch (sel) {
        case CP0_REG15__PRID:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_PRid));
            register_name = "PRid";
            break;
        case CP0_REG15__EBASE:
            check_insn(ctx, ISA_MIPS_R2);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EBase));
            register_name = "EBase";
            break;
        case CP0_REG15__CMGCRBASE:
            check_insn(ctx, ISA_MIPS_R2);
            CP0_CHECK(ctx->cmgcr);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_CMGCRBase));
            register_name = "CMGCRBase";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_16:
        switch (sel) {
        case CP0_REG16__CONFIG:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config0));
            register_name = "Config";
            break;
        case CP0_REG16__CONFIG1:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config1));
            register_name = "Config1";
            break;
        case CP0_REG16__CONFIG2:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config2));
            register_name = "Config2";
            break;
        case CP0_REG16__CONFIG3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config3));
            register_name = "Config3";
            break;
        case CP0_REG16__CONFIG4:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config4));
            register_name = "Config4";
            break;
        case CP0_REG16__CONFIG5:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config5));
            register_name = "Config5";
            break;
        /* 6,7 are implementation dependent */
        case CP0_REG16__CONFIG6:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config6));
            register_name = "Config6";
            break;
        case CP0_REG16__CONFIG7:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Config7));
            register_name = "Config7";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_17:
        switch (sel) {
        case CP0_REG17__LLADDR:
            gen_helper_dmfc0_lladdr(arg, tcg_env);
            register_name = "LLAddr";
            break;
        case CP0_REG17__MAAR:
            CP0_CHECK(ctx->mrp);
            gen_helper_dmfc0_maar(arg, tcg_env);
            register_name = "MAAR";
            break;
        case CP0_REG17__MAARI:
            CP0_CHECK(ctx->mrp);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_MAARI));
            register_name = "MAARI";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_18:
        switch (sel) {
        case CP0_REG18__WATCHLO0:
        case CP0_REG18__WATCHLO1:
        case CP0_REG18__WATCHLO2:
        case CP0_REG18__WATCHLO3:
        case CP0_REG18__WATCHLO4:
        case CP0_REG18__WATCHLO5:
        case CP0_REG18__WATCHLO6:
        case CP0_REG18__WATCHLO7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_1e0i(dmfc0_watchlo, arg, sel);
            register_name = "WatchLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_19:
        switch (sel) {
        case CP0_REG19__WATCHHI0:
        case CP0_REG19__WATCHHI1:
        case CP0_REG19__WATCHHI2:
        case CP0_REG19__WATCHHI3:
        case CP0_REG19__WATCHHI4:
        case CP0_REG19__WATCHHI5:
        case CP0_REG19__WATCHHI6:
        case CP0_REG19__WATCHHI7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_1e0i(dmfc0_watchhi, arg, sel);
            register_name = "WatchHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_20:
        switch (sel) {
        case CP0_REG20__XCONTEXT:
            check_insn(ctx, ISA_MIPS3);
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_XContext));
            register_name = "XContext";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_21:
        /* Officially reserved, but sel 0 is used for R1x000 framemask */
        CP0_CHECK(!(ctx->insn_flags & ISA_MIPS_R6));
        switch (sel) {
        case 0:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Framemask));
            register_name = "Framemask";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_22:
        tcg_gen_movi_tl(arg, 0); /* unimplemented */
        register_name = "'Diagnostic"; /* implementation dependent */
        break;
    case CP0_REGISTER_23:
        switch (sel) {
        case CP0_REG23__DEBUG:
            gen_helper_mfc0_debug(arg, tcg_env); /* EJTAG support */
            register_name = "Debug";
            break;
        case CP0_REG23__TRACECONTROL:
            /* PDtrace support */
            /* gen_helper_dmfc0_tracecontrol(arg, tcg_env);  */
            register_name = "TraceControl";
            goto cp0_unimplemented;
        case CP0_REG23__TRACECONTROL2:
            /* PDtrace support */
            /* gen_helper_dmfc0_tracecontrol2(arg, tcg_env); */
            register_name = "TraceControl2";
            goto cp0_unimplemented;
        case CP0_REG23__USERTRACEDATA1:
            /* PDtrace support */
            /* gen_helper_dmfc0_usertracedata1(arg, tcg_env);*/
            register_name = "UserTraceData1";
            goto cp0_unimplemented;
        case CP0_REG23__TRACEIBPC:
            /* PDtrace support */
            /* gen_helper_dmfc0_traceibpc(arg, tcg_env);     */
            register_name = "TraceIBPC";
            goto cp0_unimplemented;
        case CP0_REG23__TRACEDBPC:
            /* PDtrace support */
            /* gen_helper_dmfc0_tracedbpc(arg, tcg_env);     */
            register_name = "TraceDBPC";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_24:
        switch (sel) {
        case CP0_REG24__DEPC:
            /* EJTAG support */
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_DEPC));
            register_name = "DEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_25:
        switch (sel) {
        case CP0_REG25__PERFCTL0:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_Performance0));
            register_name = "Performance0";
            break;
        case CP0_REG25__PERFCNT0:
            /* gen_helper_dmfc0_performance1(arg); */
            register_name = "Performance1";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL1:
            /* gen_helper_dmfc0_performance2(arg); */
            register_name = "Performance2";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT1:
            /* gen_helper_dmfc0_performance3(arg); */
            register_name = "Performance3";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL2:
            /* gen_helper_dmfc0_performance4(arg); */
            register_name = "Performance4";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT2:
            /* gen_helper_dmfc0_performance5(arg); */
            register_name = "Performance5";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL3:
            /* gen_helper_dmfc0_performance6(arg); */
            register_name = "Performance6";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT3:
            /* gen_helper_dmfc0_performance7(arg); */
            register_name = "Performance7";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_26:
        switch (sel) {
        case CP0_REG26__ERRCTL:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_ErrCtl));
            register_name = "ErrCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_27:
        switch (sel) {
        /* ignored */
        case CP0_REG27__CACHERR:
            tcg_gen_movi_tl(arg, 0); /* unimplemented */
            register_name = "CacheErr";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_28:
        switch (sel) {
        case CP0_REG28__TAGLO:
        case CP0_REG28__TAGLO1:
        case CP0_REG28__TAGLO2:
        case CP0_REG28__TAGLO3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_TagLo));
            register_name = "TagLo";
            break;
        case CP0_REG28__DATALO:
        case CP0_REG28__DATALO1:
        case CP0_REG28__DATALO2:
        case CP0_REG28__DATALO3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_DataLo));
            register_name = "DataLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_29:
        switch (sel) {
        case CP0_REG29__TAGHI:
        case CP0_REG29__TAGHI1:
        case CP0_REG29__TAGHI2:
        case CP0_REG29__TAGHI3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_TagHi));
            register_name = "TagHi";
            break;
        case CP0_REG29__DATAHI:
        case CP0_REG29__DATAHI1:
        case CP0_REG29__DATAHI2:
        case CP0_REG29__DATAHI3:
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_DataHi));
            register_name = "DataHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_30:
        switch (sel) {
        case CP0_REG30__ERROREPC:
            tcg_gen_ld_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_ErrorEPC));
            register_name = "ErrorEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_31:
        switch (sel) {
        case CP0_REG31__DESAVE:
            /* EJTAG support */
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_DESAVE));
            register_name = "DESAVE";
            break;
        case CP0_REG31__KSCRATCH1:
        case CP0_REG31__KSCRATCH2:
        case CP0_REG31__KSCRATCH3:
        case CP0_REG31__KSCRATCH4:
        case CP0_REG31__KSCRATCH5:
        case CP0_REG31__KSCRATCH6:
            CP0_CHECK(ctx->kscrexist & (1 << sel));
            tcg_gen_ld_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_KScratch[sel - 2]));
            register_name = "KScratch";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    default:
        goto cp0_unimplemented;
    }
    trace_mips_translate_c0("dmfc0", register_name, reg, sel);
    return;

cp0_unimplemented:
    qemu_log_mask(LOG_UNIMP, "dmfc0 %s (reg %d sel %d)\n",
                  register_name, reg, sel);
    gen_mfc0_unimplemented(ctx, arg);
}

static void gen_dmtc0(DisasContext *ctx, TCGv arg, int reg, int sel)
{
    const char *register_name = "invalid";
    bool icount;

    if (sel != 0) {
        check_insn(ctx, ISA_MIPS_R1);
    }

    icount = translator_io_start(&ctx->base);

    switch (reg) {
    case CP0_REGISTER_00:
        switch (sel) {
        case CP0_REG00__INDEX:
            gen_helper_mtc0_index(tcg_env, arg);
            register_name = "Index";
            break;
        case CP0_REG00__MVPCONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_mvpcontrol(tcg_env, arg);
            register_name = "MVPControl";
            break;
        case CP0_REG00__MVPCONF0:
            CP0_CHECK(disas_mt_available(ctx));
            /* ignored */
            register_name = "MVPConf0";
            break;
        case CP0_REG00__MVPCONF1:
            CP0_CHECK(disas_mt_available(ctx));
            /* ignored */
            register_name = "MVPConf1";
            break;
        case CP0_REG00__VPCONTROL:
            CP0_CHECK(ctx->vp);
            /* ignored */
            register_name = "VPControl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_01:
        switch (sel) {
        case CP0_REG01__RANDOM:
            /* ignored */
            register_name = "Random";
            break;
        case CP0_REG01__VPECONTROL:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpecontrol(tcg_env, arg);
            register_name = "VPEControl";
            break;
        case CP0_REG01__VPECONF0:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpeconf0(tcg_env, arg);
            register_name = "VPEConf0";
            break;
        case CP0_REG01__VPECONF1:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpeconf1(tcg_env, arg);
            register_name = "VPEConf1";
            break;
        case CP0_REG01__YQMASK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_yqmask(tcg_env, arg);
            register_name = "YQMask";
            break;
        case CP0_REG01__VPESCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_VPESchedule));
            register_name = "VPESchedule";
            break;
        case CP0_REG01__VPESCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_VPEScheFBack));
            register_name = "VPEScheFBack";
            break;
        case CP0_REG01__VPEOPT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_vpeopt(tcg_env, arg);
            register_name = "VPEOpt";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_02:
        switch (sel) {
        case CP0_REG02__ENTRYLO0:
            gen_helper_dmtc0_entrylo0(tcg_env, arg);
            register_name = "EntryLo0";
            break;
        case CP0_REG02__TCSTATUS:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcstatus(tcg_env, arg);
            register_name = "TCStatus";
            break;
        case CP0_REG02__TCBIND:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcbind(tcg_env, arg);
            register_name = "TCBind";
            break;
        case CP0_REG02__TCRESTART:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcrestart(tcg_env, arg);
            register_name = "TCRestart";
            break;
        case CP0_REG02__TCHALT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tchalt(tcg_env, arg);
            register_name = "TCHalt";
            break;
        case CP0_REG02__TCCONTEXT:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tccontext(tcg_env, arg);
            register_name = "TCContext";
            break;
        case CP0_REG02__TCSCHEDULE:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcschedule(tcg_env, arg);
            register_name = "TCSchedule";
            break;
        case CP0_REG02__TCSCHEFBACK:
            CP0_CHECK(disas_mt_available(ctx));
            gen_helper_mtc0_tcschefback(tcg_env, arg);
            register_name = "TCScheFBack";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_03:
        switch (sel) {
        case CP0_REG03__ENTRYLO1:
            gen_helper_dmtc0_entrylo1(tcg_env, arg);
            register_name = "EntryLo1";
            break;
        case CP0_REG03__GLOBALNUM:
            CP0_CHECK(ctx->vp);
            /* ignored */
            register_name = "GlobalNumber";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_04:
        switch (sel) {
        case CP0_REG04__CONTEXT:
            gen_helper_mtc0_context(tcg_env, arg);
            register_name = "Context";
            break;
        case CP0_REG04__CONTEXTCONFIG:
            /* SmartMIPS ASE */
            /* gen_helper_dmtc0_contextconfig(arg); */
            register_name = "ContextConfig";
            goto cp0_unimplemented;
        case CP0_REG04__USERLOCAL:
            CP0_CHECK(ctx->ulri);
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
            register_name = "UserLocal";
            break;
        case CP0_REG04__MMID:
            CP0_CHECK(ctx->mi);
            gen_mfc0_load32(arg, offsetof(CPUMIPSState, CP0_MemoryMapID));
            register_name = "MMID";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_05:
        switch (sel) {
        case CP0_REG05__PAGEMASK:
            gen_helper_mtc0_pagemask(tcg_env, arg);
            register_name = "PageMask";
            break;
        case CP0_REG05__PAGEGRAIN:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_pagegrain(tcg_env, arg);
            register_name = "PageGrain";
            break;
        case CP0_REG05__SEGCTL0:
            CP0_CHECK(ctx->sc);
            gen_helper_mtc0_segctl0(tcg_env, arg);
            register_name = "SegCtl0";
            break;
        case CP0_REG05__SEGCTL1:
            CP0_CHECK(ctx->sc);
            gen_helper_mtc0_segctl1(tcg_env, arg);
            register_name = "SegCtl1";
            break;
        case CP0_REG05__SEGCTL2:
            CP0_CHECK(ctx->sc);
            gen_helper_mtc0_segctl2(tcg_env, arg);
            register_name = "SegCtl2";
            break;
        case CP0_REG05__PWBASE:
            check_pw(ctx);
            tcg_gen_st_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_PWBase));
            register_name = "PWBase";
            break;
        case CP0_REG05__PWFIELD:
            check_pw(ctx);
            gen_helper_mtc0_pwfield(tcg_env, arg);
            register_name = "PWField";
            break;
        case CP0_REG05__PWSIZE:
            check_pw(ctx);
            gen_helper_mtc0_pwsize(tcg_env, arg);
            register_name = "PWSize";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_06:
        switch (sel) {
        case CP0_REG06__WIRED:
            gen_helper_mtc0_wired(tcg_env, arg);
            register_name = "Wired";
            break;
        case CP0_REG06__SRSCONF0:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf0(tcg_env, arg);
            register_name = "SRSConf0";
            break;
        case CP0_REG06__SRSCONF1:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf1(tcg_env, arg);
            register_name = "SRSConf1";
            break;
        case CP0_REG06__SRSCONF2:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf2(tcg_env, arg);
            register_name = "SRSConf2";
            break;
        case CP0_REG06__SRSCONF3:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf3(tcg_env, arg);
            register_name = "SRSConf3";
            break;
        case CP0_REG06__SRSCONF4:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsconf4(tcg_env, arg);
            register_name = "SRSConf4";
            break;
        case CP0_REG06__PWCTL:
            check_pw(ctx);
            gen_helper_mtc0_pwctl(tcg_env, arg);
            register_name = "PWCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_07:
        switch (sel) {
        case CP0_REG07__HWRENA:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_hwrena(tcg_env, arg);
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "HWREna";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_08:
        switch (sel) {
        case CP0_REG08__BADVADDR:
            /* ignored */
            register_name = "BadVAddr";
            break;
        case CP0_REG08__BADINSTR:
            /* ignored */
            register_name = "BadInstr";
            break;
        case CP0_REG08__BADINSTRP:
            /* ignored */
            register_name = "BadInstrP";
            break;
        case CP0_REG08__BADINSTRX:
            /* ignored */
            register_name = "BadInstrX";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_09:
        switch (sel) {
        case CP0_REG09__COUNT:
            gen_helper_mtc0_count(tcg_env, arg);
            register_name = "Count";
            break;
        default:
            goto cp0_unimplemented;
        }
        /* Stop translation as we may have switched the execution mode */
        ctx->base.is_jmp = DISAS_STOP;
        break;
    case CP0_REGISTER_10:
        switch (sel) {
        case CP0_REG10__ENTRYHI:
            gen_helper_mtc0_entryhi(tcg_env, arg);
            register_name = "EntryHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_11:
        switch (sel) {
        case CP0_REG11__COMPARE:
            gen_helper_mtc0_compare(tcg_env, arg);
            register_name = "Compare";
            break;
        /* 6,7 are implementation dependent */
        default:
            goto cp0_unimplemented;
        }
        /* Stop translation as we may have switched the execution mode */
        ctx->base.is_jmp = DISAS_STOP;
        break;
    case CP0_REGISTER_12:
        switch (sel) {
        case CP0_REG12__STATUS:
            save_cpu_state(ctx, 1);
            gen_helper_mtc0_status(tcg_env, arg);
            /* DISAS_STOP isn't good enough here, hflags may have changed. */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Status";
            break;
        case CP0_REG12__INTCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_intctl(tcg_env, arg);
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "IntCtl";
            break;
        case CP0_REG12__SRSCTL:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_srsctl(tcg_env, arg);
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "SRSCtl";
            break;
        case CP0_REG12__SRSMAP:
            check_insn(ctx, ISA_MIPS_R2);
            gen_mtc0_store32(arg, offsetof(CPUMIPSState, CP0_SRSMap));
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "SRSMap";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_13:
        switch (sel) {
        case CP0_REG13__CAUSE:
            save_cpu_state(ctx, 1);
            gen_helper_mtc0_cause(tcg_env, arg);
            /*
             * Stop translation as we may have triggered an interrupt.
             * DISAS_STOP isn't sufficient, we need to ensure we break out of
             * translated code to check for pending interrupts.
             */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Cause";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_14:
        switch (sel) {
        case CP0_REG14__EPC:
            tcg_gen_st_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_EPC));
            register_name = "EPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_15:
        switch (sel) {
        case CP0_REG15__PRID:
            /* ignored */
            register_name = "PRid";
            break;
        case CP0_REG15__EBASE:
            check_insn(ctx, ISA_MIPS_R2);
            gen_helper_mtc0_ebase(tcg_env, arg);
            register_name = "EBase";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_16:
        switch (sel) {
        case CP0_REG16__CONFIG:
            gen_helper_mtc0_config0(tcg_env, arg);
            register_name = "Config";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG16__CONFIG1:
            /* ignored, read only */
            register_name = "Config1";
            break;
        case CP0_REG16__CONFIG2:
            gen_helper_mtc0_config2(tcg_env, arg);
            register_name = "Config2";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG16__CONFIG3:
            gen_helper_mtc0_config3(tcg_env, arg);
            register_name = "Config3";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case CP0_REG16__CONFIG4:
            /* currently ignored */
            register_name = "Config4";
            break;
        case CP0_REG16__CONFIG5:
            gen_helper_mtc0_config5(tcg_env, arg);
            register_name = "Config5";
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        /* 6,7 are implementation dependent */
        default:
            register_name = "Invalid config selector";
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_17:
        switch (sel) {
        case CP0_REG17__LLADDR:
            gen_helper_mtc0_lladdr(tcg_env, arg);
            register_name = "LLAddr";
            break;
        case CP0_REG17__MAAR:
            CP0_CHECK(ctx->mrp);
            gen_helper_mtc0_maar(tcg_env, arg);
            register_name = "MAAR";
            break;
        case CP0_REG17__MAARI:
            CP0_CHECK(ctx->mrp);
            gen_helper_mtc0_maari(tcg_env, arg);
            register_name = "MAARI";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_18:
        switch (sel) {
        case CP0_REG18__WATCHLO0:
        case CP0_REG18__WATCHLO1:
        case CP0_REG18__WATCHLO2:
        case CP0_REG18__WATCHLO3:
        case CP0_REG18__WATCHLO4:
        case CP0_REG18__WATCHLO5:
        case CP0_REG18__WATCHLO6:
        case CP0_REG18__WATCHLO7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_0e1i(mtc0_watchlo, arg, sel);
            register_name = "WatchLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_19:
        switch (sel) {
        case CP0_REG19__WATCHHI0:
        case CP0_REG19__WATCHHI1:
        case CP0_REG19__WATCHHI2:
        case CP0_REG19__WATCHHI3:
        case CP0_REG19__WATCHHI4:
        case CP0_REG19__WATCHHI5:
        case CP0_REG19__WATCHHI6:
        case CP0_REG19__WATCHHI7:
            CP0_CHECK(ctx->CP0_Config1 & (1 << CP0C1_WR));
            gen_helper_0e1i(mtc0_watchhi, arg, sel);
            register_name = "WatchHi";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_20:
        switch (sel) {
        case CP0_REG20__XCONTEXT:
            check_insn(ctx, ISA_MIPS3);
            gen_helper_mtc0_xcontext(tcg_env, arg);
            register_name = "XContext";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_21:
       /* Officially reserved, but sel 0 is used for R1x000 framemask */
        CP0_CHECK(!(ctx->insn_flags & ISA_MIPS_R6));
        switch (sel) {
        case 0:
            gen_helper_mtc0_framemask(tcg_env, arg);
            register_name = "Framemask";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_22:
        /* ignored */
        register_name = "Diagnostic"; /* implementation dependent */
        break;
    case CP0_REGISTER_23:
        switch (sel) {
        case CP0_REG23__DEBUG:
            gen_helper_mtc0_debug(tcg_env, arg); /* EJTAG support */
            /* DISAS_STOP isn't good enough here, hflags may have changed. */
            gen_save_pc(ctx->base.pc_next + 4);
            ctx->base.is_jmp = DISAS_EXIT;
            register_name = "Debug";
            break;
        case CP0_REG23__TRACECONTROL:
            /* PDtrace support */
            /* gen_helper_mtc0_tracecontrol(tcg_env, arg);  */
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "TraceControl";
            goto cp0_unimplemented;
        case CP0_REG23__TRACECONTROL2:
            /* PDtrace support */
            /* gen_helper_mtc0_tracecontrol2(tcg_env, arg); */
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "TraceControl2";
            goto cp0_unimplemented;
        case CP0_REG23__USERTRACEDATA1:
            /* PDtrace support */
            /* gen_helper_mtc0_usertracedata1(tcg_env, arg);*/
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "UserTraceData1";
            goto cp0_unimplemented;
        case CP0_REG23__TRACEIBPC:
            /* PDtrace support */
            /* gen_helper_mtc0_traceibpc(tcg_env, arg);     */
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "TraceIBPC";
            goto cp0_unimplemented;
        case CP0_REG23__TRACEDBPC:
            /* PDtrace support */
            /* gen_helper_mtc0_tracedbpc(tcg_env, arg);     */
            /* Stop translation as we may have switched the execution mode */
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "TraceDBPC";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_24:
        switch (sel) {
        case CP0_REG24__DEPC:
            /* EJTAG support */
            tcg_gen_st_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_DEPC));
            register_name = "DEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_25:
        switch (sel) {
        case CP0_REG25__PERFCTL0:
            gen_helper_mtc0_performance0(tcg_env, arg);
            register_name = "Performance0";
            break;
        case CP0_REG25__PERFCNT0:
            /* gen_helper_mtc0_performance1(tcg_env, arg); */
            register_name = "Performance1";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL1:
            /* gen_helper_mtc0_performance2(tcg_env, arg); */
            register_name = "Performance2";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT1:
            /* gen_helper_mtc0_performance3(tcg_env, arg); */
            register_name = "Performance3";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL2:
            /* gen_helper_mtc0_performance4(tcg_env, arg); */
            register_name = "Performance4";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT2:
            /* gen_helper_mtc0_performance5(tcg_env, arg); */
            register_name = "Performance5";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCTL3:
            /* gen_helper_mtc0_performance6(tcg_env, arg); */
            register_name = "Performance6";
            goto cp0_unimplemented;
        case CP0_REG25__PERFCNT3:
            /* gen_helper_mtc0_performance7(tcg_env, arg); */
            register_name = "Performance7";
            goto cp0_unimplemented;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_26:
        switch (sel) {
        case CP0_REG26__ERRCTL:
            gen_helper_mtc0_errctl(tcg_env, arg);
            ctx->base.is_jmp = DISAS_STOP;
            register_name = "ErrCtl";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_27:
        switch (sel) {
        case CP0_REG27__CACHERR:
            /* ignored */
            register_name = "CacheErr";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_28:
        switch (sel) {
        case CP0_REG28__TAGLO:
        case CP0_REG28__TAGLO1:
        case CP0_REG28__TAGLO2:
        case CP0_REG28__TAGLO3:
            gen_helper_mtc0_taglo(tcg_env, arg);
            register_name = "TagLo";
            break;
        case CP0_REG28__DATALO:
        case CP0_REG28__DATALO1:
        case CP0_REG28__DATALO2:
        case CP0_REG28__DATALO3:
            gen_helper_mtc0_datalo(tcg_env, arg);
            register_name = "DataLo";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_29:
        switch (sel) {
        case CP0_REG29__TAGHI:
        case CP0_REG29__TAGHI1:
        case CP0_REG29__TAGHI2:
        case CP0_REG29__TAGHI3:
            gen_helper_mtc0_taghi(tcg_env, arg);
            register_name = "TagHi";
            break;
        case CP0_REG29__DATAHI:
        case CP0_REG29__DATAHI1:
        case CP0_REG29__DATAHI2:
        case CP0_REG29__DATAHI3:
            gen_helper_mtc0_datahi(tcg_env, arg);
            register_name = "DataHi";
            break;
        default:
            register_name = "invalid sel";
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_30:
        switch (sel) {
        case CP0_REG30__ERROREPC:
            tcg_gen_st_tl(arg, tcg_env, offsetof(CPUMIPSState, CP0_ErrorEPC));
            register_name = "ErrorEPC";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    case CP0_REGISTER_31:
        switch (sel) {
        case CP0_REG31__DESAVE:
            /* EJTAG support */
            gen_mtc0_store32(arg, offsetof(CPUMIPSState, CP0_DESAVE));
            register_name = "DESAVE";
            break;
        case CP0_REG31__KSCRATCH1:
        case CP0_REG31__KSCRATCH2:
        case CP0_REG31__KSCRATCH3:
        case CP0_REG31__KSCRATCH4:
        case CP0_REG31__KSCRATCH5:
        case CP0_REG31__KSCRATCH6:
            CP0_CHECK(ctx->kscrexist & (1 << sel));
            tcg_gen_st_tl(arg, tcg_env,
                          offsetof(CPUMIPSState, CP0_KScratch[sel - 2]));
            register_name = "KScratch";
            break;
        default:
            goto cp0_unimplemented;
        }
        break;
    default:
        goto cp0_unimplemented;
    }
    trace_mips_translate_c0("dmtc0", register_name, reg, sel);

    /* For simplicity assume that all writes can cause interrupts.  */
    if (icount) {
        /*
         * DISAS_STOP isn't sufficient, we need to ensure we break out of
         * translated code to check for pending interrupts.
         */
        gen_save_pc(ctx->base.pc_next + 4);
        ctx->base.is_jmp = DISAS_EXIT;
    }
    return;

cp0_unimplemented:
    qemu_log_mask(LOG_UNIMP, "dmtc0 %s (reg %d sel %d)\n",
                  register_name, reg, sel);
}
#endif /* TARGET_MIPS64 */

static void gen_mftr(CPUMIPSState *env, DisasContext *ctx, int rt, int rd,
                     int u, int sel, int h)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    TCGv t0 = tcg_temp_new();

    if ((env->CP0_VPEConf0 & (1 << CP0VPEC0_MVP)) == 0 &&
        ((env->tcs[other_tc].CP0_TCBind & (0xf << CP0TCBd_CurVPE)) !=
         (env->active_tc.CP0_TCBind & (0xf << CP0TCBd_CurVPE)))) {
        tcg_gen_movi_tl(t0, -1);
    } else if ((env->CP0_VPEControl & (0xff << CP0VPECo_TargTC)) >
               (env->mvp->CP0_MVPConf0 & (0xff << CP0MVPC0_PTC))) {
        tcg_gen_movi_tl(t0, -1);
    } else if (u == 0) {
        switch (rt) {
        case 1:
            switch (sel) {
            case 1:
                gen_helper_mftc0_vpecontrol(t0, tcg_env);
                break;
            case 2:
                gen_helper_mftc0_vpeconf0(t0, tcg_env);
                break;
            default:
                goto die;
                break;
            }
            break;
        case 2:
            switch (sel) {
            case 1:
                gen_helper_mftc0_tcstatus(t0, tcg_env);
                break;
            case 2:
                gen_helper_mftc0_tcbind(t0, tcg_env);
                break;
            case 3:
                gen_helper_mftc0_tcrestart(t0, tcg_env);
                break;
            case 4:
                gen_helper_mftc0_tchalt(t0, tcg_env);
                break;
            case 5:
                gen_helper_mftc0_tccontext(t0, tcg_env);
                break;
            case 6:
                gen_helper_mftc0_tcschedule(t0, tcg_env);
                break;
            case 7:
                gen_helper_mftc0_tcschefback(t0, tcg_env);
                break;
            default:
                gen_mfc0(ctx, t0, rt, sel);
                break;
            }
            break;
        case 10:
            switch (sel) {
            case 0:
                gen_helper_mftc0_entryhi(t0, tcg_env);
                break;
            default:
                gen_mfc0(ctx, t0, rt, sel);
                break;
            }
            break;
        case 12:
            switch (sel) {
            case 0:
                gen_helper_mftc0_status(t0, tcg_env);
                break;
            default:
                gen_mfc0(ctx, t0, rt, sel);
                break;
            }
            break;
        case 13:
            switch (sel) {
            case 0:
                gen_helper_mftc0_cause(t0, tcg_env);
                break;
            default:
                goto die;
                break;
            }
            break;
        case 14:
            switch (sel) {
            case 0:
                gen_helper_mftc0_epc(t0, tcg_env);
                break;
            default:
                goto die;
                break;
            }
            break;
        case 15:
            switch (sel) {
            case 1:
                gen_helper_mftc0_ebase(t0, tcg_env);
                break;
            default:
                goto die;
                break;
            }
            break;
        case 16:
            switch (sel) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                gen_helper_mftc0_configx(t0, tcg_env, tcg_constant_tl(sel));
                break;
            default:
                goto die;
                break;
            }
            break;
        case 23:
            switch (sel) {
            case 0:
                gen_helper_mftc0_debug(t0, tcg_env);
                break;
            default:
                gen_mfc0(ctx, t0, rt, sel);
                break;
            }
            break;
        default:
            gen_mfc0(ctx, t0, rt, sel);
        }
    } else {
        switch (sel) {
        /* GPR registers. */
        case 0:
            gen_helper_1e0i(mftgpr, t0, rt);
            break;
        /* Auxiliary CPU registers */
        case 1:
            switch (rt) {
            case 0:
                gen_helper_1e0i(mftlo, t0, 0);
                break;
            case 1:
                gen_helper_1e0i(mfthi, t0, 0);
                break;
            case 2:
                gen_helper_1e0i(mftacx, t0, 0);
                break;
            case 4:
                gen_helper_1e0i(mftlo, t0, 1);
                break;
            case 5:
                gen_helper_1e0i(mfthi, t0, 1);
                break;
            case 6:
                gen_helper_1e0i(mftacx, t0, 1);
                break;
            case 8:
                gen_helper_1e0i(mftlo, t0, 2);
                break;
            case 9:
                gen_helper_1e0i(mfthi, t0, 2);
                break;
            case 10:
                gen_helper_1e0i(mftacx, t0, 2);
                break;
            case 12:
                gen_helper_1e0i(mftlo, t0, 3);
                break;
            case 13:
                gen_helper_1e0i(mfthi, t0, 3);
                break;
            case 14:
                gen_helper_1e0i(mftacx, t0, 3);
                break;
            case 16:
                gen_helper_mftdsp(t0, tcg_env);
                break;
            default:
                goto die;
            }
            break;
        /* Floating point (COP1). */
        case 2:
            /* XXX: For now we support only a single FPU context. */
            if (h == 0) {
                TCGv_i32 fp0 = tcg_temp_new_i32();

                gen_load_fpr32(ctx, fp0, rt);
                tcg_gen_ext_i32_tl(t0, fp0);
            } else {
                TCGv_i32 fp0 = tcg_temp_new_i32();

                gen_load_fpr32h(ctx, fp0, rt);
                tcg_gen_ext_i32_tl(t0, fp0);
            }
            break;
        case 3:
            /* XXX: For now we support only a single FPU context. */
            gen_helper_1e0i(cfc1, t0, rt);
            break;
        /* COP2: Not implemented. */
        case 4:
        case 5:
            /* fall through */
        default:
            goto die;
        }
    }
    trace_mips_translate_tr("mftr", rt, u, sel, h);
    gen_store_gpr(t0, rd);
    return;

die:
    LOG_DISAS("mftr (reg %d u %d sel %d h %d)\n", rt, u, sel, h);
    gen_reserved_instruction(ctx);
}

static void gen_mttr(CPUMIPSState *env, DisasContext *ctx, int rd, int rt,
                     int u, int sel, int h)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    if ((env->CP0_VPEConf0 & (1 << CP0VPEC0_MVP)) == 0 &&
        ((env->tcs[other_tc].CP0_TCBind & (0xf << CP0TCBd_CurVPE)) !=
         (env->active_tc.CP0_TCBind & (0xf << CP0TCBd_CurVPE)))) {
        /* NOP */
        ;
    } else if ((env->CP0_VPEControl & (0xff << CP0VPECo_TargTC)) >
             (env->mvp->CP0_MVPConf0 & (0xff << CP0MVPC0_PTC))) {
        /* NOP */
        ;
    } else if (u == 0) {
        switch (rd) {
        case 1:
            switch (sel) {
            case 1:
                gen_helper_mttc0_vpecontrol(tcg_env, t0);
                break;
            case 2:
                gen_helper_mttc0_vpeconf0(tcg_env, t0);
                break;
            default:
                goto die;
                break;
            }
            break;
        case 2:
            switch (sel) {
            case 1:
                gen_helper_mttc0_tcstatus(tcg_env, t0);
                break;
            case 2:
                gen_helper_mttc0_tcbind(tcg_env, t0);
                break;
            case 3:
                gen_helper_mttc0_tcrestart(tcg_env, t0);
                break;
            case 4:
                gen_helper_mttc0_tchalt(tcg_env, t0);
                break;
            case 5:
                gen_helper_mttc0_tccontext(tcg_env, t0);
                break;
            case 6:
                gen_helper_mttc0_tcschedule(tcg_env, t0);
                break;
            case 7:
                gen_helper_mttc0_tcschefback(tcg_env, t0);
                break;
            default:
                gen_mtc0(ctx, t0, rd, sel);
                break;
            }
            break;
        case 10:
            switch (sel) {
            case 0:
                gen_helper_mttc0_entryhi(tcg_env, t0);
                break;
            default:
                gen_mtc0(ctx, t0, rd, sel);
                break;
            }
            break;
        case 12:
            switch (sel) {
            case 0:
                gen_helper_mttc0_status(tcg_env, t0);
                break;
            default:
                gen_mtc0(ctx, t0, rd, sel);
                break;
            }
            break;
        case 13:
            switch (sel) {
            case 0:
                gen_helper_mttc0_cause(tcg_env, t0);
                break;
            default:
                goto die;
                break;
            }
            break;
        case 15:
            switch (sel) {
            case 1:
                gen_helper_mttc0_ebase(tcg_env, t0);
                break;
            default:
                goto die;
                break;
            }
            break;
        case 23:
            switch (sel) {
            case 0:
                gen_helper_mttc0_debug(tcg_env, t0);
                break;
            default:
                gen_mtc0(ctx, t0, rd, sel);
                break;
            }
            break;
        default:
            gen_mtc0(ctx, t0, rd, sel);
        }
    } else {
        switch (sel) {
        /* GPR registers. */
        case 0:
            gen_helper_0e1i(mttgpr, t0, rd);
            break;
        /* Auxiliary CPU registers */
        case 1:
            switch (rd) {
            case 0:
                gen_helper_0e1i(mttlo, t0, 0);
                break;
            case 1:
                gen_helper_0e1i(mtthi, t0, 0);
                break;
            case 2:
                gen_helper_0e1i(mttacx, t0, 0);
                break;
            case 4:
                gen_helper_0e1i(mttlo, t0, 1);
                break;
            case 5:
                gen_helper_0e1i(mtthi, t0, 1);
                break;
            case 6:
                gen_helper_0e1i(mttacx, t0, 1);
                break;
            case 8:
                gen_helper_0e1i(mttlo, t0, 2);
                break;
            case 9:
                gen_helper_0e1i(mtthi, t0, 2);
                break;
            case 10:
                gen_helper_0e1i(mttacx, t0, 2);
                break;
            case 12:
                gen_helper_0e1i(mttlo, t0, 3);
                break;
            case 13:
                gen_helper_0e1i(mtthi, t0, 3);
                break;
            case 14:
                gen_helper_0e1i(mttacx, t0, 3);
                break;
            case 16:
                gen_helper_mttdsp(tcg_env, t0);
                break;
            default:
                goto die;
            }
            break;
        /* Floating point (COP1). */
        case 2:
            /* XXX: For now we support only a single FPU context. */
            if (h == 0) {
                TCGv_i32 fp0 = tcg_temp_new_i32();

                tcg_gen_trunc_tl_i32(fp0, t0);
                gen_store_fpr32(ctx, fp0, rd);
            } else {
                TCGv_i32 fp0 = tcg_temp_new_i32();

                tcg_gen_trunc_tl_i32(fp0, t0);
                gen_store_fpr32h(ctx, fp0, rd);
            }
            break;
        case 3:
            /* XXX: For now we support only a single FPU context. */
            gen_helper_0e2i(ctc1, t0, tcg_constant_i32(rd), rt);
            /* Stop translation as we may have changed hflags */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        /* COP2: Not implemented. */
        case 4:
        case 5:
            /* fall through */
        default:
            goto die;
        }
    }
    trace_mips_translate_tr("mttr", rd, u, sel, h);
    return;

die:
    LOG_DISAS("mttr (reg %d u %d sel %d h %d)\n", rd, u, sel, h);
    gen_reserved_instruction(ctx);
}

static void gen_cp0(CPUMIPSState *env, DisasContext *ctx, uint32_t opc,
                    int rt, int rd)
{
    const char *opn = "ldst";

    check_cp0_enabled(ctx);
    switch (opc) {
    case OPC_MFC0:
        mips_ident(ctx,
            opc == OPC_MFC0 ? MIPS_ID_OPC_MFC0 :
            MIPS_ID_NONE);
        if (rt == 0) {
            /* Treat as NOP. */
            return;
        }
        gen_mfc0(ctx, cpu_gpr[rt], rd, ctx->opcode & 0x7);
        opn = "mfc0";
        break;
    case OPC_MTC0:
        mips_ident(ctx,
            opc == OPC_MTC0 ? MIPS_ID_OPC_MTC0 :
            MIPS_ID_NONE);
        {
            TCGv t0 = tcg_temp_new();

            gen_load_gpr(t0, rt);
            gen_mtc0(ctx, t0, rd, ctx->opcode & 0x7);
        }
        opn = "mtc0";
        break;
#if defined(TARGET_MIPS64)
    case OPC_DMFC0:
        mips_ident(ctx,
            opc == OPC_DMFC0 ? MIPS_ID_OPC_DMFC0 :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        if (rt == 0) {
            /* Treat as NOP. */
            return;
        }
        gen_dmfc0(ctx, cpu_gpr[rt], rd, ctx->opcode & 0x7);
        opn = "dmfc0";
        break;
    case OPC_DMTC0:
        mips_ident(ctx,
            opc == OPC_DMTC0 ? MIPS_ID_OPC_DMTC0 :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        {
            TCGv t0 = tcg_temp_new();

            gen_load_gpr(t0, rt);
            gen_dmtc0(ctx, t0, rd, ctx->opcode & 0x7);
        }
        opn = "dmtc0";
        break;
#endif
    case OPC_MFHC0:
        mips_ident(ctx,
            opc == OPC_MFHC0 ? MIPS_ID_OPC_MFHC0 :
            MIPS_ID_NONE);
        check_mvh(ctx);
        if (rt == 0) {
            /* Treat as NOP. */
            return;
        }
        gen_mfhc0(ctx, cpu_gpr[rt], rd, ctx->opcode & 0x7);
        opn = "mfhc0";
        break;
    case OPC_MTHC0:
        mips_ident(ctx,
            opc == OPC_MTHC0 ? MIPS_ID_OPC_MTHC0 :
            MIPS_ID_NONE);
        check_mvh(ctx);
        {
            TCGv t0 = tcg_temp_new();
            gen_load_gpr(t0, rt);
            gen_mthc0(ctx, t0, rd, ctx->opcode & 0x7);
        }
        opn = "mthc0";
        break;
    case OPC_MFTR:
        mips_ident(ctx,
            opc == OPC_MFTR ? MIPS_ID_OPC_MFTR :
            MIPS_ID_NONE);
        check_cp0_enabled(ctx);
        if (rd == 0) {
            /* Treat as NOP. */
            return;
        }
        gen_mftr(env, ctx, rt, rd, (ctx->opcode >> 5) & 1,
                 ctx->opcode & 0x7, (ctx->opcode >> 4) & 1);
        opn = "mftr";
        break;
    case OPC_MTTR:
        mips_ident(ctx,
            opc == OPC_MTTR ? MIPS_ID_OPC_MTTR :
            MIPS_ID_NONE);
        check_cp0_enabled(ctx);
        gen_mttr(env, ctx, rd, rt, (ctx->opcode >> 5) & 1,
                 ctx->opcode & 0x7, (ctx->opcode >> 4) & 1);
        opn = "mttr";
        break;
    case OPC_TLBWI:
        mips_ident(ctx,
            opc == OPC_TLBWI ? MIPS_ID_OPC_TLBWI :
            MIPS_ID_NONE);
        opn = "tlbwi";
        if (!env->tlb->helper_tlbwi) {
            goto die;
        }
        gen_helper_tlbwi(tcg_env);
        break;
    case OPC_TLBINV:
        mips_ident(ctx,
            opc == OPC_TLBINV ? MIPS_ID_OPC_TLBINV :
            MIPS_ID_NONE);
        opn = "tlbinv";
        if (ctx->ie >= 2) {
            if (!env->tlb->helper_tlbinv) {
                goto die;
            }
            gen_helper_tlbinv(tcg_env);
        } /* treat as nop if TLBINV not supported */
        break;
    case OPC_TLBINVF:
        mips_ident(ctx,
            opc == OPC_TLBINVF ? MIPS_ID_OPC_TLBINVF :
            MIPS_ID_NONE);
        opn = "tlbinvf";
        if (ctx->ie >= 2) {
            if (!env->tlb->helper_tlbinvf) {
                goto die;
            }
            gen_helper_tlbinvf(tcg_env);
        } /* treat as nop if TLBINV not supported */
        break;
    case OPC_TLBWR:
        mips_ident(ctx,
            opc == OPC_TLBWR ? MIPS_ID_OPC_TLBWR :
            MIPS_ID_NONE);
        opn = "tlbwr";
        if (!env->tlb->helper_tlbwr) {
            goto die;
        }
        gen_helper_tlbwr(tcg_env);
        break;
    case OPC_TLBP:
        mips_ident(ctx,
            opc == OPC_TLBP ? MIPS_ID_OPC_TLBP :
            MIPS_ID_NONE);
        opn = "tlbp";
        if (!env->tlb->helper_tlbp) {
            goto die;
        }
        gen_helper_tlbp(tcg_env);
        break;
    case OPC_TLBR:
        mips_ident(ctx,
            opc == OPC_TLBR ? MIPS_ID_OPC_TLBR :
            MIPS_ID_NONE);
        opn = "tlbr";
        if (!env->tlb->helper_tlbr) {
            goto die;
        }
        gen_helper_tlbr(tcg_env);
        break;
    case OPC_ERET: /* OPC_ERETNC */
        mips_ident(ctx,
            opc == OPC_ERET ? MIPS_ID_OPC_ERET :
            MIPS_ID_NONE);
        if ((ctx->insn_flags & ISA_MIPS_R6) &&
            (ctx->hflags & MIPS_HFLAG_BMASK)) {
            goto die;
        } else {
            int bit_shift = (ctx->hflags & MIPS_HFLAG_M16) ? 16 : 6;
            if (ctx->opcode & (1 << bit_shift)) {
                /* OPC_ERETNC */
                opn = "eretnc";
                check_insn(ctx, ISA_MIPS_R5);
                gen_helper_eretnc(tcg_env);
            } else {
                /* OPC_ERET */
                opn = "eret";
                check_insn(ctx, ISA_MIPS2);
                gen_helper_eret(tcg_env);
            }
            ctx->base.is_jmp = DISAS_EXIT;
        }
        break;
    case OPC_DERET:
        mips_ident(ctx,
            opc == OPC_DERET ? MIPS_ID_OPC_DERET :
            MIPS_ID_NONE);
        opn = "deret";
        check_insn(ctx, ISA_MIPS_R1);
        if ((ctx->insn_flags & ISA_MIPS_R6) &&
            (ctx->hflags & MIPS_HFLAG_BMASK)) {
            goto die;
        }
        if (!(ctx->hflags & MIPS_HFLAG_DM)) {
            MIPS_INVAL(opn);
            gen_reserved_instruction(ctx);
        } else {
            gen_helper_deret(tcg_env);
            ctx->base.is_jmp = DISAS_EXIT;
        }
        break;
    case OPC_WAIT:
        mips_ident(ctx,
            opc == OPC_WAIT ? MIPS_ID_OPC_WAIT :
            MIPS_ID_NONE);
        opn = "wait";
        check_insn(ctx, ISA_MIPS3 | ISA_MIPS_R1);
        if ((ctx->insn_flags & ISA_MIPS_R6) &&
            (ctx->hflags & MIPS_HFLAG_BMASK)) {
            goto die;
        }
        /* If we get an exception, we want to restart at next instruction */
        ctx->base.pc_next += 4;
        save_cpu_state(ctx, 1);
        ctx->base.pc_next -= 4;
        gen_helper_wait(tcg_env);
        ctx->base.is_jmp = DISAS_NORETURN;
        break;
    default:
 die:
        MIPS_INVAL(opn);
        gen_reserved_instruction(ctx);
        return;
    }
    (void)opn; /* avoid a compiler warning */
}
#endif /* !CONFIG_USER_ONLY */

/* CP1 Branches (before delay slot) */
/*
 * The CONDITION-CODE BIT the branch tests, stated by name.
 *
 * QEMU holds the eight FP condition codes as bits of one global, fpu_fcr31,
 * so `bc1t $fcc1, target` lowers to a shift of THE WHOLE REGISTER and the op
 * walk can say only that fcr31 was read.  The wire's word for that is
 * REG_FCSR, while what the instruction reads is FCC1 -- REG_PRED1 -- and
 * under the composed-register contract (#277) a stated CONTAINER justifies a
 * published MEMBER in the census and supplies nothing to the wire.
 *
 * The member is not unknown: `cc` is the encoding's own condition-code
 * field and this function has it.  Saying so is what R7.3 asks -- a register
 * the encoding names is not the emulator's to drop -- and each note sits
 * beside the shift that performs that bit's read, so an `any2`/`any4` form
 * states the two or four codes it really tests rather than a single one
 * standing in for all of them.
 */
static void gen_note_fcc_read(int cc)
{
    static const char *const fcc_names[8] = {
        "fcc0", "fcc1", "fcc2", "fcc3", "fcc4", "fcc5", "fcc6", "fcc7"
    };

    insn_dataflow_note_stated_read_name(fcc_names[cc & 7]);
}

static void gen_compute_branch1(DisasContext *ctx, uint32_t op,
                                int32_t cc, int32_t offset)
{
    target_ulong btarget;
    TCGv_i32 t0 = tcg_temp_new_i32();

    if ((ctx->insn_flags & ISA_MIPS_R6) && (ctx->hflags & MIPS_HFLAG_BMASK)) {
        gen_reserved_instruction(ctx);
        return;
    }

    if (cc != 0) {
        check_insn(ctx, ISA_MIPS4 | ISA_MIPS_R1);
    }

    btarget = ctx->base.pc_next + 4 + offset;

    switch (op) {
    case OPC_BC1F:
        mips_ident(ctx,
            op == OPC_BC1F ? MIPS_ID_OPC_BC1F :
            MIPS_ID_NONE);
        gen_note_fcc_read(cc);
        tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
        tcg_gen_not_i32(t0, t0);
        tcg_gen_andi_i32(t0, t0, 1);
        tcg_gen_extu_i32_tl(bcond, t0);
        goto not_likely;
    case OPC_BC1FL:
        mips_ident(ctx,
            op == OPC_BC1FL ? MIPS_ID_OPC_BC1FL :
            MIPS_ID_NONE);
        gen_note_fcc_read(cc);
        tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
        tcg_gen_not_i32(t0, t0);
        tcg_gen_andi_i32(t0, t0, 1);
        tcg_gen_extu_i32_tl(bcond, t0);
        goto likely;
    case OPC_BC1T:
        mips_ident(ctx,
            op == OPC_BC1T ? MIPS_ID_OPC_BC1T :
            MIPS_ID_NONE);
        gen_note_fcc_read(cc);
        tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
        tcg_gen_andi_i32(t0, t0, 1);
        tcg_gen_extu_i32_tl(bcond, t0);
        goto not_likely;
    case OPC_BC1TL:
        mips_ident(ctx,
            op == OPC_BC1TL ? MIPS_ID_OPC_BC1TL :
            MIPS_ID_NONE);
        gen_note_fcc_read(cc);
        tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
        tcg_gen_andi_i32(t0, t0, 1);
        tcg_gen_extu_i32_tl(bcond, t0);
    likely:
        ctx->hflags |= MIPS_HFLAG_BL;
        break;
    case OPC_BC1FANY2:
        mips_ident(ctx,
            op == OPC_BC1FANY2 ? MIPS_ID_OPC_BC1FANY2 :
            MIPS_ID_NONE);
        {
            TCGv_i32 t1 = tcg_temp_new_i32();
            gen_note_fcc_read(cc);
            tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
            gen_note_fcc_read(cc + 1);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 1));
            tcg_gen_nand_i32(t0, t0, t1);
            tcg_gen_andi_i32(t0, t0, 1);
            tcg_gen_extu_i32_tl(bcond, t0);
        }
        goto not_likely;
    case OPC_BC1TANY2:
        mips_ident(ctx,
            op == OPC_BC1TANY2 ? MIPS_ID_OPC_BC1TANY2 :
            MIPS_ID_NONE);
        {
            TCGv_i32 t1 = tcg_temp_new_i32();
            gen_note_fcc_read(cc);
            tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
            gen_note_fcc_read(cc + 1);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 1));
            tcg_gen_or_i32(t0, t0, t1);
            tcg_gen_andi_i32(t0, t0, 1);
            tcg_gen_extu_i32_tl(bcond, t0);
        }
        goto not_likely;
    case OPC_BC1FANY4:
        mips_ident(ctx,
            op == OPC_BC1FANY4 ? MIPS_ID_OPC_BC1FANY4 :
            MIPS_ID_NONE);
        {
            TCGv_i32 t1 = tcg_temp_new_i32();
            gen_note_fcc_read(cc);
            tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
            gen_note_fcc_read(cc + 1);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 1));
            tcg_gen_and_i32(t0, t0, t1);
            gen_note_fcc_read(cc + 2);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 2));
            tcg_gen_and_i32(t0, t0, t1);
            gen_note_fcc_read(cc + 3);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 3));
            tcg_gen_nand_i32(t0, t0, t1);
            tcg_gen_andi_i32(t0, t0, 1);
            tcg_gen_extu_i32_tl(bcond, t0);
        }
        goto not_likely;
    case OPC_BC1TANY4:
        mips_ident(ctx,
            op == OPC_BC1TANY4 ? MIPS_ID_OPC_BC1TANY4 :
            MIPS_ID_NONE);
        {
            TCGv_i32 t1 = tcg_temp_new_i32();
            gen_note_fcc_read(cc);
            tcg_gen_shri_i32(t0, fpu_fcr31, get_fp_bit(cc));
            gen_note_fcc_read(cc + 1);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 1));
            tcg_gen_or_i32(t0, t0, t1);
            gen_note_fcc_read(cc + 2);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 2));
            tcg_gen_or_i32(t0, t0, t1);
            gen_note_fcc_read(cc + 3);
            tcg_gen_shri_i32(t1, fpu_fcr31, get_fp_bit(cc + 3));
            tcg_gen_or_i32(t0, t0, t1);
            tcg_gen_andi_i32(t0, t0, 1);
            tcg_gen_extu_i32_tl(bcond, t0);
        }
    not_likely:
        ctx->hflags |= MIPS_HFLAG_BC;
        break;
    default:
        MIPS_INVAL("cp1 cond branch");
        gen_reserved_instruction(ctx);
        return;
    }
    ctx->btarget = btarget;
    plugin_gen_record_branch_target((uint64_t)btarget);
    ctx->hflags |= MIPS_HFLAG_BDS32;
}

/* R6 CP1 Branches */
static void gen_compute_branch1_r6(DisasContext *ctx, uint32_t op,
                                   int32_t ft, int32_t offset,
                                   int delayslot_size)
{
    target_ulong btarget;
    TCGv_i64 t0 = tcg_temp_new_i64();

    if (ctx->hflags & MIPS_HFLAG_BMASK) {
#ifdef MIPS_DEBUG_DISAS
        LOG_DISAS("Branch in delay / forbidden slot at PC 0x%016"
                  VADDR_PRIx "\n", ctx->base.pc_next);
#endif
        gen_reserved_instruction(ctx);
        return;
    }

    gen_load_fpr64(ctx, t0, ft);
    tcg_gen_andi_i64(t0, t0, 1);

    btarget = addr_add(ctx, ctx->base.pc_next + 4, offset);

    switch (op) {
    case OPC_BC1EQZ:
        mips_ident(ctx,
            op == OPC_BC1EQZ ? MIPS_ID_OPC_BC1EQZ :
            MIPS_ID_NONE);
        tcg_gen_xori_i64(t0, t0, 1);
        ctx->hflags |= MIPS_HFLAG_BC;
        break;
    case OPC_BC1NEZ:
        mips_ident(ctx,
            op == OPC_BC1NEZ ? MIPS_ID_OPC_BC1NEZ :
            MIPS_ID_NONE);
        /* t0 already set */
        ctx->hflags |= MIPS_HFLAG_BC;
        break;
    default:
        MIPS_INVAL("cp1 cond branch");
        gen_reserved_instruction(ctx);
        return;
    }

    tcg_gen_trunc_i64_tl(bcond, t0);

    ctx->btarget = btarget;
    plugin_gen_record_branch_target((uint64_t)btarget);

    switch (delayslot_size) {
    case 2:
        ctx->hflags |= MIPS_HFLAG_BDS16;
        break;
    case 4:
        ctx->hflags |= MIPS_HFLAG_BDS32;
        break;
    }
}

/* Coprocessor 1 (FPU) */

#define FOP(func, fmt) (((fmt) << 21) | (func))

enum fopcode {
    OPC_ADD_S = FOP(0, FMT_S),
    OPC_SUB_S = FOP(1, FMT_S),
    OPC_MUL_S = FOP(2, FMT_S),
    OPC_DIV_S = FOP(3, FMT_S),
    OPC_SQRT_S = FOP(4, FMT_S),
    OPC_ABS_S = FOP(5, FMT_S),
    OPC_MOV_S = FOP(6, FMT_S),
    OPC_NEG_S = FOP(7, FMT_S),
    OPC_ROUND_L_S = FOP(8, FMT_S),
    OPC_TRUNC_L_S = FOP(9, FMT_S),
    OPC_CEIL_L_S = FOP(10, FMT_S),
    OPC_FLOOR_L_S = FOP(11, FMT_S),
    OPC_ROUND_W_S = FOP(12, FMT_S),
    OPC_TRUNC_W_S = FOP(13, FMT_S),
    OPC_CEIL_W_S = FOP(14, FMT_S),
    OPC_FLOOR_W_S = FOP(15, FMT_S),
    OPC_SEL_S = FOP(16, FMT_S),
    OPC_MOVCF_S = FOP(17, FMT_S),
    OPC_MOVZ_S = FOP(18, FMT_S),
    OPC_MOVN_S = FOP(19, FMT_S),
    OPC_SELEQZ_S = FOP(20, FMT_S),
    OPC_RECIP_S = FOP(21, FMT_S),
    OPC_RSQRT_S = FOP(22, FMT_S),
    OPC_SELNEZ_S = FOP(23, FMT_S),
    OPC_MADDF_S = FOP(24, FMT_S),
    OPC_MSUBF_S = FOP(25, FMT_S),
    OPC_RINT_S = FOP(26, FMT_S),
    OPC_CLASS_S = FOP(27, FMT_S),
    OPC_MIN_S = FOP(28, FMT_S),
    OPC_RECIP2_S = FOP(28, FMT_S),
    OPC_MINA_S = FOP(29, FMT_S),
    OPC_RECIP1_S = FOP(29, FMT_S),
    OPC_MAX_S = FOP(30, FMT_S),
    OPC_RSQRT1_S = FOP(30, FMT_S),
    OPC_MAXA_S = FOP(31, FMT_S),
    OPC_RSQRT2_S = FOP(31, FMT_S),
    OPC_CVT_D_S = FOP(33, FMT_S),
    OPC_CVT_W_S = FOP(36, FMT_S),
    OPC_CVT_L_S = FOP(37, FMT_S),
    OPC_CVT_PS_S = FOP(38, FMT_S),
    OPC_CMP_F_S = FOP(48, FMT_S),
    OPC_CMP_UN_S = FOP(49, FMT_S),
    OPC_CMP_EQ_S = FOP(50, FMT_S),
    OPC_CMP_UEQ_S = FOP(51, FMT_S),
    OPC_CMP_OLT_S = FOP(52, FMT_S),
    OPC_CMP_ULT_S = FOP(53, FMT_S),
    OPC_CMP_OLE_S = FOP(54, FMT_S),
    OPC_CMP_ULE_S = FOP(55, FMT_S),
    OPC_CMP_SF_S = FOP(56, FMT_S),
    OPC_CMP_NGLE_S = FOP(57, FMT_S),
    OPC_CMP_SEQ_S = FOP(58, FMT_S),
    OPC_CMP_NGL_S = FOP(59, FMT_S),
    OPC_CMP_LT_S = FOP(60, FMT_S),
    OPC_CMP_NGE_S = FOP(61, FMT_S),
    OPC_CMP_LE_S = FOP(62, FMT_S),
    OPC_CMP_NGT_S = FOP(63, FMT_S),

    OPC_ADD_D = FOP(0, FMT_D),
    OPC_SUB_D = FOP(1, FMT_D),
    OPC_MUL_D = FOP(2, FMT_D),
    OPC_DIV_D = FOP(3, FMT_D),
    OPC_SQRT_D = FOP(4, FMT_D),
    OPC_ABS_D = FOP(5, FMT_D),
    OPC_MOV_D = FOP(6, FMT_D),
    OPC_NEG_D = FOP(7, FMT_D),
    OPC_ROUND_L_D = FOP(8, FMT_D),
    OPC_TRUNC_L_D = FOP(9, FMT_D),
    OPC_CEIL_L_D = FOP(10, FMT_D),
    OPC_FLOOR_L_D = FOP(11, FMT_D),
    OPC_ROUND_W_D = FOP(12, FMT_D),
    OPC_TRUNC_W_D = FOP(13, FMT_D),
    OPC_CEIL_W_D = FOP(14, FMT_D),
    OPC_FLOOR_W_D = FOP(15, FMT_D),
    OPC_SEL_D = FOP(16, FMT_D),
    OPC_MOVCF_D = FOP(17, FMT_D),
    OPC_MOVZ_D = FOP(18, FMT_D),
    OPC_MOVN_D = FOP(19, FMT_D),
    OPC_SELEQZ_D = FOP(20, FMT_D),
    OPC_RECIP_D = FOP(21, FMT_D),
    OPC_RSQRT_D = FOP(22, FMT_D),
    OPC_SELNEZ_D = FOP(23, FMT_D),
    OPC_MADDF_D = FOP(24, FMT_D),
    OPC_MSUBF_D = FOP(25, FMT_D),
    OPC_RINT_D = FOP(26, FMT_D),
    OPC_CLASS_D = FOP(27, FMT_D),
    OPC_MIN_D = FOP(28, FMT_D),
    OPC_RECIP2_D = FOP(28, FMT_D),
    OPC_MINA_D = FOP(29, FMT_D),
    OPC_RECIP1_D = FOP(29, FMT_D),
    OPC_MAX_D = FOP(30, FMT_D),
    OPC_RSQRT1_D = FOP(30, FMT_D),
    OPC_MAXA_D = FOP(31, FMT_D),
    OPC_RSQRT2_D = FOP(31, FMT_D),
    OPC_CVT_S_D = FOP(32, FMT_D),
    OPC_CVT_W_D = FOP(36, FMT_D),
    OPC_CVT_L_D = FOP(37, FMT_D),
    OPC_CMP_F_D = FOP(48, FMT_D),
    OPC_CMP_UN_D = FOP(49, FMT_D),
    OPC_CMP_EQ_D = FOP(50, FMT_D),
    OPC_CMP_UEQ_D = FOP(51, FMT_D),
    OPC_CMP_OLT_D = FOP(52, FMT_D),
    OPC_CMP_ULT_D = FOP(53, FMT_D),
    OPC_CMP_OLE_D = FOP(54, FMT_D),
    OPC_CMP_ULE_D = FOP(55, FMT_D),
    OPC_CMP_SF_D = FOP(56, FMT_D),
    OPC_CMP_NGLE_D = FOP(57, FMT_D),
    OPC_CMP_SEQ_D = FOP(58, FMT_D),
    OPC_CMP_NGL_D = FOP(59, FMT_D),
    OPC_CMP_LT_D = FOP(60, FMT_D),
    OPC_CMP_NGE_D = FOP(61, FMT_D),
    OPC_CMP_LE_D = FOP(62, FMT_D),
    OPC_CMP_NGT_D = FOP(63, FMT_D),

    OPC_CVT_S_W = FOP(32, FMT_W),
    OPC_CVT_D_W = FOP(33, FMT_W),
    OPC_CVT_S_L = FOP(32, FMT_L),
    OPC_CVT_D_L = FOP(33, FMT_L),
    OPC_CVT_PS_PW = FOP(38, FMT_W),

    OPC_ADD_PS = FOP(0, FMT_PS),
    OPC_SUB_PS = FOP(1, FMT_PS),
    OPC_MUL_PS = FOP(2, FMT_PS),
    OPC_DIV_PS = FOP(3, FMT_PS),
    OPC_ABS_PS = FOP(5, FMT_PS),
    OPC_MOV_PS = FOP(6, FMT_PS),
    OPC_NEG_PS = FOP(7, FMT_PS),
    OPC_MOVCF_PS = FOP(17, FMT_PS),
    OPC_MOVZ_PS = FOP(18, FMT_PS),
    OPC_MOVN_PS = FOP(19, FMT_PS),
    OPC_ADDR_PS = FOP(24, FMT_PS),
    OPC_MULR_PS = FOP(26, FMT_PS),
    OPC_RECIP2_PS = FOP(28, FMT_PS),
    OPC_RECIP1_PS = FOP(29, FMT_PS),
    OPC_RSQRT1_PS = FOP(30, FMT_PS),
    OPC_RSQRT2_PS = FOP(31, FMT_PS),

    OPC_CVT_S_PU = FOP(32, FMT_PS),
    OPC_CVT_PW_PS = FOP(36, FMT_PS),
    OPC_CVT_S_PL = FOP(40, FMT_PS),
    OPC_PLL_PS = FOP(44, FMT_PS),
    OPC_PLU_PS = FOP(45, FMT_PS),
    OPC_PUL_PS = FOP(46, FMT_PS),
    OPC_PUU_PS = FOP(47, FMT_PS),
    OPC_CMP_F_PS = FOP(48, FMT_PS),
    OPC_CMP_UN_PS = FOP(49, FMT_PS),
    OPC_CMP_EQ_PS = FOP(50, FMT_PS),
    OPC_CMP_UEQ_PS = FOP(51, FMT_PS),
    OPC_CMP_OLT_PS = FOP(52, FMT_PS),
    OPC_CMP_ULT_PS = FOP(53, FMT_PS),
    OPC_CMP_OLE_PS = FOP(54, FMT_PS),
    OPC_CMP_ULE_PS = FOP(55, FMT_PS),
    OPC_CMP_SF_PS = FOP(56, FMT_PS),
    OPC_CMP_NGLE_PS = FOP(57, FMT_PS),
    OPC_CMP_SEQ_PS = FOP(58, FMT_PS),
    OPC_CMP_NGL_PS = FOP(59, FMT_PS),
    OPC_CMP_LT_PS = FOP(60, FMT_PS),
    OPC_CMP_NGE_PS = FOP(61, FMT_PS),
    OPC_CMP_LE_PS = FOP(62, FMT_PS),
    OPC_CMP_NGT_PS = FOP(63, FMT_PS),
};

enum r6_f_cmp_op {
    R6_OPC_CMP_AF_S   = FOP(0, FMT_W),
    R6_OPC_CMP_UN_S   = FOP(1, FMT_W),
    R6_OPC_CMP_EQ_S   = FOP(2, FMT_W),
    R6_OPC_CMP_UEQ_S  = FOP(3, FMT_W),
    R6_OPC_CMP_LT_S   = FOP(4, FMT_W),
    R6_OPC_CMP_ULT_S  = FOP(5, FMT_W),
    R6_OPC_CMP_LE_S   = FOP(6, FMT_W),
    R6_OPC_CMP_ULE_S  = FOP(7, FMT_W),
    R6_OPC_CMP_SAF_S  = FOP(8, FMT_W),
    R6_OPC_CMP_SUN_S  = FOP(9, FMT_W),
    R6_OPC_CMP_SEQ_S  = FOP(10, FMT_W),
    R6_OPC_CMP_SEUQ_S = FOP(11, FMT_W),
    R6_OPC_CMP_SLT_S  = FOP(12, FMT_W),
    R6_OPC_CMP_SULT_S = FOP(13, FMT_W),
    R6_OPC_CMP_SLE_S  = FOP(14, FMT_W),
    R6_OPC_CMP_SULE_S = FOP(15, FMT_W),
    R6_OPC_CMP_OR_S   = FOP(17, FMT_W),
    R6_OPC_CMP_UNE_S  = FOP(18, FMT_W),
    R6_OPC_CMP_NE_S   = FOP(19, FMT_W),
    R6_OPC_CMP_SOR_S  = FOP(25, FMT_W),
    R6_OPC_CMP_SUNE_S = FOP(26, FMT_W),
    R6_OPC_CMP_SNE_S  = FOP(27, FMT_W),

    R6_OPC_CMP_AF_D   = FOP(0, FMT_L),
    R6_OPC_CMP_UN_D   = FOP(1, FMT_L),
    R6_OPC_CMP_EQ_D   = FOP(2, FMT_L),
    R6_OPC_CMP_UEQ_D  = FOP(3, FMT_L),
    R6_OPC_CMP_LT_D   = FOP(4, FMT_L),
    R6_OPC_CMP_ULT_D  = FOP(5, FMT_L),
    R6_OPC_CMP_LE_D   = FOP(6, FMT_L),
    R6_OPC_CMP_ULE_D  = FOP(7, FMT_L),
    R6_OPC_CMP_SAF_D  = FOP(8, FMT_L),
    R6_OPC_CMP_SUN_D  = FOP(9, FMT_L),
    R6_OPC_CMP_SEQ_D  = FOP(10, FMT_L),
    R6_OPC_CMP_SEUQ_D = FOP(11, FMT_L),
    R6_OPC_CMP_SLT_D  = FOP(12, FMT_L),
    R6_OPC_CMP_SULT_D = FOP(13, FMT_L),
    R6_OPC_CMP_SLE_D  = FOP(14, FMT_L),
    R6_OPC_CMP_SULE_D = FOP(15, FMT_L),
    R6_OPC_CMP_OR_D   = FOP(17, FMT_L),
    R6_OPC_CMP_UNE_D  = FOP(18, FMT_L),
    R6_OPC_CMP_NE_D   = FOP(19, FMT_L),
    R6_OPC_CMP_SOR_D  = FOP(25, FMT_L),
    R6_OPC_CMP_SUNE_D = FOP(26, FMT_L),
    R6_OPC_CMP_SNE_D  = FOP(27, FMT_L),
};

static void gen_cp1(DisasContext *ctx, uint32_t opc, int rt, int fs)
{
    TCGv t0 = tcg_temp_new();

    switch (opc) {
    case OPC_MFC1:
        mips_ident(ctx,
            opc == OPC_MFC1 ? MIPS_ID_OPC_MFC1 :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            tcg_gen_ext_i32_tl(t0, fp0);
        }
        gen_store_gpr(t0, rt);
        break;
    case OPC_MTC1:
        mips_ident(ctx,
            opc == OPC_MTC1 ? MIPS_ID_OPC_MTC1 :
            MIPS_ID_NONE);
        gen_load_gpr(t0, rt);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            tcg_gen_trunc_tl_i32(fp0, t0);
            gen_store_fpr32(ctx, fp0, fs);
        }
        break;
    case OPC_CFC1:
        mips_ident(ctx,
            opc == OPC_CFC1 ? MIPS_ID_OPC_CFC1 :
            MIPS_ID_NONE);
        gen_helper_1e0i(cfc1, t0, fs);
        gen_store_gpr(t0, rt);
        break;
    case OPC_CTC1:
        mips_ident(ctx,
            opc == OPC_CTC1 ? MIPS_ID_OPC_CTC1 :
            MIPS_ID_NONE);
        gen_load_gpr(t0, rt);
        save_cpu_state(ctx, 0);
        gen_helper_0e2i(ctc1, t0, tcg_constant_i32(fs), rt);
        /* Stop translation as we may have changed hflags */
        ctx->base.is_jmp = DISAS_STOP;
        break;
#if defined(TARGET_MIPS64)
    case OPC_DMFC1:
        mips_ident(ctx,
            opc == OPC_DMFC1 ? MIPS_ID_OPC_DMFC1 :
            MIPS_ID_NONE);
        gen_load_fpr64(ctx, t0, fs);
        gen_store_gpr(t0, rt);
        break;
    case OPC_DMTC1:
        mips_ident(ctx,
            opc == OPC_DMTC1 ? MIPS_ID_OPC_DMTC1 :
            MIPS_ID_NONE);
        gen_load_gpr(t0, rt);
        gen_store_fpr64(ctx, t0, fs);
        break;
#endif
    case OPC_MFHC1:
        mips_ident(ctx,
            opc == OPC_MFHC1 ? MIPS_ID_OPC_MFHC1 :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32h(ctx, fp0, fs);
            tcg_gen_ext_i32_tl(t0, fp0);
        }
        gen_store_gpr(t0, rt);
        break;
    case OPC_MTHC1:
        mips_ident(ctx,
            opc == OPC_MTHC1 ? MIPS_ID_OPC_MTHC1 :
            MIPS_ID_NONE);
        gen_load_gpr(t0, rt);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            tcg_gen_trunc_tl_i32(fp0, t0);
            gen_store_fpr32h(ctx, fp0, fs);
        }
        break;
    default:
        MIPS_INVAL("cp1 move");
        gen_reserved_instruction(ctx);
        return;
    }
}

static void gen_movci(DisasContext *ctx, int rd, int rs, int cc, int tf)
{
    TCGLabel *l1;
    TCGCond cond;
    TCGv_i32 t0;

    if (rd == 0) {
        /* Treat as NOP. */
        /* The operand the NOP erases; see note_gpr_folded_read(). */
        note_gpr_folded_read(rs);
        return;
    }

    if (tf) {
        cond = TCG_COND_EQ;
    } else {
        cond = TCG_COND_NE;
    }

    l1 = gen_new_label();
    t0 = tcg_temp_new_i32();
    tcg_gen_andi_i32(t0, fpu_fcr31, 1 << get_fp_bit(cc));
    tcg_gen_brcondi_i32(cond, t0, 0, l1);
    gen_load_gpr(cpu_gpr[rd], rs);
    gen_set_label(l1);
}

static inline void gen_movcf_s(DisasContext *ctx, int fs, int fd, int cc,
                               int tf)
{
    int cond;
    TCGv_i32 t0 = tcg_temp_new_i32();
    TCGLabel *l1 = gen_new_label();

    if (tf) {
        cond = TCG_COND_EQ;
    } else {
        cond = TCG_COND_NE;
    }

    tcg_gen_andi_i32(t0, fpu_fcr31, 1 << get_fp_bit(cc));
    tcg_gen_brcondi_i32(cond, t0, 0, l1);
    gen_load_fpr32(ctx, t0, fs);
    gen_store_fpr32(ctx, t0, fd);
    gen_set_label(l1);
}

static inline void gen_movcf_d(DisasContext *ctx, int fs, int fd, int cc,
                               int tf)
{
    int cond;
    TCGv_i32 t0 = tcg_temp_new_i32();
    TCGv_i64 fp0;
    TCGLabel *l1 = gen_new_label();

    if (tf) {
        cond = TCG_COND_EQ;
    } else {
        cond = TCG_COND_NE;
    }

    tcg_gen_andi_i32(t0, fpu_fcr31, 1 << get_fp_bit(cc));
    tcg_gen_brcondi_i32(cond, t0, 0, l1);
    fp0 = tcg_temp_new_i64();
    gen_load_fpr64(ctx, fp0, fs);
    gen_store_fpr64(ctx, fp0, fd);
    gen_set_label(l1);
}

static inline void gen_movcf_ps(DisasContext *ctx, int fs, int fd,
                                int cc, int tf)
{
    int cond;
    TCGv_i32 t0 = tcg_temp_new_i32();
    TCGLabel *l1 = gen_new_label();
    TCGLabel *l2 = gen_new_label();

    if (tf) {
        cond = TCG_COND_EQ;
    } else {
        cond = TCG_COND_NE;
    }

    tcg_gen_andi_i32(t0, fpu_fcr31, 1 << get_fp_bit(cc));
    tcg_gen_brcondi_i32(cond, t0, 0, l1);
    gen_load_fpr32(ctx, t0, fs);
    gen_store_fpr32(ctx, t0, fd);
    gen_set_label(l1);

    tcg_gen_andi_i32(t0, fpu_fcr31, 1 << get_fp_bit(cc + 1));
    tcg_gen_brcondi_i32(cond, t0, 0, l2);
    gen_load_fpr32h(ctx, t0, fs);
    gen_store_fpr32h(ctx, t0, fd);
    gen_set_label(l2);
}

static void gen_sel_s(DisasContext *ctx, enum fopcode op1, int fd, int ft,
                      int fs)
{
    TCGv_i32 t1 = tcg_constant_i32(0);
    TCGv_i32 fp0 = tcg_temp_new_i32();
    TCGv_i32 fp1 = tcg_temp_new_i32();
    TCGv_i32 fp2 = tcg_temp_new_i32();
    gen_load_fpr32(ctx, fp0, fd);
    gen_load_fpr32(ctx, fp1, ft);
    gen_load_fpr32(ctx, fp2, fs);

    switch (op1) {
    case OPC_SEL_S:
        mips_ident(ctx,
            op1 == OPC_SEL_S ? MIPS_ID_OPC_SEL_S :
            MIPS_ID_NONE);
        tcg_gen_andi_i32(fp0, fp0, 1);
        tcg_gen_movcond_i32(TCG_COND_NE, fp0, fp0, t1, fp1, fp2);
        break;
    case OPC_SELEQZ_S:
        mips_ident(ctx,
            op1 == OPC_SELEQZ_S ? MIPS_ID_OPC_SELEQZ_S :
            MIPS_ID_NONE);
        tcg_gen_andi_i32(fp1, fp1, 1);
        tcg_gen_movcond_i32(TCG_COND_EQ, fp0, fp1, t1, fp2, t1);
        break;
    case OPC_SELNEZ_S:
        mips_ident(ctx,
            op1 == OPC_SELNEZ_S ? MIPS_ID_OPC_SELNEZ_S :
            MIPS_ID_NONE);
        tcg_gen_andi_i32(fp1, fp1, 1);
        tcg_gen_movcond_i32(TCG_COND_NE, fp0, fp1, t1, fp2, t1);
        break;
    default:
        MIPS_INVAL("gen_sel_s");
        gen_reserved_instruction(ctx);
        break;
    }

    gen_store_fpr32(ctx, fp0, fd);
}

static void gen_sel_d(DisasContext *ctx, enum fopcode op1, int fd, int ft,
                      int fs)
{
    TCGv_i64 t1 = tcg_constant_i64(0);
    TCGv_i64 fp0 = tcg_temp_new_i64();
    TCGv_i64 fp1 = tcg_temp_new_i64();
    TCGv_i64 fp2 = tcg_temp_new_i64();
    gen_load_fpr64(ctx, fp0, fd);
    gen_load_fpr64(ctx, fp1, ft);
    gen_load_fpr64(ctx, fp2, fs);

    switch (op1) {
    case OPC_SEL_D:
        mips_ident(ctx,
            op1 == OPC_SEL_D ? MIPS_ID_OPC_SEL_D :
            MIPS_ID_NONE);
        tcg_gen_andi_i64(fp0, fp0, 1);
        tcg_gen_movcond_i64(TCG_COND_NE, fp0, fp0, t1, fp1, fp2);
        break;
    case OPC_SELEQZ_D:
        mips_ident(ctx,
            op1 == OPC_SELEQZ_D ? MIPS_ID_OPC_SELEQZ_D :
            MIPS_ID_NONE);
        tcg_gen_andi_i64(fp1, fp1, 1);
        tcg_gen_movcond_i64(TCG_COND_EQ, fp0, fp1, t1, fp2, t1);
        break;
    case OPC_SELNEZ_D:
        mips_ident(ctx,
            op1 == OPC_SELNEZ_D ? MIPS_ID_OPC_SELNEZ_D :
            MIPS_ID_NONE);
        tcg_gen_andi_i64(fp1, fp1, 1);
        tcg_gen_movcond_i64(TCG_COND_NE, fp0, fp1, t1, fp2, t1);
        break;
    default:
        MIPS_INVAL("gen_sel_d");
        gen_reserved_instruction(ctx);
        break;
    }

    gen_store_fpr64(ctx, fp0, fd);
}

static void gen_farith(DisasContext *ctx, enum fopcode op1,
                       int ft, int fs, int fd, int cc)
{
    uint32_t func = ctx->opcode & 0x3f;
    switch (op1) {
    case OPC_ADD_S:
        mips_ident(ctx,
            op1 == OPC_ADD_S ? MIPS_ID_OPC_ADD_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_add_s(fp0, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_SUB_S:
        mips_ident(ctx,
            op1 == OPC_SUB_S ? MIPS_ID_OPC_SUB_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_sub_s(fp0, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_MUL_S:
        mips_ident(ctx,
            op1 == OPC_MUL_S ? MIPS_ID_OPC_MUL_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_mul_s(fp0, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_DIV_S:
        mips_ident(ctx,
            op1 == OPC_DIV_S ? MIPS_ID_OPC_DIV_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_div_s(fp0, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_SQRT_S:
        mips_ident(ctx,
            op1 == OPC_SQRT_S ? MIPS_ID_OPC_SQRT_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_helper_float_sqrt_s(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_ABS_S:
        mips_ident(ctx,
            op1 == OPC_ABS_S ? MIPS_ID_OPC_ABS_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            if (ctx->abs2008) {
                tcg_gen_andi_i32(fp0, fp0, 0x7fffffffUL);
            } else {
                gen_helper_float_abs_s(fp0, fp0);
            }
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_MOV_S:
        mips_ident(ctx,
            op1 == OPC_MOV_S ? MIPS_ID_OPC_MOV_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_NEG_S:
        mips_ident(ctx,
            op1 == OPC_NEG_S ? MIPS_ID_OPC_NEG_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            if (ctx->abs2008) {
                tcg_gen_xori_i32(fp0, fp0, 1UL << 31);
            } else {
                gen_helper_float_chs_s(fp0, fp0);
            }
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_ROUND_L_S:
        mips_ident(ctx,
            op1 == OPC_ROUND_L_S ? MIPS_ID_OPC_ROUND_L_S :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr32(ctx, fp32, fs);
            if (ctx->nan2008) {
                gen_helper_float_round_2008_l_s(fp64, tcg_env, fp32);
            } else {
                gen_helper_float_round_l_s(fp64, tcg_env, fp32);
            }
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_TRUNC_L_S:
        mips_ident(ctx,
            op1 == OPC_TRUNC_L_S ? MIPS_ID_OPC_TRUNC_L_S :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr32(ctx, fp32, fs);
            if (ctx->nan2008) {
                gen_helper_float_trunc_2008_l_s(fp64, tcg_env, fp32);
            } else {
                gen_helper_float_trunc_l_s(fp64, tcg_env, fp32);
            }
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_CEIL_L_S:
        mips_ident(ctx,
            op1 == OPC_CEIL_L_S ? MIPS_ID_OPC_CEIL_L_S :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr32(ctx, fp32, fs);
            if (ctx->nan2008) {
                gen_helper_float_ceil_2008_l_s(fp64, tcg_env, fp32);
            } else {
                gen_helper_float_ceil_l_s(fp64, tcg_env, fp32);
            }
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_FLOOR_L_S:
        mips_ident(ctx,
            op1 == OPC_FLOOR_L_S ? MIPS_ID_OPC_FLOOR_L_S :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr32(ctx, fp32, fs);
            if (ctx->nan2008) {
                gen_helper_float_floor_2008_l_s(fp64, tcg_env, fp32);
            } else {
                gen_helper_float_floor_l_s(fp64, tcg_env, fp32);
            }
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_ROUND_W_S:
        mips_ident(ctx,
            op1 == OPC_ROUND_W_S ? MIPS_ID_OPC_ROUND_W_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_round_2008_w_s(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_round_w_s(fp0, tcg_env, fp0);
            }
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_TRUNC_W_S:
        mips_ident(ctx,
            op1 == OPC_TRUNC_W_S ? MIPS_ID_OPC_TRUNC_W_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_trunc_2008_w_s(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_trunc_w_s(fp0, tcg_env, fp0);
            }
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_CEIL_W_S:
        mips_ident(ctx,
            op1 == OPC_CEIL_W_S ? MIPS_ID_OPC_CEIL_W_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_ceil_2008_w_s(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_ceil_w_s(fp0, tcg_env, fp0);
            }
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_FLOOR_W_S:
        mips_ident(ctx,
            op1 == OPC_FLOOR_W_S ? MIPS_ID_OPC_FLOOR_W_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_floor_2008_w_s(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_floor_w_s(fp0, tcg_env, fp0);
            }
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_SEL_S:
        mips_ident(ctx,
            op1 == OPC_SEL_S ? MIPS_ID_OPC_SEL_S :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        gen_sel_s(ctx, op1, fd, ft, fs);
        break;
    case OPC_SELEQZ_S:
        mips_ident(ctx,
            op1 == OPC_SELEQZ_S ? MIPS_ID_OPC_SELEQZ_S :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        gen_sel_s(ctx, op1, fd, ft, fs);
        break;
    case OPC_SELNEZ_S:
        mips_ident(ctx,
            op1 == OPC_SELNEZ_S ? MIPS_ID_OPC_SELNEZ_S :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        gen_sel_s(ctx, op1, fd, ft, fs);
        break;
    case OPC_MOVCF_S:
        mips_ident(ctx,
            op1 == OPC_MOVCF_S ? MIPS_ID_OPC_MOVCF_S :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        gen_movcf_s(ctx, fs, fd, (ft >> 2) & 0x7, ft & 0x1);
        break;
    case OPC_MOVZ_S:
        mips_ident(ctx,
            op1 == OPC_MOVZ_S ? MIPS_ID_OPC_MOVZ_S :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        {
            TCGLabel *l1 = gen_new_label();
            TCGv_i32 fp0;

            if (ft != 0) {
                tcg_gen_brcondi_tl(TCG_COND_NE, cpu_gpr[ft], 0, l1);
            }
            fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_store_fpr32(ctx, fp0, fd);
            gen_set_label(l1);
        }
        break;
    case OPC_MOVN_S:
        mips_ident(ctx,
            op1 == OPC_MOVN_S ? MIPS_ID_OPC_MOVN_S :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        {
            TCGLabel *l1 = gen_new_label();
            TCGv_i32 fp0;

            if (ft != 0) {
                tcg_gen_brcondi_tl(TCG_COND_EQ, cpu_gpr[ft], 0, l1);
                fp0 = tcg_temp_new_i32();
                gen_load_fpr32(ctx, fp0, fs);
                gen_store_fpr32(ctx, fp0, fd);
                gen_set_label(l1);
            }
        }
        break;
    case OPC_RECIP_S:
        mips_ident(ctx,
            op1 == OPC_RECIP_S ? MIPS_ID_OPC_RECIP_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_helper_float_recip_s(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_RSQRT_S:
        mips_ident(ctx,
            op1 == OPC_RSQRT_S ? MIPS_ID_OPC_RSQRT_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_helper_float_rsqrt_s(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_MADDF_S:
        mips_ident(ctx,
            op1 == OPC_MADDF_S ? MIPS_ID_OPC_MADDF_S :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_load_fpr32(ctx, fp2, fd);
            gen_helper_float_maddf_s(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr32(ctx, fp2, fd);
        }
        break;
    case OPC_MSUBF_S:
        mips_ident(ctx,
            op1 == OPC_MSUBF_S ? MIPS_ID_OPC_MSUBF_S :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_load_fpr32(ctx, fp2, fd);
            gen_helper_float_msubf_s(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr32(ctx, fp2, fd);
        }
        break;
    case OPC_RINT_S:
        mips_ident(ctx,
            op1 == OPC_RINT_S ? MIPS_ID_OPC_RINT_S :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_helper_float_rint_s(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_CLASS_S:
        mips_ident(ctx,
            op1 == OPC_CLASS_S ? MIPS_ID_OPC_CLASS_S :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_helper_float_class_s(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_MIN_S: /* OPC_RECIP2_S */
        mips_ident(ctx,
            op1 == OPC_MIN_S ? MIPS_ID_OPC_MIN_S :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MIN_S */
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_min_s(fp2, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp2, fd);
        } else {
            /* OPC_RECIP2_S */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i32 fp0 = tcg_temp_new_i32();
                TCGv_i32 fp1 = tcg_temp_new_i32();

                gen_load_fpr32(ctx, fp0, fs);
                gen_load_fpr32(ctx, fp1, ft);
                gen_helper_float_recip2_s(fp0, tcg_env, fp0, fp1);
                gen_store_fpr32(ctx, fp0, fd);
            }
        }
        break;
    case OPC_MINA_S: /* OPC_RECIP1_S */
        mips_ident(ctx,
            op1 == OPC_MINA_S ? MIPS_ID_OPC_MINA_S :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MINA_S */
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_mina_s(fp2, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp2, fd);
        } else {
            /* OPC_RECIP1_S */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i32 fp0 = tcg_temp_new_i32();

                gen_load_fpr32(ctx, fp0, fs);
                gen_helper_float_recip1_s(fp0, tcg_env, fp0);
                gen_store_fpr32(ctx, fp0, fd);
            }
        }
        break;
    case OPC_MAX_S: /* OPC_RSQRT1_S */
        mips_ident(ctx,
            op1 == OPC_MAX_S ? MIPS_ID_OPC_MAX_S :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MAX_S */
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_max_s(fp1, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp1, fd);
        } else {
            /* OPC_RSQRT1_S */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i32 fp0 = tcg_temp_new_i32();

                gen_load_fpr32(ctx, fp0, fs);
                gen_helper_float_rsqrt1_s(fp0, tcg_env, fp0);
                gen_store_fpr32(ctx, fp0, fd);
            }
        }
        break;
    case OPC_MAXA_S: /* OPC_RSQRT2_S */
        mips_ident(ctx,
            op1 == OPC_MAXA_S ? MIPS_ID_OPC_MAXA_S :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MAXA_S */
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_helper_float_maxa_s(fp1, tcg_env, fp0, fp1);
            gen_store_fpr32(ctx, fp1, fd);
        } else {
            /* OPC_RSQRT2_S */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i32 fp0 = tcg_temp_new_i32();
                TCGv_i32 fp1 = tcg_temp_new_i32();

                gen_load_fpr32(ctx, fp0, fs);
                gen_load_fpr32(ctx, fp1, ft);
                gen_helper_float_rsqrt2_s(fp0, tcg_env, fp0, fp1);
                gen_store_fpr32(ctx, fp0, fd);
            }
        }
        break;
    case OPC_CVT_D_S:
        mips_ident(ctx,
            op1 == OPC_CVT_D_S ? MIPS_ID_OPC_CVT_D_S :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fd);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr32(ctx, fp32, fs);
            gen_helper_float_cvtd_s(fp64, tcg_env, fp32);
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_CVT_W_S:
        mips_ident(ctx,
            op1 == OPC_CVT_W_S ? MIPS_ID_OPC_CVT_W_S :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_cvt_2008_w_s(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_cvt_w_s(fp0, tcg_env, fp0);
            }
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_CVT_L_S:
        mips_ident(ctx,
            op1 == OPC_CVT_L_S ? MIPS_ID_OPC_CVT_L_S :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr32(ctx, fp32, fs);
            if (ctx->nan2008) {
                gen_helper_float_cvt_2008_l_s(fp64, tcg_env, fp32);
            } else {
                gen_helper_float_cvt_l_s(fp64, tcg_env, fp32);
            }
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_CVT_PS_S:
        mips_ident(ctx,
            op1 == OPC_CVT_PS_S ? MIPS_ID_OPC_CVT_PS_S :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp64 = tcg_temp_new_i64();
            TCGv_i32 fp32_0 = tcg_temp_new_i32();
            TCGv_i32 fp32_1 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp32_0, fs);
            gen_load_fpr32(ctx, fp32_1, ft);
            tcg_gen_concat_i32_i64(fp64, fp32_1, fp32_0);
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_CMP_F_S:
    case OPC_CMP_UN_S:
    case OPC_CMP_EQ_S:
    case OPC_CMP_UEQ_S:
    case OPC_CMP_OLT_S:
    case OPC_CMP_ULT_S:
    case OPC_CMP_OLE_S:
    case OPC_CMP_ULE_S:
    case OPC_CMP_SF_S:
    case OPC_CMP_NGLE_S:
    case OPC_CMP_SEQ_S:
    case OPC_CMP_NGL_S:
    case OPC_CMP_LT_S:
    case OPC_CMP_NGE_S:
    case OPC_CMP_LE_S:
    case OPC_CMP_NGT_S:
        mips_ident(ctx,
            op1 == OPC_CMP_F_S ? MIPS_ID_OPC_CMP_F_S :
            op1 == OPC_CMP_UN_S ? MIPS_ID_OPC_CMP_UN_S :
            op1 == OPC_CMP_EQ_S ? MIPS_ID_OPC_CMP_EQ_S :
            op1 == OPC_CMP_UEQ_S ? MIPS_ID_OPC_CMP_UEQ_S :
            op1 == OPC_CMP_OLT_S ? MIPS_ID_OPC_CMP_OLT_S :
            op1 == OPC_CMP_ULT_S ? MIPS_ID_OPC_CMP_ULT_S :
            op1 == OPC_CMP_OLE_S ? MIPS_ID_OPC_CMP_OLE_S :
            op1 == OPC_CMP_ULE_S ? MIPS_ID_OPC_CMP_ULE_S :
            op1 == OPC_CMP_SF_S ? MIPS_ID_OPC_CMP_SF_S :
            op1 == OPC_CMP_NGLE_S ? MIPS_ID_OPC_CMP_NGLE_S :
            op1 == OPC_CMP_SEQ_S ? MIPS_ID_OPC_CMP_SEQ_S :
            op1 == OPC_CMP_NGL_S ? MIPS_ID_OPC_CMP_NGL_S :
            op1 == OPC_CMP_LT_S ? MIPS_ID_OPC_CMP_LT_S :
            op1 == OPC_CMP_NGE_S ? MIPS_ID_OPC_CMP_NGE_S :
            op1 == OPC_CMP_LE_S ? MIPS_ID_OPC_CMP_LE_S :
            op1 == OPC_CMP_NGT_S ? MIPS_ID_OPC_CMP_NGT_S :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        if (ctx->opcode & (1 << 6)) {
            gen_cmpabs_s(ctx, func - 48, ft, fs, cc);
        } else {
            gen_cmp_s(ctx, func - 48, ft, fs, cc);
        }
        break;
    case OPC_ADD_D:
        mips_ident(ctx,
            op1 == OPC_ADD_D ? MIPS_ID_OPC_ADD_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | ft | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_add_d(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_SUB_D:
        mips_ident(ctx,
            op1 == OPC_SUB_D ? MIPS_ID_OPC_SUB_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | ft | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_sub_d(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MUL_D:
        mips_ident(ctx,
            op1 == OPC_MUL_D ? MIPS_ID_OPC_MUL_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | ft | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_mul_d(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_DIV_D:
        mips_ident(ctx,
            op1 == OPC_DIV_D ? MIPS_ID_OPC_DIV_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | ft | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_div_d(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_SQRT_D:
        mips_ident(ctx,
            op1 == OPC_SQRT_D ? MIPS_ID_OPC_SQRT_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_sqrt_d(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_ABS_D:
        mips_ident(ctx,
            op1 == OPC_ABS_D ? MIPS_ID_OPC_ABS_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            if (ctx->abs2008) {
                tcg_gen_andi_i64(fp0, fp0, 0x7fffffffffffffffULL);
            } else {
                gen_helper_float_abs_d(fp0, fp0);
            }
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MOV_D:
        mips_ident(ctx,
            op1 == OPC_MOV_D ? MIPS_ID_OPC_MOV_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_NEG_D:
        mips_ident(ctx,
            op1 == OPC_NEG_D ? MIPS_ID_OPC_NEG_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            if (ctx->abs2008) {
                tcg_gen_xori_i64(fp0, fp0, 1ULL << 63);
            } else {
                gen_helper_float_chs_d(fp0, fp0);
            }
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_ROUND_L_D:
        mips_ident(ctx,
            op1 == OPC_ROUND_L_D ? MIPS_ID_OPC_ROUND_L_D :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_round_2008_l_d(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_round_l_d(fp0, tcg_env, fp0);
            }
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_TRUNC_L_D:
        mips_ident(ctx,
            op1 == OPC_TRUNC_L_D ? MIPS_ID_OPC_TRUNC_L_D :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_trunc_2008_l_d(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_trunc_l_d(fp0, tcg_env, fp0);
            }
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_CEIL_L_D:
        mips_ident(ctx,
            op1 == OPC_CEIL_L_D ? MIPS_ID_OPC_CEIL_L_D :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_ceil_2008_l_d(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_ceil_l_d(fp0, tcg_env, fp0);
            }
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_FLOOR_L_D:
        mips_ident(ctx,
            op1 == OPC_FLOOR_L_D ? MIPS_ID_OPC_FLOOR_L_D :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_floor_2008_l_d(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_floor_l_d(fp0, tcg_env, fp0);
            }
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_ROUND_W_D:
        mips_ident(ctx,
            op1 == OPC_ROUND_W_D ? MIPS_ID_OPC_ROUND_W_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp64, fs);
            if (ctx->nan2008) {
                gen_helper_float_round_2008_w_d(fp32, tcg_env, fp64);
            } else {
                gen_helper_float_round_w_d(fp32, tcg_env, fp64);
            }
            gen_store_fpr32(ctx, fp32, fd);
        }
        break;
    case OPC_TRUNC_W_D:
        mips_ident(ctx,
            op1 == OPC_TRUNC_W_D ? MIPS_ID_OPC_TRUNC_W_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp64, fs);
            if (ctx->nan2008) {
                gen_helper_float_trunc_2008_w_d(fp32, tcg_env, fp64);
            } else {
                gen_helper_float_trunc_w_d(fp32, tcg_env, fp64);
            }
            gen_store_fpr32(ctx, fp32, fd);
        }
        break;
    case OPC_CEIL_W_D:
        mips_ident(ctx,
            op1 == OPC_CEIL_W_D ? MIPS_ID_OPC_CEIL_W_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp64, fs);
            if (ctx->nan2008) {
                gen_helper_float_ceil_2008_w_d(fp32, tcg_env, fp64);
            } else {
                gen_helper_float_ceil_w_d(fp32, tcg_env, fp64);
            }
            gen_store_fpr32(ctx, fp32, fd);
        }
        break;
    case OPC_FLOOR_W_D:
        mips_ident(ctx,
            op1 == OPC_FLOOR_W_D ? MIPS_ID_OPC_FLOOR_W_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp64, fs);
            if (ctx->nan2008) {
                gen_helper_float_floor_2008_w_d(fp32, tcg_env, fp64);
            } else {
                gen_helper_float_floor_w_d(fp32, tcg_env, fp64);
            }
            gen_store_fpr32(ctx, fp32, fd);
        }
        break;
    case OPC_SEL_D:
        mips_ident(ctx,
            op1 == OPC_SEL_D ? MIPS_ID_OPC_SEL_D :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        gen_sel_d(ctx, op1, fd, ft, fs);
        break;
    case OPC_SELEQZ_D:
        mips_ident(ctx,
            op1 == OPC_SELEQZ_D ? MIPS_ID_OPC_SELEQZ_D :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        gen_sel_d(ctx, op1, fd, ft, fs);
        break;
    case OPC_SELNEZ_D:
        mips_ident(ctx,
            op1 == OPC_SELNEZ_D ? MIPS_ID_OPC_SELNEZ_D :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        gen_sel_d(ctx, op1, fd, ft, fs);
        break;
    case OPC_MOVCF_D:
        mips_ident(ctx,
            op1 == OPC_MOVCF_D ? MIPS_ID_OPC_MOVCF_D :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        gen_movcf_d(ctx, fs, fd, (ft >> 2) & 0x7, ft & 0x1);
        break;
    case OPC_MOVZ_D:
        mips_ident(ctx,
            op1 == OPC_MOVZ_D ? MIPS_ID_OPC_MOVZ_D :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        {
            TCGLabel *l1 = gen_new_label();
            TCGv_i64 fp0;

            if (ft != 0) {
                tcg_gen_brcondi_tl(TCG_COND_NE, cpu_gpr[ft], 0, l1);
            }
            fp0 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_store_fpr64(ctx, fp0, fd);
            gen_set_label(l1);
        }
        break;
    case OPC_MOVN_D:
        mips_ident(ctx,
            op1 == OPC_MOVN_D ? MIPS_ID_OPC_MOVN_D :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        {
            TCGLabel *l1 = gen_new_label();
            TCGv_i64 fp0;

            if (ft != 0) {
                tcg_gen_brcondi_tl(TCG_COND_EQ, cpu_gpr[ft], 0, l1);
                fp0 = tcg_temp_new_i64();
                gen_load_fpr64(ctx, fp0, fs);
                gen_store_fpr64(ctx, fp0, fd);
                gen_set_label(l1);
            }
        }
        break;
    case OPC_RECIP_D:
        mips_ident(ctx,
            op1 == OPC_RECIP_D ? MIPS_ID_OPC_RECIP_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_recip_d(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_RSQRT_D:
        mips_ident(ctx,
            op1 == OPC_RSQRT_D ? MIPS_ID_OPC_RSQRT_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs | fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_rsqrt_d(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MADDF_D:
        mips_ident(ctx,
            op1 == OPC_MADDF_D ? MIPS_ID_OPC_MADDF_D :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fd);
            gen_helper_float_maddf_d(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_MSUBF_D:
        mips_ident(ctx,
            op1 == OPC_MSUBF_D ? MIPS_ID_OPC_MSUBF_D :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fd);
            gen_helper_float_msubf_d(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_RINT_D:
        mips_ident(ctx,
            op1 == OPC_RINT_D ? MIPS_ID_OPC_RINT_D :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_rint_d(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_CLASS_D:
        mips_ident(ctx,
            op1 == OPC_CLASS_D ? MIPS_ID_OPC_CLASS_D :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_class_d(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MIN_D: /* OPC_RECIP2_D */
        mips_ident(ctx,
            op1 == OPC_MIN_D ? MIPS_ID_OPC_MIN_D :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MIN_D */
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_min_d(fp1, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp1, fd);
        } else {
            /* OPC_RECIP2_D */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i64 fp0 = tcg_temp_new_i64();
                TCGv_i64 fp1 = tcg_temp_new_i64();

                gen_load_fpr64(ctx, fp0, fs);
                gen_load_fpr64(ctx, fp1, ft);
                gen_helper_float_recip2_d(fp0, tcg_env, fp0, fp1);
                gen_store_fpr64(ctx, fp0, fd);
            }
        }
        break;
    case OPC_MINA_D: /* OPC_RECIP1_D */
        mips_ident(ctx,
            op1 == OPC_MINA_D ? MIPS_ID_OPC_MINA_D :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MINA_D */
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_mina_d(fp1, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp1, fd);
        } else {
            /* OPC_RECIP1_D */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i64 fp0 = tcg_temp_new_i64();

                gen_load_fpr64(ctx, fp0, fs);
                gen_helper_float_recip1_d(fp0, tcg_env, fp0);
                gen_store_fpr64(ctx, fp0, fd);
            }
        }
        break;
    case OPC_MAX_D: /*  OPC_RSQRT1_D */
        mips_ident(ctx,
            op1 == OPC_MAX_D ? MIPS_ID_OPC_MAX_D :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MAX_D */
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_max_d(fp1, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp1, fd);
        } else {
            /* OPC_RSQRT1_D */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i64 fp0 = tcg_temp_new_i64();

                gen_load_fpr64(ctx, fp0, fs);
                gen_helper_float_rsqrt1_d(fp0, tcg_env, fp0);
                gen_store_fpr64(ctx, fp0, fd);
            }
        }
        break;
    case OPC_MAXA_D: /* OPC_RSQRT2_D */
        mips_ident(ctx,
            op1 == OPC_MAXA_D ? MIPS_ID_OPC_MAXA_D :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_MAXA_D */
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_maxa_d(fp1, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp1, fd);
        } else {
            /* OPC_RSQRT2_D */
            check_cp1_64bitmode(ctx);
            {
                TCGv_i64 fp0 = tcg_temp_new_i64();
                TCGv_i64 fp1 = tcg_temp_new_i64();

                gen_load_fpr64(ctx, fp0, fs);
                gen_load_fpr64(ctx, fp1, ft);
                gen_helper_float_rsqrt2_d(fp0, tcg_env, fp0, fp1);
                gen_store_fpr64(ctx, fp0, fd);
            }
        }
        break;
    case OPC_CMP_F_D:
    case OPC_CMP_UN_D:
    case OPC_CMP_EQ_D:
    case OPC_CMP_UEQ_D:
    case OPC_CMP_OLT_D:
    case OPC_CMP_ULT_D:
    case OPC_CMP_OLE_D:
    case OPC_CMP_ULE_D:
    case OPC_CMP_SF_D:
    case OPC_CMP_NGLE_D:
    case OPC_CMP_SEQ_D:
    case OPC_CMP_NGL_D:
    case OPC_CMP_LT_D:
    case OPC_CMP_NGE_D:
    case OPC_CMP_LE_D:
    case OPC_CMP_NGT_D:
        mips_ident(ctx,
            op1 == OPC_CMP_F_D ? MIPS_ID_OPC_CMP_F_D :
            op1 == OPC_CMP_UN_D ? MIPS_ID_OPC_CMP_UN_D :
            op1 == OPC_CMP_EQ_D ? MIPS_ID_OPC_CMP_EQ_D :
            op1 == OPC_CMP_UEQ_D ? MIPS_ID_OPC_CMP_UEQ_D :
            op1 == OPC_CMP_OLT_D ? MIPS_ID_OPC_CMP_OLT_D :
            op1 == OPC_CMP_ULT_D ? MIPS_ID_OPC_CMP_ULT_D :
            op1 == OPC_CMP_OLE_D ? MIPS_ID_OPC_CMP_OLE_D :
            op1 == OPC_CMP_ULE_D ? MIPS_ID_OPC_CMP_ULE_D :
            op1 == OPC_CMP_SF_D ? MIPS_ID_OPC_CMP_SF_D :
            op1 == OPC_CMP_NGLE_D ? MIPS_ID_OPC_CMP_NGLE_D :
            op1 == OPC_CMP_SEQ_D ? MIPS_ID_OPC_CMP_SEQ_D :
            op1 == OPC_CMP_NGL_D ? MIPS_ID_OPC_CMP_NGL_D :
            op1 == OPC_CMP_LT_D ? MIPS_ID_OPC_CMP_LT_D :
            op1 == OPC_CMP_NGE_D ? MIPS_ID_OPC_CMP_NGE_D :
            op1 == OPC_CMP_LE_D ? MIPS_ID_OPC_CMP_LE_D :
            op1 == OPC_CMP_NGT_D ? MIPS_ID_OPC_CMP_NGT_D :
            MIPS_ID_NONE);
        check_insn_opc_removed(ctx, ISA_MIPS_R6);
        if (ctx->opcode & (1 << 6)) {
            gen_cmpabs_d(ctx, func - 48, ft, fs, cc);
        } else {
            gen_cmp_d(ctx, func - 48, ft, fs, cc);
        }
        break;
    case OPC_CVT_S_D:
        mips_ident(ctx,
            op1 == OPC_CVT_S_D ? MIPS_ID_OPC_CVT_S_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp64, fs);
            gen_helper_float_cvts_d(fp32, tcg_env, fp64);
            gen_store_fpr32(ctx, fp32, fd);
        }
        break;
    case OPC_CVT_W_D:
        mips_ident(ctx,
            op1 == OPC_CVT_W_D ? MIPS_ID_OPC_CVT_W_D :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fs);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp64, fs);
            if (ctx->nan2008) {
                gen_helper_float_cvt_2008_w_d(fp32, tcg_env, fp64);
            } else {
                gen_helper_float_cvt_w_d(fp32, tcg_env, fp64);
            }
            gen_store_fpr32(ctx, fp32, fd);
        }
        break;
    case OPC_CVT_L_D:
        mips_ident(ctx,
            op1 == OPC_CVT_L_D ? MIPS_ID_OPC_CVT_L_D :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            if (ctx->nan2008) {
                gen_helper_float_cvt_2008_l_d(fp0, tcg_env, fp0);
            } else {
                gen_helper_float_cvt_l_d(fp0, tcg_env, fp0);
            }
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_CVT_S_W:
        mips_ident(ctx,
            op1 == OPC_CVT_S_W ? MIPS_ID_OPC_CVT_S_W :
            MIPS_ID_NONE);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_helper_float_cvts_w(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_CVT_D_W:
        mips_ident(ctx,
            op1 == OPC_CVT_D_W ? MIPS_ID_OPC_CVT_D_W :
            MIPS_ID_NONE);
        check_cp1_registers(ctx, fd);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr32(ctx, fp32, fs);
            gen_helper_float_cvtd_w(fp64, tcg_env, fp32);
            gen_store_fpr64(ctx, fp64, fd);
        }
        break;
    case OPC_CVT_S_L:
        mips_ident(ctx,
            op1 == OPC_CVT_S_L ? MIPS_ID_OPC_CVT_S_L :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp32 = tcg_temp_new_i32();
            TCGv_i64 fp64 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp64, fs);
            gen_helper_float_cvts_l(fp32, tcg_env, fp64);
            gen_store_fpr32(ctx, fp32, fd);
        }
        break;
    case OPC_CVT_D_L:
        mips_ident(ctx,
            op1 == OPC_CVT_D_L ? MIPS_ID_OPC_CVT_D_L :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_cvtd_l(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_CVT_PS_PW:
        mips_ident(ctx,
            op1 == OPC_CVT_PS_PW ? MIPS_ID_OPC_CVT_PS_PW :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_cvtps_pw(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_ADD_PS:
        mips_ident(ctx,
            op1 == OPC_ADD_PS ? MIPS_ID_OPC_ADD_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_add_ps(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_SUB_PS:
        mips_ident(ctx,
            op1 == OPC_SUB_PS ? MIPS_ID_OPC_SUB_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_sub_ps(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MUL_PS:
        mips_ident(ctx,
            op1 == OPC_MUL_PS ? MIPS_ID_OPC_MUL_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_mul_ps(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_ABS_PS:
        mips_ident(ctx,
            op1 == OPC_ABS_PS ? MIPS_ID_OPC_ABS_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_abs_ps(fp0, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MOV_PS:
        mips_ident(ctx,
            op1 == OPC_MOV_PS ? MIPS_ID_OPC_MOV_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_NEG_PS:
        mips_ident(ctx,
            op1 == OPC_NEG_PS ? MIPS_ID_OPC_NEG_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_chs_ps(fp0, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MOVCF_PS:
        mips_ident(ctx,
            op1 == OPC_MOVCF_PS ? MIPS_ID_OPC_MOVCF_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        gen_movcf_ps(ctx, fs, fd, (ft >> 2) & 0x7, ft & 0x1);
        break;
    case OPC_MOVZ_PS:
        mips_ident(ctx,
            op1 == OPC_MOVZ_PS ? MIPS_ID_OPC_MOVZ_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGLabel *l1 = gen_new_label();
            TCGv_i64 fp0;

            if (ft != 0) {
                tcg_gen_brcondi_tl(TCG_COND_NE, cpu_gpr[ft], 0, l1);
            }
            fp0 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            gen_store_fpr64(ctx, fp0, fd);
            gen_set_label(l1);
        }
        break;
    case OPC_MOVN_PS:
        mips_ident(ctx,
            op1 == OPC_MOVN_PS ? MIPS_ID_OPC_MOVN_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGLabel *l1 = gen_new_label();
            TCGv_i64 fp0;

            if (ft != 0) {
                tcg_gen_brcondi_tl(TCG_COND_EQ, cpu_gpr[ft], 0, l1);
                fp0 = tcg_temp_new_i64();
                gen_load_fpr64(ctx, fp0, fs);
                gen_store_fpr64(ctx, fp0, fd);
                gen_set_label(l1);
            }
        }
        break;
    case OPC_ADDR_PS:
        mips_ident(ctx,
            op1 == OPC_ADDR_PS ? MIPS_ID_OPC_ADDR_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, ft);
            gen_load_fpr64(ctx, fp1, fs);
            gen_helper_float_addr_ps(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_MULR_PS:
        mips_ident(ctx,
            op1 == OPC_MULR_PS ? MIPS_ID_OPC_MULR_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, ft);
            gen_load_fpr64(ctx, fp1, fs);
            gen_helper_float_mulr_ps(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_RECIP2_PS:
        mips_ident(ctx,
            op1 == OPC_RECIP2_PS ? MIPS_ID_OPC_RECIP2_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_recip2_ps(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_RECIP1_PS:
        mips_ident(ctx,
            op1 == OPC_RECIP1_PS ? MIPS_ID_OPC_RECIP1_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_recip1_ps(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_RSQRT1_PS:
        mips_ident(ctx,
            op1 == OPC_RSQRT1_PS ? MIPS_ID_OPC_RSQRT1_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_rsqrt1_ps(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_RSQRT2_PS:
        mips_ident(ctx,
            op1 == OPC_RSQRT2_PS ? MIPS_ID_OPC_RSQRT2_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_helper_float_rsqrt2_ps(fp0, tcg_env, fp0, fp1);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_CVT_S_PU:
        mips_ident(ctx,
            op1 == OPC_CVT_S_PU ? MIPS_ID_OPC_CVT_S_PU :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32h(ctx, fp0, fs);
            gen_helper_float_cvts_pu(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_CVT_PW_PS:
        mips_ident(ctx,
            op1 == OPC_CVT_PW_PS ? MIPS_ID_OPC_CVT_PW_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_helper_float_cvtpw_ps(fp0, tcg_env, fp0);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_CVT_S_PL:
        mips_ident(ctx,
            op1 == OPC_CVT_S_PL ? MIPS_ID_OPC_CVT_S_PL :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_helper_float_cvts_pl(fp0, tcg_env, fp0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_PLL_PS:
        mips_ident(ctx,
            op1 == OPC_PLL_PS ? MIPS_ID_OPC_PLL_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_store_fpr32h(ctx, fp0, fd);
            gen_store_fpr32(ctx, fp1, fd);
        }
        break;
    case OPC_PLU_PS:
        mips_ident(ctx,
            op1 == OPC_PLU_PS ? MIPS_ID_OPC_PLU_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32h(ctx, fp1, ft);
            gen_store_fpr32(ctx, fp1, fd);
            gen_store_fpr32h(ctx, fp0, fd);
        }
        break;
    case OPC_PUL_PS:
        mips_ident(ctx,
            op1 == OPC_PUL_PS ? MIPS_ID_OPC_PUL_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32h(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_store_fpr32(ctx, fp1, fd);
            gen_store_fpr32h(ctx, fp0, fd);
        }
        break;
    case OPC_PUU_PS:
        mips_ident(ctx,
            op1 == OPC_PUU_PS ? MIPS_ID_OPC_PUU_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();

            gen_load_fpr32h(ctx, fp0, fs);
            gen_load_fpr32h(ctx, fp1, ft);
            gen_store_fpr32(ctx, fp1, fd);
            gen_store_fpr32h(ctx, fp0, fd);
        }
        break;
    case OPC_CMP_F_PS:
    case OPC_CMP_UN_PS:
    case OPC_CMP_EQ_PS:
    case OPC_CMP_UEQ_PS:
    case OPC_CMP_OLT_PS:
    case OPC_CMP_ULT_PS:
    case OPC_CMP_OLE_PS:
    case OPC_CMP_ULE_PS:
    case OPC_CMP_SF_PS:
    case OPC_CMP_NGLE_PS:
    case OPC_CMP_SEQ_PS:
    case OPC_CMP_NGL_PS:
    case OPC_CMP_LT_PS:
    case OPC_CMP_NGE_PS:
    case OPC_CMP_LE_PS:
    case OPC_CMP_NGT_PS:
        mips_ident(ctx,
            op1 == OPC_CMP_F_PS ? MIPS_ID_OPC_CMP_F_PS :
            op1 == OPC_CMP_UN_PS ? MIPS_ID_OPC_CMP_UN_PS :
            op1 == OPC_CMP_EQ_PS ? MIPS_ID_OPC_CMP_EQ_PS :
            op1 == OPC_CMP_UEQ_PS ? MIPS_ID_OPC_CMP_UEQ_PS :
            op1 == OPC_CMP_OLT_PS ? MIPS_ID_OPC_CMP_OLT_PS :
            op1 == OPC_CMP_ULT_PS ? MIPS_ID_OPC_CMP_ULT_PS :
            op1 == OPC_CMP_OLE_PS ? MIPS_ID_OPC_CMP_OLE_PS :
            op1 == OPC_CMP_ULE_PS ? MIPS_ID_OPC_CMP_ULE_PS :
            op1 == OPC_CMP_SF_PS ? MIPS_ID_OPC_CMP_SF_PS :
            op1 == OPC_CMP_NGLE_PS ? MIPS_ID_OPC_CMP_NGLE_PS :
            op1 == OPC_CMP_SEQ_PS ? MIPS_ID_OPC_CMP_SEQ_PS :
            op1 == OPC_CMP_NGL_PS ? MIPS_ID_OPC_CMP_NGL_PS :
            op1 == OPC_CMP_LT_PS ? MIPS_ID_OPC_CMP_LT_PS :
            op1 == OPC_CMP_NGE_PS ? MIPS_ID_OPC_CMP_NGE_PS :
            op1 == OPC_CMP_LE_PS ? MIPS_ID_OPC_CMP_LE_PS :
            op1 == OPC_CMP_NGT_PS ? MIPS_ID_OPC_CMP_NGT_PS :
            MIPS_ID_NONE);
        if (ctx->opcode & (1 << 6)) {
            gen_cmpabs_ps(ctx, func - 48, ft, fs, cc);
        } else {
            gen_cmp_ps(ctx, func - 48, ft, fs, cc);
        }
        break;
    default:
        MIPS_INVAL("farith");
        gen_reserved_instruction(ctx);
        return;
    }
}

/* Coprocessor 3 (FPU) */
static void gen_flt3_ldst(DisasContext *ctx, uint32_t opc,
                          int fd, int fs, int base, int index)
{
    TCGv t0 = tcg_temp_new();

    if (base == 0) {
        gen_load_gpr(t0, index);
    } else if (index == 0) {
        gen_load_gpr(t0, base);
    } else {
        gen_op_addr_add(ctx, t0, cpu_gpr[base], cpu_gpr[index]);
    }
    /*
     * Don't do NOP if destination is zero: we must perform the actual
     * memory access.
     */
    switch (opc) {
    case OPC_LWXC1:
        mips_ident(ctx,
            opc == OPC_LWXC1 ? MIPS_ID_OPC_LWXC1 :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();

            tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_SL);
            tcg_gen_trunc_tl_i32(fp0, t0);
            gen_store_fpr32(ctx, fp0, fd);
        }
        break;
    case OPC_LDXC1:
        mips_ident(ctx,
            opc == OPC_LDXC1 ? MIPS_ID_OPC_LDXC1 :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        check_cp1_registers(ctx, fd);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            tcg_gen_qemu_ld_i64(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_LUXC1:
        mips_ident(ctx,
            opc == OPC_LUXC1 ? MIPS_ID_OPC_LUXC1 :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        tcg_gen_andi_tl(t0, t0, ~0x7);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();

            tcg_gen_qemu_ld_i64(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
            gen_store_fpr64(ctx, fp0, fd);
        }
        break;
    case OPC_SWXC1:
        mips_ident(ctx,
            opc == OPC_SWXC1 ? MIPS_ID_OPC_SWXC1 :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            gen_load_fpr32(ctx, fp0, fs);
            tcg_gen_qemu_st_i32(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UL);
        }
        break;
    case OPC_SDXC1:
        mips_ident(ctx,
            opc == OPC_SDXC1 ? MIPS_ID_OPC_SDXC1 :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        check_cp1_registers(ctx, fs);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            tcg_gen_qemu_st_i64(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
        }
        break;
    case OPC_SUXC1:
        mips_ident(ctx,
            opc == OPC_SUXC1 ? MIPS_ID_OPC_SUXC1 :
            MIPS_ID_NONE);
        check_cp1_64bitmode(ctx);
        tcg_gen_andi_tl(t0, t0, ~0x7);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            gen_load_fpr64(ctx, fp0, fs);
            tcg_gen_qemu_st_i64(fp0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
        }
        break;
    }
}

static void gen_flt3_arith(DisasContext *ctx, uint32_t opc,
                           int fd, int fr, int fs, int ft)
{
    switch (opc) {
    case OPC_ALNV_PS:
        mips_ident(ctx,
            opc == OPC_ALNV_PS ? MIPS_ID_OPC_ALNV_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv t0 = tcg_temp_new();
            TCGv_i32 fp = tcg_temp_new_i32();
            TCGv_i32 fph = tcg_temp_new_i32();
            TCGLabel *l1 = gen_new_label();
            TCGLabel *l2 = gen_new_label();

            gen_load_gpr(t0, fr);
            tcg_gen_andi_tl(t0, t0, 0x7);

            tcg_gen_brcondi_tl(TCG_COND_NE, t0, 0, l1);
            gen_load_fpr32(ctx, fp, fs);
            gen_load_fpr32h(ctx, fph, fs);
            gen_store_fpr32(ctx, fp, fd);
            gen_store_fpr32h(ctx, fph, fd);
            tcg_gen_br(l2);
            gen_set_label(l1);
            tcg_gen_brcondi_tl(TCG_COND_NE, t0, 4, l2);
            if (disas_is_bigendian(ctx)) {
                gen_load_fpr32(ctx, fp, fs);
                gen_load_fpr32h(ctx, fph, ft);
                gen_store_fpr32h(ctx, fp, fd);
                gen_store_fpr32(ctx, fph, fd);
            } else {
                gen_load_fpr32h(ctx, fph, fs);
                gen_load_fpr32(ctx, fp, ft);
                gen_store_fpr32(ctx, fph, fd);
                gen_store_fpr32h(ctx, fp, fd);
            }
            gen_set_label(l2);
        }
        break;
    case OPC_MADD_S:
        mips_ident(ctx,
            opc == OPC_MADD_S ? MIPS_ID_OPC_MADD_S :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_load_fpr32(ctx, fp2, fr);
            gen_helper_float_madd_s(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr32(ctx, fp2, fd);
        }
        break;
    case OPC_MADD_D:
        mips_ident(ctx,
            opc == OPC_MADD_D ? MIPS_ID_OPC_MADD_D :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        check_cp1_registers(ctx, fd | fs | ft | fr);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_madd_d(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_MADD_PS:
        mips_ident(ctx,
            opc == OPC_MADD_PS ? MIPS_ID_OPC_MADD_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_madd_ps(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_MSUB_S:
        mips_ident(ctx,
            opc == OPC_MSUB_S ? MIPS_ID_OPC_MSUB_S :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_load_fpr32(ctx, fp2, fr);
            gen_helper_float_msub_s(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr32(ctx, fp2, fd);
        }
        break;
    case OPC_MSUB_D:
        mips_ident(ctx,
            opc == OPC_MSUB_D ? MIPS_ID_OPC_MSUB_D :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        check_cp1_registers(ctx, fd | fs | ft | fr);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_msub_d(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_MSUB_PS:
        mips_ident(ctx,
            opc == OPC_MSUB_PS ? MIPS_ID_OPC_MSUB_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_msub_ps(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_NMADD_S:
        mips_ident(ctx,
            opc == OPC_NMADD_S ? MIPS_ID_OPC_NMADD_S :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_load_fpr32(ctx, fp2, fr);
            gen_helper_float_nmadd_s(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr32(ctx, fp2, fd);
        }
        break;
    case OPC_NMADD_D:
        mips_ident(ctx,
            opc == OPC_NMADD_D ? MIPS_ID_OPC_NMADD_D :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        check_cp1_registers(ctx, fd | fs | ft | fr);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_nmadd_d(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_NMADD_PS:
        mips_ident(ctx,
            opc == OPC_NMADD_PS ? MIPS_ID_OPC_NMADD_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_nmadd_ps(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_NMSUB_S:
        mips_ident(ctx,
            opc == OPC_NMSUB_S ? MIPS_ID_OPC_NMSUB_S :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        {
            TCGv_i32 fp0 = tcg_temp_new_i32();
            TCGv_i32 fp1 = tcg_temp_new_i32();
            TCGv_i32 fp2 = tcg_temp_new_i32();

            gen_load_fpr32(ctx, fp0, fs);
            gen_load_fpr32(ctx, fp1, ft);
            gen_load_fpr32(ctx, fp2, fr);
            gen_helper_float_nmsub_s(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr32(ctx, fp2, fd);
        }
        break;
    case OPC_NMSUB_D:
        mips_ident(ctx,
            opc == OPC_NMSUB_D ? MIPS_ID_OPC_NMSUB_D :
            MIPS_ID_NONE);
        check_cop1x(ctx);
        check_cp1_registers(ctx, fd | fs | ft | fr);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_nmsub_d(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    case OPC_NMSUB_PS:
        mips_ident(ctx,
            opc == OPC_NMSUB_PS ? MIPS_ID_OPC_NMSUB_PS :
            MIPS_ID_NONE);
        check_ps(ctx);
        {
            TCGv_i64 fp0 = tcg_temp_new_i64();
            TCGv_i64 fp1 = tcg_temp_new_i64();
            TCGv_i64 fp2 = tcg_temp_new_i64();

            gen_load_fpr64(ctx, fp0, fs);
            gen_load_fpr64(ctx, fp1, ft);
            gen_load_fpr64(ctx, fp2, fr);
            gen_helper_float_nmsub_ps(fp2, tcg_env, fp0, fp1, fp2);
            gen_store_fpr64(ctx, fp2, fd);
        }
        break;
    default:
        MIPS_INVAL("flt3_arith");
        gen_reserved_instruction(ctx);
        return;
    }
}

void gen_rdhwr(DisasContext *ctx, int rt, int rd, int sel)
{
    TCGv t0;

#if !defined(CONFIG_USER_ONLY)
    /*
     * The Linux kernel will emulate rdhwr if it's not supported natively.
     * Therefore only check the ISA in system mode.
     */
    check_insn(ctx, ISA_MIPS_R2);
#endif
    t0 = tcg_temp_new();

    switch (rd) {
    case 0:
        gen_helper_rdhwr_cpunum(t0, tcg_env);
        gen_store_gpr(t0, rt);
        break;
    case 1:
        gen_helper_rdhwr_synci_step(t0, tcg_env);
        gen_store_gpr(t0, rt);
        break;
    case 2:
        translator_io_start(&ctx->base);
        gen_helper_rdhwr_cc(t0, tcg_env);
        gen_store_gpr(t0, rt);
        /*
         * Break the TB to be able to take timer interrupts immediately
         * after reading count. DISAS_STOP isn't sufficient, we need to ensure
         * we break completely out of translated code.
         */
        gen_save_pc(ctx->base.pc_next + 4);
        ctx->base.is_jmp = DISAS_EXIT;
        break;
    case 3:
        gen_helper_rdhwr_ccres(t0, tcg_env);
        gen_store_gpr(t0, rt);
        break;
    case 4:
        check_insn(ctx, ISA_MIPS_R6);
        if (sel != 0) {
            /*
             * Performance counter registers are not implemented other than
             * control register 0.
             */
            generate_exception(ctx, EXCP_RI);
        }
        gen_helper_rdhwr_performance(t0, tcg_env);
        gen_store_gpr(t0, rt);
        break;
    case 5:
        check_insn(ctx, ISA_MIPS_R6);
        gen_helper_rdhwr_xnp(t0, tcg_env);
        gen_store_gpr(t0, rt);
        break;
    case 29:
#if defined(CONFIG_USER_ONLY)
        tcg_gen_ld_tl(t0, tcg_env,
                      offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
        gen_store_gpr(t0, rt);
        break;
#else
        if ((ctx->hflags & MIPS_HFLAG_CP0) ||
            (ctx->hflags & MIPS_HFLAG_HWRENA_ULR)) {
            tcg_gen_ld_tl(t0, tcg_env,
                          offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
            gen_store_gpr(t0, rt);
        } else {
            gen_reserved_instruction(ctx);
        }
        break;
#endif
    default:            /* Invalid */
        MIPS_INVAL("rdhwr");
        gen_reserved_instruction(ctx);
        break;
    }
}

static inline void clear_branch_hflags(DisasContext *ctx)
{
    ctx->hflags &= ~MIPS_HFLAG_BMASK;
    if (ctx->base.is_jmp == DISAS_NEXT) {
        save_cpu_state(ctx, 0);
    } else {
        /*
         * It is not safe to save ctx->hflags as hflags may be changed
         * in execution time by the instruction in delay / forbidden slot.
         */
        tcg_gen_andi_i32(hflags, hflags, ~MIPS_HFLAG_BMASK);
    }
}

static void gen_branch(DisasContext *ctx, int insn_bytes)
{
    if (ctx->hflags & MIPS_HFLAG_BMASK) {
        int proc_hflags = ctx->hflags & MIPS_HFLAG_BMASK;
        /* Branches completion */
        clear_branch_hflags(ctx);
        ctx->base.is_jmp = DISAS_NORETURN;
        switch (proc_hflags & MIPS_HFLAG_BMASK_BASE) {
        case MIPS_HFLAG_FBNSLOT:
            gen_goto_tb(ctx, 0, ctx->base.pc_next + insn_bytes);
            break;
        case MIPS_HFLAG_B:
            /* unconditional branch */
            if (proc_hflags & MIPS_HFLAG_BX) {
                tcg_gen_xori_i32(hflags, hflags, MIPS_HFLAG_M16);
            }
            gen_goto_tb(ctx, 0, ctx->btarget);
            break;
        case MIPS_HFLAG_BL:
            /* blikely taken case */
            gen_goto_tb(ctx, 0, ctx->btarget);
            break;
        case MIPS_HFLAG_BC:
            /* Conditional branch */
            {
                TCGLabel *l1 = gen_new_label();

                tcg_gen_brcondi_tl(TCG_COND_NE, bcond, 0, l1);
                gen_goto_tb(ctx, 1, ctx->base.pc_next + insn_bytes);
                gen_set_label(l1);
                gen_goto_tb(ctx, 0, ctx->btarget);
            }
            break;
        case MIPS_HFLAG_BR:
            /* unconditional branch to register */
            if (ctx->insn_flags & (ASE_MIPS16 | ASE_MICROMIPS)) {
                TCGv t0 = tcg_temp_new();
                TCGv_i32 t1 = tcg_temp_new_i32();

                tcg_gen_andi_tl(t0, btarget, 0x1);
                tcg_gen_trunc_tl_i32(t1, t0);
                tcg_gen_andi_i32(hflags, hflags, ~(uint32_t)MIPS_HFLAG_M16);
                tcg_gen_shli_i32(t1, t1, MIPS_HFLAG_M16_SHIFT);
                tcg_gen_or_i32(hflags, hflags, t1);

                tcg_gen_andi_tl(cpu_PC, btarget, ~(target_ulong)0x1);
            } else {
                tcg_gen_mov_tl(cpu_PC, btarget);
            }
            tcg_gen_lookup_and_goto_ptr();
            break;
        default:
            LOG_DISAS("unknown branch 0x%x\n", proc_hflags);
            gen_reserved_instruction(ctx);
        }
    }
}

/* Compact Branches */
static void gen_compute_compact_branch(DisasContext *ctx, uint32_t opc,
                                       int rs, int rt, int32_t offset)
{
    int bcond_compute = 0;
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();
    int m16_lowbit = (ctx->hflags & MIPS_HFLAG_M16) != 0;

    if (ctx->hflags & MIPS_HFLAG_BMASK) {
#ifdef MIPS_DEBUG_DISAS
        LOG_DISAS("Branch in delay / forbidden slot at PC 0x%016"
                  VADDR_PRIx "\n", ctx->base.pc_next);
#endif
        gen_reserved_instruction(ctx);
        return;
    }

    /* Load needed operands and calculate btarget */
    switch (opc) {
    /* compact branch */
    case OPC_BOVC: /* OPC_BEQZALC, OPC_BEQC */
    case OPC_BNVC: /* OPC_BNEZALC, OPC_BNEC */
        mips_ident(ctx,
            opc == OPC_BOVC ? MIPS_ID_OPC_BOVC :
            opc == OPC_BNVC ? MIPS_ID_OPC_BNVC :
            MIPS_ID_NONE);
        gen_load_gpr(t0, rs);
        gen_load_gpr(t1, rt);
        bcond_compute = 1;
        ctx->btarget = addr_add(ctx, ctx->base.pc_next + 4, offset);
        plugin_gen_record_branch_target((uint64_t)ctx->btarget);
        if (rs <= rt && rs == 0) {
            /* OPC_BEQZALC, OPC_BNEZALC */
            tcg_gen_movi_tl(cpu_gpr[31], ctx->base.pc_next + 4 + m16_lowbit);
        }
        break;
    case OPC_BLEZC: /* OPC_BGEZC, OPC_BGEC */
    case OPC_BGTZC: /* OPC_BLTZC, OPC_BLTC */
        mips_ident(ctx,
            opc == OPC_BLEZC ? MIPS_ID_OPC_BLEZC :
            opc == OPC_BGTZC ? MIPS_ID_OPC_BGTZC :
            MIPS_ID_NONE);
        gen_load_gpr(t0, rs);
        gen_load_gpr(t1, rt);
        bcond_compute = 1;
        ctx->btarget = addr_add(ctx, ctx->base.pc_next + 4, offset);
        plugin_gen_record_branch_target((uint64_t)ctx->btarget);
        break;
    case OPC_BLEZALC: /* OPC_BGEZALC, OPC_BGEUC */
    case OPC_BGTZALC: /* OPC_BLTZALC, OPC_BLTUC */
        mips_ident(ctx,
            opc == OPC_BLEZALC ? MIPS_ID_OPC_BLEZALC :
            opc == OPC_BGTZALC ? MIPS_ID_OPC_BGTZALC :
            MIPS_ID_NONE);
        if (rs == 0 || rs == rt) {
            /* OPC_BLEZALC, OPC_BGEZALC */
            /* OPC_BGTZALC, OPC_BLTZALC */
            tcg_gen_movi_tl(cpu_gpr[31], ctx->base.pc_next + 4 + m16_lowbit);
        }
        gen_load_gpr(t0, rs);
        gen_load_gpr(t1, rt);
        bcond_compute = 1;
        ctx->btarget = addr_add(ctx, ctx->base.pc_next + 4, offset);
        plugin_gen_record_branch_target((uint64_t)ctx->btarget);
        break;
    case OPC_BC:
    case OPC_BALC:
        mips_ident(ctx,
            opc == OPC_BC ? MIPS_ID_OPC_BC :
            opc == OPC_BALC ? MIPS_ID_OPC_BALC :
            MIPS_ID_NONE);
        ctx->btarget = addr_add(ctx, ctx->base.pc_next + 4, offset);
        plugin_gen_record_branch_target((uint64_t)ctx->btarget);
        break;
    case OPC_BEQZC:
    case OPC_BNEZC:
        mips_ident(ctx,
            opc == OPC_BEQZC ? MIPS_ID_OPC_BEQZC :
            opc == OPC_BNEZC ? MIPS_ID_OPC_BNEZC :
            MIPS_ID_NONE);
        if (rs != 0) {
            /* OPC_BEQZC, OPC_BNEZC */
            gen_load_gpr(t0, rs);
            bcond_compute = 1;
            ctx->btarget = addr_add(ctx, ctx->base.pc_next + 4, offset);
            plugin_gen_record_branch_target((uint64_t)ctx->btarget);
        } else {
            /* OPC_JIC, OPC_JIALC */
            TCGv tbase = tcg_temp_new();

            gen_load_gpr(tbase, rt);
            gen_op_addr_addi(ctx, btarget, tbase, offset);
        }
        break;
    default:
        MIPS_INVAL("Compact branch/jump");
        gen_reserved_instruction(ctx);
        return;
    }

    if (bcond_compute == 0) {
        /* Unconditional compact branch */
        switch (opc) {
        case OPC_JIALC:
            mips_ident(ctx,
                opc == OPC_JIALC ? MIPS_ID_OPC_JIALC :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(cpu_gpr[31], ctx->base.pc_next + 4 + m16_lowbit);
            /* Fallthrough */
        case OPC_JIC:
            mips_ident(ctx,
                opc == OPC_JIC ? MIPS_ID_OPC_JIC :
                MIPS_ID_NONE);
            ctx->hflags |= MIPS_HFLAG_BR;
            break;
        case OPC_BALC:
            mips_ident(ctx,
                opc == OPC_BALC ? MIPS_ID_OPC_BALC :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(cpu_gpr[31], ctx->base.pc_next + 4 + m16_lowbit);
            /* Fallthrough */
        case OPC_BC:
            mips_ident(ctx,
                opc == OPC_BC ? MIPS_ID_OPC_BC :
                MIPS_ID_NONE);
            ctx->hflags |= MIPS_HFLAG_B;
            break;
        default:
            MIPS_INVAL("Compact branch/jump");
            gen_reserved_instruction(ctx);
            return;
        }

        /* Generating branch here as compact branches don't have delay slot */
        gen_branch(ctx, 4);
    } else {
        /* Conditional compact branch */
        TCGLabel *fs = gen_new_label();
        save_cpu_state(ctx, 0);

        switch (opc) {
        case OPC_BLEZALC: /* OPC_BGEZALC, OPC_BGEUC */
            mips_ident(ctx,
                opc == OPC_BLEZALC ? MIPS_ID_OPC_BLEZALC :
                MIPS_ID_NONE);
            if (rs == 0 && rt != 0) {
                /* OPC_BLEZALC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_LE), t1, 0, fs);
            } else if (rs != 0 && rt != 0 && rs == rt) {
                /* OPC_BGEZALC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_GE), t1, 0, fs);
            } else {
                /* OPC_BGEUC */
                tcg_gen_brcond_tl(tcg_invert_cond(TCG_COND_GEU), t0, t1, fs);
            }
            break;
        case OPC_BGTZALC: /* OPC_BLTZALC, OPC_BLTUC */
            mips_ident(ctx,
                opc == OPC_BGTZALC ? MIPS_ID_OPC_BGTZALC :
                MIPS_ID_NONE);
            if (rs == 0 && rt != 0) {
                /* OPC_BGTZALC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_GT), t1, 0, fs);
            } else if (rs != 0 && rt != 0 && rs == rt) {
                /* OPC_BLTZALC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_LT), t1, 0, fs);
            } else {
                /* OPC_BLTUC */
                tcg_gen_brcond_tl(tcg_invert_cond(TCG_COND_LTU), t0, t1, fs);
            }
            break;
        case OPC_BLEZC: /* OPC_BGEZC, OPC_BGEC */
            mips_ident(ctx,
                opc == OPC_BLEZC ? MIPS_ID_OPC_BLEZC :
                MIPS_ID_NONE);
            if (rs == 0 && rt != 0) {
                /* OPC_BLEZC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_LE), t1, 0, fs);
            } else if (rs != 0 && rt != 0 && rs == rt) {
                /* OPC_BGEZC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_GE), t1, 0, fs);
            } else {
                /* OPC_BGEC */
                tcg_gen_brcond_tl(tcg_invert_cond(TCG_COND_GE), t0, t1, fs);
            }
            break;
        case OPC_BGTZC: /* OPC_BLTZC, OPC_BLTC */
            mips_ident(ctx,
                opc == OPC_BGTZC ? MIPS_ID_OPC_BGTZC :
                MIPS_ID_NONE);
            if (rs == 0 && rt != 0) {
                /* OPC_BGTZC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_GT), t1, 0, fs);
            } else if (rs != 0 && rt != 0 && rs == rt) {
                /* OPC_BLTZC */
                tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_LT), t1, 0, fs);
            } else {
                /* OPC_BLTC */
                tcg_gen_brcond_tl(tcg_invert_cond(TCG_COND_LT), t0, t1, fs);
            }
            break;
        case OPC_BOVC: /* OPC_BEQZALC, OPC_BEQC */
        case OPC_BNVC: /* OPC_BNEZALC, OPC_BNEC */
            mips_ident(ctx,
                opc == OPC_BOVC ? MIPS_ID_OPC_BOVC :
                opc == OPC_BNVC ? MIPS_ID_OPC_BNVC :
                MIPS_ID_NONE);
            if (rs >= rt) {
                /* OPC_BOVC, OPC_BNVC */
                TCGv t2 = tcg_temp_new();
                TCGv t3 = tcg_temp_new();
                TCGv t4 = tcg_temp_new();
                TCGv input_overflow = tcg_temp_new();

                gen_load_gpr(t0, rs);
                gen_load_gpr(t1, rt);
                tcg_gen_ext32s_tl(t2, t0);
                tcg_gen_setcond_tl(TCG_COND_NE, input_overflow, t2, t0);
                tcg_gen_ext32s_tl(t3, t1);
                tcg_gen_setcond_tl(TCG_COND_NE, t4, t3, t1);
                tcg_gen_or_tl(input_overflow, input_overflow, t4);

                tcg_gen_add_tl(t4, t2, t3);
                tcg_gen_ext32s_tl(t4, t4);
                tcg_gen_xor_tl(t2, t2, t3);
                tcg_gen_xor_tl(t3, t4, t3);
                tcg_gen_andc_tl(t2, t3, t2);
                tcg_gen_setcondi_tl(TCG_COND_LT, t4, t2, 0);
                tcg_gen_or_tl(t4, t4, input_overflow);
                if (opc == OPC_BOVC) {
                    /* OPC_BOVC */
                    tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_NE), t4, 0, fs);
                } else {
                    /* OPC_BNVC */
                    tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_EQ), t4, 0, fs);
                }
            } else if (rs < rt && rs == 0) {
                /* OPC_BEQZALC, OPC_BNEZALC */
                if (opc == OPC_BEQZALC) {
                    /* OPC_BEQZALC */
                    tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_EQ), t1, 0, fs);
                } else {
                    /* OPC_BNEZALC */
                    tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_NE), t1, 0, fs);
                }
            } else {
                /* OPC_BEQC, OPC_BNEC */
                if (opc == OPC_BEQC) {
                    /* OPC_BEQC */
                    tcg_gen_brcond_tl(tcg_invert_cond(TCG_COND_EQ), t0, t1, fs);
                } else {
                    /* OPC_BNEC */
                    tcg_gen_brcond_tl(tcg_invert_cond(TCG_COND_NE), t0, t1, fs);
                }
            }
            break;
        case OPC_BEQZC:
            mips_ident(ctx,
                opc == OPC_BEQZC ? MIPS_ID_OPC_BEQZC :
                MIPS_ID_NONE);
            tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_EQ), t0, 0, fs);
            break;
        case OPC_BNEZC:
            mips_ident(ctx,
                opc == OPC_BNEZC ? MIPS_ID_OPC_BNEZC :
                MIPS_ID_NONE);
            tcg_gen_brcondi_tl(tcg_invert_cond(TCG_COND_NE), t0, 0, fs);
            break;
        default:
            MIPS_INVAL("Compact conditional branch/jump");
            gen_reserved_instruction(ctx);
            return;
        }

        /* Generating branch here as compact branches don't have delay slot */
        gen_goto_tb(ctx, 1, ctx->btarget);
        gen_set_label(fs);

        ctx->hflags |= MIPS_HFLAG_FBNSLOT;
    }
}

void gen_addiupc(DisasContext *ctx, int rx, int imm,
                 int is_64_bit, int extended)
{
    target_ulong npc;

    if (extended && (ctx->hflags & MIPS_HFLAG_BMASK)) {
        gen_reserved_instruction(ctx);
        return;
    }

    npc = pc_relative_pc(ctx) + imm;
    if (!is_64_bit) {
        npc = (int32_t)npc;
    }
    tcg_gen_movi_tl(cpu_gpr[rx], npc);
}

static void gen_cache_operation(DisasContext *ctx, uint32_t op, int base,
                                int16_t offset)
{
    TCGv_i32 t0 = tcg_constant_i32(op);
    TCGv t1 = tcg_temp_new();
    gen_base_offset_addr(ctx, t1, base, offset);
    gen_helper_cache(tcg_env, t1, t0);
}

static inline bool is_uhi(DisasContext *ctx, int sdbbp_code)
{
#ifdef CONFIG_USER_ONLY
    return false;
#else
    bool is_user = (ctx->hflags & MIPS_HFLAG_KSU) == MIPS_HFLAG_UM;
    return semihosting_enabled(is_user) && sdbbp_code == 1;
#endif
}

void gen_ldxs(DisasContext *ctx, int base, int index, int rd)
{
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();

    gen_load_gpr(t0, base);

    if (index != 0) {
        gen_load_gpr(t1, index);
        tcg_gen_shli_tl(t1, t1, 2);
        gen_op_addr_add(ctx, t0, t1, t0);
    }

    tcg_gen_qemu_ld_tl(t1, t0, ctx->mem_idx, mo_endian(ctx) | MO_SL);
    gen_store_gpr(t1, rd);
}

static void gen_sync(int stype)
{
    TCGBar tcg_mo = TCG_BAR_SC;

    switch (stype) {
    case 0x4: /* SYNC_WMB */
        tcg_mo |= TCG_MO_ST_ST;
        break;
    case 0x10: /* SYNC_MB */
        tcg_mo |= TCG_MO_ALL;
        break;
    case 0x11: /* SYNC_ACQUIRE */
        tcg_mo |= TCG_MO_LD_LD | TCG_MO_LD_ST;
        break;
    case 0x12: /* SYNC_RELEASE */
        tcg_mo |= TCG_MO_ST_ST | TCG_MO_LD_ST;
        break;
    case 0x13: /* SYNC_RMB */
        tcg_mo |= TCG_MO_LD_LD;
        break;
    default:
        tcg_mo |= TCG_MO_ALL;
        break;
    }

    tcg_gen_mb(tcg_mo);
}

/* ISA extensions (ASEs) */

/* MIPS16 extension to MIPS32 */
#include "mips16e_translate.c.inc"

/* microMIPS extension to MIPS32/MIPS64 */

/*
 * Values for microMIPS fmt field.  Variable-width, depending on which
 * formats the instruction supports.
 */
enum {
    FMT_SD_S = 0,
    FMT_SD_D = 1,

    FMT_SDPS_S = 0,
    FMT_SDPS_D = 1,
    FMT_SDPS_PS = 2,

    FMT_SWL_S = 0,
    FMT_SWL_W = 1,
    FMT_SWL_L = 2,

    FMT_DWL_D = 0,
    FMT_DWL_W = 1,
    FMT_DWL_L = 2
};

#include "micromips_translate.c.inc"

#include "nanomips_translate.c.inc"

/* MIPSDSP functions. */

/* Indexed load is not for DSP only */
static void gen_mips_lx(DisasContext *ctx, uint32_t opc,
                        int rd, int base, int offset)
{
    TCGv t0;

    if (!(ctx->insn_flags & INSN_OCTEON)) {
        check_dsp(ctx);
    }
    t0 = tcg_temp_new();

    if (base == 0) {
        gen_load_gpr(t0, offset);
    } else if (offset == 0) {
        gen_load_gpr(t0, base);
    } else {
        gen_op_addr_add(ctx, t0, cpu_gpr[base], cpu_gpr[offset]);
    }

    switch (opc) {
    case OPC_LBUX:
        mips_ident(ctx,
            opc == OPC_LBUX ? MIPS_ID_OPC_LBUX :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, MO_UB);
        gen_store_gpr(t0, rd);
        break;
    case OPC_LHX:
        mips_ident(ctx,
            opc == OPC_LHX ? MIPS_ID_OPC_LHX :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_SW);
        gen_store_gpr(t0, rd);
        break;
    case OPC_LWX:
        mips_ident(ctx,
            opc == OPC_LWX ? MIPS_ID_OPC_LWX :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_SL);
        gen_store_gpr(t0, rd);
        break;
#if defined(TARGET_MIPS64)
    case OPC_LDX:
        mips_ident(ctx,
            opc == OPC_LDX ? MIPS_ID_OPC_LDX :
            MIPS_ID_NONE);
        tcg_gen_qemu_ld_tl(t0, t0, ctx->mem_idx, mo_endian(ctx) | MO_UQ);
        gen_store_gpr(t0, rd);
        break;
#endif
    }
}

static void gen_mipsdsp_arith(DisasContext *ctx, uint32_t op1, uint32_t op2,
                              int ret, int v1, int v2)
{
    TCGv v1_t;
    TCGv v2_t;

    if (ret == 0) {
        /* Treat as NOP. */
        return;
    }

    v1_t = tcg_temp_new();
    v2_t = tcg_temp_new();

    gen_load_gpr(v1_t, v1);
    gen_load_gpr(v2_t, v2);

    switch (op1) {
    case OPC_ADDUH_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_ADDUH_QB_DSP ? MIPS_ID_OPC_ADDUH_QB_DSP :
            MIPS_ID_NONE);
        check_dsp_r2(ctx);
        switch (op2) {
        case OPC_ADDUH_QB:
            mips_ident(ctx,
                op2 == OPC_ADDUH_QB ? MIPS_ID_OPC_ADDUH_QB :
                MIPS_ID_NONE);
            gen_helper_adduh_qb(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_ADDUH_R_QB:
            mips_ident(ctx,
                op2 == OPC_ADDUH_R_QB ? MIPS_ID_OPC_ADDUH_R_QB :
                MIPS_ID_NONE);
            gen_helper_adduh_r_qb(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_ADDQH_PH:
            mips_ident(ctx,
                op2 == OPC_ADDQH_PH ? MIPS_ID_OPC_ADDQH_PH :
                MIPS_ID_NONE);
            gen_helper_addqh_ph(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_ADDQH_R_PH:
            mips_ident(ctx,
                op2 == OPC_ADDQH_R_PH ? MIPS_ID_OPC_ADDQH_R_PH :
                MIPS_ID_NONE);
            gen_helper_addqh_r_ph(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_ADDQH_W:
            mips_ident(ctx,
                op2 == OPC_ADDQH_W ? MIPS_ID_OPC_ADDQH_W :
                MIPS_ID_NONE);
            gen_helper_addqh_w(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_ADDQH_R_W:
            mips_ident(ctx,
                op2 == OPC_ADDQH_R_W ? MIPS_ID_OPC_ADDQH_R_W :
                MIPS_ID_NONE);
            gen_helper_addqh_r_w(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_SUBUH_QB:
            mips_ident(ctx,
                op2 == OPC_SUBUH_QB ? MIPS_ID_OPC_SUBUH_QB :
                MIPS_ID_NONE);
            gen_helper_subuh_qb(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_SUBUH_R_QB:
            mips_ident(ctx,
                op2 == OPC_SUBUH_R_QB ? MIPS_ID_OPC_SUBUH_R_QB :
                MIPS_ID_NONE);
            gen_helper_subuh_r_qb(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_SUBQH_PH:
            mips_ident(ctx,
                op2 == OPC_SUBQH_PH ? MIPS_ID_OPC_SUBQH_PH :
                MIPS_ID_NONE);
            gen_helper_subqh_ph(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_SUBQH_R_PH:
            mips_ident(ctx,
                op2 == OPC_SUBQH_R_PH ? MIPS_ID_OPC_SUBQH_R_PH :
                MIPS_ID_NONE);
            gen_helper_subqh_r_ph(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_SUBQH_W:
            mips_ident(ctx,
                op2 == OPC_SUBQH_W ? MIPS_ID_OPC_SUBQH_W :
                MIPS_ID_NONE);
            gen_helper_subqh_w(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_SUBQH_R_W:
            mips_ident(ctx,
                op2 == OPC_SUBQH_R_W ? MIPS_ID_OPC_SUBQH_R_W :
                MIPS_ID_NONE);
            gen_helper_subqh_r_w(cpu_gpr[ret], v1_t, v2_t);
            break;
        }
        break;
    case OPC_ABSQ_S_PH_DSP:
        mips_ident(ctx,
            op1 == OPC_ABSQ_S_PH_DSP ? MIPS_ID_OPC_ABSQ_S_PH_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_ABSQ_S_QB:
            mips_ident(ctx,
                op2 == OPC_ABSQ_S_QB ? MIPS_ID_OPC_ABSQ_S_QB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_absq_s_qb(cpu_gpr[ret], v2_t, tcg_env);
            break;
        case OPC_ABSQ_S_PH:
            mips_ident(ctx,
                op2 == OPC_ABSQ_S_PH ? MIPS_ID_OPC_ABSQ_S_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_absq_s_ph(cpu_gpr[ret], v2_t, tcg_env);
            break;
        case OPC_ABSQ_S_W:
            mips_ident(ctx,
                op2 == OPC_ABSQ_S_W ? MIPS_ID_OPC_ABSQ_S_W :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_absq_s_w(cpu_gpr[ret], v2_t, tcg_env);
            break;
        case OPC_PRECEQ_W_PHL:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_W_PHL ? MIPS_ID_OPC_PRECEQ_W_PHL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_andi_tl(cpu_gpr[ret], v2_t, 0xFFFF0000);
            tcg_gen_ext32s_tl(cpu_gpr[ret], cpu_gpr[ret]);
            break;
        case OPC_PRECEQ_W_PHR:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_W_PHR ? MIPS_ID_OPC_PRECEQ_W_PHR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_andi_tl(cpu_gpr[ret], v2_t, 0x0000FFFF);
            tcg_gen_shli_tl(cpu_gpr[ret], cpu_gpr[ret], 16);
            tcg_gen_ext32s_tl(cpu_gpr[ret], cpu_gpr[ret]);
            break;
        case OPC_PRECEQU_PH_QBL:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_PH_QBL ? MIPS_ID_OPC_PRECEQU_PH_QBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_ph_qbl(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQU_PH_QBR:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_PH_QBR ? MIPS_ID_OPC_PRECEQU_PH_QBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_ph_qbr(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQU_PH_QBLA:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_PH_QBLA ? MIPS_ID_OPC_PRECEQU_PH_QBLA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_ph_qbla(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQU_PH_QBRA:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_PH_QBRA ? MIPS_ID_OPC_PRECEQU_PH_QBRA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_ph_qbra(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_PH_QBL:
            mips_ident(ctx,
                op2 == OPC_PRECEU_PH_QBL ? MIPS_ID_OPC_PRECEU_PH_QBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_ph_qbl(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_PH_QBR:
            mips_ident(ctx,
                op2 == OPC_PRECEU_PH_QBR ? MIPS_ID_OPC_PRECEU_PH_QBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_ph_qbr(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_PH_QBLA:
            mips_ident(ctx,
                op2 == OPC_PRECEU_PH_QBLA ? MIPS_ID_OPC_PRECEU_PH_QBLA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_ph_qbla(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_PH_QBRA:
            mips_ident(ctx,
                op2 == OPC_PRECEU_PH_QBRA ? MIPS_ID_OPC_PRECEU_PH_QBRA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_ph_qbra(cpu_gpr[ret], v2_t);
            break;
        }
        break;
    case OPC_ADDU_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_ADDU_QB_DSP ? MIPS_ID_OPC_ADDU_QB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_ADDQ_PH:
            mips_ident(ctx,
                op2 == OPC_ADDQ_PH ? MIPS_ID_OPC_ADDQ_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addq_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDQ_S_PH:
            mips_ident(ctx,
                op2 == OPC_ADDQ_S_PH ? MIPS_ID_OPC_ADDQ_S_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addq_s_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDQ_S_W:
            mips_ident(ctx,
                op2 == OPC_ADDQ_S_W ? MIPS_ID_OPC_ADDQ_S_W :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addq_s_w(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_QB:
            mips_ident(ctx,
                op2 == OPC_ADDU_QB ? MIPS_ID_OPC_ADDU_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addu_qb(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_S_QB:
            mips_ident(ctx,
                op2 == OPC_ADDU_S_QB ? MIPS_ID_OPC_ADDU_S_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addu_s_qb(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_PH:
            mips_ident(ctx,
                op2 == OPC_ADDU_PH ? MIPS_ID_OPC_ADDU_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_addu_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_S_PH:
            mips_ident(ctx,
                op2 == OPC_ADDU_S_PH ? MIPS_ID_OPC_ADDU_S_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_addu_s_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBQ_PH:
            mips_ident(ctx,
                op2 == OPC_SUBQ_PH ? MIPS_ID_OPC_SUBQ_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subq_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBQ_S_PH:
            mips_ident(ctx,
                op2 == OPC_SUBQ_S_PH ? MIPS_ID_OPC_SUBQ_S_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subq_s_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBQ_S_W:
            mips_ident(ctx,
                op2 == OPC_SUBQ_S_W ? MIPS_ID_OPC_SUBQ_S_W :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subq_s_w(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_QB:
            mips_ident(ctx,
                op2 == OPC_SUBU_QB ? MIPS_ID_OPC_SUBU_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subu_qb(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_S_QB:
            mips_ident(ctx,
                op2 == OPC_SUBU_S_QB ? MIPS_ID_OPC_SUBU_S_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subu_s_qb(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_PH:
            mips_ident(ctx,
                op2 == OPC_SUBU_PH ? MIPS_ID_OPC_SUBU_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_subu_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_S_PH:
            mips_ident(ctx,
                op2 == OPC_SUBU_S_PH ? MIPS_ID_OPC_SUBU_S_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_subu_s_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDSC:
            mips_ident(ctx,
                op2 == OPC_ADDSC ? MIPS_ID_OPC_ADDSC :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addsc(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDWC:
            mips_ident(ctx,
                op2 == OPC_ADDWC ? MIPS_ID_OPC_ADDWC :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addwc(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MODSUB:
            mips_ident(ctx,
                op2 == OPC_MODSUB ? MIPS_ID_OPC_MODSUB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_modsub(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_RADDU_W_QB:
            mips_ident(ctx,
                op2 == OPC_RADDU_W_QB ? MIPS_ID_OPC_RADDU_W_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_raddu_w_qb(cpu_gpr[ret], v1_t);
            break;
        }
        break;
    case OPC_CMPU_EQ_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_CMPU_EQ_QB_DSP ? MIPS_ID_OPC_CMPU_EQ_QB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_PRECR_QB_PH:
            mips_ident(ctx,
                op2 == OPC_PRECR_QB_PH ? MIPS_ID_OPC_PRECR_QB_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_precr_qb_ph(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PRECRQ_QB_PH:
            mips_ident(ctx,
                op2 == OPC_PRECRQ_QB_PH ? MIPS_ID_OPC_PRECRQ_QB_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrq_qb_ph(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PRECR_SRA_PH_W:
            mips_ident(ctx,
                op2 == OPC_PRECR_SRA_PH_W ? MIPS_ID_OPC_PRECR_SRA_PH_W :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            {
                TCGv_i32 sa_t = tcg_constant_i32(v2);
                gen_helper_precr_sra_ph_w(cpu_gpr[ret], sa_t, v1_t,
                                          cpu_gpr[ret]);
                break;
            }
        case OPC_PRECR_SRA_R_PH_W:
            mips_ident(ctx,
                op2 == OPC_PRECR_SRA_R_PH_W ? MIPS_ID_OPC_PRECR_SRA_R_PH_W :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            {
                TCGv_i32 sa_t = tcg_constant_i32(v2);
                gen_helper_precr_sra_r_ph_w(cpu_gpr[ret], sa_t, v1_t,
                                            cpu_gpr[ret]);
                break;
            }
        case OPC_PRECRQ_PH_W:
            mips_ident(ctx,
                op2 == OPC_PRECRQ_PH_W ? MIPS_ID_OPC_PRECRQ_PH_W :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrq_ph_w(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PRECRQ_RS_PH_W:
            mips_ident(ctx,
                op2 == OPC_PRECRQ_RS_PH_W ? MIPS_ID_OPC_PRECRQ_RS_PH_W :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrq_rs_ph_w(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_PRECRQU_S_QB_PH:
            mips_ident(ctx,
                op2 == OPC_PRECRQU_S_QB_PH ? MIPS_ID_OPC_PRECRQU_S_QB_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrqu_s_qb_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        }
        break;
#ifdef TARGET_MIPS64
    case OPC_ABSQ_S_QH_DSP:
        mips_ident(ctx,
            op1 == OPC_ABSQ_S_QH_DSP ? MIPS_ID_OPC_ABSQ_S_QH_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_PRECEQ_L_PWL:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_L_PWL ? MIPS_ID_OPC_PRECEQ_L_PWL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_andi_tl(cpu_gpr[ret], v2_t, 0xFFFFFFFF00000000ull);
            break;
        case OPC_PRECEQ_L_PWR:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_L_PWR ? MIPS_ID_OPC_PRECEQ_L_PWR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_shli_tl(cpu_gpr[ret], v2_t, 32);
            break;
        case OPC_PRECEQ_PW_QHL:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_PW_QHL ? MIPS_ID_OPC_PRECEQ_PW_QHL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceq_pw_qhl(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQ_PW_QHR:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_PW_QHR ? MIPS_ID_OPC_PRECEQ_PW_QHR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceq_pw_qhr(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQ_PW_QHLA:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_PW_QHLA ? MIPS_ID_OPC_PRECEQ_PW_QHLA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceq_pw_qhla(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQ_PW_QHRA:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_PW_QHRA ? MIPS_ID_OPC_PRECEQ_PW_QHRA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceq_pw_qhra(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQU_QH_OBL:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_QH_OBL ? MIPS_ID_OPC_PRECEQU_QH_OBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_qh_obl(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQU_QH_OBR:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_QH_OBR ? MIPS_ID_OPC_PRECEQU_QH_OBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_qh_obr(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQU_QH_OBLA:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_QH_OBLA ? MIPS_ID_OPC_PRECEQU_QH_OBLA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_qh_obla(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEQU_QH_OBRA:
            mips_ident(ctx,
                op2 == OPC_PRECEQU_QH_OBRA ? MIPS_ID_OPC_PRECEQU_QH_OBRA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precequ_qh_obra(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_QH_OBL:
            mips_ident(ctx,
                op2 == OPC_PRECEU_QH_OBL ? MIPS_ID_OPC_PRECEU_QH_OBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_qh_obl(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_QH_OBR:
            mips_ident(ctx,
                op2 == OPC_PRECEU_QH_OBR ? MIPS_ID_OPC_PRECEU_QH_OBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_qh_obr(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_QH_OBLA:
            mips_ident(ctx,
                op2 == OPC_PRECEU_QH_OBLA ? MIPS_ID_OPC_PRECEU_QH_OBLA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_qh_obla(cpu_gpr[ret], v2_t);
            break;
        case OPC_PRECEU_QH_OBRA:
            mips_ident(ctx,
                op2 == OPC_PRECEU_QH_OBRA ? MIPS_ID_OPC_PRECEU_QH_OBRA :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_preceu_qh_obra(cpu_gpr[ret], v2_t);
            break;
        case OPC_ABSQ_S_OB:
            mips_ident(ctx,
                op2 == OPC_ABSQ_S_OB ? MIPS_ID_OPC_ABSQ_S_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_absq_s_ob(cpu_gpr[ret], v2_t, tcg_env);
            break;
        case OPC_ABSQ_S_PW:
            mips_ident(ctx,
                op2 == OPC_ABSQ_S_PW ? MIPS_ID_OPC_ABSQ_S_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_absq_s_pw(cpu_gpr[ret], v2_t, tcg_env);
            break;
        case OPC_ABSQ_S_QH:
            mips_ident(ctx,
                op2 == OPC_ABSQ_S_QH ? MIPS_ID_OPC_ABSQ_S_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_absq_s_qh(cpu_gpr[ret], v2_t, tcg_env);
            break;
        }
        break;
    case OPC_ADDU_OB_DSP:
        mips_ident(ctx,
            op1 == OPC_ADDU_OB_DSP ? MIPS_ID_OPC_ADDU_OB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_RADDU_L_OB:
            mips_ident(ctx,
                op2 == OPC_RADDU_L_OB ? MIPS_ID_OPC_RADDU_L_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_raddu_l_ob(cpu_gpr[ret], v1_t);
            break;
        case OPC_SUBQ_PW:
            mips_ident(ctx,
                op2 == OPC_SUBQ_PW ? MIPS_ID_OPC_SUBQ_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subq_pw(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBQ_S_PW:
            mips_ident(ctx,
                op2 == OPC_SUBQ_S_PW ? MIPS_ID_OPC_SUBQ_S_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subq_s_pw(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBQ_QH:
            mips_ident(ctx,
                op2 == OPC_SUBQ_QH ? MIPS_ID_OPC_SUBQ_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subq_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBQ_S_QH:
            mips_ident(ctx,
                op2 == OPC_SUBQ_S_QH ? MIPS_ID_OPC_SUBQ_S_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subq_s_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_OB:
            mips_ident(ctx,
                op2 == OPC_SUBU_OB ? MIPS_ID_OPC_SUBU_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subu_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_S_OB:
            mips_ident(ctx,
                op2 == OPC_SUBU_S_OB ? MIPS_ID_OPC_SUBU_S_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_subu_s_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_QH:
            mips_ident(ctx,
                op2 == OPC_SUBU_QH ? MIPS_ID_OPC_SUBU_QH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_subu_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBU_S_QH:
            mips_ident(ctx,
                op2 == OPC_SUBU_S_QH ? MIPS_ID_OPC_SUBU_S_QH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_subu_s_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_SUBUH_OB:
            mips_ident(ctx,
                op2 == OPC_SUBUH_OB ? MIPS_ID_OPC_SUBUH_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_subuh_ob(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_SUBUH_R_OB:
            mips_ident(ctx,
                op2 == OPC_SUBUH_R_OB ? MIPS_ID_OPC_SUBUH_R_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_subuh_r_ob(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_ADDQ_PW:
            mips_ident(ctx,
                op2 == OPC_ADDQ_PW ? MIPS_ID_OPC_ADDQ_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addq_pw(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDQ_S_PW:
            mips_ident(ctx,
                op2 == OPC_ADDQ_S_PW ? MIPS_ID_OPC_ADDQ_S_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addq_s_pw(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDQ_QH:
            mips_ident(ctx,
                op2 == OPC_ADDQ_QH ? MIPS_ID_OPC_ADDQ_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addq_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDQ_S_QH:
            mips_ident(ctx,
                op2 == OPC_ADDQ_S_QH ? MIPS_ID_OPC_ADDQ_S_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addq_s_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_OB:
            mips_ident(ctx,
                op2 == OPC_ADDU_OB ? MIPS_ID_OPC_ADDU_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addu_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_S_OB:
            mips_ident(ctx,
                op2 == OPC_ADDU_S_OB ? MIPS_ID_OPC_ADDU_S_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_addu_s_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_QH:
            mips_ident(ctx,
                op2 == OPC_ADDU_QH ? MIPS_ID_OPC_ADDU_QH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_addu_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDU_S_QH:
            mips_ident(ctx,
                op2 == OPC_ADDU_S_QH ? MIPS_ID_OPC_ADDU_S_QH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_addu_s_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_ADDUH_OB:
            mips_ident(ctx,
                op2 == OPC_ADDUH_OB ? MIPS_ID_OPC_ADDUH_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_adduh_ob(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_ADDUH_R_OB:
            mips_ident(ctx,
                op2 == OPC_ADDUH_R_OB ? MIPS_ID_OPC_ADDUH_R_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_adduh_r_ob(cpu_gpr[ret], v1_t, v2_t);
            break;
        }
        break;
    case OPC_CMPU_EQ_OB_DSP:
        mips_ident(ctx,
            op1 == OPC_CMPU_EQ_OB_DSP ? MIPS_ID_OPC_CMPU_EQ_OB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_PRECR_OB_QH:
            mips_ident(ctx,
                op2 == OPC_PRECR_OB_QH ? MIPS_ID_OPC_PRECR_OB_QH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_precr_ob_qh(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PRECR_SRA_QH_PW:
            mips_ident(ctx,
                op2 == OPC_PRECR_SRA_QH_PW ? MIPS_ID_OPC_PRECR_SRA_QH_PW :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            {
                TCGv_i32 ret_t = tcg_constant_i32(ret);
                gen_helper_precr_sra_qh_pw(v2_t, v1_t, v2_t, ret_t);
                break;
            }
        case OPC_PRECR_SRA_R_QH_PW:
            mips_ident(ctx,
                op2 == OPC_PRECR_SRA_R_QH_PW ? MIPS_ID_OPC_PRECR_SRA_R_QH_PW :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            {
                TCGv_i32 sa_v = tcg_constant_i32(ret);
                gen_helper_precr_sra_r_qh_pw(v2_t, v1_t, v2_t, sa_v);
                break;
            }
        case OPC_PRECRQ_OB_QH:
            mips_ident(ctx,
                op2 == OPC_PRECRQ_OB_QH ? MIPS_ID_OPC_PRECRQ_OB_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrq_ob_qh(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PRECRQ_PW_L:
            mips_ident(ctx,
                op2 == OPC_PRECRQ_PW_L ? MIPS_ID_OPC_PRECRQ_PW_L :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrq_pw_l(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PRECRQ_QH_PW:
            mips_ident(ctx,
                op2 == OPC_PRECRQ_QH_PW ? MIPS_ID_OPC_PRECRQ_QH_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrq_qh_pw(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PRECRQ_RS_QH_PW:
            mips_ident(ctx,
                op2 == OPC_PRECRQ_RS_QH_PW ? MIPS_ID_OPC_PRECRQ_RS_QH_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrq_rs_qh_pw(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_PRECRQU_S_OB_QH:
            mips_ident(ctx,
                op2 == OPC_PRECRQU_S_OB_QH ? MIPS_ID_OPC_PRECRQU_S_OB_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_precrqu_s_ob_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        }
        break;
#endif
    }
}

static void gen_mipsdsp_shift(DisasContext *ctx, uint32_t opc,
                              int ret, int v1, int v2)
{
    uint32_t op2;
    TCGv t0;
    TCGv v1_t;
    TCGv v2_t;

    if (ret == 0) {
        /* Treat as NOP. */
        return;
    }

    t0 = tcg_temp_new();
    v1_t = tcg_temp_new();
    v2_t = tcg_temp_new();

    tcg_gen_movi_tl(t0, v1);
    gen_load_gpr(v1_t, v1);
    gen_load_gpr(v2_t, v2);

    switch (opc) {
    case OPC_SHLL_QB_DSP:
        mips_ident(ctx,
            opc == OPC_SHLL_QB_DSP ? MIPS_ID_OPC_SHLL_QB_DSP :
            MIPS_ID_NONE);
        {
            op2 = MASK_SHLL_QB(ctx->opcode);
            switch (op2) {
            case OPC_SHLL_QB:
                mips_ident(ctx,
                    op2 == OPC_SHLL_QB ? MIPS_ID_OPC_SHLL_QB :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_qb(cpu_gpr[ret], t0, v2_t, tcg_env);
                break;
            case OPC_SHLLV_QB:
                mips_ident(ctx,
                    op2 == OPC_SHLLV_QB ? MIPS_ID_OPC_SHLLV_QB :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_qb(cpu_gpr[ret], v1_t, v2_t, tcg_env);
                break;
            case OPC_SHLL_PH:
                mips_ident(ctx,
                    op2 == OPC_SHLL_PH ? MIPS_ID_OPC_SHLL_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_ph(cpu_gpr[ret], t0, v2_t, tcg_env);
                break;
            case OPC_SHLLV_PH:
                mips_ident(ctx,
                    op2 == OPC_SHLLV_PH ? MIPS_ID_OPC_SHLLV_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
                break;
            case OPC_SHLL_S_PH:
                mips_ident(ctx,
                    op2 == OPC_SHLL_S_PH ? MIPS_ID_OPC_SHLL_S_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_s_ph(cpu_gpr[ret], t0, v2_t, tcg_env);
                break;
            case OPC_SHLLV_S_PH:
                mips_ident(ctx,
                    op2 == OPC_SHLLV_S_PH ? MIPS_ID_OPC_SHLLV_S_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_s_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
                break;
            case OPC_SHLL_S_W:
                mips_ident(ctx,
                    op2 == OPC_SHLL_S_W ? MIPS_ID_OPC_SHLL_S_W :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_s_w(cpu_gpr[ret], t0, v2_t, tcg_env);
                break;
            case OPC_SHLLV_S_W:
                mips_ident(ctx,
                    op2 == OPC_SHLLV_S_W ? MIPS_ID_OPC_SHLLV_S_W :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shll_s_w(cpu_gpr[ret], v1_t, v2_t, tcg_env);
                break;
            case OPC_SHRL_QB:
                mips_ident(ctx,
                    op2 == OPC_SHRL_QB ? MIPS_ID_OPC_SHRL_QB :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shrl_qb(cpu_gpr[ret], t0, v2_t);
                break;
            case OPC_SHRLV_QB:
                mips_ident(ctx,
                    op2 == OPC_SHRLV_QB ? MIPS_ID_OPC_SHRLV_QB :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shrl_qb(cpu_gpr[ret], v1_t, v2_t);
                break;
            case OPC_SHRL_PH:
                mips_ident(ctx,
                    op2 == OPC_SHRL_PH ? MIPS_ID_OPC_SHRL_PH :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_shrl_ph(cpu_gpr[ret], t0, v2_t);
                break;
            case OPC_SHRLV_PH:
                mips_ident(ctx,
                    op2 == OPC_SHRLV_PH ? MIPS_ID_OPC_SHRLV_PH :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_shrl_ph(cpu_gpr[ret], v1_t, v2_t);
                break;
            case OPC_SHRA_QB:
                mips_ident(ctx,
                    op2 == OPC_SHRA_QB ? MIPS_ID_OPC_SHRA_QB :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_shra_qb(cpu_gpr[ret], t0, v2_t);
                break;
            case OPC_SHRA_R_QB:
                mips_ident(ctx,
                    op2 == OPC_SHRA_R_QB ? MIPS_ID_OPC_SHRA_R_QB :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_shra_r_qb(cpu_gpr[ret], t0, v2_t);
                break;
            case OPC_SHRAV_QB:
                mips_ident(ctx,
                    op2 == OPC_SHRAV_QB ? MIPS_ID_OPC_SHRAV_QB :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_shra_qb(cpu_gpr[ret], v1_t, v2_t);
                break;
            case OPC_SHRAV_R_QB:
                mips_ident(ctx,
                    op2 == OPC_SHRAV_R_QB ? MIPS_ID_OPC_SHRAV_R_QB :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_shra_r_qb(cpu_gpr[ret], v1_t, v2_t);
                break;
            case OPC_SHRA_PH:
                mips_ident(ctx,
                    op2 == OPC_SHRA_PH ? MIPS_ID_OPC_SHRA_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shra_ph(cpu_gpr[ret], t0, v2_t);
                break;
            case OPC_SHRA_R_PH:
                mips_ident(ctx,
                    op2 == OPC_SHRA_R_PH ? MIPS_ID_OPC_SHRA_R_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shra_r_ph(cpu_gpr[ret], t0, v2_t);
                break;
            case OPC_SHRAV_PH:
                mips_ident(ctx,
                    op2 == OPC_SHRAV_PH ? MIPS_ID_OPC_SHRAV_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shra_ph(cpu_gpr[ret], v1_t, v2_t);
                break;
            case OPC_SHRAV_R_PH:
                mips_ident(ctx,
                    op2 == OPC_SHRAV_R_PH ? MIPS_ID_OPC_SHRAV_R_PH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shra_r_ph(cpu_gpr[ret], v1_t, v2_t);
                break;
            case OPC_SHRA_R_W:
                mips_ident(ctx,
                    op2 == OPC_SHRA_R_W ? MIPS_ID_OPC_SHRA_R_W :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shra_r_w(cpu_gpr[ret], t0, v2_t);
                break;
            case OPC_SHRAV_R_W:
                mips_ident(ctx,
                    op2 == OPC_SHRAV_R_W ? MIPS_ID_OPC_SHRAV_R_W :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_shra_r_w(cpu_gpr[ret], v1_t, v2_t);
                break;
            default:            /* Invalid */
                MIPS_INVAL("MASK SHLL.QB");
                gen_reserved_instruction(ctx);
                break;
            }
            break;
        }
#ifdef TARGET_MIPS64
    case OPC_SHLL_OB_DSP:
        mips_ident(ctx,
            opc == OPC_SHLL_OB_DSP ? MIPS_ID_OPC_SHLL_OB_DSP :
            MIPS_ID_NONE);
        op2 = MASK_SHLL_OB(ctx->opcode);
        switch (op2) {
        case OPC_SHLL_PW:
            mips_ident(ctx,
                op2 == OPC_SHLL_PW ? MIPS_ID_OPC_SHLL_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_pw(cpu_gpr[ret], v2_t, t0, tcg_env);
            break;
        case OPC_SHLLV_PW:
            mips_ident(ctx,
                op2 == OPC_SHLLV_PW ? MIPS_ID_OPC_SHLLV_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_pw(cpu_gpr[ret], v2_t, v1_t, tcg_env);
            break;
        case OPC_SHLL_S_PW:
            mips_ident(ctx,
                op2 == OPC_SHLL_S_PW ? MIPS_ID_OPC_SHLL_S_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_s_pw(cpu_gpr[ret], v2_t, t0, tcg_env);
            break;
        case OPC_SHLLV_S_PW:
            mips_ident(ctx,
                op2 == OPC_SHLLV_S_PW ? MIPS_ID_OPC_SHLLV_S_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_s_pw(cpu_gpr[ret], v2_t, v1_t, tcg_env);
            break;
        case OPC_SHLL_OB:
            mips_ident(ctx,
                op2 == OPC_SHLL_OB ? MIPS_ID_OPC_SHLL_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_ob(cpu_gpr[ret], v2_t, t0, tcg_env);
            break;
        case OPC_SHLLV_OB:
            mips_ident(ctx,
                op2 == OPC_SHLLV_OB ? MIPS_ID_OPC_SHLLV_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_ob(cpu_gpr[ret], v2_t, v1_t, tcg_env);
            break;
        case OPC_SHLL_QH:
            mips_ident(ctx,
                op2 == OPC_SHLL_QH ? MIPS_ID_OPC_SHLL_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_qh(cpu_gpr[ret], v2_t, t0, tcg_env);
            break;
        case OPC_SHLLV_QH:
            mips_ident(ctx,
                op2 == OPC_SHLLV_QH ? MIPS_ID_OPC_SHLLV_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_qh(cpu_gpr[ret], v2_t, v1_t, tcg_env);
            break;
        case OPC_SHLL_S_QH:
            mips_ident(ctx,
                op2 == OPC_SHLL_S_QH ? MIPS_ID_OPC_SHLL_S_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_s_qh(cpu_gpr[ret], v2_t, t0, tcg_env);
            break;
        case OPC_SHLLV_S_QH:
            mips_ident(ctx,
                op2 == OPC_SHLLV_S_QH ? MIPS_ID_OPC_SHLLV_S_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shll_s_qh(cpu_gpr[ret], v2_t, v1_t, tcg_env);
            break;
        case OPC_SHRA_OB:
            mips_ident(ctx,
                op2 == OPC_SHRA_OB ? MIPS_ID_OPC_SHRA_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_shra_ob(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRAV_OB:
            mips_ident(ctx,
                op2 == OPC_SHRAV_OB ? MIPS_ID_OPC_SHRAV_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_shra_ob(cpu_gpr[ret], v2_t, v1_t);
            break;
        case OPC_SHRA_R_OB:
            mips_ident(ctx,
                op2 == OPC_SHRA_R_OB ? MIPS_ID_OPC_SHRA_R_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_shra_r_ob(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRAV_R_OB:
            mips_ident(ctx,
                op2 == OPC_SHRAV_R_OB ? MIPS_ID_OPC_SHRAV_R_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_shra_r_ob(cpu_gpr[ret], v2_t, v1_t);
            break;
        case OPC_SHRA_PW:
            mips_ident(ctx,
                op2 == OPC_SHRA_PW ? MIPS_ID_OPC_SHRA_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_pw(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRAV_PW:
            mips_ident(ctx,
                op2 == OPC_SHRAV_PW ? MIPS_ID_OPC_SHRAV_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_pw(cpu_gpr[ret], v2_t, v1_t);
            break;
        case OPC_SHRA_R_PW:
            mips_ident(ctx,
                op2 == OPC_SHRA_R_PW ? MIPS_ID_OPC_SHRA_R_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_r_pw(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRAV_R_PW:
            mips_ident(ctx,
                op2 == OPC_SHRAV_R_PW ? MIPS_ID_OPC_SHRAV_R_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_r_pw(cpu_gpr[ret], v2_t, v1_t);
            break;
        case OPC_SHRA_QH:
            mips_ident(ctx,
                op2 == OPC_SHRA_QH ? MIPS_ID_OPC_SHRA_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_qh(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRAV_QH:
            mips_ident(ctx,
                op2 == OPC_SHRAV_QH ? MIPS_ID_OPC_SHRAV_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_qh(cpu_gpr[ret], v2_t, v1_t);
            break;
        case OPC_SHRA_R_QH:
            mips_ident(ctx,
                op2 == OPC_SHRA_R_QH ? MIPS_ID_OPC_SHRA_R_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_r_qh(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRAV_R_QH:
            mips_ident(ctx,
                op2 == OPC_SHRAV_R_QH ? MIPS_ID_OPC_SHRAV_R_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shra_r_qh(cpu_gpr[ret], v2_t, v1_t);
            break;
        case OPC_SHRL_OB:
            mips_ident(ctx,
                op2 == OPC_SHRL_OB ? MIPS_ID_OPC_SHRL_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shrl_ob(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRLV_OB:
            mips_ident(ctx,
                op2 == OPC_SHRLV_OB ? MIPS_ID_OPC_SHRLV_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_shrl_ob(cpu_gpr[ret], v2_t, v1_t);
            break;
        case OPC_SHRL_QH:
            mips_ident(ctx,
                op2 == OPC_SHRL_QH ? MIPS_ID_OPC_SHRL_QH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_shrl_qh(cpu_gpr[ret], v2_t, t0);
            break;
        case OPC_SHRLV_QH:
            mips_ident(ctx,
                op2 == OPC_SHRLV_QH ? MIPS_ID_OPC_SHRLV_QH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_shrl_qh(cpu_gpr[ret], v2_t, v1_t);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK SHLL.OB");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
#endif
    }
}

static void gen_mipsdsp_multiply(DisasContext *ctx, uint32_t op1, uint32_t op2,
                                 int ret, int v1, int v2, int check_ret)
{
    TCGv_i32 t0;
    TCGv v1_t;
    TCGv v2_t;

    if ((ret == 0) && (check_ret == 1)) {
        /* Treat as NOP. */
        return;
    }

    t0 = tcg_temp_new_i32();
    v1_t = tcg_temp_new();
    v2_t = tcg_temp_new();

    tcg_gen_movi_i32(t0, ret);
    gen_load_gpr(v1_t, v1);
    gen_load_gpr(v2_t, v2);

    switch (op1) {
    case OPC_MUL_PH_DSP:
        mips_ident(ctx,
            op1 == OPC_MUL_PH_DSP ? MIPS_ID_OPC_MUL_PH_DSP :
            MIPS_ID_NONE);
        check_dsp_r2(ctx);
        switch (op2) {
        case  OPC_MUL_PH:
            mips_ident(ctx,
                op2 == OPC_MUL_PH ? MIPS_ID_OPC_MUL_PH :
                MIPS_ID_NONE);
            gen_helper_mul_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case  OPC_MUL_S_PH:
            mips_ident(ctx,
                op2 == OPC_MUL_S_PH ? MIPS_ID_OPC_MUL_S_PH :
                MIPS_ID_NONE);
            gen_helper_mul_s_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULQ_S_W:
            mips_ident(ctx,
                op2 == OPC_MULQ_S_W ? MIPS_ID_OPC_MULQ_S_W :
                MIPS_ID_NONE);
            gen_helper_mulq_s_w(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULQ_RS_W:
            mips_ident(ctx,
                op2 == OPC_MULQ_RS_W ? MIPS_ID_OPC_MULQ_RS_W :
                MIPS_ID_NONE);
            gen_helper_mulq_rs_w(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        }
        break;
    case OPC_DPA_W_PH_DSP:
        mips_ident(ctx,
            op1 == OPC_DPA_W_PH_DSP ? MIPS_ID_OPC_DPA_W_PH_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_DPAU_H_QBL:
            mips_ident(ctx,
                op2 == OPC_DPAU_H_QBL ? MIPS_ID_OPC_DPAU_H_QBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpau_h_qbl(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPAU_H_QBR:
            mips_ident(ctx,
                op2 == OPC_DPAU_H_QBR ? MIPS_ID_OPC_DPAU_H_QBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpau_h_qbr(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPSU_H_QBL:
            mips_ident(ctx,
                op2 == OPC_DPSU_H_QBL ? MIPS_ID_OPC_DPSU_H_QBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpsu_h_qbl(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPSU_H_QBR:
            mips_ident(ctx,
                op2 == OPC_DPSU_H_QBR ? MIPS_ID_OPC_DPSU_H_QBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpsu_h_qbr(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPA_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPA_W_PH ? MIPS_ID_OPC_DPA_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dpa_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPAX_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPAX_W_PH ? MIPS_ID_OPC_DPAX_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dpax_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPAQ_S_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPAQ_S_W_PH ? MIPS_ID_OPC_DPAQ_S_W_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpaq_s_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPAQX_S_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPAQX_S_W_PH ? MIPS_ID_OPC_DPAQX_S_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dpaqx_s_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPAQX_SA_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPAQX_SA_W_PH ? MIPS_ID_OPC_DPAQX_SA_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dpaqx_sa_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPS_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPS_W_PH ? MIPS_ID_OPC_DPS_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dps_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPSX_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPSX_W_PH ? MIPS_ID_OPC_DPSX_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dpsx_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPSQ_S_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPSQ_S_W_PH ? MIPS_ID_OPC_DPSQ_S_W_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpsq_s_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPSQX_S_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPSQX_S_W_PH ? MIPS_ID_OPC_DPSQX_S_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dpsqx_s_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPSQX_SA_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPSQX_SA_W_PH ? MIPS_ID_OPC_DPSQX_SA_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_dpsqx_sa_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_MULSAQ_S_W_PH:
            mips_ident(ctx,
                op2 == OPC_MULSAQ_S_W_PH ? MIPS_ID_OPC_MULSAQ_S_W_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_mulsaq_s_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPAQ_SA_L_W:
            mips_ident(ctx,
                op2 == OPC_DPAQ_SA_L_W ? MIPS_ID_OPC_DPAQ_SA_L_W :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpaq_sa_l_w(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_DPSQ_SA_L_W:
            mips_ident(ctx,
                op2 == OPC_DPSQ_SA_L_W ? MIPS_ID_OPC_DPSQ_SA_L_W :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_dpsq_sa_l_w(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_MAQ_S_W_PHL:
            mips_ident(ctx,
                op2 == OPC_MAQ_S_W_PHL ? MIPS_ID_OPC_MAQ_S_W_PHL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_maq_s_w_phl(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_MAQ_S_W_PHR:
            mips_ident(ctx,
                op2 == OPC_MAQ_S_W_PHR ? MIPS_ID_OPC_MAQ_S_W_PHR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_maq_s_w_phr(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_MAQ_SA_W_PHL:
            mips_ident(ctx,
                op2 == OPC_MAQ_SA_W_PHL ? MIPS_ID_OPC_MAQ_SA_W_PHL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_maq_sa_w_phl(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_MAQ_SA_W_PHR:
            mips_ident(ctx,
                op2 == OPC_MAQ_SA_W_PHR ? MIPS_ID_OPC_MAQ_SA_W_PHR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_maq_sa_w_phr(t0, v1_t, v2_t, tcg_env);
            break;
        case OPC_MULSA_W_PH:
            mips_ident(ctx,
                op2 == OPC_MULSA_W_PH ? MIPS_ID_OPC_MULSA_W_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_mulsa_w_ph(t0, v1_t, v2_t, tcg_env);
            break;
        }
        break;
#ifdef TARGET_MIPS64
    case OPC_DPAQ_W_QH_DSP:
        mips_ident(ctx,
            op1 == OPC_DPAQ_W_QH_DSP ? MIPS_ID_OPC_DPAQ_W_QH_DSP :
            MIPS_ID_NONE);
        {
            int ac = ret & 0x03;
            tcg_gen_movi_i32(t0, ac);

            switch (op2) {
            case OPC_DMADD:
                mips_ident(ctx,
                    op2 == OPC_DMADD ? MIPS_ID_OPC_DMADD :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dmadd(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DMADDU:
                mips_ident(ctx,
                    op2 == OPC_DMADDU ? MIPS_ID_OPC_DMADDU :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dmaddu(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DMSUB:
                mips_ident(ctx,
                    op2 == OPC_DMSUB ? MIPS_ID_OPC_DMSUB :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dmsub(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DMSUBU:
                mips_ident(ctx,
                    op2 == OPC_DMSUBU ? MIPS_ID_OPC_DMSUBU :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dmsubu(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPA_W_QH:
                mips_ident(ctx,
                    op2 == OPC_DPA_W_QH ? MIPS_ID_OPC_DPA_W_QH :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_dpa_w_qh(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPAQ_S_W_QH:
                mips_ident(ctx,
                    op2 == OPC_DPAQ_S_W_QH ? MIPS_ID_OPC_DPAQ_S_W_QH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpaq_s_w_qh(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPAQ_SA_L_PW:
                mips_ident(ctx,
                    op2 == OPC_DPAQ_SA_L_PW ? MIPS_ID_OPC_DPAQ_SA_L_PW :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpaq_sa_l_pw(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPAU_H_OBL:
                mips_ident(ctx,
                    op2 == OPC_DPAU_H_OBL ? MIPS_ID_OPC_DPAU_H_OBL :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpau_h_obl(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPAU_H_OBR:
                mips_ident(ctx,
                    op2 == OPC_DPAU_H_OBR ? MIPS_ID_OPC_DPAU_H_OBR :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpau_h_obr(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPS_W_QH:
                mips_ident(ctx,
                    op2 == OPC_DPS_W_QH ? MIPS_ID_OPC_DPS_W_QH :
                    MIPS_ID_NONE);
                check_dsp_r2(ctx);
                gen_helper_dps_w_qh(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPSQ_S_W_QH:
                mips_ident(ctx,
                    op2 == OPC_DPSQ_S_W_QH ? MIPS_ID_OPC_DPSQ_S_W_QH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpsq_s_w_qh(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPSQ_SA_L_PW:
                mips_ident(ctx,
                    op2 == OPC_DPSQ_SA_L_PW ? MIPS_ID_OPC_DPSQ_SA_L_PW :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpsq_sa_l_pw(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPSU_H_OBL:
                mips_ident(ctx,
                    op2 == OPC_DPSU_H_OBL ? MIPS_ID_OPC_DPSU_H_OBL :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpsu_h_obl(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_DPSU_H_OBR:
                mips_ident(ctx,
                    op2 == OPC_DPSU_H_OBR ? MIPS_ID_OPC_DPSU_H_OBR :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_dpsu_h_obr(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_S_L_PWL:
                mips_ident(ctx,
                    op2 == OPC_MAQ_S_L_PWL ? MIPS_ID_OPC_MAQ_S_L_PWL :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_s_l_pwl(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_S_L_PWR:
                mips_ident(ctx,
                    op2 == OPC_MAQ_S_L_PWR ? MIPS_ID_OPC_MAQ_S_L_PWR :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_s_l_pwr(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_S_W_QHLL:
                mips_ident(ctx,
                    op2 == OPC_MAQ_S_W_QHLL ? MIPS_ID_OPC_MAQ_S_W_QHLL :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_s_w_qhll(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_SA_W_QHLL:
                mips_ident(ctx,
                    op2 == OPC_MAQ_SA_W_QHLL ? MIPS_ID_OPC_MAQ_SA_W_QHLL :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_sa_w_qhll(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_S_W_QHLR:
                mips_ident(ctx,
                    op2 == OPC_MAQ_S_W_QHLR ? MIPS_ID_OPC_MAQ_S_W_QHLR :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_s_w_qhlr(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_SA_W_QHLR:
                mips_ident(ctx,
                    op2 == OPC_MAQ_SA_W_QHLR ? MIPS_ID_OPC_MAQ_SA_W_QHLR :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_sa_w_qhlr(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_S_W_QHRL:
                mips_ident(ctx,
                    op2 == OPC_MAQ_S_W_QHRL ? MIPS_ID_OPC_MAQ_S_W_QHRL :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_s_w_qhrl(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_SA_W_QHRL:
                mips_ident(ctx,
                    op2 == OPC_MAQ_SA_W_QHRL ? MIPS_ID_OPC_MAQ_SA_W_QHRL :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_sa_w_qhrl(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_S_W_QHRR:
                mips_ident(ctx,
                    op2 == OPC_MAQ_S_W_QHRR ? MIPS_ID_OPC_MAQ_S_W_QHRR :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_s_w_qhrr(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MAQ_SA_W_QHRR:
                mips_ident(ctx,
                    op2 == OPC_MAQ_SA_W_QHRR ? MIPS_ID_OPC_MAQ_SA_W_QHRR :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_maq_sa_w_qhrr(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MULSAQ_S_L_PW:
                mips_ident(ctx,
                    op2 == OPC_MULSAQ_S_L_PW ? MIPS_ID_OPC_MULSAQ_S_L_PW :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_mulsaq_s_l_pw(v1_t, v2_t, t0, tcg_env);
                break;
            case OPC_MULSAQ_S_W_QH:
                mips_ident(ctx,
                    op2 == OPC_MULSAQ_S_W_QH ? MIPS_ID_OPC_MULSAQ_S_W_QH :
                    MIPS_ID_NONE);
                check_dsp(ctx);
                gen_helper_mulsaq_s_w_qh(v1_t, v2_t, t0, tcg_env);
                break;
            }
        }
        break;
#endif
    case OPC_ADDU_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_ADDU_QB_DSP ? MIPS_ID_OPC_ADDU_QB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_MULEU_S_PH_QBL:
            mips_ident(ctx,
                op2 == OPC_MULEU_S_PH_QBL ? MIPS_ID_OPC_MULEU_S_PH_QBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleu_s_ph_qbl(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULEU_S_PH_QBR:
            mips_ident(ctx,
                op2 == OPC_MULEU_S_PH_QBR ? MIPS_ID_OPC_MULEU_S_PH_QBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleu_s_ph_qbr(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULQ_RS_PH:
            mips_ident(ctx,
                op2 == OPC_MULQ_RS_PH ? MIPS_ID_OPC_MULQ_RS_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_mulq_rs_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULEQ_S_W_PHL:
            mips_ident(ctx,
                op2 == OPC_MULEQ_S_W_PHL ? MIPS_ID_OPC_MULEQ_S_W_PHL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleq_s_w_phl(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULEQ_S_W_PHR:
            mips_ident(ctx,
                op2 == OPC_MULEQ_S_W_PHR ? MIPS_ID_OPC_MULEQ_S_W_PHR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleq_s_w_phr(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULQ_S_PH:
            mips_ident(ctx,
                op2 == OPC_MULQ_S_PH ? MIPS_ID_OPC_MULQ_S_PH :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_mulq_s_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        }
        break;
#ifdef TARGET_MIPS64
    case OPC_ADDU_OB_DSP:
        mips_ident(ctx,
            op1 == OPC_ADDU_OB_DSP ? MIPS_ID_OPC_ADDU_OB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_MULEQ_S_PW_QHL:
            mips_ident(ctx,
                op2 == OPC_MULEQ_S_PW_QHL ? MIPS_ID_OPC_MULEQ_S_PW_QHL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleq_s_pw_qhl(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULEQ_S_PW_QHR:
            mips_ident(ctx,
                op2 == OPC_MULEQ_S_PW_QHR ? MIPS_ID_OPC_MULEQ_S_PW_QHR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleq_s_pw_qhr(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULEU_S_QH_OBL:
            mips_ident(ctx,
                op2 == OPC_MULEU_S_QH_OBL ? MIPS_ID_OPC_MULEU_S_QH_OBL :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleu_s_qh_obl(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULEU_S_QH_OBR:
            mips_ident(ctx,
                op2 == OPC_MULEU_S_QH_OBR ? MIPS_ID_OPC_MULEU_S_QH_OBR :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_muleu_s_qh_obr(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_MULQ_RS_QH:
            mips_ident(ctx,
                op2 == OPC_MULQ_RS_QH ? MIPS_ID_OPC_MULQ_RS_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_mulq_rs_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        }
        break;
#endif
    }
}

static void gen_mipsdsp_bitinsn(DisasContext *ctx, uint32_t op1, uint32_t op2,
                                int ret, int val)
{
    int16_t imm;
    TCGv t0;
    TCGv val_t;

    if (ret == 0) {
        /* Treat as NOP. */
        return;
    }

    t0 = tcg_temp_new();
    val_t = tcg_temp_new();
    gen_load_gpr(val_t, val);

    switch (op1) {
    case OPC_ABSQ_S_PH_DSP:
        mips_ident(ctx,
            op1 == OPC_ABSQ_S_PH_DSP ? MIPS_ID_OPC_ABSQ_S_PH_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_BITREV:
            mips_ident(ctx,
                op2 == OPC_BITREV ? MIPS_ID_OPC_BITREV :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_bitrev(cpu_gpr[ret], val_t);
            break;
        case OPC_REPL_QB:
            mips_ident(ctx,
                op2 == OPC_REPL_QB ? MIPS_ID_OPC_REPL_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            {
                target_long result;
                imm = (ctx->opcode >> 16) & 0xFF;
                result = (uint32_t)imm << 24 |
                         (uint32_t)imm << 16 |
                         (uint32_t)imm << 8  |
                         (uint32_t)imm;
                result = (int32_t)result;
                tcg_gen_movi_tl(cpu_gpr[ret], result);
            }
            break;
        case OPC_REPLV_QB:
            mips_ident(ctx,
                op2 == OPC_REPLV_QB ? MIPS_ID_OPC_REPLV_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_ext8u_tl(cpu_gpr[ret], val_t);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 8);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 16);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            tcg_gen_ext32s_tl(cpu_gpr[ret], cpu_gpr[ret]);
            break;
        case OPC_REPL_PH:
            mips_ident(ctx,
                op2 == OPC_REPL_PH ? MIPS_ID_OPC_REPL_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            {
                imm = (ctx->opcode >> 16) & 0x03FF;
                imm = (int16_t)(imm << 6) >> 6;
                tcg_gen_movi_tl(cpu_gpr[ret], \
                                (target_long)((int32_t)imm << 16 | \
                                (uint16_t)imm));
            }
            break;
        case OPC_REPLV_PH:
            mips_ident(ctx,
                op2 == OPC_REPLV_PH ? MIPS_ID_OPC_REPLV_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_ext16u_tl(cpu_gpr[ret], val_t);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 16);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            tcg_gen_ext32s_tl(cpu_gpr[ret], cpu_gpr[ret]);
            break;
        }
        break;
#ifdef TARGET_MIPS64
    case OPC_ABSQ_S_QH_DSP:
        mips_ident(ctx,
            op1 == OPC_ABSQ_S_QH_DSP ? MIPS_ID_OPC_ABSQ_S_QH_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_REPL_OB:
            mips_ident(ctx,
                op2 == OPC_REPL_OB ? MIPS_ID_OPC_REPL_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            {
                target_long temp;

                imm = (ctx->opcode >> 16) & 0xFF;
                temp = ((uint64_t)imm << 8) | (uint64_t)imm;
                temp = (temp << 16) | temp;
                temp = (temp << 32) | temp;
                tcg_gen_movi_tl(cpu_gpr[ret], temp);
                break;
            }
        case OPC_REPL_PW:
            mips_ident(ctx,
                op2 == OPC_REPL_PW ? MIPS_ID_OPC_REPL_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            {
                target_long temp;

                imm = (ctx->opcode >> 16) & 0x03FF;
                imm = (int16_t)(imm << 6) >> 6;
                temp = ((target_long)imm << 32) \
                       | ((target_long)imm & 0xFFFFFFFF);
                tcg_gen_movi_tl(cpu_gpr[ret], temp);
                break;
            }
        case OPC_REPL_QH:
            mips_ident(ctx,
                op2 == OPC_REPL_QH ? MIPS_ID_OPC_REPL_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            {
                target_long temp;

                imm = (ctx->opcode >> 16) & 0x03FF;
                imm = (int16_t)(imm << 6) >> 6;

                temp = ((uint64_t)(uint16_t)imm << 48) |
                       ((uint64_t)(uint16_t)imm << 32) |
                       ((uint64_t)(uint16_t)imm << 16) |
                       (uint64_t)(uint16_t)imm;
                tcg_gen_movi_tl(cpu_gpr[ret], temp);
                break;
            }
        case OPC_REPLV_OB:
            mips_ident(ctx,
                op2 == OPC_REPLV_OB ? MIPS_ID_OPC_REPLV_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_ext8u_tl(cpu_gpr[ret], val_t);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 8);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 16);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 32);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            break;
        case OPC_REPLV_PW:
            mips_ident(ctx,
                op2 == OPC_REPLV_PW ? MIPS_ID_OPC_REPLV_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_ext32u_i64(cpu_gpr[ret], val_t);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 32);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            break;
        case OPC_REPLV_QH:
            mips_ident(ctx,
                op2 == OPC_REPLV_QH ? MIPS_ID_OPC_REPLV_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            tcg_gen_ext16u_tl(cpu_gpr[ret], val_t);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 16);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            tcg_gen_shli_tl(t0, cpu_gpr[ret], 32);
            tcg_gen_or_tl(cpu_gpr[ret], cpu_gpr[ret], t0);
            break;
        }
        break;
#endif
    }
}

static void gen_mipsdsp_add_cmp_pick(DisasContext *ctx,
                                     uint32_t op1, uint32_t op2,
                                     int ret, int v1, int v2, int check_ret)
{
    TCGv t1;
    TCGv v1_t;
    TCGv v2_t;

    if ((ret == 0) && (check_ret == 1)) {
        /* Treat as NOP. */
        return;
    }

    t1 = tcg_temp_new();
    v1_t = tcg_temp_new();
    v2_t = tcg_temp_new();

    gen_load_gpr(v1_t, v1);
    gen_load_gpr(v2_t, v2);

    switch (op1) {
    case OPC_CMPU_EQ_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_CMPU_EQ_QB_DSP ? MIPS_ID_OPC_CMPU_EQ_QB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_CMPU_EQ_QB:
            mips_ident(ctx,
                op2 == OPC_CMPU_EQ_QB ? MIPS_ID_OPC_CMPU_EQ_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpu_eq_qb(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPU_LT_QB:
            mips_ident(ctx,
                op2 == OPC_CMPU_LT_QB ? MIPS_ID_OPC_CMPU_LT_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpu_lt_qb(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPU_LE_QB:
            mips_ident(ctx,
                op2 == OPC_CMPU_LE_QB ? MIPS_ID_OPC_CMPU_LE_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpu_le_qb(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPGU_EQ_QB:
            mips_ident(ctx,
                op2 == OPC_CMPGU_EQ_QB ? MIPS_ID_OPC_CMPGU_EQ_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpgu_eq_qb(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_CMPGU_LT_QB:
            mips_ident(ctx,
                op2 == OPC_CMPGU_LT_QB ? MIPS_ID_OPC_CMPGU_LT_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpgu_lt_qb(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_CMPGU_LE_QB:
            mips_ident(ctx,
                op2 == OPC_CMPGU_LE_QB ? MIPS_ID_OPC_CMPGU_LE_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpgu_le_qb(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_CMPGDU_EQ_QB:
            mips_ident(ctx,
                op2 == OPC_CMPGDU_EQ_QB ? MIPS_ID_OPC_CMPGDU_EQ_QB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_cmpgu_eq_qb(t1, v1_t, v2_t);
            tcg_gen_mov_tl(cpu_gpr[ret], t1);
            tcg_gen_andi_tl(cpu_dspctrl, cpu_dspctrl, 0xF0FFFFFF);
            tcg_gen_shli_tl(t1, t1, 24);
            tcg_gen_or_tl(cpu_dspctrl, cpu_dspctrl, t1);
            break;
        case OPC_CMPGDU_LT_QB:
            mips_ident(ctx,
                op2 == OPC_CMPGDU_LT_QB ? MIPS_ID_OPC_CMPGDU_LT_QB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_cmpgu_lt_qb(t1, v1_t, v2_t);
            tcg_gen_mov_tl(cpu_gpr[ret], t1);
            tcg_gen_andi_tl(cpu_dspctrl, cpu_dspctrl, 0xF0FFFFFF);
            tcg_gen_shli_tl(t1, t1, 24);
            tcg_gen_or_tl(cpu_dspctrl, cpu_dspctrl, t1);
            break;
        case OPC_CMPGDU_LE_QB:
            mips_ident(ctx,
                op2 == OPC_CMPGDU_LE_QB ? MIPS_ID_OPC_CMPGDU_LE_QB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_cmpgu_le_qb(t1, v1_t, v2_t);
            tcg_gen_mov_tl(cpu_gpr[ret], t1);
            tcg_gen_andi_tl(cpu_dspctrl, cpu_dspctrl, 0xF0FFFFFF);
            tcg_gen_shli_tl(t1, t1, 24);
            tcg_gen_or_tl(cpu_dspctrl, cpu_dspctrl, t1);
            break;
        case OPC_CMP_EQ_PH:
            mips_ident(ctx,
                op2 == OPC_CMP_EQ_PH ? MIPS_ID_OPC_CMP_EQ_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_eq_ph(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMP_LT_PH:
            mips_ident(ctx,
                op2 == OPC_CMP_LT_PH ? MIPS_ID_OPC_CMP_LT_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_lt_ph(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMP_LE_PH:
            mips_ident(ctx,
                op2 == OPC_CMP_LE_PH ? MIPS_ID_OPC_CMP_LE_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_le_ph(v1_t, v2_t, tcg_env);
            break;
        case OPC_PICK_QB:
            mips_ident(ctx,
                op2 == OPC_PICK_QB ? MIPS_ID_OPC_PICK_QB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_pick_qb(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_PICK_PH:
            mips_ident(ctx,
                op2 == OPC_PICK_PH ? MIPS_ID_OPC_PICK_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_pick_ph(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_PACKRL_PH:
            mips_ident(ctx,
                op2 == OPC_PACKRL_PH ? MIPS_ID_OPC_PACKRL_PH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_packrl_ph(cpu_gpr[ret], v1_t, v2_t);
            break;
        }
        break;
#ifdef TARGET_MIPS64
    case OPC_CMPU_EQ_OB_DSP:
        mips_ident(ctx,
            op1 == OPC_CMPU_EQ_OB_DSP ? MIPS_ID_OPC_CMPU_EQ_OB_DSP :
            MIPS_ID_NONE);
        switch (op2) {
        case OPC_CMP_EQ_PW:
            mips_ident(ctx,
                op2 == OPC_CMP_EQ_PW ? MIPS_ID_OPC_CMP_EQ_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_eq_pw(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMP_LT_PW:
            mips_ident(ctx,
                op2 == OPC_CMP_LT_PW ? MIPS_ID_OPC_CMP_LT_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_lt_pw(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMP_LE_PW:
            mips_ident(ctx,
                op2 == OPC_CMP_LE_PW ? MIPS_ID_OPC_CMP_LE_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_le_pw(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMP_EQ_QH:
            mips_ident(ctx,
                op2 == OPC_CMP_EQ_QH ? MIPS_ID_OPC_CMP_EQ_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_eq_qh(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMP_LT_QH:
            mips_ident(ctx,
                op2 == OPC_CMP_LT_QH ? MIPS_ID_OPC_CMP_LT_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_lt_qh(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMP_LE_QH:
            mips_ident(ctx,
                op2 == OPC_CMP_LE_QH ? MIPS_ID_OPC_CMP_LE_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmp_le_qh(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPGDU_EQ_OB:
            mips_ident(ctx,
                op2 == OPC_CMPGDU_EQ_OB ? MIPS_ID_OPC_CMPGDU_EQ_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_cmpgdu_eq_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPGDU_LT_OB:
            mips_ident(ctx,
                op2 == OPC_CMPGDU_LT_OB ? MIPS_ID_OPC_CMPGDU_LT_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_cmpgdu_lt_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPGDU_LE_OB:
            mips_ident(ctx,
                op2 == OPC_CMPGDU_LE_OB ? MIPS_ID_OPC_CMPGDU_LE_OB :
                MIPS_ID_NONE);
            check_dsp_r2(ctx);
            gen_helper_cmpgdu_le_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPGU_EQ_OB:
            mips_ident(ctx,
                op2 == OPC_CMPGU_EQ_OB ? MIPS_ID_OPC_CMPGU_EQ_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpgu_eq_ob(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_CMPGU_LT_OB:
            mips_ident(ctx,
                op2 == OPC_CMPGU_LT_OB ? MIPS_ID_OPC_CMPGU_LT_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpgu_lt_ob(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_CMPGU_LE_OB:
            mips_ident(ctx,
                op2 == OPC_CMPGU_LE_OB ? MIPS_ID_OPC_CMPGU_LE_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpgu_le_ob(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_CMPU_EQ_OB:
            mips_ident(ctx,
                op2 == OPC_CMPU_EQ_OB ? MIPS_ID_OPC_CMPU_EQ_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpu_eq_ob(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPU_LT_OB:
            mips_ident(ctx,
                op2 == OPC_CMPU_LT_OB ? MIPS_ID_OPC_CMPU_LT_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpu_lt_ob(v1_t, v2_t, tcg_env);
            break;
        case OPC_CMPU_LE_OB:
            mips_ident(ctx,
                op2 == OPC_CMPU_LE_OB ? MIPS_ID_OPC_CMPU_LE_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_cmpu_le_ob(v1_t, v2_t, tcg_env);
            break;
        case OPC_PACKRL_PW:
            mips_ident(ctx,
                op2 == OPC_PACKRL_PW ? MIPS_ID_OPC_PACKRL_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_packrl_pw(cpu_gpr[ret], v1_t, v2_t);
            break;
        case OPC_PICK_OB:
            mips_ident(ctx,
                op2 == OPC_PICK_OB ? MIPS_ID_OPC_PICK_OB :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_pick_ob(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_PICK_PW:
            mips_ident(ctx,
                op2 == OPC_PICK_PW ? MIPS_ID_OPC_PICK_PW :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_pick_pw(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        case OPC_PICK_QH:
            mips_ident(ctx,
                op2 == OPC_PICK_QH ? MIPS_ID_OPC_PICK_QH :
                MIPS_ID_NONE);
            check_dsp(ctx);
            gen_helper_pick_qh(cpu_gpr[ret], v1_t, v2_t, tcg_env);
            break;
        }
        break;
#endif
    }
}

static void gen_mipsdsp_append(CPUMIPSState *env, DisasContext *ctx,
                               uint32_t op1, int rt, int rs, int sa)
{
    TCGv t0;

    check_dsp_r2(ctx);

    if (rt == 0) {
        /* Treat as NOP. */
        return;
    }

    t0 = tcg_temp_new();
    gen_load_gpr(t0, rs);

    switch (op1) {
    case OPC_APPEND_DSP:
        mips_ident(ctx,
            op1 == OPC_APPEND_DSP ? MIPS_ID_OPC_APPEND_DSP :
            MIPS_ID_NONE);
        switch (MASK_APPEND(ctx->opcode)) {
        case OPC_APPEND:
            mips_ident(ctx,
                MASK_APPEND(ctx->opcode) == OPC_APPEND ? MIPS_ID_OPC_APPEND :
                MIPS_ID_NONE);
            if (sa != 0) {
                tcg_gen_deposit_tl(cpu_gpr[rt], t0, cpu_gpr[rt], sa, 32 - sa);
            }
            tcg_gen_ext32s_tl(cpu_gpr[rt], cpu_gpr[rt]);
            break;
        case OPC_PREPEND:
            mips_ident(ctx,
                MASK_APPEND(ctx->opcode) == OPC_PREPEND ? MIPS_ID_OPC_PREPEND :
                MIPS_ID_NONE);
            if (sa != 0) {
                tcg_gen_ext32u_tl(cpu_gpr[rt], cpu_gpr[rt]);
                tcg_gen_shri_tl(cpu_gpr[rt], cpu_gpr[rt], sa);
                tcg_gen_shli_tl(t0, t0, 32 - sa);
                tcg_gen_or_tl(cpu_gpr[rt], cpu_gpr[rt], t0);
            }
            tcg_gen_ext32s_tl(cpu_gpr[rt], cpu_gpr[rt]);
            break;
        case OPC_BALIGN:
            mips_ident(ctx,
                MASK_APPEND(ctx->opcode) == OPC_BALIGN ? MIPS_ID_OPC_BALIGN :
                MIPS_ID_NONE);
            sa &= 3;
            if (sa != 0 && sa != 2) {
                tcg_gen_shli_tl(cpu_gpr[rt], cpu_gpr[rt], 8 * sa);
                tcg_gen_ext32u_tl(t0, t0);
                tcg_gen_shri_tl(t0, t0, 8 * (4 - sa));
                tcg_gen_or_tl(cpu_gpr[rt], cpu_gpr[rt], t0);
            }
            tcg_gen_ext32s_tl(cpu_gpr[rt], cpu_gpr[rt]);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK APPEND");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
#ifdef TARGET_MIPS64
    case OPC_DAPPEND_DSP:
        mips_ident(ctx,
            op1 == OPC_DAPPEND_DSP ? MIPS_ID_OPC_DAPPEND_DSP :
            MIPS_ID_NONE);
        switch (MASK_DAPPEND(ctx->opcode)) {
        case OPC_DAPPEND:
            mips_ident(ctx,
                MASK_DAPPEND(ctx->opcode) == OPC_DAPPEND ?
                    MIPS_ID_OPC_DAPPEND :
                MIPS_ID_NONE);
            if (sa != 0) {
                tcg_gen_deposit_tl(cpu_gpr[rt], t0, cpu_gpr[rt], sa, 64 - sa);
            }
            break;
        case OPC_PREPENDD:
            mips_ident(ctx,
                MASK_DAPPEND(ctx->opcode) == OPC_PREPENDD ?
                    MIPS_ID_OPC_PREPENDD :
                MIPS_ID_NONE);
            tcg_gen_shri_tl(cpu_gpr[rt], cpu_gpr[rt], 0x20 | sa);
            tcg_gen_shli_tl(t0, t0, 64 - (0x20 | sa));
            tcg_gen_or_tl(cpu_gpr[rt], t0, t0);
            break;
        case OPC_PREPENDW:
            mips_ident(ctx,
                MASK_DAPPEND(ctx->opcode) == OPC_PREPENDW ?
                    MIPS_ID_OPC_PREPENDW :
                MIPS_ID_NONE);
            if (sa != 0) {
                tcg_gen_shri_tl(cpu_gpr[rt], cpu_gpr[rt], sa);
                tcg_gen_shli_tl(t0, t0, 64 - sa);
                tcg_gen_or_tl(cpu_gpr[rt], cpu_gpr[rt], t0);
            }
            break;
        case OPC_DBALIGN:
            mips_ident(ctx,
                MASK_DAPPEND(ctx->opcode) == OPC_DBALIGN ?
                    MIPS_ID_OPC_DBALIGN :
                MIPS_ID_NONE);
            sa &= 7;
            if (sa != 0 && sa != 2 && sa != 4) {
                tcg_gen_shli_tl(cpu_gpr[rt], cpu_gpr[rt], 8 * sa);
                tcg_gen_shri_tl(t0, t0, 8 * (8 - sa));
                tcg_gen_or_tl(cpu_gpr[rt], cpu_gpr[rt], t0);
            }
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK DAPPEND");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
#endif
    }
}

static void gen_mipsdsp_accinsn(DisasContext *ctx, uint32_t op1, uint32_t op2,
                                int ret, int v1, int v2, int check_ret)

{
    TCGv t0;
    TCGv t1;
    TCGv v1_t;
    int16_t imm;

    if ((ret == 0) && (check_ret == 1)) {
        /* Treat as NOP. */
        return;
    }

    t0 = tcg_temp_new();
    t1 = tcg_temp_new();
    v1_t = tcg_temp_new();

    gen_load_gpr(v1_t, v1);

    switch (op1) {
    case OPC_EXTR_W_DSP:
        mips_ident(ctx,
            op1 == OPC_EXTR_W_DSP ? MIPS_ID_OPC_EXTR_W_DSP :
            MIPS_ID_NONE);
        check_dsp(ctx);
        switch (op2) {
        case OPC_EXTR_W:
            mips_ident(ctx,
                op2 == OPC_EXTR_W ? MIPS_ID_OPC_EXTR_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_extr_w(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_EXTR_R_W:
            mips_ident(ctx,
                op2 == OPC_EXTR_R_W ? MIPS_ID_OPC_EXTR_R_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_extr_r_w(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_EXTR_RS_W:
            mips_ident(ctx,
                op2 == OPC_EXTR_RS_W ? MIPS_ID_OPC_EXTR_RS_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_extr_rs_w(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_EXTR_S_H:
            mips_ident(ctx,
                op2 == OPC_EXTR_S_H ? MIPS_ID_OPC_EXTR_S_H :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_extr_s_h(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_EXTRV_S_H:
            mips_ident(ctx,
                op2 == OPC_EXTRV_S_H ? MIPS_ID_OPC_EXTRV_S_H :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_extr_s_h(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_EXTRV_W:
            mips_ident(ctx,
                op2 == OPC_EXTRV_W ? MIPS_ID_OPC_EXTRV_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_extr_w(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_EXTRV_R_W:
            mips_ident(ctx,
                op2 == OPC_EXTRV_R_W ? MIPS_ID_OPC_EXTRV_R_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_extr_r_w(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_EXTRV_RS_W:
            mips_ident(ctx,
                op2 == OPC_EXTRV_RS_W ? MIPS_ID_OPC_EXTRV_RS_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_extr_rs_w(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_EXTP:
            mips_ident(ctx,
                op2 == OPC_EXTP ? MIPS_ID_OPC_EXTP :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_extp(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_EXTPV:
            mips_ident(ctx,
                op2 == OPC_EXTPV ? MIPS_ID_OPC_EXTPV :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_extp(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_EXTPDP:
            mips_ident(ctx,
                op2 == OPC_EXTPDP ? MIPS_ID_OPC_EXTPDP :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_extpdp(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_EXTPDPV:
            mips_ident(ctx,
                op2 == OPC_EXTPDPV ? MIPS_ID_OPC_EXTPDPV :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_extpdp(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_SHILO:
            mips_ident(ctx,
                op2 == OPC_SHILO ? MIPS_ID_OPC_SHILO :
                MIPS_ID_NONE);
            imm = (ctx->opcode >> 20) & 0x3F;
            tcg_gen_movi_tl(t0, ret);
            tcg_gen_movi_tl(t1, imm);
            gen_helper_shilo(t0, t1, tcg_env);
            break;
        case OPC_SHILOV:
            mips_ident(ctx,
                op2 == OPC_SHILOV ? MIPS_ID_OPC_SHILOV :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, ret);
            gen_helper_shilo(t0, v1_t, tcg_env);
            break;
        case OPC_MTHLIP:
            mips_ident(ctx,
                op2 == OPC_MTHLIP ? MIPS_ID_OPC_MTHLIP :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, ret);
            gen_helper_mthlip(t0, v1_t, tcg_env);
            break;
        case OPC_WRDSP:
            mips_ident(ctx,
                op2 == OPC_WRDSP ? MIPS_ID_OPC_WRDSP :
                MIPS_ID_NONE);
            imm = (ctx->opcode >> 11) & 0x3FF;
            tcg_gen_movi_tl(t0, imm);
            gen_helper_wrdsp(v1_t, t0, tcg_env);
            break;
        case OPC_RDDSP:
            mips_ident(ctx,
                op2 == OPC_RDDSP ? MIPS_ID_OPC_RDDSP :
                MIPS_ID_NONE);
            imm = (ctx->opcode >> 16) & 0x03FF;
            tcg_gen_movi_tl(t0, imm);
            gen_helper_rddsp(cpu_gpr[ret], t0, tcg_env);
            break;
        }
        break;
#ifdef TARGET_MIPS64
    case OPC_DEXTR_W_DSP:
        mips_ident(ctx,
            op1 == OPC_DEXTR_W_DSP ? MIPS_ID_OPC_DEXTR_W_DSP :
            MIPS_ID_NONE);
        check_dsp(ctx);
        switch (op2) {
        case OPC_DMTHLIP:
            mips_ident(ctx,
                op2 == OPC_DMTHLIP ? MIPS_ID_OPC_DMTHLIP :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, ret);
            gen_helper_dmthlip(v1_t, t0, tcg_env);
            break;
        case OPC_DSHILO:
            mips_ident(ctx,
                op2 == OPC_DSHILO ? MIPS_ID_OPC_DSHILO :
                MIPS_ID_NONE);
            {
                int shift = (ctx->opcode >> 19) & 0x7F;
                int ac = (ctx->opcode >> 11) & 0x03;
                tcg_gen_movi_tl(t0, shift);
                tcg_gen_movi_tl(t1, ac);
                gen_helper_dshilo(t0, t1, tcg_env);
                break;
            }
        case OPC_DSHILOV:
            mips_ident(ctx,
                op2 == OPC_DSHILOV ? MIPS_ID_OPC_DSHILOV :
                MIPS_ID_NONE);
            {
                int ac = (ctx->opcode >> 11) & 0x03;
                tcg_gen_movi_tl(t0, ac);
                gen_helper_dshilo(v1_t, t0, tcg_env);
                break;
            }
        case OPC_DEXTP:
            mips_ident(ctx,
                op2 == OPC_DEXTP ? MIPS_ID_OPC_DEXTP :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);

            gen_helper_dextp(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTPV:
            mips_ident(ctx,
                op2 == OPC_DEXTPV ? MIPS_ID_OPC_DEXTPV :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextp(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTPDP:
            mips_ident(ctx,
                op2 == OPC_DEXTPDP ? MIPS_ID_OPC_DEXTPDP :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextpdp(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTPDPV:
            mips_ident(ctx,
                op2 == OPC_DEXTPDPV ? MIPS_ID_OPC_DEXTPDPV :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextpdp(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTR_L:
            mips_ident(ctx,
                op2 == OPC_DEXTR_L ? MIPS_ID_OPC_DEXTR_L :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextr_l(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTR_R_L:
            mips_ident(ctx,
                op2 == OPC_DEXTR_R_L ? MIPS_ID_OPC_DEXTR_R_L :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextr_r_l(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTR_RS_L:
            mips_ident(ctx,
                op2 == OPC_DEXTR_RS_L ? MIPS_ID_OPC_DEXTR_RS_L :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextr_rs_l(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTR_W:
            mips_ident(ctx,
                op2 == OPC_DEXTR_W ? MIPS_ID_OPC_DEXTR_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextr_w(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTR_R_W:
            mips_ident(ctx,
                op2 == OPC_DEXTR_R_W ? MIPS_ID_OPC_DEXTR_R_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextr_r_w(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTR_RS_W:
            mips_ident(ctx,
                op2 == OPC_DEXTR_RS_W ? MIPS_ID_OPC_DEXTR_RS_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextr_rs_w(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTR_S_H:
            mips_ident(ctx,
                op2 == OPC_DEXTR_S_H ? MIPS_ID_OPC_DEXTR_S_H :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            tcg_gen_movi_tl(t1, v1);
            gen_helper_dextr_s_h(cpu_gpr[ret], t0, t1, tcg_env);
            break;
        case OPC_DEXTRV_S_H:
            mips_ident(ctx,
                op2 == OPC_DEXTRV_S_H ? MIPS_ID_OPC_DEXTRV_S_H :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextr_s_h(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTRV_L:
            mips_ident(ctx,
                op2 == OPC_DEXTRV_L ? MIPS_ID_OPC_DEXTRV_L :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextr_l(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTRV_R_L:
            mips_ident(ctx,
                op2 == OPC_DEXTRV_R_L ? MIPS_ID_OPC_DEXTRV_R_L :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextr_r_l(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTRV_RS_L:
            mips_ident(ctx,
                op2 == OPC_DEXTRV_RS_L ? MIPS_ID_OPC_DEXTRV_RS_L :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextr_rs_l(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTRV_W:
            mips_ident(ctx,
                op2 == OPC_DEXTRV_W ? MIPS_ID_OPC_DEXTRV_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextr_w(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTRV_R_W:
            mips_ident(ctx,
                op2 == OPC_DEXTRV_R_W ? MIPS_ID_OPC_DEXTRV_R_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextr_r_w(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        case OPC_DEXTRV_RS_W:
            mips_ident(ctx,
                op2 == OPC_DEXTRV_RS_W ? MIPS_ID_OPC_DEXTRV_RS_W :
                MIPS_ID_NONE);
            tcg_gen_movi_tl(t0, v2);
            gen_helper_dextr_rs_w(cpu_gpr[ret], t0, v1_t, tcg_env);
            break;
        }
        break;
#endif
    }
}

/* End MIPSDSP functions. */

static void decode_opc_special_r6(CPUMIPSState *env, DisasContext *ctx)
{
    int rs, rt, rd, sa;
    uint32_t op1, op2;

    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;
    sa = (ctx->opcode >> 6) & 0x1f;

    op1 = MASK_SPECIAL(ctx->opcode);
    switch (op1) {
    case OPC_MULT:
    case OPC_MULTU:
    case OPC_DIV:
    case OPC_DIVU:
        mips_ident(ctx,
            op1 == OPC_MULT ? MIPS_ID_OPC_MULT :
            op1 == OPC_MULTU ? MIPS_ID_OPC_MULTU :
            op1 == OPC_DIV ? MIPS_ID_OPC_DIV :
            op1 == OPC_DIVU ? MIPS_ID_OPC_DIVU :
            MIPS_ID_NONE);
        op2 = MASK_R6_MULDIV(ctx->opcode);
        switch (op2) {
        case R6_OPC_MUL:
        case R6_OPC_MUH:
        case R6_OPC_MULU:
        case R6_OPC_MUHU:
        case R6_OPC_DIV:
        case R6_OPC_MOD:
        case R6_OPC_DIVU:
        case R6_OPC_MODU:
            mips_ident(ctx,
                op2 == R6_OPC_MUL ? MIPS_ID_R6_OPC_MUL :
                op2 == R6_OPC_MUH ? MIPS_ID_R6_OPC_MUH :
                op2 == R6_OPC_MULU ? MIPS_ID_R6_OPC_MULU :
                op2 == R6_OPC_MUHU ? MIPS_ID_R6_OPC_MUHU :
                op2 == R6_OPC_DIV ? MIPS_ID_R6_OPC_DIV :
                op2 == R6_OPC_MOD ? MIPS_ID_R6_OPC_MOD :
                op2 == R6_OPC_DIVU ? MIPS_ID_R6_OPC_DIVU :
                op2 == R6_OPC_MODU ? MIPS_ID_R6_OPC_MODU :
                MIPS_ID_NONE);
            gen_r6_muldiv(ctx, op2, rd, rs, rt);
            break;
        default:
            MIPS_INVAL("special_r6 muldiv");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_SELEQZ:
    case OPC_SELNEZ:
        mips_ident(ctx,
            op1 == OPC_SELEQZ ? MIPS_ID_OPC_SELEQZ :
            op1 == OPC_SELNEZ ? MIPS_ID_OPC_SELNEZ :
            MIPS_ID_NONE);
        gen_cond_move(ctx, op1, rd, rs, rt);
        break;
    case R6_OPC_CLO:
    case R6_OPC_CLZ:
        mips_ident(ctx,
            op1 == R6_OPC_CLO ? MIPS_ID_R6_OPC_CLO :
            op1 == R6_OPC_CLZ ? MIPS_ID_R6_OPC_CLZ :
            MIPS_ID_NONE);
        if (rt == 0 && sa == 1) {
            /*
             * Major opcode and function field is shared with preR6 MFHI/MTHI.
             * We need additionally to check other fields.
             */
            gen_cl(ctx, op1, rd, rs);
        } else {
            gen_reserved_instruction(ctx);
        }
        break;
    case R6_OPC_SDBBP:
        mips_ident(ctx,
            op1 == R6_OPC_SDBBP ? MIPS_ID_R6_OPC_SDBBP :
            MIPS_ID_NONE);
        if (is_uhi(ctx, extract32(ctx->opcode, 6, 20))) {
            ctx->base.is_jmp = DISAS_SEMIHOST;
        } else {
            if (ctx->hflags & MIPS_HFLAG_SBRI) {
                gen_reserved_instruction(ctx);
            } else {
                generate_exception_end(ctx, EXCP_DBp);
            }
        }
        break;
#if defined(TARGET_MIPS64)
    case R6_OPC_DCLO:
    case R6_OPC_DCLZ:
        mips_ident(ctx,
            op1 == R6_OPC_DCLO ? MIPS_ID_R6_OPC_DCLO :
            op1 == R6_OPC_DCLZ ? MIPS_ID_R6_OPC_DCLZ :
            MIPS_ID_NONE);
        if (rt == 0 && sa == 1) {
            /*
             * Major opcode and function field is shared with preR6 MFHI/MTHI.
             * We need additionally to check other fields.
             */
            check_mips_64(ctx);
            gen_cl(ctx, op1, rd, rs);
        } else {
            gen_reserved_instruction(ctx);
        }
        break;
    case OPC_DMULT:
    case OPC_DMULTU:
    case OPC_DDIV:
    case OPC_DDIVU:
        mips_ident(ctx,
            op1 == OPC_DMULT ? MIPS_ID_OPC_DMULT :
            op1 == OPC_DMULTU ? MIPS_ID_OPC_DMULTU :
            op1 == OPC_DDIV ? MIPS_ID_OPC_DDIV :
            op1 == OPC_DDIVU ? MIPS_ID_OPC_DDIVU :
            MIPS_ID_NONE);

        op2 = MASK_R6_MULDIV(ctx->opcode);
        switch (op2) {
        case R6_OPC_DMUL:
        case R6_OPC_DMUH:
        case R6_OPC_DMULU:
        case R6_OPC_DMUHU:
        case R6_OPC_DDIV:
        case R6_OPC_DMOD:
        case R6_OPC_DDIVU:
        case R6_OPC_DMODU:
            mips_ident(ctx,
                op2 == R6_OPC_DMUL ? MIPS_ID_R6_OPC_DMUL :
                op2 == R6_OPC_DMUH ? MIPS_ID_R6_OPC_DMUH :
                op2 == R6_OPC_DMULU ? MIPS_ID_R6_OPC_DMULU :
                op2 == R6_OPC_DMUHU ? MIPS_ID_R6_OPC_DMUHU :
                op2 == R6_OPC_DDIV ? MIPS_ID_R6_OPC_DDIV :
                op2 == R6_OPC_DMOD ? MIPS_ID_R6_OPC_DMOD :
                op2 == R6_OPC_DDIVU ? MIPS_ID_R6_OPC_DDIVU :
                op2 == R6_OPC_DMODU ? MIPS_ID_R6_OPC_DMODU :
                MIPS_ID_NONE);
            check_mips_64(ctx);
            gen_r6_muldiv(ctx, op2, rd, rs, rt);
            break;
        default:
            MIPS_INVAL("special_r6 muldiv");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
#endif
    default:            /* Invalid */
        MIPS_INVAL("special_r6");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void decode_opc_special_tx79(CPUMIPSState *env, DisasContext *ctx)
{
    int rs = extract32(ctx->opcode, 21, 5);
    int rt = extract32(ctx->opcode, 16, 5);
    int rd = extract32(ctx->opcode, 11, 5);
    uint32_t op1 = MASK_SPECIAL(ctx->opcode);

    switch (op1) {
    case OPC_MOVN:         /* Conditional move */
    case OPC_MOVZ:
        mips_ident(ctx,
            op1 == OPC_MOVN ? MIPS_ID_OPC_MOVN :
            op1 == OPC_MOVZ ? MIPS_ID_OPC_MOVZ :
            MIPS_ID_NONE);
        gen_cond_move(ctx, op1, rd, rs, rt);
        break;
    case OPC_MFHI:          /* Move from HI/LO */
    case OPC_MFLO:
        mips_ident(ctx,
            op1 == OPC_MFHI ? MIPS_ID_OPC_MFHI :
            op1 == OPC_MFLO ? MIPS_ID_OPC_MFLO :
            MIPS_ID_NONE);
        gen_HILO(ctx, op1, 0, rd);
        break;
    case OPC_MTHI:
    case OPC_MTLO:          /* Move to HI/LO */
        mips_ident(ctx,
            op1 == OPC_MTHI ? MIPS_ID_OPC_MTHI :
            op1 == OPC_MTLO ? MIPS_ID_OPC_MTLO :
            MIPS_ID_NONE);
        gen_HILO(ctx, op1, 0, rs);
        break;
    case OPC_MULT:
    case OPC_MULTU:
        mips_ident(ctx,
            op1 == OPC_MULT ? MIPS_ID_OPC_MULT :
            op1 == OPC_MULTU ? MIPS_ID_OPC_MULTU :
            MIPS_ID_NONE);
        gen_mul_txx9(ctx, op1, rd, rs, rt);
        break;
    case OPC_DIV:
    case OPC_DIVU:
        mips_ident(ctx,
            op1 == OPC_DIV ? MIPS_ID_OPC_DIV :
            op1 == OPC_DIVU ? MIPS_ID_OPC_DIVU :
            MIPS_ID_NONE);
        gen_muldiv(ctx, op1, 0, rs, rt);
        break;
#if defined(TARGET_MIPS64)
    case OPC_DMULT:
    case OPC_DMULTU:
    case OPC_DDIV:
    case OPC_DDIVU:
        mips_ident(ctx,
            op1 == OPC_DMULT ? MIPS_ID_OPC_DMULT :
            op1 == OPC_DMULTU ? MIPS_ID_OPC_DMULTU :
            op1 == OPC_DDIV ? MIPS_ID_OPC_DDIV :
            op1 == OPC_DDIVU ? MIPS_ID_OPC_DDIVU :
            MIPS_ID_NONE);
        check_insn_opc_user_only(ctx, INSN_R5900);
        gen_muldiv(ctx, op1, 0, rs, rt);
        break;
#endif
    case OPC_JR:
        mips_ident(ctx,
            op1 == OPC_JR ? MIPS_ID_OPC_JR :
            MIPS_ID_NONE);
        gen_compute_branch(ctx, op1, 4, rs, 0, 0, 4);
        break;
    default:            /* Invalid */
        MIPS_INVAL("special_tx79");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void decode_opc_special_legacy(CPUMIPSState *env, DisasContext *ctx)
{
    int rs, rt, rd;
    uint32_t op1;

    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;

    op1 = MASK_SPECIAL(ctx->opcode);
    switch (op1) {
    case OPC_MOVN:         /* Conditional move */
    case OPC_MOVZ:
        mips_ident(ctx,
            op1 == OPC_MOVN ? MIPS_ID_OPC_MOVN :
            op1 == OPC_MOVZ ? MIPS_ID_OPC_MOVZ :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS4 | ISA_MIPS_R1 |
                   INSN_LOONGSON2E | INSN_LOONGSON2F);
        gen_cond_move(ctx, op1, rd, rs, rt);
        break;
    case OPC_MFHI:          /* Move from HI/LO */
    case OPC_MFLO:
        mips_ident(ctx,
            op1 == OPC_MFHI ? MIPS_ID_OPC_MFHI :
            op1 == OPC_MFLO ? MIPS_ID_OPC_MFLO :
            MIPS_ID_NONE);
        gen_HILO(ctx, op1, rs & 3, rd);
        break;
    case OPC_MTHI:
    case OPC_MTLO:          /* Move to HI/LO */
        mips_ident(ctx,
            op1 == OPC_MTHI ? MIPS_ID_OPC_MTHI :
            op1 == OPC_MTLO ? MIPS_ID_OPC_MTLO :
            MIPS_ID_NONE);
        gen_HILO(ctx, op1, rd & 3, rs);
        break;
    case OPC_MOVCI:
        mips_ident(ctx,
            op1 == OPC_MOVCI ? MIPS_ID_OPC_MOVCI :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS4 | ISA_MIPS_R1);
        if (env->CP0_Config1 & (1 << CP0C1_FP)) {
            check_cp1_enabled(ctx);
            gen_movci(ctx, rd, rs, (ctx->opcode >> 18) & 0x7,
                      (ctx->opcode >> 16) & 1);
        } else {
            generate_exception_err(ctx, EXCP_CpU, 1);
        }
        break;
    case OPC_MULT:
    case OPC_MULTU:
        mips_ident(ctx,
            op1 == OPC_MULT ? MIPS_ID_OPC_MULT :
            op1 == OPC_MULTU ? MIPS_ID_OPC_MULTU :
            MIPS_ID_NONE);
        gen_muldiv(ctx, op1, rd & 3, rs, rt);
        break;
    case OPC_DIV:
    case OPC_DIVU:
        mips_ident(ctx,
            op1 == OPC_DIV ? MIPS_ID_OPC_DIV :
            op1 == OPC_DIVU ? MIPS_ID_OPC_DIVU :
            MIPS_ID_NONE);
        gen_muldiv(ctx, op1, 0, rs, rt);
        break;
#if defined(TARGET_MIPS64)
    case OPC_DMULT:
    case OPC_DMULTU:
    case OPC_DDIV:
    case OPC_DDIVU:
        mips_ident(ctx,
            op1 == OPC_DMULT ? MIPS_ID_OPC_DMULT :
            op1 == OPC_DMULTU ? MIPS_ID_OPC_DMULTU :
            op1 == OPC_DDIV ? MIPS_ID_OPC_DDIV :
            op1 == OPC_DDIVU ? MIPS_ID_OPC_DDIVU :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        check_mips_64(ctx);
        gen_muldiv(ctx, op1, 0, rs, rt);
        break;
#endif
    case OPC_JR:
        mips_ident(ctx,
            op1 == OPC_JR ? MIPS_ID_OPC_JR :
            MIPS_ID_NONE);
        gen_compute_branch(ctx, op1, 4, rs, 0, 0, 4);
        break;
    case OPC_SPIM:
        mips_ident(ctx,
            op1 == OPC_SPIM ? MIPS_ID_OPC_SPIM :
            MIPS_ID_NONE);
#ifdef MIPS_STRICT_STANDARD
        MIPS_INVAL("SPIM");
        gen_reserved_instruction(ctx);
#else
        /* Implemented as RI exception for now. */
        MIPS_INVAL("spim (unofficial)");
        gen_reserved_instruction(ctx);
#endif
        break;
    default:            /* Invalid */
        MIPS_INVAL("special_legacy");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void decode_opc_special(CPUMIPSState *env, DisasContext *ctx)
{
    int rs, rt, rd, sa;
    uint32_t op1;

    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;
    sa = (ctx->opcode >> 6) & 0x1f;

    op1 = MASK_SPECIAL(ctx->opcode);
    switch (op1) {
    case OPC_SLL:          /* Shift with immediate */
        mips_ident(ctx,
            op1 == OPC_SLL ? mips_ident_q_OPC_SLL(ctx->opcode) :
            MIPS_ID_NONE);
        if (sa == 5 && rd == 0 &&
            rs == 0 && rt == 0) { /* PAUSE */
            if ((ctx->insn_flags & ISA_MIPS_R6) &&
                (ctx->hflags & MIPS_HFLAG_BMASK)) {
                gen_reserved_instruction(ctx);
                break;
            }
        }
        /* Fallthrough */
    case OPC_SRA:
        mips_ident(ctx,
            op1 == OPC_SRA ? MIPS_ID_OPC_SRA :
            MIPS_ID_NONE);
        gen_shift_imm(ctx, op1, rd, rt, sa);
        break;
    case OPC_SRL:
        mips_ident(ctx,
            op1 == OPC_SRL ? MIPS_ID_OPC_SRL :
            MIPS_ID_NONE);
        switch ((ctx->opcode >> 21) & 0x1f) {
        case 1:
            /* rotr is decoded as srl on non-R2 CPUs */
            if (ctx->insn_flags & ISA_MIPS_R2) {
                op1 = OPC_ROTR;
            }
            /* Fallthrough */
        case 0:
            gen_shift_imm(ctx, op1, rd, rt, sa);
            break;
        default:
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_ADD:
    case OPC_ADDU:
    case OPC_SUB:
    case OPC_SUBU:
        mips_ident(ctx,
            op1 == OPC_ADD ? MIPS_ID_OPC_ADD :
            op1 == OPC_ADDU ? MIPS_ID_OPC_ADDU :
            op1 == OPC_SUB ? MIPS_ID_OPC_SUB :
            op1 == OPC_SUBU ? MIPS_ID_OPC_SUBU :
            MIPS_ID_NONE);
        gen_arith(ctx, op1, rd, rs, rt);
        break;
    case OPC_SLLV:         /* Shifts */
    case OPC_SRAV:
        mips_ident(ctx,
            op1 == OPC_SLLV ? MIPS_ID_OPC_SLLV :
            op1 == OPC_SRAV ? MIPS_ID_OPC_SRAV :
            MIPS_ID_NONE);
        gen_shift(ctx, op1, rd, rs, rt);
        break;
    case OPC_SRLV:
        mips_ident(ctx,
            op1 == OPC_SRLV ? MIPS_ID_OPC_SRLV :
            MIPS_ID_NONE);
        switch ((ctx->opcode >> 6) & 0x1f) {
        case 1:
            /* rotrv is decoded as srlv on non-R2 CPUs */
            if (ctx->insn_flags & ISA_MIPS_R2) {
                op1 = OPC_ROTRV;
            }
            /* Fallthrough */
        case 0:
            gen_shift(ctx, op1, rd, rs, rt);
            break;
        default:
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_SLT:          /* Set on less than */
    case OPC_SLTU:
        mips_ident(ctx,
            op1 == OPC_SLT ? MIPS_ID_OPC_SLT :
            op1 == OPC_SLTU ? MIPS_ID_OPC_SLTU :
            MIPS_ID_NONE);
        gen_slt(ctx, op1, rd, rs, rt);
        break;
    case OPC_AND:          /* Logic*/
    case OPC_OR:
    case OPC_NOR:
    case OPC_XOR:
        mips_ident(ctx,
            op1 == OPC_AND ? MIPS_ID_OPC_AND :
            op1 == OPC_OR ? MIPS_ID_OPC_OR :
            op1 == OPC_NOR ? MIPS_ID_OPC_NOR :
            op1 == OPC_XOR ? MIPS_ID_OPC_XOR :
            MIPS_ID_NONE);
        gen_logic(ctx, op1, rd, rs, rt);
        break;
    case OPC_JALR:
        mips_ident(ctx,
            op1 == OPC_JALR ? MIPS_ID_OPC_JALR :
            MIPS_ID_NONE);
        gen_compute_branch(ctx, op1, 4, rs, rd, sa, 4);
        break;
    case OPC_TGE: /* Traps */
    case OPC_TGEU:
    case OPC_TLT:
    case OPC_TLTU:
    case OPC_TEQ:
    case OPC_TNE:
        mips_ident(ctx,
            op1 == OPC_TGE ? MIPS_ID_OPC_TGE :
            op1 == OPC_TGEU ? MIPS_ID_OPC_TGEU :
            op1 == OPC_TLT ? MIPS_ID_OPC_TLT :
            op1 == OPC_TLTU ? MIPS_ID_OPC_TLTU :
            op1 == OPC_TEQ ? MIPS_ID_OPC_TEQ :
            op1 == OPC_TNE ? MIPS_ID_OPC_TNE :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS2);
        gen_trap(ctx, op1, rs, rt, -1, extract32(ctx->opcode, 6, 10));
        break;
    case OPC_PMON:
        mips_ident(ctx,
            op1 == OPC_PMON ? MIPS_ID_OPC_PMON :
            MIPS_ID_NONE);
        /* Pmon entry point, also R4010 selsl */
#ifdef MIPS_STRICT_STANDARD
        MIPS_INVAL("PMON / selsl");
        gen_reserved_instruction(ctx);
#else
        gen_helper_pmon(tcg_env, tcg_constant_i32(sa));
#endif
        break;
    case OPC_SYSCALL:
        mips_ident(ctx,
            op1 == OPC_SYSCALL ? MIPS_ID_OPC_SYSCALL :
            MIPS_ID_NONE);
        generate_exception_end(ctx, EXCP_SYSCALL);
        break;
    case OPC_BREAK:
        mips_ident(ctx,
            op1 == OPC_BREAK ? MIPS_ID_OPC_BREAK :
            MIPS_ID_NONE);
        generate_exception_break(ctx, extract32(ctx->opcode, 6, 20));
        break;
    case OPC_SYNC:
        mips_ident(ctx,
            op1 == OPC_SYNC ? MIPS_ID_OPC_SYNC :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS2);
        gen_sync(extract32(ctx->opcode, 6, 5));
        break;

#if defined(TARGET_MIPS64)
        /* MIPS64 specific opcodes */
    case OPC_DSLL:
    case OPC_DSRA:
    case OPC_DSLL32:
    case OPC_DSRA32:
        mips_ident(ctx,
            op1 == OPC_DSLL ? MIPS_ID_OPC_DSLL :
            op1 == OPC_DSRA ? MIPS_ID_OPC_DSRA :
            op1 == OPC_DSLL32 ? MIPS_ID_OPC_DSLL32 :
            op1 == OPC_DSRA32 ? MIPS_ID_OPC_DSRA32 :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        check_mips_64(ctx);
        gen_shift_imm(ctx, op1, rd, rt, sa);
        break;
    case OPC_DSRL:
        mips_ident(ctx,
            op1 == OPC_DSRL ? MIPS_ID_OPC_DSRL :
            MIPS_ID_NONE);
        switch ((ctx->opcode >> 21) & 0x1f) {
        case 1:
            /* drotr is decoded as dsrl on non-R2 CPUs */
            if (ctx->insn_flags & ISA_MIPS_R2) {
                op1 = OPC_DROTR;
            }
            /* Fallthrough */
        case 0:
            check_insn(ctx, ISA_MIPS3);
            check_mips_64(ctx);
            gen_shift_imm(ctx, op1, rd, rt, sa);
            break;
        default:
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_DSRL32:
        mips_ident(ctx,
            op1 == OPC_DSRL32 ? MIPS_ID_OPC_DSRL32 :
            MIPS_ID_NONE);
        switch ((ctx->opcode >> 21) & 0x1f) {
        case 1:
            /* drotr32 is decoded as dsrl32 on non-R2 CPUs */
            if (ctx->insn_flags & ISA_MIPS_R2) {
                op1 = OPC_DROTR32;
            }
            /* Fallthrough */
        case 0:
            check_insn(ctx, ISA_MIPS3);
            check_mips_64(ctx);
            gen_shift_imm(ctx, op1, rd, rt, sa);
            break;
        default:
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_DADD:
    case OPC_DADDU:
    case OPC_DSUB:
    case OPC_DSUBU:
        mips_ident(ctx,
            op1 == OPC_DADD ? MIPS_ID_OPC_DADD :
            op1 == OPC_DADDU ? MIPS_ID_OPC_DADDU :
            op1 == OPC_DSUB ? MIPS_ID_OPC_DSUB :
            op1 == OPC_DSUBU ? MIPS_ID_OPC_DSUBU :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        check_mips_64(ctx);
        gen_arith(ctx, op1, rd, rs, rt);
        break;
    case OPC_DSLLV:
    case OPC_DSRAV:
        mips_ident(ctx,
            op1 == OPC_DSLLV ? MIPS_ID_OPC_DSLLV :
            op1 == OPC_DSRAV ? MIPS_ID_OPC_DSRAV :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        check_mips_64(ctx);
        gen_shift(ctx, op1, rd, rs, rt);
        break;
    case OPC_DSRLV:
        mips_ident(ctx,
            op1 == OPC_DSRLV ? MIPS_ID_OPC_DSRLV :
            MIPS_ID_NONE);
        switch ((ctx->opcode >> 6) & 0x1f) {
        case 1:
            /* drotrv is decoded as dsrlv on non-R2 CPUs */
            if (ctx->insn_flags & ISA_MIPS_R2) {
                op1 = OPC_DROTRV;
            }
            /* Fallthrough */
        case 0:
            check_insn(ctx, ISA_MIPS3);
            check_mips_64(ctx);
            gen_shift(ctx, op1, rd, rs, rt);
            break;
        default:
            gen_reserved_instruction(ctx);
            break;
        }
        break;
#endif
    default:
        if (ctx->insn_flags & ISA_MIPS_R6) {
            decode_opc_special_r6(env, ctx);
        } else if (ctx->insn_flags & INSN_R5900) {
            decode_opc_special_tx79(env, ctx);
        } else {
            decode_opc_special_legacy(env, ctx);
        }
    }
}


static void decode_opc_special2_legacy(CPUMIPSState *env, DisasContext *ctx)
{
    int rs, rt, rd;
    uint32_t op1;

    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;

    op1 = MASK_SPECIAL2(ctx->opcode);
    switch (op1) {
    case OPC_MADD: /* Multiply and add/sub */
    case OPC_MADDU:
    case OPC_MSUB:
    case OPC_MSUBU:
        mips_ident(ctx,
            op1 == OPC_MADD ? MIPS_ID_OPC_MADD :
            op1 == OPC_MADDU ? MIPS_ID_OPC_MADDU :
            op1 == OPC_MSUB ? MIPS_ID_OPC_MSUB :
            op1 == OPC_MSUBU ? MIPS_ID_OPC_MSUBU :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R1);
        gen_muldiv(ctx, op1, rd & 3, rs, rt);
        break;
    case OPC_MUL:
        mips_ident(ctx,
            op1 == OPC_MUL ? MIPS_ID_OPC_MUL :
            MIPS_ID_NONE);
        gen_arith(ctx, op1, rd, rs, rt);
        break;
    case OPC_CLO:
    case OPC_CLZ:
        mips_ident(ctx,
            op1 == OPC_CLO ? MIPS_ID_OPC_CLO :
            op1 == OPC_CLZ ? MIPS_ID_OPC_CLZ :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R1);
        gen_cl(ctx, op1, rd, rs);
        break;
    case OPC_SDBBP:
        mips_ident(ctx,
            op1 == OPC_SDBBP ? MIPS_ID_OPC_SDBBP :
            MIPS_ID_NONE);
        if (is_uhi(ctx, extract32(ctx->opcode, 6, 20))) {
            ctx->base.is_jmp = DISAS_SEMIHOST;
        } else {
            /*
             * XXX: not clear which exception should be raised
             *      when in debug mode...
             */
            check_insn(ctx, ISA_MIPS_R1);
            generate_exception_end(ctx, EXCP_DBp);
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DCLO:
    case OPC_DCLZ:
        mips_ident(ctx,
            op1 == OPC_DCLO ? MIPS_ID_OPC_DCLO :
            op1 == OPC_DCLZ ? MIPS_ID_OPC_DCLZ :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R1);
        check_mips_64(ctx);
        gen_cl(ctx, op1, rd, rs);
        break;
#endif
    default:            /* Invalid */
        MIPS_INVAL("special2_legacy");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void decode_opc_special3_r6(CPUMIPSState *env, DisasContext *ctx)
{
    int rs, rt, rd, sa;
    uint32_t op1, op2;
    int16_t imm;

    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;
    sa = (ctx->opcode >> 6) & 0x1f;
    imm = (int16_t)ctx->opcode >> 7;

    op1 = MASK_SPECIAL3(ctx->opcode);
    switch (op1) {
    case R6_OPC_PREF:
        mips_ident(ctx,
            op1 == R6_OPC_PREF ? MIPS_ID_R6_OPC_PREF :
            MIPS_ID_NONE);
        if (rt >= 24) {
            /* hint codes 24-31 are reserved and signal RI */
            gen_reserved_instruction(ctx);
        }
        /* Treat as NOP.  See gen_pref_note_operands() for the read it hides. */
        gen_pref_note_operands(rs, -1);
        break;
    case R6_OPC_CACHE:
        mips_ident(ctx,
            op1 == R6_OPC_CACHE ? MIPS_ID_R6_OPC_CACHE :
            MIPS_ID_NONE);
        check_cp0_enabled(ctx);
        if (ctx->hflags & MIPS_HFLAG_ITC_CACHE) {
            gen_cache_operation(ctx, rt, rs, imm);
        }
        break;
    case R6_OPC_SC:
        mips_ident(ctx,
            op1 == R6_OPC_SC ? MIPS_ID_R6_OPC_SC :
            MIPS_ID_NONE);
        gen_st_cond(ctx, rt, rs, imm, mo_endian(ctx) | MO_SL, false);
        break;
    case R6_OPC_LL:
        mips_ident(ctx,
            op1 == R6_OPC_LL ? MIPS_ID_R6_OPC_LL :
            MIPS_ID_NONE);
        gen_ld(ctx, op1, rt, rs, imm);
        break;
    case OPC_BSHFL:
        mips_ident(ctx,
            op1 == OPC_BSHFL ? MIPS_ID_OPC_BSHFL :
            MIPS_ID_NONE);
        {
            if (rd == 0) {
                /* Treat as NOP. */
                break;
            }
            op2 = MASK_BSHFL(ctx->opcode);
            switch (op2) {
            case OPC_ALIGN:
            case OPC_ALIGN_1:
            case OPC_ALIGN_2:
            case OPC_ALIGN_3:
                mips_ident(ctx,
                    op2 == OPC_ALIGN ? MIPS_ID_OPC_ALIGN :
                    op2 == OPC_ALIGN_1 ? MIPS_ID_OPC_ALIGN_1 :
                    op2 == OPC_ALIGN_2 ? MIPS_ID_OPC_ALIGN_2 :
                    op2 == OPC_ALIGN_3 ? MIPS_ID_OPC_ALIGN_3 :
                    MIPS_ID_NONE);
                gen_align(ctx, 32, rd, rs, rt, sa & 3);
                break;
            case OPC_BITSWAP:
                mips_ident(ctx,
                    op2 == OPC_BITSWAP ? MIPS_ID_OPC_BITSWAP :
                    MIPS_ID_NONE);
                gen_bitswap(ctx, op2, rd, rt);
                break;
            }
        }
        break;
#ifndef CONFIG_USER_ONLY
    case OPC_GINV:
        mips_ident(ctx,
            op1 == OPC_GINV ? MIPS_ID_OPC_GINV :
            MIPS_ID_NONE);
        if (unlikely(ctx->gi <= 1)) {
            gen_reserved_instruction(ctx);
        }
        check_cp0_enabled(ctx);
        switch ((ctx->opcode >> 6) & 3) {
        case 0:    /* GINVI */
            /* Treat as NOP. */
            break;
        case 2:    /* GINVT */
            gen_helper_0e1i(ginvt, cpu_gpr[rs], extract32(ctx->opcode, 8, 2));
            break;
        default:
            gen_reserved_instruction(ctx);
            break;
        }
        break;
#endif
#if defined(TARGET_MIPS64)
    case R6_OPC_SCD:
        mips_ident(ctx,
            op1 == R6_OPC_SCD ? MIPS_ID_R6_OPC_SCD :
            MIPS_ID_NONE);
        gen_st_cond(ctx, rt, rs, imm, mo_endian(ctx) | MO_UQ, false);
        break;
    case R6_OPC_LLD:
        mips_ident(ctx,
            op1 == R6_OPC_LLD ? MIPS_ID_R6_OPC_LLD :
            MIPS_ID_NONE);
        gen_ld(ctx, op1, rt, rs, imm);
        break;
    case OPC_DBSHFL:
        mips_ident(ctx,
            op1 == OPC_DBSHFL ? MIPS_ID_OPC_DBSHFL :
            MIPS_ID_NONE);
        check_mips_64(ctx);
        {
            if (rd == 0) {
                /* Treat as NOP. */
                break;
            }
            op2 = MASK_DBSHFL(ctx->opcode);
            switch (op2) {
            case OPC_DALIGN:
            case OPC_DALIGN_1:
            case OPC_DALIGN_2:
            case OPC_DALIGN_3:
            case OPC_DALIGN_4:
            case OPC_DALIGN_5:
            case OPC_DALIGN_6:
            case OPC_DALIGN_7:
                mips_ident(ctx,
                    op2 == OPC_DALIGN ? MIPS_ID_OPC_DALIGN :
                    op2 == OPC_DALIGN_1 ? MIPS_ID_OPC_DALIGN_1 :
                    op2 == OPC_DALIGN_2 ? MIPS_ID_OPC_DALIGN_2 :
                    op2 == OPC_DALIGN_3 ? MIPS_ID_OPC_DALIGN_3 :
                    op2 == OPC_DALIGN_4 ? MIPS_ID_OPC_DALIGN_4 :
                    op2 == OPC_DALIGN_5 ? MIPS_ID_OPC_DALIGN_5 :
                    op2 == OPC_DALIGN_6 ? MIPS_ID_OPC_DALIGN_6 :
                    op2 == OPC_DALIGN_7 ? MIPS_ID_OPC_DALIGN_7 :
                    MIPS_ID_NONE);
                gen_align(ctx, 64, rd, rs, rt, sa & 7);
                break;
            case OPC_DBITSWAP:
                mips_ident(ctx,
                    op2 == OPC_DBITSWAP ? MIPS_ID_OPC_DBITSWAP :
                    MIPS_ID_NONE);
                gen_bitswap(ctx, op2, rd, rt);
                break;
            }

        }
        break;
#endif
    default:            /* Invalid */
        MIPS_INVAL("special3_r6");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void decode_opc_special3_legacy(CPUMIPSState *env, DisasContext *ctx)
{
    int rs, rt, rd;
    uint32_t op1, op2;

    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;

    op1 = MASK_SPECIAL3(ctx->opcode);
    switch (op1) {
    case OPC_MUL_PH_DSP:
        mips_ident(ctx,
            op1 == OPC_MUL_PH_DSP ? MIPS_ID_OPC_MUL_PH_DSP :
            MIPS_ID_NONE);
        /*
         * OPC_ADDUH_QB_DSP, OPC_MUL_PH_DSP have
         * the same mask and op1.
         */
        if ((ctx->insn_flags & ASE_DSP_R2) && (op1 == OPC_MUL_PH_DSP)) {
            op2 = MASK_ADDUH_QB(ctx->opcode);
            switch (op2) {
            case OPC_ADDUH_QB:
            case OPC_ADDUH_R_QB:
            case OPC_ADDQH_PH:
            case OPC_ADDQH_R_PH:
            case OPC_ADDQH_W:
            case OPC_ADDQH_R_W:
            case OPC_SUBUH_QB:
            case OPC_SUBUH_R_QB:
            case OPC_SUBQH_PH:
            case OPC_SUBQH_R_PH:
            case OPC_SUBQH_W:
            case OPC_SUBQH_R_W:
                mips_ident(ctx,
                    op2 == OPC_ADDUH_QB ? MIPS_ID_OPC_ADDUH_QB :
                    op2 == OPC_ADDUH_R_QB ? MIPS_ID_OPC_ADDUH_R_QB :
                    op2 == OPC_ADDQH_PH ? MIPS_ID_OPC_ADDQH_PH :
                    op2 == OPC_ADDQH_R_PH ? MIPS_ID_OPC_ADDQH_R_PH :
                    op2 == OPC_ADDQH_W ? MIPS_ID_OPC_ADDQH_W :
                    op2 == OPC_ADDQH_R_W ? MIPS_ID_OPC_ADDQH_R_W :
                    op2 == OPC_SUBUH_QB ? MIPS_ID_OPC_SUBUH_QB :
                    op2 == OPC_SUBUH_R_QB ? MIPS_ID_OPC_SUBUH_R_QB :
                    op2 == OPC_SUBQH_PH ? MIPS_ID_OPC_SUBQH_PH :
                    op2 == OPC_SUBQH_R_PH ? MIPS_ID_OPC_SUBQH_R_PH :
                    op2 == OPC_SUBQH_W ? MIPS_ID_OPC_SUBQH_W :
                    op2 == OPC_SUBQH_R_W ? MIPS_ID_OPC_SUBQH_R_W :
                    MIPS_ID_NONE);
                gen_mipsdsp_arith(ctx, op1, op2, rd, rs, rt);
                break;
            case OPC_MUL_PH:
            case OPC_MUL_S_PH:
            case OPC_MULQ_S_W:
            case OPC_MULQ_RS_W:
                mips_ident(ctx,
                    op2 == OPC_MUL_PH ? MIPS_ID_OPC_MUL_PH :
                    op2 == OPC_MUL_S_PH ? MIPS_ID_OPC_MUL_S_PH :
                    op2 == OPC_MULQ_S_W ? MIPS_ID_OPC_MULQ_S_W :
                    op2 == OPC_MULQ_RS_W ? MIPS_ID_OPC_MULQ_RS_W :
                    MIPS_ID_NONE);
                gen_mipsdsp_multiply(ctx, op1, op2, rd, rs, rt, 1);
                break;
            default:
                MIPS_INVAL("MASK ADDUH.QB");
                gen_reserved_instruction(ctx);
                break;
            }
        } else {
            gen_reserved_instruction(ctx);
        }
        break;
    case OPC_LX_DSP:
        mips_ident(ctx,
            op1 == OPC_LX_DSP ? MIPS_ID_OPC_LX_DSP :
            MIPS_ID_NONE);
        op2 = MASK_LX(ctx->opcode);
        switch (op2) {
#if defined(TARGET_MIPS64)
        case OPC_LDX:
            mips_ident(ctx,
                op2 == OPC_LDX ? MIPS_ID_OPC_LDX :
                MIPS_ID_NONE);
            QEMU_FALLTHROUGH;  /* mips_ident */
#endif
        case OPC_LBUX:
        case OPC_LHX:
        case OPC_LWX:
            mips_ident(ctx,
                op2 == OPC_LBUX ? MIPS_ID_OPC_LBUX :
                op2 == OPC_LHX ? MIPS_ID_OPC_LHX :
                op2 == OPC_LWX ? MIPS_ID_OPC_LWX :
                MIPS_ID_NONE);
            gen_mips_lx(ctx, op2, rd, rs, rt);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK LX");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_ABSQ_S_PH_DSP:
        mips_ident(ctx,
            op1 == OPC_ABSQ_S_PH_DSP ? MIPS_ID_OPC_ABSQ_S_PH_DSP :
            MIPS_ID_NONE);
        op2 = MASK_ABSQ_S_PH(ctx->opcode);
        switch (op2) {
        case OPC_ABSQ_S_QB:
        case OPC_ABSQ_S_PH:
        case OPC_ABSQ_S_W:
        case OPC_PRECEQ_W_PHL:
        case OPC_PRECEQ_W_PHR:
        case OPC_PRECEQU_PH_QBL:
        case OPC_PRECEQU_PH_QBR:
        case OPC_PRECEQU_PH_QBLA:
        case OPC_PRECEQU_PH_QBRA:
        case OPC_PRECEU_PH_QBL:
        case OPC_PRECEU_PH_QBR:
        case OPC_PRECEU_PH_QBLA:
        case OPC_PRECEU_PH_QBRA:
            mips_ident(ctx,
                op2 == OPC_ABSQ_S_QB ? MIPS_ID_OPC_ABSQ_S_QB :
                op2 == OPC_ABSQ_S_PH ? MIPS_ID_OPC_ABSQ_S_PH :
                op2 == OPC_ABSQ_S_W ? MIPS_ID_OPC_ABSQ_S_W :
                op2 == OPC_PRECEQ_W_PHL ? MIPS_ID_OPC_PRECEQ_W_PHL :
                op2 == OPC_PRECEQ_W_PHR ? MIPS_ID_OPC_PRECEQ_W_PHR :
                op2 == OPC_PRECEQU_PH_QBL ? MIPS_ID_OPC_PRECEQU_PH_QBL :
                op2 == OPC_PRECEQU_PH_QBR ? MIPS_ID_OPC_PRECEQU_PH_QBR :
                op2 == OPC_PRECEQU_PH_QBLA ? MIPS_ID_OPC_PRECEQU_PH_QBLA :
                op2 == OPC_PRECEQU_PH_QBRA ? MIPS_ID_OPC_PRECEQU_PH_QBRA :
                op2 == OPC_PRECEU_PH_QBL ? MIPS_ID_OPC_PRECEU_PH_QBL :
                op2 == OPC_PRECEU_PH_QBR ? MIPS_ID_OPC_PRECEU_PH_QBR :
                op2 == OPC_PRECEU_PH_QBLA ? MIPS_ID_OPC_PRECEU_PH_QBLA :
                op2 == OPC_PRECEU_PH_QBRA ? MIPS_ID_OPC_PRECEU_PH_QBRA :
                MIPS_ID_NONE);
            gen_mipsdsp_arith(ctx, op1, op2, rd, rs, rt);
            break;
        case OPC_BITREV:
        case OPC_REPL_QB:
        case OPC_REPLV_QB:
        case OPC_REPL_PH:
        case OPC_REPLV_PH:
            mips_ident(ctx,
                op2 == OPC_BITREV ? MIPS_ID_OPC_BITREV :
                op2 == OPC_REPL_QB ? MIPS_ID_OPC_REPL_QB :
                op2 == OPC_REPLV_QB ? MIPS_ID_OPC_REPLV_QB :
                op2 == OPC_REPL_PH ? MIPS_ID_OPC_REPL_PH :
                op2 == OPC_REPLV_PH ? MIPS_ID_OPC_REPLV_PH :
                MIPS_ID_NONE);
            gen_mipsdsp_bitinsn(ctx, op1, op2, rd, rt);
            break;
        default:
            MIPS_INVAL("MASK ABSQ_S.PH");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_ADDU_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_ADDU_QB_DSP ? MIPS_ID_OPC_ADDU_QB_DSP :
            MIPS_ID_NONE);
        op2 = MASK_ADDU_QB(ctx->opcode);
        switch (op2) {
        case OPC_ADDQ_PH:
        case OPC_ADDQ_S_PH:
        case OPC_ADDQ_S_W:
        case OPC_ADDU_QB:
        case OPC_ADDU_S_QB:
        case OPC_ADDU_PH:
        case OPC_ADDU_S_PH:
        case OPC_SUBQ_PH:
        case OPC_SUBQ_S_PH:
        case OPC_SUBQ_S_W:
        case OPC_SUBU_QB:
        case OPC_SUBU_S_QB:
        case OPC_SUBU_PH:
        case OPC_SUBU_S_PH:
        case OPC_ADDSC:
        case OPC_ADDWC:
        case OPC_MODSUB:
        case OPC_RADDU_W_QB:
            mips_ident(ctx,
                op2 == OPC_ADDQ_PH ? MIPS_ID_OPC_ADDQ_PH :
                op2 == OPC_ADDQ_S_PH ? MIPS_ID_OPC_ADDQ_S_PH :
                op2 == OPC_ADDQ_S_W ? MIPS_ID_OPC_ADDQ_S_W :
                op2 == OPC_ADDU_QB ? MIPS_ID_OPC_ADDU_QB :
                op2 == OPC_ADDU_S_QB ? MIPS_ID_OPC_ADDU_S_QB :
                op2 == OPC_ADDU_PH ? MIPS_ID_OPC_ADDU_PH :
                op2 == OPC_ADDU_S_PH ? MIPS_ID_OPC_ADDU_S_PH :
                op2 == OPC_SUBQ_PH ? MIPS_ID_OPC_SUBQ_PH :
                op2 == OPC_SUBQ_S_PH ? MIPS_ID_OPC_SUBQ_S_PH :
                op2 == OPC_SUBQ_S_W ? MIPS_ID_OPC_SUBQ_S_W :
                op2 == OPC_SUBU_QB ? MIPS_ID_OPC_SUBU_QB :
                op2 == OPC_SUBU_S_QB ? MIPS_ID_OPC_SUBU_S_QB :
                op2 == OPC_SUBU_PH ? MIPS_ID_OPC_SUBU_PH :
                op2 == OPC_SUBU_S_PH ? MIPS_ID_OPC_SUBU_S_PH :
                op2 == OPC_ADDSC ? MIPS_ID_OPC_ADDSC :
                op2 == OPC_ADDWC ? MIPS_ID_OPC_ADDWC :
                op2 == OPC_MODSUB ? MIPS_ID_OPC_MODSUB :
                op2 == OPC_RADDU_W_QB ? MIPS_ID_OPC_RADDU_W_QB :
                MIPS_ID_NONE);
            gen_mipsdsp_arith(ctx, op1, op2, rd, rs, rt);
            break;
        case OPC_MULEU_S_PH_QBL:
        case OPC_MULEU_S_PH_QBR:
        case OPC_MULQ_RS_PH:
        case OPC_MULEQ_S_W_PHL:
        case OPC_MULEQ_S_W_PHR:
        case OPC_MULQ_S_PH:
            mips_ident(ctx,
                op2 == OPC_MULEU_S_PH_QBL ? MIPS_ID_OPC_MULEU_S_PH_QBL :
                op2 == OPC_MULEU_S_PH_QBR ? MIPS_ID_OPC_MULEU_S_PH_QBR :
                op2 == OPC_MULQ_RS_PH ? MIPS_ID_OPC_MULQ_RS_PH :
                op2 == OPC_MULEQ_S_W_PHL ? MIPS_ID_OPC_MULEQ_S_W_PHL :
                op2 == OPC_MULEQ_S_W_PHR ? MIPS_ID_OPC_MULEQ_S_W_PHR :
                op2 == OPC_MULQ_S_PH ? MIPS_ID_OPC_MULQ_S_PH :
                MIPS_ID_NONE);
            gen_mipsdsp_multiply(ctx, op1, op2, rd, rs, rt, 1);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK ADDU.QB");
            gen_reserved_instruction(ctx);
            break;

        }
        break;
    case OPC_CMPU_EQ_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_CMPU_EQ_QB_DSP ? MIPS_ID_OPC_CMPU_EQ_QB_DSP :
            MIPS_ID_NONE);
        op2 = MASK_CMPU_EQ_QB(ctx->opcode);
        switch (op2) {
        case OPC_PRECR_SRA_PH_W:
        case OPC_PRECR_SRA_R_PH_W:
            mips_ident(ctx,
                op2 == OPC_PRECR_SRA_PH_W ? MIPS_ID_OPC_PRECR_SRA_PH_W :
                op2 == OPC_PRECR_SRA_R_PH_W ? MIPS_ID_OPC_PRECR_SRA_R_PH_W :
                MIPS_ID_NONE);
            gen_mipsdsp_arith(ctx, op1, op2, rt, rs, rd);
            break;
        case OPC_PRECR_QB_PH:
        case OPC_PRECRQ_QB_PH:
        case OPC_PRECRQ_PH_W:
        case OPC_PRECRQ_RS_PH_W:
        case OPC_PRECRQU_S_QB_PH:
            mips_ident(ctx,
                op2 == OPC_PRECR_QB_PH ? MIPS_ID_OPC_PRECR_QB_PH :
                op2 == OPC_PRECRQ_QB_PH ? MIPS_ID_OPC_PRECRQ_QB_PH :
                op2 == OPC_PRECRQ_PH_W ? MIPS_ID_OPC_PRECRQ_PH_W :
                op2 == OPC_PRECRQ_RS_PH_W ? MIPS_ID_OPC_PRECRQ_RS_PH_W :
                op2 == OPC_PRECRQU_S_QB_PH ? MIPS_ID_OPC_PRECRQU_S_QB_PH :
                MIPS_ID_NONE);
            gen_mipsdsp_arith(ctx, op1, op2, rd, rs, rt);
            break;
        case OPC_CMPU_EQ_QB:
        case OPC_CMPU_LT_QB:
        case OPC_CMPU_LE_QB:
        case OPC_CMP_EQ_PH:
        case OPC_CMP_LT_PH:
        case OPC_CMP_LE_PH:
            mips_ident(ctx,
                op2 == OPC_CMPU_EQ_QB ? MIPS_ID_OPC_CMPU_EQ_QB :
                op2 == OPC_CMPU_LT_QB ? MIPS_ID_OPC_CMPU_LT_QB :
                op2 == OPC_CMPU_LE_QB ? MIPS_ID_OPC_CMPU_LE_QB :
                op2 == OPC_CMP_EQ_PH ? MIPS_ID_OPC_CMP_EQ_PH :
                op2 == OPC_CMP_LT_PH ? MIPS_ID_OPC_CMP_LT_PH :
                op2 == OPC_CMP_LE_PH ? MIPS_ID_OPC_CMP_LE_PH :
                MIPS_ID_NONE);
            gen_mipsdsp_add_cmp_pick(ctx, op1, op2, rd, rs, rt, 0);
            break;
        case OPC_CMPGU_EQ_QB:
        case OPC_CMPGU_LT_QB:
        case OPC_CMPGU_LE_QB:
        case OPC_CMPGDU_EQ_QB:
        case OPC_CMPGDU_LT_QB:
        case OPC_CMPGDU_LE_QB:
        case OPC_PICK_QB:
        case OPC_PICK_PH:
        case OPC_PACKRL_PH:
            mips_ident(ctx,
                op2 == OPC_CMPGU_EQ_QB ? MIPS_ID_OPC_CMPGU_EQ_QB :
                op2 == OPC_CMPGU_LT_QB ? MIPS_ID_OPC_CMPGU_LT_QB :
                op2 == OPC_CMPGU_LE_QB ? MIPS_ID_OPC_CMPGU_LE_QB :
                op2 == OPC_CMPGDU_EQ_QB ? MIPS_ID_OPC_CMPGDU_EQ_QB :
                op2 == OPC_CMPGDU_LT_QB ? MIPS_ID_OPC_CMPGDU_LT_QB :
                op2 == OPC_CMPGDU_LE_QB ? MIPS_ID_OPC_CMPGDU_LE_QB :
                op2 == OPC_PICK_QB ? MIPS_ID_OPC_PICK_QB :
                op2 == OPC_PICK_PH ? MIPS_ID_OPC_PICK_PH :
                op2 == OPC_PACKRL_PH ? MIPS_ID_OPC_PACKRL_PH :
                MIPS_ID_NONE);
            gen_mipsdsp_add_cmp_pick(ctx, op1, op2, rd, rs, rt, 1);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK CMPU.EQ.QB");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_SHLL_QB_DSP:
        mips_ident(ctx,
            op1 == OPC_SHLL_QB_DSP ? MIPS_ID_OPC_SHLL_QB_DSP :
            MIPS_ID_NONE);
        gen_mipsdsp_shift(ctx, op1, rd, rs, rt);
        break;
    case OPC_DPA_W_PH_DSP:
        mips_ident(ctx,
            op1 == OPC_DPA_W_PH_DSP ? MIPS_ID_OPC_DPA_W_PH_DSP :
            MIPS_ID_NONE);
        op2 = MASK_DPA_W_PH(ctx->opcode);
        switch (op2) {
        case OPC_DPAU_H_QBL:
        case OPC_DPAU_H_QBR:
        case OPC_DPSU_H_QBL:
        case OPC_DPSU_H_QBR:
        case OPC_DPA_W_PH:
        case OPC_DPAX_W_PH:
        case OPC_DPAQ_S_W_PH:
        case OPC_DPAQX_S_W_PH:
        case OPC_DPAQX_SA_W_PH:
        case OPC_DPS_W_PH:
        case OPC_DPSX_W_PH:
        case OPC_DPSQ_S_W_PH:
        case OPC_DPSQX_S_W_PH:
        case OPC_DPSQX_SA_W_PH:
        case OPC_MULSAQ_S_W_PH:
        case OPC_DPAQ_SA_L_W:
        case OPC_DPSQ_SA_L_W:
        case OPC_MAQ_S_W_PHL:
        case OPC_MAQ_S_W_PHR:
        case OPC_MAQ_SA_W_PHL:
        case OPC_MAQ_SA_W_PHR:
        case OPC_MULSA_W_PH:
            mips_ident(ctx,
                op2 == OPC_DPAU_H_QBL ? MIPS_ID_OPC_DPAU_H_QBL :
                op2 == OPC_DPAU_H_QBR ? MIPS_ID_OPC_DPAU_H_QBR :
                op2 == OPC_DPSU_H_QBL ? MIPS_ID_OPC_DPSU_H_QBL :
                op2 == OPC_DPSU_H_QBR ? MIPS_ID_OPC_DPSU_H_QBR :
                op2 == OPC_DPA_W_PH ? MIPS_ID_OPC_DPA_W_PH :
                op2 == OPC_DPAX_W_PH ? MIPS_ID_OPC_DPAX_W_PH :
                op2 == OPC_DPAQ_S_W_PH ? MIPS_ID_OPC_DPAQ_S_W_PH :
                op2 == OPC_DPAQX_S_W_PH ? MIPS_ID_OPC_DPAQX_S_W_PH :
                op2 == OPC_DPAQX_SA_W_PH ? MIPS_ID_OPC_DPAQX_SA_W_PH :
                op2 == OPC_DPS_W_PH ? MIPS_ID_OPC_DPS_W_PH :
                op2 == OPC_DPSX_W_PH ? MIPS_ID_OPC_DPSX_W_PH :
                op2 == OPC_DPSQ_S_W_PH ? MIPS_ID_OPC_DPSQ_S_W_PH :
                op2 == OPC_DPSQX_S_W_PH ? MIPS_ID_OPC_DPSQX_S_W_PH :
                op2 == OPC_DPSQX_SA_W_PH ? MIPS_ID_OPC_DPSQX_SA_W_PH :
                op2 == OPC_MULSAQ_S_W_PH ? MIPS_ID_OPC_MULSAQ_S_W_PH :
                op2 == OPC_DPAQ_SA_L_W ? MIPS_ID_OPC_DPAQ_SA_L_W :
                op2 == OPC_DPSQ_SA_L_W ? MIPS_ID_OPC_DPSQ_SA_L_W :
                op2 == OPC_MAQ_S_W_PHL ? MIPS_ID_OPC_MAQ_S_W_PHL :
                op2 == OPC_MAQ_S_W_PHR ? MIPS_ID_OPC_MAQ_S_W_PHR :
                op2 == OPC_MAQ_SA_W_PHL ? MIPS_ID_OPC_MAQ_SA_W_PHL :
                op2 == OPC_MAQ_SA_W_PHR ? MIPS_ID_OPC_MAQ_SA_W_PHR :
                op2 == OPC_MULSA_W_PH ? MIPS_ID_OPC_MULSA_W_PH :
                MIPS_ID_NONE);
            gen_mipsdsp_multiply(ctx, op1, op2, rd, rs, rt, 0);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK DPAW.PH");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_INSV_DSP:
        mips_ident(ctx,
            op1 == OPC_INSV_DSP ? MIPS_ID_OPC_INSV_DSP :
            MIPS_ID_NONE);
        op2 = MASK_INSV(ctx->opcode);
        switch (op2) {
        case OPC_INSV:
            mips_ident(ctx,
                op2 == OPC_INSV ? MIPS_ID_OPC_INSV :
                MIPS_ID_NONE);
            check_dsp(ctx);
            {
                TCGv t0, t1;

                if (rt == 0) {
                    break;
                }

                t0 = tcg_temp_new();
                t1 = tcg_temp_new();

                gen_load_gpr(t0, rt);
                gen_load_gpr(t1, rs);

                gen_helper_insv(cpu_gpr[rt], tcg_env, t1, t0);
                break;
            }
        default:            /* Invalid */
            MIPS_INVAL("MASK INSV");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_APPEND_DSP:
        mips_ident(ctx,
            op1 == OPC_APPEND_DSP ? MIPS_ID_OPC_APPEND_DSP :
            MIPS_ID_NONE);
        gen_mipsdsp_append(env, ctx, op1, rt, rs, rd);
        break;
    case OPC_EXTR_W_DSP:
        mips_ident(ctx,
            op1 == OPC_EXTR_W_DSP ? MIPS_ID_OPC_EXTR_W_DSP :
            MIPS_ID_NONE);
        op2 = MASK_EXTR_W(ctx->opcode);
        switch (op2) {
        case OPC_EXTR_W:
        case OPC_EXTR_R_W:
        case OPC_EXTR_RS_W:
        case OPC_EXTR_S_H:
        case OPC_EXTRV_S_H:
        case OPC_EXTRV_W:
        case OPC_EXTRV_R_W:
        case OPC_EXTRV_RS_W:
        case OPC_EXTP:
        case OPC_EXTPV:
        case OPC_EXTPDP:
        case OPC_EXTPDPV:
            mips_ident(ctx,
                op2 == OPC_EXTR_W ? MIPS_ID_OPC_EXTR_W :
                op2 == OPC_EXTR_R_W ? MIPS_ID_OPC_EXTR_R_W :
                op2 == OPC_EXTR_RS_W ? MIPS_ID_OPC_EXTR_RS_W :
                op2 == OPC_EXTR_S_H ? MIPS_ID_OPC_EXTR_S_H :
                op2 == OPC_EXTRV_S_H ? MIPS_ID_OPC_EXTRV_S_H :
                op2 == OPC_EXTRV_W ? MIPS_ID_OPC_EXTRV_W :
                op2 == OPC_EXTRV_R_W ? MIPS_ID_OPC_EXTRV_R_W :
                op2 == OPC_EXTRV_RS_W ? MIPS_ID_OPC_EXTRV_RS_W :
                op2 == OPC_EXTP ? MIPS_ID_OPC_EXTP :
                op2 == OPC_EXTPV ? MIPS_ID_OPC_EXTPV :
                op2 == OPC_EXTPDP ? MIPS_ID_OPC_EXTPDP :
                op2 == OPC_EXTPDPV ? MIPS_ID_OPC_EXTPDPV :
                MIPS_ID_NONE);
            gen_mipsdsp_accinsn(ctx, op1, op2, rt, rs, rd, 1);
            break;
        case OPC_RDDSP:
            mips_ident(ctx,
                op2 == OPC_RDDSP ? MIPS_ID_OPC_RDDSP :
                MIPS_ID_NONE);
            gen_mipsdsp_accinsn(ctx, op1, op2, rd, rs, rt, 1);
            break;
        case OPC_SHILO:
        case OPC_SHILOV:
        case OPC_MTHLIP:
        case OPC_WRDSP:
            mips_ident(ctx,
                op2 == OPC_SHILO ? MIPS_ID_OPC_SHILO :
                op2 == OPC_SHILOV ? MIPS_ID_OPC_SHILOV :
                op2 == OPC_MTHLIP ? MIPS_ID_OPC_MTHLIP :
                op2 == OPC_WRDSP ? MIPS_ID_OPC_WRDSP :
                MIPS_ID_NONE);
            gen_mipsdsp_accinsn(ctx, op1, op2, rd, rs, rt, 0);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK EXTR.W");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_ABSQ_S_QH_DSP:
        mips_ident(ctx,
            op1 == OPC_ABSQ_S_QH_DSP ? MIPS_ID_OPC_ABSQ_S_QH_DSP :
            MIPS_ID_NONE);
        op2 = MASK_ABSQ_S_QH(ctx->opcode);
        switch (op2) {
        case OPC_PRECEQ_L_PWL:
        case OPC_PRECEQ_L_PWR:
        case OPC_PRECEQ_PW_QHL:
        case OPC_PRECEQ_PW_QHR:
        case OPC_PRECEQ_PW_QHLA:
        case OPC_PRECEQ_PW_QHRA:
        case OPC_PRECEQU_QH_OBL:
        case OPC_PRECEQU_QH_OBR:
        case OPC_PRECEQU_QH_OBLA:
        case OPC_PRECEQU_QH_OBRA:
        case OPC_PRECEU_QH_OBL:
        case OPC_PRECEU_QH_OBR:
        case OPC_PRECEU_QH_OBLA:
        case OPC_PRECEU_QH_OBRA:
        case OPC_ABSQ_S_OB:
        case OPC_ABSQ_S_PW:
        case OPC_ABSQ_S_QH:
            mips_ident(ctx,
                op2 == OPC_PRECEQ_L_PWL ? MIPS_ID_OPC_PRECEQ_L_PWL :
                op2 == OPC_PRECEQ_L_PWR ? MIPS_ID_OPC_PRECEQ_L_PWR :
                op2 == OPC_PRECEQ_PW_QHL ? MIPS_ID_OPC_PRECEQ_PW_QHL :
                op2 == OPC_PRECEQ_PW_QHR ? MIPS_ID_OPC_PRECEQ_PW_QHR :
                op2 == OPC_PRECEQ_PW_QHLA ? MIPS_ID_OPC_PRECEQ_PW_QHLA :
                op2 == OPC_PRECEQ_PW_QHRA ? MIPS_ID_OPC_PRECEQ_PW_QHRA :
                op2 == OPC_PRECEQU_QH_OBL ? MIPS_ID_OPC_PRECEQU_QH_OBL :
                op2 == OPC_PRECEQU_QH_OBR ? MIPS_ID_OPC_PRECEQU_QH_OBR :
                op2 == OPC_PRECEQU_QH_OBLA ? MIPS_ID_OPC_PRECEQU_QH_OBLA :
                op2 == OPC_PRECEQU_QH_OBRA ? MIPS_ID_OPC_PRECEQU_QH_OBRA :
                op2 == OPC_PRECEU_QH_OBL ? MIPS_ID_OPC_PRECEU_QH_OBL :
                op2 == OPC_PRECEU_QH_OBR ? MIPS_ID_OPC_PRECEU_QH_OBR :
                op2 == OPC_PRECEU_QH_OBLA ? MIPS_ID_OPC_PRECEU_QH_OBLA :
                op2 == OPC_PRECEU_QH_OBRA ? MIPS_ID_OPC_PRECEU_QH_OBRA :
                op2 == OPC_ABSQ_S_OB ? MIPS_ID_OPC_ABSQ_S_OB :
                op2 == OPC_ABSQ_S_PW ? MIPS_ID_OPC_ABSQ_S_PW :
                op2 == OPC_ABSQ_S_QH ? MIPS_ID_OPC_ABSQ_S_QH :
                MIPS_ID_NONE);
            gen_mipsdsp_arith(ctx, op1, op2, rd, rs, rt);
            break;
        case OPC_REPL_OB:
        case OPC_REPL_PW:
        case OPC_REPL_QH:
        case OPC_REPLV_OB:
        case OPC_REPLV_PW:
        case OPC_REPLV_QH:
            mips_ident(ctx,
                op2 == OPC_REPL_OB ? MIPS_ID_OPC_REPL_OB :
                op2 == OPC_REPL_PW ? MIPS_ID_OPC_REPL_PW :
                op2 == OPC_REPL_QH ? MIPS_ID_OPC_REPL_QH :
                op2 == OPC_REPLV_OB ? MIPS_ID_OPC_REPLV_OB :
                op2 == OPC_REPLV_PW ? MIPS_ID_OPC_REPLV_PW :
                op2 == OPC_REPLV_QH ? MIPS_ID_OPC_REPLV_QH :
                MIPS_ID_NONE);
            gen_mipsdsp_bitinsn(ctx, op1, op2, rd, rt);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK ABSQ_S.QH");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_ADDU_OB_DSP:
        mips_ident(ctx,
            op1 == OPC_ADDU_OB_DSP ? MIPS_ID_OPC_ADDU_OB_DSP :
            MIPS_ID_NONE);
        op2 = MASK_ADDU_OB(ctx->opcode);
        switch (op2) {
        case OPC_RADDU_L_OB:
        case OPC_SUBQ_PW:
        case OPC_SUBQ_S_PW:
        case OPC_SUBQ_QH:
        case OPC_SUBQ_S_QH:
        case OPC_SUBU_OB:
        case OPC_SUBU_S_OB:
        case OPC_SUBU_QH:
        case OPC_SUBU_S_QH:
        case OPC_SUBUH_OB:
        case OPC_SUBUH_R_OB:
        case OPC_ADDQ_PW:
        case OPC_ADDQ_S_PW:
        case OPC_ADDQ_QH:
        case OPC_ADDQ_S_QH:
        case OPC_ADDU_OB:
        case OPC_ADDU_S_OB:
        case OPC_ADDU_QH:
        case OPC_ADDU_S_QH:
        case OPC_ADDUH_OB:
        case OPC_ADDUH_R_OB:
            mips_ident(ctx,
                op2 == OPC_RADDU_L_OB ? MIPS_ID_OPC_RADDU_L_OB :
                op2 == OPC_SUBQ_PW ? MIPS_ID_OPC_SUBQ_PW :
                op2 == OPC_SUBQ_S_PW ? MIPS_ID_OPC_SUBQ_S_PW :
                op2 == OPC_SUBQ_QH ? MIPS_ID_OPC_SUBQ_QH :
                op2 == OPC_SUBQ_S_QH ? MIPS_ID_OPC_SUBQ_S_QH :
                op2 == OPC_SUBU_OB ? MIPS_ID_OPC_SUBU_OB :
                op2 == OPC_SUBU_S_OB ? MIPS_ID_OPC_SUBU_S_OB :
                op2 == OPC_SUBU_QH ? MIPS_ID_OPC_SUBU_QH :
                op2 == OPC_SUBU_S_QH ? MIPS_ID_OPC_SUBU_S_QH :
                op2 == OPC_SUBUH_OB ? MIPS_ID_OPC_SUBUH_OB :
                op2 == OPC_SUBUH_R_OB ? MIPS_ID_OPC_SUBUH_R_OB :
                op2 == OPC_ADDQ_PW ? MIPS_ID_OPC_ADDQ_PW :
                op2 == OPC_ADDQ_S_PW ? MIPS_ID_OPC_ADDQ_S_PW :
                op2 == OPC_ADDQ_QH ? MIPS_ID_OPC_ADDQ_QH :
                op2 == OPC_ADDQ_S_QH ? MIPS_ID_OPC_ADDQ_S_QH :
                op2 == OPC_ADDU_OB ? MIPS_ID_OPC_ADDU_OB :
                op2 == OPC_ADDU_S_OB ? MIPS_ID_OPC_ADDU_S_OB :
                op2 == OPC_ADDU_QH ? MIPS_ID_OPC_ADDU_QH :
                op2 == OPC_ADDU_S_QH ? MIPS_ID_OPC_ADDU_S_QH :
                op2 == OPC_ADDUH_OB ? MIPS_ID_OPC_ADDUH_OB :
                op2 == OPC_ADDUH_R_OB ? MIPS_ID_OPC_ADDUH_R_OB :
                MIPS_ID_NONE);
            gen_mipsdsp_arith(ctx, op1, op2, rd, rs, rt);
            break;
        case OPC_MULEQ_S_PW_QHL:
        case OPC_MULEQ_S_PW_QHR:
        case OPC_MULEU_S_QH_OBL:
        case OPC_MULEU_S_QH_OBR:
        case OPC_MULQ_RS_QH:
            mips_ident(ctx,
                op2 == OPC_MULEQ_S_PW_QHL ? MIPS_ID_OPC_MULEQ_S_PW_QHL :
                op2 == OPC_MULEQ_S_PW_QHR ? MIPS_ID_OPC_MULEQ_S_PW_QHR :
                op2 == OPC_MULEU_S_QH_OBL ? MIPS_ID_OPC_MULEU_S_QH_OBL :
                op2 == OPC_MULEU_S_QH_OBR ? MIPS_ID_OPC_MULEU_S_QH_OBR :
                op2 == OPC_MULQ_RS_QH ? MIPS_ID_OPC_MULQ_RS_QH :
                MIPS_ID_NONE);
            gen_mipsdsp_multiply(ctx, op1, op2, rd, rs, rt, 1);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK ADDU.OB");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_CMPU_EQ_OB_DSP:
        mips_ident(ctx,
            op1 == OPC_CMPU_EQ_OB_DSP ? MIPS_ID_OPC_CMPU_EQ_OB_DSP :
            MIPS_ID_NONE);
        op2 = MASK_CMPU_EQ_OB(ctx->opcode);
        switch (op2) {
        case OPC_PRECR_SRA_QH_PW:
        case OPC_PRECR_SRA_R_QH_PW:
            mips_ident(ctx,
                op2 == OPC_PRECR_SRA_QH_PW ? MIPS_ID_OPC_PRECR_SRA_QH_PW :
                op2 == OPC_PRECR_SRA_R_QH_PW ? MIPS_ID_OPC_PRECR_SRA_R_QH_PW :
                MIPS_ID_NONE);
            /* Return value is rt. */
            gen_mipsdsp_arith(ctx, op1, op2, rt, rs, rd);
            break;
        case OPC_PRECR_OB_QH:
        case OPC_PRECRQ_OB_QH:
        case OPC_PRECRQ_PW_L:
        case OPC_PRECRQ_QH_PW:
        case OPC_PRECRQ_RS_QH_PW:
        case OPC_PRECRQU_S_OB_QH:
            mips_ident(ctx,
                op2 == OPC_PRECR_OB_QH ? MIPS_ID_OPC_PRECR_OB_QH :
                op2 == OPC_PRECRQ_OB_QH ? MIPS_ID_OPC_PRECRQ_OB_QH :
                op2 == OPC_PRECRQ_PW_L ? MIPS_ID_OPC_PRECRQ_PW_L :
                op2 == OPC_PRECRQ_QH_PW ? MIPS_ID_OPC_PRECRQ_QH_PW :
                op2 == OPC_PRECRQ_RS_QH_PW ? MIPS_ID_OPC_PRECRQ_RS_QH_PW :
                op2 == OPC_PRECRQU_S_OB_QH ? MIPS_ID_OPC_PRECRQU_S_OB_QH :
                MIPS_ID_NONE);
            gen_mipsdsp_arith(ctx, op1, op2, rd, rs, rt);
            break;
        case OPC_CMPU_EQ_OB:
        case OPC_CMPU_LT_OB:
        case OPC_CMPU_LE_OB:
        case OPC_CMP_EQ_QH:
        case OPC_CMP_LT_QH:
        case OPC_CMP_LE_QH:
        case OPC_CMP_EQ_PW:
        case OPC_CMP_LT_PW:
        case OPC_CMP_LE_PW:
            mips_ident(ctx,
                op2 == OPC_CMPU_EQ_OB ? MIPS_ID_OPC_CMPU_EQ_OB :
                op2 == OPC_CMPU_LT_OB ? MIPS_ID_OPC_CMPU_LT_OB :
                op2 == OPC_CMPU_LE_OB ? MIPS_ID_OPC_CMPU_LE_OB :
                op2 == OPC_CMP_EQ_QH ? MIPS_ID_OPC_CMP_EQ_QH :
                op2 == OPC_CMP_LT_QH ? MIPS_ID_OPC_CMP_LT_QH :
                op2 == OPC_CMP_LE_QH ? MIPS_ID_OPC_CMP_LE_QH :
                op2 == OPC_CMP_EQ_PW ? MIPS_ID_OPC_CMP_EQ_PW :
                op2 == OPC_CMP_LT_PW ? MIPS_ID_OPC_CMP_LT_PW :
                op2 == OPC_CMP_LE_PW ? MIPS_ID_OPC_CMP_LE_PW :
                MIPS_ID_NONE);
            gen_mipsdsp_add_cmp_pick(ctx, op1, op2, rd, rs, rt, 0);
            break;
        case OPC_CMPGDU_EQ_OB:
        case OPC_CMPGDU_LT_OB:
        case OPC_CMPGDU_LE_OB:
        case OPC_CMPGU_EQ_OB:
        case OPC_CMPGU_LT_OB:
        case OPC_CMPGU_LE_OB:
        case OPC_PACKRL_PW:
        case OPC_PICK_OB:
        case OPC_PICK_PW:
        case OPC_PICK_QH:
            mips_ident(ctx,
                op2 == OPC_CMPGDU_EQ_OB ? MIPS_ID_OPC_CMPGDU_EQ_OB :
                op2 == OPC_CMPGDU_LT_OB ? MIPS_ID_OPC_CMPGDU_LT_OB :
                op2 == OPC_CMPGDU_LE_OB ? MIPS_ID_OPC_CMPGDU_LE_OB :
                op2 == OPC_CMPGU_EQ_OB ? MIPS_ID_OPC_CMPGU_EQ_OB :
                op2 == OPC_CMPGU_LT_OB ? MIPS_ID_OPC_CMPGU_LT_OB :
                op2 == OPC_CMPGU_LE_OB ? MIPS_ID_OPC_CMPGU_LE_OB :
                op2 == OPC_PACKRL_PW ? MIPS_ID_OPC_PACKRL_PW :
                op2 == OPC_PICK_OB ? MIPS_ID_OPC_PICK_OB :
                op2 == OPC_PICK_PW ? MIPS_ID_OPC_PICK_PW :
                op2 == OPC_PICK_QH ? MIPS_ID_OPC_PICK_QH :
                MIPS_ID_NONE);
            gen_mipsdsp_add_cmp_pick(ctx, op1, op2, rd, rs, rt, 1);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK CMPU_EQ.OB");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_DAPPEND_DSP:
        mips_ident(ctx,
            op1 == OPC_DAPPEND_DSP ? MIPS_ID_OPC_DAPPEND_DSP :
            MIPS_ID_NONE);
        gen_mipsdsp_append(env, ctx, op1, rt, rs, rd);
        break;
    case OPC_DEXTR_W_DSP:
        mips_ident(ctx,
            op1 == OPC_DEXTR_W_DSP ? MIPS_ID_OPC_DEXTR_W_DSP :
            MIPS_ID_NONE);
        op2 = MASK_DEXTR_W(ctx->opcode);
        switch (op2) {
        case OPC_DEXTP:
        case OPC_DEXTPDP:
        case OPC_DEXTPDPV:
        case OPC_DEXTPV:
        case OPC_DEXTR_L:
        case OPC_DEXTR_R_L:
        case OPC_DEXTR_RS_L:
        case OPC_DEXTR_W:
        case OPC_DEXTR_R_W:
        case OPC_DEXTR_RS_W:
        case OPC_DEXTR_S_H:
        case OPC_DEXTRV_L:
        case OPC_DEXTRV_R_L:
        case OPC_DEXTRV_RS_L:
        case OPC_DEXTRV_S_H:
        case OPC_DEXTRV_W:
        case OPC_DEXTRV_R_W:
        case OPC_DEXTRV_RS_W:
            mips_ident(ctx,
                op2 == OPC_DEXTP ? MIPS_ID_OPC_DEXTP :
                op2 == OPC_DEXTPDP ? MIPS_ID_OPC_DEXTPDP :
                op2 == OPC_DEXTPDPV ? MIPS_ID_OPC_DEXTPDPV :
                op2 == OPC_DEXTPV ? MIPS_ID_OPC_DEXTPV :
                op2 == OPC_DEXTR_L ? MIPS_ID_OPC_DEXTR_L :
                op2 == OPC_DEXTR_R_L ? MIPS_ID_OPC_DEXTR_R_L :
                op2 == OPC_DEXTR_RS_L ? MIPS_ID_OPC_DEXTR_RS_L :
                op2 == OPC_DEXTR_W ? MIPS_ID_OPC_DEXTR_W :
                op2 == OPC_DEXTR_R_W ? MIPS_ID_OPC_DEXTR_R_W :
                op2 == OPC_DEXTR_RS_W ? MIPS_ID_OPC_DEXTR_RS_W :
                op2 == OPC_DEXTR_S_H ? MIPS_ID_OPC_DEXTR_S_H :
                op2 == OPC_DEXTRV_L ? MIPS_ID_OPC_DEXTRV_L :
                op2 == OPC_DEXTRV_R_L ? MIPS_ID_OPC_DEXTRV_R_L :
                op2 == OPC_DEXTRV_RS_L ? MIPS_ID_OPC_DEXTRV_RS_L :
                op2 == OPC_DEXTRV_S_H ? MIPS_ID_OPC_DEXTRV_S_H :
                op2 == OPC_DEXTRV_W ? MIPS_ID_OPC_DEXTRV_W :
                op2 == OPC_DEXTRV_R_W ? MIPS_ID_OPC_DEXTRV_R_W :
                op2 == OPC_DEXTRV_RS_W ? MIPS_ID_OPC_DEXTRV_RS_W :
                MIPS_ID_NONE);
            gen_mipsdsp_accinsn(ctx, op1, op2, rt, rs, rd, 1);
            break;
        case OPC_DMTHLIP:
        case OPC_DSHILO:
        case OPC_DSHILOV:
            mips_ident(ctx,
                op2 == OPC_DMTHLIP ? MIPS_ID_OPC_DMTHLIP :
                op2 == OPC_DSHILO ? MIPS_ID_OPC_DSHILO :
                op2 == OPC_DSHILOV ? MIPS_ID_OPC_DSHILOV :
                MIPS_ID_NONE);
            gen_mipsdsp_accinsn(ctx, op1, op2, rd, rs, rt, 0);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK EXTR.W");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_DPAQ_W_QH_DSP:
        mips_ident(ctx,
            op1 == OPC_DPAQ_W_QH_DSP ? MIPS_ID_OPC_DPAQ_W_QH_DSP :
            MIPS_ID_NONE);
        op2 = MASK_DPAQ_W_QH(ctx->opcode);
        switch (op2) {
        case OPC_DPAU_H_OBL:
        case OPC_DPAU_H_OBR:
        case OPC_DPSU_H_OBL:
        case OPC_DPSU_H_OBR:
        case OPC_DPA_W_QH:
        case OPC_DPAQ_S_W_QH:
        case OPC_DPS_W_QH:
        case OPC_DPSQ_S_W_QH:
        case OPC_MULSAQ_S_W_QH:
        case OPC_DPAQ_SA_L_PW:
        case OPC_DPSQ_SA_L_PW:
        case OPC_MULSAQ_S_L_PW:
            mips_ident(ctx,
                op2 == OPC_DPAU_H_OBL ? MIPS_ID_OPC_DPAU_H_OBL :
                op2 == OPC_DPAU_H_OBR ? MIPS_ID_OPC_DPAU_H_OBR :
                op2 == OPC_DPSU_H_OBL ? MIPS_ID_OPC_DPSU_H_OBL :
                op2 == OPC_DPSU_H_OBR ? MIPS_ID_OPC_DPSU_H_OBR :
                op2 == OPC_DPA_W_QH ? MIPS_ID_OPC_DPA_W_QH :
                op2 == OPC_DPAQ_S_W_QH ? MIPS_ID_OPC_DPAQ_S_W_QH :
                op2 == OPC_DPS_W_QH ? MIPS_ID_OPC_DPS_W_QH :
                op2 == OPC_DPSQ_S_W_QH ? MIPS_ID_OPC_DPSQ_S_W_QH :
                op2 == OPC_MULSAQ_S_W_QH ? MIPS_ID_OPC_MULSAQ_S_W_QH :
                op2 == OPC_DPAQ_SA_L_PW ? MIPS_ID_OPC_DPAQ_SA_L_PW :
                op2 == OPC_DPSQ_SA_L_PW ? MIPS_ID_OPC_DPSQ_SA_L_PW :
                op2 == OPC_MULSAQ_S_L_PW ? MIPS_ID_OPC_MULSAQ_S_L_PW :
                MIPS_ID_NONE);
            gen_mipsdsp_multiply(ctx, op1, op2, rd, rs, rt, 0);
            break;
        case OPC_MAQ_S_W_QHLL:
        case OPC_MAQ_S_W_QHLR:
        case OPC_MAQ_S_W_QHRL:
        case OPC_MAQ_S_W_QHRR:
        case OPC_MAQ_SA_W_QHLL:
        case OPC_MAQ_SA_W_QHLR:
        case OPC_MAQ_SA_W_QHRL:
        case OPC_MAQ_SA_W_QHRR:
        case OPC_MAQ_S_L_PWL:
        case OPC_MAQ_S_L_PWR:
        case OPC_DMADD:
        case OPC_DMADDU:
        case OPC_DMSUB:
        case OPC_DMSUBU:
            mips_ident(ctx,
                op2 == OPC_MAQ_S_W_QHLL ? MIPS_ID_OPC_MAQ_S_W_QHLL :
                op2 == OPC_MAQ_S_W_QHLR ? MIPS_ID_OPC_MAQ_S_W_QHLR :
                op2 == OPC_MAQ_S_W_QHRL ? MIPS_ID_OPC_MAQ_S_W_QHRL :
                op2 == OPC_MAQ_S_W_QHRR ? MIPS_ID_OPC_MAQ_S_W_QHRR :
                op2 == OPC_MAQ_SA_W_QHLL ? MIPS_ID_OPC_MAQ_SA_W_QHLL :
                op2 == OPC_MAQ_SA_W_QHLR ? MIPS_ID_OPC_MAQ_SA_W_QHLR :
                op2 == OPC_MAQ_SA_W_QHRL ? MIPS_ID_OPC_MAQ_SA_W_QHRL :
                op2 == OPC_MAQ_SA_W_QHRR ? MIPS_ID_OPC_MAQ_SA_W_QHRR :
                op2 == OPC_MAQ_S_L_PWL ? MIPS_ID_OPC_MAQ_S_L_PWL :
                op2 == OPC_MAQ_S_L_PWR ? MIPS_ID_OPC_MAQ_S_L_PWR :
                op2 == OPC_DMADD ? MIPS_ID_OPC_DMADD :
                op2 == OPC_DMADDU ? MIPS_ID_OPC_DMADDU :
                op2 == OPC_DMSUB ? MIPS_ID_OPC_DMSUB :
                op2 == OPC_DMSUBU ? MIPS_ID_OPC_DMSUBU :
                MIPS_ID_NONE);
            gen_mipsdsp_multiply(ctx, op1, op2, rd, rs, rt, 0);
            break;
        default:            /* Invalid */
            MIPS_INVAL("MASK DPAQ.W.QH");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_DINSV_DSP:
        mips_ident(ctx,
            op1 == OPC_DINSV_DSP ? MIPS_ID_OPC_DINSV_DSP :
            MIPS_ID_NONE);
        op2 = MASK_INSV(ctx->opcode);
        switch (op2) {
        case OPC_DINSV:
            mips_ident(ctx,
                op2 == OPC_DINSV ? MIPS_ID_OPC_DINSV :
                MIPS_ID_NONE);
        {
            TCGv t0, t1;

            check_dsp(ctx);

            if (rt == 0) {
                break;
            }

            t0 = tcg_temp_new();
            t1 = tcg_temp_new();

            gen_load_gpr(t0, rt);
            gen_load_gpr(t1, rs);

            gen_helper_dinsv(cpu_gpr[rt], tcg_env, t1, t0);
            break;
        }
        default:            /* Invalid */
            MIPS_INVAL("MASK DINSV");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_SHLL_OB_DSP:
        mips_ident(ctx,
            op1 == OPC_SHLL_OB_DSP ? MIPS_ID_OPC_SHLL_OB_DSP :
            MIPS_ID_NONE);
        gen_mipsdsp_shift(ctx, op1, rd, rs, rt);
        break;
#endif
    default:            /* Invalid */
        MIPS_INVAL("special3_legacy");
        gen_reserved_instruction(ctx);
        break;
    }
}


#if defined(TARGET_MIPS64)

static void decode_mmi(CPUMIPSState *env, DisasContext *ctx)
{
    uint32_t opc = MASK_MMI(ctx->opcode);
    int rs = extract32(ctx->opcode, 21, 5);
    int rt = extract32(ctx->opcode, 16, 5);
    int rd = extract32(ctx->opcode, 11, 5);

    switch (opc) {
    case MMI_OPC_MULT1:
    case MMI_OPC_MULTU1:
    case MMI_OPC_MADD:
    case MMI_OPC_MADDU:
    case MMI_OPC_MADD1:
    case MMI_OPC_MADDU1:
        mips_ident(ctx,
            opc == MMI_OPC_MULT1 ? MIPS_ID_MMI_OPC_MULT1 :
            opc == MMI_OPC_MULTU1 ? MIPS_ID_MMI_OPC_MULTU1 :
            opc == MMI_OPC_MADD ? MIPS_ID_MMI_OPC_MADD :
            opc == MMI_OPC_MADDU ? MIPS_ID_MMI_OPC_MADDU :
            opc == MMI_OPC_MADD1 ? MIPS_ID_MMI_OPC_MADD1 :
            opc == MMI_OPC_MADDU1 ? MIPS_ID_MMI_OPC_MADDU1 :
            MIPS_ID_NONE);
        gen_mul_txx9(ctx, opc, rd, rs, rt);
        break;
    case MMI_OPC_DIV1:
    case MMI_OPC_DIVU1:
        mips_ident(ctx,
            opc == MMI_OPC_DIV1 ? MIPS_ID_MMI_OPC_DIV1 :
            opc == MMI_OPC_DIVU1 ? MIPS_ID_MMI_OPC_DIVU1 :
            MIPS_ID_NONE);
        gen_div1_tx79(ctx, opc, rs, rt);
        break;
    default:
        MIPS_INVAL("TX79 MMI class");
        gen_reserved_instruction(ctx);
        break;
    }
}

static void gen_mmi_sq(DisasContext *ctx, int base, int rt, int offset)
{
    gen_reserved_instruction(ctx);    /* TODO: MMI_OPC_SQ */
}

/*
 * The TX79-specific instruction Store Quadword
 *
 * +--------+-------+-------+------------------------+
 * | 011111 |  base |   rt  |           offset       | SQ
 * +--------+-------+-------+------------------------+
 *      6       5       5                 16
 *
 * has the same opcode as the Read Hardware Register instruction
 *
 * +--------+-------+-------+-------+-------+--------+
 * | 011111 | 00000 |   rt  |   rd  | 00000 | 111011 | RDHWR
 * +--------+-------+-------+-------+-------+--------+
 *      6       5       5       5       5        6
 *
 * that is required, trapped and emulated by the Linux kernel. However, all
 * RDHWR encodings yield address error exceptions on the TX79 since the SQ
 * offset is odd. Therefore all valid SQ instructions can execute normally.
 * In user mode, QEMU must verify the upper and lower 11 bits to distinguish
 * between SQ and RDHWR, as the Linux kernel does.
 */
static void decode_mmi_sq(CPUMIPSState *env, DisasContext *ctx)
{
    int base = extract32(ctx->opcode, 21, 5);
    int rt = extract32(ctx->opcode, 16, 5);
    int offset = extract32(ctx->opcode, 0, 16);

#ifdef CONFIG_USER_ONLY
    uint32_t op1 = MASK_SPECIAL3(ctx->opcode);
    uint32_t op2 = extract32(ctx->opcode, 6, 5);

    if (base == 0 && op2 == 0 && op1 == OPC_RDHWR) {
        int rd = extract32(ctx->opcode, 11, 5);

        gen_rdhwr(ctx, rt, rd, 0);
        return;
    }
#endif

    gen_mmi_sq(ctx, base, rt, offset);
}

#endif

static void decode_opc_special3(CPUMIPSState *env, DisasContext *ctx)
{
    int rs, rt, rd, sa;
    uint32_t op1, op2;
    int16_t imm;

    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;
    sa = (ctx->opcode >> 6) & 0x1f;
    imm = sextract32(ctx->opcode, 7, 9);

    op1 = MASK_SPECIAL3(ctx->opcode);

    /*
     * EVA loads and stores overlap Loongson 2E instructions decoded by
     * decode_opc_special3_legacy(), so be careful to allow their decoding when
     * EVA is absent.
     */
    if (ctx->eva) {
        switch (op1) {
        case OPC_LWLE:
        case OPC_LWRE:
        case OPC_LBUE:
        case OPC_LHUE:
        case OPC_LBE:
        case OPC_LHE:
        case OPC_LLE:
        case OPC_LWE:
            mips_ident(ctx,
                op1 == OPC_LWLE ? MIPS_ID_OPC_LWLE :
                op1 == OPC_LWRE ? MIPS_ID_OPC_LWRE :
                op1 == OPC_LBUE ? MIPS_ID_OPC_LBUE :
                op1 == OPC_LHUE ? MIPS_ID_OPC_LHUE :
                op1 == OPC_LBE ? MIPS_ID_OPC_LBE :
                op1 == OPC_LHE ? MIPS_ID_OPC_LHE :
                op1 == OPC_LLE ? MIPS_ID_OPC_LLE :
                op1 == OPC_LWE ? MIPS_ID_OPC_LWE :
                MIPS_ID_NONE);
            check_cp0_enabled(ctx);
            gen_ld(ctx, op1, rt, rs, imm);
            return;
        case OPC_SWLE:
        case OPC_SWRE:
        case OPC_SBE:
        case OPC_SHE:
        case OPC_SWE:
            mips_ident(ctx,
                op1 == OPC_SWLE ? MIPS_ID_OPC_SWLE :
                op1 == OPC_SWRE ? MIPS_ID_OPC_SWRE :
                op1 == OPC_SBE ? MIPS_ID_OPC_SBE :
                op1 == OPC_SHE ? MIPS_ID_OPC_SHE :
                op1 == OPC_SWE ? MIPS_ID_OPC_SWE :
                MIPS_ID_NONE);
            check_cp0_enabled(ctx);
            gen_st(ctx, op1, rt, rs, imm);
            return;
        case OPC_SCE:
            mips_ident(ctx,
                op1 == OPC_SCE ? MIPS_ID_OPC_SCE :
                MIPS_ID_NONE);
            check_cp0_enabled(ctx);
            gen_st_cond(ctx, rt, rs, imm, mo_endian(ctx) | MO_SL, true);
            return;
        case OPC_CACHEE:
            mips_ident(ctx,
                op1 == OPC_CACHEE ? MIPS_ID_OPC_CACHEE :
                MIPS_ID_NONE);
            check_eva(ctx);
            check_cp0_enabled(ctx);
            if (ctx->hflags & MIPS_HFLAG_ITC_CACHE) {
                gen_cache_operation(ctx, rt, rs, imm);
            }
            return;
        case OPC_PREFE:
            mips_ident(ctx,
                op1 == OPC_PREFE ? MIPS_ID_OPC_PREFE :
                MIPS_ID_NONE);
            check_cp0_enabled(ctx);
            /* Treat as NOP.  See gen_pref_note_operands(). */
            gen_pref_note_operands(rs, -1);
            return;
        }
    }

    switch (op1) {
    case OPC_EXT:
    case OPC_INS:
        mips_ident(ctx,
            op1 == OPC_EXT ? MIPS_ID_OPC_EXT :
            op1 == OPC_INS ? MIPS_ID_OPC_INS :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R2);
        gen_bitops(ctx, op1, rt, rs, sa, rd);
        break;
    case OPC_BSHFL:
        mips_ident(ctx,
            op1 == OPC_BSHFL ? MIPS_ID_OPC_BSHFL :
            MIPS_ID_NONE);
        op2 = MASK_BSHFL(ctx->opcode);
        switch (op2) {
        case OPC_ALIGN:
        case OPC_ALIGN_1:
        case OPC_ALIGN_2:
        case OPC_ALIGN_3:
        case OPC_BITSWAP:
            mips_ident(ctx,
                op2 == OPC_ALIGN ? MIPS_ID_OPC_ALIGN :
                op2 == OPC_ALIGN_1 ? MIPS_ID_OPC_ALIGN_1 :
                op2 == OPC_ALIGN_2 ? MIPS_ID_OPC_ALIGN_2 :
                op2 == OPC_ALIGN_3 ? MIPS_ID_OPC_ALIGN_3 :
                op2 == OPC_BITSWAP ? MIPS_ID_OPC_BITSWAP :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R6);
            decode_opc_special3_r6(env, ctx);
            break;
        default:
            check_insn(ctx, ISA_MIPS_R2);
            gen_bshfl(ctx, op2, rt, rd);
            break;
        }
        break;
#if defined(TARGET_MIPS64)
    case OPC_DEXTM:
    case OPC_DEXTU:
    case OPC_DEXT:
    case OPC_DINSM:
    case OPC_DINSU:
    case OPC_DINS:
        mips_ident(ctx,
            op1 == OPC_DEXTM ? MIPS_ID_OPC_DEXTM :
            op1 == OPC_DEXTU ? MIPS_ID_OPC_DEXTU :
            op1 == OPC_DEXT ? MIPS_ID_OPC_DEXT :
            op1 == OPC_DINSM ? MIPS_ID_OPC_DINSM :
            op1 == OPC_DINSU ? MIPS_ID_OPC_DINSU :
            op1 == OPC_DINS ? MIPS_ID_OPC_DINS :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R2);
        check_mips_64(ctx);
        gen_bitops(ctx, op1, rt, rs, sa, rd);
        break;
    case OPC_DBSHFL:
        mips_ident(ctx,
            op1 == OPC_DBSHFL ? MIPS_ID_OPC_DBSHFL :
            MIPS_ID_NONE);
        op2 = MASK_DBSHFL(ctx->opcode);
        switch (op2) {
        case OPC_DALIGN:
        case OPC_DALIGN_1:
        case OPC_DALIGN_2:
        case OPC_DALIGN_3:
        case OPC_DALIGN_4:
        case OPC_DALIGN_5:
        case OPC_DALIGN_6:
        case OPC_DALIGN_7:
        case OPC_DBITSWAP:
            mips_ident(ctx,
                op2 == OPC_DALIGN ? MIPS_ID_OPC_DALIGN :
                op2 == OPC_DALIGN_1 ? MIPS_ID_OPC_DALIGN_1 :
                op2 == OPC_DALIGN_2 ? MIPS_ID_OPC_DALIGN_2 :
                op2 == OPC_DALIGN_3 ? MIPS_ID_OPC_DALIGN_3 :
                op2 == OPC_DALIGN_4 ? MIPS_ID_OPC_DALIGN_4 :
                op2 == OPC_DALIGN_5 ? MIPS_ID_OPC_DALIGN_5 :
                op2 == OPC_DALIGN_6 ? MIPS_ID_OPC_DALIGN_6 :
                op2 == OPC_DALIGN_7 ? MIPS_ID_OPC_DALIGN_7 :
                op2 == OPC_DBITSWAP ? MIPS_ID_OPC_DBITSWAP :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R6);
            decode_opc_special3_r6(env, ctx);
            break;
        default:
            check_insn(ctx, ISA_MIPS_R2);
            check_mips_64(ctx);
            op2 = MASK_DBSHFL(ctx->opcode);
            gen_bshfl(ctx, op2, rt, rd);
            break;
        }
        break;
#endif
    case OPC_RDHWR:
        mips_ident(ctx,
            op1 == OPC_RDHWR ? MIPS_ID_OPC_RDHWR :
            MIPS_ID_NONE);
        gen_rdhwr(ctx, rt, rd, extract32(ctx->opcode, 6, 3));
        break;
    case OPC_FORK:
        mips_ident(ctx,
            op1 == OPC_FORK ? MIPS_ID_OPC_FORK :
            MIPS_ID_NONE);
        check_mt(ctx);
        {
            TCGv t0 = tcg_temp_new();
            TCGv t1 = tcg_temp_new();

            gen_load_gpr(t0, rt);
            gen_load_gpr(t1, rs);
            gen_helper_fork(t0, t1);
        }
        break;
    case OPC_YIELD:
        mips_ident(ctx,
            op1 == OPC_YIELD ? MIPS_ID_OPC_YIELD :
            MIPS_ID_NONE);
        check_mt(ctx);
        {
            TCGv t0 = tcg_temp_new();

            gen_load_gpr(t0, rs);
            gen_helper_yield(t0, tcg_env, t0);
            gen_store_gpr(t0, rd);
        }
        break;
    default:
        if (ctx->insn_flags & ISA_MIPS_R6) {
            decode_opc_special3_r6(env, ctx);
        } else {
            decode_opc_special3_legacy(env, ctx);
        }
    }
}

static bool decode_opc_legacy(CPUMIPSState *env, DisasContext *ctx)
{
    int32_t offset;
    int rs, rt, rd, sa;
    uint32_t op, op1;
    int16_t imm;

    op = MASK_OP_MAJOR(ctx->opcode);
    rs = (ctx->opcode >> 21) & 0x1f;
    rt = (ctx->opcode >> 16) & 0x1f;
    rd = (ctx->opcode >> 11) & 0x1f;
    sa = (ctx->opcode >> 6) & 0x1f;
    imm = (int16_t)ctx->opcode;
    switch (op) {
    case OPC_SPECIAL:
        mips_ident(ctx,
            op == OPC_SPECIAL ? MIPS_ID_OPC_SPECIAL :
            MIPS_ID_NONE);
        decode_opc_special(env, ctx);
        break;
    case OPC_SPECIAL2:
        mips_ident(ctx,
            op == OPC_SPECIAL2 ? MIPS_ID_OPC_SPECIAL2 :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        if ((ctx->insn_flags & INSN_R5900) && (ctx->insn_flags & ASE_MMI)) {
            decode_mmi(env, ctx);
            break;
        }
#endif
        if (TARGET_LONG_BITS == 32 && (ctx->insn_flags & ASE_MXU)) {
            if (decode_ase_mxu(ctx, ctx->opcode)) {
                break;
            }
        }
        decode_opc_special2_legacy(env, ctx);
        break;
    case OPC_SPECIAL3:
        mips_ident(ctx,
            op == OPC_SPECIAL3 ? MIPS_ID_OPC_SPECIAL3 :
            MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
        if (ctx->insn_flags & INSN_R5900) {
            decode_mmi_sq(env, ctx);    /* MMI_OPC_SQ */
        } else {
            decode_opc_special3(env, ctx);
        }
#else
        decode_opc_special3(env, ctx);
#endif
        break;
    case OPC_REGIMM:
        mips_ident(ctx,
            op == OPC_REGIMM ? MIPS_ID_OPC_REGIMM :
            MIPS_ID_NONE);
        op1 = MASK_REGIMM(ctx->opcode);
        switch (op1) {
        case OPC_BLTZL: /* REGIMM branches */
        case OPC_BGEZL:
        case OPC_BLTZALL:
        case OPC_BGEZALL:
            mips_ident(ctx,
                op1 == OPC_BLTZL ? MIPS_ID_OPC_BLTZL :
                op1 == OPC_BGEZL ? MIPS_ID_OPC_BGEZL :
                op1 == OPC_BLTZALL ? MIPS_ID_OPC_BLTZALL :
                op1 == OPC_BGEZALL ? MIPS_ID_OPC_BGEZALL :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS2);
            check_insn_opc_removed(ctx, ISA_MIPS_R6);
            /* Fallthrough */
        case OPC_BLTZ:
        case OPC_BGEZ:
            mips_ident(ctx,
                op1 == OPC_BLTZ ? MIPS_ID_OPC_BLTZ :
                op1 == OPC_BGEZ ? MIPS_ID_OPC_BGEZ :
                MIPS_ID_NONE);
            gen_compute_branch(ctx, op1, 4, rs, -1, imm << 2, 4);
            break;
        case OPC_BLTZAL:
        case OPC_BGEZAL:
            mips_ident(ctx,
                op1 == OPC_BLTZAL ? MIPS_ID_OPC_BLTZAL :
                op1 == OPC_BGEZAL ? MIPS_ID_OPC_BGEZAL :
                MIPS_ID_NONE);
            if (ctx->insn_flags & ISA_MIPS_R6) {
                if (rs == 0) {
                    /* OPC_NAL, OPC_BAL */
                    gen_compute_branch(ctx, op1, 4, 0, -1, imm << 2, 4);
                } else {
                    gen_reserved_instruction(ctx);
                }
            } else {
                gen_compute_branch(ctx, op1, 4, rs, -1, imm << 2, 4);
            }
            break;
        case OPC_TGEI: /* REGIMM traps */
        case OPC_TGEIU:
        case OPC_TLTI:
        case OPC_TLTIU:
        case OPC_TEQI:
        case OPC_TNEI:
            mips_ident(ctx,
                op1 == OPC_TGEI ? MIPS_ID_OPC_TGEI :
                op1 == OPC_TGEIU ? MIPS_ID_OPC_TGEIU :
                op1 == OPC_TLTI ? MIPS_ID_OPC_TLTI :
                op1 == OPC_TLTIU ? MIPS_ID_OPC_TLTIU :
                op1 == OPC_TEQI ? MIPS_ID_OPC_TEQI :
                op1 == OPC_TNEI ? MIPS_ID_OPC_TNEI :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS2);
            check_insn_opc_removed(ctx, ISA_MIPS_R6);
            gen_trap(ctx, op1, rs, -1, imm, 0);
            break;
        case OPC_SIGRIE:
            mips_ident(ctx,
                op1 == OPC_SIGRIE ? MIPS_ID_OPC_SIGRIE :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R6);
            gen_reserved_instruction(ctx);
            break;
        case OPC_SYNCI:
            mips_ident(ctx,
                op1 == OPC_SYNCI ? MIPS_ID_OPC_SYNCI :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R2);
            /*
             * Break the TB to be able to sync copied instructions
             * immediately.
             */
            ctx->base.is_jmp = DISAS_STOP;
            break;
        case OPC_BPOSGE32:    /* MIPS DSP branch */
            mips_ident(ctx,
                op1 == OPC_BPOSGE32 ? MIPS_ID_OPC_BPOSGE32 :
                MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
            QEMU_FALLTHROUGH;  /* mips_ident */
        case OPC_BPOSGE64:
            mips_ident(ctx,
                op1 == OPC_BPOSGE64 ? MIPS_ID_OPC_BPOSGE64 :
                MIPS_ID_NONE);
#endif
            check_dsp(ctx);
            gen_compute_branch(ctx, op1, 4, -1, -2, (int32_t)imm << 2, 4);
            break;
#if defined(TARGET_MIPS64)
        case OPC_DAHI:
            mips_ident(ctx,
                op1 == OPC_DAHI ? MIPS_ID_OPC_DAHI :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R6);
            check_mips_64(ctx);
            if (rs != 0) {
                tcg_gen_addi_tl(cpu_gpr[rs], cpu_gpr[rs], (int64_t)imm << 32);
            }
            break;
        case OPC_DATI:
            mips_ident(ctx,
                op1 == OPC_DATI ? MIPS_ID_OPC_DATI :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R6);
            check_mips_64(ctx);
            if (rs != 0) {
                tcg_gen_addi_tl(cpu_gpr[rs], cpu_gpr[rs], (int64_t)imm << 48);
            }
            break;
#endif
        default:            /* Invalid */
            MIPS_INVAL("regimm");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_CP0:
        mips_ident(ctx,
            op == OPC_CP0 ? MIPS_ID_OPC_CP0 :
            MIPS_ID_NONE);
        check_cp0_enabled(ctx);
        op1 = MASK_CP0(ctx->opcode);
        switch (op1) {
        case OPC_MFC0:
        case OPC_MTC0:
        case OPC_MFTR:
        case OPC_MTTR:
        case OPC_MFHC0:
        case OPC_MTHC0:
            mips_ident(ctx,
                op1 == OPC_MFC0 ? MIPS_ID_OPC_MFC0 :
                op1 == OPC_MTC0 ? MIPS_ID_OPC_MTC0 :
                op1 == OPC_MFTR ? MIPS_ID_OPC_MFTR :
                op1 == OPC_MTTR ? MIPS_ID_OPC_MTTR :
                op1 == OPC_MFHC0 ? MIPS_ID_OPC_MFHC0 :
                op1 == OPC_MTHC0 ? MIPS_ID_OPC_MTHC0 :
                MIPS_ID_NONE);
#if defined(TARGET_MIPS64)
            QEMU_FALLTHROUGH;  /* mips_ident */
        case OPC_DMFC0:
        case OPC_DMTC0:
            mips_ident(ctx,
                op1 == OPC_DMFC0 ? MIPS_ID_OPC_DMFC0 :
                op1 == OPC_DMTC0 ? MIPS_ID_OPC_DMTC0 :
                MIPS_ID_NONE);
#endif
#ifndef CONFIG_USER_ONLY
            gen_cp0(env, ctx, op1, rt, rd);
#endif /* !CONFIG_USER_ONLY */
            break;
        case OPC_C0:
        case OPC_C0_1:
        case OPC_C0_2:
        case OPC_C0_3:
        case OPC_C0_4:
        case OPC_C0_5:
        case OPC_C0_6:
        case OPC_C0_7:
        case OPC_C0_8:
        case OPC_C0_9:
        case OPC_C0_A:
        case OPC_C0_B:
        case OPC_C0_C:
        case OPC_C0_D:
        case OPC_C0_E:
        case OPC_C0_F:
            mips_ident(ctx,
                op1 == OPC_C0 ? MIPS_ID_OPC_C0 :
                op1 == OPC_C0_1 ? MIPS_ID_OPC_C0_1 :
                op1 == OPC_C0_2 ? MIPS_ID_OPC_C0_2 :
                op1 == OPC_C0_3 ? MIPS_ID_OPC_C0_3 :
                op1 == OPC_C0_4 ? MIPS_ID_OPC_C0_4 :
                op1 == OPC_C0_5 ? MIPS_ID_OPC_C0_5 :
                op1 == OPC_C0_6 ? MIPS_ID_OPC_C0_6 :
                op1 == OPC_C0_7 ? MIPS_ID_OPC_C0_7 :
                op1 == OPC_C0_8 ? MIPS_ID_OPC_C0_8 :
                op1 == OPC_C0_9 ? MIPS_ID_OPC_C0_9 :
                op1 == OPC_C0_A ? MIPS_ID_OPC_C0_A :
                op1 == OPC_C0_B ? MIPS_ID_OPC_C0_B :
                op1 == OPC_C0_C ? MIPS_ID_OPC_C0_C :
                op1 == OPC_C0_D ? MIPS_ID_OPC_C0_D :
                op1 == OPC_C0_E ? MIPS_ID_OPC_C0_E :
                op1 == OPC_C0_F ? MIPS_ID_OPC_C0_F :
                MIPS_ID_NONE);
#ifndef CONFIG_USER_ONLY
            gen_cp0(env, ctx, MASK_C0(ctx->opcode), rt, rd);
#endif /* !CONFIG_USER_ONLY */
            break;
        case OPC_MFMC0:
            mips_ident(ctx,
                op1 == OPC_MFMC0 ? MIPS_ID_OPC_MFMC0 :
                MIPS_ID_NONE);
#ifndef CONFIG_USER_ONLY
            {
                uint32_t op2;
                TCGv t0 = tcg_temp_new();

                op2 = MASK_MFMC0(ctx->opcode);
                switch (op2) {
                case OPC_DMT:
                    mips_ident(ctx,
                        op2 == OPC_DMT ? MIPS_ID_OPC_DMT :
                        MIPS_ID_NONE);
                    check_cp0_mt(ctx);
                    gen_helper_dmt(t0);
                    gen_store_gpr(t0, rt);
                    break;
                case OPC_EMT:
                    mips_ident(ctx,
                        op2 == OPC_EMT ? MIPS_ID_OPC_EMT :
                        MIPS_ID_NONE);
                    check_cp0_mt(ctx);
                    gen_helper_emt(t0);
                    gen_store_gpr(t0, rt);
                    break;
                case OPC_DVPE:
                    mips_ident(ctx,
                        op2 == OPC_DVPE ? MIPS_ID_OPC_DVPE :
                        MIPS_ID_NONE);
                    check_cp0_mt(ctx);
                    gen_helper_dvpe(t0, tcg_env);
                    gen_store_gpr(t0, rt);
                    break;
                case OPC_EVPE:
                    mips_ident(ctx,
                        op2 == OPC_EVPE ? MIPS_ID_OPC_EVPE :
                        MIPS_ID_NONE);
                    check_cp0_mt(ctx);
                    gen_helper_evpe(t0, tcg_env);
                    gen_store_gpr(t0, rt);
                    break;
                case OPC_DVP:
                    mips_ident(ctx,
                        op2 == OPC_DVP ? MIPS_ID_OPC_DVP :
                        MIPS_ID_NONE);
                    check_insn(ctx, ISA_MIPS_R6);
                    if (ctx->vp) {
                        gen_helper_dvp(t0, tcg_env);
                        gen_store_gpr(t0, rt);
                    }
                    break;
                case OPC_EVP:
                    mips_ident(ctx,
                        op2 == OPC_EVP ? MIPS_ID_OPC_EVP :
                        MIPS_ID_NONE);
                    check_insn(ctx, ISA_MIPS_R6);
                    if (ctx->vp) {
                        gen_helper_evp(t0, tcg_env);
                        gen_store_gpr(t0, rt);
                    }
                    break;
                case OPC_DI:
                    mips_ident(ctx,
                        op2 == OPC_DI ? MIPS_ID_OPC_DI :
                        MIPS_ID_NONE);
                    check_insn(ctx, ISA_MIPS_R2);
                    save_cpu_state(ctx, 1);
                    gen_helper_di(t0, tcg_env);
                    gen_store_gpr(t0, rt);
                    /*
                     * Stop translation as we may have switched
                     * the execution mode.
                     */
                    ctx->base.is_jmp = DISAS_STOP;
                    break;
                case OPC_EI:
                    mips_ident(ctx,
                        op2 == OPC_EI ? MIPS_ID_OPC_EI :
                        MIPS_ID_NONE);
                    check_insn(ctx, ISA_MIPS_R2);
                    save_cpu_state(ctx, 1);
                    gen_helper_ei(t0, tcg_env);
                    gen_store_gpr(t0, rt);
                    /*
                     * DISAS_STOP isn't sufficient, we need to ensure we break
                     * out of translated code to check for pending interrupts.
                     */
                    gen_save_pc(ctx->base.pc_next + 4);
                    ctx->base.is_jmp = DISAS_EXIT;
                    break;
                default:            /* Invalid */
                    MIPS_INVAL("mfmc0");
                    gen_reserved_instruction(ctx);
                    break;
                }
            }
#endif /* !CONFIG_USER_ONLY */
            break;
        case OPC_RDPGPR:
            mips_ident(ctx,
                op1 == OPC_RDPGPR ? MIPS_ID_OPC_RDPGPR :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R2);
            gen_load_srsgpr(rt, rd);
            break;
        case OPC_WRPGPR:
            mips_ident(ctx,
                op1 == OPC_WRPGPR ? MIPS_ID_OPC_WRPGPR :
                MIPS_ID_NONE);
            check_insn(ctx, ISA_MIPS_R2);
            gen_store_srsgpr(rt, rd);
            break;
        default:
            MIPS_INVAL("cp0");
            gen_reserved_instruction(ctx);
            break;
        }
        break;
    case OPC_BOVC: /* OPC_BEQZALC, OPC_BEQC, OPC_ADDI */
        mips_ident(ctx,
            op == OPC_BOVC ? MIPS_ID_OPC_BOVC :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_BOVC, OPC_BEQZALC, OPC_BEQC */
            gen_compute_compact_branch(ctx, op, rs, rt, imm << 2);
        } else {
            /* OPC_ADDI */
            /* Arithmetic with immediate opcode */
            gen_arith_imm(ctx, op, rt, rs, imm);
        }
        break;
    case OPC_ADDIU:
        mips_ident(ctx,
            op == OPC_ADDIU ? MIPS_ID_OPC_ADDIU :
            MIPS_ID_NONE);
         gen_arith_imm(ctx, op, rt, rs, imm);
         break;
    case OPC_SLTI: /* Set on less than with immediate opcode */
    case OPC_SLTIU:
        mips_ident(ctx,
            op == OPC_SLTI ? MIPS_ID_OPC_SLTI :
            op == OPC_SLTIU ? MIPS_ID_OPC_SLTIU :
            MIPS_ID_NONE);
         gen_slt_imm(ctx, op, rt, rs, imm);
         break;
    case OPC_ANDI: /* Arithmetic with immediate opcode */
    case OPC_LUI: /* OPC_AUI */
    case OPC_ORI:
    case OPC_XORI:
        mips_ident(ctx,
            op == OPC_ANDI ? MIPS_ID_OPC_ANDI :
            op == OPC_LUI ? MIPS_ID_OPC_LUI :
            op == OPC_ORI ? MIPS_ID_OPC_ORI :
            op == OPC_XORI ? MIPS_ID_OPC_XORI :
            MIPS_ID_NONE);
         gen_logic_imm(ctx, op, rt, rs, imm);
         break;
    case OPC_J: /* Jump */
    case OPC_JAL:
        mips_ident(ctx,
            op == OPC_J ? MIPS_ID_OPC_J :
            op == OPC_JAL ? MIPS_ID_OPC_JAL :
            MIPS_ID_NONE);
         offset = (int32_t)(ctx->opcode & 0x3FFFFFF) << 2;
         gen_compute_branch(ctx, op, 4, rs, rt, offset, 4);
         break;
    /* Branch */
    case OPC_BLEZC: /* OPC_BGEZC, OPC_BGEC, OPC_BLEZL */
        mips_ident(ctx,
            op == OPC_BLEZC ? MIPS_ID_OPC_BLEZC :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            if (rt == 0) {
                gen_reserved_instruction(ctx);
                break;
            }
            /* OPC_BLEZC, OPC_BGEZC, OPC_BGEC */
            gen_compute_compact_branch(ctx, op, rs, rt, imm << 2);
        } else {
            /* OPC_BLEZL */
            gen_compute_branch(ctx, op, 4, rs, rt, imm << 2, 4);
        }
        break;
    case OPC_BGTZC: /* OPC_BLTZC, OPC_BLTC, OPC_BGTZL */
        mips_ident(ctx,
            op == OPC_BGTZC ? MIPS_ID_OPC_BGTZC :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            if (rt == 0) {
                gen_reserved_instruction(ctx);
                break;
            }
            /* OPC_BGTZC, OPC_BLTZC, OPC_BLTC */
            gen_compute_compact_branch(ctx, op, rs, rt, imm << 2);
        } else {
            /* OPC_BGTZL */
            gen_compute_branch(ctx, op, 4, rs, rt, imm << 2, 4);
        }
        break;
    case OPC_BLEZALC: /* OPC_BGEZALC, OPC_BGEUC, OPC_BLEZ */
        mips_ident(ctx,
            op == OPC_BLEZALC ? MIPS_ID_OPC_BLEZALC :
            MIPS_ID_NONE);
        if (rt == 0) {
            /* OPC_BLEZ */
            gen_compute_branch(ctx, op, 4, rs, rt, imm << 2, 4);
        } else {
            check_insn(ctx, ISA_MIPS_R6);
            /* OPC_BLEZALC, OPC_BGEZALC, OPC_BGEUC */
            gen_compute_compact_branch(ctx, op, rs, rt, imm << 2);
        }
        break;
    case OPC_BGTZALC: /* OPC_BLTZALC, OPC_BLTUC, OPC_BGTZ */
        mips_ident(ctx,
            op == OPC_BGTZALC ? MIPS_ID_OPC_BGTZALC :
            MIPS_ID_NONE);
        if (rt == 0) {
            /* OPC_BGTZ */
            gen_compute_branch(ctx, op, 4, rs, rt, imm << 2, 4);
        } else {
            check_insn(ctx, ISA_MIPS_R6);
            /* OPC_BGTZALC, OPC_BLTZALC, OPC_BLTUC */
            gen_compute_compact_branch(ctx, op, rs, rt, imm << 2);
        }
        break;
    case OPC_BEQL:
    case OPC_BNEL:
        mips_ident(ctx,
            op == OPC_BEQL ? MIPS_ID_OPC_BEQL :
            op == OPC_BNEL ? MIPS_ID_OPC_BNEL :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS2);
         check_insn_opc_removed(ctx, ISA_MIPS_R6);
        /* Fallthrough */
    case OPC_BEQ:
    case OPC_BNE:
        mips_ident(ctx,
            op == OPC_BEQ ? MIPS_ID_OPC_BEQ :
            op == OPC_BNE ? MIPS_ID_OPC_BNE :
            MIPS_ID_NONE);
         gen_compute_branch(ctx, op, 4, rs, rt, imm << 2, 4);
         break;
    case OPC_LL: /* Load and stores */
        mips_ident(ctx,
            op == OPC_LL ? MIPS_ID_OPC_LL :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS2);
        if (ctx->insn_flags & INSN_R5900) {
            check_insn_opc_user_only(ctx, INSN_R5900);
        }
        /* Fallthrough */
    case OPC_LWL:
    case OPC_LWR:
    case OPC_LB:
    case OPC_LH:
    case OPC_LW:
    case OPC_LWPC:
    case OPC_LBU:
    case OPC_LHU:
        mips_ident(ctx,
            op == OPC_LWL ? MIPS_ID_OPC_LWL :
            op == OPC_LWR ? MIPS_ID_OPC_LWR :
            op == OPC_LB ? MIPS_ID_OPC_LB :
            op == OPC_LH ? MIPS_ID_OPC_LH :
            op == OPC_LW ? MIPS_ID_OPC_LW :
            op == OPC_LWPC ? MIPS_ID_OPC_LWPC :
            op == OPC_LBU ? MIPS_ID_OPC_LBU :
            op == OPC_LHU ? MIPS_ID_OPC_LHU :
            MIPS_ID_NONE);
         gen_ld(ctx, op, rt, rs, imm);
         break;
    case OPC_SWL:
    case OPC_SWR:
    case OPC_SB:
    case OPC_SH:
    case OPC_SW:
        mips_ident(ctx,
            op == OPC_SWL ? MIPS_ID_OPC_SWL :
            op == OPC_SWR ? MIPS_ID_OPC_SWR :
            op == OPC_SB ? MIPS_ID_OPC_SB :
            op == OPC_SH ? MIPS_ID_OPC_SH :
            op == OPC_SW ? MIPS_ID_OPC_SW :
            MIPS_ID_NONE);
         gen_st(ctx, op, rt, rs, imm);
         break;
    case OPC_SC:
        mips_ident(ctx,
            op == OPC_SC ? MIPS_ID_OPC_SC :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS2);
        if (ctx->insn_flags & INSN_R5900) {
            check_insn_opc_user_only(ctx, INSN_R5900);
        }
        gen_st_cond(ctx, rt, rs, imm, mo_endian(ctx) | MO_SL, false);
        break;
    case OPC_CACHE:
        mips_ident(ctx,
            op == OPC_CACHE ? MIPS_ID_OPC_CACHE :
            MIPS_ID_NONE);
        check_cp0_enabled(ctx);
        check_insn(ctx, ISA_MIPS3 | ISA_MIPS_R1);
        if (ctx->hflags & MIPS_HFLAG_ITC_CACHE) {
            gen_cache_operation(ctx, rt, rs, imm);
        }
        /* Treat as NOP. */
        break;
    case OPC_PREF:
        mips_ident(ctx,
            op == OPC_PREF ? MIPS_ID_OPC_PREF :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS4 | ISA_MIPS_R1 | INSN_R5900);
        /* Treat as NOP.  See gen_pref_note_operands(). */
        gen_pref_note_operands(rs, -1);
        break;

    /* Floating point (COP1). */
    case OPC_LWC1:
    case OPC_LDC1:
    case OPC_SWC1:
    case OPC_SDC1:
        mips_ident(ctx,
            op == OPC_LWC1 ? MIPS_ID_OPC_LWC1 :
            op == OPC_LDC1 ? MIPS_ID_OPC_LDC1 :
            op == OPC_SWC1 ? MIPS_ID_OPC_SWC1 :
            op == OPC_SDC1 ? MIPS_ID_OPC_SDC1 :
            MIPS_ID_NONE);
        gen_cop1_ldst(ctx, op, rt, rs, imm);
        break;

    case OPC_CP1:
        mips_ident(ctx,
            op == OPC_CP1 ? MIPS_ID_OPC_CP1 :
            MIPS_ID_NONE);
        op1 = MASK_CP1(ctx->opcode);

        switch (op1) {
        case OPC_MFHC1:
        case OPC_MTHC1:
            mips_ident(ctx,
                op1 == OPC_MFHC1 ? MIPS_ID_OPC_MFHC1 :
                op1 == OPC_MTHC1 ? MIPS_ID_OPC_MTHC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            check_insn(ctx, ISA_MIPS_R2);
            /* fall through */
        case OPC_MFC1:
        case OPC_CFC1:
        case OPC_MTC1:
        case OPC_CTC1:
            mips_ident(ctx,
                op1 == OPC_MFC1 ? MIPS_ID_OPC_MFC1 :
                op1 == OPC_CFC1 ? MIPS_ID_OPC_CFC1 :
                op1 == OPC_MTC1 ? MIPS_ID_OPC_MTC1 :
                op1 == OPC_CTC1 ? MIPS_ID_OPC_CTC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            gen_cp1(ctx, op1, rt, rd);
            break;
#if defined(TARGET_MIPS64)
        case OPC_DMFC1:
        case OPC_DMTC1:
            mips_ident(ctx,
                op1 == OPC_DMFC1 ? MIPS_ID_OPC_DMFC1 :
                op1 == OPC_DMTC1 ? MIPS_ID_OPC_DMTC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            check_insn(ctx, ISA_MIPS3);
            check_mips_64(ctx);
            gen_cp1(ctx, op1, rt, rd);
            break;
#endif
        case OPC_BC1EQZ: /* OPC_BC1ANY2 */
            mips_ident(ctx,
                op1 == OPC_BC1EQZ ? MIPS_ID_OPC_BC1EQZ :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            if (ctx->insn_flags & ISA_MIPS_R6) {
                /* OPC_BC1EQZ */
                gen_compute_branch1_r6(ctx, MASK_CP1(ctx->opcode),
                                       rt, imm << 2, 4);
            } else {
                /* OPC_BC1ANY2 */
                check_cop1x(ctx);
                if (!ase_3d_available(env)) {
                    return false;
                }
                gen_compute_branch1(ctx, MASK_BC1(ctx->opcode),
                                    (rt >> 2) & 0x7, imm << 2);
            }
            break;
        case OPC_BC1NEZ:
            mips_ident(ctx,
                op1 == OPC_BC1NEZ ? MIPS_ID_OPC_BC1NEZ :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            check_insn(ctx, ISA_MIPS_R6);
            gen_compute_branch1_r6(ctx, MASK_CP1(ctx->opcode),
                                   rt, imm << 2, 4);
            break;
        case OPC_BC1ANY4:
            mips_ident(ctx,
                op1 == OPC_BC1ANY4 ? MIPS_ID_OPC_BC1ANY4 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            check_insn_opc_removed(ctx, ISA_MIPS_R6);
            check_cop1x(ctx);
            if (!ase_3d_available(env)) {
                return false;
            }
            /* fall through */
        case OPC_BC1:
            mips_ident(ctx,
                op1 == OPC_BC1 ? MIPS_ID_OPC_BC1 :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            check_insn_opc_removed(ctx, ISA_MIPS_R6);
            gen_compute_branch1(ctx, MASK_BC1(ctx->opcode),
                                (rt >> 2) & 0x7, imm << 2);
            break;
        case OPC_PS_FMT:
            mips_ident(ctx,
                op1 == OPC_PS_FMT ? MIPS_ID_OPC_PS_FMT :
                MIPS_ID_NONE);
            check_ps(ctx);
            /* fall through */
        case OPC_S_FMT:
        case OPC_D_FMT:
            mips_ident(ctx,
                op1 == OPC_S_FMT ? MIPS_ID_OPC_S_FMT :
                op1 == OPC_D_FMT ? MIPS_ID_OPC_D_FMT :
                MIPS_ID_NONE);
            check_cp1_enabled(ctx);
            gen_farith(ctx, ctx->opcode & FOP(0x3f, 0x1f), rt, rd, sa,
                       (imm >> 8) & 0x7);
            break;
        case OPC_W_FMT:
        case OPC_L_FMT:
            mips_ident(ctx,
                op1 == OPC_W_FMT ? MIPS_ID_OPC_W_FMT :
                op1 == OPC_L_FMT ? MIPS_ID_OPC_L_FMT :
                MIPS_ID_NONE);
        {
            int r6_op = ctx->opcode & FOP(0x3f, 0x1f);
            check_cp1_enabled(ctx);
            if (ctx->insn_flags & ISA_MIPS_R6) {
                switch (r6_op) {
                case R6_OPC_CMP_AF_S:
                case R6_OPC_CMP_UN_S:
                case R6_OPC_CMP_EQ_S:
                case R6_OPC_CMP_UEQ_S:
                case R6_OPC_CMP_LT_S:
                case R6_OPC_CMP_ULT_S:
                case R6_OPC_CMP_LE_S:
                case R6_OPC_CMP_ULE_S:
                case R6_OPC_CMP_SAF_S:
                case R6_OPC_CMP_SUN_S:
                case R6_OPC_CMP_SEQ_S:
                case R6_OPC_CMP_SEUQ_S:
                case R6_OPC_CMP_SLT_S:
                case R6_OPC_CMP_SULT_S:
                case R6_OPC_CMP_SLE_S:
                case R6_OPC_CMP_SULE_S:
                case R6_OPC_CMP_OR_S:
                case R6_OPC_CMP_UNE_S:
                case R6_OPC_CMP_NE_S:
                case R6_OPC_CMP_SOR_S:
                case R6_OPC_CMP_SUNE_S:
                case R6_OPC_CMP_SNE_S:
                    mips_ident(ctx,
                        r6_op == R6_OPC_CMP_AF_S ? MIPS_ID_R6_OPC_CMP_AF_S :
                        r6_op == R6_OPC_CMP_UN_S ? MIPS_ID_R6_OPC_CMP_UN_S :
                        r6_op == R6_OPC_CMP_EQ_S ? MIPS_ID_R6_OPC_CMP_EQ_S :
                        r6_op == R6_OPC_CMP_UEQ_S ? MIPS_ID_R6_OPC_CMP_UEQ_S :
                        r6_op == R6_OPC_CMP_LT_S ? MIPS_ID_R6_OPC_CMP_LT_S :
                        r6_op == R6_OPC_CMP_ULT_S ? MIPS_ID_R6_OPC_CMP_ULT_S :
                        r6_op == R6_OPC_CMP_LE_S ? MIPS_ID_R6_OPC_CMP_LE_S :
                        r6_op == R6_OPC_CMP_ULE_S ? MIPS_ID_R6_OPC_CMP_ULE_S :
                        r6_op == R6_OPC_CMP_SAF_S ? MIPS_ID_R6_OPC_CMP_SAF_S :
                        r6_op == R6_OPC_CMP_SUN_S ? MIPS_ID_R6_OPC_CMP_SUN_S :
                        r6_op == R6_OPC_CMP_SEQ_S ? MIPS_ID_R6_OPC_CMP_SEQ_S :
                        r6_op == R6_OPC_CMP_SEUQ_S ?
                            MIPS_ID_R6_OPC_CMP_SEUQ_S :
                        r6_op == R6_OPC_CMP_SLT_S ? MIPS_ID_R6_OPC_CMP_SLT_S :
                        r6_op == R6_OPC_CMP_SULT_S ?
                            MIPS_ID_R6_OPC_CMP_SULT_S :
                        r6_op == R6_OPC_CMP_SLE_S ? MIPS_ID_R6_OPC_CMP_SLE_S :
                        r6_op == R6_OPC_CMP_SULE_S ?
                            MIPS_ID_R6_OPC_CMP_SULE_S :
                        r6_op == R6_OPC_CMP_OR_S ? MIPS_ID_R6_OPC_CMP_OR_S :
                        r6_op == R6_OPC_CMP_UNE_S ? MIPS_ID_R6_OPC_CMP_UNE_S :
                        r6_op == R6_OPC_CMP_NE_S ? MIPS_ID_R6_OPC_CMP_NE_S :
                        r6_op == R6_OPC_CMP_SOR_S ? MIPS_ID_R6_OPC_CMP_SOR_S :
                        r6_op == R6_OPC_CMP_SUNE_S ?
                            MIPS_ID_R6_OPC_CMP_SUNE_S :
                        r6_op == R6_OPC_CMP_SNE_S ? MIPS_ID_R6_OPC_CMP_SNE_S :
                        MIPS_ID_NONE);
                    gen_r6_cmp_s(ctx, ctx->opcode & 0x1f, rt, rd, sa);
                    break;
                case R6_OPC_CMP_AF_D:
                case R6_OPC_CMP_UN_D:
                case R6_OPC_CMP_EQ_D:
                case R6_OPC_CMP_UEQ_D:
                case R6_OPC_CMP_LT_D:
                case R6_OPC_CMP_ULT_D:
                case R6_OPC_CMP_LE_D:
                case R6_OPC_CMP_ULE_D:
                case R6_OPC_CMP_SAF_D:
                case R6_OPC_CMP_SUN_D:
                case R6_OPC_CMP_SEQ_D:
                case R6_OPC_CMP_SEUQ_D:
                case R6_OPC_CMP_SLT_D:
                case R6_OPC_CMP_SULT_D:
                case R6_OPC_CMP_SLE_D:
                case R6_OPC_CMP_SULE_D:
                case R6_OPC_CMP_OR_D:
                case R6_OPC_CMP_UNE_D:
                case R6_OPC_CMP_NE_D:
                case R6_OPC_CMP_SOR_D:
                case R6_OPC_CMP_SUNE_D:
                case R6_OPC_CMP_SNE_D:
                    mips_ident(ctx,
                        r6_op == R6_OPC_CMP_AF_D ? MIPS_ID_R6_OPC_CMP_AF_D :
                        r6_op == R6_OPC_CMP_UN_D ? MIPS_ID_R6_OPC_CMP_UN_D :
                        r6_op == R6_OPC_CMP_EQ_D ? MIPS_ID_R6_OPC_CMP_EQ_D :
                        r6_op == R6_OPC_CMP_UEQ_D ? MIPS_ID_R6_OPC_CMP_UEQ_D :
                        r6_op == R6_OPC_CMP_LT_D ? MIPS_ID_R6_OPC_CMP_LT_D :
                        r6_op == R6_OPC_CMP_ULT_D ? MIPS_ID_R6_OPC_CMP_ULT_D :
                        r6_op == R6_OPC_CMP_LE_D ? MIPS_ID_R6_OPC_CMP_LE_D :
                        r6_op == R6_OPC_CMP_ULE_D ? MIPS_ID_R6_OPC_CMP_ULE_D :
                        r6_op == R6_OPC_CMP_SAF_D ? MIPS_ID_R6_OPC_CMP_SAF_D :
                        r6_op == R6_OPC_CMP_SUN_D ? MIPS_ID_R6_OPC_CMP_SUN_D :
                        r6_op == R6_OPC_CMP_SEQ_D ? MIPS_ID_R6_OPC_CMP_SEQ_D :
                        r6_op == R6_OPC_CMP_SEUQ_D ?
                            MIPS_ID_R6_OPC_CMP_SEUQ_D :
                        r6_op == R6_OPC_CMP_SLT_D ? MIPS_ID_R6_OPC_CMP_SLT_D :
                        r6_op == R6_OPC_CMP_SULT_D ?
                            MIPS_ID_R6_OPC_CMP_SULT_D :
                        r6_op == R6_OPC_CMP_SLE_D ? MIPS_ID_R6_OPC_CMP_SLE_D :
                        r6_op == R6_OPC_CMP_SULE_D ?
                            MIPS_ID_R6_OPC_CMP_SULE_D :
                        r6_op == R6_OPC_CMP_OR_D ? MIPS_ID_R6_OPC_CMP_OR_D :
                        r6_op == R6_OPC_CMP_UNE_D ? MIPS_ID_R6_OPC_CMP_UNE_D :
                        r6_op == R6_OPC_CMP_NE_D ? MIPS_ID_R6_OPC_CMP_NE_D :
                        r6_op == R6_OPC_CMP_SOR_D ? MIPS_ID_R6_OPC_CMP_SOR_D :
                        r6_op == R6_OPC_CMP_SUNE_D ?
                            MIPS_ID_R6_OPC_CMP_SUNE_D :
                        r6_op == R6_OPC_CMP_SNE_D ? MIPS_ID_R6_OPC_CMP_SNE_D :
                        MIPS_ID_NONE);
                    gen_r6_cmp_d(ctx, ctx->opcode & 0x1f, rt, rd, sa);
                    break;
                default:
                    gen_farith(ctx, ctx->opcode & FOP(0x3f, 0x1f),
                               rt, rd, sa, (imm >> 8) & 0x7);

                    break;
                }
            } else {
                gen_farith(ctx, ctx->opcode & FOP(0x3f, 0x1f), rt, rd, sa,
                           (imm >> 8) & 0x7);
            }
            break;
        }
        default:
            MIPS_INVAL("cp1");
            gen_reserved_instruction(ctx);
            break;
        }
        break;

    /* Compact branches [R6] and COP2 [non-R6] */
    case OPC_BC: /* OPC_LWC2 */
    case OPC_BALC: /* OPC_SWC2 */
        mips_ident(ctx,
            op == OPC_BC ? MIPS_ID_OPC_BC :
            op == OPC_BALC ? MIPS_ID_OPC_BALC :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_BC, OPC_BALC */
            gen_compute_compact_branch(ctx, op, 0, 0,
                                       sextract32(ctx->opcode << 2, 0, 28));
        } else if (ctx->insn_flags & ASE_LEXT) {
            gen_loongson_lswc2(ctx, rt, rs, rd);
        } else {
            /* OPC_LWC2, OPC_SWC2 */
            /* COP2: Not implemented. */
            generate_exception_err(ctx, EXCP_CpU, 2);
        }
        break;
    case OPC_BEQZC: /* OPC_JIC, OPC_LDC2 */
    case OPC_BNEZC: /* OPC_JIALC, OPC_SDC2 */
        mips_ident(ctx,
            op == OPC_BEQZC ? MIPS_ID_OPC_BEQZC :
            op == OPC_BNEZC ? MIPS_ID_OPC_BNEZC :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            if (rs != 0) {
                /* OPC_BEQZC, OPC_BNEZC */
                gen_compute_compact_branch(ctx, op, rs, 0,
                                           sextract32(ctx->opcode << 2, 0, 23));
            } else {
                /* OPC_JIC, OPC_JIALC */
                gen_compute_compact_branch(ctx, op, 0, rt, imm);
            }
        } else if (ctx->insn_flags & ASE_LEXT) {
            gen_loongson_lsdc2(ctx, rt, rs, rd);
        } else {
            /* OPC_LWC2, OPC_SWC2 */
            /* COP2: Not implemented. */
            generate_exception_err(ctx, EXCP_CpU, 2);
        }
        break;
    case OPC_CP2:
        mips_ident(ctx,
            op == OPC_CP2 ? MIPS_ID_OPC_CP2 :
            MIPS_ID_NONE);
        check_insn(ctx, ASE_LMMI);
        /* Note that these instructions use different fields.  */
        gen_loongson_multimedia(ctx, sa, rd, rt);
        break;

    case OPC_CP3:
        mips_ident(ctx,
            op == OPC_CP3 ? MIPS_ID_OPC_CP3 :
            MIPS_ID_NONE);
        if (ctx->CP0_Config1 & (1 << CP0C1_FP)) {
            check_cp1_enabled(ctx);
            op1 = MASK_CP3(ctx->opcode);
            switch (op1) {
            case OPC_LUXC1:
            case OPC_SUXC1:
                mips_ident(ctx,
                    op1 == OPC_LUXC1 ? MIPS_ID_OPC_LUXC1 :
                    op1 == OPC_SUXC1 ? MIPS_ID_OPC_SUXC1 :
                    MIPS_ID_NONE);
                check_insn(ctx, ISA_MIPS5 | ISA_MIPS_R2);
                /* Fallthrough */
            case OPC_LWXC1:
            case OPC_LDXC1:
            case OPC_SWXC1:
            case OPC_SDXC1:
                mips_ident(ctx,
                    op1 == OPC_LWXC1 ? MIPS_ID_OPC_LWXC1 :
                    op1 == OPC_LDXC1 ? MIPS_ID_OPC_LDXC1 :
                    op1 == OPC_SWXC1 ? MIPS_ID_OPC_SWXC1 :
                    op1 == OPC_SDXC1 ? MIPS_ID_OPC_SDXC1 :
                    MIPS_ID_NONE);
                check_insn(ctx, ISA_MIPS4 | ISA_MIPS_R2);
                gen_flt3_ldst(ctx, op1, sa, rd, rs, rt);
                break;
            case OPC_PREFX:
                mips_ident(ctx,
                    op1 == OPC_PREFX ? MIPS_ID_OPC_PREFX :
                    MIPS_ID_NONE);
                check_insn(ctx, ISA_MIPS4 | ISA_MIPS_R2);
                /* Treat as NOP.  See gen_pref_note_operands(). */
                gen_pref_note_operands(rs, rt);
                break;
            case OPC_ALNV_PS:
                mips_ident(ctx,
                    op1 == OPC_ALNV_PS ? MIPS_ID_OPC_ALNV_PS :
                    MIPS_ID_NONE);
                check_insn(ctx, ISA_MIPS5 | ISA_MIPS_R2);
                /* Fallthrough */
            case OPC_MADD_S:
            case OPC_MADD_D:
            case OPC_MADD_PS:
            case OPC_MSUB_S:
            case OPC_MSUB_D:
            case OPC_MSUB_PS:
            case OPC_NMADD_S:
            case OPC_NMADD_D:
            case OPC_NMADD_PS:
            case OPC_NMSUB_S:
            case OPC_NMSUB_D:
            case OPC_NMSUB_PS:
                mips_ident(ctx,
                    op1 == OPC_MADD_S ? MIPS_ID_OPC_MADD_S :
                    op1 == OPC_MADD_D ? MIPS_ID_OPC_MADD_D :
                    op1 == OPC_MADD_PS ? MIPS_ID_OPC_MADD_PS :
                    op1 == OPC_MSUB_S ? MIPS_ID_OPC_MSUB_S :
                    op1 == OPC_MSUB_D ? MIPS_ID_OPC_MSUB_D :
                    op1 == OPC_MSUB_PS ? MIPS_ID_OPC_MSUB_PS :
                    op1 == OPC_NMADD_S ? MIPS_ID_OPC_NMADD_S :
                    op1 == OPC_NMADD_D ? MIPS_ID_OPC_NMADD_D :
                    op1 == OPC_NMADD_PS ? MIPS_ID_OPC_NMADD_PS :
                    op1 == OPC_NMSUB_S ? MIPS_ID_OPC_NMSUB_S :
                    op1 == OPC_NMSUB_D ? MIPS_ID_OPC_NMSUB_D :
                    op1 == OPC_NMSUB_PS ? MIPS_ID_OPC_NMSUB_PS :
                    MIPS_ID_NONE);
                check_insn(ctx, ISA_MIPS4 | ISA_MIPS_R2);
                gen_flt3_arith(ctx, op1, sa, rs, rd, rt);
                break;
            default:
                MIPS_INVAL("cp3");
                gen_reserved_instruction(ctx);
                break;
            }
        } else {
            generate_exception_err(ctx, EXCP_CpU, 1);
        }
        break;

#if defined(TARGET_MIPS64)
    /* MIPS64 opcodes */
    case OPC_LLD:
        mips_ident(ctx,
            op == OPC_LLD ? MIPS_ID_OPC_LLD :
            MIPS_ID_NONE);
        if (ctx->insn_flags & INSN_R5900) {
            check_insn_opc_user_only(ctx, INSN_R5900);
        }
        /* fall through */
    case OPC_LDL:
    case OPC_LDR:
    case OPC_LWU:
    case OPC_LD:
        mips_ident(ctx,
            op == OPC_LDL ? MIPS_ID_OPC_LDL :
            op == OPC_LDR ? MIPS_ID_OPC_LDR :
            op == OPC_LWU ? MIPS_ID_OPC_LWU :
            op == OPC_LD ? MIPS_ID_OPC_LD :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        check_mips_64(ctx);
        gen_ld(ctx, op, rt, rs, imm);
        break;
    case OPC_SDL:
    case OPC_SDR:
    case OPC_SD:
        mips_ident(ctx,
            op == OPC_SDL ? MIPS_ID_OPC_SDL :
            op == OPC_SDR ? MIPS_ID_OPC_SDR :
            op == OPC_SD ? MIPS_ID_OPC_SD :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        check_mips_64(ctx);
        gen_st(ctx, op, rt, rs, imm);
        break;
    case OPC_SCD:
        mips_ident(ctx,
            op == OPC_SCD ? MIPS_ID_OPC_SCD :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        if (ctx->insn_flags & INSN_R5900) {
            check_insn_opc_user_only(ctx, INSN_R5900);
        }
        check_mips_64(ctx);
        gen_st_cond(ctx, rt, rs, imm, mo_endian(ctx) | MO_UQ, false);
        break;
    case OPC_BNVC: /* OPC_BNEZALC, OPC_BNEC, OPC_DADDI */
        mips_ident(ctx,
            op == OPC_BNVC ? MIPS_ID_OPC_BNVC :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            /* OPC_BNVC, OPC_BNEZALC, OPC_BNEC */
            gen_compute_compact_branch(ctx, op, rs, rt, imm << 2);
        } else {
            /* OPC_DADDI */
            check_insn(ctx, ISA_MIPS3);
            check_mips_64(ctx);
            gen_arith_imm(ctx, op, rt, rs, imm);
        }
        break;
    case OPC_DADDIU:
        mips_ident(ctx,
            op == OPC_DADDIU ? MIPS_ID_OPC_DADDIU :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS3);
        check_mips_64(ctx);
        gen_arith_imm(ctx, op, rt, rs, imm);
        break;
#else
    case OPC_BNVC: /* OPC_BNEZALC, OPC_BNEC */
        mips_ident(ctx,
            op == OPC_BNVC ? MIPS_ID_OPC_BNVC :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
            gen_compute_compact_branch(ctx, op, rs, rt, imm << 2);
        } else {
            MIPS_INVAL("major opcode");
            gen_reserved_instruction(ctx);
        }
        break;
#endif
    case OPC_DAUI: /* OPC_JALX */
        mips_ident(ctx,
            op == OPC_DAUI ? MIPS_ID_OPC_DAUI :
            MIPS_ID_NONE);
        if (ctx->insn_flags & ISA_MIPS_R6) {
#if defined(TARGET_MIPS64)
            /* OPC_DAUI */
            check_mips_64(ctx);
            if (rs == 0) {
                generate_exception(ctx, EXCP_RI);
            } else if (rt != 0) {
                TCGv t0 = tcg_temp_new();
                gen_load_gpr(t0, rs);
                tcg_gen_addi_tl(cpu_gpr[rt], t0, imm << 16);
            }
#else
            gen_reserved_instruction(ctx);
            MIPS_INVAL("major opcode");
#endif
        } else {
            /* OPC_JALX */
            check_insn(ctx, ASE_MIPS16 | ASE_MICROMIPS);
            offset = (int32_t)(ctx->opcode & 0x3FFFFFF) << 2;
            gen_compute_branch(ctx, op, 4, rs, rt, offset, 4);
        }
        break;
    case OPC_MDMX:
        mips_ident(ctx,
            op == OPC_MDMX ? MIPS_ID_OPC_MDMX :
            MIPS_ID_NONE);
        /* MDMX: Not implemented. */
        break;
    case OPC_PCREL:
        mips_ident(ctx,
            op == OPC_PCREL ? MIPS_ID_OPC_PCREL :
            MIPS_ID_NONE);
        check_insn(ctx, ISA_MIPS_R6);
        gen_pcrel(ctx, ctx->opcode, ctx->base.pc_next, rs);
        break;
    default:            /* Invalid */
        MIPS_INVAL("major opcode");
        return false;
    }
    return true;
}

static void decode_opc(CPUMIPSState *env, DisasContext *ctx)
{
    /* make sure instructions are on a word boundary */
    if (ctx->base.pc_next & 0x3) {
        env->CP0_BadVAddr = ctx->base.pc_next;
        generate_exception_err(ctx, EXCP_AdEL, EXCP_INST_NOTAVAIL);
        return;
    }

    /* Handle blikely not taken case */
    if ((ctx->hflags & MIPS_HFLAG_BMASK_BASE) == MIPS_HFLAG_BL) {
        TCGLabel *l1 = gen_new_label();

        tcg_gen_brcondi_tl(TCG_COND_NE, bcond, 0, l1);
        tcg_gen_movi_i32(hflags, ctx->hflags & ~MIPS_HFLAG_BMASK);
        gen_goto_tb(ctx, 1, ctx->base.pc_next + 4);
        gen_set_label(l1);
    }

    /* Transition to the auto-generated decoder.  */

    /* Vendor specific extensions */
    if (cpu_supports_isa(env, INSN_R5900) && decode_ext_txx9(ctx, ctx->opcode)) {
        return;
    }
    if (cpu_supports_isa(env, INSN_VR54XX) && decode_ext_vr54xx(ctx, ctx->opcode)) {
        return;
    }
    if (TARGET_LONG_BITS == 64 && decode_ext_loongson(ctx, ctx->opcode)) {
        return;
    }
#if defined(TARGET_MIPS64)
    if (ase_lcsr_available(env) && decode_ase_lcsr(ctx, ctx->opcode)) {
        return;
    }
    if (cpu_supports_isa(env, INSN_OCTEON) && decode_ext_octeon(ctx, ctx->opcode)) {
        return;
    }
#endif

    /* ISA extensions */
    if (ase_msa_available(env) && decode_ase_msa(ctx, ctx->opcode)) {
        return;
    }

    /* ISA (from latest to oldest) */
    if (cpu_supports_isa(env, ISA_MIPS_R6) && decode_isa_rel6(ctx, ctx->opcode)) {
        return;
    }

    if (decode_opc_legacy(env, ctx)) {
        return;
    }

    gen_reserved_instruction(ctx);
}

static void mips_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPUMIPSState *env = cpu_env(cs);

    ctx->page_start = ctx->base.pc_first & TARGET_PAGE_MASK;
    ctx->saved_pc = -1;
    ctx->insn_flags = env->insn_flags;
    ctx->CP0_Config0 = env->CP0_Config0;
    ctx->CP0_Config1 = env->CP0_Config1;
    ctx->CP0_Config2 = env->CP0_Config2;
    ctx->CP0_Config3 = env->CP0_Config3;
    ctx->CP0_Config5 = env->CP0_Config5;
    ctx->btarget = 0;
    ctx->kscrexist = (env->CP0_Config4 >> CP0C4_KScrExist) & 0xff;
    ctx->rxi = (env->CP0_Config3 >> CP0C3_RXI) & 1;
    ctx->ie = (env->CP0_Config4 >> CP0C4_IE) & 3;
    ctx->bi = (env->CP0_Config3 >> CP0C3_BI) & 1;
    ctx->bp = (env->CP0_Config3 >> CP0C3_BP) & 1;
    ctx->PAMask = env->PAMask;
    ctx->mvh = (env->CP0_Config5 >> CP0C5_MVH) & 1;
    ctx->eva = (env->CP0_Config5 >> CP0C5_EVA) & 1;
    ctx->sc = (env->CP0_Config3 >> CP0C3_SC) & 1;
    ctx->CP0_LLAddr_shift = env->CP0_LLAddr_shift;
    ctx->cmgcr = (env->CP0_Config3 >> CP0C3_CMGCR) & 1;
    /* Restore delay slot state from the tb context.  */
    ctx->hflags = (uint32_t)ctx->base.tb->flags; /* FIXME: maybe use 64 bits? */
    ctx->ulri = (env->CP0_Config3 >> CP0C3_ULRI) & 1;
    ctx->ps = ((env->active_fpu.fcr0 >> FCR0_PS) & 1) ||
             (env->insn_flags & (INSN_LOONGSON2E | INSN_LOONGSON2F));
    ctx->vp = (env->CP0_Config5 >> CP0C5_VP) & 1;
    ctx->mrp = (env->CP0_Config5 >> CP0C5_MRP) & 1;
    ctx->nan2008 = (env->active_fpu.fcr31 >> FCR31_NAN2008) & 1;
    ctx->abs2008 = (env->active_fpu.fcr31 >> FCR31_ABS2008) & 1;
    ctx->mi = (env->CP0_Config5 >> CP0C5_MI) & 1;
    ctx->gi = (env->CP0_Config5 >> CP0C5_GI) & 3;
    restore_cpu_state(env, ctx);
#ifdef CONFIG_USER_ONLY
        ctx->mem_idx = MIPS_HFLAG_UM;
#else
        ctx->mem_idx = hflags_mmu_index(ctx->hflags);
#endif
    ctx->default_tcg_memop_mask = (!(ctx->insn_flags & ISA_NANOMIPS32) &&
                                  (ctx->insn_flags & (ISA_MIPS_R6 |
                                  INSN_LOONGSON3A))) ? MO_UNALN : MO_ALIGN;

    /*
     * Execute a branch and its delay slot as a single instruction.
     * This is what GDB expects and is consistent with what the
     * hardware does (e.g. if a delay slot instruction faults, the
     * reported PC is the PC of the branch).
     */
    if ((tb_cflags(ctx->base.tb) & CF_SINGLE_STEP) &&
        (ctx->hflags & MIPS_HFLAG_BMASK)) {
        ctx->base.max_insns = 2;
    }

    LOG_DISAS("\ntb %p idx %d hflags %04x\n", ctx->base.tb, ctx->mem_idx,
              ctx->hflags);
}

static void mips_tr_tb_start(DisasContextBase *dcbase, CPUState *cs)
{
}

static void mips_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    tcg_gen_insn_start(ctx->base.pc_next, ctx->hflags & MIPS_HFLAG_BMASK,
                       ctx->btarget);
}

static void mips_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    CPUMIPSState *env = cpu_env(cs);
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    int insn_bytes;
    int is_slot;
    bool was_slot;

    is_slot = ctx->hflags & MIPS_HFLAG_BMASK;
    /*
     * Taken BEFORE the forcing below, because the two cases it merges have
     * different owners for the transfer gen_branch() emits.  See the
     * plugin_gen_record_ctrl_* calls at the bottom of this function.
     */
    was_slot = is_slot != 0;
    ctx->decode_ident = MIPS_ID_NONE;
    if (ctx->insn_flags & ISA_NANOMIPS32) {
        ctx->opcode = translator_lduw(env, &ctx->base, ctx->base.pc_next);
        insn_bytes = decode_isa_nanomips(env, ctx);
    } else if (!(ctx->hflags & MIPS_HFLAG_M16)) {
        ctx->opcode = translator_ldl(env, &ctx->base, ctx->base.pc_next);
        insn_bytes = 4;
        decode_opc(env, ctx);
        /*
         * Published for the base ISA only.  The microMIPS, MIPS16e and
         * nanoMIPS decoders reach the same generators by handing them a
         * BASE-ISA opcode constant -- gen_arith(ctx, OPC_ADDU, ...) for
         * microMIPS ADDU16, and hundreds more sites like it -- so a row
         * chosen inside a generator on those paths names the base-ISA
         * encoding and not the instruction that was decoded.  Those
         * decoders have their own case labels and are their own export;
         * until that export exists they publish nothing, which is the
         * honest answer rather than a base-ISA name for a 16-bit
         * encoding.
         */
        mips_ident_publish(ctx);
    } else if (ctx->insn_flags & ASE_MICROMIPS) {
        ctx->opcode = translator_lduw(env, &ctx->base, ctx->base.pc_next);
        insn_bytes = decode_isa_micromips(env, ctx);
    } else if (ctx->insn_flags & ASE_MIPS16) {
        ctx->opcode = translator_lduw(env, &ctx->base, ctx->base.pc_next);
        insn_bytes = decode_ase_mips16e(env, ctx);
    } else {
        gen_reserved_instruction(ctx);
        g_assert(ctx->base.is_jmp == DISAS_NORETURN);
        /*
         * MIPS_HFLAG_M16 is set on a CPU that implements neither MIPS16e
         * nor microMIPS, so nothing was fetched and there is no instruction
         * length to add.  The TB still needs one: translator_loop() derives
         * tb->size from pc_next, and a zero-length TB trips
         * assert(tb->size != 0) in setjmp_gen_code(), killing the process
         * instead of delivering the Reserved Instruction exception just
         * raised.  Two bytes is the shortest instruction any ISA mode of
         * this architecture has, and no byte of it was consulted during
         * translation, so it cannot under-cover the TB's invalidation range.
         */
        ctx->base.pc_next += 2;
        return;
    }

    if (ctx->hflags & MIPS_HFLAG_BMASK) {
        if (!(ctx->hflags & (MIPS_HFLAG_BDS16 | MIPS_HFLAG_BDS32 |
                             MIPS_HFLAG_FBNSLOT))) {
            /*
             * Force to generate branch as there is neither delay nor
             * forbidden slot.
             */
            is_slot = 1;
        }
        if ((ctx->hflags & MIPS_HFLAG_M16) &&
            (ctx->hflags & MIPS_HFLAG_FBNSLOT)) {
            /*
             * Force to generate branch as microMIPS R6 doesn't restrict
             * branches in the forbidden slot.
             */
            is_slot = 1;
        }
    }
    if (is_slot) {
        /*
         * WHOSE TRANSFER THIS IS.  When is_slot was already set on entry,
         * the branch is the PREVIOUS instruction and gen_branch() is
         * emitting ITS transfer here, at the end of the delay (or forbidden)
         * slot.  Nothing in the op list says so, and a consumer that reads
         * ownership off position credits the slot with the branch and leaves
         * the branch reading as an ordinary instruction -- measured at 1,991
         * of 6,549 classifications on a mipsel workload, which is every
         * delay-slot branch in it.
         *
         * When is_slot was FORCED to 1 above, the branch has neither a delay
         * nor a forbidden slot and gen_branch() is emitting the transfer of
         * the instruction just decoded, which is this one.  No statement is
         * owed then, and making one would move the transfer off the
         * instruction that performs it.
         */
        if (was_slot) {
            plugin_gen_record_ctrl_resume();
        }
        gen_branch(ctx, insn_bytes);
    } else if (ctx->hflags & MIPS_HFLAG_BMASK) {
        /*
         * BMASK was clear on entry (is_slot was 0) and is set now, so the
         * instruction just decoded is a branch that has armed its slot.  Its
         * transfer will be emitted by the gen_branch() above during the NEXT
         * instruction -- or not in this block at all, if the block ends
         * here, which is the delay-slot sibling of a page-straddling block
         * and is reported as QEMU_PLUGIN_CTRL_PENDING.
         */
        plugin_gen_record_ctrl_deferred();
    }
    if (ctx->base.is_jmp == DISAS_SEMIHOST) {
        generate_exception_err(ctx, EXCP_SEMIHOST, insn_bytes);
    }
    ctx->base.pc_next += insn_bytes;

    if (ctx->base.is_jmp != DISAS_NEXT) {
        return;
    }

    /*
     * End the TB on (most) page crossings.
     * See mips_tr_init_disas_context about single-stepping a branch
     * together with its delay slot.
     */
    if (ctx->base.pc_next - ctx->page_start >= TARGET_PAGE_SIZE
        && !(tb_cflags(ctx->base.tb) & CF_SINGLE_STEP)) {
        ctx->base.is_jmp = DISAS_TOO_MANY;
    }
}

static void mips_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_STOP:
        gen_save_pc(ctx->base.pc_next);
        tcg_gen_lookup_and_goto_ptr();
        break;
    case DISAS_NEXT:
    case DISAS_TOO_MANY:
        save_cpu_state(ctx, 0);
        gen_goto_tb(ctx, 0, ctx->base.pc_next);
        break;
    case DISAS_EXIT:
        tcg_gen_exit_tb(NULL, 0);
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * v4 repair (maintainer-vetoable): never-split RETREAT support.  The
 * checkpoint captures hflags at each insn boundary; a retreat restores
 * it, so ending the TB at a boundary that re-opens a delay slot (the
 * dropped sequence's first insn was the slot of a kept branch) re-arms
 * the pending-branch state.  saved_hflags is poisoned so save_cpu_state
 * in tb_stop re-emits the hflags (and, under BMASK, btarget) stores —
 * the spills it thinks it already emitted may have been dropped with
 * the retreated ops.  ctx->btarget itself is compile-time state set by
 * the kept branch and is still valid.  The dropped insns are LUI/ORI
 * immediate loads and never touch hflags themselves.
 */
static uint64_t mips_tr_nosplit_checkpoint(DisasContextBase *dcbase,
                                           CPUState *cpu)
{
    return container_of(dcbase, DisasContext, base)->hflags;
}

static bool mips_tr_nosplit_retreat(DisasContextBase *dcbase, CPUState *cpu,
                                    vaddr retreat_pc, uint64_t checkpoint)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    ctx->hflags = (uint32_t)checkpoint;
    ctx->saved_hflags = ~ctx->hflags;
    return true;
}

static const TranslatorOps mips_tr_ops = {
    .init_disas_context = mips_tr_init_disas_context,
    .tb_start           = mips_tr_tb_start,
    .insn_start         = mips_tr_insn_start,
    .translate_insn     = mips_tr_translate_insn,
    .tb_stop            = mips_tr_tb_stop,
    .nosplit_checkpoint = mips_tr_nosplit_checkpoint,
    .nosplit_retreat    = mips_tr_nosplit_retreat,
};

void mips_translate_code(CPUState *cs, TranslationBlock *tb,
                         int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext ctx;

    translator_loop(cs, tb, max_insns, pc, host_pc, &mips_tr_ops, &ctx.base);
}

void mips_tcg_init(void)
{
    cpu_gpr[0] = NULL;
    for (unsigned i = 1; i < 32; i++)
        cpu_gpr[i] = tcg_global_mem_new(tcg_env,
                                        offsetof(CPUMIPSState,
                                                 active_tc.gpr[i]),
                                        regnames[i]);
#if defined(TARGET_MIPS64)
    cpu_gpr_hi[0] = NULL;

    for (unsigned i = 1; i < 32; i++) {
        g_autofree char *rname = g_strdup_printf("%s[hi]", regnames[i]);

        cpu_gpr_hi[i] = tcg_global_mem_new_i64(tcg_env,
                                               offsetof(CPUMIPSState,
                                                        active_tc.gpr_hi[i]),
                                               rname);
    }
#endif /* !TARGET_MIPS64 */
    for (unsigned i = 0; i < 32; i++) {
        int off = offsetof(CPUMIPSState, active_fpu.fpr[i].wr.d[0]);

        fpu_f64[i] = tcg_global_mem_new_i64(tcg_env, off, fregnames[i]);
    }
    msa_translate_init();
    cpu_PC = tcg_global_mem_new(tcg_env,
                                offsetof(CPUMIPSState, active_tc.PC), "PC");
    for (unsigned i = 0; i < MIPS_DSP_ACC; i++) {
        cpu_HI[i] = tcg_global_mem_new(tcg_env,
                                       offsetof(CPUMIPSState, active_tc.HI[i]),
                                       regnames_HI[i]);
        cpu_LO[i] = tcg_global_mem_new(tcg_env,
                                       offsetof(CPUMIPSState, active_tc.LO[i]),
                                       regnames_LO[i]);
    }
    cpu_dspctrl = tcg_global_mem_new(tcg_env,
                                     offsetof(CPUMIPSState,
                                              active_tc.DSPControl),
                                     "DSPControl");
    bcond = tcg_global_mem_new(tcg_env,
                               offsetof(CPUMIPSState, bcond), "bcond");
    btarget = tcg_global_mem_new(tcg_env,
                                 offsetof(CPUMIPSState, btarget), "btarget");
    hflags = tcg_global_mem_new_i32(tcg_env,
                                    offsetof(CPUMIPSState, hflags), "hflags");

    fpu_fcr0 = tcg_global_mem_new_i32(tcg_env,
                                      offsetof(CPUMIPSState, active_fpu.fcr0),
                                      "fcr0");
    fpu_fcr31 = tcg_global_mem_new_i32(tcg_env,
                                       offsetof(CPUMIPSState, active_fpu.fcr31),
                                       "fcr31");
    cpu_lladdr = tcg_global_mem_new(tcg_env, offsetof(CPUMIPSState, lladdr),
                                    "lladdr");
    cpu_llval = tcg_global_mem_new(tcg_env, offsetof(CPUMIPSState, llval),
                                   "llval");

    if (TARGET_LONG_BITS == 32) {
        mxu_translate_init();
    }

    /*
     * The CP0 registers an EXCEPTION writes, for the dataflow extraction.
     *
     * No TCG global names these -- the translator never touches CP0_Cause,
     * CP0_Status or CP0_BadVAddr, because the write is not performed by the
     * translated code at all: `syscall` and `teq` emit a call to
     * helper_raise_exception(), and the CP0 state is written afterwards by
     * mips_cpu_do_interrupt() during exception DELIVERY.  Without this
     * declaration that state arrives at a consumer as a bare CPUArchState
     * byte range with no register name, so an instruction whose
     * architectural destination IS the exception state has no write row to
     * match and the whole destination family refuses (#218).
     *
     * R7.6 is the ruling that the delivery write set is in the raising
     * instruction's set; the CP-H hand row on raise_exception states WHICH
     * of these it writes and cites mips_cpu_do_interrupt() line by line.
     * This declaration is only the naming half -- it says which register a
     * given env offset IS, and says nothing about who writes it.
     *
     * The names are the GDB stub's (target/mips/gdbstub.c spells these
     * "badvaddr", "status" and "cause"), which is the namespace
     * insn_dataflow_reg_name() already answers in.  Declared here, beside
     * the globals, in offsetof() and sizeof() -- the compiler reading
     * CPUMIPSState rather than anyone typing a number.
     *
     * CP0_EPC is deliberately NOT declared: the delivery writes it, but the
     * tracer's register vocabulary has no row spelling "epc", so naming the
     * offset would produce a name that then maps to nothing.  A name that
     * cannot be resolved is not better than no name -- it moves the refusal
     * one gate later without answering anything -- and the three declared
     * here already carry REG_SYSEXC, which is the one generic word all of
     * this state shares.
     */
    insn_dataflow_declare_regfile("badvaddr", NULL,
                                  offsetof(CPUMIPSState, CP0_BadVAddr),
                                  sizeof(((CPUMIPSState *)0)->CP0_BadVAddr),
                                  sizeof(((CPUMIPSState *)0)->CP0_BadVAddr),
                                  1);
    insn_dataflow_declare_regfile("status", NULL,
                                  offsetof(CPUMIPSState, CP0_Status),
                                  sizeof(((CPUMIPSState *)0)->CP0_Status),
                                  sizeof(((CPUMIPSState *)0)->CP0_Status),
                                  1);
    insn_dataflow_declare_regfile("cause", NULL,
                                  offsetof(CPUMIPSState, CP0_Cause),
                                  sizeof(((CPUMIPSState *)0)->CP0_Cause),
                                  sizeof(((CPUMIPSState *)0)->CP0_Cause),
                                  1);
    /*
     * CP0_UserLocal -- the THREAD POINTER, and the register `rdhwr rt,$29`
     * reads.
     *
     * The read IS stated: gen_rdhwr's UL arm emits a load from this env
     * offset, so the extractor sees a byte range and asks what register it
     * is.  Nothing answered, because no TCG global names it and it has no
     * row in the GDB stub's namespace either (#240) -- so a fact QEMU DID
     * state arrived at a consumer as an anonymous range and every published
     * REG_TLS source it would have justified was counted unjustified.
     *
     * Declared here for the same reason the three CP0 rows above are, and
     * in the same terms: offsetof() and sizeof(), the compiler reading
     * CPUMIPSState.  The spelling is "userlocal" because the GDB stub has
     * none to borrow; champsim_tracer's fold_nonarch() is where that
     * spelling meets REG_TLS, which is the same route "lr" and "x8/s0"
     * already take.
     */
    insn_dataflow_declare_regfile("userlocal", NULL,
                                  offsetof(CPUMIPSState,
                                           active_tc.CP0_UserLocal),
                                  sizeof(((CPUMIPSState *)0)
                                         ->active_tc.CP0_UserLocal),
                                  sizeof(((CPUMIPSState *)0)
                                         ->active_tc.CP0_UserLocal),
                                  1);
}

void mips_restore_state_to_opc(CPUState *cs,
                               const TranslationBlock *tb,
                               const uint64_t *data)
{
    CPUMIPSState *env = cpu_env(cs);

    env->active_tc.PC = data[0];
    env->hflags &= ~MIPS_HFLAG_BMASK;
    env->hflags |= data[1];
    switch (env->hflags & MIPS_HFLAG_BMASK_BASE) {
    case MIPS_HFLAG_BR:
        break;
    case MIPS_HFLAG_BC:
    case MIPS_HFLAG_BL:
    case MIPS_HFLAG_B:
        env->btarget = data[2];
        break;
    }
}
