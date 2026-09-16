/*
 * mips_enum -- enumerate the mipsel OPCODE SPACE from the GNU binutils 2.42
 * MIPS opcode table, and synthesise one representative encoding per opcode
 * SHAPE.
 *
 * Nothing is transcribed.  The rows come from the real mips_opcodes[] array
 * compiled out of binutils-2.42/opcodes/mips-opc.c, and the bit position of
 * every operand comes from that same file's decode_mips_operand(), which is
 * the function the GNU assembler and disassembler themselves call.  The
 * representative encoding is therefore built out of the reference's own
 * field layout, not out of a hand-written table.
 *
 * Author: Maccoy Merrell
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sysdep.h"
#include "opcode/mips.h"

/* Mirrors contrib/plugins/champsim_tracer/tools/isaxcheck.cc kIsaTable's
   mipsel row: mips32r2 + msa,dsp,dspr2,dspr3,eva,virt,ginv,crc,mt,mips3d. */
#ifndef ISA_SEL
#define ISA_SEL  ISA_MIPS32R2
#endif
#ifndef ASE_SEL
#define ASE_SEL  (ASE_DSP | ASE_DSPR2 | ASE_DSPR3 | ASE_MSA | ASE_MT | \
                  ASE_EVA | ASE_VIRT | ASE_GINV | ASE_CRC | ASE_MIPS3D)
#endif

static const char *optype_name(enum mips_operand_type t)
{
    switch (t) {
    case OP_INT: return "INT";
    case OP_MAPPED_INT: return "MAPPED_INT";
    case OP_MSB: return "MSB";
    case OP_REG: return "REG";
    case OP_OPTIONAL_REG: return "OPTREG";
    case OP_REG_PAIR: return "REGPAIR";
    case OP_PCREL: return "PCREL";
    case OP_PERF_REG: return "PERF";
    case OP_ADDIUSP_INT: return "ADDIUSP";
    case OP_CLO_CLZ_DEST: return "CLOCLZ";
    case OP_LWM_SWM_LIST: return "LWMLIST";
    case OP_ENTRY_EXIT_LIST: return "EELIST";
    case OP_SAVE_RESTORE_LIST: return "SRLIST";
    case OP_MDMX_IMM_REG: return "MDMXIMM";
    case OP_REPEAT_DEST_REG: return "RPTDEST";
    case OP_REPEAT_PREV_REG: return "RPTPREV";
    case OP_PC: return "PC";
    case OP_REG28: return "GP28";
    case OP_VU0_SUFFIX: return "VU0SUF";
    case OP_VU0_MATCH_SUFFIX: return "VU0MSUF";
    case OP_IMM_INDEX: return "IMMIDX";
    case OP_REG_INDEX: return "REGIDX";
    case OP_SAME_RS_RT: return "SAMERSRT";
    case OP_CHECK_PREV: return "CHKPREV";
    case OP_NON_ZERO_REG: return "NZREG";
    default: return "?";
    }
}

static int is_reg_like(enum mips_operand_type t)
{
    switch (t) {
    case OP_REG: case OP_OPTIONAL_REG: case OP_REG_PAIR:
    case OP_CLO_CLZ_DEST: case OP_REPEAT_DEST_REG: case OP_REPEAT_PREV_REG:
    case OP_SAME_RS_RT: case OP_CHECK_PREV: case OP_NON_ZERO_REG:
    case OP_MDMX_IMM_REG: case OP_REG_INDEX:
        return 1;
    default:
        return 0;
    }
}

static void insert_field(unsigned long *enc, unsigned lsb, unsigned size,
                         unsigned long val)
{
    unsigned long m;
    if (size == 0 || size >= 32) return;
    m = ((1UL << size) - 1UL) << lsb;
    *enc = (*enc & ~m) | ((val << lsb) & m);
}

/* variant: 0 = distinct small registers, 1 = all operand fields zero,
   2 = distinct registers starting higher, 3 = immediates set to 1. */
static int build_enc(const struct mips_opcode *o, int variant,
                     unsigned long *out, char *sig, size_t sigsz)
{
    unsigned long enc = o->match;
    const char *s;
    int nreg = 0, nop = 0;
    size_t sl = 0;
    /* register values handed out in order; index 0 is normally the
       destination, so give it a distinct value from the sources. */
    static const unsigned char regs_a[] = { 4, 5, 6, 7, 8, 9, 10, 11 };
    static const unsigned char regs_b[] = { 12, 13, 14, 15, 16, 17, 18, 19 };
    const unsigned char *regs = (variant == 2) ? regs_b : regs_a;
    unsigned long prev_reg = 0;
    int have_prev = 0;

    sig[0] = 0;
    for (s = o->args; *s; ++s) {
        const struct mips_operand *op;
        unsigned long val = 0;

        if (*s == ',' || *s == '(' || *s == ')') continue;
        if (*s == '#') { ++s; continue; }

        op = decode_mips_operand(s);
        if (!op) return -1;                       /* undecodable args string */

        if (op->size == 0 || op->size >= 32) {
            /* OP_PC / OP_REG28: no encoded field. */
            goto record;
        }

        if (variant == 1) {
            val = 0;
        } else if (is_reg_like(op->type)) {
            switch (op->type) {
            case OP_REPEAT_DEST_REG:
            case OP_REPEAT_PREV_REG:
            case OP_SAME_RS_RT:
            case OP_CHECK_PREV:
                val = have_prev ? prev_reg : regs[0];
                break;
            case OP_CLO_CLZ_DEST:
                /* spans rd and rt; both halves must hold the same reg */
                val = regs[0];
                break;
            default:
                val = regs[nreg % (int)(sizeof regs_a)];
                nreg++;
                break;
            }
            if (op->size < 5) val &= (1UL << op->size) - 1UL;
            if (op->type == OP_NON_ZERO_REG && val == 0) val = 1;
            if (op->type == OP_REG_PAIR) val = 0;   /* pair index, table-mapped */
            prev_reg = val; have_prev = 1;
        } else {
            switch (op->type) {
            case OP_MSB: {
                const struct mips_msb_operand *m =
                    (const struct mips_msb_operand *) op;
                /* keep msb inside range; pick the smallest legal value */
                val = m->add_lsb ? 0 : 0;
                break;
            }
            case OP_MAPPED_INT:
            case OP_PERF_REG:
            case OP_IMM_INDEX:
            case OP_PCREL:
                val = 0;
                break;
            case OP_INT:
                val = (variant == 3) ? 1 : 0;
                break;
            default:
                val = 0;
                break;
            }
        }

        if (op->type == OP_CLO_CLZ_DEST) {
            /* mips-formats.h: OP_CLO_CLZ_DEST occupies rd (11) and rt (16) */
            insert_field(&enc, 11, 5, val);
            insert_field(&enc, 16, 5, val);
        } else {
            insert_field(&enc, op->lsb, op->size, val);
        }

    record:
        if (sl + 16 < sigsz) {
            sl += (size_t) snprintf(sig + sl, sigsz - sl, "%s%s%u@%u",
                                    nop ? "," : "", optype_name(op->type),
                                    op->size, op->lsb);
        }
        nop++;
        if (*s == 'm' || *s == '+' || *s == '-') ++s;
    }
    if (nop == 0) snprintf(sig, sigsz, "-");
    *out = enc & 0xffffffffUL;
    return 0;
}

static void flagstr(char *buf, size_t n, const struct mips_opcode *o)
{
    snprintf(buf, n, "pinfo=0x%lx,pinfo2=0x%lx",
             (unsigned long) o->pinfo, (unsigned long) o->pinfo2);
}

int main(int argc, char **argv)
{
    int variant = 0;
    int only_row = -1;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--variant=", 10)) variant = atoi(argv[i] + 10);
        else if (!strncmp(argv[i], "--row=", 6)) only_row = atoi(argv[i] + 6);
    }

    printf("row\tname\targs\tmatch\tmask\tenc_word\tenc_bytes_le\targsig\talias\tmacro\tmember\tflags\n");
    for (int i = 0; i < bfd_mips_num_opcodes; i++) {
        const struct mips_opcode *o = &mips_opcodes[i];
        unsigned long enc = 0;
        char sig[256], fl[64];
        int macro, member, alias;

        if (only_row >= 0 && i != only_row) continue;
        if (!o->name) continue;
        macro  = (o->pinfo == INSN_MACRO);
        member = opcode_is_member(o, ISA_SEL, ASE_SEL, 0) ? 1 : 0;
        alias  = (o->pinfo2 & INSN2_ALIAS) ? 1 : 0;

        if (macro || !o->args) {
            printf("%d\t%s\t%s\t%08lx\t%08lx\t\t\t-\t%d\t%d\t%d\tMACRO\n",
                   i, o->name, o->args ? o->args : "", (unsigned long) o->match,
                   (unsigned long) o->mask, alias, macro, member);
            continue;
        }
        if (build_enc(o, variant, &enc, sig, sizeof sig) != 0) {
            printf("%d\t%s\t%s\t%08lx\t%08lx\t\t\tBADARGS\t%d\t%d\t%d\tBADARGS\n",
                   i, o->name, o->args, (unsigned long) o->match,
                   (unsigned long) o->mask, alias, macro, member);
            continue;
        }
        flagstr(fl, sizeof fl, o);
        printf("%d\t%s\t%s\t%08lx\t%08lx\t%08lx\t%02lx%02lx%02lx%02lx\t%s\t%d\t%d\t%d\t%s\n",
               i, o->name, o->args, (unsigned long) o->match,
               (unsigned long) o->mask, enc,
               enc & 0xff, (enc >> 8) & 0xff, (enc >> 16) & 0xff, (enc >> 24) & 0xff,
               sig, alias, macro, member, fl);
    }
    return 0;
}
