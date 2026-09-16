/*
 * xl3 -- XED + LLVM MC side-by-side elaborator for x86_64.
 * Emits one TSV row per encoding:  hex \t tool \t ok \t len \t mnem \t SRC \t DST \t MEM
 * Canonicalisation follows the ARC-3 rulings R1-R5 and R7.1:
 *   - registers reported as the largest enclosing architectural register (R4)
 *   - a conditional write implies a preserved-value read (R4/R5): a false
 *     condition leaves the old value in place, so the instruction really does
 *     take the destination as a source
 *   - R7.1-NARROW: a sub-width write does NOT imply a read of the enclosing
 *     register, and a partial flag write does NOT imply a read of RFLAGS
 *
 * R7.1-NARROW is a STANDING RULE, not a deletion.  Both preserve-reads are
 * still DETECTED and counted, and the counts are printed to stderr, so that a
 * reference which starts inventing them again is visible rather than silent.
 * The ruling, verbatim (2026-08-23):
 *
 *   "Things like narrow writes into registers are irrelevant (rename doesn't
 *    care, because it doesn't know the data-width-scope of the next reader).
 *    I know for a fact that during execution we track register-data-width, so
 *    the fact that a register's upper contents may not be modified does not
 *    imply it is a source AND a destination for the instruction unless the
 *    instruction specifically takes it as a source."
 *
 * XED, iced-x86 and LLVM MC all model the HARDWARE bit-preserve.  That is a
 * different question from the one the wire answers -- the wire records the
 * regfile dependency a renaming machine must respect (R7) -- so emitting the
 * preserve-read here was a REFERENCE defect, adjudicated reference-side and
 * corrected here rather than labelled downstream.  A label cannot change set
 * identity, so a labelled row can never leave the disagree column.
 * Author: Maccoy Merrell.
 */
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <set>
#include <vector>
#include <memory>
#include <fstream>
#include <iostream>
#include <algorithm>

extern "C" {
#include "xed/xed-interface.h"
#include "xed/xed-operand-accessors.h"
}

#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/TargetParser/Triple.h"

typedef std::set<std::string> RSet;

static std::string join(const RSet &s){
    std::string o; for (auto &x : s){ if(!o.empty()) o += ","; o += x; } return o.empty()?"-":o;
}
/* Common register vocabulary shared by both tools. */
static std::string norm(std::string n){
    for (auto &c : n) c = (char)toupper((unsigned char)c);
    if (n=="EFLAGS"||n=="FLAGS") n="RFLAGS";
    if (n=="RIP"||n=="EIP"||n=="IP") n="RIP";
    if (n=="FPSW"||n=="FPCW"||n=="FPUSTATUS") n=n;             /* kept distinct */
    if (n.size()>1 && n[0]=='S' && n.substr(0,4)=="SSP") n="SSP";
    if (n.size()>4 && n.compare(0,3,"ST(")==0) n = "ST" + n.substr(3, n.size()-4);
    if (n=="FPSW"||n=="X87STATUS") n="X87STATUS";
    if (n=="FPCW") n="X87CONTROL";
    return n;
}

/* ------------------------------------------------------------------ XED */
static unsigned g_all6 = 0;   /* calibrated mask of CF PF AF ZF SF OF */
/* R7.1-NARROW: preserve-reads DETECTED and SUPPRESSED, per arm.  A count of
 * zero on a whole sweep means the rule stopped reaching its subject and is no
 * longer proving anything -- an inert rule is a finding, not a pass. */
static unsigned long g_sup_narrow_xed = 0, g_sup_flags_xed = 0,
                     g_sup_narrow_llvm = 0, g_sup_scalar_xed = 0,
                     g_sup_scalar_llvm = 0;

/* R7.1-SCALAR -- the same ruling, where XED spells the preserve as an
 * operand ACTION instead of a width.
 *
 * A legacy (non-VEX) scalar SSE form writes only the low element and leaves
 * the rest of the register alone, and XED's datafiles record that by
 * declaring the destination `REG0=XMM_R():rw`.  For SQRTSD the `r` half of
 * that is PURELY the surviving upper lanes; for ADDSD it is also the first
 * addend.  XED's declaration is byte-identical in the two cases -- compare
 * xed-isa.txt, where SQRTSD and ADDSD both read
 *     OPERANDS : REG0=XMM_R():rw:sd MEM0:r:sd
 * -- so the elaborator has to be told which operations are UNARY.  iced-x86
 * and LLVM MC carry the same conflation (LLVM picks the `_Int` opcode, whose
 * destination is tied), so no reference can adjudicate this one.
 *
 * THE SCOPE IS DERIVED FROM THE WHOLE CLASS, NOT FROM THE ROWS THAT
 * DISAGREED.  Enumerating xed-isa.txt for every legacy pattern declaring
 * `REG0=XMM_R():rw` under the simd_scalar attribute yields exactly 24
 * iclasses:
 *   ADDSD ADDSS CMPSD_XMM CMPSS CVTSD2SS CVTSI2SD CVTSI2SS CVTSS2SD DIVSD
 *   DIVSS MAXSD MAXSS MINSD MINSS MULSD MULSS RCPSS ROUNDSD ROUNDSS RSQRTSS
 *   SQRTSD SQRTSS SUBSD SUBSS
 * Ten of them compute the destination from their other operands alone
 * (SDM: "DEST[63:0] <- CONVERT/SQRT/ROUND(SRC); DEST[127:64] unmodified");
 * the other fourteen take the destination as an operand of the operation.
 * The ten are listed below; the fourteen are deliberately NOT, and that
 * split is the whole content of the rule.
 *
 * ROUNDSD and ROUNDSS are in the list although no row currently disagrees on
 * them: scope follows the class.  If the tracer names their destination as a
 * source, the rule is what makes that visible instead of cancelling out. */
static bool r71_scalar_unary(const char* ic){
    static const char* U[] = {"CVTSD2SS","CVTSI2SD","CVTSI2SS","CVTSS2SD",
                              "RCPSS","ROUNDSD","ROUNDSS","RSQRTSS",
                              "SQRTSD","SQRTSS"};
    for (auto u : U) if (!strcmp(ic,u)) return true;
    return false;
}

static void xed_calibrate(void){
    /* 4801d8 = add %rbx,%rax : writes all six status flags. */
    xed_uint8_t b[3] = {0x48,0x01,0xd8};
    xed_decoded_inst_t d; xed_decoded_inst_zero(&d);
    xed_decoded_inst_set_mode(&d, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    if (xed_decode(&d,b,3)==XED_ERROR_NONE){
        const xed_simple_flag_t* fi = xed_decoded_inst_get_rflags_info(&d);
        if (fi) g_all6 = xed_flag_set_mask(xed_simple_flag_get_written_flag_set(fi));
    }
}

/* WHY is RFLAGS a source?  With the preserve-reads gone, an RFLAGS source
 * that survives is a REAL edge, and the roll-up downstream must be able to
 * say WHICH real edge rather than guessing from the signature shape:
 *   FR  the instruction tests named flag bits (cmc tests CF, rcl/rcr rotate
 *       through it, in/out gate on IOPL)
 *   OR  an explicit RFLAGS operand XED marks read or read-modify (popf)
 *   CW  R4: the flag write is CONDITIONAL, so the old value really does
 *       flow through when the condition is false (shl/shr/rol by CL==0)
 * Empty when RFLAGS is not a source at all. */
static bool xed_elab(const uint8_t*b, unsigned n, std::string&mnem, unsigned&len,
                     RSet&src, RSet&dst, std::string&mem, std::string&flagwhy)
{
    xed_decoded_inst_t d; xed_decoded_inst_zero(&d);
    xed_decoded_inst_set_mode(&d, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    xed3_operand_set_cet(&d, 1);                      /* ENDBR64 needs this */
    /* XED decodes 0F 1A / 0F 1B as a reserved NOP unless MPX decoding is
     * switched on, and its default is off.  The guest under measurement has
     * MPX: QEMU implements the whole extension in TCG -- cpu_bndl[4] /
     * cpu_bndu[4] are TCG globals over CPUX86State.bnd_regs, translate.c
     * case 0x11a / 0x11b emit real BNDCL / BNDCU / BNDCN / BNDMK / BNDMOV /
     * BNDLDX / BNDSTX code under HF_MPX_EN_MASK, and CPUID_7_0_EBX_MPX is
     * inside TCG_7_0_EBX_FEATURES (target/i386/cpu.c).  Leaving mpxmode at 0
     * compares the tracer against a machine the guest is not, and charges
     * the bound-register dependency QEMU really has to the tracer as a
     * phantom.  This is the same shape as the `cet` line above. */
    xed3_operand_set_mpxmode(&d, 1);
    if (xed_decode(&d,b,n)!=XED_ERROR_NONE) return false;
    len = xed_decoded_inst_get_length(&d);
    mnem = xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&d));
    bool vex_zeroing = xed_classify_avx(&d) || xed_classify_avx512(&d);
    /* R7.1-SCALAR applies to the LEGACY encodings only -- the VEX and EVEX
     * forms name their merge donor as a separate operand and XED declares
     * their destination write-only, so there is nothing to suppress. */
    bool scalar_unary = !vex_zeroing && r71_scalar_unary(mnem.c_str());
    const xed_inst_t* xi = xed_decoded_inst_inst(&d);
    unsigned no = xed_inst_noperands(xi);
    for (unsigned i=0;i<no;i++){
        const xed_operand_t* op = xed_inst_operand(xi,i);
        xed_operand_enum_t nm = xed_operand_name(op);
        xed_operand_action_enum_t a = xed_decoded_inst_operand_action(&d,i);
        bool isreg = xed_operand_is_register(nm) || xed_operand_is_memory_addressing_register(nm);
        if (!isreg) continue;
        xed_reg_enum_t r = xed_decoded_inst_get_reg(&d,nm);
        if (r==XED_REG_INVALID) continue;
        xed_reg_enum_t e = xed_get_largest_enclosing_register(r);
        std::string cn = norm(xed_reg_enum_t2str(e));
        bool rd=false, wr=false, cw=false;
        bool suppress_rd = false;
        switch(a){
        case XED_OPERAND_ACTION_R:   rd=true; break;
        case XED_OPERAND_ACTION_W:   wr=true; break;
        case XED_OPERAND_ACTION_RW:  rd=wr=true; break;
        case XED_OPERAND_ACTION_RCW: rd=wr=true; cw=true; break;
        case XED_OPERAND_ACTION_CW:  wr=true; cw=true; break;
        case XED_OPERAND_ACTION_CRW: rd=wr=true; break;
        case XED_OPERAND_ACTION_CR:  rd=true; break;
        default: break;
        }
        if (scalar_unary && i==0 && a==XED_OPERAND_ACTION_RW){
            suppress_rd = true; rd = false; g_sup_scalar_xed++;
        }
        (void)suppress_rd;
        if (rd){ src.insert(cn); if (cn=="RFLAGS") flagwhy += flagwhy.empty()?"OR":",OR"; }
        if (wr) dst.insert(cn);
        if (cw){ src.insert(cn);                       /* R4 */
                 if (cn=="RFLAGS") flagwhy += flagwhy.empty()?"CW":",CW"; }
        if (wr && cn!="RFLAGS"){
            unsigned ob = xed_decoded_inst_operand_length_bits(&d,i);
            unsigned eb = xed_get_register_width_bits64(e);
            bool gpr32_zx = (ob==32 && eb==64 &&
                             xed_reg_class(r)==XED_REG_CLASS_GPR);
            bool vec = (xed_reg_class(e)==XED_REG_CLASS_XMM ||
                        xed_reg_class(e)==XED_REG_CLASS_YMM ||
                        xed_reg_class(e)==XED_REG_CLASS_ZMM);
            /* VEX/EVEX writes zero the bits above the written width; legacy
             * SSE writes preserve them.  Only the latter implies a read. */
            bool zx = gpr32_zx || (vec && vex_zeroing);
            /* R7.1-NARROW: the upper bits survive, and that is not a source.
             * `setz %al`, `mov %dl,%al`, legacy `aesimc` writing 128 of 512 --
             * none of them TAKES the enclosing register as an input. */
            if (ob && ob<eb && !zx) g_sup_narrow_xed++;
        }
    }
    unsigned nm2 = xed_decoded_inst_number_of_memory_operands(&d);
    char mb[256]; mb[0]=0;
    for (unsigned m=0;m<nm2;m++){
        xed_reg_enum_t br = xed_decoded_inst_get_base_reg(&d,m);
        xed_reg_enum_t ir = xed_decoded_inst_get_index_reg(&d,m);
        xed_reg_enum_t sr = xed_decoded_inst_get_seg_reg(&d,m);
        if (br!=XED_REG_INVALID) src.insert(norm(xed_reg_enum_t2str(xed_get_largest_enclosing_register(br))));
        if (ir!=XED_REG_INVALID) src.insert(norm(xed_reg_enum_t2str(xed_get_largest_enclosing_register(ir))));
        if (sr!=XED_REG_INVALID) src.insert(norm(xed_reg_enum_t2str(sr)));
        char one[64];
        snprintf(one,sizeof one,"%s%c%c%u", m?";":"",
                 xed_decoded_inst_mem_read(&d,m)?'R':'-',
                 xed_decoded_inst_mem_written(&d,m)?'W':'-',
                 xed_decoded_inst_get_memory_operand_length(&d,m));
        strncat(mb,one,sizeof(mb)-strlen(mb)-1);
    }
    mem = mb[0]?mb:"-";
    const xed_simple_flag_t* fi = xed_decoded_inst_get_rflags_info(&d);
    if (fi){
        /* XED reports the x87 condition codes fc0..fc3 through the SAME
         * simple-flag channel as RFLAGS.  Folding them into RFLAGS would
         * invent an RFLAGS dependency on every x87 instruction. */
        bool x87cc = false;
        unsigned nf = xed_simple_flag_get_nflags(fi);
        for (unsigned f=0; f<nf; f++){
            const char* fn = xed_flag_enum_t2str(
                xed_flag_action_get_flag_name(xed_simple_flag_get_flag_action(fi,f)));
            if (fn && fn[0]=='f' && fn[1]=='c'){ x87cc = true; break; }
        }
        unsigned rdm = x87cc?0:xed_flag_set_mask(xed_simple_flag_get_read_flag_set(fi));
        unsigned wrm = x87cc?0:xed_flag_set_mask(xed_simple_flag_get_written_flag_set(fi));
        unsigned um  = x87cc?0:xed_flag_set_mask(xed_simple_flag_get_undefined_flag_set(fi));
        if (rdm){ src.insert("RFLAGS"); flagwhy += flagwhy.empty()?"FR":",FR"; }
        if (wrm|um) dst.insert("RFLAGS");
        /* R7.1-NARROW, flag bank: the same argument.  `inc` leaves CF alone
         * and `stc` writes one bit; neither reads RFLAGS to do it. */
        if ((wrm|um) && ((wrm|um) & g_all6) != g_all6) g_sup_flags_xed++;
    }
    return true;
}

/* ----------------------------------------------------------------- LLVM */
static std::unique_ptr<llvm::MCSubtargetInfo> STI;
static std::unique_ptr<llvm::MCRegisterInfo>  MRI;
static std::unique_ptr<llvm::MCAsmInfo>       MAI;
static std::unique_ptr<llvm::MCContext>       CTX;
static std::unique_ptr<llvm::MCDisassembler>  DIS;
static std::unique_ptr<llvm::MCInstrInfo>     MII;

static std::string ll_enclosing(llvm::MCPhysReg r, bool &sub){
    llvm::MCPhysReg top = r;
    for (llvm::MCPhysReg s : MRI->superregs(r)) if (MRI->getName(s)) top = s;
    sub = (top != r);
    return norm(MRI->getName(top));
}

/* R7.1-SCALAR for LLVM MC.  LLVM disassembles these to the `_Int` opcodes,
 * whose destination is TIED to the first source -- the same conflation XED
 * has, spelled as a tied operand.  The names are the ten iclasses above with
 * LLVM's r/m/rr/rm/ri suffixes, and never the V-prefixed VEX/EVEX forms. */
static bool ll_scalar_unary(const std::string &m){
    static const char* U[] = {"CVTSD2SS","CVTSI2SD","CVTSI2SS","CVTSS2SD",
                              "RCPSS","ROUNDSD","ROUNDSS","RSQRTSS",
                              "SQRTSD","SQRTSS"};
    if (!m.empty() && m[0]=='V') return false;
    for (auto u : U){ size_t L = strlen(u);
        if (m.size()>L && m.compare(0,L,u)==0 &&
            (m[L]=='r' || m[L]=='m')) return true; }
    return false;
}

static bool ll_elab(const uint8_t*b, unsigned n, std::string&mnem, unsigned&len,
                    RSet&src, RSet&dst, std::string&mem)
{
    llvm::MCInst I; uint64_t sz=0;
    if (DIS->getInstruction(I,sz,llvm::ArrayRef<uint8_t>(b,n),0x100000,llvm::nulls())
        != llvm::MCDisassembler::Success) return false;
    len = (unsigned)sz;
    const llvm::MCInstrDesc &D = MII->get(I.getOpcode());
    mnem = MII->getName(I.getOpcode()).str();
    unsigned nd = D.getNumDefs();
    for (unsigned i=0;i<I.getNumOperands();i++){
        const llvm::MCOperand &O = I.getOperand(i);
        if (!O.isReg() || O.getReg()==0) continue;
        bool sub=false;
        std::string cn = ll_enclosing(O.getReg(), sub);
        const char *rn = MRI->getName(O.getReg());
        bool gpr32 = rn && ((rn[0]=='E') ||
                            (rn[0]=='R' && strlen(rn)>=3 && rn[strlen(rn)-1]=='D'));
        /* VEX/EVEX-encoded writes zero the bits above the written width.
         * LLVM's MC layer exposes no encoding-kind bit here, so the VEX
         * mnemonic prefix is the available discriminator. */
        bool vecz = (mnem.size() && mnem[0]=='V') &&
                    (cn.compare(0,3,"ZMM")==0 || cn.compare(0,3,"YMM")==0 ||
                     cn.compare(0,3,"XMM")==0);
        if (vecz) sub = false;
        int tied = (i<D.getNumOperands())
                     ? D.getOperandConstraint(i, llvm::MCOI::TIED_TO) : -1;
        if (i<nd){
            dst.insert(cn);
            if (tied!=-1){
                if (ll_scalar_unary(mnem)) g_sup_scalar_llvm++;   /* R7.1 */
                else src.insert(cn);
            }
            if (sub && !gpr32 && cn!="RFLAGS") g_sup_narrow_llvm++;  /* R7.1 */
        } else {
            /* an operand TIED to the destination of a unary scalar form is
             * the merge donor, not an input (R7.1-SCALAR) */
            if (tied!=-1 && ll_scalar_unary(mnem)) g_sup_scalar_llvm++;
            else src.insert(cn);
            if (tied!=-1){
                dst.insert(cn);
                if (sub && !gpr32 && cn!="RFLAGS") g_sup_narrow_llvm++;  /* R7.1 */
            }
        }
    }
    for (llvm::MCPhysReg r : D.implicit_defs()){ bool s2; dst.insert(ll_enclosing(r,s2)); }
    for (llvm::MCPhysReg r : D.implicit_uses()){ bool s2; src.insert(ll_enclosing(r,s2)); }
    char mb[32];
    snprintf(mb,sizeof mb,"%c%c?", D.mayLoad()?'R':'-', D.mayStore()?'W':'-');
    mem = (D.mayLoad()||D.mayStore()) ? mb : "-";
    return true;
}

/* ----------------------------------------------------------------- main */
static int hexnib(char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}

int main(int argc, char**argv)
{
    if (argc<2){ fprintf(stderr,"usage: xl3 <hexlist-file>\n"); return 2; }
    fprintf(stderr,"[t0]\n");
    xed_tables_init(); fprintf(stderr,"[t1 xed_tables_init]\n"); xed_calibrate(); fprintf(stderr,"[t2 calibrate all6=%u]\n", g_all6);
    fprintf(stderr,"[t3 llvm init]\n");
    LLVMInitializeX86TargetInfo(); LLVMInitializeX86TargetMC();
    LLVMInitializeX86Disassembler(); LLVMInitializeX86AsmPrinter();
    std::string triple="x86_64-unknown-linux-gnu", err;
    const llvm::Target* T = llvm::TargetRegistry::lookupTarget(triple, err);
    if(!T){ fprintf(stderr,"no target\n"); return 1; }
    llvm::Triple TT(triple);
    const char* feat = getenv("PROBE_FEAT") ? getenv("PROBE_FEAT") : "";
    STI.reset(T->createMCSubtargetInfo(triple, "x86-64", feat));
    MRI.reset(T->createMCRegInfo(triple));
    llvm::MCTargetOptions opt;
    MAI.reset(T->createMCAsmInfo(*MRI, triple, opt));
    CTX.reset(new llvm::MCContext(TT, MAI.get(), MRI.get(), STI.get()));
    DIS.reset(T->createMCDisassembler(*STI,*CTX));
    MII.reset(T->createMCInstrInfo());
    fprintf(stderr,"[t4 mc ready]\n");

    std::ifstream in(argv[1]);
    std::string line;
    printf("hex\ttool\tok\tlen\tmnem\tsrc\tdst\tmem\tflagwhy\n");
    while (std::getline(in,line)){
        while(!line.empty() && (line.back()=='\n'||line.back()=='\r')) line.pop_back();
        if(line.empty()) continue;
        uint8_t buf[32]; unsigned n=0;
        for (size_t i=0;i+1<line.size() && n<32;i+=2){
            int hi=hexnib(line[i]), lo=hexnib(line[i+1]);
            if(hi<0||lo<0) break;
            buf[n++]=(uint8_t)((hi<<4)|lo);
        }
        if(!n) continue;
        { std::string m,mm,fw; unsigned L=0; RSet s,d;
          bool ok = xed_elab(buf,n,m,L,s,d,mm,fw);
          printf("%s\tXED\t%d\t%u\t%s\t%s\t%s\t%s\t%s\n", line.c_str(), ok?1:0, L,
                 ok?m.c_str():"-", ok?join(s).c_str():"-", ok?join(d).c_str():"-",
                 ok?mm.c_str():"-", (ok&&!fw.empty())?fw.c_str():"-"); }
        { std::string m,mm; unsigned L=0; RSet s,d;
          bool ok = ll_elab(buf,n,m,L,s,d,mm);
          printf("%s\tLLVM\t%d\t%u\t%s\t%s\t%s\t%s\t-\n", line.c_str(), ok?1:0, L,
                 ok?m.c_str():"-", ok?join(s).c_str():"-", ok?join(d).c_str():"-",
                 ok?mm.c_str():"-"); }
    }
    fprintf(stderr, "[R7.1-NARROW suppressed preserve-reads] "
                    "xed-subwidth=%lu xed-partialflag=%lu llvm-subwidth=%lu "
                    "xed-scalarunary=%lu llvm-scalarunary=%lu\n",
            g_sup_narrow_xed, g_sup_flags_xed, g_sup_narrow_llvm,
            g_sup_scalar_xed, g_sup_scalar_llvm);
    return 0;
}
