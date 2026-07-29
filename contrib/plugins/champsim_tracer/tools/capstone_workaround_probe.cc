/*
 * capstone_workaround_probe — retest harness for the Capstone access-flag
 * / operand-modelling workarounds in disas/capstone.c.
 *
 * Every workaround in disas/capstone.c exists because Capstone
 * 6.0.0-Alpha7 (subprojects/capstone.wrap) reports incorrect or missing
 * per-operand access/detail for a specific, narrow set of encodings. This
 * tool is the runnable half of the retirement procedure documented in
 * docs/troubleshooting.rst ("Retiring a Capstone workaround"): each entry
 * below re-derives the minimal repro bytes cited in the matching
 * disas/capstone.c comment, decodes them with cs_disasm() against
 * whatever Capstone this binary was linked against, and reports one of:
 *
 *   STILL NEEDED    the documented defect is still present -- keep the
 *                   workaround.
 *   RETIRE CANDIDATE  Capstone now reports this case correctly -- the
 *                   matching disas/capstone.c predicate is dead code for
 *                   this encoding and can be removed (after confirming
 *                   every entry for its family also flips).
 *   INCONCLUSIVE    the case failed to decode at all; the repro bytes may
 *                   need updating for the new Capstone before this entry
 *                   is trustworthy.
 *
 * This binary always links subprojects/capstone (see meson.build: same
 * cst_capstone_dep as cst_decode), never a system libcapstone -- the
 * defects are version-specific and a host's package-manager Capstone is
 * routinely a different major release (verified during authoring: this
 * host's /usr/bin/cstool is v5.0.1, which cannot reproduce any of these
 * Alpha7 defects and cannot be used to "manually verify" the cstool
 * one-liners in the disas/capstone.c comments either -- build cstool from
 * subprojects/capstone, or just run this tool, whenever a comment says to
 * "verify with cstool").
 *
 * To retest against a new Capstone: bump subprojects/capstone.wrap,
 * reconfigure, `ninja -C build contrib-plugins`, then run
 * `build/contrib/plugins/capstone_workaround_probe`. A workaround whose
 * entry flips to RETIRE CANDIDATE is safe to delete from disas/capstone.c
 * -- delete the predicate function, its call site(s), and this file's
 * matching entry in the same change.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#define CAPSTONE_AARCH64_COMPAT_HEADER
#define CAPSTONE_SYSTEMZ_COMPAT_HEADER
#include <capstone/capstone.h>

namespace {

enum class Verdict { kStillNeeded, kRetireCandidate, kInconclusive };

const char *VerdictStr(Verdict v)
{
    switch (v) {
    case Verdict::kStillNeeded:     return "STILL NEEDED   ";
    case Verdict::kRetireCandidate: return "RETIRE CANDIDATE";
    case Verdict::kInconclusive:    return "INCONCLUSIVE    ";
    }
    return "?";
}

/* One workaround case: decode `bytes` for `arch`/`mode` and hand the
 * resulting cs_insn to `check`, which returns true while the documented
 * defect is still observed (i.e. the disas/capstone.c workaround is
 * still needed). */
struct Case {
    const char *id;              /* matches the disas/capstone.c predicate name */
    const char *capstone_c_site; /* function name to grep for */
    const char *targets;         /* "6.0.0-Alpha7" or similar, from the comment */
    const char *description;
    cs_arch arch;
    cs_mode mode;
    std::vector<uint8_t> bytes;
    bool (*check)(const cs_insn &insn);
};

uint8_t OpAccess_x86(const cs_insn &insn, unsigned idx)
{
    return insn.detail->x86.operands[idx].access;
}
uint8_t OpAccess_a64(const cs_insn &insn, unsigned idx)
{
    return insn.detail->arm64.operands[idx].access;
}
uint8_t OpAccess_mips(const cs_insn &insn, unsigned idx)
{
    return insn.detail->mips.operands[idx].access;
}

bool StillBuggy_PextrStore(const cs_insn &insn)
{
    /* PEXTRD $1, %xmm0, (%rax): MEM (operand 2) must be WRITE. Bug: READ. */
    return !(OpAccess_x86(insn, 2) & CS_AC_WRITE);
}
bool StillBuggy_MoveStore(const cs_insn &insn)
{
    /* VMOVDQA %ymm0, (%rax): no operand should carry WRITE at all is the
     * bug signature (a real load always leaves one operand WRITE). */
    for (uint8_t i = 0; i < insn.detail->x86.op_count; i++) {
        if (OpAccess_x86(insn, i) & CS_AC_WRITE) {
            return false;
        }
    }
    return true;
}
bool StillBuggy_VexLaneExtractStore(const cs_insn &insn)
{
    /* vextractf128 $1,%ymm0,(%rax): MEM (operand 2) is the r/m
     * DESTINATION and must be WRITE. Bug: READ. */
    return !(OpAccess_x86(insn, 2) & CS_AC_WRITE);
}
bool StillBuggy_Cvtps2phStore(const cs_insn &insn)
{
    /* vcvtps2ph $0,%ymm0,(%rax): MEM (operand 2) is the r/m DESTINATION
     * and must be WRITE. Bug: READ.  Its load counterpart VCVTPH2PS is
     * reported correctly, which is why the workaround matches this
     * spelling exactly rather than a `cvt` family. */
    return !(OpAccess_x86(insn, 2) & CS_AC_WRITE);
}
bool StillBuggy_MaskMovStore(const cs_insn &insn)
{
    /* vmaskmovps %xmm0,%xmm0,(%rax) is the STORE form (0F38 2E); the
     * load form (2C) prints identically.  Bug signature is the same as
     * the MOV family's: no operand carries WRITE at all, where the load
     * form leaves its destination register WRITE. */
    for (uint8_t i = 0; i < insn.detail->x86.op_count; i++) {
        if (OpAccess_x86(insn, i) & CS_AC_WRITE) {
            return false;
        }
    }
    return true;
}
bool StillBuggy_KmovStore(const cs_insn &insn)
{
    /* kmovw %k0,(%rax) is the STORE form (0F 91); the load form (0F 90)
     * prints identically and does mark its %k destination WRITE. */
    for (uint8_t i = 0; i < insn.detail->x86.op_count; i++) {
        if (OpAccess_x86(insn, i) & CS_AC_WRITE) {
            return false;
        }
    }
    return true;
}
bool StillBuggy_BroadcastI128Erased(const cs_insn &insn)
{
    /* vbroadcasti128 (%rax),%ymm0: MEM (operand 0) must be READ and the
     * register (operand 1) WRITE. Bug: both access == 0.  The f128 twin
     * one opcode byte away is correct, so this checks the erasure, not
     * a family convention. */
    return OpAccess_x86(insn, 0) == 0 && OpAccess_x86(insn, 1) == 0;
}
bool StillBuggy_TestA9_32(const cs_insn &insn)
{
    /* testl $0x200000,%eax: operand 1 (%eax) must be plain READ. Bug: RW. */
    return OpAccess_x86(insn, 1) == (CS_AC_READ | CS_AC_WRITE);
}
bool StillBuggy_StosInverted(const cs_insn &insn)
{
    /* rep stosq %rax,(%rdi): MEM must be WRITE. Bug: READ. */
    return !(OpAccess_x86(insn, 0) & CS_AC_WRITE);
}
bool StillBuggy_CmpslLost(const cs_insn &insn)
{
    /* cmpsl (%rdi),(%rsi), 32-bit form only: both MEM operands must be
     * READ. Bug: both access == 0. */
    return OpAccess_x86(insn, 0) == 0 && OpAccess_x86(insn, 1) == 0;
}
bool StillBuggy_InsbLost(const cs_insn &insn)
{
    /* insb %dx,(%rdi): MEM (operand 1) must be WRITE. Bug: access == 0. */
    return OpAccess_x86(insn, 1) == 0;
}
bool StillBuggy_InslLostBoth(const cs_insn &insn)
{
    /* insl %dx,(%rdi): 32-bit form additionally drops READ on %dx. */
    return OpAccess_x86(insn, 0) == 0 && OpAccess_x86(insn, 1) == 0;
}
bool StillBuggy_ScalarRound(const cs_insn &insn)
{
    /* roundss $1,(%rip),%xmm1: MEM (operand 1) must be READ. Bug: 0. */
    return OpAccess_x86(insn, 1) == 0;
}
bool StillBuggy_ShadowStackStore(const cs_insn &insn)
{
    /* wrssd %ecx,(%rip): both operands access == 0. */
    return OpAccess_x86(insn, 0) == 0 && OpAccess_x86(insn, 1) == 0;
}
bool StillBuggy_NopPhantomRead(const cs_insn &insn)
{
    /* 66 0f 1f 44 00 00 (multi-byte NOP): MEM must show NO access.
     * Bug: phantom READ. */
    return OpAccess_x86(insn, 0) & CS_AC_READ;
}
bool StillBuggy_PushSeg(const cs_insn &insn)
{
    /* pushq %fs: operand must be READ. Bug: access == 0. */
    return OpAccess_x86(insn, 0) == 0;
}
bool StillBuggy_SwpMemAccess(const cs_insn &insn)
{
    /* swp w1,w0,[x2]: the MEM operand (index 2) must carry
     * READ|WRITE (it's the LSE atomic-swap family). Bug: access == 0. */
    return OpAccess_a64(insn, 2) == 0;
}
bool StillBuggy_ShiftImmAliasDropsImm(const cs_insn &insn)
{
    /* lsl w0,w1,#3: the true alias is 3-operand (Rd,Rn,#imm). Bug:
     * Capstone drops the IMM operand, so op_count == 2. */
    return insn.detail->arm64.op_count == 2;
}
bool StillBuggy_MipsMsaMemAccess(const cs_insn &insn)
{
    /* ld.b $w0,0($a0): the MEM operand (index 1) must be READ.
     * Bug: access == 0. */
    return OpAccess_mips(insn, 1) == 0;
}
bool StillBuggy_MipsUnalignedMemAccess(const cs_insn &insn)
{
    /* lwl $t0,3($a0): the MEM operand (index 1) must be READ.
     * Bug: access == 0. Same predicate as the MSA case above --
     * cap_fill_mips_operands infers both from one 0-access rule. */
    return OpAccess_mips(insn, 1) == 0;
}
bool StillBuggy_MipsLwlPartialWrite(const cs_insn &insn)
{
    /* lwl $t0,3($a0): $t0 (index 0) is a partial write, so the old
     * value is also an input. Bug: Capstone reports WRITE only. */
    return OpAccess_mips(insn, 0) == CS_AC_WRITE;
}
bool StillBuggy_MipsScPartialRead(const cs_insn &insn)
{
    /* sc $t0,0($a0): $t0 (index 0) is overwritten with the
     * success/failure bit after being read as the store source.
     * Bug: Capstone reports READ only. */
    return OpAccess_mips(insn, 0) == CS_AC_READ;
}

const std::vector<Case> &Cases()
{
    static const std::vector<Case> cases = {
        {"cap_x86_is_extract_store", "cap_fill_x86_operands", "6.0.0-Alpha7",
         "PEXTRD store form: MEM destination reported READ, not WRITE",
         CS_ARCH_X86, CS_MODE_64, {0x66, 0x0f, 0x3a, 0x16, 0x00, 0x01},
         StillBuggy_PextrStore},
        {"cap_x86_is_extract_store (VEXTRACTF128)", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "VEX lane extract to memory: MEM destination "
         "reported READ, not WRITE",
         CS_ARCH_X86, CS_MODE_64, {0xc4, 0xe3, 0x7d, 0x19, 0x00, 0x01},
         StillBuggy_VexLaneExtractStore},
        {"cap_x86_is_extract_store (VCVTPS2PH)", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "F16C down-convert to memory: r/m destination "
         "reported READ, not WRITE (VCVTPH2PS load form is correct)",
         CS_ARCH_X86, CS_MODE_64, {0xc4, 0xe3, 0x7d, 0x1d, 0x00, 0x00},
         StillBuggy_Cvtps2phStore},
        {"cap_x86_is_move_family", "cap_fill_x86_operands", "6.0.0",
         "VMOVDQA store form: no operand carries WRITE at all",
         CS_ARCH_X86, CS_MODE_64, {0xc5, 0xfd, 0x7f, 0x00},
         StillBuggy_MoveStore},
        {"cap_x86_is_move_family (VMASKMOVPS store)",
         "cap_fill_x86_operands", "6.0.0-Alpha7",
         "AVX masked store (0F38 2E): no operand carries WRITE at all, "
         "where the identically-printed load form (2C) marks its "
         "destination register WRITE",
         CS_ARCH_X86, CS_MODE_64, {0xc4, 0xe2, 0x79, 0x2e, 0x00},
         StillBuggy_MaskMovStore},
        {"cap_x86_is_move_family (KMOVW store)", "cap_fill_x86_operands",
         "6.0.0-Alpha7",
         "AVX-512 mask store (0F 91): no operand carries WRITE at all, "
         "where the identically-printed load form (0F 90) marks its %k "
         "destination WRITE.  Decode-only: QEMU's i386 TCG front end "
         "implements no EVEX, so this never reaches a trace",
         CS_ARCH_X86, CS_MODE_64, {0xc5, 0xf8, 0x91, 0x00},
         StillBuggy_KmovStore},
        {"cap_x86_is_erased_mem_load", "cap_fill_x86_operands",
         "6.0.0-Alpha7",
         "VBROADCASTI128: access == 0 on BOTH operands, erasing the "
         "memory source (VBROADCASTF128, one opcode byte away, is "
         "reported correctly)",
         CS_ARCH_X86, CS_MODE_64, {0xc4, 0xe2, 0x7d, 0x5a, 0x00},
         StillBuggy_BroadcastI128Erased},
        {"cap_x86_is_test (phantom write)", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "TEST opcode A9, 32-bit operand size: %eax "
         "reported READ|WRITE instead of plain READ",
         CS_ARCH_X86, CS_MODE_64, {0xa9, 0x00, 0x00, 0x20, 0x00},
         StillBuggy_TestA9_32},
        {"cap_x86_string_mem_access (STOS)", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "STOS: (%rdi) destination reported READ, not WRITE",
         CS_ARCH_X86, CS_MODE_64, {0xf3, 0x48, 0xab},
         StillBuggy_StosInverted},
        {"cap_x86_string_mem_access (CMPSL)", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "CMPS opcode A7, 32-bit operand size only: both "
         "MEM operands access == 0",
         CS_ARCH_X86, CS_MODE_64, {0xa7},
         StillBuggy_CmpslLost},
        {"cap_x86_string_mem_access (INSB)", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "INS, every operand size: MEM operand access == 0",
         CS_ARCH_X86, CS_MODE_64, {0x6c},
         StillBuggy_InsbLost},
        {"cap_x86_string_mem_access (INSL)", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "INS 32-bit form additionally drops READ on %dx",
         CS_ARCH_X86, CS_MODE_64, {0x6d},
         StillBuggy_InslLostBoth},
        {"cap_x86_is_scalar_round", "cap_fill_x86_operands", "6.0.0-Alpha7",
         "Scalar ROUNDSS/ROUNDSD MEM source access == 0 (packed forms "
         "correct)",
         CS_ARCH_X86, CS_MODE_64,
         {0x66, 0x0f, 0x3a, 0x0a, 0x0d, 0, 0, 0, 0, 0x01},
         StillBuggy_ScalarRound},
        {"cap_x86_is_shadow_stack_store", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "WRSS/WRUSS: both operands access == 0",
         CS_ARCH_X86, CS_MODE_64, {0x0f, 0x38, 0xf6, 0x0d, 0, 0, 0, 0},
         StillBuggy_ShadowStackStore},
        {"cap_x86_mem_is_never_accessed", "cap_fill_x86_operands",
         "6.0.0-Alpha7", "Multi-byte NOP (0F 1F): MEM operand reported "
         "READ though the insn never touches memory",
         CS_ARCH_X86, CS_MODE_64, {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
         StillBuggy_NopPhantomRead},
        {"cap_x86_is_push", "cap_fill_x86_operands", "6.0.0-Alpha7",
         "PUSH %fs/%gs: operand access == 0",
         CS_ARCH_X86, CS_MODE_64, {0x0f, 0xa0},
         StillBuggy_PushSeg},
        {"cap_aarch64_infer_mem_access (SWP)", "cap_fill_arm64_operands",
         "6.0.0-Alpha7 (SWP rows only)",
         "LSE SWP family: MEM operand access == 0 (register-offset "
         "load/store forms of this same bug were already fixed upstream "
         "in 6.0.0-Alpha8, commit e5c6e09 / #2802; SWP rows are still "
         "open as of capstone master 857e556, 2026-07)",
         CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
         {0x40, 0x80, 0x21, 0xb8},
         StillBuggy_SwpMemAccess},
        {"cap_aarch64_is_buggy_shift_imm_alias", "cap_fill_arm64_operands",
         "6.0.0", "LSL/LSR/ASR/ROR #imm alias of UBFM/SBFM/EXTR: the IMM "
         "operand is dropped from the structured array (op_count 2, not 3)",
         CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
         {0x20, 0x70, 0x1d, 0x53},
         StillBuggy_ShiftImmAliasDropsImm},
        {"cap_fill_mips_operands (MSA access==0)", "cap_fill_mips_operands",
         "6.0.0", "MSA vector LD.B/H/W/D: MEM operand access == 0",
         CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN),
         {0x20, 0x20, 0x00, 0x78},
         StillBuggy_MipsMsaMemAccess},
        {"cap_fill_mips_operands (unaligned access==0)",
         "cap_fill_mips_operands", "6.0.0",
         "Unaligned scalar LWL/LWR/LDL/LDR/SWL/SWR/SDL/SDR: MEM operand "
         "access == 0",
         CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN),
         {0x03, 0x00, 0x88, 0x88},
         StillBuggy_MipsUnalignedMemAccess},
        {"cap_fill_mips_operands (LWL/LWR partial write)",
         "cap_fill_mips_operands", "6.0.0",
         "LWL/LWR/LDL/LDR: $rt reported WRITE-only; the pre-existing "
         "value is also an input (partial merge)",
         CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN),
         {0x03, 0x00, 0x88, 0x88},
         StillBuggy_MipsLwlPartialWrite},
        {"cap_fill_mips_operands (SC success-bit write)",
         "cap_fill_mips_operands", "6.0.0",
         "SC/SCD/SCE/SCWP: $rt reported READ-only; misses the "
         "success/failure write-back",
         CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN),
         {0x00, 0x00, 0x88, 0xe0},
         StillBuggy_MipsScPartialRead},
    };
    return cases;
}

Verdict RunCase(const Case &c)
{
    csh h;
    if (cs_open(c.arch, c.mode, &h) != CS_ERR_OK) {
        return Verdict::kInconclusive;
    }
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    if (c.arch == CS_ARCH_X86) {
        cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }
    cs_insn *insn = nullptr;
    size_t n = cs_disasm(h, c.bytes.data(), c.bytes.size(), 0x1000, 1, &insn);
    Verdict v = Verdict::kInconclusive;
    if (n > 0) {
        v = c.check(insn[0]) ? Verdict::kStillNeeded
                              : Verdict::kRetireCandidate;
        cs_free(insn, n);
    }
    cs_close(&h);
    return v;
}

} /* namespace */

int main(int argc, char **argv)
{
    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        printf("usage: %s\n\n"
               "Retest every disas/capstone.c Capstone-defect workaround "
               "against the Capstone this binary was linked against "
               "(subprojects/capstone, see capstone.wrap). No arguments; "
               "exit status is nonzero iff any case is INCONCLUSIVE.\n",
               argv[0]);
        return 0;
    }

    int major, minor;
    cs_version(&major, &minor);
    printf("Capstone linked: %d.%d (subprojects/capstone; capstone.wrap "
           "pins the exact revision)\n\n", major, minor);

    unsigned still_needed = 0, retire = 0, inconclusive = 0;
    for (const Case &c : Cases()) {
        Verdict v = RunCase(c);
        printf("%s  %-42s %-24s  %s\n", VerdictStr(v), c.id, c.targets,
               c.description);
        switch (v) {
        case Verdict::kStillNeeded:     still_needed++;   break;
        case Verdict::kRetireCandidate: retire++;         break;
        case Verdict::kInconclusive:    inconclusive++;   break;
        }
    }

    printf("\n%u still needed, %u retire candidates, %u inconclusive "
           "(out of %zu)\n",
           still_needed, retire, inconclusive, Cases().size());
    if (retire > 0) {
        printf("\nA RETIRE CANDIDATE means Capstone now reports that "
               "encoding correctly -- go re-run the case's disas/"
               "capstone.c predicate (grep the function name above) by "
               "hand across the whole family it guards before deleting "
               "it; this tool checks one representative encoding per "
               "workaround, not the full family sweep documented in each "
               "comment.\n");
    }
    return inconclusive > 0 ? 1 : 0;
}
