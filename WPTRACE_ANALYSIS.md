# WPTrace Plugin Comprehensive Analysis

## 1. TraceISA Enum (Lines 59-64)

```c
typedef enum {
    TRACE_ISA_UNKNOWN = 0,
    TRACE_ISA_X86     = 1,   /* x86_64 and i386 */
    TRACE_ISA_AARCH64 = 2,   /* AArch64 (ARMv8+) */
    /* Future ISAs: TRACE_ISA_RISCV = 3, TRACE_ISA_MIPS = 4, ... */
} TraceISA;

static TraceISA trace_isa = TRACE_ISA_UNKNOWN;
```

This enum defines the supported ISAs. To add RISC-V and MIPS:
- Add `TRACE_ISA_RISCV = 3,` 
- Add `TRACE_ISA_MIPS = 4,`

## 2. GenericOpcode Enum (Lines 98-152)

Complete list of 51 generic operation types (GEN_OP_UNKNOWN=0 through GEN_OP_DEC=51):

**Integer ALU Operations:**
- GEN_OP_INT_ADD (1), GEN_OP_INT_SUB (2), GEN_OP_INT_MUL (3), GEN_OP_INT_DIV (4)
- GEN_OP_INT_ADC (47), GEN_OP_INT_SBB (48)
- GEN_OP_NEG (49), GEN_OP_INC (50), GEN_OP_DEC (51)

**Bitwise Operations:**
- GEN_OP_AND (5), GEN_OP_OR (6), GEN_OP_XOR (7), GEN_OP_NOT (8)

**Shift Operations:**
- GEN_OP_SHL (9), GEN_OP_SHR (10), GEN_OP_SAR (11)
- GEN_OP_ROL (12), GEN_OP_ROR (13)

**Data Movement:**
- GEN_OP_MOV (14), GEN_OP_LEA (19), GEN_OP_PUSH (17), GEN_OP_POP (18)
- GEN_OP_MOVSX (20), GEN_OP_MOVZX (21), GEN_OP_XCHG (22)

**Comparison & Logic:**
- GEN_OP_CMP (23), GEN_OP_TEST (24), GEN_OP_CMOV (45), GEN_OP_SETCC (46)

**Memory Operations:**
- GEN_OP_LOAD (15), GEN_OP_STORE (16)

**Control Flow:**
- GEN_OP_BRANCH (25), GEN_OP_CALL (26), GEN_OP_RET (27)

**Floating-Point:**
- GEN_OP_FP_ADD (28), GEN_OP_FP_SUB (29), GEN_OP_FP_MUL (30), GEN_OP_FP_DIV (31)
- GEN_OP_FP_SQRT (32), GEN_OP_FP_MOV (33), GEN_OP_FP_CVT (34), GEN_OP_FP_CMP (35)

**Vector/SIMD:**
- GEN_OP_VEC_ADD (36), GEN_OP_VEC_SUB (37), GEN_OP_VEC_MUL (38)
- GEN_OP_VEC_MOV (39), GEN_OP_VEC_SHUF (40), GEN_OP_VEC_LOGIC (41)

**Special:**
- GEN_OP_NOP (42), GEN_OP_SYSCALL (43), GEN_OP_FENCE (44)

## 3. GenericRegId Enum (Lines 172-219)

**Structure:**
- REG_NONE (0)
- REG_GPR0-REG_GPR31 (1-32): General-purpose integer registers
- REG_FPR0-REG_FPR31 (33-64): Floating-point registers
- REG_VEC0-REG_VEC31 (65-96): Vector/SIMD registers
- REG_SP (250): Stack pointer
- REG_FLAGS (251): Condition flags/status register
- REG_IP (252): Instruction pointer
- REG_LR (253): Link register
- REG_FP_REG (254): Frame pointer

This scheme is ISA-agnostic. x86 maps to these, ARM maps to these, and RISC-V/MIPS would map their registers to this numbering.

## 4. BranchType Enum (Lines 157-166)

```c
enum BranchType {
    BRANCH_NONE = 0,
    BRANCH_DIRECT_JUMP = 1,
    BRANCH_INDIRECT_JUMP = 2,
    BRANCH_DIRECT_CALL = 3,
    BRANCH_INDIRECT_CALL = 4,
    BRANCH_RETURN = 5,
    BRANCH_COND_DIRECT = 6,
    BRANCH_SYSCALL_TYPE = 7,
};
```

## 5. InsnFields Struct (Lines 225-234)

```c
typedef struct {
    uint8_t opcode;                 /* GenericOpcode */
    uint8_t branch_type;            /* BranchType (BRANCH_NONE if not branch) */
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    uint8_t src_regs[MAX_SRC_REGS]; /* Source register IDs (GenericRegId) */
    uint8_t dst_regs[MAX_DST_REGS]; /* Destination register IDs (GenericRegId) */
    bool has_immediate;
    int64_t immediate;
} InsnFields;
```

This represents the decoded, ISA-agnostic per-instruction metadata. Stored in BB templates.

## 6. MnemonicEntry and Mnemonic Table (Lines 388-575)

**Structure:**
```c
typedef struct {
    const char *name;
    uint8_t opcode;
    uint8_t branch_type;
} MnemonicEntry;

static const MnemonicEntry mnemonic_table[] = {
    {"add",      GEN_OP_INT_ADD,  BRANCH_NONE},
    {"adc",      GEN_OP_INT_ADC,  BRANCH_NONE},
    ...
    {"bl",       GEN_OP_CALL,     BRANCH_DIRECT_CALL},  /* AArch64 */
    ...
    {NULL,       0,               0}  /* Terminator */
};
```

**Mapping Coverage:**
- x86 instructions: add, adc, sub, sbb, imul, mul, idiv, div, and, or, xor, not, neg, inc, dec, shl, sal, shr, sar, rol, ror, mov, lea, push, pop, xchg, movsx, movsxd, movsl, movzx, movzb, cltq, cqto, cwtl, cdqe, cbw, cwde, cdq, cqo, cmp, test, jmp, call, ret, nop, syscall, sysenter, int, mfence, lfence, sfence
- x86 FP: addss, addsd, addps, addpd, subss, subsd, subps, subpd, mulss, mulsd, mulps, mulpd, divss, divsd, divps, divpd, sqrtss, sqrtsd, sqrtps, sqrtpd, movss, movsd, ucomiss, ucomisd, comiss, comisd
- x86 Vector: movaps, movapd, movups, movupd, movdqa, movdqu, andps, andpd, orps, orpd, xorps, xorpd, andnps, andnpd, pand, pandn, por, pxor, shufps, shufpd, pshufd, pshufb, paddb, paddw, paddd, paddq, psubb, psubw, psubd, psubq, pmulld, pmullw
- AArch64 ALU: adds, subs, madd, msub, sdiv, udiv, orr, orn, eor, eon, mvn, bic, lsl, lsr, asr
- AArch64 Memory: movz, movn, movk, ldr, ldp, ldrb, ldrh, ldrsb, ldrsh, ldrsw, str, stp, strb, strh
- AArch64 Compare: cmn, tst
- AArch64 Control: bl, blr, br, svc
- AArch64 Conditional: csel, csinc, csinv, csneg
- AArch64 FP: fadd, fsub, fmul, fdiv, fsqrt, fmov, fcmp, fcvt, fcvtzs, fcvtzu, scvtf, ucvtf

## 7. classify_mnemonic() Function (Lines 599-723)

**Signature:**
```c
static void classify_mnemonic(const char *mnem, uint8_t *opcode,
                              uint8_t *branch_type)
```

**Algorithm:**
1. Initialize outputs: opcode=GEN_OP_UNKNOWN, branch_type=BRANCH_NONE
2. Skip x86 prefixes: lock, rep, repz, repnz, data16
3. **x86-specific:**
   - Conditional branch detection: j<cc> (not jmp)
   - cmov<cc> variants
   - set<cc> variants
4. **AArch64-specific:**
   - Conditional branches: b.<cc>
   - Unconditional branch: b
   - ret instruction
   - Compare & branch: cbz, cbnz, tbz, tbnz
5. **Generic:**
   - FP conversion: cvt.../vcvt...
   - NOP variants: nopl, nopw, etc.
6. Direct lookup in mnemonic_table
7. AVX v-prefix fallback: strip 'v' and retry
8. x86 size suffix fallback: strip trailing q/l/w/b and retry

## 8. parse_x86_operands() Function (Lines 912-1202)

**Signature:**
```c
static void parse_x86_operands(const char *operands, InsnFields *out)
```

**Approach:**
1. Split operands by commas (respecting parentheses/brackets)
2. Detect memory operands (contain '(' or '[')
3. Adjust MOV to LOAD/STORE based on memory operands
4. Detect indirect branches (*operand prefix)
5. **Per opcode class parsing:**
   - **Two-operand ALU**: src→dst (both src and dst), FLAGS as dst
   - **Data movement (MOV/MOVSX/MOVZX/CMOV)**: src→dst
   - **LOAD**: memory→register
   - **STORE**: register→memory
   - **LEA**: address registers as sources
   - **CMP/TEST**: both operands as sources, FLAGS as dst
   - **PUSH**: src + SP as sources, SP as dst
   - **POP**: SP as source, SP and register as dst
   - **XCHG**: both operands as src+dst
   - **Unary (NOT/NEG/INC/DEC)**: operand as src+dst, FLAGS as dst (except NOT)
   - **CALL**: indirect operands handled, SP as src+dst, IP as dst
   - **RET**: SP as src+dst, IP as dst
   - **BRANCH**: FLAGS as src for conditional, indirect operands handled
   - **MUL**: multi-operand handling with RAX/RDX
   - **DIV**: RAX/RDX special handling
   - **SETCC**: FLAGS as src
   - **FP/Vector**: conservative parsing for 2-op and 3-op forms
6. Extract immediate values from $ prefix

## 9. parse_aarch64_operands() Function (Lines 1208-1367)

**Signature:**
```c
static void parse_aarch64_operands(const char *operands, InsnFields *out)
```

**Approach:**
1. Split operands by commas
2. **AArch64 convention:** First operand is destination, rest are sources
3. **Per opcode class parsing:**
   - **ALU operations**: dst=ops[0], rest are sources
   - **MOV/MOVSX/MOVZX/CMOV**: dst=ops[0], rest are sources
   - **LOAD (ldr/ldp)**: ops[0] is dst, ops[1] also dst for ldp, memory operands extract base+index
   - **STORE (str/stp)**: ops[0] is src, ops[1] also src for stp, memory operands extract base+index
   - **CMP/TST**: all operands as sources, FLAGS as dst
   - **BRANCH**: operands as sources (register for indirect)
   - **CALL (bl/blr)**: indirect call extracts register, LR is dst
   - **RET**: LR is src
   - **FP operations**: dst=ops[0], rest as sources; for fcmp all are sources, FLAGS is dst
   - **Default**: ops[0] is dst, rest are sources
4. Extract immediate values from # prefix

## 10. parse_x86_reg() Function (Lines 268-344)

**Maps x86 register names to GenericRegId:**

**64-bit:** rax→REG_GPR0, rcx→REG_GPR1, rdx→REG_GPR2, rbx→REG_GPR3, rsp→REG_SP, rbp→REG_FP_REG, rsi→REG_GPR4, rdi→REG_GPR5

**32-bit:** eax→REG_GPR0, ecx→REG_GPR1, edx→REG_GPR2, ebx→REG_GPR3, esp→REG_SP, ebp→REG_FP_REG, esi→REG_GPR4, edi→REG_GPR5

**16-bit:** ax→REG_GPR0, cx→REG_GPR1, dx→REG_GPR2, bx→REG_GPR3, sp→REG_SP, bp→REG_FP_REG, si→REG_GPR4, di→REG_GPR5

**8-bit:** al/ah→REG_GPR0, cl/ch→REG_GPR1, dl/dh→REG_GPR2, bl/bh→REG_GPR3, spl→REG_SP, bpl→REG_FP_REG, sil→REG_GPR4, dil→REG_GPR5

**Extended (R8-R15):** r8→REG_GPR6 (n-2 formula), up to r15→REG_GPR13

**SIMD:** xmm/ymm/zmm registers 0-31 → REG_VEC0 + n

**x87:** st* → REG_FPR0

**Special:** rip/eip→REG_IP, rflags/eflags→REG_FLAGS

## 11. parse_aarch64_reg() Function (Lines 349-385)

**Maps AArch64 register names to GenericRegId:**

**General purpose:** x0-x30, w0-w30 → REG_GPR0 + n (n=0-30)

**Zero registers:** xzr/wzr → REG_NONE (reads as zero, no dependency)

**Stack pointer:** sp → REG_SP

**Link register:** lr → REG_LR

**Frame pointer:** fp → REG_FP_REG

**Vector/FP:** v0-v31, d0-d31, s0-s31, q0-q31, h0-h31, b0-b31 → REG_VEC0 + n (n=0-31)

## 12. decode_disas_to_generic() Function (Lines 1373-1412)

**Signature:**
```c
static void decode_disas_to_generic(const char *disas, InsnFields *out)
```

**Algorithm - ISA Dispatch:**
1. Clear output InsnFields structure
2. Extract mnemonic (first space-delimited token from disassembly string)
3. Call classify_mnemonic() to get opcode + branch_type
4. Skip whitespace to operands section
5. **ISA-based dispatch:**
   ```c
   switch (trace_isa) {
   case TRACE_ISA_X86:
       parse_x86_operands(p, out);
       break;
   case TRACE_ISA_AARCH64:
       parse_aarch64_operands(p, out);
       break;
   default:
       /* Unknown ISA: no operand parsing */
       break;
   }
   ```

**Key Pattern:** This is where you'd add:
```c
case TRACE_ISA_RISCV:
    parse_riscv_operands(p, out);
    break;
case TRACE_ISA_MIPS:
    parse_mips_operands(p, out);
    break;
```

## 13. qemu_plugin_install() Function (Lines 2874-2976)

**ISA Detection Section (Lines 2877-2887):**
```c
target_name = info->target_name;
if (g_str_has_prefix(target_name, "x86_64") ||
    g_str_has_prefix(target_name, "i386")) {
    trace_isa = TRACE_ISA_X86;
} else if (g_str_has_prefix(target_name, "aarch64")) {
    trace_isa = TRACE_ISA_AARCH64;
} else {
    trace_isa = TRACE_ISA_UNKNOWN;
    fprintf(stderr, "wptrace: warning: unsupported ISA '%s', "
            "instruction decode will be limited\n", target_name);
}
```

**To add RISC-V and MIPS support:**
```c
else if (g_str_has_prefix(target_name, "riscv") ||
         g_str_has_prefix(target_name, "riscv64") ||
         g_str_has_prefix(target_name, "riscv32")) {
    trace_isa = TRACE_ISA_RISCV;
} else if (g_str_has_prefix(target_name, "mips") ||
           g_str_has_prefix(target_name, "mips64")) {
    trace_isa = TRACE_ISA_MIPS;
}
```

**Supported target_name prefixes from QEMU:**
- x86_64, i386
- aarch64, arm
- riscv32, riscv64
- mips, mips64, mipsel, mips64el

**Argument parsing** (Lines 2890-2918): Handles depth, outfile, debug, wp, start, stop, program, spfile options

## 14. write_bin_header() Function (Lines 2287-2328)

**Binary Format - where ISA byte is written (Line 2296):**
```c
write_u32(f, WPT_MAGIC);           /* Magic: 0x54505704 (v4) */
write_u8(f, (uint8_t)trace_isa);   /* ISA byte (TRACE_ISA_X86, etc.) */
write_uleb128(f, g_hash_table_size(template_map));
```

**Complete header format:**
```
[MAGIC(u32)] [ISA(u8)] [NUM_TEMPLATES(ULEB128)]
For each template:
  [TEMPLATE_ID(ULEB128)] [START_PC(u64)] [NUM_INSNS(ULEB128)] [FALL_THROUGH_PC(u64)]
  For each instruction:
    [PC(u64)] [OPCODE(u8)] [BRANCH_TYPE(u8)] [N_SRC(u8)] [N_DST(u8)]
    [SRC_REGS...] [DST_REGS...] [HAS_IMM(u8)] [IMM(u64 if has_imm)]
```

## 15. meson.build Configuration (Lines 1-32)

```meson
contrib_plugins = ['bbv', 'cache', 'cflow', 'drcov', 'execlog', 'hotblocks',
                   'hotpages', 'howvec', 'hwprofile', 'ips', 'simpoints',
                   'stoptrigger', 'wptrace']

if host_os != 'windows'
  contrib_plugins += 'lockstep'
endif

# Build plugin for each source
if get_option('plugins')
  foreach i : contrib_plugins
    if host_os == 'windows'
      t += shared_module(i, files(i + '.c') + 'win32_linker.c',
                        include_directories: '../../include/qemu',
                        link_depends: [win32_qemu_plugin_api_lib],
                        link_args: win32_qemu_plugin_api_link_flags,
                        dependencies: glib)
    else
      t += shared_module(i, files(i + '.c'),
                        include_directories: '../../include/qemu',
                        dependencies: glib)
    endif
  endforeach
endif
```

**No changes needed for compilation** - wptrace.c is already in the list and compiles as-is.

---

## Summary: Adding RISC-V and MIPS Support

### Required Changes:

1. **TraceISA enum**: Add TRACE_ISA_RISCV=3, TRACE_ISA_MIPS=4

2. **Implement parse_riscv_operands()** following the AArch64 pattern:
   - RISC-V: dst=x1-x31, fp register x8-x9, all operands follow register naming

3. **Implement parse_mips_operands()** following the AArch64 pattern:
   - MIPS: rd (destination) typically first, rs/rt as sources

4. **Add register mapping functions:**
   - parse_riscv_reg(): x0-x31 → REG_GPR0-REG_GPR31
   - parse_mips_reg(): $0-$31 or $at, $v0, etc. → REG_GPR0-REG_GPR31

5. **Add mnemonics to mnemonic_table[]:**
   - RISC-V: add, addi, sub, and, andi, or, ori, xor, xori, sll, slli, srl, srli, sra, srai, lw, sw, beq, bne, blt, bge, bltu, bgeu, jal, jalr, etc.
   - MIPS: add, addi, addiu, sub, and, andi, or, ori, xor, xori, sll, srl, sra, lw, sw, beq, bne, j, jal, jr, etc.

6. **Update classify_mnemonic()** if RISC-V/MIPS need special conditional branch handling

7. **Update qemu_plugin_install()** ISA detection (lines 2878-2887)

8. **Update decode_disas_to_generic()** dispatch (lines 1400-1410)

___BEGIN___COMMAND_DONE_MARKER___0
