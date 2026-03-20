/*
 * Shared lookup tables for wptrace decoding.
 * Generated from the baseline wptrace.c to keep the core logic compact.
 */
#ifndef WPTRACE_TABLES_INC
#define WPTRACE_TABLES_INC

/*
 * x86 register name table: maps all 64/32/16/8-bit GPR variants
 * and special registers to GenericRegId for hash table initialization.
 */
static const RegEntry x86_reg_entries[] = {
    /* 64-bit GPRs */
    {"rax", REG_GPR0}, {"rcx", REG_GPR1}, {"rdx", REG_GPR2},
    {"rbx", REG_GPR3}, {"rsp", REG_SP},   {"rbp", REG_FP_REG},
    {"rsi", REG_GPR4}, {"rdi", REG_GPR5},
    /* 32-bit GPRs */
    {"eax", REG_GPR0}, {"ecx", REG_GPR1}, {"edx", REG_GPR2},
    {"ebx", REG_GPR3}, {"esp", REG_SP},   {"ebp", REG_FP_REG},
    {"esi", REG_GPR4}, {"edi", REG_GPR5},
    /* 16-bit GPRs */
    {"ax", REG_GPR0}, {"cx", REG_GPR1}, {"dx", REG_GPR2},
    {"bx", REG_GPR3}, {"sp", REG_SP},   {"bp", REG_FP_REG},
    {"si", REG_GPR4}, {"di", REG_GPR5},
    /* 8-bit GPRs */
    {"al", REG_GPR0}, {"ah", REG_GPR0},
    {"cl", REG_GPR1}, {"ch", REG_GPR1},
    {"dl", REG_GPR2}, {"dh", REG_GPR2},
    {"bl", REG_GPR3}, {"bh", REG_GPR3},
    {"spl", REG_SP},  {"bpl", REG_FP_REG},
    {"sil", REG_GPR4}, {"dil", REG_GPR5},
    /* Special registers */
    {"rip", REG_IP}, {"eip", REG_IP},
    {"rflags", REG_FLAGS}, {"eflags", REG_FLAGS},
    {NULL, 0}
};

/*
 * AArch64 register name table for exact-match lookups.
 */
static const RegEntry aarch64_reg_entries[] = {
    {"xzr", REG_NONE}, {"wzr", REG_NONE},
    {"sp", REG_SP}, {"lr", REG_LR}, {"fp", REG_FP_REG},
    {NULL, 0}
};

/*
 * RISC-V register name table for exact-match lookups.
 */
static const RegEntry riscv_reg_entries[] = {
    {"zero", REG_NONE},
    {"ra", REG_LR}, {"sp", REG_SP}, {"gp", REG_GPR3},
    {"tp", REG_GPR4}, {"fp", REG_FP_REG},
    {NULL, 0}
};

/*
 * MIPS register name table for exact-match lookups.
 */
static const RegEntry mips_reg_entries[] = {
    {"zero", REG_NONE}, {"0", REG_NONE},
    {"at", REG_GPR1}, {"sp", REG_SP}, {"fp", REG_FP_REG},
    {"ra", REG_LR}, {"gp", REG_GPR28},
    {NULL, 0}
};

/* Searched linearly (only called at translate time) */
static const MnemonicEntry mnemonic_table[] = {
    /* Integer ALU */
    {"add",      GEN_OP_INT_ADD,  BRANCH_NONE},
    {"adc",      GEN_OP_INT_ADC,  BRANCH_NONE},
    {"sub",      GEN_OP_INT_SUB,  BRANCH_NONE},
    {"sbb",      GEN_OP_INT_SBB,  BRANCH_NONE},
    {"imul",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"mul",      GEN_OP_INT_MUL,  BRANCH_NONE},
    {"idiv",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"div",      GEN_OP_INT_DIV,  BRANCH_NONE},
    {"and",      GEN_OP_AND,      BRANCH_NONE},
    {"or",       GEN_OP_OR,       BRANCH_NONE},
    {"xor",      GEN_OP_XOR,      BRANCH_NONE},
    {"not",      GEN_OP_NOT,      BRANCH_NONE},
    {"neg",      GEN_OP_NEG,      BRANCH_NONE},
    {"inc",      GEN_OP_INC,      BRANCH_NONE},
    {"dec",      GEN_OP_DEC,      BRANCH_NONE},
    /* Shifts/rotates */
    {"shl",      GEN_OP_SHL,      BRANCH_NONE},
    {"sal",      GEN_OP_SHL,      BRANCH_NONE},
    {"shr",      GEN_OP_SHR,      BRANCH_NONE},
    {"sar",      GEN_OP_SAR,      BRANCH_NONE},
    {"rol",      GEN_OP_ROL,      BRANCH_NONE},
    {"ror",      GEN_OP_ROR,      BRANCH_NONE},
    /* Data movement */
    {"mov",      GEN_OP_MOV,      BRANCH_NONE},
    {"lea",      GEN_OP_LEA,      BRANCH_NONE},
    {"push",     GEN_OP_PUSH,     BRANCH_NONE},
    {"pop",      GEN_OP_POP,      BRANCH_NONE},
    {"xchg",     GEN_OP_XCHG,     BRANCH_NONE},
    /* Sign/zero extend */
    {"movsx",    GEN_OP_MOVSX,    BRANCH_NONE},
    {"movsxd",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movsl",    GEN_OP_MOVSX,    BRANCH_NONE},
    {"movsbw",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movsbl",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movswl",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movsbq",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movswq",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movslq",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movzx",    GEN_OP_MOVZX,    BRANCH_NONE},
    {"movzb",    GEN_OP_MOVZX,    BRANCH_NONE},
    {"movzbw",   GEN_OP_MOVZX,    BRANCH_NONE},
    {"movzbl",   GEN_OP_MOVZX,    BRANCH_NONE},
    {"movzwl",   GEN_OP_MOVZX,    BRANCH_NONE},
    {"movzbq",   GEN_OP_MOVZX,    BRANCH_NONE},
    {"movzwq",   GEN_OP_MOVZX,    BRANCH_NONE},
    {"cltq",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cqto",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cwtl",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cdqe",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cbw",      GEN_OP_MOVSX,    BRANCH_NONE},
    {"cwde",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cdq",      GEN_OP_MOVSX,    BRANCH_NONE},
    {"cqo",      GEN_OP_MOVSX,    BRANCH_NONE},
    /* Comparison */
    {"cmp",      GEN_OP_CMP,      BRANCH_NONE},
    {"test",     GEN_OP_TEST,     BRANCH_NONE},
    /* Control flow */
    {"jmp",      GEN_OP_BRANCH,   BRANCH_DIRECT_JUMP},
    {"call",     GEN_OP_CALL,     BRANCH_DIRECT_CALL},
    {"ret",      GEN_OP_RET,      BRANCH_RETURN},
    {"nop",      GEN_OP_NOP,      BRANCH_NONE},
    {"syscall",  GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    {"sysenter", GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    {"int",      GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    /* Fences */
    {"mfence",   GEN_OP_FENCE,    BRANCH_NONE},
    {"lfence",   GEN_OP_FENCE,    BRANCH_NONE},
    {"sfence",   GEN_OP_FENCE,    BRANCH_NONE},
    /* Scalar FP */
    {"addss",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"addsd",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"addps",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"addpd",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"subss",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"subsd",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"subps",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"subpd",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"mulss",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"mulsd",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"mulps",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"mulpd",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"divss",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"divsd",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"divps",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"divpd",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"sqrtss",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"sqrtsd",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"sqrtps",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"sqrtpd",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"movss",    GEN_OP_FP_MOV,   BRANCH_NONE},
    {"movsd",    GEN_OP_FP_MOV,   BRANCH_NONE},
    {"ucomiss",  GEN_OP_FP_CMP,   BRANCH_NONE},
    {"ucomisd",  GEN_OP_FP_CMP,   BRANCH_NONE},
    {"comiss",   GEN_OP_FP_CMP,   BRANCH_NONE},
    {"comisd",   GEN_OP_FP_CMP,   BRANCH_NONE},
    /* x87 FP */
    {"fld1",     GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fldz",     GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fldcw",    GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fst",      GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fstp",     GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fnstcw",   GEN_OP_STORE,    BRANCH_NONE},
    {"fsubr",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"fdivr",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"fdivp",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"fdivrp",   GEN_OP_FP_DIV,   BRANCH_NONE},
    {"wait",     GEN_OP_FENCE,    BRANCH_NONE},
    {"fwait",    GEN_OP_FENCE,    BRANCH_NONE},
    /* Vector mov */
    {"movaps",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movapd",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movups",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movupd",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movdqa",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movdqu",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movd",     GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movq",     GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"vmovd",    GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"vmovq",    GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"vmovdqa",  GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"vmovdqu",  GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"stmxcsr",  GEN_OP_STORE,    BRANCH_NONE},
    {"ldmxcsr",  GEN_OP_LOAD,     BRANCH_NONE},
    /* Vector logic */
    {"andps",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"andpd",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"orps",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"orpd",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"xorps",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"xorpd",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"andnps",   GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"andnpd",   GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"pand",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"pandn",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"por",      GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"pxor",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    /* Vector shuffle */
    {"shufps",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    {"shufpd",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    {"pshufd",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    {"pshufb",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    /* Vector add/sub/mul */
    {"paddb",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"paddw",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"paddd",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"paddq",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"psubb",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"psubw",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"psubd",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"psubq",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"pmulld",   GEN_OP_VEC_MUL,  BRANCH_NONE},
    {"pmullw",   GEN_OP_VEC_MUL,  BRANCH_NONE},
    /* AArch64 ALU */
    {"adds",     GEN_OP_INT_ADD,  BRANCH_NONE},
    {"subs",     GEN_OP_INT_SUB,  BRANCH_NONE},
    {"madd",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"msub",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"sdiv",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"udiv",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"orr",      GEN_OP_OR,       BRANCH_NONE},
    {"orn",      GEN_OP_OR,       BRANCH_NONE},
    {"eor",      GEN_OP_XOR,      BRANCH_NONE},
    {"eon",      GEN_OP_XOR,      BRANCH_NONE},
    {"mvn",      GEN_OP_NOT,      BRANCH_NONE},
    {"bic",      GEN_OP_AND,      BRANCH_NONE},
    {"lsl",      GEN_OP_SHL,      BRANCH_NONE},
    {"lsr",      GEN_OP_SHR,      BRANCH_NONE},
    {"asr",      GEN_OP_SAR,      BRANCH_NONE},
    /* AArch64 data movement */
    {"movz",     GEN_OP_MOV,      BRANCH_NONE},
    {"movn",     GEN_OP_MOV,      BRANCH_NONE},
    {"movk",     GEN_OP_MOV,      BRANCH_NONE},
    {"ldr",      GEN_OP_LOAD,     BRANCH_NONE},
    {"ldp",      GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrb",     GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrh",     GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrsb",    GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrsh",    GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrsw",    GEN_OP_LOAD,     BRANCH_NONE},
    {"str",      GEN_OP_STORE,    BRANCH_NONE},
    {"stp",      GEN_OP_STORE,    BRANCH_NONE},
    {"strb",     GEN_OP_STORE,    BRANCH_NONE},
    {"strh",     GEN_OP_STORE,    BRANCH_NONE},
    /* AArch64 comparison */
    {"cmn",      GEN_OP_CMP,      BRANCH_NONE},
    {"tst",      GEN_OP_TEST,     BRANCH_NONE},
    /* AArch64 control flow */
    {"bl",       GEN_OP_CALL,     BRANCH_DIRECT_CALL},
    {"blr",      GEN_OP_CALL,     BRANCH_INDIRECT_CALL},
    {"br",       GEN_OP_BRANCH,   BRANCH_INDIRECT_JUMP},
    {"svc",      GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    /* AArch64 conditional */
    {"csel",     GEN_OP_CMOV,     BRANCH_NONE},
    {"csinc",    GEN_OP_CMOV,     BRANCH_NONE},
    {"csinv",    GEN_OP_CMOV,     BRANCH_NONE},
    {"csneg",    GEN_OP_CMOV,     BRANCH_NONE},
    /* AArch64 FP */
    {"fadd",     GEN_OP_FP_ADD,   BRANCH_NONE},
    {"fsub",     GEN_OP_FP_SUB,   BRANCH_NONE},
    {"fmul",     GEN_OP_FP_MUL,   BRANCH_NONE},
    {"fdiv",     GEN_OP_FP_DIV,   BRANCH_NONE},
    {"fsqrt",    GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"fmov",     GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fcmp",     GEN_OP_FP_CMP,   BRANCH_NONE},
    {"fcvt",     GEN_OP_FP_CVT,   BRANCH_NONE},
    {"fcvtzs",   GEN_OP_FP_CVT,   BRANCH_NONE},
    {"fcvtzu",   GEN_OP_FP_CVT,   BRANCH_NONE},
    {"scvtf",    GEN_OP_FP_CVT,   BRANCH_NONE},
    {"ucvtf",    GEN_OP_FP_CVT,   BRANCH_NONE},
    /* RISC-V / MIPS integer ALU */
    {"addi",     GEN_OP_INT_ADD,  BRANCH_NONE},
    {"addiu",    GEN_OP_INT_ADD,  BRANCH_NONE},
    {"addu",     GEN_OP_INT_ADD,  BRANCH_NONE},
    {"addw",     GEN_OP_INT_ADD,  BRANCH_NONE},
    {"addiw",    GEN_OP_INT_ADD,  BRANCH_NONE},
    {"subw",     GEN_OP_INT_SUB,  BRANCH_NONE},
    {"subu",     GEN_OP_INT_SUB,  BRANCH_NONE},
    {"andi",     GEN_OP_AND,      BRANCH_NONE},
    {"ori",      GEN_OP_OR,       BRANCH_NONE},
    {"xori",     GEN_OP_XOR,      BRANCH_NONE},
    {"nor",      GEN_OP_OR,       BRANCH_NONE},
    /* RISC-V / MIPS shifts */
    {"sll",      GEN_OP_SHL,      BRANCH_NONE},
    {"slli",     GEN_OP_SHL,      BRANCH_NONE},
    {"sllw",     GEN_OP_SHL,      BRANCH_NONE},
    {"slliw",    GEN_OP_SHL,      BRANCH_NONE},
    {"sllv",     GEN_OP_SHL,      BRANCH_NONE},
    {"srl",      GEN_OP_SHR,      BRANCH_NONE},
    {"srli",     GEN_OP_SHR,      BRANCH_NONE},
    {"srlw",     GEN_OP_SHR,      BRANCH_NONE},
    {"srliw",    GEN_OP_SHR,      BRANCH_NONE},
    {"srlv",     GEN_OP_SHR,      BRANCH_NONE},
    {"sra",      GEN_OP_SAR,      BRANCH_NONE},
    {"srai",     GEN_OP_SAR,      BRANCH_NONE},
    {"sraw",     GEN_OP_SAR,      BRANCH_NONE},
    {"sraiw",    GEN_OP_SAR,      BRANCH_NONE},
    {"srav",     GEN_OP_SAR,      BRANCH_NONE},
    /* RISC-V / MIPS multiply and divide */
    {"mulh",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"mulhu",    GEN_OP_INT_MUL,  BRANCH_NONE},
    {"mulhsu",   GEN_OP_INT_MUL,  BRANCH_NONE},
    {"mulw",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"mult",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"multu",    GEN_OP_INT_MUL,  BRANCH_NONE},
    {"divu",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"divw",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"divuw",    GEN_OP_INT_DIV,  BRANCH_NONE},
    {"rem",      GEN_OP_INT_DIV,  BRANCH_NONE},
    {"remu",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"remw",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"remuw",    GEN_OP_INT_DIV,  BRANCH_NONE},
    /* RISC-V / MIPS compare */
    {"slt",      GEN_OP_CMP,      BRANCH_NONE},
    {"slti",     GEN_OP_CMP,      BRANCH_NONE},
    {"sltu",     GEN_OP_CMP,      BRANCH_NONE},
    {"sltiu",    GEN_OP_CMP,      BRANCH_NONE},
    /* RISC-V / MIPS data movement */
    {"lui",      GEN_OP_MOV,      BRANCH_NONE},
    {"auipc",    GEN_OP_LEA,      BRANCH_NONE},
    {"li",       GEN_OP_MOV,      BRANCH_NONE},
    {"la",       GEN_OP_LEA,      BRANCH_NONE},
    {"mv",       GEN_OP_MOV,      BRANCH_NONE},
    {"move",     GEN_OP_MOV,      BRANCH_NONE},
    {"mfhi",     GEN_OP_MOV,      BRANCH_NONE},
    {"mflo",     GEN_OP_MOV,      BRANCH_NONE},
    {"mthi",     GEN_OP_MOV,      BRANCH_NONE},
    {"mtlo",     GEN_OP_MOV,      BRANCH_NONE},
    /* RISC-V / MIPS loads */
    {"lb",       GEN_OP_LOAD,     BRANCH_NONE},
    {"lbu",      GEN_OP_LOAD,     BRANCH_NONE},
    {"lh",       GEN_OP_LOAD,     BRANCH_NONE},
    {"lhu",      GEN_OP_LOAD,     BRANCH_NONE},
    {"lw",       GEN_OP_LOAD,     BRANCH_NONE},
    {"lwu",      GEN_OP_LOAD,     BRANCH_NONE},
    {"ld",       GEN_OP_LOAD,     BRANCH_NONE},
    {"lwl",      GEN_OP_LOAD,     BRANCH_NONE},
    {"lwr",      GEN_OP_LOAD,     BRANCH_NONE},
    /* RISC-V / MIPS stores */
    {"sb",       GEN_OP_STORE,    BRANCH_NONE},
    {"sh",       GEN_OP_STORE,    BRANCH_NONE},
    {"sw",       GEN_OP_STORE,    BRANCH_NONE},
    {"sd",       GEN_OP_STORE,    BRANCH_NONE},
    {"swl",      GEN_OP_STORE,    BRANCH_NONE},
    {"swr",      GEN_OP_STORE,    BRANCH_NONE},
    /* RISC-V FP loads/stores */
    {"flw",      GEN_OP_LOAD,     BRANCH_NONE},
    {"fld",      GEN_OP_LOAD,     BRANCH_NONE},
    {"fsw",      GEN_OP_STORE,    BRANCH_NONE},
    {"fsd",      GEN_OP_STORE,    BRANCH_NONE},
    /* MIPS coprocessor loads/stores */
    {"lwc1",     GEN_OP_LOAD,     BRANCH_NONE},
    {"ldc1",     GEN_OP_LOAD,     BRANCH_NONE},
    {"swc1",     GEN_OP_STORE,    BRANCH_NONE},
    {"sdc1",     GEN_OP_STORE,    BRANCH_NONE},
    /* RISC-V / MIPS control flow */
    {"j",        GEN_OP_BRANCH,   BRANCH_DIRECT_JUMP},
    {"jal",      GEN_OP_CALL,     BRANCH_DIRECT_CALL},
    {"jalr",     GEN_OP_CALL,     BRANCH_INDIRECT_CALL},
    {"jr",       GEN_OP_BRANCH,   BRANCH_INDIRECT_JUMP},
    /* RISC-V / MIPS conditional branches */
    {"beq",      GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bne",      GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"blt",      GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bge",      GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bltu",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bgeu",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"blez",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bgtz",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bltz",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bgez",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"beqz",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bnez",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    /* RISC-V / MIPS system */
    {"ecall",    GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    {"ebreak",   GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    {"fence",    GEN_OP_FENCE,    BRANCH_NONE},
    /* AArch64 / MIPS unconditional branch */
    {"b",        GEN_OP_BRANCH,   BRANCH_DIRECT_JUMP},
    /* AArch64 compare-and-branch / test-and-branch */
    {"cbz",      GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"cbnz",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"tbz",      GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"tbnz",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    /* MIPS branch-likely variants */
    {"beql",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bnel",     GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"blezl",    GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bgtzl",    GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bltzl",    GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bgezl",    GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    /* MIPS branch-and-link */
    {"bltzal",   GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {"bgezal",   GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    {NULL,       0,               0}
};

/*
 * Prefix classification table for mnemonic patterns that can't be
 * handled by exact match. Two kinds of entries:
 *   - Dot-prefixes (e.g. "fadd."): matched when mnemonic contains '.'
 *   - Bare prefixes (e.g. "amo"): matched by truncating to prefix length
 */
static const MnemonicEntry prefix_class_table[] = {
    /* AArch64 conditional branches: b.eq, b.ne, b.gt, etc. */
    {"b.",       GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
    /* RISC-V FP instructions with dot suffix */
    {"fadd.",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"fsub.",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"fmul.",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"fdiv.",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"fsqrt.",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"fmv.",     GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fsgnj.",   GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fsgnjn.",  GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fsgnjx.",  GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fcvt.",    GEN_OP_FP_CVT,   BRANCH_NONE},
    {"feq.",     GEN_OP_FP_CMP,   BRANCH_NONE},
    {"flt.",     GEN_OP_FP_CMP,   BRANCH_NONE},
    {"fle.",     GEN_OP_FP_CMP,   BRANCH_NONE},
    {"fmadd.",   GEN_OP_FP_MUL,   BRANCH_NONE},
    {"fmsub.",   GEN_OP_FP_MUL,   BRANCH_NONE},
    {"fnmadd.",  GEN_OP_FP_MUL,   BRANCH_NONE},
    {"fnmsub.",  GEN_OP_FP_MUL,   BRANCH_NONE},
    /* RISC-V atomic ops */
    {"lr.",      GEN_OP_LOAD,     BRANCH_NONE},
    {"sc.",      GEN_OP_STORE,    BRANCH_NONE},
    {"fence.",   GEN_OP_FENCE,    BRANCH_NONE},
    /* MIPS FP instructions with dot suffix */
    {"add.",     GEN_OP_FP_ADD,   BRANCH_NONE},
    {"sub.",     GEN_OP_FP_SUB,   BRANCH_NONE},
    {"mul.",     GEN_OP_FP_MUL,   BRANCH_NONE},
    {"div.",     GEN_OP_FP_DIV,   BRANCH_NONE},
    {"sqrt.",    GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"mov.",     GEN_OP_FP_MOV,   BRANCH_NONE},
    {"cvt.",     GEN_OP_FP_CVT,   BRANCH_NONE},
    {"c.",       GEN_OP_FP_CMP,   BRANCH_NONE},
    {"madd.",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"msub.",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"nmadd.",   GEN_OP_FP_MUL,   BRANCH_NONE},
    {"nmsub.",   GEN_OP_FP_MUL,   BRANCH_NONE},
    /* Non-dot bare prefixes: matched by truncating mnemonic to 3-4 chars */
    {"amo",      GEN_OP_XCHG,     BRANCH_NONE},    /* RISC-V atomic */
    {"cmov",     GEN_OP_CMOV,     BRANCH_NONE},    /* x86 cmov<cc> */
    {"set",      GEN_OP_SETCC,    BRANCH_NONE},    /* x86 set<cc> */
    {"nop",      GEN_OP_NOP,      BRANCH_NONE},    /* NOP variants */
    {"cvt",      GEN_OP_FP_CVT,   BRANCH_NONE},    /* x86 cvt... */
    {"vcvt",     GEN_OP_FP_CVT,   BRANCH_NONE},    /* x86 vcvt... */
    {NULL,       0,               0}
};

#endif /* WPTRACE_TABLES_INC */
