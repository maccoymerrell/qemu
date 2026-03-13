# WPTrace Plugin: RISC-V and MIPS ISA Support Implementation Guide

## Overview

This guide provides a step-by-step plan to add RISC-V and MIPS support to the wptrace plugin in QEMU.

---

## Phase 1: Enum Definitions (Lines 59-64)

### Location: `contrib/plugins/wptrace.c` - TraceISA enum

**Current state:**
```c
typedef enum {
    TRACE_ISA_UNKNOWN = 0,
    TRACE_ISA_X86     = 1,
    TRACE_ISA_AARCH64 = 2,
} TraceISA;
```

**Add these lines:**
```c
typedef enum {
    TRACE_ISA_UNKNOWN = 0,
    TRACE_ISA_X86     = 1,
    TRACE_ISA_AARCH64 = 2,
    TRACE_ISA_RISCV   = 3,    /* RISC-V (riscv32, riscv64) */
    TRACE_ISA_MIPS    = 4,    /* MIPS (mips, mips64, mipsel, mips64el) */
} TraceISA;
```

**Validation:** Ensure GEN_OP_COUNT is still valid (currently 51)

---

## Phase 2: Register Mapping Functions

### Location: After `parse_aarch64_reg()` function (around line 385)

#### 2A: Add `parse_riscv_reg()` function

**Requirements:**
- Map x0-x31 integer registers
- Map f0-f31 floating-point registers
- Map ABI names (ra, sp, gp, tp, t0-t6, s0-s11, a0-a7, etc.)
- x0 (zero) → REG_NONE (no dependency)
- x1 (ra) → REG_LR
- x2 (sp) → REG_SP
- x8 (fp) → REG_FP_REG

**File location:** Insert ~110 lines before `split_operands()` function (line 732)

**Template:** See WPTRACE_CODE_REFERENCE.txt section 5

#### 2B: Add `parse_mips_reg()` function

**Requirements:**
- Map $0-$31 numeric registers
- Map ABI names ($zero, $at, $v0-$v1, $a0-$a3, $t0-$t9, $s0-$s7, $sp, $fp, $ra, etc.)
- $0 (zero) → REG_NONE (no dependency)
- $31 (ra) → REG_LR
- $29 (sp) → REG_SP
- $30 (fp) → REG_FP_REG

**File location:** Insert ~100 lines after `parse_riscv_reg()`

**Template:** See WPTRACE_CODE_REFERENCE.txt section 5

---

## Phase 3: Mnemonic Table Extensions

### Location: `mnemonic_table[]` array (lines 395-575)

**Insert RISC-V mnemonics** (before `{NULL, 0, 0}` terminator):
- ALU: add, addi, sub, mul, div, and, andi, or, ori, xor, xori
- Shifts: sll, slli, srl, srli, sra, srai
- Memory: lw, ld, lh, lb, sw, sd, sh, sb
- Branches: beq, bne, blt, bge, bltu, bgeu
- Control: jal, jalr, ret
- FP: fadd.s, fadd.d, fsub.s, fsub.d, fmul.s, fmul.d, fdiv.s, fdiv.d, fsqrt.s, fsqrt.d, flw, fld, fsw, fsd

**Insert MIPS mnemonics** (before `{NULL, 0, 0}` terminator):
- ALU: add, addu, addi, addiu, sub, subu, mult, multu, mul, div, divu
- Bitwise: and, andi, or, ori, xor, xori
- Shifts: sll, slli, srl, srli, sra, srai
- Memory: lw, ld, lh, lb, sw, sd, sh, sb
- Branches: beq, bne, bltz, bgez, blez, bgtz
- Control: j, jal, jr, jalr

**File lines:** Add ~50 lines before line 574 (before `{NULL, 0, 0}`)

---

## Phase 4: Operand Parsing Functions

### Location: After `parse_aarch64_operands()` function (around line 1367)

#### 4A: Add helper functions for memory operand extraction

For RISC-V and MIPS, add:
```c
static void extract_riscv_mem_regs(const char *op, InsnFields *out)
static void extract_mips_mem_regs(const char *op, InsnFields *out)
```

Both should:
- Parse memory operand format: offset(base) for both ISAs
- Extract base register and optional index register
- Add to source registers via `add_src_reg()`

#### 4B: Add `parse_riscv_operands()` function (~150 lines)

**Pattern:**
```c
static void parse_riscv_operands(const char *operands, InsnFields *out)
```

**Implementation approach:**
1. Split operands by commas
2. Handle register + immediate patterns
3. Per-opcode class (similar to AArch64 pattern):
   - **ALU**: ops[0]=dst, ops[1..n]=sources
   - **LOAD**: memory operand, ops[last]=dst
   - **STORE**: ops[0]=src, memory operand
   - **BRANCHES**: all operands as sources
   - **JAL/JALR**: handle return address implicitly (REG_LR as dst)

**File location:** Insert before `classify_mnemonic()` function displacement

#### 4C: Add `parse_mips_operands()` function (~150 lines)

**Pattern:**
```c
static void parse_mips_operands(const char *operands, InsnFields *out)
```

**Implementation approach:**
1. Split operands by commas
2. MIPS convention: rd (destination), rs, rt (sources)
3. Per-opcode class:
   - **ALU (3-operand)**: ops[0]=dst, ops[1..2]=sources
   - **ALU (2-operand)**: ops[0]=src/dst, ops[1]=src
   - **LOAD**: ops[0]=dst, ops[1]=memory operand
   - **STORE**: ops[0]=src, ops[1]=memory operand
   - **BRANCHES**: all operands as sources
   - **JAL**: $31 (ra) as dst
   - **JALR**: handle rd register, $31 implicit if rd=0

**File location:** Insert after `parse_riscv_operands()`

---

## Phase 5: Mnemonic Classification

### Location: `classify_mnemonic()` function (lines 599-723)

**Add after AArch64 branch detection section (around line 666):**

```c
/* RISC-V conditional branches */
if (trace_isa == TRACE_ISA_RISCV && (strncmp(mnem, "beq", 3) == 0 ||
                strncmp(mnem, "bne", 3) == 0 ||
                strncmp(mnem, "blt", 3) == 0 ||
                strncmp(mnem, "bge", 3) == 0 ||
                strncmp(mnem, "bltu", 4) == 0 ||
                strncmp(mnem, "bgeu", 4) == 0)) {
    *opcode = GEN_OP_BRANCH;
    *branch_type = BRANCH_COND_DIRECT;
    return;
}

/* RISC-V unconditional branches */
if (trace_isa == TRACE_ISA_RISCV && strcmp(mnem, "jal") == 0) {
    *opcode = GEN_OP_CALL;
    *branch_type = BRANCH_DIRECT_CALL;
    return;
}
if (trace_isa == TRACE_ISA_RISCV && strcmp(mnem, "jalr") == 0) {
    *opcode = GEN_OP_CALL;
    *branch_type = BRANCH_INDIRECT_CALL;
    return;
}

/* MIPS conditional branches */
if (trace_isa == TRACE_ISA_MIPS && (strncmp(mnem, "beq", 3) == 0 ||
                strncmp(mnem, "bne", 3) == 0 ||
                strncmp(mnem, "bltz", 4) == 0 ||
                strncmp(mnem, "bgez", 4) == 0 ||
                strncmp(mnem, "blez", 4) == 0 ||
                strncmp(mnem, "bgtz", 4) == 0)) {
    *opcode = GEN_OP_BRANCH;
    *branch_type = BRANCH_COND_DIRECT;
    return;
}

/* MIPS unconditional branches */
if (trace_isa == TRACE_ISA_MIPS && strcmp(mnem, "j") == 0) {
    *opcode = GEN_OP_BRANCH;
    *branch_type = BRANCH_DIRECT_JUMP;
    return;
}
if (trace_isa == TRACE_ISA_MIPS && strcmp(mnem, "jal") == 0) {
    *opcode = GEN_OP_CALL;
    *branch_type = BRANCH_DIRECT_CALL;
    return;
}
if (trace_isa == TRACE_ISA_MIPS && strcmp(mnem, "jr") == 0) {
    *opcode = GEN_OP_BRANCH;
    *branch_type = BRANCH_INDIRECT_JUMP;
    return;
}
if (trace_isa == TRACE_ISA_MIPS && strcmp(mnem, "jalr") == 0) {
    *opcode = GEN_OP_CALL;
    *branch_type = BRANCH_INDIRECT_CALL;
    return;
}
```

---

## Phase 6: ISA Dispatch in Decode Function

### Location: `decode_disas_to_generic()` function (lines 1373-1412)

**Current dispatch (lines 1400-1410):**
```c
switch (trace_isa) {
case TRACE_ISA_X86:
    parse_x86_operands(p, out);
    break;
case TRACE_ISA_AARCH64:
    parse_aarch64_operands(p, out);
    break;
default:
    break;
}
```

**Update to:**
```c
switch (trace_isa) {
case TRACE_ISA_X86:
    parse_x86_operands(p, out);
    break;
case TRACE_ISA_AARCH64:
    parse_aarch64_operands(p, out);
    break;
case TRACE_ISA_RISCV:
    parse_riscv_operands(p, out);
    break;
case TRACE_ISA_MIPS:
    parse_mips_operands(p, out);
    break;
default:
    break;
}
```

---

## Phase 7: ISA Detection in Plugin Install

### Location: `qemu_plugin_install()` function (lines 2877-2887)

**Current detection:**
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

**Update to:**
```c
target_name = info->target_name;
if (g_str_has_prefix(target_name, "x86_64") ||
    g_str_has_prefix(target_name, "i386")) {
    trace_isa = TRACE_ISA_X86;
} else if (g_str_has_prefix(target_name, "aarch64")) {
    trace_isa = TRACE_ISA_AARCH64;
} else if (g_str_has_prefix(target_name, "riscv32") ||
           g_str_has_prefix(target_name, "riscv64") ||
           g_str_has_prefix(target_name, "riscv")) {
    trace_isa = TRACE_ISA_RISCV;
} else if (g_str_has_prefix(target_name, "mips64el") ||
           g_str_has_prefix(target_name, "mips64") ||
           g_str_has_prefix(target_name, "mipsel") ||
           g_str_has_prefix(target_name, "mips")) {
    trace_isa = TRACE_ISA_MIPS;
} else {
    trace_isa = TRACE_ISA_UNKNOWN;
    fprintf(stderr, "wptrace: warning: unsupported ISA '%s', "
            "instruction decode will be limited\n", target_name);
}
```

---

## Phase 8: Testing & Validation

### Test Cases for RISC-V

1. **Basic ALU**: Test add, sub, mul, div operations
2. **Bitwise**: Test and, or, xor, shifts
3. **Memory**: Test lw, sw load/store patterns
4. **Branches**: Test beq, bne, blt, bge conditional branches
5. **Control Flow**: Test jal (direct call), jalr (indirect call)
6. **Register Mapping**: Verify x0-x31, f0-f31 maps correctly

### Test Cases for MIPS

1. **Basic ALU**: Test add, addi, sub, mult operations
2. **Bitwise**: Test and, or, xor, shifts
3. **Memory**: Test lw, sw, ld, sd patterns
4. **Branches**: Test beq, bne, bltz, bgez conditional branches
5. **Control Flow**: Test j (direct jump), jal (call), jr (indirect jump), jalr (indirect call)
6. **Register Mapping**: Verify $0-$31 numeric and ABI names

### Test Commands

```bash
# For RISC-V
qemu-riscv64 -plugin ./contrib/plugins/libwptrace.so,outfile=riscv_trace ./test_program

# For MIPS
qemu-mips -plugin ./contrib/plugins/libwptrace.so,outfile=mips_trace ./test_program
qemu-mips64 -plugin ./contrib/plugins/libwptrace.so,outfile=mips64_trace ./test_program
```

### Validation Steps

1. Check generated .bin file magic and ISA byte:
   ```bash
   hexdump -C riscv_trace.bin | head
   # Should show: 04 57 50 54 (magic) followed by 03 (RISC-V) or 04 (MIPS)
   ```

2. Verify BB templates are created and encoded
3. Verify body entries contain correct instruction counts
4. Verify memory addresses are captured correctly

---

## Integration Checklist

- [ ] TraceISA enum updated with RISCV and MIPS values
- [ ] parse_riscv_reg() function implemented (~110 lines)
- [ ] parse_mips_reg() function implemented (~100 lines)
- [ ] RISC-V mnemonics added to mnemonic_table[] (~30 entries)
- [ ] MIPS mnemonics added to mnemonic_table[] (~30 entries)
- [ ] parse_riscv_operands() function implemented (~150 lines)
- [ ] parse_mips_operands() function implemented (~150 lines)
- [ ] classify_mnemonic() updated with RISC-V branch patterns
- [ ] classify_mnemonic() updated with MIPS branch patterns
- [ ] decode_disas_to_generic() switch statement updated
- [ ] qemu_plugin_install() ISA detection updated
- [ ] Compilation successful (meson build)
- [ ] RISC-V basic tests pass
- [ ] MIPS basic tests pass
- [ ] Binary format validation (magic + ISA byte)
- [ ] Text output format validation

---

## Expected Files Changes

```
contrib/plugins/wptrace.c:
  - Lines 59-64: TraceISA enum (+2 lines)
  - Lines 386-495: Register mapping functions (+210 lines)
  - Lines 545-575: Mnemonic table extensions (+60 lines)
  - Lines 1150-1350: Operand parsing functions (+300 lines)
  - Lines 625-705: classify_mnemonic() extensions (+80 lines)
  - Lines 1400-1410: decode_disas_to_generic() dispatch (+8 lines)
  - Lines 2877-2887: qemu_plugin_install() ISA detection (+10 lines)

Total: ~668 lines of new code
Compilation: No changes to meson.build required
```

---

## References

- RISC-V ISA Manual: https://riscv.org/technical/specifications/
  - Base ISA: add, sub, and, or, xor, sll, srl, sra, lw, sw, beq, bne, jal, jalr
  
- MIPS ISA Manual: MIPS Architecture Reference Manual
  - Base ISA: add, addi, sub, and, andi, or, ori, xor, xori, sll, srl, sra
  - Branches: beq, bne, bltz, bgez, blez, bgtz
  - Control: j, jal, jr, jalr

- QEMU Target Names: `info->target_name` from plugin interface
  - riscv32, riscv64, mips, mips64, mipsel, mips64el

