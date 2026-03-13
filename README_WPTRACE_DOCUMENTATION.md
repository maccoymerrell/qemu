# WPTrace Plugin Documentation Index

This directory contains comprehensive documentation for adding RISC-V and MIPS ISA support to the QEMU wptrace plugin.

## 📚 Documentation Files

### 1. **WPTRACE_QUICK_START.md** (8.8 KB) ⭐ START HERE
   - Overview of the 8 implementation phases
   - Critical code patterns and templates
   - Quick reference register mapping tables
   - Testing strategy and validation checklist
   - Common issues and solutions
   - **Best for:** Quick overview and understanding the big picture

### 2. **WPTRACE_ANALYSIS.md** (14 KB) 📖 COMPREHENSIVE REFERENCE
   - Complete breakdown of all 15 major components
   - Line numbers for every enum, struct, and function
   - TraceISA enum (currently: UNKNOWN, X86, AARCH64)
   - GenericOpcode enum (51 operation types)
   - GenericRegId enum (integer, FP, vector registers)
   - BranchType enum (8 branch types)
   - InsnFields struct (decoded instruction representation)
   - MnemonicEntry table structure (x86, AArch64 coverage)
   - classify_mnemonic() algorithm flow
   - parse_x86_operands() function approach
   - parse_aarch64_operands() function approach
   - parse_x86_reg() register mapping
   - parse_aarch64_reg() register mapping
   - decode_disas_to_generic() ISA dispatch mechanism
   - qemu_plugin_install() ISA detection
   - write_bin_header() binary format specification
   - meson.build configuration
   - **Best for:** Understanding existing code structure and patterns

### 3. **WPTRACE_CODE_REFERENCE.txt** (17 KB) 💻 IMPLEMENTATION TEMPLATES
   - Copy-paste ready code sections with full context
   - classify_mnemonic() complete implementation pattern
   - parse_x86_operands() ALU operation patterns
   - parse_aarch64_operands() ALU operation patterns
   - parse_riscv_reg() template function (~110 lines)
   - parse_mips_reg() template function (~100 lines)
   - RISC-V mnemonics to add to mnemonic_table
   - MIPS mnemonics to add to mnemonic_table
   - Memory operand extraction patterns
   - **Best for:** Copy-paste implementation and coding

### 4. **RISC-V_MIPS_IMPLEMENTATION_GUIDE.md** (12 KB) 🛠️ STEP-BY-STEP
   - 8 implementation phases with exact line numbers
   - Phase 1: Enum definitions (2 lines to add)
   - Phase 2: Register mapping functions (210 lines)
   - Phase 3: Mnemonic table extensions (60 lines)
   - Phase 4: Operand parsing functions (300 lines)
   - Phase 5: Mnemonic classification (80 lines)
   - Phase 6: ISA dispatch (8 lines)
   - Phase 7: ISA detection (10 lines)
   - Phase 8: Testing & validation
   - Total: ~668 lines of new code
   - Integration checklist (17 items)
   - Expected file changes breakdown
   - Testing strategy with actual commands
   - References to RISC-V and MIPS ISA manuals
   - **Best for:** Step-by-step implementation guidance

---

## 🎯 Quick Navigation by Task

### Understanding the codebase?
→ Read **WPTRACE_ANALYSIS.md** sections 1-15 in order

### Implementing new ISAs?
→ Follow **RISC-V_MIPS_IMPLEMENTATION_GUIDE.md** phases 1-8

### Writing code?
→ Use **WPTRACE_CODE_REFERENCE.txt** sections 1-6 as templates

### Need a quick overview?
→ Start with **WPTRACE_QUICK_START.md**

### Looking for specific function?
→ Find line numbers in WPTRACE_ANALYSIS.md, then view in wptrace.c

---

## 📊 Implementation Summary

### What Needs to be Added

| Component | New Code | Where | Status |
|-----------|----------|-------|--------|
| TraceISA enum | 2 lines | Lines 59-64 | Template provided |
| parse_riscv_reg() | ~110 lines | After line 385 | Code reference ready |
| parse_mips_reg() | ~100 lines | After parse_riscv_reg() | Code reference ready |
| RISC-V mnemonics | ~30 entries | Line 574 (before {NULL}) | Code reference ready |
| MIPS mnemonics | ~30 entries | Line 574 (before {NULL}) | Code reference ready |
| parse_riscv_operands() | ~150 lines | After line 1367 | Code reference ready |
| parse_mips_operands() | ~150 lines | After parse_riscv_operands() | Code reference ready |
| classify_mnemonic() updates | ~80 lines | Around line 666 | Code reference ready |
| decode_disas_to_generic() | ~8 lines | Lines 1400-1410 | Code reference ready |
| qemu_plugin_install() | ~10 lines | Lines 2877-2887 | Code reference ready |

**Total: ~668 lines of new code**

### Files Modified

- `contrib/plugins/wptrace.c` - Main implementation
- `contrib/plugins/meson.build` - No changes required (wptrace already listed)

### Binary Format Changes

- **BACKWARD COMPATIBLE** - Only adds 2 new ISA byte values (3=RISCV, 4=MIPS)
- ISA byte location: Byte 4 of output file
- Magic number unchanged: 0x54505704 (v4)

---

## 🧪 Testing & Validation

### Build Instructions
```bash
cd /home/runner/work/qemu/qemu
meson build
ninja -C build
```

### Test RISC-V
```bash
qemu-riscv64 -plugin ./build/contrib/plugins/libwptrace.so,outfile=rv_test ./program
```

### Test MIPS
```bash
qemu-mips -plugin ./build/contrib/plugins/libwptrace.so,outfile=mips_test ./program
qemu-mips64 -plugin ./build/contrib/plugins/libwptrace.so,outfile=mips64_test ./program
```

### Verify Output
```bash
# Check magic and ISA byte
hexdump -C rv_test.bin | head -3
# Should show: 04 57 50 54 (magic) followed by 03 (RISC-V) or 04 (MIPS)
```

---

## 📋 Key Data Structures

### TraceISA Enum
- UNKNOWN (0), X86 (1), AARCH64 (2), **RISCV (3)**, **MIPS (4)**

### GenericOpcode Enum
51 types: INT_ADD, INT_SUB, INT_MUL, INT_DIV, AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR, MOV, LOAD, STORE, PUSH, POP, LEA, MOVSX, MOVZX, XCHG, CMP, TEST, BRANCH, CALL, RET, FP_ADD, FP_SUB, FP_MUL, FP_DIV, FP_SQRT, FP_MOV, FP_CVT, FP_CMP, VEC_ADD, VEC_SUB, VEC_MUL, VEC_MOV, VEC_SHUF, VEC_LOGIC, NOP, SYSCALL, FENCE, CMOV, SETCC, INT_ADC, INT_SBB, NEG, INC, DEC

### GenericRegId Enum
- REG_NONE (0)
- REG_GPR0-REG_GPR31 (1-32)
- REG_FPR0-REG_FPR31 (33-64)
- REG_VEC0-REG_VEC31 (65-96)
- REG_SP (250), REG_FLAGS (251), REG_IP (252), REG_LR (253), REG_FP_REG (254)

### BranchType Enum
NONE (0), DIRECT_JUMP (1), INDIRECT_JUMP (2), DIRECT_CALL (3), INDIRECT_CALL (4), RETURN (5), COND_DIRECT (6), SYSCALL_TYPE (7)

---

## 🔍 Key Functions Overview

| Function | Purpose | Lines | ISA Specific? |
|----------|---------|-------|--------------|
| parse_x86_reg() | Map x86 names to generic IDs | 268-344 | Yes (x86) |
| parse_aarch64_reg() | Map ARM names to generic IDs | 349-385 | Yes (ARM) |
| **parse_riscv_reg()** | Map RISC-V names to generic IDs | NEW | Yes (RISC-V) |
| **parse_mips_reg()** | Map MIPS names to generic IDs | NEW | Yes (MIPS) |
| classify_mnemonic() | Classify instruction opcode | 599-723 | Mixed |
| parse_x86_operands() | Extract operands for x86 | 912-1202 | Yes (x86) |
| parse_aarch64_operands() | Extract operands for ARM | 1208-1367 | Yes (ARM) |
| **parse_riscv_operands()** | Extract operands for RISC-V | NEW | Yes (RISC-V) |
| **parse_mips_operands()** | Extract operands for MIPS | NEW | Yes (MIPS) |
| decode_disas_to_generic() | Dispatch to ISA operand parser | 1373-1412 | Mixed |
| write_bin_header() | Write binary trace header | 2287-2328 | No |
| qemu_plugin_install() | Plugin initialization & ISA detection | 2874-2976 | Mixed |

---

## 📚 External References

### RISC-V ISA Documentation
- RISC-V Unprivileged ISA: https://riscv.org/technical/specifications/
- Base ISA (RV32I/RV64I): add, addi, sub, and, andi, or, ori, xor, xori, sll, slli, srl, srli, sra, srai
- Memory: lw, sw, ld, sd, lh, sh, lb, sb
- Branches: beq, bne, blt, bge, bltu, bgeu
- Jumps: jal, jalr
- Extensions: FD (floating-point), RV128I, RV32E, etc.

### MIPS ISA Documentation
- MIPS Architecture Reference Manual: https://www.mips.com/
- Base ISA: add, addi, addiu, addu, sub, subu, and, andi, or, ori, xor, xori
- Shifts: sll, slli, srl, srli, sra, srai, sllv, srlv, srav
- Memory: lw, sw, ld, sd, lh, sh, lb, sb
- Branches: beq, bne, bltz, bgez, blez, bgtz
- Jumps: j, jal, jr, jalr

### QEMU Plugin API
- Include: `<qemu-plugin.h>`
- Functions used: qemu_plugin_insn_disas(), qemu_plugin_insn_vaddr(), qemu_plugin_insn_size()
- Callbacks: vcpu_tb_trans(), vcpu_tb_exec(), qemu_plugin_install()

---

## ✅ Validation Checklist

Before considering the implementation complete:

- [ ] All 4 documentation files read and understood
- [ ] Phase 1: Enum values added (2 lines)
- [ ] Phase 2: Register functions implemented (210 lines)
- [ ] Phase 3: Mnemonics added to table (60 lines)
- [ ] Phase 4: Operand parsing implemented (300 lines)
- [ ] Phase 5: Mnemonic classification updated (80 lines)
- [ ] Phase 6: ISA dispatch updated (8 lines)
- [ ] Phase 7: ISA detection added (10 lines)
- [ ] Code compiles without errors
- [ ] Code compiles without warnings
- [ ] RISC-V tests run without segfaults
- [ ] MIPS tests run without segfaults
- [ ] RISC-V trace files generated
- [ ] MIPS trace files generated
- [ ] Binary format validation passed (magic + ISA byte)
- [ ] Register mapping verified
- [ ] Instruction classification verified
- [ ] Memory address capture verified

---

## 📞 Support & Debugging

### If your code doesn't compile:
1. Check function signatures match the template in WPTRACE_CODE_REFERENCE.txt
2. Verify line counts match (Phase 2: ~210 lines, Phase 4: ~300 lines, etc.)
3. Ensure opening/closing braces are balanced

### If register mapping fails:
1. Check parse_riscv_reg() and parse_mips_reg() handle all register types
2. Verify ABI name mappings in addition to numeric register names
3. Test with simple instructions first (add, mov)

### If operand parsing fails:
1. Verify operand splitting handles memory addressing syntax: offset(base) or [base, index]
2. Check that register extractor functions are called for each operand
3. Ensure immediate value extraction works (# for immediates)

### If branch detection fails:
1. Check ISA-specific branch patterns in classify_mnemonic()
2. Verify conditional branch detection for beq, bne, blt, bge, etc.
3. Ensure call/return detection works for jal/jalr/ret

---

## 🎓 Learning Path

1. **Week 1:** Read WPTRACE_ANALYSIS.md and WPTRACE_QUICK_START.md
2. **Week 2:** Study existing x86 and AArch64 implementations in wptrace.c
3. **Week 3:** Implement Phase 1-3 (enums, register functions, mnemonics)
4. **Week 4:** Implement Phase 4-5 (operand parsing, classification)
5. **Week 5:** Implement Phase 6-7 (dispatch, ISA detection)
6. **Week 6:** Testing and validation
7. **Week 7:** Optimize and document

---

Generated: 2025
For QEMU wptrace plugin RISC-V & MIPS support
