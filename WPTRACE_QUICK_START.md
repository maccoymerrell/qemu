# WPTrace Plugin - Quick Start Guide for RISC-V & MIPS Support

## Key Files Generated

Three comprehensive documents have been created in `/home/runner/work/qemu/qemu/`:

1. **WPTRACE_ANALYSIS.md** (408 lines)
   - Complete breakdown of all enums, structs, and functions
   - Line numbers for every component
   - Full mnemonic table coverage
   - ISA detection patterns

2. **WPTRACE_CODE_REFERENCE.txt** (478 lines)
   - Copy-paste ready code templates
   - Detailed function implementations for RISC-V and MIPS
   - Mnemonic table entries ready to add
   - Memory operand extraction patterns

3. **RISC-V_MIPS_IMPLEMENTATION_GUIDE.md**
   - Step-by-step implementation checklist
   - Phase-by-phase breakdown
   - Testing strategy
   - Validation procedures
   - Integration checklist

4. **meson.build** (32 lines)
   - No changes required - wptrace already listed

---

## The 8 Implementation Phases (Overview)

### Phase 1: Enum Definitions
- Add `TRACE_ISA_RISCV = 3` and `TRACE_ISA_MIPS = 4` to TraceISA enum
- **Location:** Lines 59-64 in wptrace.c
- **Lines to add:** 2

### Phase 2: Register Mapping Functions
- Implement `parse_riscv_reg()` - maps x0-x31, f0-f31, ABI names
- Implement `parse_mips_reg()` - maps $0-$31, ABI names ($v0, $a0, etc.)
- **Location:** After line 385 (after parse_aarch64_reg)
- **Lines to add:** ~210

### Phase 3: Mnemonic Table Extensions
- Add ~30 RISC-V mnemonics (add, lw, beq, jal, fadd.s, etc.)
- Add ~30 MIPS mnemonics (add, lw, beq, j, etc.)
- **Location:** Before line 574 (before {NULL, 0, 0} terminator)
- **Lines to add:** ~60

### Phase 4: Operand Parsing Functions
- Implement `parse_riscv_operands()` - operand-to-register mapping
- Implement `parse_mips_operands()` - operand-to-register mapping
- Add helper functions for memory operand extraction
- **Location:** Around line 1367 (after parse_aarch64_operands)
- **Lines to add:** ~300

### Phase 5: Mnemonic Classification
- Add RISC-V conditional branch detection (beq, bne, blt, bge, etc.)
- Add RISC-V call detection (jal, jalr)
- Add MIPS conditional branch detection (beq, bne, bltz, bgez, etc.)
- Add MIPS control flow detection (j, jal, jr, jalr)
- **Location:** Around line 666 in classify_mnemonic()
- **Lines to add:** ~80

### Phase 6: ISA Dispatch
- Add TRACE_ISA_RISCV case calling parse_riscv_operands()
- Add TRACE_ISA_MIPS case calling parse_mips_operands()
- **Location:** Lines 1400-1410 in decode_disas_to_generic()
- **Lines to add:** ~8

### Phase 7: ISA Detection
- Add target_name prefix checks for "riscv32", "riscv64", "riscv"
- Add target_name prefix checks for "mips", "mips64", "mipsel", "mips64el"
- **Location:** Lines 2877-2887 in qemu_plugin_install()
- **Lines to add:** ~10

### Phase 8: Testing & Validation
- Compile plugin
- Test with RISC-V and MIPS QEMU binaries
- Verify trace output format and correctness

---

## Critical Code Patterns

### Pattern 1: Register Mapping (Functions ~110 lines each)
```c
static uint8_t parse_riscv_reg(const char *name)
{
    // x0-x31 → REG_GPR0-REG_GPR31 (with special cases)
    // f0-f31 → REG_FPR0-REG_FPR31
    // ABI names: ra→REG_LR, sp→REG_SP, fp→REG_FP_REG, etc.
}
```

### Pattern 2: Mnemonic Table Entry
```c
{"add",      GEN_OP_INT_ADD,  BRANCH_NONE},
{"beq",      GEN_OP_BRANCH,   BRANCH_COND_DIRECT},
{"jal",      GEN_OP_CALL,     BRANCH_DIRECT_CALL},
```

### Pattern 3: Operand Parsing (Functions ~150 lines each)
```c
static void parse_riscv_operands(const char *operands, InsnFields *out)
{
    // 1. Split operands by commas
    // 2. First operand is destination (except for branches)
    // 3. Rest are sources
    // 4. Handle memory addressing for loads/stores
    // 5. Extract immediates from operands
}
```

### Pattern 4: ISA-Specific Branch Detection
```c
if (trace_isa == TRACE_ISA_RISCV && 
    (strncmp(mnem, "beq", 3) == 0 || strncmp(mnem, "bne", 3) == 0)) {
    *opcode = GEN_OP_BRANCH;
    *branch_type = BRANCH_COND_DIRECT;
    return;
}
```

### Pattern 5: ISA Dispatch
```c
switch (trace_isa) {
case TRACE_ISA_X86:
    parse_x86_operands(p, out);
    break;
case TRACE_ISA_RISCV:
    parse_riscv_operands(p, out);
    break;
case TRACE_ISA_MIPS:
    parse_mips_operands(p, out);
    break;
// ...
}
```

---

## Register Mapping Quick Reference

### RISC-V to Generic
| RISC-V | Mapping | Generic |
|--------|---------|---------|
| x0 | zero | REG_NONE |
| x1 | ra (return addr) | REG_LR |
| x2 | sp (stack ptr) | REG_SP |
| x3-x31 | general purpose | REG_GPR0 + (n-1) |
| f0-f31 | floating point | REG_FPR0 + n |

### MIPS to Generic
| MIPS | Mapping | Generic |
|------|---------|---------|
| $0 | zero | REG_NONE |
| $31 | ra (return addr) | REG_LR |
| $29 | sp (stack ptr) | REG_SP |
| $30 | fp (frame ptr) | REG_FP_REG |
| $1-$28 | general purpose | REG_GPR0 + (n-1) |

---

## Binary Format Changes

The wptrace binary format is **backward compatible** with new ISA values:

```
Header Format:
[MAGIC: 0x54505704 (v4)] [ISA: 1 byte] [...]
                                ↑
                        0=UNKNOWN
                        1=X86
                        2=AARCH64
                        3=RISCV    ← NEW
                        4=MIPS     ← NEW
```

No other format changes needed - ISA byte is already reserved.

---

## Testing Strategy

### Build & Test RISC-V
```bash
cd /home/runner/work/qemu/qemu
meson build
ninja -C build  # compiles wptrace plugin

# Create test RISC-V program or use existing
qemu-riscv64 -plugin ./build/contrib/plugins/libwptrace.so,outfile=riscv_test ./test_prog

# Verify output
ls -la riscv_test.bin riscv_test.txt
hexdump -C riscv_test.bin | head -3  # Check magic and ISA byte
```

### Build & Test MIPS
```bash
# Similar to RISC-V
qemu-mips -plugin ./build/contrib/plugins/libwptrace.so,outfile=mips_test ./test_prog
qemu-mips64 -plugin ./build/contrib/plugins/libwptrace.so,outfile=mips64_test ./test_prog
```

### Validation Checklist
- [ ] Compilation successful (no errors/warnings)
- [ ] Plugin loads in QEMU (no segfaults)
- [ ] Trace files created (.bin and .txt if debug=1)
- [ ] Magic number correct: 0x54505704
- [ ] ISA byte present and correct (0x03 for RISC-V, 0x04 for MIPS)
- [ ] Basic block templates created (num_templates > 0)
- [ ] Instruction counts match expected
- [ ] Registers correctly mapped to generic IDs
- [ ] Memory addresses captured

---

## File Structure After Implementation

```
contrib/plugins/wptrace.c
├── Lines 59-64:        TraceISA enum (RISCV=3, MIPS=4)
├── Lines 268-385:      parse_x86_reg, parse_aarch64_reg
├── Lines 386-495:      parse_riscv_reg, parse_mips_reg (NEW)
├── Lines 496-575:      split_operands, helper functions
├── Lines 395-575:      mnemonic_table[] (+RISC-V, +MIPS entries)
├── Lines 599-723:      classify_mnemonic() (+RISC-V, +MIPS branch detection)
├── Lines 912-1202:     parse_x86_operands
├── Lines 1208-1367:    parse_aarch64_operands
├── Lines 1368-1495:    parse_riscv_operands, parse_mips_operands (NEW)
├── Lines 1373-1412:    decode_disas_to_generic() (updated dispatch)
├── Lines 2287-2328:    write_bin_header() (unchanged)
├── Lines 2877-2887:    qemu_plugin_install() (updated ISA detection)
└── Lines 2970-2976:    Plugin registration (unchanged)
```

---

## Common Issues & Solutions

### Issue: Plugin compiles but doesn't recognize RISC-V/MIPS
**Solution:** Check ISA detection in qemu_plugin_install(). Ensure target_name string comparison matches QEMU's naming (case-sensitive).

### Issue: Register mapping shows REG_NONE for valid instructions
**Solution:** Verify register parser handles both numeric (x0-x31, $0-$31) and ABI names (ra, sp, etc.).

### Issue: Operand parsing doesn't extract registers
**Solution:** Check if register extractor functions are called correctly. Verify operand splitting handles memory addressing syntax properly.

### Issue: Binary trace doesn't show new ISA byte
**Solution:** Ensure write_bin_header() is called after ISA detection. ISA should be written at byte 4 of output file.

---

## Next Steps

1. **Start with Phase 1-2:** Add enums and register mapping functions
2. **Test Phase 1-2:** Basic register name parsing
3. **Continue with Phase 3-4:** Mnemonic table and operand parsing
4. **Test Phase 3-4:** Instruction classification and register extraction
5. **Add Phase 5-6:** Branch detection and dispatch
6. **Test Phase 5-6:** Complex instruction sequences
7. **Add Phase 7:** ISA detection
8. **Full system test:** Compile and test with QEMU binaries

---

## Documentation Files Location

All documentation saved to `/home/runner/work/qemu/qemu/`:

- `WPTRACE_ANALYSIS.md` - Comprehensive breakdown (408 lines)
- `WPTRACE_CODE_REFERENCE.txt` - Code templates (478 lines)
- `RISC-V_MIPS_IMPLEMENTATION_GUIDE.md` - Step-by-step guide
- `WPTRACE_QUICK_START.md` - This file
- Original source: `contrib/plugins/wptrace.c` (2976 lines)

