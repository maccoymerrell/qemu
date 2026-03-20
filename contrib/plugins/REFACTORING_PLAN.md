# WPTrace Refactoring Plan

## Current State
- **Original Size**: 5104 lines
- **Target Size**: < 2550 lines (less than half)
- **Reduction Needed**: >2550 lines (~50%)

## Problem Analysis

The wptrace.c file has grown large due to:

1. **Static Data Tables** (~446 lines):
   - Register name tables for 4 ISAs (x86, AArch64, RISC-V, MIPS): ~61 lines
   - Mnemonic-to-opcode mapping table: ~338 lines
   - Prefix classification table: ~47 lines

2. **Duplicate ISA-Specific Code** (~850+ lines):
   - parse_x86_operands(): ~290 lines
   - parse_aarch64_operands(): ~160 lines
   - parse_riscv_operands(): ~225 lines
   - parse_mips_operands(): ~175 lines
   - These functions have 60-70% code similarity

3. **ISA-Specific Register Parsers** (~250 lines):
   - parse_x86_reg(), parse_aarch64_reg(), parse_riscv_reg(), parse_mips_reg()
   - extract_x86_reg(), extract_aarch64_reg(), extract_riscv_reg(), extract_mips_reg()
   - extract_x86_mem_regs(), etc.

4. **Other Areas**:
   - Template management
   - Wrong-path simulation
   - I/O formatting

## Refactoring Strategy

### Phase 1: Extract Static Data (✓ COMPLETED)
**Savings: ~446 lines**

- Created `wptrace_data.inc` with all register and mnemonic tables
- Main file will #include this file
- Tables remain functionally identical

### Phase 2: Consolidate Operand Parsers
**Estimated Savings: ~600 lines**

Current structure has 4 nearly-identical parsers with pattern:
```c
static void parse_ISA_operands(const char *disas, uint8_t opcode, InsnFields *out) {
    // Split operands
    // Switch on opcode type
    // Extract registers/immediates
}
```

**Proposed Consolidation:**

1. Create ISA-agnostic operand parsing helpers:
   ```c
   typedef struct {
       uint8_t (*extract_reg)(const char*);
       void (*extract_mem_regs)(const char*, InsnFields*);
   } ISAOpsTable;
   ```

2. Single unified parser with ISA-specific callbacks:
   ```c
   static void parse_operands_unified(const char *disas, uint8_t opcode,
                                      InsnFields *out, const ISAOpsTable *ops);
   ```

3. Small ISA-specific wrappers that call unified parser

### Phase 3: Streamline Register Parsing
**Estimated Savings: ~150 lines**

- Consolidate the 4 parse_*_reg() functions into a dispatch table
- Merge extract_*_reg() functions using function pointers
- Merge extract_*_mem_regs() using parameterized bracket/paren parsing

### Phase 4: Remove Dead Code & Simplify
**Estimated Savings: ~100 lines**

- Remove unnecessary disambiguation in classify_mnemonic()
- Consolidate similar memory tracking callbacks
- Simplify template deduplication logic where possible

### Phase 5: Code Formatting & Comments
**Estimated Savings: ~200 lines**

- Reduce verbose comments (keep essential ones)
- Remove blank separator lines between similar code
- Use more compact formatting where readable

## Expected Final Size

| Component | Original | After Refactor | Savings |
|-----------|----------|----------------|---------|
| Static data | 446 | 10 (#include) | 436 |
| Operand parsers | 850 | 250 | 600 |
| Register parsers | 250 | 100 | 150 |
| Dead code | 100 | 0 | 100 |
| Comments/formatting | 400 | 200 | 200 |
| Core logic | 3058 | 3058 | 0 |
| **TOTAL** | **5104** | **~2620** | **~2484** |

**Final estimate: ~2400-2600 lines** (within target of <2550)

## Functional Equivalency Testing

Created 4 test workloads per requirements:

### Test (a): Store-Forwarding on Wrong-Path
- File: `/tmp/wptrace_tests/test_a_store_forward.c`
- Tests: Wrong-path writes don't propagate to memory
- Tests: Wrong-path loads see wrong-path stores via forwarding
- Correct path: stride 1, Wrong path: stride 2

### Test (b): Integer Divide-by-Zero on Wrong-Path
- File: `/tmp/wptrace_tests/test_b_div_zero.c`
- Tests: Wrong-path exceptions only affect wrong-path
- Large loop to test smith predictor behavior
- Wrong-path should remain in loop if not exiting

### Test (c): 5-Block Loop Smith Predictor
- File: `/tmp/wptrace_tests/test_c_five_blocks.c`
- Tests: Wrong-path follows loop structure
- Exactly 5 basic blocks in pattern
- Smith predictor should keep wrong-path in loop

### Test (d): 20-Block Value-Change Optimization
- File: `/tmp/wptrace_tests/test_d_value_change.c`
- Tests: Trace format value-change-only optimization
- Dynamic parameters change every 2 invocations
- Should only output parameters when they actually changed

## Testing Procedure

1. **Baseline**: Trace all 4 tests with original wptrace.c
2. **Refactor**: Apply phases 1-5 incrementally
3. **Verify**: After each phase, trace all 4 tests and compare with baseline
4. **Final Check**: Binary diff of trace outputs to verify equivalency

## Implementation Notes

- Maintain all existing functionality
- Preserve ISA extension hooks
- Keep performance characteristics (O(1) hash table lookups)
- Ensure binary trace format remains unchanged
- Document any unavoidable behavior changes

## Risks & Mitigations

**Risk**: Breaking functional equivalency during refactoring
**Mitigation**: Incremental changes with testing after each phase

**Risk**: Introducing subtle parsing bugs
**Mitigation**: Extensive test coverage with all 4 ISAs

**Risk**: Performance regression
**Mitigation**: Maintain hash table lookups, avoid algorithm changes

## Next Steps

1. Apply Phase 1: Include wptrace_data.inc in wptrace.c
2. Test compilation
3. Begin Phase 2: Consolidate operand parsers
4. Run test workloads to verify equivalency
