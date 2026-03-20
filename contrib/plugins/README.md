# WPTrace Test Workloads

This directory contains test programs to validate the functional equivalency of the refactored wptrace plugin.

## Test Programs

### test_a - Store-Forwarding on Wrong-Path
**File**: `test_a_store_forward.c`

Tests wrong-path store forwarding behavior:
- Correct path: Indexes array at intervals of 1
- Wrong path: Indexes array at intervals of 2
- Validates that wrong-path writes don't propagate to memory
- Validates that wrong-path loads see wrong-path stores via forwarding

**Compile**: `gcc -O2 -o test_a test_a_store_forward.c`

### test_b - Integer Divide-by-Zero on Wrong-Path
**File**: `test_b_div_zero.c`

Tests exception handling on wrong-path:
- Large loop (1000 iterations) for smith predictor testing
- Wrong-path attempts divide-by-zero
- Validates exceptions are isolated to wrong-path
- Tests that wrong-path remains in loop if not exiting

**Compile**: `gcc -O2 -o test_b test_b_div_zero.c`

### test_c - 5-Block Loop Smith Predictor
**File**: `test_c_five_blocks.c`

Tests smith predictor with 5-block loop:
- Exactly 5 basic blocks in loop structure
- Tests branch prediction pattern learning
- Wrong-path should follow loop unless exiting
- Validates smith predictor behavior

**Compile**: `gcc -O2 -o test_c test_c_five_blocks.c`

### test_d - 20-Block Value-Change Optimization
**File**: `test_d_value_change.c`

Tests trace format value-change optimization:
- 20 basic blocks with varying execution paths
- Dynamic parameters change only every 2nd invocation
- Validates that trace only outputs parameters when changed
- Tests trace compression efficiency

**Compile**: `gcc -O2 -o test_d test_d_value_change.c`

## Running Tests with WPTrace

### Build QEMU with wptrace plugin

```bash
# From QEMU source root
./configure --target-list=x86_64-linux-user
make
```

### Trace a test program

```bash
# Basic trace
qemu-x86_64 -plugin contrib/plugins/libwptrace.so,outfile=test_a.bin \
    /tmp/wptrace_tests/test_a

# With wrong-path tracing
qemu-x86_64 -plugin contrib/plugins/libwptrace.so,outfile=test_a.bin,wp=1 \
    /tmp/wptrace_tests/test_a

# With debug output
qemu-x86_64 -plugin contrib/plugins/libwptrace.so,outfile=test_a.txt,debug=1 \
    /tmp/wptrace_tests/test_a
```

## Validation Procedure

### 1. Baseline with Original Code

```bash
# Checkout original wptrace.c
git checkout <original-commit> contrib/plugins/wptrace.c

# Rebuild plugin
make

# Trace all tests
for test in a b c d; do
    qemu-x86_64 -plugin contrib/plugins/libwptrace.so,outfile=baseline_${test}.bin,wp=1 \
        /tmp/wptrace_tests/test_${test}
done
```

### 2. Test with Refactored Code

```bash
# Checkout refactored wptrace.c
git checkout <refactored-commit> contrib/plugins/wptrace.c

# Rebuild plugin
make

# Trace all tests
for test in a b c d; do
    qemu-x86_64 -plugin contrib/plugins/libwptrace.so,outfile=refactored_${test}.bin,wp=1 \
        /tmp/wptrace_tests/test_${test}
done
```

### 3. Compare Traces

```bash
# Binary comparison
for test in a b c d; do
    echo "Comparing test_${test}..."
    cmp baseline_${test}.bin refactored_${test}.bin && echo "PASS" || echo "FAIL"
done

# Or use the decode script
for test in a b c d; do
    python3 contrib/plugins/wptrace_decode.py baseline_${test}.bin > baseline_${test}.txt
    python3 contrib/plugins/wptrace_decode.py refactored_${test}.bin > refactored_${test}.txt
    diff -u baseline_${test}.txt refactored_${test}.txt
done
```

## Expected Results

All tests should produce **identical** trace output between original and refactored code. Any differences indicate a functional equivalency issue that must be addressed.

### Success Criteria

- Binary traces are byte-for-byte identical
- Decoded text traces match exactly
- No missing or extra basic blocks
- Dynamic parameters (addresses, targets) match
- Wrong-path sequences match

### Common Issues

If traces don't match, check:
1. Hash table initialization order (should be deterministic)
2. Register parsing logic (case sensitivity, aliasing)
3. Mnemonic lookup (exact vs prefix matching)
4. Operand extraction (memory addressing, immediates)
5. Branch type classification

## Notes

- All tests use `-O2` optimization to generate realistic code
- Tests are designed to be deterministic (no random numbers, no time dependencies)
- Wrong-path behavior depends on branch predictor state, so use consistent QEMU builds
- For reproducibility, disable ASLR: `setarch $(uname -m) -R qemu-x86_64 ...`
