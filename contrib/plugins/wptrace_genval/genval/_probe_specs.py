"""Auto-extracted probe specs.

Pure inline-assembly probes for one-shot opcode/branch coverage,
previously living in genval/blocks.py (the now-removed C++ block
catalog).  Extracted into a flat data file so the legacy import
shim could go away.  Each entry registers one CodeBlock via
_register_probe — no compiler involvement, no C++.
"""

from .asm_blocks import _register_probe


_register_probe('probe_x86_lea', {'x86_64': {'asm': '"leaq 3(%%rax,%%rax,4), %%rax"',
            'clobbers': '"rax"',
            'opcodes': ['LEA']}})

_register_probe('probe_x86_push_pop', {'x86_64': {'asm': '"pushq $0x1234\\n\\t"\n    "popq %%rax"',
            'clobbers': '"rax","cc"',
            'opcodes': ['PUSH', 'POP']}})

_register_probe('probe_x86_movsx_movzx', {'x86_64': {'asm': '"movb $-1, %%al\\n\\t"\n'
                   '    "movsx %%al, %%ebx\\n\\t"\n'
                   '    "movzx %%al, %%ecx"',
            'clobbers': '"rax","rbx","rcx"',
            'opcodes': ['MOVSX', 'MOVZX']}})

_register_probe('probe_x86_xchg', {'x86_64': {'asm': '"xchg %%rax, %%rbx"',
            'clobbers': '"rax","rbx"',
            'opcodes': ['XCHG']}})

_register_probe('probe_x86_cmov', {'x86_64': {'asm': '"cmp %%rcx, %%rbx\\n\\t"\n    "cmovl %%rdx, %%rax"',
            'clobbers': '"rax","cc"',
            'opcodes': ['CMOV', 'CMP']}})

_register_probe('probe_x86_setcc', {'x86_64': {'asm': '"xor %%eax, %%eax\\n\\t"\n'
                   '    "cmp %%rcx, %%rbx\\n\\t"\n'
                   '    "sete %%al"',
            'clobbers': '"rax","cc"',
            'opcodes': ['SETCC']}})

_register_probe('probe_x86_fence', {'x86_64': {'asm': '"mfence"', 'clobbers': '"memory"', 'opcodes': ['FENCE']}})

_register_probe('probe_x86_rotate', {'x86_64': {'asm': '"rol $5, %%rax\\n\\t"\n    "ror $3, %%rbx"',
            'clobbers': '"rax","rbx","cc"',
            'opcodes': ['ROL', 'ROR']}})

_register_probe('probe_x86_inc_dec', {'x86_64': {'asm': '"inc %%rax\\n\\t"\n    "dec %%rbx"',
            'clobbers': '"rax","rbx","cc"',
            'opcodes': ['INC', 'DEC']}})

_register_probe('probe_x86_neg_not', {'x86_64': {'asm': '"neg %%rax\\n\\t"\n    "not %%rbx"',
            'clobbers': '"rax","rbx","cc"',
            'opcodes': ['NEG', 'NOT']}})

_register_probe('probe_x86_test', {'x86_64': {'asm': '"test %%rax, %%rbx"',
            'clobbers': '"cc"',
            'opcodes': ['TEST']}})

_register_probe('probe_x86_shift', {'x86_64': {'asm': '"shl $3, %%rax\\n\\t"\n'
                   '    "shr $2, %%rbx\\n\\t"\n'
                   '    "sar $1, %%rcx"',
            'clobbers': '"rax","rbx","rcx","cc"',
            'opcodes': ['SHL', 'SHR', 'SAR']}})

_register_probe('probe_x86_int_mul', {'x86_64': {'asm': '"imul %%rbx, %%rax"',
            'clobbers': '"rax","cc"',
            'opcodes': ['INT_MUL']}})

_register_probe('probe_x86_int_div', {'x86_64': {'asm': '"xor %%edx, %%edx\\n\\t"\n'
                   '    "mov $7, %%rbx\\n\\t"\n'
                   '    "mov $1000, %%rax\\n\\t"\n'
                   '    "div %%rbx"',
            'clobbers': '"rax","rbx","rdx","cc"',
            'opcodes': ['INT_DIV']}})

_register_probe('probe_x86_int_adc_sbb', {'x86_64': {'asm': '"clc\\n\\t"\n'
                   '    "adc %%rbx, %%rax\\n\\t"\n'
                   '    "sbb %%rdx, %%rcx"',
            'clobbers': '"rax","rcx","cc"',
            'opcodes': ['INT_ADC', 'INT_SBB']}})

_register_probe('probe_x86_logic', {'x86_64': {'asm': '"and %%rbx, %%rax\\n\\t"\n'
                   '    "or %%rdx, %%rcx\\n\\t"\n'
                   '    "xor %%rsi, %%rdi"',
            'clobbers': '"rax","rcx","rdi","cc"',
            'opcodes': ['AND', 'OR', 'XOR']}})

_register_probe('probe_x86_int_add_sub', {'x86_64': {'asm': '"add %%rbx, %%rax\\n\\t"\n    "sub %%rdx, %%rcx"',
            'clobbers': '"rax","rcx","cc"',
            'opcodes': ['INT_ADD', 'INT_SUB']}})

_register_probe('probe_x86_load_store', {'x86_64': {'asm': '"subq $8, %%rsp\\n\\t"\n'
                   '    "fnstcw (%%rsp)\\n\\t"\n'
                   '    "stmxcsr (%%rsp)\\n\\t"\n'
                   '    "ldmxcsr (%%rsp)\\n\\t"\n'
                   '    "fldcw (%%rsp)\\n\\t"\n'
                   '    "addq $8, %%rsp"',
            'clobbers': '"memory"',
            'opcodes': ['LOAD', 'STORE']}})

_register_probe('probe_x86_vec_arith', {'x86_64': {'asm': '"paddq %%xmm1, %%xmm0\\n\\t"\n'
                   '    "psubq %%xmm1, %%xmm2\\n\\t"\n'
                   '    "pmullw %%xmm1, %%xmm3"',
            'clobbers': '"xmm0","xmm2","xmm3"',
            'opcodes': ['VEC_ADD', 'VEC_SUB', 'VEC_MUL']}})

_register_probe('probe_x86_vec_move', {'x86_64': {'asm': '"movdqa %%xmm0, %%xmm1\\n\\t"\n'
                   '    "pshufd $0x1B, %%xmm0, %%xmm2"',
            'clobbers': '"xmm1","xmm2"',
            'opcodes': ['VEC_MOV', 'VEC_SHUF']}})

_register_probe('probe_x86_vec_logic', {'x86_64': {'asm': '"pand %%xmm1, %%xmm0\\n\\t"\n'
                   '    "por %%xmm1, %%xmm2\\n\\t"\n'
                   '    "pxor %%xmm1, %%xmm3"',
            'clobbers': '"xmm0","xmm2","xmm3"',
            'opcodes': ['VEC_LOGIC']}})

_register_probe('probe_x86_fp_arith', {'x86_64': {'asm': '"addsd %%xmm1, %%xmm0\\n\\t"\n'
                   '    "subsd %%xmm1, %%xmm2\\n\\t"\n'
                   '    "mulsd %%xmm1, %%xmm3\\n\\t"\n'
                   '    "divsd %%xmm1, %%xmm4"',
            'clobbers': '"xmm0","xmm2","xmm3","xmm4"',
            'opcodes': ['FP_ADD', 'FP_SUB', 'FP_MUL', 'FP_DIV']}})

_register_probe('probe_x86_fp_sqrt_cmp', {'x86_64': {'asm': '"sqrtsd %%xmm1, %%xmm0\\n\\t"\n'
                   '    "ucomisd %%xmm1, %%xmm0"',
            'clobbers': '"xmm0","cc"',
            'opcodes': ['FP_SQRT', 'FP_CMP']}})

_register_probe('probe_x86_fp_mov_cvt', {'x86_64': {'asm': '"movsd %%xmm1, %%xmm0\\n\\t"\n'
                   '    "cvtsi2sd %%rax, %%xmm2"',
            'clobbers': '"xmm0","xmm2"',
            'opcodes': ['FP_MOV', 'FP_CVT']}})

_register_probe('probe_x86_fma', {'x86_64': {'asm': '"vfmadd132sd %%xmm1, %%xmm2, %%xmm0\\n\\t"\n'
                   '    "vfmsub132sd %%xmm4, %%xmm5, %%xmm3"',
            'clobbers': '"xmm0","xmm3"',
            'opcodes': ['FP_MADD', 'FP_MSUB']}})

_register_probe('probe_x86_vec_madd', {'x86_64': {'asm': '"pmaddwd %%xmm1, %%xmm0"',
            'clobbers': '"xmm0"',
            'opcodes': ['VEC_MADD']}})

_register_probe('probe_x86_nop', {'x86_64': {'asm': '".byte 0x0f, 0x1f, 0x00"',
            'clobbers': '"memory"',
            'opcodes': ['NOP']}})

_register_probe('probe_arm_int_add_sub', {'aarch64': {'asm': '"add x0, x1, x2\\n\\t"\n    "sub x3, x4, x5"',
             'clobbers': '"x0","x3","cc"',
             'opcodes': ['INT_ADD', 'INT_SUB']}})

_register_probe('probe_arm_int_mul_div', {'aarch64': {'asm': '"mov x1, #1000\\n\\t"\n'
                    '    "mov x2, #7\\n\\t"\n'
                    '    "mul  x0, x1, x2\\n\\t"\n'
                    '    "umulh x4, x1, x2\\n\\t"\n'
                    '    "udiv x3, x1, x2"',
             'clobbers': '"x0","x1","x2","x3","x4"',
             'opcodes': ['INT_MADD', 'INT_MUL', 'INT_DIV']}})

_register_probe('probe_arm_logic', {'aarch64': {'asm': '"and x0, x1, x2\\n\\t"\n'
                    '    "orr x3, x4, x5\\n\\t"\n'
                    '    "eor x6, x7, x0"',
             'clobbers': '"x0","x3","x6"',
             'opcodes': ['AND', 'OR', 'XOR']}})

_register_probe('probe_arm_shift', {'aarch64': {'asm': '"lsl x0, x1, x2\\n\\t"\n'
                    '    "lsr x3, x4, x5\\n\\t"\n'
                    '    "asr x6, x7, x0"',
             'clobbers': '"x0","x3","x6"',
             'opcodes': ['SHL', 'SHR', 'SAR']}})

_register_probe('probe_arm_sxt_uxt', {'aarch64': {'asm': '"sxtb x0, w1\\n\\t"\n'
                    '    "uxtb x2, w3\\n\\t"\n'
                    '    "sxth x4, w5\\n\\t"\n'
                    '    "uxth x6, w7"',
             'clobbers': '"x0","x2","x4","x6"',
             'opcodes': ['MOVSX', 'MOVZX']}})

_register_probe('probe_arm_adc_sbc', {'aarch64': {'asm': '"cmp x0, x0\\n\\t"     /* clear carry to known state '
                    '*/\n'
                    '    "adc x1, x2, x3\\n\\t"\n'
                    '    "sbc x4, x5, x6"',
             'clobbers': '"x1","x4","cc"',
             'opcodes': ['INT_ADC', 'INT_SBB']}})

_register_probe('probe_arm_load_store', {'aarch64': {'asm': '"sub sp, sp, #16\\n\\t"\n'
                    '    "stp x0, x1, [sp]\\n\\t"\n'
                    '    "ldp x2, x3, [sp]\\n\\t"\n'
                    '    "add sp, sp, #16"',
             'clobbers': '"x2","x3","memory"',
             'opcodes': ['LOAD', 'STORE']}})

_register_probe('probe_arm_vec_arith', {'aarch64': {'asm': '"addp v0.16b, v1.16b, v2.16b\\n\\t"\n'
                    '    "sabd v3.16b, v4.16b, v5.16b\\n\\t"\n'
                    '    "pmul v6.16b, v7.16b, v1.16b\\n\\t"\n'
                    '    "mla  v0.16b, v7.16b, v1.16b"',
             'clobbers': '"v0","v3","v6"',
             'opcodes': ['VEC_ADD', 'VEC_SUB', 'VEC_MUL', 'VEC_MADD']}})

_register_probe('probe_arm_vec_logic', {'aarch64': {'asm': '"bit  v0.16b, v1.16b, v2.16b\\n\\t"\n'
                    '    "bsl  v3.16b, v4.16b, v5.16b\\n\\t"\n'
                    '    "cmeq v6.16b, v7.16b, v1.16b"',
             'clobbers': '"v0","v3","v6"',
             'opcodes': ['VEC_LOGIC']}})

_register_probe('probe_arm_fp_arith', {'aarch64': {'asm': '"fadd d0, d1, d2\\n\\t"\n'
                    '    "fsub d3, d4, d5\\n\\t"\n'
                    '    "fmul d6, d7, d1\\n\\t"\n'
                    '    "fdiv d0, d2, d3"',
             'clobbers': '"d0","d3","d6"',
             'opcodes': ['FP_ADD', 'FP_SUB', 'FP_MUL', 'FP_DIV']}})

_register_probe('probe_arm_fp_sqrt_cmp', {'aarch64': {'asm': '"fsqrt d0, d1\\n\\t"\n    "fcmp d0, d1"',
             'clobbers': '"d0","cc"',
             'opcodes': ['FP_SQRT', 'FP_CMP']}})

_register_probe('probe_arm_fp_mov_cvt', {'aarch64': {'asm': '"fmov d0, d1\\n\\t"\n    "scvtf d2, x0"',
             'clobbers': '"d0","d2"',
             'opcodes': ['FP_MOV', 'FP_CVT']}})

_register_probe('probe_arm_nop', {'aarch64': {'asm': '"nop\\n\\t"\n    "nop"',
             'clobbers': '"memory"',
             'opcodes': ['NOP']}})

_register_probe('probe_rv_int_add_sub', {'riscv64': {'asm': '"add t0, t1, t2\\n\\t"\n    "sub t3, t4, t5"',
             'clobbers': '"t0","t3"',
             'opcodes': ['INT_ADD', 'INT_SUB']}})

_register_probe('probe_rv_int_mul_div', {'riscv64': {'asm': '"li t1, 1000\\n\\t"\n'
                    '    "li t2, 7\\n\\t"\n'
                    '    "mul  t0, t1, t2\\n\\t"\n'
                    '    "divu t3, t1, t2"',
             'clobbers': '"t0","t1","t2","t3"',
             'opcodes': ['INT_MUL', 'INT_DIV']}})

_register_probe('probe_rv_logic', {'riscv64': {'asm': '"and t0, t1, t2\\n\\t"\n'
                    '    "or  t3, t4, t5\\n\\t"\n'
                    '    "xor t6, a0, a1"',
             'clobbers': '"t0","t3","t6"',
             'opcodes': ['AND', 'OR', 'XOR']}})

_register_probe('probe_rv_shift', {'riscv64': {'asm': '"slli t0, t1, 3\\n\\t"\n'
                    '    "srli t2, t3, 2\\n\\t"\n'
                    '    "srai t4, t5, 1"',
             'clobbers': '"t0","t2","t4"',
             'opcodes': ['SHL', 'SHR', 'SAR']}})

_register_probe('probe_rv_sxt_uxt', {'riscv64': {'asm': '"sext.w t0, t1\\n\\t"\n    "andi  t2, t3, 0xff"',
             'clobbers': '"t0","t2"',
             'opcodes': ['INT_ADD', 'AND']}})

_register_probe('probe_rv_load_store', {'riscv64': {'asm': '"addi sp, sp, -16\\n\\t"\n'
                    '    "sd t0, 0(sp)\\n\\t"\n'
                    '    "sd t1, 8(sp)\\n\\t"\n'
                    '    "ld t2, 0(sp)\\n\\t"\n'
                    '    "ld t3, 8(sp)\\n\\t"\n'
                    '    "addi sp, sp, 16"',
             'clobbers': '"t2","t3","memory"',
             'opcodes': ['LOAD', 'STORE']}})

_register_probe('probe_rv_fp_arith', {'riscv64': {'asm': '"fadd.d ft0, ft1, ft2\\n\\t"\n'
                    '    "fsub.d ft3, ft4, ft5\\n\\t"\n'
                    '    "fmul.d ft6, ft7, ft1\\n\\t"\n'
                    '    "fdiv.d ft0, ft2, ft3"',
             'clobbers': '"ft0","ft3","ft6"',
             'opcodes': ['FP_ADD', 'FP_SUB', 'FP_MUL', 'FP_DIV']}})

_register_probe('probe_rv_fp_sqrt_cmp', {'riscv64': {'asm': '"fsqrt.d ft0, ft1\\n\\t"\n    "feq.d  t0, ft0, ft1"',
             'clobbers': '"ft0","t0"',
             'opcodes': ['FP_SQRT', 'FP_CMP']}})

_register_probe('probe_rv_fp_mov_cvt', {'riscv64': {'asm': '"fmv.d    ft0, ft1\\n\\t"\n    "fcvt.d.l ft2, t0"',
             'clobbers': '"ft0","ft2"',
             'opcodes': ['FP_MOV', 'FP_CVT']}})

_register_probe('probe_rv_nop', {'riscv64': {'asm': '"nop\\n\\t"\n    "nop"',
             'clobbers': '"memory"',
             'opcodes': ['NOP']}})

_register_probe('probe_mips_int_add_sub', {'mipsel': {'asm': '"addu $t0, $t1, $t2\\n\\t"\n    "subu $t3, $t4, $t5"',
            'clobbers': '"$t0","$t3"',
            'opcodes': ['INT_ADD', 'INT_SUB']}})

_register_probe('probe_mips_int_mul_div', {'mipsel': {'asm': '"li   $t1, 1000\\n\\t"\n'
                   '    "li   $t2, 7\\n\\t"\n'
                   '    "mul  $t0, $t1, $t2\\n\\t"\n'
                   '    "divu $t1, $t2\\n\\t"\n'
                   '    "mflo $t3"',
            'clobbers': '"$t0","$t1","$t2","$t3","hi","lo"',
            'opcodes': ['INT_MUL', 'INT_DIV']}})

_register_probe('probe_mips_logic', {'mipsel': {'asm': '"and $t0, $t1, $t2\\n\\t"\n'
                   '    "or  $t3, $t4, $t5\\n\\t"\n'
                   '    "xor $t6, $t7, $t8"',
            'clobbers': '"$t0","$t3","$t6"',
            'opcodes': ['AND', 'OR', 'XOR']}})

_register_probe('probe_mips_shift', {'mipsel': {'asm': '"sll $t0, $t1, 3\\n\\t"\n'
                   '    "srl $t2, $t3, 2\\n\\t"\n'
                   '    "sra $t4, $t5, 1"',
            'clobbers': '"$t0","$t2","$t4"',
            'opcodes': ['SHL', 'SHR', 'SAR']}})

_register_probe('probe_mips_sxt_uxt', {'mipsel': {'asm': '"seb  $t0, $t1\\n\\t"\n'
                   '    "seh  $t2, $t3\\n\\t"\n'
                   '    "andi $t4, $t5, 0xff"',
            'clobbers': '"$t0","$t2","$t4"',
            'opcodes': ['MOVSX', 'AND']}})

_register_probe('probe_mips_load_store', {'mipsel': {'asm': '"addiu $sp, $sp, -8\\n\\t"\n'
                   '    "sw    $t0, 0($sp)\\n\\t"\n'
                   '    "sw    $t1, 4($sp)\\n\\t"\n'
                   '    "lw    $t2, 0($sp)\\n\\t"\n'
                   '    "lw    $t3, 4($sp)\\n\\t"\n'
                   '    "addiu $sp, $sp, 8"',
            'clobbers': '"$t2","$t3","memory"',
            'opcodes': ['LOAD', 'STORE']}})

_register_probe('probe_mips_fp_arith', {'mipsel': {'asm': '"add.d $f0, $f2, $f4\\n\\t"\n'
                   '    "sub.d $f6, $f8, $f10\\n\\t"\n'
                   '    "mul.d $f12, $f14, $f2\\n\\t"\n'
                   '    "div.d $f0, $f4, $f6"',
            'clobbers': '"$f0","$f6","$f12"',
            'opcodes': ['FP_ADD', 'FP_SUB', 'FP_MUL', 'FP_DIV']}})

_register_probe('probe_mips_fp_sqrt_cmp', {'mipsel': {'asm': '"sqrt.d $f0, $f2\\n\\t"\n    "c.eq.d $f0, $f2"',
            'clobbers': '"$f0"',
            'opcodes': ['FP_SQRT', 'FP_CMP']}})

_register_probe('probe_mips_fp_mov_cvt', {'mipsel': {'asm': '"mov.d    $f0, $f2\\n\\t"\n    "cvt.d.w  $f4, $f6"',
            'clobbers': '"$f0","$f4"',
            'opcodes': ['FP_MOV', 'FP_CVT']}})

_register_probe('probe_mips_nop', {'mipsel': {'asm': '"nop\\n\\t"\n    "nop"',
            'clobbers': '"memory"',
            'opcodes': ['SHL']}})

_register_probe('probe_x86_mov', {'x86_64': {'asm': '"mov %%rbx, %%rax"',
            'clobbers': '"rax"',
            'opcodes': ['MOV']}})

_register_probe('probe_arm_mov_not_neg', {'aarch64': {'asm': '"mov x0, x1\\n\\t"\n'
                    '    "mvn x2, x3\\n\\t"\n'
                    '    "neg x4, x5"',
             'clobbers': '"x0","x2","x4"',
             'opcodes': ['OR', 'INT_SUB']}})

_register_probe('probe_arm_cmp_test', {'aarch64': {'asm': '"cmp x0, x1\\n\\t"\n    "tst x2, x3"',
             'clobbers': '"cc"',
             'opcodes': ['INT_SUB', 'AND']}})

_register_probe('probe_arm_cmov_setcc', {'aarch64': {'asm': '"cmp x0, x1\\n\\t"\n'
                    '    "csel x2, x3, x4, eq\\n\\t"\n'
                    '    "cset x5, ne\\n\\t"\n'
                    '    "csinc x6, x7, x0, gt"',
             'clobbers': '"x2","x5","x6","cc"',
             'opcodes': ['CMOV', 'INT_SUB']}})

_register_probe('probe_arm_fence', {'aarch64': {'asm': '"dmb ish\\n\\t"\n    "dsb ish\\n\\t"\n    "isb"',
             'clobbers': '"memory"',
             'opcodes': ['FENCE']}})

_register_probe('probe_arm_lea', {'aarch64': {'asm': '"1:\\n\\t"\n    "adr  x0, 1b\\n\\t"\n    "adrp x1, 1b"',
             'clobbers': '"x0","x1"',
             'opcodes': ['LEA']}})

_register_probe('probe_arm_xchg', {'aarch64': {'asm': '".arch armv8.1-a\\n\\t"\n'
                    '    "sub sp, sp, #16\\n\\t"\n'
                    '    "mov x0, sp\\n\\t"\n'
                    '    "mov x1, #0\\n\\t"\n'
                    '    "swp x2, x1, [x0]\\n\\t"\n'
                    '    "add sp, sp, #16\\n\\t"\n'
                    '    ".arch armv8-a"',
             'clobbers': '"x0","x1","x2","memory"',
             'opcodes': ['XCHG']}})

_register_probe('probe_arm_rotate', {'aarch64': {'asm': '"ror  x0, x1, #5\\n\\t"\n    "extr x2, x3, x3, #7"',
             'clobbers': '"x0","x2"',
             'opcodes': ['ROR']}})

_register_probe('probe_arm_vec_mov', {'aarch64': {'asm': '"dup  v0.16b, w1\\n\\t"\n'
                    '    "ins  v2.b[0], w3\\n\\t"\n'
                    '    "movi v4.16b, #0xAA"',
             'clobbers': '"v0","v2","v4"',
             'opcodes': ['VEC_MOV']}})

_register_probe('probe_arm_vec_shuf', {'aarch64': {'asm': '"zip1 v0.16b, v1.16b, v2.16b\\n\\t"\n'
                    '    "uzp1 v3.16b, v4.16b, v5.16b\\n\\t"\n'
                    '    "trn1 v6.16b, v7.16b, v1.16b\\n\\t"\n'
                    '    "ext  v0.16b, v1.16b, v2.16b, #4\\n\\t"\n'
                    '    "tbl  v3.16b, {v4.16b}, v5.16b"',
             'clobbers': '"v0","v3","v6"',
             'opcodes': ['VEC_SHUF']}})

_register_probe('probe_arm_msub_cmp_neg_not', {'aarch64': {'asm': '"ccmp x0, x1, #0, eq\\n\\t"\n'
                    '    "msub x2, x3, x4, x5\\n\\t"\n'
                    '    "abs  v0.16b, v1.16b\\n\\t"\n'
                    '    "not  v2.16b, v3.16b"',
             'clobbers': '"x2","v0","v2","cc"',
             'opcodes': ['CMP', 'INT_MSUB', 'NEG', 'NOT']}})

_register_probe('probe_arm_fp_madd_msub', {'aarch64': {'asm': '"fmadd d0, d1, d2, d3\\n\\t"\n'
                    '    "fmsub d4, d5, d6, d7"',
             'clobbers': '"d0","d4"',
             'opcodes': ['FP_MADD', 'FP_MSUB']}})

_register_probe('probe_arm_vec_msub', {'aarch64': {'asm': '"mls v0.16b, v1.16b, v2.16b"',
             'clobbers': '"v0"',
             'opcodes': ['VEC_MSUB']}})

_register_probe('probe_rv_mov', {'riscv64': {'asm': '"mv t0, t1"', 'clobbers': '"t0"', 'opcodes': ['MOV']}})

_register_probe('probe_rv_lea', {'riscv64': {'asm': '"auipc t0, 1"', 'clobbers': '"t0"', 'opcodes': ['LEA']}})

_register_probe('probe_rv_fence', {'riscv64': {'asm': '"fence rw, rw"',
             'clobbers': '"memory"',
             'opcodes': ['FENCE']}})

_register_probe('probe_rv_xchg', {'riscv64': {'asm': '"addi sp, sp, -16\\n\\t"\n'
                    '    "li t1, 0xCAFE\\n\\t"\n'
                    '    "amoswap.d t0, t1, (sp)\\n\\t"\n'
                    '    "addi sp, sp, 16"',
             'clobbers': '"t0","t1","memory"',
             'opcodes': ['XCHG']}})

_register_probe('probe_rv_cmp', {'riscv64': {'asm': '"slt   t0, t1, t2\\n\\t"\n'
                    '    "sltu  t3, t4, t5\\n\\t"\n'
                    '    "slti  a0, a1, 5"',
             'clobbers': '"t0","t3","a0"',
             'opcodes': ['CMP']}})

_register_probe('probe_rv_fp_madd_msub', {'riscv64': {'asm': '"fmadd.d ft0, ft1, ft2, ft3\\n\\t"\n'
                    '    "fmsub.d ft4, ft5, ft6, ft7"',
             'clobbers': '"ft0","ft4"',
             'opcodes': ['FP_MADD', 'FP_MSUB']}})

_register_probe('probe_rv_vec_arith', {'riscv64': {'asm': '".option push\\n\\t"\n'
                    '    ".option arch, +v\\n\\t"\n'
                    '    "vsetvli t0, zero, e64, m1, ta, ma\\n\\t"\n'
                    '    "vadd.vv  v0,  v1,  v2\\n\\t"\n'
                    '    "vsub.vv  v3,  v4,  v5\\n\\t"\n'
                    '    "vmul.vv  v6,  v7,  v8\\n\\t"\n'
                    '    "vfmadd.vv v9, v10, v11\\n\\t"\n'
                    '    "vfmsub.vv v12, v13, v14\\n\\t"\n'
                    '    ".option pop"',
             'clobbers': '"t0","memory"',
             'opcodes': ['VEC_ADD',
                         'VEC_SUB',
                         'VEC_MUL',
                         'VEC_MADD',
                         'VEC_MSUB']}})

_register_probe('probe_mips_mov', {'mipsel': {'asm': '"move $t0, $t1"', 'clobbers': '"$t0"', 'opcodes': ['OR']}})

_register_probe('probe_mips_neg_not', {'mipsel': {'asm': '"negu $t0, $t1\\n\\t"\n    "not  $t2, $t3"',
            'clobbers': '"$t0","$t2"',
            'opcodes': ['INT_SUB', 'NOT']}})

_register_probe('probe_mips_cmov', {'mipsel': {'asm': '"li   $t1, 0\\n\\t"\n'
                   '    "movz $t0, $t2, $t1\\n\\t"\n'
                   '    "movn $t3, $t4, $t5"',
            'clobbers': '"$t0","$t1","$t3"',
            'opcodes': ['CMOV']}})

_register_probe('probe_mips_rotate', {'mipsel': {'asm': '"rotr  $t0, $t1, 5\\n\\t"\n    "rotrv $t2, $t3, $t4"',
            'clobbers': '"$t0","$t2"',
            'opcodes': ['ROR']}})

_register_probe('probe_mips_fence', {'mipsel': {'asm': '"sync"', 'clobbers': '"memory"', 'opcodes': ['FENCE']}})

_register_probe('probe_mips_cmp', {'mipsel': {'asm': '"slt   $t0, $t1, $t2\\n\\t"\n'
                   '    "sltu  $t3, $t4, $t5\\n\\t"\n'
                   '    "slti  $t6, $t7, 5"',
            'clobbers': '"$t0","$t3","$t6"',
            'opcodes': ['CMP']}})

_register_probe('probe_mips_madd_msub', {'mipsel': {'asm': '"li    $t0, 3\\n\\t"\n'
                   '    "li    $t1, 5\\n\\t"\n'
                   '    "madd  $t0, $t1\\n\\t"\n'
                   '    "msub  $t0, $t1"',
            'clobbers': '"$t0","$t1","hi","lo"',
            'opcodes': ['INT_MADD', 'INT_MSUB']}})

_register_probe('probe_mips_fp_madd_msub', {'mipsel': {'asm': '"madd.d $f0, $f2, $f4, $f6\\n\\t"\n'
                   '    "msub.d $f8, $f10, $f12, $f14"',
            'clobbers': '"$f0","$f8"',
            'opcodes': ['FP_MADD', 'FP_MSUB']}})

_register_probe('probe_mips_xchg_nop_neg', {'mipsel': {'asm': '"addiu $sp, $sp, -8\\n\\t"\n'
                   '    "sw    $zero, 0($sp)\\n\\t"\n'
                   '    "li    $t1, 1\\n\\t"\n'
                   '    "ll    $t0, 0($sp)\\n\\t"\n'
                   '    "sc    $t1, 0($sp)\\n\\t"\n'
                   '    "addiu $sp, $sp, 8\\n\\t"\n'
                   '    "ssnop\\n\\t"\n'
                   '    "abs   $t2, $t3"',
            'clobbers': '"$t0","$t1","$t2","memory"',
            'opcodes': ['XCHG', 'NOP', 'INT_SUB']}})


# ===========================================================================
# Prefetch / cache-line-flush / TLB-invalidate probes (added 2026-05).
#
# Exercises the synthetic-EA capture path the plugin added for the new
# GEN_OP_PREFETCH / GEN_OP_CACHE_FLUSH / GEN_OP_TLB_FLUSH opcodes — these
# instructions translate to TCG no-ops in QEMU (no architectural memop is
# emitted), so the plugin computes the EA from the operand and the
# captured base/index register values and stores it in the load-memop
# slot.  The probes ALSO carry author-declared per-insn `reg_sets` so
# the validator's `_check_expected_reg_sets` catches drift between
# author intent and what the asm we wrote actually decodes to.
#
# All probes use the stack pointer as the base address — every ISA's
# user-mode runtime guarantees SP points at a writable, mapped page —
# and stick to small displacements that stay inside the same page.
# True TLB-invalidate instructions (x86 INVLPG, AArch64 TLBI*, RISC-V
# SFENCE.VMA, MIPS TLBP/...) are privileged and would fault in user
# mode; they are exercised by the tracer's mnemonic-classification
# tests instead, not here.
# ===========================================================================

_register_probe('probe_x86_prefetch', {
    'x86_64': {
        'asm':      '"prefetcht0 (%%rsp)\\n\\t"\n'
                    '    "prefetcht1 8(%%rsp)\\n\\t"\n'
                    '    "prefetchnta 16(%%rsp)\\n\\t"\n'
                    '    "prefetchw 24(%%rsp)"',
        'clobbers': '"memory"',
        'opcodes':  ['PREFETCH'],
        'reg_sets': [
            {'src': ['REG_SP'], 'dst': []},
            {'src': ['REG_SP'], 'dst': []},
            {'src': ['REG_SP'], 'dst': []},
            {'src': ['REG_SP'], 'dst': []},
        ],
    },
})

_register_probe('probe_x86_prefetch_sib', {
    'x86_64': {
        # SIB-encoded form exercising the base + index*scale + disp path
        # of the synthetic-EA computation (scale=8, x86 SIB scale field).
        'asm':      '"xor %%rdx, %%rdx\\n\\t"\n'
                    '    "prefetcht0 (%%rsp,%%rdx,8)"',
        'clobbers': '"rdx","memory","cc"',
        'opcodes':  ['XOR', 'PREFETCH'],
        'reg_sets': [
            # XOR also writes RFLAGS — Capstone's regs_write walk
            # picks it up and the tracer records REG_FLAGS in dst_regs.
            {'src': ['REG_GPR2'], 'dst': ['REG_GPR2', 'REG_FLAGS']},
            {'src': ['REG_SP', 'REG_GPR2'], 'dst': []},
        ],
    },
})

_register_probe('probe_x86_clflush', {
    'x86_64': {
        # CLFLUSH on the stack: harmless in user mode; the plugin
        # captures the EA via the synthetic-EA path.
        'asm':      '"clflush (%%rsp)"',
        'clobbers': '"memory"',
        'opcodes':  ['CACHE_FLUSH'],
        'reg_sets': [
            {'src': ['REG_SP'], 'dst': []},
        ],
    },
})

_register_probe('probe_aarch64_prfm', {
    'aarch64': {
        # PRFM with a register-form addressing mode.  AArch64 user-mode
        # always permits PRFM hints; the plugin's synthetic-EA path
        # computes [sp + #disp] for the immediate form.
        'asm':      '"prfm pldl1keep, [sp]\\n\\t"\n'
                    '    "prfum pldl1strm, [sp, #8]"',
        'clobbers': '"memory"',
        'opcodes':  ['PREFETCH'],
        'reg_sets': [
            {'src': ['REG_SP'], 'dst': []},
            {'src': ['REG_SP'], 'dst': []},
        ],
    },
})

_register_probe('probe_riscv_prefetch', {
    'riscv64': {
        # Zicbop prefetch hints.  The base -march=rv64gc cross
        # compilers GCC ships don't include Zicbop, so we wrap the
        # mnemonics in `.option arch, +zicbop` to enable them
        # locally for the assembler.  QEMU's user-mode RISC-V
        # treats these as architectural prefetches; the tracer
        # mnemonic table maps them to GEN_OP_PREFETCH.
        'asm':      '".option push\\n\\t"\n'
                    '    ".option arch, +zicbop\\n\\t"\n'
                    '    "prefetch.r 0(sp)\\n\\t"\n'
                    '    "prefetch.w 64(sp)\\n\\t"\n'
                    '    "prefetch.i 128(sp)\\n\\t"\n'
                    '    ".option pop"',
        'clobbers': '"memory"',
        'opcodes':  ['PREFETCH'],
        'reg_sets': [
            {'src': ['REG_SP'], 'dst': []},
            {'src': ['REG_SP'], 'dst': []},
            {'src': ['REG_SP'], 'dst': []},
        ],
    },
})

_register_probe('probe_mips_pref', {
    'mipsel': {
        # MIPS PREF — hint to prefetch [base+offset].  Hint code 0
        # (load-streaming) is universally accepted.
        'asm':      '"pref 0, 0($sp)\\n\\t"\n'
                    '    "pref 1, 32($sp)"',
        'clobbers': '"memory"',
        'opcodes':  ['PREFETCH'],
        'reg_sets': [
            {'src': ['REG_SP'], 'dst': []},
            {'src': ['REG_SP'], 'dst': []},
        ],
    },
})
