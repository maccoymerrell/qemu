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
            'opcodes': ['LEA'],
            'dep_refines': ['DEP_LEA']}})

_register_probe('probe_x86_push_pop', {'x86_64': {'asm': '"pushq $0x1234\\n\\t"\n    "popq %%rax"',
            'clobbers': '"rax","cc"',
            'opcodes': ['PUSH', 'POP'],
            'dep_refines': ['DEP_X86_STACK_PUSH', 'DEP_X86_STACK_POP']}})

_register_probe('probe_x86_movsx_movzx', {'x86_64': {'asm': '"movb $-1, %%al\\n\\t"\n'
                   '    "movsx %%al, %%ebx\\n\\t"\n'
                   '    "movzx %%al, %%ecx"',
            'clobbers': '"rax","rbx","rcx"',
            'opcodes': ['MOVSX', 'MOVZX'],
            'dep_refines': ['DEP_PASSTHROUGH']}})

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
            'opcodes': ['SHL', 'SHR']}})

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
            'opcodes': ['INT_ADD', 'INT_SUB']}})

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

# Multi-memop multi-lane LOAD: PINSRD inserts one 32-bit dword from
# memory into a specific lane of xmm.  Four PINSRD instructions, each
# feeding a different lane (0..3) of %xmm0 from a different memory
# slot.  Each insn is its own memop -> single-lane case; the
# four-instruction sequence as a whole exercises the "different
# memops feed different lanes of one register" pattern at the
# basic-block level, even though no SINGLE x86 instruction in the
# legacy SSE space gets to do that.  The eventual gather/scatter
# refiner work (LANE_MASK_KIND_GATHER) will lift this into a
# single-instruction probe — when the plugin gains that path, the
# inline arrows / deps lines will show the per-source lane split
# automatically.
_register_probe('probe_x86_vec_load_multi_lane', {'x86_64': {'asm':
                   '"pinsrd $0, (%%rsp), %%xmm0\\n\\t"\n'
                   '    "pinsrd $1, 4(%%rsp), %%xmm0\\n\\t"\n'
                   '    "pinsrd $2, 8(%%rsp), %%xmm0\\n\\t"\n'
                   '    "pinsrd $3, 12(%%rsp), %%xmm0"',
            'clobbers': '"xmm0"',
            'opcodes': ['VEC_SHUF']}})

# Multi-memop multi-lane STORE: PEXTRD extracts one 32-bit dword
# from a specific xmm lane to memory.  Four PEXTRD instructions
# scatter the four lanes of %xmm0 into four memory slots.
_register_probe('probe_x86_vec_store_multi_lane', {'x86_64': {'asm':
                   '"pextrd $0, %%xmm0, (%%rsp)\\n\\t"\n'
                   '    "pextrd $1, %%xmm0, 4(%%rsp)\\n\\t"\n'
                   '    "pextrd $2, %%xmm0, 8(%%rsp)\\n\\t"\n'
                   '    "pextrd $3, %%xmm0, 12(%%rsp)"',
            'clobbers': '"memory"',
            'opcodes': ['VEC_SHUF']}})

# AArch64 LD2/LD3/LD4 multi-structure loads — one instruction with
# multiple memops where each memop targets a different destination
# register, but at the lane level each dst register's lanes come
# from interleaved positions in memory.  QEMU's plugin operand
# walker typically reports these as several memops (one per element
# pair/triplet/quadruplet).
_register_probe('probe_arm_vec_load_multi_lane', {'aarch64': {'asm':
                    '"mov  x9, sp\\n\\t"\n'
                    '    "ld2 {v0.4s, v1.4s}, [x9]\\n\\t"\n'
                    '    "ld3 {v2.4h, v3.4h, v4.4h}, [x9]\\n\\t"\n'
                    '    "ld4 {v5.16b, v6.16b, v7.16b, v8.16b}, [x9]"',
            'clobbers': '"x9","v0","v1","v2","v3","v4","v5","v6","v7","v8"',
            'opcodes': ['VEC_LOAD']}})

# AArch64 LD1 multi-register form — distinct ISA semantics from
# LD2/LD3/LD4: this loads contiguous bytes into N adjacent vector
# regs sequentially (no element interleave).  Exercises the
# `dep_vec_struct_load` sequential refiner separately from the
# `dep_vec_struct_load_interleaved` refiner bound to LD2/LD3/LD4.
_register_probe('probe_arm_vec_load_multi_reg', {'aarch64': {'asm':
                    '"mov  x9, sp\\n\\t"\n'
                    '    "ld1 {v9.4s, v10.4s}, [x9]\\n\\t"\n'
                    '    "ld1 {v11.4s, v12.4s, v13.4s}, [x9]\\n\\t"\n'
                    '    "ld1 {v14.16b, v15.16b, v16.16b, v17.16b}, [x9]"',
            'clobbers': '"x9","v9","v10","v11","v12","v13","v14","v15","v16","v17"',
            'opcodes': ['VEC_LOAD']}})

# AArch64 ST2/ST3/ST4 multi-structure stores — companion to the
# load probe.  Each instruction has multiple memops, each draining
# a different lane subset of the source register set.
_register_probe('probe_arm_vec_store_multi_lane', {'aarch64': {'asm':
                    '"mov  x9, sp\\n\\t"\n'
                    '    "st2 {v0.4s, v1.4s}, [x9]\\n\\t"\n'
                    '    "st3 {v2.4h, v3.4h, v4.4h}, [x9]\\n\\t"\n'
                    '    "st4 {v5.16b, v6.16b, v7.16b, v8.16b}, [x9]"',
            'clobbers': '"x9","memory"',
            'opcodes': ['VEC_STORE']}})

# AArch64 ST1 multi-register form — sequential mirror of the LD1
# multi-reg probe; exercises `dep_vec_struct_store` distinctly from
# the `dep_vec_struct_store_interleaved` refiner bound to ST2/ST3/ST4.
_register_probe('probe_arm_vec_store_multi_reg', {'aarch64': {'asm':
                    '"mov  x9, sp\\n\\t"\n'
                    '    "st1 {v9.4s, v10.4s}, [x9]\\n\\t"\n'
                    '    "st1 {v11.4s, v12.4s, v13.4s}, [x9]\\n\\t"\n'
                    '    "st1 {v14.16b, v15.16b, v16.16b, v17.16b}, [x9]"',
            'clobbers': '"x9","memory"',
            'opcodes': ['VEC_STORE']}})

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
             'opcodes': ['SHL', 'SHR']}})

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
             'opcodes': ['INT_ADD', 'INT_SUB']}})

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

# Same FADD/FSUB/FMUL/FDIV mnemonics as probe_arm_fp_arith, but the
# packed-vector forms (Vd.<arr>): refine_arm64_fp_vec must promote the
# statically-classified scalar FP_* op to its VEC_* twin from the
# decoded operand arrangement.
_register_probe('probe_arm_fp_vec_promote', {'aarch64': {'asm':
                    '"fadd v0.2d, v1.2d, v2.2d\\n\\t"\n'
                    '    "fsub v3.4s, v4.4s, v5.4s\\n\\t"\n'
                    '    "fmul v6.4s, v7.4s, v1.4s\\n\\t"\n'
                    '    "fdiv v0.2d, v2.2d, v3.2d"',
             'clobbers': '"v0","v3","v6"',
             'opcodes': ['VEC_ADD', 'VEC_SUB', 'VEC_MUL', 'VEC_DIV']}})

_register_probe('probe_arm_fp_vec_sqrt', {'aarch64': {'asm':
                    '"fsqrt v0.2d, v1.2d\\n\\t"\n'
                    '    "fmla v2.4s, v3.4s, v4.4s"',
             'clobbers': '"v0","v2"',
             'opcodes': ['VEC_SQRT', 'VEC_MADD']}})

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
             'opcodes': ['SHL', 'SHR']}})

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
            'opcodes': ['SHL', 'SHR']}})

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
             'opcodes': ['CMP', 'TEST']}})

_register_probe('probe_arm_cmov_setcc', {'aarch64': {'asm': '"cmp x0, x1\\n\\t"\n'
                    '    "csel x2, x3, x4, eq\\n\\t"\n'
                    '    "cset x5, ne\\n\\t"\n'
                    '    "csinc x6, x7, x0, gt"',
             'clobbers': '"x2","x5","x6","cc"',
             'opcodes': ['CMOV', 'CMP']}})

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

# ROR by immediate is an alias of EXTR (Capstone disassembles it as
# extr -> GEN_OP_BITMANIP); only the register form (RORV) stays a
# real ROR.  EXTR itself is bit-field extract -> BITMANIP.
_register_probe('probe_arm_rotate', {'aarch64': {'asm': '"ror  x0, x1, x4\\n\\t"\n    "extr x2, x3, x3, #7"',
             'clobbers': '"x0","x2"',
             'opcodes': ['ROR', 'BITMANIP']}})

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

# The RVV unconditionally-masked carry/merge families take v0 as a
# MANDATORY data operand — the carry-in of vadc/vmadc, the borrow-in of
# vsbc/vmsbc, the select control of vmerge/vfmerge (RVV v1.0 §11.4,
# §11.5, §11.15) — spelled with the trailing `m` on the operand-shape
# suffix.  This probe exists because NO cross-check can cover it: both
# Capstone and LLVM MC print `v0` in the operand string and neither
# reports the read, so isaxcheck sees two decoders agreeing and stays
# green either way.  disas/capstone.c restores the read from the
# specification; the author-declared reg_sets below are the only thing
# that will go red if that restoration is ever dropped.
#
# The unmasked siblings `vmadc.vv` / `vmsbc.vv` are included as the
# negative control: they encode no carry-in and must NOT name v0.
_register_probe('probe_rv_v0_carry_mask', {
    'riscv64': {
        'asm':      '".option push\\n\\t"\n'
                    '    ".option arch, +v\\n\\t"\n'
                    '    "vsetvli t0, zero, e64, m1, ta, ma\\n\\t"\n'
                    '    "vadc.vvm   v4, v5, v6, v0\\n\\t"\n'
                    '    "vsbc.vvm   v7, v8, v9, v0\\n\\t"\n'
                    '    "vmadc.vvm  v10, v11, v12, v0\\n\\t"\n'
                    '    "vmsbc.vvm  v13, v14, v15, v0\\n\\t"\n'
                    '    "vmerge.vvm v16, v17, v18, v0\\n\\t"\n'
                    '    "vmerge.vxm v19, v20, t1, v0\\n\\t"\n'
                    '    "vmadc.vv   v21, v22, v23\\n\\t"\n'
                    '    "vmsbc.vv   v24, v25, v26\\n\\t"\n'
                    '    ".option pop"',
        'clobbers': '"t0","memory"',
        'opcodes':  [],
        # REG_VCTRL is vl/vtype, the vector configuration every RVV
        # instruction consumes; REG_VEC0 is the carry/select operand
        # this probe exists for.  Note its absence on the last two.
        'reg_sets': [
            {'src': ['REG_ZERO'],
             'dst': ['REG_GPR5', 'REG_VCTRL']},                 # vsetvli
            {'src': ['REG_VEC5', 'REG_VEC6', 'REG_VCTRL', 'REG_VEC0'],
             'dst': ['REG_VEC4']},                              # vadc.vvm
            {'src': ['REG_VEC8', 'REG_VEC9', 'REG_VCTRL', 'REG_VEC0'],
             'dst': ['REG_VEC7']},                              # vsbc.vvm
            {'src': ['REG_VEC11', 'REG_VEC12', 'REG_VCTRL', 'REG_VEC0'],
             'dst': ['REG_VEC10']},                             # vmadc.vvm
            {'src': ['REG_VEC14', 'REG_VEC15', 'REG_VCTRL', 'REG_VEC0'],
             'dst': ['REG_VEC13']},                             # vmsbc.vvm
            {'src': ['REG_VEC17', 'REG_VEC18', 'REG_VCTRL', 'REG_VEC0'],
             'dst': ['REG_VEC16']},                             # vmerge.vvm
            {'src': ['REG_VEC20', 'REG_GPR6', 'REG_VCTRL', 'REG_VEC0'],
             'dst': ['REG_VEC19']},                             # vmerge.vxm
            {'src': ['REG_VEC22', 'REG_VEC23', 'REG_VCTRL'],
             'dst': ['REG_VEC21']},                             # vmadc.vv
            {'src': ['REG_VEC25', 'REG_VEC26', 'REG_VCTRL'],
             'dst': ['REG_VEC24']},                             # vmsbc.vv
        ],
    },
})

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
            # LL / SC are exclusive-monitor primitives, not RMW
            # swaps: LL is a tagged load, SC is a tagged store.
            # Reclassified as LOAD / STORE + MF_ATOMIC per the
            # "RMW is XCHG, but LL/SC alone aren't swaps" rule.
            'opcodes': ['LOAD', 'STORE', 'NOP', 'INT_SUB']}})


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


# ===========================================================================
# Atomic-flag probes.
#
# Exercises the writer's CST_INSN_FLAG_ATOMIC annotation: any insn
# classified with MF_ATOMIC in the per-ISA mnemonic tables (or
# x86 `lock`-prefixed) must carry is_atomic=true in its template.
# The validator's _check_atomic_count catches divergence between
# the writer's BodyStats aggregation and a static template walk;
# these probes ensure the atomic code path is exercised at all.
#
# All probes work in user mode and use the stack as a non-shared
# atomic target (single-thread; the atomic semantics are observable
# in flags / loaded values but no actual cross-thread synchronisation
# is required).
# ===========================================================================

_register_probe('probe_x86_lock_xadd', {
    'x86_64': {
        # `lock xadd src, mem` — atomic fetch-and-add.  The plugin
        # classifies xadd as GEN_OP_INT_ADD (with MF_ATOMIC) —
        # consistent with the LDADD / AMOADD convention on the other
        # ISAs: the data-mutation operation is add, the exchange is
        # incidental.  INC/DEC under LOCK carry their own
        # GEN_OP_INC / GEN_OP_DEC; the lock prefix alone causes
        # CST_INSN_FLAG_ATOMIC on every instruction in the sequence.
        'asm':      '"movq $1, %%rax\\n\\t"\n'
                    '    "lock xaddq %%rax, (%%rsp)\\n\\t"\n'
                    '    "lock incq (%%rsp)\\n\\t"\n'
                    '    "lock decq (%%rsp)"',
        'clobbers': '"rax","memory","cc"',
        'opcodes':  ['INT_ADD', 'INC', 'DEC'],
    },
})

_register_probe('probe_aarch64_ldadd', {
    'aarch64': {
        # LSE atomics: LDADD performs *atomic* RMW.  Requires armv8.1-a
        # +lse from the assembler; gate locally so the rest of the
        # binary stays armv8-a.
        'asm':      '".arch armv8.1-a\\n\\t"\n'
                    '    "mov x9, #1\\n\\t"\n'
                    '    "ldadd x9, x10, [sp]\\n\\t"\n'
                    '    "ldaddal x9, x10, [sp]\\n\\t"\n'
                    '    ".arch armv8-a"',
        'clobbers': '"x9","x10","memory"',
        'opcodes':  ['INT_ADD'],
    },
})

_register_probe('probe_riscv_amoadd', {
    'riscv64': {
        # RV64 A-extension: AMOADD is atomic RMW.
        'asm':      '"li t0, 1\\n\\t"\n'
                    '    "amoadd.d t1, t0, (sp)\\n\\t"\n'
                    '    "amoadd.d.aqrl t1, t0, (sp)"',
        'clobbers': '"t0","t1","memory"',
        'opcodes':  ['INT_ADD'],
    },
})

_register_probe('probe_mips_ll_sc', {
    'mipsel': {
        # MIPS LL / SC — load-linked / store-conditional.  Both are
        # MF_ATOMIC exclusive-monitor primitives but individually
        # they are just a tagged load (LL) and tagged store (SC),
        # not a swap: the atomic RMW emerges from the pair, not
        # from either instruction alone.  Classified accordingly.
        'asm':      '"li $t0, 1\\n\\t"\n'
                    '    "ll $t1, 0($sp)\\n\\t"\n'
                    '    "addu $t1, $t1, $t0\\n\\t"\n'
                    '    "sc $t1, 0($sp)"',
        'clobbers': '"$t0","$t1","memory"',
        'opcodes':  ['LOAD', 'STORE'],
    },
})


# ====================================================================
# EXACT-CHECK PROBES
# --------------------------------------------------------------------
# Each probe below carries an `insns` key holding a list parallel to
# its asm body — every entry exact-matched by validator.py's
# _check_expected_insns against the decoded trace.  The helper
# `_insn(opcode, src=..., dst=..., ...)` from asm_blocks.py compresses
# the per-entry dict; see BlockPlan.expected_insns for the full set
# of fields.
#
# These probes exist independently of the legacy `opcodes` /
# `reg_sets` keys so authors can add exact checks incrementally.  The
# validator's existing static_reg_sets / opcode_coverage probes still
# run against the same templates.
# ====================================================================

from .asm_blocks import _insn

# Plain integer ADD reg, reg → reg.  One-instruction probe.  Spans all
# four ISAs with the same shape: two GPRs read, one GPR (and on x86 /
# AArch64 the integer flags reg) written.
_register_probe('probe_exact_int_add_rr', {
    'x86_64': {
        # `addq %rbx, %rax` (ATT: dst-last; RAX is read+written, RBX read).
        'asm':      '"addq %%rbx, %%rax"',
        'clobbers': '"rax","cc"',
        'opcodes':  ['INT_ADD'],
        'insns': [
            _insn("GEN_OP_INT_ADD",
                  branch_type="BRANCH_NONE",
                  src=["REG_GPR0", "REG_GPR3"],
                  dst=["REG_GPR0", "REG_FLAGS"],
                  insn_flags_clear=[
                      "CST_INSN_FLAG_HAS_IMM",
                      "CST_INSN_FLAG_ATOMIC",
                      "CST_INSN_FLAG_BRANCH_COND",
                      "CST_INSN_FLAG_VEC",
                      "CST_INSN_FLAG_LANE_PARALLEL",
                  ]),
        ],
    },
    'aarch64': {
        # `add x0, x0, x1` (no flag write — ADD vs ADDS).
        'asm':      '"add x0, x0, x1"',
        'clobbers': '"x0"',
        'opcodes':  ['INT_ADD'],
        'insns': [
            _insn("GEN_OP_INT_ADD",
                  branch_type="BRANCH_NONE",
                  src=["REG_GPR0", "REG_GPR1"],
                  dst=["REG_GPR0"],
                  insn_flags_clear=[
                      "CST_INSN_FLAG_HAS_IMM",
                      "CST_INSN_FLAG_ATOMIC",
                      "CST_INSN_FLAG_BRANCH_COND",
                      "CST_INSN_FLAG_VEC",
                      "CST_INSN_FLAG_LANE_PARALLEL",
                  ]),
        ],
    },
    'riscv64': {
        # `add t0, t0, t1` (RV64 R-type; no flags register).
        'asm':      '"add t0, t0, t1"',
        'clobbers': '"t0"',
        'opcodes':  ['INT_ADD'],
        'insns': [
            _insn("GEN_OP_INT_ADD",
                  branch_type="BRANCH_NONE",
                  src=["REG_GPR5", "REG_GPR6"],
                  dst=["REG_GPR5"],
                  insn_flags_clear=[
                      "CST_INSN_FLAG_HAS_IMM",
                      "CST_INSN_FLAG_ATOMIC",
                      "CST_INSN_FLAG_BRANCH_COND",
                      "CST_INSN_FLAG_VEC",
                      "CST_INSN_FLAG_LANE_PARALLEL",
                  ]),
        ],
    },
    'mipsel': {
        # `addu $t0, $t1, $t2` (MIPS unsigned add; no implicit flag).
        'asm':      '"addu $t0, $t1, $t2"',
        'clobbers': '"$t0"',
        'opcodes':  ['INT_ADD'],
        'insns': [
            _insn("GEN_OP_INT_ADD",
                  branch_type="BRANCH_NONE",
                  src=["REG_GPR9", "REG_GPR10"],
                  dst=["REG_GPR8"],
                  insn_flags_clear=[
                      "CST_INSN_FLAG_HAS_IMM",
                      "CST_INSN_FLAG_ATOMIC",
                      "CST_INSN_FLAG_BRANCH_COND",
                      "CST_INSN_FLAG_VEC",
                      "CST_INSN_FLAG_LANE_PARALLEL",
                  ]),
        ],
    },
})


# Integer SUB reg, reg → reg.
_register_probe('probe_exact_int_sub_rr', {
    'x86_64':  {'asm': '"subq %%rbx, %%rax"', 'clobbers': '"rax","cc"',
                'opcodes': ['INT_SUB'],
                'insns': [_insn("INT_SUB", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR3"],
                                dst=["REG_GPR0", "REG_FLAGS"])]},
    'aarch64': {'asm': '"sub x0, x0, x1"', 'clobbers': '"x0"',
                'opcodes': ['INT_SUB'],
                'insns': [_insn("INT_SUB", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR1"],
                                dst=["REG_GPR0"])]},
    'riscv64': {'asm': '"sub t0, t0, t1"', 'clobbers': '"t0"',
                'opcodes': ['INT_SUB'],
                'insns': [_insn("INT_SUB", branch_type="NONE",
                                src=["REG_GPR5", "REG_GPR6"],
                                dst=["REG_GPR5"])]},
    'mipsel':  {'asm': '"subu $t0, $t1, $t2"', 'clobbers': '"$t0"',
                'opcodes': ['INT_SUB'],
                'insns': [_insn("INT_SUB", branch_type="NONE",
                                src=["REG_GPR9", "REG_GPR10"],
                                dst=["REG_GPR8"])]},
})

# Bitwise AND reg, reg → reg.
_register_probe('probe_exact_and_rr', {
    'x86_64':  {'asm': '"andq %%rbx, %%rax"', 'clobbers': '"rax","cc"',
                'opcodes': ['AND'],
                'insns': [_insn("AND", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR3"],
                                dst=["REG_GPR0", "REG_FLAGS"])]},
    'aarch64': {'asm': '"and x0, x0, x1"', 'clobbers': '"x0"',
                'opcodes': ['AND'],
                'insns': [_insn("AND", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR1"],
                                dst=["REG_GPR0"])]},
    'riscv64': {'asm': '"and t0, t0, t1"', 'clobbers': '"t0"',
                'opcodes': ['AND'],
                'insns': [_insn("AND", branch_type="NONE",
                                src=["REG_GPR5", "REG_GPR6"],
                                dst=["REG_GPR5"])]},
    'mipsel':  {'asm': '"and $t0, $t1, $t2"', 'clobbers': '"$t0"',
                'opcodes': ['AND'],
                'insns': [_insn("AND", branch_type="NONE",
                                src=["REG_GPR9", "REG_GPR10"],
                                dst=["REG_GPR8"])]},
})

# Bitwise OR reg, reg → reg.
_register_probe('probe_exact_or_rr', {
    'x86_64':  {'asm': '"orq %%rbx, %%rax"', 'clobbers': '"rax","cc"',
                'opcodes': ['OR'],
                'insns': [_insn("OR", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR3"],
                                dst=["REG_GPR0", "REG_FLAGS"])]},
    'aarch64': {'asm': '"orr x0, x0, x1"', 'clobbers': '"x0"',
                'opcodes': ['OR'],
                'insns': [_insn("OR", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR1"],
                                dst=["REG_GPR0"])]},
    'riscv64': {'asm': '"or t0, t0, t1"', 'clobbers': '"t0"',
                'opcodes': ['OR'],
                'insns': [_insn("OR", branch_type="NONE",
                                src=["REG_GPR5", "REG_GPR6"],
                                dst=["REG_GPR5"])]},
    'mipsel':  {'asm': '"or $t0, $t1, $t2"', 'clobbers': '"$t0"',
                'opcodes': ['OR'],
                'insns': [_insn("OR", branch_type="NONE",
                                src=["REG_GPR9", "REG_GPR10"],
                                dst=["REG_GPR8"])]},
})

# Bitwise XOR reg, reg → reg.
_register_probe('probe_exact_xor_rr', {
    'x86_64':  {'asm': '"xorq %%rbx, %%rax"', 'clobbers': '"rax","cc"',
                'opcodes': ['XOR'],
                'insns': [_insn("XOR", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR3"],
                                dst=["REG_GPR0", "REG_FLAGS"])]},
    'aarch64': {'asm': '"eor x0, x0, x1"', 'clobbers': '"x0"',
                'opcodes': ['XOR'],
                'insns': [_insn("XOR", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR1"],
                                dst=["REG_GPR0"])]},
    'riscv64': {'asm': '"xor t0, t0, t1"', 'clobbers': '"t0"',
                'opcodes': ['XOR'],
                'insns': [_insn("XOR", branch_type="NONE",
                                src=["REG_GPR5", "REG_GPR6"],
                                dst=["REG_GPR5"])]},
    'mipsel':  {'asm': '"xor $t0, $t1, $t2"', 'clobbers': '"$t0"',
                'opcodes': ['XOR'],
                'insns': [_insn("XOR", branch_type="NONE",
                                src=["REG_GPR9", "REG_GPR10"],
                                dst=["REG_GPR8"])]},
})

# Logical shift-left reg, imm → reg.  AArch64 omitted intentionally:
# `lsl reg, reg, #imm` encodes as UBFM (the LSL alias is just a
# disasm hint), so Capstone returns AARCH64_INS_UBFM → GEN_OP_MOVZX
# rather than GEN_OP_SHL.  That divergence is locked in by the
# dedicated probe_exact_aarch64_ubfm probe below.
_register_probe('probe_exact_shl_ri', {
    'x86_64':  {'asm': '"shlq $3, %%rax"', 'clobbers': '"rax","cc"',
                'opcodes': ['SHL'],
                'insns': [_insn("SHL", branch_type="NONE",
                                src=["REG_GPR0"],
                                dst=["REG_GPR0", "REG_FLAGS"],
                                insn_flags=["CST_INSN_FLAG_HAS_IMM"])]},
    'riscv64': {'asm': '"slli t0, t0, 3"', 'clobbers': '"t0"',
                'opcodes': ['SHL'],
                'insns': [_insn("SHL", branch_type="NONE",
                                src=["REG_GPR5"],
                                dst=["REG_GPR5"],
                                insn_flags=["CST_INSN_FLAG_HAS_IMM"])]},
    'mipsel':  {'asm': '"sll $t0, $t1, 3"', 'clobbers': '"$t0"',
                'opcodes': ['SHL'],
                'insns': [_insn("SHL", branch_type="NONE",
                                src=["REG_GPR9"],
                                dst=["REG_GPR8"],
                                insn_flags=["CST_INSN_FLAG_HAS_IMM"])]},
})

# AArch64 UBFM — the encoding LSL #imm / LSR #imm / UBFIZ / UBFX
# all alias to.  Tracer classifies AARCH64_INS_UBFM → MOVZX (which is
# arguably a misclassification of LSL #imm but matches the current
# table; that classification is a separate fix).  HAS_IMM is asserted
# SET because the source instruction does carry an immediate (the
# shift amount); if the tracer's operand walker doesn't currently
# expose UBFM's immr/imms as QEMU_PLUGIN_OP_IMM the probe will fail
# here — which is the intent: a probe surfaces the gap so the tracer
# learns to report it.
_register_probe('probe_exact_aarch64_ubfm', {
    'aarch64': {'asm': '"lsl x0, x0, #3"', 'clobbers': '"x0"',
                'opcodes': ['MOVZX'],
                'insns': [_insn("MOVZX", branch_type="NONE",
                                src=["REG_GPR0"],
                                dst=["REG_GPR0"],
                                insn_flags=["CST_INSN_FLAG_HAS_IMM"])]},
})


# Compare reg, reg.  x86 / aarch64 CMP writes flags only; RISC-V SLT
# and MIPS SLT write rd alongside reading rs1/rs2 — both classify as
# GEN_OP_CMP in the tracer but have different reg-set shapes, so the
# probe declares ISA-specific specs.
_register_probe('probe_exact_cmp_rr', {
    'x86_64':  {'asm': '"cmpq %%rbx, %%rax"', 'clobbers': '"cc"',
                'opcodes': ['CMP'],
                'insns': [_insn("CMP", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR3"],
                                dst=["REG_FLAGS"])]},
    'aarch64': {'asm': '"cmp x0, x1"', 'clobbers': '"cc"',
                'opcodes': ['CMP'],
                'insns': [_insn("CMP", branch_type="NONE",
                                src=["REG_GPR0", "REG_GPR1"],
                                dst=["REG_FLAGS"])]},
    'riscv64': {'asm': '"slt t0, t1, t2"', 'clobbers': '"t0"',
                'opcodes': ['CMP'],
                'insns': [_insn("CMP", branch_type="NONE",
                                src=["REG_GPR6", "REG_GPR7"],
                                dst=["REG_GPR5"])]},
    'mipsel':  {'asm': '"slt $t0, $t1, $t2"', 'clobbers': '"$t0"',
                'opcodes': ['CMP'],
                'insns': [_insn("CMP", branch_type="NONE",
                                src=["REG_GPR9", "REG_GPR10"],
                                dst=["REG_GPR8"])]},
})

# Plain register-base + zero-offset load.  x86 mov-from-memory is the
# more-specific GEN_OP_MOV classification per the format spec (LOAD is
# the fall-through bucket); aarch64 LDR / riscv64 LD / mipsel LW each
# remain the load-specific mnemonic and classify as GEN_OP_LOAD.
#
# dst_deps=[["load_data[0]"]] asserts the precise "the dst depends
# only on the loaded value, not on the address-mode reg" shape that
# dep_passthrough produces.  Today riscv64 LD / mipsel LW bind
# dep_all_to_all, so the dep mask comes out as 0x3 (both bits set)
# and the probe correctly flags the precision gap until those rows
# get reclassified to dep_passthrough.
_register_probe('probe_exact_load_rm', {
    'x86_64':  {'asm': '"movq (%%rsp), %%rax"', 'clobbers': '"rax"',
                'opcodes': ['MOV'],
                'insns': [_insn("MOV", branch_type="NONE",
                                src=["REG_SP"],
                                dst=["REG_GPR0"],
                                load_addr_deps=[["src_reg[0]"]],
                                dst_deps=[["load_data[0]"]])]},
    'aarch64': {'asm': '"ldr x0, [sp]"', 'clobbers': '"x0"',
                'opcodes': ['LOAD'],
                'insns': [_insn("LOAD", branch_type="NONE",
                                src=["REG_SP"],
                                dst=["REG_GPR0"],
                                load_addr_deps=[["src_reg[0]"]],
                                dst_deps=[["load_data[0]"]])]},
    'riscv64': {'asm': '"ld t0, 0(sp)"', 'clobbers': '"t0"',
                'opcodes': ['LOAD'],
                'insns': [_insn("LOAD", branch_type="NONE",
                                src=["REG_SP"],
                                dst=["REG_GPR5"],
                                load_addr_deps=[["src_reg[0]"]],
                                dst_deps=[["load_data[0]"]])]},
    'mipsel':  {'asm': '"lw $t0, 0($sp)"', 'clobbers': '"$t0"',
                'opcodes': ['LOAD'],
                'insns': [_insn("LOAD", branch_type="NONE",
                                src=["REG_SP"],
                                dst=["REG_GPR8"],
                                load_addr_deps=[["src_reg[0]"]],
                                dst_deps=[["load_data[0]"]])]},
})

# Plain register-base + zero-offset store.  Walker operand order
# across all four ISAs is REG-src first, MEM-base added second, so
# src_regs[] = [VALUE, BASE].  store_addr_deps points at index 1
# (the base); store_data_deps points at index 0 (the value).
_register_probe('probe_exact_store_rm', {
    'x86_64':  {'asm': '"movq %%rax, (%%rsp)"', 'clobbers': '"memory"',
                'opcodes': ['MOV'],
                'insns': [_insn("MOV", branch_type="NONE",
                                src=["REG_GPR0", "REG_SP"],
                                dst=[],
                                store_addr_deps=[["src_reg[1]"]],
                                store_data_deps=[["src_reg[0]"]])]},
    'aarch64': {'asm': '"str x0, [sp]"', 'clobbers': '"memory"',
                'opcodes': ['STORE'],
                'insns': [_insn("STORE", branch_type="NONE",
                                src=["REG_GPR0", "REG_SP"],
                                dst=[],
                                store_addr_deps=[["src_reg[1]"]],
                                store_data_deps=[["src_reg[0]"]])]},
    'riscv64': {'asm': '"sd t0, 0(sp)"', 'clobbers': '"memory"',
                'opcodes': ['STORE'],
                'insns': [_insn("STORE", branch_type="NONE",
                                src=["REG_GPR5", "REG_SP"],
                                dst=[],
                                store_addr_deps=[["src_reg[1]"]],
                                store_data_deps=[["src_reg[0]"]])]},
    'mipsel':  {'asm': '"sw $t0, 0($sp)"', 'clobbers': '"memory"',
                'opcodes': ['STORE'],
                'insns': [_insn("STORE", branch_type="NONE",
                                src=["REG_GPR8", "REG_SP"],
                                dst=[],
                                store_addr_deps=[["src_reg[1]"]],
                                store_data_deps=[["src_reg[0]"]])]},
})

# ============================================================================
# Ambiguity / high-consequence probes.  Each targets an encoding whose
# operand roles, implicit registers, or memop direction are easy to get
# wrong even when the tracer-internal handling "should be trivial" —
# misreads here corrupt consumer dataflow silently.  src/dst are exact
# set assertions; {} entries are unchecked setup instructions.
# ============================================================================

# The stack-push family's store DATA, when the pushed value is not a
# named register operand.  `pushq (%rax)` reads its base register to
# FORM an address and pushes what the load returns; naming the base as
# the stored datum is a false dependency edge that no decoder
# cross-check and no PIN comparison can see (the store's count,
# address, width and value are all correct — only the mask is wrong).
# Two bases, because they failed differently: with a non-SP base the
# store's data named the BASE REGISTER, and with the stack pointer
# itself as the base there was no non-SP source left to name at all,
# so the push declared no store whatsoever.
# The sibling shape on `call`, where the pushed value is the return
# address rather than the indirect target, is covered class-wide by
# the validator's `call_return_store` invariant, which needs no probe
# because a call terminates its basic block.
_register_probe('probe_x86_push_mem', {'x86_64': {
    'asm':      '"movq %%rsp, %%rax\\n\\t"\n'
                '    "pushq (%%rax)\\n\\t"\n'
                '    "addq $8, %%rsp\\n\\t"\n'
                '    "pushq (%%rsp)\\n\\t"\n'
                '    "addq $8, %%rsp"',
    'clobbers': '"rax","memory","cc"',
    'opcodes':  ['PUSH'],
    'insns': [
        {},
        _insn("GEN_OP_PUSH",
              store_data_deps=[["load_data[0]"]]),
        {},
        _insn("GEN_OP_PUSH",
              load_addr_deps=[["src_reg[0]"]],
              store_addr_deps=[["src_reg[0]"]],
              store_data_deps=[["load_data[0]"]]),
        {},
    ]}})

# x86 read-modify-write direction.  `add r,(m)` and `add (m),r` share
# X86_INS_ADD, and Capstone-under-AT&T reverses the operand array vs the
# Intel docs — exactly the conditions under which a load/store direction
# flip slips in.  The store form must carry BOTH a load and a store slot
# and no register destination (flags aside); the load form exactly one
# load slot and a register destination.
_register_probe('probe_x86_rmw_direction', {'x86_64': {
    'asm': '"addq %%rax, (%%rsp)\\n\\t"\n'
           '    "addq (%%rsp), %%rax"',
    'clobbers': '"rax","cc","memory"',
    'opcodes': ['INT_ADD'],
    'insns': [
        _insn("GEN_OP_INT_ADD",
              src=["REG_GPR0", "REG_SP"],
              dst=["REG_FLAGS"],
              load_addr_deps=[["src_reg[1]"]],
              store_addr_deps=[["src_reg[1]"]]),
        # Load form: the MEM base walks first, so SP is src_reg[0]
        # (the store form above walks the value reg first).
        _insn("GEN_OP_INT_ADD",
              src=["REG_GPR0", "REG_SP"],
              dst=["REG_GPR0", "REG_FLAGS"],
              load_addr_deps=[["src_reg[0]"]],
              store_addr_deps=[],
              store_data_deps=[]),
    ]}})

# x86 cmpxchg: implicit RAX is compared (read) and conditionally
# written; the memory store only fires on success, but the template's
# static shape still carries both slots.  LOCK must set the atomic flag.
_register_probe('probe_x86_cmpxchg', {'x86_64': {
    'asm': '"movq $5, (%%rsp)\\n\\t"\n'
           '    "movq $5, %%rax\\n\\t"\n'
           '    "movq $9, %%rbx\\n\\t"\n'
           '    "lock cmpxchgq %%rbx, (%%rsp)"',
    'clobbers': '"rax","cc","memory"',
    'opcodes': ['XCHG'],
    'insns': [
        {}, {}, {},
        _insn("GEN_OP_XCHG",
              src=["REG_GPR0", "REG_GPR3", "REG_SP"],
              dst=["REG_GPR0", "REG_FLAGS"],
              insn_flags=["CST_INSN_FLAG_ATOMIC"]),
    ]}})

# aarch64 pre/post-index writeback.  Two invariants, by design:
#   1. opcode = GEN_OP_INT_ADD for EVERY writeback form, load or store
#      alike — the opcode carries the substantial (address-ALU)
#      operation; the memory side rides in the memop stream and its
#      delay belongs to the consumer's memory model.  An asymmetric
#      writeback detector once let LOADS keep GEN_OP_LOAD here.
#   2. the base register is BOTH an address source and a destination;
#      dropping the writeback dst breaks every downstream dependency
#      through the base.
_register_probe('probe_arm_writeback_addr', {'aarch64': {
    'asm': '"sub sp, sp, #64\\n\\t"\n'
           '    "mov x9, sp\\n\\t"\n'
           '    "ldr x0, [x9], #8\\n\\t"\n'
           '    "str x1, [x9, #8]!\\n\\t"\n'
           '    "ldp x2, x3, [x9], #16\\n\\t"\n'
           '    "add sp, sp, #64"',
    'clobbers': '"x0","x1","x2","x3","x9","memory"',
    'opcodes': ['INT_ADD'],
    'insns': [
        {}, {},
        _insn("GEN_OP_INT_ADD",
              src=["REG_GPR9"],
              dst=["REG_GPR0", "REG_GPR9"],
              load_addr_deps=[["src_reg[0]"]]),
        _insn("GEN_OP_INT_ADD",
              src=["REG_GPR1", "REG_GPR9"],
              dst=["REG_GPR9"]),
        _insn("GEN_OP_INT_ADD",
              src=["REG_GPR9"],
              dst=["REG_GPR2", "REG_GPR3", "REG_GPR9"]),
        {},
    ]}})

# mips lwl/lwr: the unaligned-word pair partially writes the
# destination, so the dst register is ALSO a source — and this sits in
# the same Capstone access-flag territory as the known MSA/unaligned
# workarounds in disas/capstone.c (regression-pins them).
_register_probe('probe_mips_lwl_lwr', {'mipsel': {
    'asm': '"addiu $sp, $sp, -16\\n\\t"\n'
           '    "sw $t1, 0($sp)\\n\\t"\n'
           '    "sw $t1, 4($sp)\\n\\t"\n'
           '    "addiu $t2, $sp, 1\\n\\t"\n'
           '    "lwr $t0, 0($t2)\\n\\t"\n'
           '    "lwl $t0, 3($t2)\\n\\t"\n'
           '    "addiu $sp, $sp, 16"',
    'clobbers': '"$t0","$t2","memory"',
    'opcodes': ['LOAD'],
    'insns': [
        {}, {}, {}, {},
        _insn("GEN_OP_LOAD",
              src=["REG_GPR8", "REG_GPR10"],
              dst=["REG_GPR8"]),
        _insn("GEN_OP_LOAD",
              src=["REG_GPR8", "REG_GPR10"],
              dst=["REG_GPR8"]),
        {},
    ]}})

# Zero-register semantics.  riscv x0 / mips $zero as a destination is
# architecturally discarded but must still be identified as REG_ZERO;
# aarch64 encodes XZR and SP as the same register number 31, with the
# role decided per instruction — the classic disambiguation trap.
_register_probe('probe_zero_reg', {
    'aarch64': {
        'asm': '"orr x9, xzr, x10\\n\\t"\n'
               '    "add x9, sp, #16"',
        'clobbers': '"x9"',
        'insns': [
            # Capstone prints the alias (mov x9, x10): the XZR source
            # disappears.  Pin it — XZR is constant zero, nothing lost.
            {"src": ["REG_GPR10"], "dst": ["REG_GPR9"]},
            {"src": ["REG_SP"], "dst": ["REG_GPR9"]},
        ]},
    'riscv64': {
        'asm': '"add x0, t0, t1\\n\\t"\n'
               '    "add t2, x0, t0"',
        'clobbers': '',
        'insns': [
            {"src": ["REG_GPR5", "REG_GPR6"], "dst": ["REG_ZERO"]},
            # Capstone prints the alias (mv t2, t0): the x0 source
            # disappears from the operand list.  Pin that behaviour —
            # x0 is the constant zero, so no dependency is lost.
            {"src": ["REG_GPR5"], "dst": ["REG_GPR7"]},
        ]},
    'mipsel': {
        'asm': '"addu $zero, $t0, $t1\\n\\t"\n'
               '    "addu $t3, $zero, $t0"',
        'clobbers': '"$t3"',
        'insns': [
            {"src": ["REG_GPR8", "REG_GPR9"], "dst": ["REG_ZERO"]},
            {"src": ["REG_ZERO", "REG_GPR8"], "dst": ["REG_GPR11"]},
        ]},
})

# Implicit accumulators: x86 cqo (RAX -> RDX sign spill), one-operand
# mulq (RDX:RAX widening destination), shift-by-CL (implicit count
# register); mips mult/mfhi/mflo (the HI:LO accumulator never appears
# in the encoding's operand fields at all).
_register_probe('probe_implicit_acc', {
    'x86_64': {
        'asm': '"movq $3, %%rax\\n\\t"\n'
               '    "cqo\\n\\t"\n'
               '    "movq $5, %%rbx\\n\\t"\n'
               '    "mulq %%rbx\\n\\t"\n'
               '    "movq $2, %%rcx\\n\\t"\n'
               '    "shlq %%cl, %%rbx"',
        'clobbers': '"rax","rbx","rcx","rdx","cc"',
        'opcodes': ['INT_MUL', 'SHL'],
        'insns': [
            {},
            # Capstone marks RAX written too (conservative rw on the
            # implicit pair); the trace follows Capstone.
            {"src": ["REG_GPR0"], "dst": ["REG_GPR0", "REG_GPR2"]},
            {},
            {"src": ["REG_GPR0", "REG_GPR3"],
             "dst": ["REG_GPR0", "REG_GPR2", "REG_FLAGS"]},
            {},
            {"src": ["REG_GPR1", "REG_GPR3"],
             "dst": ["REG_GPR3", "REG_FLAGS"]},
        ]},
    'mipsel': {
        'asm': '"li $t1, 7\\n\\t"\n'
               '    "li $t2, 9\\n\\t"\n'
               '    "mult $t1, $t2\\n\\t"\n'
               '    "mfhi $t3\\n\\t"\n'
               '    "mflo $t4"',
        'clobbers': '"$t1","$t2","$t3","$t4","hi","lo"',
        'opcodes': ['INT_MUL'],
        'insns': [
            {}, {},
            {"src": ["REG_GPR9", "REG_GPR10"], "dst": ["REG_ACC0"]},
            {"src": ["REG_ACC0"], "dst": ["REG_GPR11"]},
            {"src": ["REG_ACC0"], "dst": ["REG_GPR12"]},
        ]},
})

