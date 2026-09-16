#!/usr/bin/env python3
"""The Zcmp/Zcmt enumeration profile for the riscv64 denominator.

WHY THIS IS A SECOND PROFILE AND NOT EIGHT MORE ROWS OF THE FIRST
----------------------------------------------------------------
Zcmp and Zcmt occupy the compressed FP-store encoding space.  They are
MUTUALLY EXCLUSIVE with Zcd, which is what C+D implies on RV64GC, and QEMU
enforces exactly that:

    target/riscv/tcg/tcg-cpu.c:767
        if (cpu->cfg.ext_zcd && (cpu->cfg.ext_zcmp || cpu->cfg.ext_zcmt)) {
            error_setg(errp, "Zcmp/Zcmt extensions are incompatible with "
                             "Zcd extension");

So no single guest, and no single decoder configuration, has both.  Setting
Capstone's CS_MODE_RISCV_ZCMP_ZCMT_ZCE on top of the RV64GC mode the base
enumeration uses rewrites 331 already-correct decodes (measured; see the
kIsaTable comment in tools/isaxcheck.cc) -- `cm.push`'s representative
encoding 42b8 decodes as `fsd fa6, 0x30(sp)` in the base profile and as
`cm.push {ra}, -0x10` here.  One enumeration pass cannot carry both, which is
the whole reason these eight opcodes were sitting in excluded.tsv.

BUT THEY ARE NOT OUT OF THE TRACER'S SCOPE, so excluding them would be a
false statement about what the tracer covers.  cap_mode_riscv()
(champsim_tracer_mnemonics_riscv.h:42) reads Tag_RISCV_arch out of the guest
ELF and turns a `zcmp` / `zcmt` / `zce` token into
CS_MODE_RISCV_ZCMP_ZCMT_ZCE.  A guest built for Zcmp is traced with the
Zcmp decoder, and these eight opcodes are then live.  They belong in the
denominator; they belong in a second pass.

THE REFERENCE
-------------
Sail-RISCV has no clause for either extension, so rank 1 is silent and
cannot be made to speak.  Rank 2 (LLVM MC) decodes all eight once told
`+zcmp,+zcmt` but models none of their register traffic: its MCInstrDesc
carries no operand and no implicit def/use for the register list, so it
reports RD{} WR{} for cm.push exactly as Capstone does.  A reference that
agrees with the subject by being equally empty measures nothing.

The reference below is therefore QEMU's own translation (R6, the same leg
the mipsel harness uses for its trap footprint and FCSR classes), read out
of target/riscv/insn_trans/trans_rvzce.c.inc and target/riscv/zce_helper.c
with the line cited per row.  R6's premise holds here: QEMU implements these
instructions fully, and every register it touches is named in the TCG the
translator emits.
"""

# Representative encodings, little-endian bytes, verified by decoding each one
# with `isaxcheck --isa=riscv64 --cs-mode-add=zcmp`.  rlist=4 is the shortest
# legal list ({ra}); the list width is the C3 generic field of these opcodes
# (one row covers every rlist), and spimm likewise.
ROWS = [
    dict(
        opcode_id='ZCMP:CM_PUSH', mnemonic='cm.push', hex='42b8',
        ext='Zcmp', family='Zcmp', asm='cm.push {ra}, -0x10',
        ref_src=['REG_SP', 'REG_LR'],
        ref_dst=['REG_SP'],
        cite='trans_rvzce.c.inc:221-252 trans_cm_push: dest_gpr(xSP) then '
             'subi -> sp is read; get_gpr(i) for each register in the rlist '
             'bitmap -> ra is read; qemu_st_tl per register; '
             'gen_set_gpr(xSP) -> sp is written',
    ),
    dict(
        opcode_id='ZCMP:CM_POP', mnemonic='cm.pop', hex='42ba',
        ext='Zcmp', family='Zcmp', asm='cm.pop {ra}, 0x10',
        ref_src=['REG_SP'],
        ref_dst=['REG_SP', 'REG_LR'],
        cite='trans_rvzce.c.inc:166-219 gen_pop(ret=false): dest_gpr(xSP) '
             'read for the address, qemu_ld_tl + gen_set_gpr(i) writes each '
             'register in the rlist bitmap, gen_set_gpr(xSP) writes sp',
    ),
    dict(
        opcode_id='ZCMP:CM_POPRET', mnemonic='cm.popret', hex='42be',
        ext='Zcmp', family='Zcmp', asm='cm.popret {ra}, 0x10',
        ref_src=['REG_SP'],
        ref_dst=['REG_SP', 'REG_LR'],
        cite='trans_rvzce.c.inc:166-219 gen_pop(ret=true).  ra is NOT a '
             'source: rlist >= 4 always contains ra (decode_push_pop_list '
             ':148-156), so this instruction defines ra from memory before '
             'the get_gpr(xRA) at :205 reads it back for the jump -- no '
             'prior writer, so no edge a regfile must respect (R7)',
    ),
    dict(
        opcode_id='ZCMP:CM_POPRETZ', mnemonic='cm.popretz', hex='42bc',
        ext='Zcmp', family='Zcmp', asm='cm.popretz {ra}, 0x10',
        ref_src=['REG_SP'],
        ref_dst=['REG_SP', 'REG_LR', 'REG_GPR10'],
        cite='trans_rvzce.c.inc:166-219 gen_pop(ret=true, ret_val=true); '
             ':200-202 gen_set_gpr(xA0, ctx->zero) adds the a0 write',
    ),
    dict(
        opcode_id='ZCMP:CM_MVSA01', mnemonic='cm.mvsa01', hex='26ac',
        ext='Zcmp', family='Zcmp', asm='cm.mvsa01 s0, s1',
        ref_src=['REG_GPR10', 'REG_GPR11'],
        ref_dst=['REG_FP_REG', 'REG_GPR9'],
        cite='trans_rvzce.c.inc:282-296 trans_cm_mvsa01: get_gpr(xA0), '
             'get_gpr(xA1) are the sources; gen_set_gpr(a->rs1), '
             'gen_set_gpr(a->rs2) are the destinations.  a0/a1 -> s0/s1, '
             'so the direction is the opposite of cm.mva01s',
    ),
    dict(
        opcode_id='ZCMP:CM_MVA01S', mnemonic='cm.mva01s', hex='66ac',
        ext='Zcmp', family='Zcmp', asm='cm.mva01s s0, s1',
        ref_src=['REG_FP_REG', 'REG_GPR9'],
        ref_dst=['REG_GPR10', 'REG_GPR11'],
        cite='trans_rvzce.c.inc:270-280 trans_cm_mva01s: get_gpr(a->rs1), '
             'get_gpr(a->rs2) are the sources; gen_set_gpr(xA0), '
             'gen_set_gpr(xA1) are the destinations',
    ),
    dict(
        opcode_id='ZCMT:CM_JT', mnemonic='cm.jt', hex='02a0',
        ext='Zcmt', family='Zcmt', asm='cm.jt 0',
        ref_src=['REG_SYS'],
        ref_dst=[],
        cite='trans_rvzce.c.inc:298-318 trans_cm_jalt -> helper cm_jalt '
             '(zce_helper.c:25-56) reads env->jvt for the table base and '
             'mode.  JVT is CSR 0x017, which the harness folds to REG_SYS. '
             'index < 32 so no link register is written.  The jump-table '
             'entry is fetched with cpu_ld*_code, i.e. from code space, '
             'which is outside the memop scope on both sides',
    ),
    dict(
        opcode_id='ZCMT:CM_JALT', mnemonic='cm.jalt', hex='82a0',
        ext='Zcmt', family='Zcmt', asm='cm.jalt 0x20',
        ref_src=['REG_SYS'],
        ref_dst=['REG_LR'],
        cite='trans_rvzce.c.inc:298-318 trans_cm_jalt, same env->jvt read; '
             ':310-315 index >= 32 so gen_set_gpr(xRA, succ_pc) writes the '
             'link register',
    ),
]

# The two decoder legs have to be told the same thing or the pass compares
# one ISA against another.  Capstone: one mode bit.  LLVM: the RV64 base
# without the +c that would imply Zcd, plus the Zc* subsets that Zcmp needs.
CS_MODE_ADD = 'zcmp'
LLVM_MATTR = ('+64bit,+i,+m,+a,+f,+d,+zca,+zcb,+zcmp,+zcmt,'
              '+zicsr,+zifencei')

PROFILE = 'zcmp'
BASE_PROFILE = 'rv64gc'
