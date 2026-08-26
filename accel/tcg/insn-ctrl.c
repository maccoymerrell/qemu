/*
 * Per-instruction control transfer, derived from the IR the target's
 * translator emitted.  See include/exec/insn-ctrl.h for what this is and
 * why the op range is bounded the way it is.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op-common.h"
#include "qemu/plugin.h"
#include "qemu/qemu-plugin.h"
#include "exec/insn-ctrl.h"

#ifdef CONFIG_PLUGIN

/*
 * Where a temp's value came from, propagated FORWARD across the ops of one
 * instruction.  Forward with overwrite is the right direction and not a
 * shortcut: TCG temps are reused within an instruction, so the origin of a
 * temp is whatever the most recent op that wrote it made of its inputs,
 * which is exactly what a forward pass with assignment computes.
 */
typedef enum {
    ORIG_NONE = 0,
    ORIG_CONST,     /* a compile-time constant, value in .val            */
    ORIG_REG,       /* read from TCG global .reg, unmodified or derived  */
    ORIG_LOAD,      /* a guest load produced it; .reg is the ADDRESS reg */
} OriginKind;

typedef struct {
    uint8_t  kind;
    int32_t  reg;
    uint64_t val;
} Origin;

/*
 * The program-counter global, learned rather than named.
 *
 * A direct branch lowers to `goto_tb $n; <assign the successor constant to
 * the PC>; exit_tb`, so the global assigned a constant between a goto_tb and
 * its exit_tb IS the program counter, on any target, and the first direct
 * branch translated says which one it is.  Learning it beats a table of
 * per-target names for the reason the whole arc exists: a name is something
 * somebody wrote down, and this is something the machine did.
 *
 * One target per process, so one cached index.  -1 until a direct branch has
 * been seen; until then indirect provenance is reported INCOMPLETE rather
 * than guessed at.
 */
static int32_t pc_global = -1;

static inline bool temp_is_global(const TCGContext *s, const TCGTemp *ts)
{
    return (size_t)(ts - s->temps) < (size_t)s->nb_globals;
}

static Origin origin_of(const TCGContext *s, const Origin *orig,
                        const TCGTemp *ts)
{
    size_t i = ts - s->temps;
    Origin o;

    if (ts->kind == TEMP_CONST) {
        o.kind = ORIG_CONST;
        o.reg = -1;
        o.val = (uint64_t)ts->val;
        return o;
    }
    if (temp_is_global(s, ts)) {
        /*
         * A global read is a register read even if something wrote the same
         * global earlier in this instruction: the tracked origin is what a
         * previous op made of it, and for provenance the register name is
         * the more specific answer.  Prefer the tracked one only when it
         * names a DIFFERENT register, which is what `mov pc, lr` produces.
         */
        if (orig[i].kind == ORIG_REG || orig[i].kind == ORIG_LOAD) {
            return orig[i];
        }
        o.kind = ORIG_REG;
        o.reg = (int32_t)i;
        o.val = 0;
        return o;
    }
    return orig[i];
}

/* Classify one instruction's op range, [first, last] inclusive. */
static void ctrl_one(struct qemu_plugin_insn *insn, Origin *orig,
                     size_t norig)
{
    TCGContext *s = tcg_ctx;
    const TCGOp *first = insn->ctrl_first_op;
    const TCGOp *last = insn->ctrl_last_op;
    const TCGOp *end;
    const TCGOp *op;
    /*
     * Program order, in up to two pieces.  The second is the range of ops a
     * LATER instruction's translate_insn() emitted on this one's behalf --
     * a MIPS branch's transfer, emitted by gen_branch() at the end of the
     * delay slot.  See ctrl_borrow_first in include/qemu/plugin.h.
     */
    struct { const TCGOp *first, *last; } seg[2];
    unsigned nseg = 0, si;
    uint32_t flags = QEMU_PLUGIN_CTRL_VALID;
    /*
     * The instruction's ARCHITECTURAL continuation: the address a call it
     * makes returns to, and the address its not-taken edge goes to.  Usually
     * the next instruction, but a delay-slot branch's continuation is past
     * the SLOT -- the slot is part of the branch's execution -- and the
     * translator named the slot, so the extent is read off it rather than
     * assumed.
     */
    const struct qemu_plugin_insn *lender = insn->ctrl_borrow_lender;
    uint64_t fallthrough = lender ? lender->vaddr + lender->len
                                  : insn->vaddr + insn->len;
    uint64_t target = 0;
    bool have_target = false;
    int32_t tgt_reg = -1, addr_reg = -1;
    unsigned n_goto_tb = 0;
    bool in_goto_tb = false;
    bool saw_goto_ptr = false, saw_exit_tb = false;
    bool direct_by_value = false;
    int32_t link_reg = -1, link_addr_reg = -1;
    unsigned goto_tb_idx_seen = 0;   /* bitmap of the indices used */

    insn->ctrl_flags = 0;
    insn->ctrl_target = 0;
    insn->ctrl_target_reg = -1;
    insn->ctrl_addr_reg = -1;
    insn->ctrl_link_reg = -1;
    insn->ctrl_link_addr_reg = -1;

    if (insn->ctrl_deferred && !insn->ctrl_borrow_first) {
        /*
         * The block ended between this branch and its delay slot, so the ops
         * that perform the transfer were never emitted here.  It IS a
         * transfer -- the translator said so -- but this block cannot say
         * what kind, and inventing one from the re-dispatch tb_stop emitted
         * would publish the fall-through as the branch's target.
         */
        flags |= QEMU_PLUGIN_CTRL_PENDING;
    }
    if (insn->ctrl_foreign) {
        /*
         * Ops emitted during this instruction performed a transfer belonging
         * to an instruction outside this block.  They are excluded below --
         * ctrl_last_op was closed before them -- and the exclusion is
         * reported rather than left to look like an absence.
         */
        flags |= QEMU_PLUGIN_CTRL_FOREIGN;
    }

    if (!first || !last) {
        insn->ctrl_flags = flags;
        return;
    }

    seg[nseg].first = first;
    seg[nseg].last = last;
    nseg++;
    if (insn->ctrl_borrow_first && insn->ctrl_borrow_last) {
        seg[nseg].first = insn->ctrl_borrow_first;
        seg[nseg].last = insn->ctrl_borrow_last;
        nseg++;
    }

    /*
     * ONE origin state across both segments, and the intervening delay
     * slot's ops deliberately skipped.  That is not a shortcut: MIPS reads a
     * branch's target register AT THE BRANCH, so the provenance the transfer
     * ops should be read against is the one the branch left, not the one the
     * slot went on to overwrite.  `jr $ra` in a block whose slot writes $ra
     * still returns through the value $ra held at the branch, and this walk
     * says so.
     */
    memset(orig, 0, norig * sizeof(orig[0]));

    for (si = 0; si < nseg; si++) {
        /*
         * The range is HALF-OPEN against the op after @last, not closed
         * against @last, and that is not a style choice.  A closed loop that
         * tests
         * `op == last` at the bottom never terminates when @last is not
         * actually reachable from @first -- the ordinary case for an
         * instruction
         * whose transfer is emitted in tb_stop(), where the tail at
         * plugin_gen_insn_end() IS the range's first op.  It then walks to the
         * end of the block and reads every following instruction's ops as this
         * one's, which reads as a branch on instructions that are not.
         * Measured: it put a control transfer on `nop`.
         */
        end = QTAILQ_NEXT(seg[si].last, link);
        for (op = QTAILQ_NEXT(seg[si].first, link); op && op != end;
             op = QTAILQ_NEXT(op, link)) {
            const TCGOpDef *def = &tcg_op_defs[op->opc];
            unsigned nb_oargs, nb_iargs;

            switch (op->opc) {
            case INDEX_op_goto_tb:
                n_goto_tb++;
                goto_tb_idx_seen |= 1u << (op->args[0] & 31);
                in_goto_tb = true;
                break;

            case INDEX_op_goto_ptr:
                saw_goto_ptr = true;
                /*
                 * The target expression is whatever was last assigned to the PC
                 * global.  Its origin has been propagated forward to here.
                 */
                if (pc_global >= 0 && (size_t)pc_global < norig) {
                    Origin o = orig[pc_global];
                    if (o.kind == ORIG_REG) {
                        tgt_reg = o.reg;
                    } else if (o.kind == ORIG_LOAD) {
                        flags |= QEMU_PLUGIN_CTRL_TGT_LOAD;
                        addr_reg = o.reg;
                    } else if (o.kind == ORIG_CONST) {
                        /*
                         * A COMPILE-TIME successor reached through goto_ptr.
                         * goto_tb is a CHAINING optimisation, not a semantic:
                         * translator_use_goto_tb() declines whenever the target
                         * is outside the block's page, and the translator then
                         * emits the same constant into the PC and dispatches
                         * through lookup_and_goto_ptr instead.  Measured on
                         * glibc-linked guests, that is the COMMON case --
                         * every aarch64 `bl`, every x86 `callq`, every riscv
                         * `jal` in the benchmark took it.  Reading goto_ptr
                         * as "indirect"
                         * would call all of them computed branches.  What makes
                         * a transfer direct is that its target is a constant,
                         * and that is what is tested.
                         */
                        target = o.val;
                        have_target = true;
                        if (target == insn->vaddr) {
                            flags |= QEMU_PLUGIN_CTRL_SELF;
                        }
                        direct_by_value = true;
                    } else {
                        flags |= QEMU_PLUGIN_CTRL_INCOMPLETE;
                    }
                } else {
                    flags |= QEMU_PLUGIN_CTRL_INCOMPLETE;
                }
                break;

            case INDEX_op_exit_tb:
                saw_exit_tb = true;
                in_goto_tb = false;
                break;

            default:
                break;
            }

            if (op->opc == INDEX_op_call) {
                nb_oargs = TCGOP_CALLO(op);
                nb_iargs = TCGOP_CALLI(op);
            } else {
                nb_oargs = def->nb_oargs;
                nb_iargs = def->nb_iargs;
            }

            /*
             * LINK, and the PC global's identity, both come out of the ordinary
             * operand walk rather than a per-op special case.
             */
            if (op->opc == INDEX_op_qemu_st_i32 ||
                op->opc == INDEX_op_qemu_st_i64 ||
                op->opc == INDEX_op_qemu_st8_i32 ||
                op->opc == INDEX_op_qemu_st_i128) {
                /* args[0] is the data being stored. */
                const TCGTemp *dts = arg_temp(op->args[0]);
                Origin o = origin_of(s, orig, dts);
                if (o.kind == ORIG_CONST && o.val == fallthrough) {
                    const TCGTemp *ats = arg_temp(op->args[1]);
                    Origin ao = ats ? origin_of(s, orig, ats)
                                    : (Origin){ ORIG_NONE, -1, 0 };
                    flags |= QEMU_PLUGIN_CTRL_LINK;
                    if (ao.kind == ORIG_REG) {
                        link_addr_reg = ao.reg;
                    }
                }
            }

            /* Propagate origins across this op's outputs. */
            if (nb_oargs > 0 && op->opc != INDEX_op_call) {
                Origin src = { ORIG_NONE, -1, 0 };
                bool src_set = false;

                for (unsigned k = 0; k < nb_iargs; k++) {
                    const TCGTemp *its = arg_temp(op->args[nb_oargs + k]);
                    Origin o;

                    if (!its) {
                        continue;
                    }
                    o = origin_of(s, orig, its);
                    if (o.kind == ORIG_NONE) {
                        continue;
                    }
                    if (!src_set) {
                        src = o;
                        src_set = true;
                    } else if (o.kind == ORIG_REG && src.kind == ORIG_CONST) {
                        /* a register input outranks a constant one */
                        src = o;
                    }
                }

                /*
                 * A load's result is a load, not the origin of its address --
                 * but the address register is worth keeping, because it is what
                 * separates `ret` (through the stack pointer) from an indirect
                 * jump through a loaded function pointer.
                 */
                if (op->opc == INDEX_op_qemu_ld_i32 ||
                    op->opc == INDEX_op_qemu_ld_i64 ||
                    op->opc == INDEX_op_qemu_ld_i128) {
                    const TCGTemp *ats = arg_temp(op->args[nb_oargs]);
                    Origin ao = ats ? origin_of(s, orig, ats)
                                    : (Origin){ ORIG_NONE, -1, 0 };
                    src.kind = ORIG_LOAD;
                    src.reg = ao.kind == ORIG_REG ? ao.reg : -1;
                    src.val = 0;
                    src_set = true;
                } else if (nb_iargs == 0) {
                    src.kind = ORIG_NONE;
                    src.reg = -1;
                    src.val = 0;
                }

                for (unsigned k = 0; k < nb_oargs; k++) {
                    const TCGTemp *ots = arg_temp(op->args[k]);
                    size_t oi;

                    if (!ots) {
                        continue;
                    }
                    oi = ots - s->temps;
                    if (oi >= norig) {
                        continue;
                    }
                    orig[oi] = src_set ? src : (Origin){ ORIG_NONE, -1, 0 };

                    /*
                     * A constant assigned to a global between a goto_tb and its
                     * exit_tb is the successor address, and the global it was
                     * assigned to is the program counter.
                     */
                    if (in_goto_tb && temp_is_global(s, ots) &&
                        src_set && src.kind == ORIG_CONST) {
                        if (pc_global < 0) {
                            pc_global = (int32_t)oi;
                        }
                        if ((int32_t)oi == pc_global) {
                            if (src.val == insn->vaddr) {
                                flags |= QEMU_PLUGIN_CTRL_SELF;
                            }
                            if (!have_target || target == fallthrough) {
                                target = src.val;
                                have_target = true;
                            }
                        }
                    }

                    /*
                     * LINK through a register: the fall-through address, as a
                     * constant, assigned to a guest register.  Excluding the PC
                     * itself, which every direct branch assigns.
                     */
                    if (temp_is_global(s, ots) && src_set &&
                        src.kind == ORIG_CONST && src.val == fallthrough &&
                        (int32_t)oi != pc_global) {
                        flags |= QEMU_PLUGIN_CTRL_LINK;
                        link_reg = (int32_t)oi;
                    }
                }
            } else if (op->opc == INDEX_op_call) {
                /* A helper's outputs have no origin this walk can state. */
                for (unsigned k = 0; k < nb_oargs; k++) {
                    const TCGTemp *ots = arg_temp(op->args[k]);
                    size_t oi = ots ? (size_t)(ots - s->temps) : norig;
                    if (oi < norig) {
                        orig[oi] = (Origin){ ORIG_NONE, -1, 0 };
                    }
                }
            }
        }
    }

    if (n_goto_tb || saw_goto_ptr) {
        flags |= QEMU_PLUGIN_CTRL_TRANSFER;
        if (n_goto_tb || direct_by_value) {
            flags |= QEMU_PLUGIN_CTRL_DIRECT;
        }
        if (saw_goto_ptr && !direct_by_value) {
            flags |= QEMU_PLUGIN_CTRL_INDIRECT;
        }
        /*
         * Two statically-known successors means the instruction chose.  So
         * does one static successor beside a computed one.  Counting DISTINCT
         * goto_tb indices rather than goto_tb ops is deliberate: QEMU emits
         * one per edge and gives each edge its own index, so a repeated index
         * is one edge reached twice, not two edges.
         */
        if (ctpop32(goto_tb_idx_seen) >= 2 ||
            (n_goto_tb && saw_goto_ptr)) {
            flags |= QEMU_PLUGIN_CTRL_CONDITIONAL;
        }
    } else if (saw_exit_tb) {
        flags |= QEMU_PLUGIN_CTRL_NOCHAIN;
    }

    insn->ctrl_flags = flags;
    insn->ctrl_target = have_target ? target : 0;
    insn->ctrl_target_reg = tgt_reg;
    insn->ctrl_addr_reg = addr_reg;
    insn->ctrl_link_reg = link_reg;
    insn->ctrl_link_addr_reg = link_addr_reg;
}

/*
 * CST_CTRL_DUMP=<path>: the op range each instruction was classified from,
 * and the classification.  A walk over an op list is not something a count
 * can be debugged from -- the range being wrong looks exactly like the
 * classifier being wrong -- so the range itself is dumpable.
 */
static FILE *ctrl_dump;
static bool ctrl_dump_tried;

static void ctrl_emit_dump(const struct qemu_plugin_insn *insn)
{
    const TCGOp *op, *end;

    if (!ctrl_dump_tried) {
        const char *path = getenv("CST_CTRL_DUMP");
        ctrl_dump_tried = true;
        if (path) {
            ctrl_dump = fopen(path, "w");
        }
    }
    if (!ctrl_dump) {
        return;
    }
    fprintf(ctrl_dump, "INSN %016" PRIx64 " len=%u flags=%08x target=%"
            PRIx64 " treg=%d areg=%d\n", (uint64_t)insn->vaddr, insn->len,
            insn->ctrl_flags, insn->ctrl_target, insn->ctrl_target_reg,
            insn->ctrl_addr_reg);
    if (!insn->ctrl_first_op || !insn->ctrl_last_op) {
        fprintf(ctrl_dump, "   (no range)\n");
        return;
    }
    end = QTAILQ_NEXT((const TCGOp *)insn->ctrl_last_op, link);
    for (op = QTAILQ_NEXT((const TCGOp *)insn->ctrl_first_op, link);
         op && op != end; op = QTAILQ_NEXT(op, link)) {
        fprintf(ctrl_dump, "   %s\n", tcg_op_defs[op->opc].name);
    }
    fflush(ctrl_dump);
}

void insn_ctrl_classify(struct qemu_plugin_tb *ptb)
{
    static Origin *orig;
    static size_t orig_n;
    TCGContext *s = tcg_ctx;
    size_t need = s->nb_temps;

    if (need > orig_n) {
        orig = g_renew(Origin, orig, need);
        orig_n = need;
    }

    for (size_t i = 0; i < ptb->n; i++) {
        struct qemu_plugin_insn *insn = g_ptr_array_index(ptb->insns, i);
        ctrl_one(insn, orig, need);
        ctrl_emit_dump(insn);
        /*
         * The op pointers are live only until plugin_gen_inject() rewrites
         * the list.  Dropping them here means a stale range can never be
         * walked, rather than relying on the next translation to overwrite
         * them.
         */
        insn->ctrl_first_op = NULL;
        insn->ctrl_last_op = NULL;
        insn->ctrl_borrow_first = NULL;
        insn->ctrl_borrow_last = NULL;
        insn->ctrl_borrow_lender = NULL;
    }
}

#endif /* CONFIG_PLUGIN */
