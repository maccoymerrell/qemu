/*
 * ChampSim Tracer -- the memop-impossible check's exemption list.
 *
 * ONE LIST, IN ONE PLACE, INCLUDED BY BOTH SIDES.  The check exists in two
 * copies: an ONLINE one at emit (champsim_tracer_mem_access_recorder.cc,
 * note_impossible_slot()) and an OFFLINE one in the acceptance tool
 * (tools/cst_lint.h, AttributionLint).  Each used to carry its own list and
 * each said in its own comment that it mirrored the other.  They did not:
 * the online copy additionally exempted GEN_OP_LOAD, GEN_OP_STORE,
 * GEN_OP_VEC_LOAD, GEN_OP_VEC_STORE and atomics, so it passed what the
 * offline one failed -- 990 of one trace's 2,397 offline firings were
 * exactly that gap, and nothing could see the divergence because each check
 * was reading its own list (FINDING 85-A(i)).
 *
 * The lists are now this file, and a future divergence has to be written
 * here where both sides read it.
 *
 * WHICH SIDE WAS RIGHT, and why the explicit memory classes are NOT here.
 * A GEN_OP_STORE whose template carries no static store slot is a decode
 * failure the check exists to surface, and exempting the class hides
 * exactly the instructions worth looking at.  x86_64 `fxsave64 0x40(%rax)`
 * was the witness: GEN_OP_STORE, max_dep_loads == max_dep_stores == 0, 55
 * memops per execution.  The online exemption made it invisible; the
 * offline check fired on it; the store slot it should have carried is a
 * real gap and was closed at its source rather than by widening this list.
 *
 * WHAT IS HERE, and the reason each earns it.  These classes record a
 * memop that the STATIC operand layout genuinely does not carry:
 *
 *   PREFETCH / CACHE_FLUSH / TLB_FLUSH / FENCE
 *       the synthetic-EA classes.  record_synthetic_load() mints a
 *       load-style memop from the effective address even though no operand
 *       of the instruction is a data access, so a 0/0 template is the
 *       correct one.
 *
 *   PUSH / POP / RET
 *       the x86 implicit-stack corner encodings -- `pop %rsp`, `iretq` --
 *       whose stack traffic is not an encoded operand and which therefore
 *       reach the wire with no static slot.
 *
 * THE SECOND CLAUSE IS NOT AN OPCODE and so is not in this macro: an
 * instruction that writes a SEGMENT register (REG_SEG0 .. REG_SEG0 + 5) is
 * exempt too, because the descriptor fetch QEMU's segment-load helper
 * performs is that mov's own load.  Both sides implement it -- the plugin
 * over its generic-id enum, the tool over the trace's own register map --
 * because they reach the register list by different routes; the RULE is
 * stated once, here.
 *
 * Author: Maccoy Merrell.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_CST_MEM_LINT_EXEMPT_H
#define CHAMPSIM_TRACER_CST_MEM_LINT_EXEMPT_H

/*
 * X-macro over the exempt generic opcodes, by NAME.
 *
 * By name because the two consumers spell the same class differently: the
 * plugin has the enumerator, and the offline tool resolves the class out of
 * the trace's own opcode map so a renumbering stays harmless.  The token is
 * the enumerator on one side and stringified on the other, and both come
 * from this one list.
 */
#define CST_MEM_IMPOSSIBLE_EXEMPT_OPCODES(X)                                  \
    X(GEN_OP_PREFETCH)                                                        \
    X(GEN_OP_CACHE_FLUSH)                                                     \
    X(GEN_OP_TLB_FLUSH)                                                       \
    X(GEN_OP_FENCE)                                                           \
    X(GEN_OP_PUSH)                                                            \
    X(GEN_OP_POP)                                                             \
    X(GEN_OP_RET)

#endif /* CHAMPSIM_TRACER_CST_MEM_LINT_EXEMPT_H */
