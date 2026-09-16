/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * A helper's argument shape, taken from the target's own DEF_HELPER lines.
 *
 * The reader meets a helper call as one edge and its arguments as temps.  An
 * argument that is a pointer built from tcg_env is how a register that has no
 * TCG global reaches the helper, and the pointer says neither how many bytes
 * it spans nor whether the helper reads or writes through it.  The DECLARED
 * TYPE says the first half: `Reg *` is one vector register and the compiler
 * knows how big one is.  The second half -- the direction -- is not in the
 * type, and is adjudicated in the target's checked-in usage data.
 *
 * This file expands HELPER_H into the first half.  Every argument type the
 * target spells must have a df_argsize_ definition below or the expansion
 * does not compile, so a new pointer type cannot arrive unclassified.
 *
 * Define HELPER_H and include this once, from a target TU that can see the
 * target's own structures (sizeof(Reg) is only meaningful there).
 *
 * Copyright (c) 2026 Maccoy Merrell
 */

#include "exec/helper-head.h.inc"
#include "exec/insn-dataflow.h"

/* One more level of indirection so the name is expanded before stringifying. */
#define df_str_(s) #s
#define df_str(s)  df_str_(s)

/*
 * Bytes of CPUArchState an argument of this type names, or 0 when it names
 * none.  Zero is the answer for every scalar, for tcg_env itself, and for a
 * bare `ptr` whose pointee this file cannot know -- it is not a claim that the
 * helper touches nothing, it is this file declining to guess, and the caller
 * then keeps the unbounded record and counts it.
 */
#define df_argsize_void      0
#define df_argsize_noreturn  0
#define df_argsize_i32       0
#define df_argsize_s32       0
#define df_argsize_i64       0
#define df_argsize_s64       0
#define df_argsize_i128      0
#define df_argsize_int       0
#define df_argsize_f16       0
#define df_argsize_f32       0
#define df_argsize_f64       0
#define df_argsize_ptr       0
#define df_argsize_cptr      0
#define df_argsize_env       0
#define df_argsize_fpst      0
#define df_argsize_tl        0
#define df_argsize(t)        df_argsize_##t

#define DEF_HELPER_FLAGS_0(NAME, FLAGS, RET)                            \
    { df_str(NAME), 0, { 0 } },
#define DEF_HELPER_FLAGS_1(NAME, FLAGS, RET, T1)                        \
    { df_str(NAME), 1, { df_argsize(T1) } },
#define DEF_HELPER_FLAGS_2(NAME, FLAGS, RET, T1, T2)                    \
    { df_str(NAME), 2, { df_argsize(T1), df_argsize(T2) } },
#define DEF_HELPER_FLAGS_3(NAME, FLAGS, RET, T1, T2, T3)                \
    { df_str(NAME), 3, { df_argsize(T1), df_argsize(T2),                \
                         df_argsize(T3) } },
#define DEF_HELPER_FLAGS_4(NAME, FLAGS, RET, T1, T2, T3, T4)            \
    { df_str(NAME), 4, { df_argsize(T1), df_argsize(T2),                \
                         df_argsize(T3), df_argsize(T4) } },
#define DEF_HELPER_FLAGS_5(NAME, FLAGS, RET, T1, T2, T3, T4, T5)        \
    { df_str(NAME), 5, { df_argsize(T1), df_argsize(T2),                \
                         df_argsize(T3), df_argsize(T4),                \
                         df_argsize(T5) } },
#define DEF_HELPER_FLAGS_6(NAME, FLAGS, RET, T1, T2, T3, T4, T5, T6)    \
    { df_str(NAME), 6, { df_argsize(T1), df_argsize(T2),                \
                         df_argsize(T3), df_argsize(T4),                \
                         df_argsize(T5), df_argsize(T6) } },
#define DEF_HELPER_FLAGS_7(NAME, FLAGS, RET, T1, T2, T3, T4, T5, T6, T7) \
    { df_str(NAME), 7, { df_argsize(T1), df_argsize(T2),                \
                         df_argsize(T3), df_argsize(T4),                \
                         df_argsize(T5), df_argsize(T6),                \
                         df_argsize(T7) } },

static const InsnDfHelperArgs insn_df_helper_args[] = {
#include HELPER_H
};

#undef DEF_HELPER_FLAGS_0
#undef DEF_HELPER_FLAGS_1
#undef DEF_HELPER_FLAGS_2
#undef DEF_HELPER_FLAGS_3
#undef DEF_HELPER_FLAGS_4
#undef DEF_HELPER_FLAGS_5
#undef DEF_HELPER_FLAGS_6
#undef DEF_HELPER_FLAGS_7
#undef df_str
#undef df_str_
