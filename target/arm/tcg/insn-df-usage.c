/*
 * What arm's helpers do through the pointers they are handed.
 *
 * Every floating-point helper this target has reaches the FP status word as a
 * pointer built from tcg_env by fpstatus_ptr(), so the op stream shows a call
 * with a pointer argument and nothing else.  The declared type says how many
 * bytes of CPUARMState the pointer names -- one float_status -- and the
 * compiler supplies that here.  Which way the helper moves data through it is
 * a fact about the helper's body, not its type, and is adjudicated one row at
 * a time in insn-df-helper-usage.tsv.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "exec/insn-dataflow.h"
#include "translate.h"

/* The adjudication: one row per helper that names a register. */
#include "insn-df-usage.h.inc"

/* The shape: one row per helper, from target/arm/helper.h itself. */
#define HELPER_H "helper.h"
#include "exec/insn-df-helper-args.h.inc"
#undef HELPER_H

void arm_insn_df_declare_helper_usage(void)
{
    insn_dataflow_declare_helper_usage(insn_df_helper_args,
                                       ARRAY_SIZE(insn_df_helper_args),
                                       insn_df_helper_dirs,
                                       ARRAY_SIZE(insn_df_helper_dirs));
}
