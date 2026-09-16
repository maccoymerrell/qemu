/*
 * What x86's helpers do through the pointers they are handed.
 *
 * SSE and MMX reach their register operands as pointers built from tcg_env,
 * so the op stream shows a call with a pointer argument and nothing else.
 * The declared type says how many bytes of CPUArchState the pointer names --
 * one ZMMReg, one MMXReg -- and the compiler supplies that here.  Which way
 * the helper moves data through it is a fact about the helper's body, not its
 * type, and is adjudicated one row at a time in insn-df-helper-usage.tsv.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "exec/insn-dataflow.h"
#include "tcg/helper-tcg.h"

/* The adjudication: one row per helper that names a register. */
#include "insn-df-usage.h.inc"

/*
 * The extent each x86 pointer type names, from the compiler.  ZMMReg and
 * MMXReg are whole registers and their size is what sizeof says; `Reg` is
 * whichever of the two ops_sse_header.h.inc is currently spelling, and the
 * macro is expanded inside that inclusion, so it resolves to the right one
 * for each of the three widths the header is included at.
 */
#define df_argsize_Reg     sizeof(Reg)
#define df_argsize_ZMMReg  sizeof(ZMMReg)
#define df_argsize_MMXReg  sizeof(MMXReg)

/* The shape: one row per helper, from target/i386/helper.h itself. */
#define HELPER_H "helper.h"
#include "exec/insn-df-helper-args.h.inc"
#undef HELPER_H

void x86_insn_df_declare_helper_usage(void)
{
    insn_dataflow_declare_helper_usage(insn_df_helper_args,
                                       ARRAY_SIZE(insn_df_helper_args),
                                       insn_df_helper_dirs,
                                       ARRAY_SIZE(insn_df_helper_dirs));
}
