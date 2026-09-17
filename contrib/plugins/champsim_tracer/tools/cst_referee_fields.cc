/*
 * cst_referee_fields — the plugin-world half of the external referee.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This is the only translation unit in the referee that sees
 * champsim_tracer.h.  Everything it exports is in cst_referee_fields.h, which
 * names no plugin type, so the driver — which compiles disas/capstone.c's
 * include world beside it — never has to pull the plugin's headers in.
 *
 * See cst_referee_fields.h for why the referee exists at all.  What follows
 * is the same install-time sequence the plugin performs, plus the globals and
 * the stubs a decode-without-a-machine needs.
 */

#include "champsim_tracer.h"
#include "champsim_tracer_mnemonics.h"
#include "champsim_tracer_capstone_tables.h"
#include "champsim_tracer_capstone_mode.h"
#include "champsim_tracer_reg_handle_cache.h"
#include "champsim_tracer_stats.h"

#include "cst_referee_fields.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

/* ------------------------------------------------------------------ */
/* Plugin globals the decode path reads.                               */
/* ------------------------------------------------------------------ */

TraceISA trace_isa = TRACE_ISA_UNKNOWN;
/*
 * The QEMU target name.  The plugin fills it from the emulator it is loaded
 * into; there is no emulator here, and cstref_init() resolves the Capstone
 * mode from the ISA name it was given instead, so this exists only to satisfy
 * the capture TU's link and is never read.
 */
const char *target_name = nullptr;
bool target_big_endian = false;
const InsnClassification *active_insn_table = nullptr;
unsigned active_insn_table_size = 0;
const RegClassification *active_reg_table = nullptr;
unsigned active_reg_table_size = 0;
GMutex unknown_warn_lock;
FILE *unknown_warn_file = nullptr;

/* ------------------------------------------------------------------ */
/* Plugin runtime the decode path does NOT read.                       */
/* ------------------------------------------------------------------ */

Stats &thread_stats_get()
{
    static Stats s;
    return s;
}

/*
 * THE STUBS ABORT.  They do not answer.
 *
 * Everything below serves the capture's QEMU-side corpora — the statements an
 * emulator makes while it translates.  This process has no emulator, so there
 * is nothing for them to report, and a stub that returned "no statements"
 * would let the referee write a QEMU column of silence that a scorer would
 * read as a decoder saying nothing rather than as a tool that never looked.
 * That is the silent-false-success shape, and the way out of it is to make
 * the condition impossible rather than to document it: the referee drives
 * only the Capstone-side entry points, and any path that reaches one of these
 * kills the run and names the entry point it reached.
 */
static void cstref_no_machine(const char *who)
{
    fprintf(stderr,
            "cst_referee: %s was called.  This tool has no emulator, so it "
            "has no QEMU statements to report; reaching a QEMU-side capture "
            "entry point means the driver asked for a corpus only a running "
            "emulator can write.  Refusing rather than answering with "
            "silence.\n", who);
    abort();
}

#define CSTREF_STUB(rettype, name, args)                                \
    rettype name args                                                   \
    {                                                                   \
        cstref_no_machine(#name);                                       \
        __builtin_unreachable();                                        \
    }

extern "C" {

/*
 * These two are on the decode path and are genuinely answerable offline: the
 * plugin treats a register it cannot read exactly as it treats one no vCPU
 * exposes, and capture_initial_regfile() — the only caller — is not reached
 * from decode_detail_to_generic().
 */
int qemu_plugin_read_register(struct qemu_plugin_register *, GByteArray *)
{
    return 0;
}

GArray *qemu_plugin_get_registers(void)
{
    return nullptr;
}

/*
 * No guest binary, so the tables fall back to the same default Capstone mode
 * set they choose when a guest ELF cannot be sniffed.  That fallback is the
 * mode this tool stamps and the mode the corpus row is scored under.
 */
const char *qemu_plugin_path_to_binary(void)
{
    return nullptr;
}

/* QEMU's dataflow statement ABI — see the abort note above. */
CSTREF_STUB(unsigned, qemu_plugin_dataflow_nregs, (void))
CSTREF_STUB(const char *, qemu_plugin_dataflow_reg_name,
            (unsigned, uint32_t *, uint32_t *))
CSTREF_STUB(bool, qemu_plugin_dataflow_prov_field,
            (unsigned, uint32_t *, uint32_t *))
CSTREF_STUB(const char *, qemu_plugin_dataflow_field_reg, (uint32_t, uint32_t))
CSTREF_STUB(bool, qemu_plugin_dataflow_prov_atom, (unsigned, uint32_t *))
CSTREF_STUB(unsigned, qemu_plugin_insn_reg_reads,
            (const struct qemu_plugin_tb *, size_t, uint64_t *, unsigned))
CSTREF_STUB(unsigned, qemu_plugin_insn_reg_writes,
            (const struct qemu_plugin_tb *, size_t, uint64_t *, unsigned))
CSTREF_STUB(unsigned, qemu_plugin_insn_fields,
            (const struct qemu_plugin_tb *, size_t,
             qemu_plugin_dataflow_field *, unsigned))
CSTREF_STUB(unsigned, qemu_plugin_insn_synthetic_eas,
            (const struct qemu_plugin_tb *, size_t,
             qemu_plugin_dataflow_ea *, unsigned))
CSTREF_STUB(const char *, qemu_plugin_insn_decode_name,
            (const struct qemu_plugin_tb *, size_t))
CSTREF_STUB(const char *, qemu_plugin_insn_decode_word,
            (const struct qemu_plugin_tb *, size_t))
CSTREF_STUB(bool, qemu_plugin_insn_undecoded,
            (const struct qemu_plugin_tb *, size_t))
CSTREF_STUB(bool, qemu_plugin_insn_immediate,
            (const struct qemu_plugin_tb *, size_t, unsigned, uint64_t *,
             uint32_t *))
CSTREF_STUB(bool, qemu_plugin_insn_dataflow_status,
            (const struct qemu_plugin_tb *, size_t,
             qemu_plugin_dataflow_status *))
/*
 * QEMU's in-process Capstone consult, which this tool must never reach: it
 * disassembles with its OWN pinned Capstone through cap_disas_raw_detail(),
 * and a stub that quietly answered here would make the referee score a second
 * decode path while its report named the first.
 */
CSTREF_STUB(bool, qemu_plugin_cap_decode,
            (int, unsigned int, const uint8_t *, size_t, uint64_t,
             qemu_plugin_insn_info *))

} /* extern "C" */

/*
 * THE SLED'S TRANSLATION PRIMITIVE, and it is the clearest case in this file.
 *
 * `cst_capture_sled_run()` in champsim_tracer_capture.cc drives QEMU through
 * one translation per sled slot; the primitive that performs it lives in
 * champsim_tracer.cc, which this library does not link.  A stub returning
 * "translated, no chain" would hand the sweep a full run of fabricated
 * counters and a corpus of nothing, which is exactly the silence the note
 * above is about -- and worse here, because the sled's whole product is the
 * rows a REAL translation writes.
 *
 * It is unreachable in practice: the referee drives the Capstone side and
 * never calls the sweep.  The stub exists so the library LINKS and so that
 * any future path which did reach it would die naming this entry point.
 * Not `extern "C"` -- capture.h declares it as C++, and the two spellings
 * have to agree or the link fails for a second, unrelated reason.
 */
CSTREF_STUB(bool, cst_sled_translate_slot, (uint64_t, bool *))

/* ------------------------------------------------------------------ */

static bool table_ready;
static int g_cap_arch = -1;
static unsigned g_cap_mode;

bool cstref_init(const char *isa_name)
{
    TraceISA isa = TRACE_ISA_UNKNOWN;

    if (!strcmp(isa_name, "aarch64")) {
        isa = TRACE_ISA_AARCH64;
    } else if (!strcmp(isa_name, "riscv64")) {
        isa = TRACE_ISA_RISCV;
    } else if (!strcmp(isa_name, "mipsel")) {
        isa = TRACE_ISA_MIPS;
    } else if (!strcmp(isa_name, "x86_64")) {
        isa = TRACE_ISA_X86;
    } else {
        return false;
    }

    /*
     * The same assignments champsim_tracer.cc makes at install time, in the
     * same order, followed by the same reverse-index build.  Deliberately no
     * additions: if the plugin grows a fifth thing it must set before
     * decoding, this file stops matching it visibly rather than quietly.
     */
    trace_isa = isa;
    active_insn_table = isa_insn_class[isa];
    active_insn_table_size = isa_insn_class_size[isa];
    active_reg_table = isa_reg_class[isa];
    active_reg_table_size = isa_reg_class_size[isa];
    build_qemu_reg_reverse_index();

    /*
     * The arch/mode pair comes from champsim_tracer_capstone_mode.h -- the
     * one place either apparatus arm gets it, so a mirror of it cannot drift.
     * The mode resolvers read the extension set out of the guest ELF when
     * there is one; there is none here, so each returns its documented
     * fallback set, and the driver stamps which.
     */
    g_cap_arch = cst_capstone_arch_for_isa(isa);
    g_cap_mode = (g_cap_arch >= 0)
               ? cst_capstone_mode_for_isa(isa, isa_name)
               : 0;

    table_ready = active_insn_table && active_reg_table && g_cap_arch >= 0;
    return table_ready;
}

int cstref_cap_arch(void)
{
    return g_cap_arch;
}

unsigned cstref_cap_mode(void)
{
    return g_cap_mode;
}

bool cstref_decode(uint64_t pc, const void *bytes, size_t nbytes,
                   const struct qemu_plugin_insn_info *info,
                   CstRefFacts *out)
{
    if (!table_ready || !info || !out) {
        return false;
    }

    InsnFieldsScratch scratch;

    insn_fields_scratch_reset(&scratch);

    /*
     * The encoding bytes are passed through because the capture keys every
     * row it writes on them.  This is the call the in-process arm made, with
     * the same arguments, so the rows it produces are the rows that arm
     * produced -- not a second implementation of them.
     */
    decode_detail_to_generic(pc, bytes, nbytes, info, &scratch.f, nullptr);

    const InsnFields &f = scratch.f;

    /*
     * GEN_OP_UNKNOWN is decode_detail_to_generic()'s early return: the
     * mnemonic is not in the ISA table, so nothing downstream of the
     * classification ran and the fields are empty by construction rather than
     * by dataflow.  The distinction travels rather than being flattened.
     */
    out->ok = f.opcode != GEN_OP_UNKNOWN;
    out->opcode = f.opcode;
    out->branch_type = f.branch_type;
    out->branch_conditional = f.branch_conditional;
    out->is_atomic = f.is_atomic;
    out->has_reg_deps = f.has_reg_deps;
    out->has_addr_deps = f.has_addr_deps;
    out->has_vec_lanes = f.has_vec_lanes;
    out->lane_mask_kind = f.lane_mask_kind;
    out->lane_bytes = f.lane_bytes;
    out->max_dep_loads = f.max_dep_loads;
    out->max_dep_stores = f.max_dep_stores;
    out->n_src_regs = f.n_src_regs;
    out->n_dst_regs = f.n_dst_regs;
    return true;
}

const char *cstref_opcode_name(unsigned opcode)
{
    return generic_opcode_name_or_unknown(opcode);
}

const char *cstref_branch_name(unsigned branch_type)
{
    return branch_type_name_or_unknown(branch_type);
}

const char *cstref_reg_name(unsigned gen_id)
{
    return generic_reg_name_or_unknown(gen_id);
}
