/*
 * Routines for target instruction disassembly.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "disas/disas.h"
#include "disas/capstone.h"
#include "qemu/qemu-plugin.h"
#include "exec/translator.h"
#include "disas-internal.h"


static int translator_read_memory(bfd_vma memaddr, bfd_byte *myaddr,
                                  int length, struct disassemble_info *info)
{
    const DisasContextBase *db = info->application_data;
    return translator_st(db, myaddr, memaddr, length) ? 0 : EIO;
}

void target_disas(FILE *out, CPUState *cpu, const struct DisasContextBase *db)
{
    uint64_t code = db->pc_first;
    size_t size = translator_st_len(db);
    uint64_t pc;
    int count;
    CPUDebug s;

    disas_initialize_debug_target(&s, cpu);
    s.info.read_memory_func = translator_read_memory;
    s.info.application_data = (void *)db;
    s.info.fprintf_func = fprintf;
    s.info.stream = out;
    s.info.buffer_vma = code;
    s.info.buffer_length = size;
    s.info.show_opcodes = true;

    if (s.info.cap_arch >= 0 && cap_disas_target(&s.info, code, size)) {
        return;
    }

    if (s.info.print_insn == NULL) {
        s.info.print_insn = print_insn_od_target;
    }

    for (pc = code; size > 0; pc += count, size -= count) {
        fprintf(out, "0x%08" PRIx64 ":  ", pc);
        count = s.info.print_insn(pc, &s.info);
        fprintf(out, "\n");
        if (count < 0) {
            break;
        }
        if (size < count) {
            fprintf(out,
                    "Disassembler disagrees with translator over instruction "
                    "decoding\n"
                    "Please report this to qemu-devel@nongnu.org\n");
            break;
        }
    }
}

#ifdef CONFIG_PLUGIN
static void plugin_print_address(bfd_vma addr, struct disassemble_info *info)
{
    /* does nothing */
}

/*
 * We should only be dissembling one instruction at a time here. If
 * there is left over it usually indicates the front end has read more
 * bytes than it needed.
 */
char *plugin_disas(CPUState *cpu, const DisasContextBase *db,
                   uint64_t addr, size_t size)
{
    CPUDebug s;
    GString *ds = g_string_new(NULL);

    disas_initialize_debug_target(&s, cpu);
    s.info.read_memory_func = translator_read_memory;
    s.info.application_data = (void *)db;
    s.info.fprintf_func = disas_gstring_printf;
    s.info.stream = (FILE *)ds;  /* abuse this slot */
    s.info.buffer_vma = addr;
    s.info.buffer_length = size;
    s.info.print_address_func = plugin_print_address;

    if (s.info.cap_arch >= 0 && cap_disas_plugin(&s.info, addr, size)) {
        ; /* done */
    } else if (s.info.print_insn) {
        s.info.print_insn(addr, &s.info);
    } else {
        ; /* cannot disassemble -- return empty string */
    }

    /* Return the buffer, freeing the GString container.  */
    return g_string_free(ds, false);
}

/*
 * Disassemble a single instruction with Capstone detail mode and fill
 * a qemu_plugin_insn_info struct.  Falls back to the ISA's print_insn
 * disassembler when Capstone is not available (e.g. RISC-V, MIPS),
 * populating only the mnemonic and op_str fields so that the plugin
 * can still use its MNEM-table fallback path.
 */
bool plugin_disas_detail(CPUState *cpu, const DisasContextBase *db,
                         uint64_t addr, size_t size,
                         qemu_plugin_insn_info *out)
{
    CPUDebug s;

    disas_initialize_debug_target(&s, cpu);
    s.info.read_memory_func = translator_read_memory;
    s.info.application_data = (void *)db;
    s.info.buffer_vma = addr;
    s.info.buffer_length = size;

    if (s.info.cap_arch >= 0) {
        return cap_disas_plugin_detail(&s.info, addr, size, out);
    }

    /*
     * Capstone not available for this ISA — fall back to the builtin
     * disassembler.  Extract mnemonic and op_str from the disassembly
     * string so the plugin's MNEM-table lookup still works.
     */
    memset(out, 0, sizeof(*out));

    GString *ds = g_string_new(NULL);
    s.info.fprintf_func = disas_gstring_printf;
    s.info.stream = (FILE *)ds;
    s.info.print_address_func = plugin_print_address;

    if (s.info.print_insn) {
        s.info.print_insn(addr, &s.info);
    }

    if (ds->len > 0) {
        /* Split "mnemonic<ws>operands" into out->mnemonic / out->op_str */
        const char *p = ds->str;
        while (*p && g_ascii_isspace(*p)) {
            p++;
        }
        size_t mlen = 0;
        while (p[mlen] && !g_ascii_isspace(p[mlen])) {
            mlen++;
        }
        if (mlen >= QEMU_PLUGIN_INSN_DETAIL_MNEMSZ) {
            mlen = QEMU_PLUGIN_INSN_DETAIL_MNEMSZ - 1;
        }
        memcpy(out->mnemonic, p, mlen);
        out->mnemonic[mlen] = '\0';
        p += mlen;
        while (*p && g_ascii_isspace(*p)) {
            p++;
        }
        g_strlcpy(out->op_str, p, QEMU_PLUGIN_INSN_DETAIL_OPSTRSZ);
    }

    g_string_free(ds, true);
    return out->mnemonic[0] != '\0';
}
#endif /* CONFIG_PLUGIN */
