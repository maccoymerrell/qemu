/*
 * idprobe: dump QEMU's own decode identity for every translated insn.
 * One line per translated instruction:
 *   <vaddr> <decode_id> <decode_name> | <capstone disas>
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *out;
static GMutex lock;

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    g_mutex_lock(&lock);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        const char *nm = qemu_plugin_insn_decode_name(insn);
        char *d = qemu_plugin_insn_disas(insn);
        uint8_t buf[16];
        size_t len = qemu_plugin_insn_size(insn);
        if (len > sizeof(buf)) {
            len = sizeof(buf);
        }
        qemu_plugin_insn_data(insn, buf, len);
        fprintf(out, "%016" PRIx64 "\t%" PRIu32 "\t%s\t",
                qemu_plugin_insn_vaddr(insn),
                qemu_plugin_insn_decode_id(insn),
                nm ? nm : "-");
        for (size_t k = 0; k < len; k++) {
            fprintf(out, "%02x", buf[k]);
        }
        fprintf(out, "\t%s\n", d ? d : "?");
        g_free(d);
    }
    g_mutex_unlock(&lock);
}

static void at_exit(qemu_plugin_id_t id, void *p)
{
    fflush(out);
    if (out != stderr) {
        fclose(out);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *path = NULL;
    for (int i = 0; i < argc; i++) {
        if (g_str_has_prefix(argv[i], "out=")) {
            path = argv[i] + 4;
        }
    }
    out = path ? fopen(path, "w") : stderr;
    if (!out) {
        return -1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
