/*
 * The comparison capture, segregated from the shipped plugin.
 *
 * See champsim_tracer_capture.h for why this file is empty in a release
 * build.  What follows is compiled only under -Dcst_capture=true.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_capture.h"

#ifdef CST_CAPTURE

#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include <qemu-plugin.h>
}

#include "champsim_tracer_mnemonics.h"
#include "champsim_tracer_generic_ids.h"

namespace {

/*
 * One corpus file.
 *
 * Opened on first use from the environment variable that names it, with its
 * column header written once.  A file the run asked for and this process
 * cannot open aborts the run: the alternative is a capture that silently
 * produces nothing, and downstream a corpus that is absent and a corpus that
 * is empty are the same file.
 */
class Corpus {
public:
    Corpus(const char *env, const char *header) : env_(env), header_(header) {}

    FILE *get()
    {
        if (!tried_) {
            tried_ = true;
            const char *path = getenv(env_);

            if (path && *path) {
                f_ = fopen(path, "w");
                if (!f_) {
                    fprintf(stderr,
                            "champsim_tracer capture: cannot open %s=%s -- a "
                            "corpus that was asked for and is missing is a "
                            "refusal, not an empty result\n", env_, path);
                    abort();
                }
                setvbuf(f_, nullptr, _IOFBF, 1 << 20);
                fputs(header_, f_);
            }
        }
        return f_;
    }

    ~Corpus()
    {
        if (f_) {
            fclose(f_);
        }
    }

private:
    const char *env_;
    const char *header_;
    bool tried_ = false;
    FILE *f_ = nullptr;
};

/*
 * The corpora, one per question the apparatus asks.
 *
 * Immortalised rather than given static destructors: the plugin's own exit
 * path runs after these would be torn down, and a capture that loses its last
 * buffer is short for a reason nothing records.
 */
Corpus *corpus_src;      /* the read list, per encoding */
Corpus *corpus_opc;      /* the opcode and branch words, per encoding */
Corpus *corpus_mech;     /* why the classifier said what it said */
Corpus *corpus_ident;    /* the decode rule QEMU reached, beside the mnemonic */

void corpora_init()
{
    static bool done;

    if (!done) {
        done = true;
        corpus_src = new Corpus("CST_SRC_ENC_DUMP",
                                "#isa\tencoding\tmnem\tsrc\n");
        corpus_opc = new Corpus("CST_OPC_ENC_DUMP",
                                "#isa\tencoding\tmnem\topcode\n");
        corpus_mech = new Corpus("CST_SRC_MECH_DUMP",
                                 "#isa\tencoding\tmech\n");
        corpus_ident = new Corpus("CST_QEMU_IDENT_PAIRS",
                                  "#isa\tencoding\tmnem\trule\tword\n");
    }
}

/*
 * The encoding, as the bytes actually are.
 *
 * Little-endian targets and big-endian ones both get the byte sequence in
 * memory order rather than a word the capture assembled, because the row is
 * keyed on the encoding and a key that depends on the capturing host is not
 * one key.
 */
void hex_bytes(const void *bytes, size_t n, char *out, size_t outsz)
{
    static const char digits[] = "0123456789abcdef";
    const unsigned char *p = static_cast<const unsigned char *>(bytes);
    size_t k = 0;

    for (size_t i = 0; i < n && k + 3 <= outsz; i++) {
        out[k++] = digits[p[i] >> 4];
        out[k++] = digits[p[i] & 0xf];
    }
    out[k] = '\0';
}

const char *isa_name()
{
    static const char *n;

    if (!n) {
        const qemu_info_t *info = nullptr;

        (void)info;
        n = getenv("CST_CAPTURE_ISA");
        if (!n || !*n) {
            n = "unknown";
        }
    }
    return n;
}

} /* namespace */

void cst_capture_insn(uint64_t pc, const void *bytes, size_t nbytes,
                      const struct qemu_plugin_insn_info *info,
                      const struct InsnFields *f)
{
    (void)pc;

    if (!bytes || !nbytes || !f) {
        return;
    }
    corpora_init();

    char enc[2 * 32 + 1];
    const char *isa = isa_name();

    hex_bytes(bytes, nbytes, enc, sizeof(enc));
    const char *mnem = info && info->mnemonic[0] ? info->mnemonic : "-";

    if (FILE *o = corpus_src->get()) {
        char src[512];
        size_t k = 0;

        src[0] = '\0';
        for (unsigned i = 0; i < f->n_src_regs; i++) {
            const char *nm = generic_reg_name_or_unknown(f->src_regs[i]);
            int w = snprintf(src + k, sizeof(src) - k, "%s%s",
                             k ? "," : "", nm);

            if (w < 0 || (size_t)w >= sizeof(src) - k) {
                break;
            }
            k += (size_t)w;
        }
        fprintf(o, "%s\t%s\t%s\t%s\n", isa, enc, mnem, k ? src : "-");
    }

    if (FILE *o = corpus_opc->get()) {
        fprintf(o, "%s\t%s\t%s\t%s\n", isa, enc, mnem,
                generic_opcode_name_or_unknown(f->opcode));
    }

    if (FILE *o = corpus_mech->get()) {
        /*
         * The mechanism is what a reader needs to tell a list that is short
         * because the instruction reads little from one that is short because
         * the classifier had nothing to say.  Both look like a short list.
         */
        fprintf(o, "%s\t%s\t%s\n", isa, enc,
                f->opcode == GEN_OP_UNKNOWN ? "unclassified"
                : f->n_src_regs             ? "walked"
                                            : "walked-empty");
    }

    if (FILE *o = corpus_ident->get()) {
        fprintf(o, "%s\t%s\t%s\t%s\t%s\n", isa, enc, mnem, "-", "-");
    }
}

#endif /* CST_CAPTURE */
