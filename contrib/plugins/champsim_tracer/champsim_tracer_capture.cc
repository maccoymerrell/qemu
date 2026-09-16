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

#include <elf.h>
#include <glib.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include <qemu-plugin.h>
#include <qemu-plugin-dataflow.h>
}

#include "champsim_tracer_mnemonics.h"
#include "champsim_tracer_generic_ids.h"
#include "champsim_tracer_vocabulary.h"

namespace {

/*
 * Which build produced a corpus.
 *
 * Two corpora are only comparable if the same pair of binaries wrote them; a
 * join across builds is the frozen-arm failure, and it does not announce
 * itself -- the rows look like rows.  So every corpus carries the GNU build
 * ids of the plugin and the emulator that wrote it, and the scorer refuses a
 * set whose stamps disagree.
 *
 * The ids are read out of the loaded objects' own PT_NOTE segments rather
 * than by hashing files, so the stamp names what is RUNNING and cannot be
 * fooled by a rebuild between the run and the read.
 */
/*
 * QEMU ships its own include/elf.h, and this plugin's include path reaches it
 * before the system's, so the note type the build id lives under may not be
 * spelled here.  Its value is fixed by the ELF note ABI.
 */
#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID  3
#endif

struct BuildIdScan {
    const char *want;       /* substring of the object's path; NULL = the exe */
    char out[2 * 64 + 1];
    bool found;
};

int build_id_cb(struct dl_phdr_info *info, size_t, void *data)
{
    BuildIdScan *s = static_cast<BuildIdScan *>(data);
    const char *nm = info->dlpi_name ? info->dlpi_name : "";

    if (s->want ? !strstr(nm, s->want) : nm[0] != '\0') {
        return 0;
    }
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];

        if (p->p_type != PT_NOTE) {
            continue;
        }

        const unsigned char *base =
            reinterpret_cast<const unsigned char *>(info->dlpi_addr +
                                                    p->p_vaddr);
        size_t off = 0;

        while (off + sizeof(ElfW(Nhdr)) <= p->p_memsz) {
            const ElfW(Nhdr) *n =
                reinterpret_cast<const ElfW(Nhdr) *>(base + off);
            const char *name = reinterpret_cast<const char *>(n + 1);
            size_t namesz = (n->n_namesz + 3) & ~3u;
            size_t descsz = (n->n_descsz + 3) & ~3u;

            if (n->n_type == NT_GNU_BUILD_ID && n->n_namesz == 4 &&
                memcmp(name, "GNU", 4) == 0) {
                static const char hx[] = "0123456789abcdef";
                const unsigned char *d =
                    reinterpret_cast<const unsigned char *>(name + namesz);
                size_t k = 0;

                for (uint32_t j = 0;
                     j < n->n_descsz && k + 2 < sizeof(s->out); j++) {
                    s->out[k++] = hx[d[j] >> 4];
                    s->out[k++] = hx[d[j] & 0xf];
                }
                s->out[k] = '\0';
                s->found = true;
                return 1;
            }
            off += sizeof(ElfW(Nhdr)) + namesz + descsz;
        }
    }
    return 1;   /* the object matched and carries no build id */
}

const char *build_id_of(const char *want)
{
    BuildIdScan s = { want, { 0 }, false };

    dl_iterate_phdr(build_id_cb, &s);
    if (!s.found) {
        return "none";
    }

    static char kept[2][sizeof(s.out)];
    static unsigned next;
    char *slot = kept[next++ % 2];

    memcpy(slot, s.out, sizeof(s.out));
    return slot;
}

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
                fprintf(f_, "#so plugin=%s emulator=%s\n",
                        build_id_of("champsim_tracer"), build_id_of(nullptr));
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
        corpus_ident = new Corpus(
            "CST_QEMU_IDENT_PAIRS",
            "#isa\tencoding\tmnem\trule\tword\topcode\tbranch\n");
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

}

void cst_capture_qemu_ident(const struct qemu_plugin_tb *tb, size_t idx,
                            const void *bytes, size_t nbytes, const char *mnem)
{
    if (!tb || !bytes || !nbytes) {
        return;
    }
    corpora_init();

    FILE *o = corpus_ident->get();

    if (!o) {
        return;
    }

    char enc[2 * 32 + 1];

    hex_bytes(bytes, nbytes, enc, sizeof(enc));

    /*
     * Four answers, and they are not the same answer.
     *
     * "undecoded" means no rule matched the bytes at all.  A rule with no word
     * matched and had nothing generic to say about itself.  A word the
     * vocabulary does not know is a skew between this plugin and this
     * emulator.  Each gets its own spelling here, because collapsing any two
     * of them would let a scorer read a build problem as a decoder gap.
     */
    const char *rule = qemu_plugin_insn_decode_name(tb, idx);
    const char *word = qemu_plugin_insn_decode_word(tb, idx);
    const char *opc;
    const char *brn;
    uint8_t opcode = 0;
    uint8_t branch = 0;

    if (qemu_plugin_insn_undecoded(tb, idx)) {
        rule = "#undecoded";
        opc = brn = "#undecoded";
    } else if (!word) {
        opc = brn = "#noword";
    } else if (cst_vocabulary_lookup(word, &opcode, &branch)) {
        opc = generic_opcode_name_or_unknown(opcode);
        brn = branch_type_name_or_unknown(branch);
    } else {
        opc = brn = "#unknownword";
    }

    fprintf(o, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", isa_name(), enc,
            mnem && mnem[0] ? mnem : "-", rule ? rule : "-",
            word ? word : "-", opc, brn);
}

#endif /* CST_CAPTURE */
