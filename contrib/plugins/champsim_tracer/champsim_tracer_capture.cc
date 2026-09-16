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
#include <limits.h>
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
                /*
                 * Line buffered, not block buffered.
                 *
                 * The corpora are immortal (see below): nothing closes them,
                 * and qemu-user's exit does not come back through stdio, so a
                 * block-buffered stream ends its file in the middle of a row.
                 * A torn last row is worse than a missing one -- it parses,
                 * it is short a column, and a scorer reports a bucket for an
                 * encoding nobody wrote.  A measured riscv64 capture ended in
                 * exactly that row, in both corpora it wrote.  A row per
                 * write costs the capture, which is apparatus, nothing the
                 * release build pays.
                 */
                setvbuf(f_, nullptr, _IOLBF, 1 << 16);
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
Corpus *corpus_vec;      /* how a helper's env pointers were recorded */
Corpus *corpus_ident;    /* the decode rule QEMU reached, beside the mnemonic */
Corpus *corpus_stmt;     /* the decoder-only statements, per encoding */

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
        corpus_vec = new Corpus(
            "CST_VEC_ENV_DUMP",
            "#isa\tencoding\tvecops\tdropped\tbounded\tunbounded\n");
        corpus_ident = new Corpus(
            "CST_QEMU_IDENT_PAIRS",
            "#isa\tencoding\tmnem\trule\tword\topcode\tbranch\n");
        corpus_stmt = new Corpus(
            "CST_DF_STMT_DUMP",
            "#isa\tencoding\tatomic\timm\tvece\toprsz\tmemops\tfieldregs"
            "\tzero\tpcread\tnrd\tnwr\n");
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

/*
 * Which provenance bit stands for the architectural zero register.
 *
 * The three atoms sit at the top of the register namespace and their indices
 * are a property of the emulator, not of this plugin, so the bit is asked for
 * rather than spelled: a build whose namespace is a different width would
 * otherwise have a hard-coded index quietly land on a real register.
 *
 * The search is bounded by the widest set the reader below asks for.  A build
 * that answers for no bit at all returns UINT_MAX, and the caller writes no
 * zero column rather than a false absence.
 */
/*
 * Which provenance bit is the target's program counter.
 *
 * A pc-relative value is computed at translation time and materialised as a
 * constant on every target QEMU has -- the op that would have named the
 * program counter is never emitted, so a read of it is a decoder-only fact
 * exactly as the zero register is, and exactly as invisible in the read set's
 * SIZE, which moves by one for any statement at all.  It therefore gets its
 * own column.
 *
 * The bit is found by NAME over the register namespace rather than spelled,
 * for the reason zero_atom_bit() gives: indices are the emulator's.  The name
 * is matched case-insensitively against "pc" because the targets spell the
 * same register differently ("PC" on MIPS, "pc" on aarch64 and RISC-V) and
 * the spelling is the target's, not this plugin's.
 *
 * A TARGET WHOSE PROGRAM COUNTER IS NOT A TCG GLOBAL ANSWERS UINT_MAX and the
 * column reads "-" -- an absence of the instrument, which is not the same
 * claim as a measured zero.  x86 is that target: its EIP lives in
 * CPUArchState and reaches the reader through the env-range machinery, so its
 * fold is carried by the `fieldregs` column instead.
 */
unsigned pc_reg_bit()
{
    static unsigned bit = UINT_MAX;
    static bool done;

    if (!done) {
        done = true;
        for (unsigned r = 0; r < qemu_plugin_dataflow_nregs(); r++) {
            const char *n = qemu_plugin_dataflow_reg_name(r, nullptr, nullptr);

            if (n && (n[0] == 'p' || n[0] == 'P') &&
                (n[1] == 'c' || n[1] == 'C') && n[2] == '\0') {
                bit = r;
                break;
            }
        }
    }
    return bit;
}

unsigned zero_atom_bit()
{
    static unsigned bit = UINT_MAX;
    static bool done;

    if (!done) {
        done = true;
        for (unsigned b = 0; b < 8 * 64; b++) {
            uint32_t atom = 0;

            if (qemu_plugin_dataflow_prov_atom(b, &atom) &&
                atom == QEMU_PLUGIN_DF_ATOM_ZERO) {
                bit = b;
                break;
            }
        }
    }
    return bit;
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

void cst_capture_vec_env(const struct qemu_plugin_tb *tb, size_t idx,
                         const void *bytes, size_t nbytes)
{
    if (!tb || !bytes || !nbytes) {
        return;
    }
    corpora_init();

    FILE *o = corpus_vec->get();

    if (!o) {
        return;
    }

    qemu_plugin_dataflow_status st = { };

    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        return;
    }

    /*
     * An instruction that hands a helper no env pointer says nothing about
     * how env pointers are recorded, and writing a row for it would put a
     * pair of zeros in the corpus that a scorer would read as coverage.
     */
    if (st.n_env_ptr_bounded == 0 && st.n_env_ptr_unbounded == 0) {
        return;
    }

    char enc[2 * 32 + 1];

    hex_bytes(bytes, nbytes, enc, sizeof(enc));
    fprintf(o, "%s\t%s\t%u\t%u\t%u\t%u\n", isa_name(), enc,
            st.n_vec_operands, st.n_vec_dropped,
            st.n_env_ptr_bounded, st.n_env_ptr_unbounded);
}

void cst_capture_df_stmt(const struct qemu_plugin_tb *tb, size_t idx,
                         const void *bytes, size_t nbytes)
{
    if (!tb || !bytes || !nbytes) {
        return;
    }
    corpora_init();

    FILE *o = corpus_stmt->get();

    if (!o) {
        return;
    }

    qemu_plugin_dataflow_status st = { };

    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        /*
         * The emulator has no dataflow answer for this instruction at all.
         * A row of zeros would read as "every statement absent", which is a
         * different claim, so no row is written and the corpus stays a
         * statement about instructions the reader reached.
         */
        return;
    }

    char enc[2 * 32 + 1];

    hex_bytes(bytes, nbytes, enc, sizeof(enc));

    /* The immediates, each with the role the decoder gave it. */
    char imm[192];
    size_t k = 0;

    imm[0] = '\0';
    for (unsigned i = 0; i < st.n_immediates; i++) {
        uint64_t value = 0;
        uint32_t role = 0;
        int w;

        if (!qemu_plugin_insn_immediate(tb, idx, i, &value, &role)) {
            continue;
        }
        w = snprintf(imm + k, sizeof(imm) - k, "%s%s:0x%llx", k ? "," : "",
                     role == QEMU_PLUGIN_DF_IMM_DISP ? "disp" : "imm",
                     (unsigned long long)value);
        if (w < 0 || (size_t)w >= sizeof(imm) - k) {
            break;
        }
        k += (size_t)w;
    }

    /*
     * The env ranges that resolve to a register NAME.  A range the target
     * never declared answers "?", which is what a consumer would be handed,
     * so the column separates "no env access" from "an env access nobody can
     * name" rather than printing a bare count for both.
     */
    char fields[256];
    size_t fk = 0;
    qemu_plugin_dataflow_field frows[16];
    unsigned nf;

    for (unsigned i = 0; i < 16; i++) {
        frows[i] = qemu_plugin_dataflow_field();
        frows[i].struct_size = sizeof(frows[i]);
    }
    nf = qemu_plugin_insn_fields(tb, idx, frows, 16);

    fields[0] = '\0';
    for (unsigned i = 0; i < nf; i++) {
        const char *nm =
            qemu_plugin_dataflow_field_reg(frows[i].env_offset, frows[i].size);
        int w = snprintf(fields + fk, sizeof(fields) - fk, "%s%s",
                         fk ? "," : "", nm ? nm : "?");

        if (w < 0 || (size_t)w >= sizeof(fields) - fk) {
            break;
        }
        fk += (size_t)w;
    }

    char vece[8];

    if (st.vec_vece == QEMU_PLUGIN_DF_VECE_NONE) {
        snprintf(vece, sizeof(vece), "-");
    } else {
        snprintf(vece, sizeof(vece), "%u", st.vec_vece);
    }

    /*
     * The architectural zero register, in whichever direction it was stated.
     *
     * It is an ATOM and not a register: it has no storage, so it appears in
     * the read and write sets under a bit the namespace reserves rather than
     * one that stands for a global.  A decoder that folds `xzr` or `$zero`
     * away leaves nothing in the op stream at all, so an unstated zero and an
     * instruction that genuinely touches no register look identical here --
     * which is exactly why the column exists separately from the read list.
     *
     * A set that could not be recorded in full is refused whole by the ABI,
     * and a refusal reads "-" like an absence would; the status row's
     * `incomplete` is what separates them, and it is carried by the columns
     * above.
     */
    char zero[4];
    uint64_t rd[8], wr[8];
    unsigned zbit = zero_atom_bit();
    unsigned pcbit = pc_reg_bit();
    bool z_rd = false, z_wr = false, pc_rd = false;
    unsigned n_rd = 0, n_wr = 0;
    bool have_sets = false;

    if (qemu_plugin_insn_reg_reads(tb, idx, rd, 8) <= 8 &&
        qemu_plugin_insn_reg_writes(tb, idx, wr, 8) <= 8) {
        have_sets = true;
        for (unsigned w = 0; w < 8; w++) {
            n_rd += (unsigned)__builtin_popcountll(rd[w]);
            n_wr += (unsigned)__builtin_popcountll(wr[w]);
        }
        if (zbit != UINT_MAX && zbit / 64 < 8) {
            z_rd = (rd[zbit / 64] >> (zbit % 64)) & 1;
            z_wr = (wr[zbit / 64] >> (zbit % 64)) & 1;
        }
        if (pcbit != UINT_MAX && pcbit / 64 < 8) {
            pc_rd = (rd[pcbit / 64] >> (pcbit % 64)) & 1;
        }
    }
    snprintf(zero, sizeof(zero), "%s%s",
             z_rd ? "r" : "", z_wr ? "w" : "");

    /*
     * THE SIZE OF THE READ AND WRITE SETS.
     *
     * A statement that names a register the ops do not -- the MOPS syndrome's
     * three, the folded program counter, the zero register -- changes the set
     * and nothing else this corpus carries, so without these two columns the
     * only instrument that could score such a statement would be the wire.
     * A set the ABI REFUSED (this instruction could not be recorded in full)
     * reads "-" rather than 0: a refusal and an instruction that touches no
     * register are different claims.
     */
    fprintf(o, "%s\t%s\t%u\t%s\t%s\t%u\t%u\t%s\t%s\t%s\t", isa_name(),
            enc, (st.properties & QEMU_PLUGIN_DF_P_ATOMIC) ? 1u : 0u,
            k ? imm : "-", vece, st.vec_oprsz, st.n_memops,
            fk ? fields : "-", zero[0] ? zero : "-",
            pcbit == UINT_MAX ? "-" : (pc_rd ? "r" : "0"));
    if (have_sets) {
        fprintf(o, "%u\t%u\n", n_rd, n_wr);
    } else {
        fprintf(o, "-\t-\n");
    }
}

#endif /* CST_CAPTURE */
